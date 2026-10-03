package io.github.sequelcore.vigil.login;

import java.time.Clock;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Reusable password-login guard called from the application's own login route.
 *
 * <p>The application keeps the route, the user lookup and the account status; the guard adds
 * lockout with backoff, equal-cost verification, and a result that hides which part failed:
 *
 * <ul>
 *   <li>A locked identifier is rejected immediately, without lookup or hashing, so lock state is
 *       not a CPU amplifier. Unknown identifiers are counted and locked exactly like known ones, so
 *       a lock reveals nothing about existence.
 *   <li>Otherwise a hash is always verified: the account's, or a dummy hash made with the same
 *       encoder when the user is unknown, so unknown users cost the same as wrong passwords.
 *   <li>Failures (unknown, wrong password, inactive account) are recorded; success resets.
 * </ul>
 *
 * <p>Concurrent requests can pass the lock check together, so up to {@code maxFailures - 1 +
 * concurrent requests} guesses may be made before the first lock.
 *
 * <p>Every verified attempt takes at least a floor calibrated at construction from the encoder's
 * own dummy verification, so accounts whose stored hash is cheaper than the encoder's default (for
 * example an older work factor) are not faster than unknown users. A stored hash that is more
 * expensive than the default cannot be hidden this way and stays distinguishable until it is
 * rehashed ({@link LoginResult#needsRehash()}) or migrated; keep stored hashes at or below the
 * encoder's cost. The floor holds a request thread for at most one dummy-verification time.
 */
public final class PasswordLoginGuard {

  /** Namespace of password-login keys; step-up PIN verification uses a different one. */
  static final String KEY_NAMESPACE = "password:";

  private static final int MAX_IDENTIFIER_LENGTH = 320;
  private static final int MAX_PASSWORD_LENGTH = 128;

  private final PasswordEncoder encoder;
  private final LoginAttemptStore store;
  private final LoginPolicy policy;
  private final Clock clock;
  private final String dummyHash;
  private final long floorNanos;

  /**
   * Creates a guard with the default node-local store.
   *
   * @param encoder the application's password encoder, for example {@code
   *     VigilPasswordService.encoder()}
   * @param policy lockout policy
   */
  public PasswordLoginGuard(PasswordEncoder encoder, LoginPolicy policy) {
    this(encoder, new CaffeineLoginAttemptStore(policy), policy);
  }

  /**
   * Creates a guard with an application-supplied store, for example a shared one.
   *
   * @param encoder the application's password encoder
   * @param store failure counters
   * @param policy lockout policy
   */
  public PasswordLoginGuard(PasswordEncoder encoder, LoginAttemptStore store, LoginPolicy policy) {
    this(encoder, store, policy, Clock.systemUTC());
  }

  PasswordLoginGuard(
      PasswordEncoder encoder, LoginAttemptStore store, LoginPolicy policy, Clock clock) {
    this.encoder = Objects.requireNonNull(encoder, "encoder");
    this.store = Objects.requireNonNull(store, "store");
    this.policy = Objects.requireNonNull(policy, "policy");
    this.clock = Objects.requireNonNull(clock, "clock");
    this.dummyHash = encoder.encode(UUID.randomUUID().toString());
    this.floorNanos = calibrate();
  }

  /**
   * Attempts a password login.
   *
   * @param identifier the identifier the user typed, such as an email or username
   * @param password the password the user typed
   * @param lookup the application's lookup; it receives the identifier with surrounding whitespace
   *     removed and returns the account with its status, or empty when there is none
   * @return the result; on rejection the caller returns one generic error for every cause
   */
  public LoginResult authenticate(
      String identifier, String password, Function<String, Optional<LoginAccount>> lookup) {
    Objects.requireNonNull(lookup, "lookup");
    String key = normalize(identifier);
    if (key != null && store.isLocked(key, clock.instant())) {
      return LoginResult.rejected();
    }

    Optional<LoginAccount> account =
        key == null ? Optional.empty() : lookup.apply(identifier.strip());
    boolean usable = password != null && password.length() <= MAX_PASSWORD_LENGTH;
    String candidate = usable ? password : "";
    String hash = account.map(LoginAccount::passwordHash).orElse(dummyHash);
    long started = System.nanoTime();
    boolean matches = encoder.matches(candidate, hash);
    awaitFloor(started);

    if (account.isPresent() && account.get().active() && matches && usable) {
      store.reset(key);
      return LoginResult.success(account.get().subject(), encoder.upgradeEncoding(hash));
    }
    if (key != null) {
      store.recordFailure(key, clock.instant(), policy);
    }
    return LoginResult.rejected();
  }

  private long calibrate() {
    long[] samples = new long[5];
    for (int i = 0; i < samples.length; i++) {
      long start = System.nanoTime();
      encoder.matches("calibration", dummyHash);
      samples[i] = System.nanoTime() - start;
    }
    java.util.Arrays.sort(samples);
    return samples[samples.length / 2];
  }

  private void awaitFloor(long started) {
    boolean interrupted = Thread.interrupted();
    long remaining;
    while ((remaining = floorNanos - (System.nanoTime() - started)) > 0) {
      java.util.concurrent.locks.LockSupport.parkNanos(remaining);
      interrupted |= Thread.interrupted();
    }
    if (interrupted) {
      Thread.currentThread().interrupt();
    }
  }

  private static String normalize(String identifier) {
    if (identifier == null) {
      return null;
    }
    String trimmed = identifier.strip();
    if (trimmed.isEmpty() || trimmed.length() > MAX_IDENTIFIER_LENGTH) {
      return null;
    }
    return KEY_NAMESPACE + trimmed.toLowerCase(Locale.ROOT);
  }
}
