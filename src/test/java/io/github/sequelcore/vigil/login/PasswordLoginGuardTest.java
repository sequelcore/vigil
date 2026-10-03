package io.github.sequelcore.vigil.login;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

class PasswordLoginGuardTest {

  private static final LoginPolicy POLICY =
      new LoginPolicy(3, Duration.ofMinutes(1), Duration.ofMinutes(4), Duration.ofMinutes(10), 100);

  private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(4);
  private final String hash = encoder.encode("correct-horse");
  private final AtomicInteger lookups = new AtomicInteger();
  private final Function<String, Optional<LoginAccount>> lookup =
      id -> {
        lookups.incrementAndGet();
        return "ana@example.com".equalsIgnoreCase(id)
            ? Optional.of(new LoginAccount("ana-id", hash, true))
            : Optional.empty();
      };
  private MutableClock clock;
  private PasswordLoginGuard guard;

  @BeforeEach
  void setUp() {
    clock = new MutableClock();
    guard = new PasswordLoginGuard(encoder, new CaffeineLoginAttemptStore(POLICY), POLICY, clock);
  }

  @Test
  @DisplayName("Correct password authenticates and returns the subject")
  void succeeds() {
    LoginResult result = guard.authenticate("Ana@Example.com ", "correct-horse", lookup);

    assertThat(result.authenticated()).isTrue();
    assertThat(result.subject()).isEqualTo("ana-id");
    assertThat(result.needsRehash()).isFalse();
  }

  @Test
  @DisplayName("Locks after max failures and refuses even the correct password without lookup")
  void locks() {
    fail("ana@example.com", 3);
    lookups.set(0);

    LoginResult result = guard.authenticate("ana@example.com", "correct-horse", lookup);

    assertThat(result).isEqualTo(LoginResult.rejected());
    assertThat(lookups).hasValue(0);
  }

  @Test
  @DisplayName("Lock expires, and the next failure doubles it up to the maximum")
  void backoff() {
    fail("ana@example.com", 3);
    clock.advance(Duration.ofSeconds(61));
    assertThat(guard.authenticate("ana@example.com", "wrong", lookup).authenticated()).isFalse();

    clock.advance(Duration.ofSeconds(61));
    assertThat(locked("ana@example.com")).as("second lock lasts 2 minutes").isTrue();
    clock.advance(Duration.ofSeconds(60));
    assertThat(locked("ana@example.com")).isFalse();

    assertThat(POLICY.lockFor(10)).isEqualTo(Duration.ofMinutes(4));
    assertThat(POLICY.lockFor(2)).isZero();
  }

  @Test
  @DisplayName("Success resets the failure count")
  void resetsAfterSuccess() {
    fail("ana@example.com", 2);
    assertThat(guard.authenticate("ana@example.com", "correct-horse", lookup).authenticated())
        .isTrue();

    fail("ana@example.com", 2);

    assertThat(locked("ana@example.com")).isFalse();
  }

  @Test
  @DisplayName("Failures outside the window are forgotten")
  void windowExpires() {
    fail("ana@example.com", 2);
    clock.advance(Duration.ofMinutes(11));

    fail("ana@example.com", 2);

    assertThat(locked("ana@example.com")).isFalse();
  }

  @Test
  @DisplayName("Unknown users are counted and locked like known ones and look the same")
  void unknownUser() {
    assertThat(guard.authenticate("ghost@example.com", "x", lookup))
        .isEqualTo(guard.authenticate("ana@example.com", "x", lookup));

    fail("ghost@example.com", 2);

    assertThat(locked("ghost@example.com")).isTrue();
    assertThat(guard.authenticate("ghost@example.com", "x", lookup).needsRehash()).isFalse();
  }

  @Test
  @DisplayName("Inactive account with the right password is rejected generically")
  void inactiveAccount() {
    Function<String, Optional<LoginAccount>> inactive =
        id -> Optional.of(new LoginAccount("ana-id", hash, false));

    assertThat(guard.authenticate("ana@example.com", "correct-horse", inactive))
        .isEqualTo(LoginResult.rejected());
  }

  @Test
  @DisplayName("Null, blank, oversized input and oversized password are rejected")
  void badInput() {
    assertThat(guard.authenticate(null, "x", lookup).authenticated()).isFalse();
    assertThat(guard.authenticate("  ", null, lookup).authenticated()).isFalse();
    assertThat(guard.authenticate("a".repeat(400), "x", lookup).authenticated()).isFalse();
    assertThat(guard.authenticate("ana@example.com", "p".repeat(200), lookup).authenticated())
        .isFalse();
  }

  @Test
  @DisplayName("Rehash is flagged when the stored hash is weaker than the encoder")
  void rehash() {
    String weak = new BCryptPasswordEncoder(4).encode("pw");
    PasswordLoginGuard stronger =
        new PasswordLoginGuard(
            new BCryptPasswordEncoder(5), new CaffeineLoginAttemptStore(POLICY), POLICY, clock);

    LoginResult result =
        stronger.authenticate("u", "pw", id -> Optional.of(new LoginAccount("u", weak, true)));

    assertThat(result.authenticated()).isTrue();
    assertThat(result.needsRehash()).isTrue();
  }

  @Test
  @DisplayName("Rejecting an unknown user takes about as long as a wrong password")
  void constantTime() {
    BCryptPasswordEncoder slow = new BCryptPasswordEncoder(10);
    String slowHash = slow.encode("correct-horse");
    LoginPolicy lenient =
        new LoginPolicy(
            10_000, Duration.ofMinutes(1), Duration.ofMinutes(1), Duration.ofMinutes(1), 10_000);
    PasswordLoginGuard timed =
        new PasswordLoginGuard(slow, new CaffeineLoginAttemptStore(lenient), lenient, clock);
    Function<String, Optional<LoginAccount>> known =
        id ->
            "ana".equals(id)
                ? Optional.of(new LoginAccount("a", slowHash, true))
                : Optional.empty();
    for (int i = 0; i < 3; i++) {
      timed.authenticate("ana", "wrong", known);
      timed.authenticate("nobody", "wrong", known);
    }

    long[] wrong = new long[15];
    long[] unknown = new long[15];
    for (int i = 0; i < wrong.length; i++) {
      long start = System.nanoTime();
      timed.authenticate("ana", "wrong", known);
      wrong[i] = System.nanoTime() - start;
      start = System.nanoTime();
      timed.authenticate("nobody" + i, "wrong", known);
      unknown[i] = System.nanoTime() - start;
    }

    double wrongMedian = median(wrong);
    double unknownMedian = median(unknown);
    assertThat(unknownMedian / wrongMedian).isBetween(0.7, 1.3);
  }

  @Test
  @DisplayName("A legacy cheaper hash is not faster than an unknown user")
  void legacyCostParity() {
    BCryptPasswordEncoder current = new BCryptPasswordEncoder(10);
    String legacyHash = new BCryptPasswordEncoder(4).encode("correct-horse");
    LoginPolicy lenient =
        new LoginPolicy(
            10_000, Duration.ofMinutes(1), Duration.ofMinutes(1), Duration.ofMinutes(1), 10_000);
    PasswordLoginGuard timed =
        new PasswordLoginGuard(current, new CaffeineLoginAttemptStore(lenient), lenient, clock);
    Function<String, Optional<LoginAccount>> legacy =
        id ->
            "old".equals(id)
                ? Optional.of(new LoginAccount("o", legacyHash, true))
                : Optional.empty();
    for (int i = 0; i < 3; i++) {
      timed.authenticate("old", "wrong", legacy);
      timed.authenticate("nobody", "wrong", legacy);
    }

    long[] known = new long[15];
    long[] unknown = new long[15];
    for (int i = 0; i < known.length; i++) {
      long start = System.nanoTime();
      timed.authenticate("old", "wrong", legacy);
      known[i] = System.nanoTime() - start;
      start = System.nanoTime();
      timed.authenticate("nobody" + i, "wrong", legacy);
      unknown[i] = System.nanoTime() - start;
    }

    assertThat(median(unknown) / median(known)).isBetween(0.7, 1.3);
  }

  @Test
  @DisplayName("An interrupted thread still waits out the floor and keeps its interrupt status")
  void interruptKeepsFloorAndStatus() {
    BCryptPasswordEncoder current = new BCryptPasswordEncoder(10);
    PasswordLoginGuard timed =
        new PasswordLoginGuard(current, new CaffeineLoginAttemptStore(POLICY), POLICY, clock);
    String legacyHash = new BCryptPasswordEncoder(4).encode("pw");
    Function<String, Optional<LoginAccount>> legacy =
        id -> Optional.of(new LoginAccount("o", legacyHash, true));
    timed.authenticate("warm", "x", legacy);
    long start = System.nanoTime();
    timed.authenticate("plain", "x", legacy);
    long normal = System.nanoTime() - start;

    Thread.currentThread().interrupt();
    try {
      start = System.nanoTime();
      LoginResult result = timed.authenticate("other", "x", legacy);
      long interrupted = System.nanoTime() - start;

      assertThat(result.authenticated()).isFalse();
      assertThat(Thread.currentThread().isInterrupted()).isTrue();
      assertThat(interrupted).isGreaterThan(normal / 2);
    } finally {
      Thread.interrupted();
    }
  }

  private void fail(String id, int times) {
    for (int i = 0; i < times; i++) {
      guard.authenticate(id, "wrong", lookup);
    }
  }

  private boolean locked(String id) {
    lookups.set(0);
    guard.authenticate(id, "correct-horse", lookup);
    return lookups.get() == 0;
  }

  @Test
  @DisplayName("Policy rejects invalid values")
  void policyValidation() {
    Duration d = Duration.ofMinutes(1);
    assertThatThrownBy(() -> new LoginPolicy(0, d, d, d, 1))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new LoginPolicy(1, Duration.ZERO, d, d, 1))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new LoginPolicy(1, d, Duration.ofSeconds(1), d, 1))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new LoginPolicy(1, d, d, Duration.ZERO, 1))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new LoginPolicy(1, d, d, d, 0))
        .isInstanceOf(IllegalArgumentException.class);
    assertThat(LoginPolicy.defaults().maxFailures()).isEqualTo(5);
    assertThat(LoginPolicy.withDefaults(0, null, null, null, 0)).isEqualTo(LoginPolicy.defaults());
    assertThat(
            LoginPolicy.withDefaults(2, Duration.ofHours(1), Duration.ofMinutes(1), d, 5).maxLock())
        .isEqualTo(Duration.ofHours(1));
    assertThat(new LoginAccount("subj", "hash", true).toString())
        .isEqualTo("LoginAccount[redacted]");
  }

  private static double median(long[] values) {
    long[] sorted = values.clone();
    Arrays.sort(sorted);
    return sorted[sorted.length / 2];
  }

  private static final class MutableClock extends Clock {
    private Instant now = Instant.parse("2026-01-01T00:00:00Z");

    void advance(Duration d) {
      now = now.plus(d);
    }

    @Override
    public java.time.ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(java.time.ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return now;
    }
  }
}
