package io.github.sequelcore.vigil.stepup.pin;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import java.time.Clock;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/** Hashes, validates, rotates, and revokes personal numeric PINs. */
public final class VigilPinService {
  private static final Pattern NUMERIC = Pattern.compile("[0-9]+");

  private final VigilProperties.StepUp.Pin config;
  private final BCryptPasswordEncoder encoder;
  private final Clock clock;

  public VigilPinService(VigilProperties.StepUp.Pin config) {
    this(config, Clock.systemUTC());
  }

  VigilPinService(VigilProperties.StepUp.Pin config, Clock clock) {
    this.config = config;
    this.clock = clock;
    this.encoder = new BCryptPasswordEncoder(config.bcryptStrength());
  }

  public void enroll(PinCredentialStore store, UUID tenantId, String actorId, PinCredential pin) {
    save(store, tenantId, actorId, pin, false);
  }

  public void rotate(PinCredentialStore store, UUID tenantId, String actorId, PinCredential pin) {
    save(store, tenantId, actorId, pin, false);
  }

  public void revoke(PinCredentialStore store, UUID tenantId, String actorId) {
    store.save(tenantId, actorId, new PinCredentialRecord("", Instant.now(clock), true));
  }

  public boolean matches(PinCredential pin, PinCredentialRecord record) {
    return record != null
        && !record.revoked()
        && encoder.matches(new String(pin.value()), record.hash());
  }

  private void save(
      PinCredentialStore store, UUID tenantId, String actorId, PinCredential pin, boolean revoked) {
    String raw = new String(pin.value());
    validate(raw);
    store.save(
        tenantId,
        actorId,
        new PinCredentialRecord(encoder.encode(raw), Instant.now(clock), revoked));
  }

  private void validate(String pin) {
    if (!NUMERIC.matcher(pin).matches()
        || pin.length() < config.minLength()
        || pin.length() > config.maxLength()) {
      throw new IllegalArgumentException(
          "PIN does not satisfy the configured numeric length policy");
    }
    if (config.rejectCommonPatterns() && isCommonPattern(pin)) {
      throw new IllegalArgumentException("PIN is too easy to guess");
    }
  }

  private boolean isCommonPattern(String pin) {
    if (new HashSet<Character>(pin.chars().mapToObj(c -> (char) c).toList()).size() == 1) {
      return true;
    }
    boolean ascending = true;
    boolean descending = true;
    for (int index = 1; index < pin.length(); index++) {
      ascending &= pin.charAt(index) == pin.charAt(index - 1) + 1;
      descending &= pin.charAt(index) == pin.charAt(index - 1) - 1;
    }
    return ascending || descending || Set.of("000000", "111111", "123456", "654321").contains(pin);
  }
}
