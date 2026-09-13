package io.github.sequelcore.vigil.enrollment;

import java.time.Duration;
import java.util.Base64;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/** Opt-in configuration for contact-only self-service enrollment. */
@ConfigurationProperties(prefix = "vigil.enrollment")
@Validated
public record EnrollmentProperties(
    boolean enabled,
    String audience,
    @DefaultValue("OPAQUE_TOKEN") EnrollmentProofFormat proofFormat,
    String codeHmacKey,
    @DefaultValue("15m") Duration proofTtl,
    @DefaultValue("24h") Duration totalLifetime,
    @DefaultValue("5") int attemptLimit,
    @DefaultValue("3") int resendLimit,
    @DefaultValue("1m") Duration resendCooldown) {
  public EnrollmentProperties {
    if (proofFormat == null) {
      proofFormat = EnrollmentProofFormat.OPAQUE_TOKEN;
    }
    if (proofTtl == null) {
      proofTtl = Duration.ofMinutes(15);
    }
    if (totalLifetime == null) {
      totalLifetime = Duration.ofHours(24);
    }
    if (resendCooldown == null) {
      resendCooldown = Duration.ofMinutes(1);
    }
    if (proofTtl.isNegative() || proofTtl.isZero()) {
      throw new IllegalArgumentException("vigil.enrollment.proof-ttl must be positive");
    }
    if (totalLifetime.isNegative() || totalLifetime.isZero()) {
      throw new IllegalArgumentException("vigil.enrollment.total-lifetime must be positive");
    }
    if (totalLifetime.compareTo(proofTtl) < 0) {
      throw new IllegalArgumentException(
          "vigil.enrollment.total-lifetime must be at least vigil.enrollment.proof-ttl");
    }
    if (resendCooldown.isNegative()) {
      throw new IllegalArgumentException("vigil.enrollment.resend-cooldown cannot be negative");
    }
    if (attemptLimit <= 0 || resendLimit < 0) {
      throw new IllegalArgumentException(
          "vigil.enrollment.attempt-limit must be positive and resend-limit cannot be negative");
    }
    if (proofFormat == EnrollmentProofFormat.DECIMAL_CODE
        && proofTtl.compareTo(Duration.ofMinutes(15)) > 0) {
      throw new IllegalArgumentException(
          "vigil.enrollment.proof-ttl must be at most 15m for decimal codes");
    }
    if (proofFormat == EnrollmentProofFormat.DECIMAL_CODE && attemptLimit > 5) {
      throw new IllegalArgumentException(
          "vigil.enrollment.attempt-limit must be at most 5 for decimal codes");
    }
  }

  /** Fails closed when the optional module has been explicitly enabled without its authority. */
  public EnrollmentProperties validatedForEnabledUse() {
    if (audience == null || audience.isBlank()) {
      throw new IllegalArgumentException(
          "vigil.enrollment.audience is required when enrollment is enabled");
    }
    if (proofFormat == EnrollmentProofFormat.DECIMAL_CODE && decodedCodeHmacKey() == null) {
      throw new IllegalArgumentException(
          "vigil.enrollment.code-hmac-key must be canonical Base64URL for exactly 32 bytes when decimal codes are enabled");
    }
    return this;
  }

  byte[] decodedCodeHmacKey() {
    if (codeHmacKey == null || codeHmacKey.length() != 43) {
      return null;
    }
    try {
      byte[] decoded = Base64.getUrlDecoder().decode(codeHmacKey);
      return decoded.length == 32
              && Base64.getUrlEncoder().withoutPadding().encodeToString(decoded).equals(codeHmacKey)
          ? decoded
          : null;
    } catch (IllegalArgumentException exception) {
      return null;
    }
  }

  @Override
  public String toString() {
    return "EnrollmentProperties[redacted]";
  }
}
