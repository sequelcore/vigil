package io.github.sequelcore.vigil.enrollment;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/** Opt-in configuration for contact-only self-service enrollment. */
@ConfigurationProperties(prefix = "vigil.enrollment")
@Validated
public record EnrollmentProperties(
    boolean enabled,
    String audience,
    @DefaultValue("15m") Duration proofTtl,
    @DefaultValue("24h") Duration totalLifetime,
    @DefaultValue("5") int attemptLimit,
    @DefaultValue("3") int resendLimit,
    @DefaultValue("1m") Duration resendCooldown) {
  public EnrollmentProperties {
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
  }

  /** Fails closed when the optional module has been explicitly enabled without its authority. */
  public EnrollmentProperties validatedForEnabledUse() {
    if (audience == null || audience.isBlank()) {
      throw new IllegalArgumentException(
          "vigil.enrollment.audience is required when enrollment is enabled");
    }
    return this;
  }
}
