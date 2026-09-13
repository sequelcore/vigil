package io.github.sequelcore.vigil.enrollment;

import java.time.Duration;

final class EnrollmentTestProperties {
  private static final String CODE_HMAC_KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

  private EnrollmentTestProperties() {}

  static EnrollmentProperties decimalCode(String audience, int attemptLimit) {
    return new EnrollmentProperties(
        true,
        audience,
        EnrollmentProofFormat.DECIMAL_CODE,
        CODE_HMAC_KEY,
        Duration.ofMinutes(15),
        Duration.ofHours(24),
        attemptLimit,
        2,
        Duration.ofMinutes(1));
  }

  static EnrollmentProperties opaqueToken(String audience, int attemptLimit) {
    return new EnrollmentProperties(
        true,
        audience,
        EnrollmentProofFormat.OPAQUE_TOKEN,
        null,
        null,
        null,
        attemptLimit,
        2,
        null);
  }
}
