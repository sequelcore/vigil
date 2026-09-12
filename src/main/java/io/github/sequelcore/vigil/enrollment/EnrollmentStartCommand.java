package io.github.sequelcore.vigil.enrollment;

import java.time.Instant;

/** Input to one atomic start or resend store operation. */
public record EnrollmentStartCommand(
    String canonicalEmail,
    String contextId,
    String contextVersion,
    String audience,
    String purpose,
    String proofDigest,
    Instant now,
    Instant proofExpiresAt,
    Instant totalExpiresAt,
    int resendLimit,
    java.time.Duration resendCooldown) {
  @Override
  public String toString() {
    return "EnrollmentStartCommand[redacted]";
  }
}
