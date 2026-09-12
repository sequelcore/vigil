package io.github.sequelcore.vigil.enrollment;

import java.time.Instant;

/** Input to the store's atomic verification-and-receipt operation. */
public record EnrollmentVerificationCommand(
    String canonicalEmail,
    String contextId,
    String contextVersion,
    String audience,
    String purpose,
    String proofDigest,
    Instant now,
    int attemptLimit) {
  @Override
  public String toString() {
    return "EnrollmentVerificationCommand[redacted]";
  }
}
