package io.github.sequelcore.vigil.enrollment;

import java.time.Instant;

/** Input to the store's atomic lookup of a durable, unapplied verification receipt. */
public record EnrollmentRecoveryCommand(
    String canonicalEmail,
    String contextId,
    String contextVersion,
    String audience,
    String purpose,
    Instant now) {
  @Override
  public String toString() {
    return "EnrollmentRecoveryCommand[redacted]";
  }
}
