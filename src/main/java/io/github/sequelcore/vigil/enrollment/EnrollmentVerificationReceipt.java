package io.github.sequelcore.vigil.enrollment;

import java.time.Instant;
import java.util.UUID;

/** Durable one-time handoff evidence for the application identity transaction. */
public record EnrollmentVerificationReceipt(
    UUID receiptId,
    String canonicalEmail,
    String contextId,
    String contextVersion,
    String audience,
    String purpose,
    java.util.UUID lifecycleId,
    long generation,
    Instant verifiedAt) {
  @Override
  public String toString() {
    return "EnrollmentVerificationReceipt[redacted]";
  }
}
