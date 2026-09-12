package io.github.sequelcore.vigil.enrollment;

import java.time.Instant;
import java.util.UUID;

/** Result of an atomic proof creation or rotation. */
public record EnrollmentStartOutcome(
    boolean created, UUID lifecycleId, long generation, Instant proofExpiresAt) {
  public static EnrollmentStartOutcome notCreated() {
    return new EnrollmentStartOutcome(false, null, -1, null);
  }
}
