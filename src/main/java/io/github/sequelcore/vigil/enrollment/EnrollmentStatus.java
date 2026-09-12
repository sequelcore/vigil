package io.github.sequelcore.vigil.enrollment;

/** Durable enrollment lifecycle state. */
public enum EnrollmentStatus {
  PENDING,
  VERIFIED_PENDING_APPLY,
  COMPLETED,
  REJECTED,
  EXPIRED,
  SUPERSEDED
}
