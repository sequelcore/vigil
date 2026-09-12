package io.github.sequelcore.vigil.enrollment;

/** Contact verification result. It contains no session, token, or credential material. */
public enum EnrollmentVerificationResult {
  /** The receipt is durably complete; repeated values are idempotent acknowledgements only. */
  COMPLETED,

  /** The same durable receipt must be retried through {@link EnrollmentService#recover}. */
  PENDING_RECOVERY,

  /** The proof, binding, lifecycle, or authoritative host outcome was rejected. */
  REJECTED
}
