package io.github.sequelcore.vigil.enrollment;

/**
 * Applies a verified contact to application-owned identity state.
 *
 * <p>Implementations must make {@link #applyVerifiedContact(EnrollmentVerificationReceipt)}
 * transactional and idempotent by receipt ID, and recheck the context binding and version before
 * changing state. Any later credential-enrollment permission must be recorded with that receipt and
 * consumed first-write-wins so replay cannot replace a credential or create another session. It is
 * intentionally not a user lookup or auto-linking API.
 */
@FunctionalInterface
public interface EnrollmentIdentityPort {
  /**
   * Applies the verified contact or authoritatively rejects it after rechecking host state.
   *
   * <p>Exceptions mean the result is ambiguous and are retried through recovery; do not use an
   * exception for a known conflict such as an existing account.
   */
  ApplyOutcome applyVerifiedContact(EnrollmentVerificationReceipt receipt);

  /** Authoritative result of applying a verification receipt to host identity state. */
  enum ApplyOutcome {
    APPLIED,
    REJECTED
  }
}
