package io.github.sequelcore.vigil.enrollment;

/**
 * Applies a verified contact to application-owned identity state.
 *
 * <p>Implementations must make {@link #applyVerifiedContact(EnrollmentVerificationReceipt)}
 * transactional and idempotent by receipt ID, and recheck the context binding and version before
 * changing state. A credential-finalizing host may record a receipt-bound finalization permission,
 * but this method neither creates nor activates a credential, session, or account link. A host with
 * a pending password verifier must validate its registration ceremony before calling Vigil and
 * revalidate it before consuming that permission first-write-wins after Vigil acknowledges
 * completion. An invalid ceremony must not advance verification or credential activation;
 * pending-state retirement requires authorized host action or expiry. It is intentionally not a
 * user lookup or auto-linking API.
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
