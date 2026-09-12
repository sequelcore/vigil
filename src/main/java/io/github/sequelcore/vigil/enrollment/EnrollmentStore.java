package io.github.sequelcore.vigil.enrollment;

/**
 * Durable shared-state SPI for the enrollment lifecycle.
 *
 * <p>Every method is an atomic domain operation across processes. Implementations must enforce
 * lifecycle transitions and generation predicates in durable storage; load/save implementations and
 * process-local locking do not satisfy this contract.
 */
public interface EnrollmentStore {
  /**
   * Atomically begins a lifecycle and persists generation one with its total expiry.
   *
   * <p>The stable enrollment identity is context ID, audience, and purpose; canonical email and
   * context version are mutable proof bindings. A start with either binding changed must atomically
   * make the new lifecycle the only current lifecycle for that stable identity and supersede every
   * earlier lifecycle, so an earlier proof cannot produce a receipt, recover a receipt, or report a
   * completed replay. Implementations may retain superseded rows for bounded audit retention, but
   * must exclude them from every current-lifecycle operation.
   *
   * <p>A duplicate start for the same active canonical-email/context/version/audience/purpose
   * lifecycle must return {@link EnrollmentStartOutcome#notCreated()} and must not change started
   * time, total expiry, attempts, resend count, generation, or cooldown state. The duplicate check
   * and any supersession/new-lifecycle creation are one durable atomic operation across processes.
   */
  EnrollmentStartOutcome start(EnrollmentStartCommand command);

  /**
   * Atomically rotates a pending generation, superseding its prior proof only after enforcing the
   * persisted cooldown, resend limit, and original total-lifetime expiry.
   */
  EnrollmentStartOutcome resend(EnrollmentStartCommand command);

  /**
   * Atomically checks digest and every binding, records an attempt when appropriate, and creates at
   * most one receipt for the current generation. Existing-receipt and completed results are valid
   * only for the same correct proof digest; a different digest must be recorded/rejected. A
   * completed result is terminal replay evidence and never authorizes another host-side effect.
   */
  EnrollmentVerificationOutcome createVerificationReceipt(EnrollmentVerificationCommand command);

  /** Returns only the existing receipt in {@link EnrollmentStatus#VERIFIED_PENDING_APPLY}. */
  EnrollmentVerificationReceipt recoverVerificationReceipt(EnrollmentRecoveryCommand command);

  /**
   * Records an outcome only if its complete lifecycle binding and generation are still current and
   * its state is {@link EnrollmentStatus#PENDING}. It must not mutate verified or terminal state.
   */
  void recordDeliveryOutcome(EnrollmentDeliveryOutcomeCommand command);

  /** Marks the matching durable receipt complete without creating a replacement receipt. */
  void acknowledgeCompletion(EnrollmentVerificationReceipt receipt);

  /**
   * Marks the matching receipt terminally rejected after an authoritative host rejection, without
   * creating a replacement receipt or leaving recovery work pending.
   */
  void rejectCompletion(EnrollmentVerificationReceipt receipt);
}
