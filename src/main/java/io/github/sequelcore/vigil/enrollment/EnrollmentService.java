package io.github.sequelcore.vigil.enrollment;

import java.time.Clock;
import java.time.Instant;

/**
 * Contact-only enrollment proof lifecycle orchestration.
 *
 * <p>This service creates no HTTP routes, credentials, sessions, users, or persistence adapter. Its
 * store and application identity ports own the atomic durable transitions and application
 * transaction respectively.
 */
public final class EnrollmentService {
  private static final String ENROLLMENT_PURPOSE = "contact-enrollment";
  private final EnrollmentProperties properties;
  private final EnrollmentProofCodec proofCodec;
  private final EmailCanonicalizer canonicalizer;
  private final EnrollmentIdentityPort identityPort;
  private final EnrollmentDeliveryPort deliveryPort;
  private final EnrollmentAbuseControl abuseControl;
  private final EnrollmentStore store;
  private final Clock clock;

  public EnrollmentService(
      EnrollmentProperties properties,
      EmailCanonicalizer canonicalizer,
      EnrollmentIdentityPort identityPort,
      EnrollmentDeliveryPort deliveryPort,
      EnrollmentAbuseControl abuseControl,
      EnrollmentStore store) {
    this(
        properties,
        canonicalizer,
        identityPort,
        deliveryPort,
        abuseControl,
        store,
        Clock.systemUTC());
  }

  EnrollmentService(
      EnrollmentProperties properties,
      EmailCanonicalizer canonicalizer,
      EnrollmentIdentityPort identityPort,
      EnrollmentDeliveryPort deliveryPort,
      EnrollmentAbuseControl abuseControl,
      EnrollmentStore store,
      Clock clock) {
    this.properties = properties.validatedForEnabledUse();
    this.proofCodec = new EnrollmentProofCodec(this.properties);
    this.canonicalizer = canonicalizer;
    this.identityPort = identityPort;
    this.deliveryPort = deliveryPort;
    this.abuseControl = abuseControl;
    this.store = store;
    this.clock = clock;
  }

  /**
   * Starts a new enrollment lifecycle. Its response intentionally does not reveal account state.
   */
  public EnrollmentRequestResult start(EnrollmentStartRequest request) {
    processRequest(request, EnrollmentOperation.START);
    return EnrollmentRequestResult.ACCEPTED;
  }

  /** Rotates the pending proof when the application admission policy allows it. */
  public EnrollmentRequestResult resend(EnrollmentStartRequest request) {
    processRequest(request, EnrollmentOperation.RESEND);
    return EnrollmentRequestResult.ACCEPTED;
  }

  /**
   * Verifies a contact proof and then asks the application to apply the durable receipt.
   *
   * <p>No application identity call occurs until the store has atomically created or returned a
   * verified receipt. A failed application call leaves that same receipt recoverable.
   */
  public EnrollmentVerificationResult verify(EnrollmentVerificationRequest request) {
    if (request == null || !hasBinding(request.contextId(), request.contextVersion())) {
      return EnrollmentVerificationResult.REJECTED;
    }
    String canonicalEmail = canonicalize(request.email());
    if (canonicalEmail == null
        || !admitted(
            canonicalEmail,
            request.contextId(),
            request.contextVersion(),
            EnrollmentOperation.VERIFY)) {
      return EnrollmentVerificationResult.REJECTED;
    }
    String proofDigest =
        proofCodec.digest(
            request.proof(),
            canonicalEmail,
            request.contextId(),
            request.contextVersion(),
            properties.audience(),
            ENROLLMENT_PURPOSE);
    if (proofDigest == null) {
      return EnrollmentVerificationResult.REJECTED;
    }
    EnrollmentVerificationOutcome outcome;
    try {
      outcome =
          store.createVerificationReceipt(
              new EnrollmentVerificationCommand(
                  canonicalEmail,
                  request.contextId(),
                  request.contextVersion(),
                  properties.audience(),
                  ENROLLMENT_PURPOSE,
                  proofDigest,
                  Instant.now(clock),
                  properties.attemptLimit()));
    } catch (RuntimeException exception) {
      return EnrollmentVerificationResult.REJECTED;
    }
    if (outcome == null || outcome.kind() == EnrollmentVerificationOutcome.Kind.REJECTED) {
      return EnrollmentVerificationResult.REJECTED;
    }
    if (outcome.kind() == EnrollmentVerificationOutcome.Kind.COMPLETED) {
      return EnrollmentVerificationResult.COMPLETED;
    }
    return applyAndAcknowledge(outcome.receipt());
  }

  /** Retries an existing durable receipt only; it cannot mint another receipt. */
  public EnrollmentVerificationResult recover(EnrollmentRecoveryRequest request) {
    if (request == null || !hasBinding(request.contextId(), request.contextVersion())) {
      return EnrollmentVerificationResult.REJECTED;
    }
    String canonicalEmail = canonicalize(request.email());
    if (canonicalEmail == null) {
      return EnrollmentVerificationResult.REJECTED;
    }
    try {
      EnrollmentVerificationReceipt receipt =
          store.recoverVerificationReceipt(
              new EnrollmentRecoveryCommand(
                  canonicalEmail,
                  request.contextId(),
                  request.contextVersion(),
                  properties.audience(),
                  ENROLLMENT_PURPOSE,
                  Instant.now(clock)));
      return receipt == null ? EnrollmentVerificationResult.REJECTED : applyAndAcknowledge(receipt);
    } catch (RuntimeException exception) {
      return EnrollmentVerificationResult.PENDING_RECOVERY;
    }
  }

  private void processRequest(EnrollmentStartRequest request, EnrollmentOperation operation) {
    if (request == null || !hasBinding(request.contextId(), request.contextVersion())) {
      return;
    }
    String canonicalEmail = canonicalize(request.email());
    if (canonicalEmail == null
        || !admitted(canonicalEmail, request.contextId(), request.contextVersion(), operation)) {
      return;
    }
    String proof = proofCodec.generate();
    Instant now = Instant.now(clock);
    EnrollmentStartCommand command =
        new EnrollmentStartCommand(
            canonicalEmail,
            request.contextId(),
            request.contextVersion(),
            properties.audience(),
            ENROLLMENT_PURPOSE,
            proofCodec.digest(
                proof,
                canonicalEmail,
                request.contextId(),
                request.contextVersion(),
                properties.audience(),
                ENROLLMENT_PURPOSE),
            now,
            now.plus(properties.proofTtl()),
            operation == EnrollmentOperation.START ? now.plus(properties.totalLifetime()) : null,
            properties.resendLimit(),
            properties.resendCooldown());
    try {
      EnrollmentStartOutcome outcome =
          operation == EnrollmentOperation.START ? store.start(command) : store.resend(command);
      if (outcome != null && outcome.created()) {
        deliver(request, canonicalEmail, proof, outcome);
      }
    } catch (RuntimeException exception) {
      // The request-facing result is deliberately generic; adapters own safe operational logging.
    }
  }

  private EnrollmentVerificationResult applyAndAcknowledge(EnrollmentVerificationReceipt receipt) {
    if (receipt == null) {
      return EnrollmentVerificationResult.REJECTED;
    }
    try {
      EnrollmentIdentityPort.ApplyOutcome applyOutcome = identityPort.applyVerifiedContact(receipt);
      if (applyOutcome == EnrollmentIdentityPort.ApplyOutcome.APPLIED) {
        store.acknowledgeCompletion(receipt);
        return EnrollmentVerificationResult.COMPLETED;
      }
      if (applyOutcome == EnrollmentIdentityPort.ApplyOutcome.REJECTED) {
        store.rejectCompletion(receipt);
        return EnrollmentVerificationResult.REJECTED;
      }
      return EnrollmentVerificationResult.PENDING_RECOVERY;
    } catch (RuntimeException exception) {
      return EnrollmentVerificationResult.PENDING_RECOVERY;
    }
  }

  private void deliver(
      EnrollmentStartRequest request,
      String canonicalEmail,
      String proof,
      EnrollmentStartOutcome outcome) {
    EnrollmentDeliveryPort.DeliveryOutcome deliveryOutcome;
    try {
      deliveryOutcome =
          deliveryPort.deliver(
              new EnrollmentDelivery(
                  request,
                  canonicalEmail,
                  properties.audience(),
                  ENROLLMENT_PURPOSE,
                  outcome,
                  properties.proofFormat(),
                  proof));
      if (deliveryOutcome == null) {
        deliveryOutcome = EnrollmentDeliveryPort.DeliveryOutcome.RETRYABLE_FAILURE;
      }
    } catch (RuntimeException exception) {
      deliveryOutcome = EnrollmentDeliveryPort.DeliveryOutcome.RETRYABLE_FAILURE;
    }
    try {
      store.recordDeliveryOutcome(
          new EnrollmentDeliveryOutcomeCommand(
              canonicalEmail,
              request.contextId(),
              request.contextVersion(),
              properties.audience(),
              ENROLLMENT_PURPOSE,
              outcome.lifecycleId(),
              outcome.generation(),
              deliveryOutcome));
    } catch (RuntimeException exception) {
      // Delivery happened outside the durable transaction; an adapter may reconcile this outcome.
    }
  }

  private boolean admitted(
      String canonicalEmail,
      String contextId,
      String contextVersion,
      EnrollmentOperation operation) {
    try {
      return abuseControl.admit(
          new EnrollmentAdmission(canonicalEmail, contextId, contextVersion, operation));
    } catch (RuntimeException exception) {
      return false;
    }
  }

  private String canonicalize(String email) {
    try {
      String canonicalEmail = canonicalizer.canonicalize(email);
      return canonicalEmail == null || canonicalEmail.isBlank() ? null : canonicalEmail;
    } catch (RuntimeException exception) {
      return null;
    }
  }

  private static boolean hasBinding(String contextId, String contextVersion) {
    return contextId != null
        && !contextId.isBlank()
        && contextVersion != null
        && !contextVersion.isBlank();
  }
}
