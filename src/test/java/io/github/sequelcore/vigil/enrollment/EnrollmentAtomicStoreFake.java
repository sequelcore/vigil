package io.github.sequelcore.vigil.enrollment;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/** Deterministic atomic contract fake; it is not a shared-storage implementation. */
final class EnrollmentAtomicStoreFake implements EnrollmentStore {
  State state;
  final List<State> states = new ArrayList<>();
  final List<UUID> createdReceiptIds = new ArrayList<>();
  int verificationCalls;

  @Override
  public synchronized EnrollmentStartOutcome start(EnrollmentStartCommand command) {
    State existing = find(command);
    if (existing != null
        && (existing.status == EnrollmentStatus.PENDING
            || existing.status == EnrollmentStatus.VERIFIED_PENDING_APPLY)) {
      return EnrollmentStartOutcome.notCreated();
    }
    states.stream()
        .filter(candidate -> sameStableIdentity(candidate, command))
        .forEach(candidate -> candidate.status = EnrollmentStatus.SUPERSEDED);
    state = new State(command);
    states.add(state);
    return created();
  }

  @Override
  public synchronized EnrollmentStartOutcome resend(EnrollmentStartCommand command) {
    State current = find(command);
    if (current == null
        || current.status != EnrollmentStatus.PENDING
        || !command.now().isBefore(current.totalExpiresAt)
        || current.resends >= command.resendLimit()
        || command.now().isBefore(current.lastSentAt.plus(command.resendCooldown()))) {
      return EnrollmentStartOutcome.notCreated();
    }
    state = current;
    current.proofDigest = command.proofDigest();
    current.generation++;
    current.proofExpiresAt = earliest(command.proofExpiresAt(), current.totalExpiresAt);
    current.lastSentAt = command.now();
    current.resends++;
    return created();
  }

  @Override
  public synchronized EnrollmentVerificationOutcome createVerificationReceipt(
      EnrollmentVerificationCommand command) {
    verificationCalls++;
    State current = find(command);
    if (current == null) {
      return EnrollmentVerificationOutcome.rejected();
    }
    state = current;
    if (!current.proofDigest.equals(command.proofDigest())) {
      current.attempts++;
      if (current.status == EnrollmentStatus.PENDING
          && current.attempts >= command.attemptLimit()) {
        current.status = EnrollmentStatus.EXPIRED;
      }
      return EnrollmentVerificationOutcome.rejected();
    }
    if (current.status == EnrollmentStatus.COMPLETED) {
      return new EnrollmentVerificationOutcome(EnrollmentVerificationOutcome.Kind.COMPLETED, null);
    }
    if (current.status == EnrollmentStatus.VERIFIED_PENDING_APPLY) {
      return new EnrollmentVerificationOutcome(
          EnrollmentVerificationOutcome.Kind.EXISTING_RECEIPT, current.receipt);
    }
    if (current.status != EnrollmentStatus.PENDING
        || !command.now().isBefore(current.proofExpiresAt)
        || !command.now().isBefore(current.totalExpiresAt)) {
      if (current.status == EnrollmentStatus.PENDING) {
        current.status = EnrollmentStatus.EXPIRED;
      }
      return EnrollmentVerificationOutcome.rejected();
    }
    current.receipt =
        new EnrollmentVerificationReceipt(
            UUID.randomUUID(),
            current.canonicalEmail,
            current.contextId,
            current.contextVersion,
            current.audience,
            current.purpose,
            current.lifecycleId,
            current.generation,
            command.now());
    createdReceiptIds.add(current.receipt.receiptId());
    current.status = EnrollmentStatus.VERIFIED_PENDING_APPLY;
    return new EnrollmentVerificationOutcome(
        EnrollmentVerificationOutcome.Kind.CREATED_RECEIPT, current.receipt);
  }

  @Override
  public synchronized EnrollmentVerificationReceipt recoverVerificationReceipt(
      EnrollmentRecoveryCommand command) {
    State current = find(command);
    return current != null && current.status == EnrollmentStatus.VERIFIED_PENDING_APPLY
        ? current.receipt
        : null;
  }

  @Override
  public synchronized void recordDeliveryOutcome(EnrollmentDeliveryOutcomeCommand command) {
    State current = find(command);
    if (current != null
        && current.generation == command.generation()
        && current.status == EnrollmentStatus.PENDING) {
      if (command.outcome() == EnrollmentDeliveryPort.DeliveryOutcome.PERMANENT_FAILURE) {
        current.status = EnrollmentStatus.EXPIRED;
      }
    }
  }

  @Override
  public synchronized void acknowledgeCompletion(EnrollmentVerificationReceipt receipt) {
    State current = find(receipt);
    if (current != null && current.status == EnrollmentStatus.VERIFIED_PENDING_APPLY) {
      current.status = EnrollmentStatus.COMPLETED;
    }
  }

  @Override
  public synchronized void rejectCompletion(EnrollmentVerificationReceipt receipt) {
    State current = find(receipt);
    if (current != null && current.status == EnrollmentStatus.VERIFIED_PENDING_APPLY) {
      current.status = EnrollmentStatus.REJECTED;
    }
  }

  private EnrollmentStartOutcome created() {
    return new EnrollmentStartOutcome(
        true, state.lifecycleId, state.generation, state.proofExpiresAt);
  }

  private static boolean matches(State value, EnrollmentStartCommand command) {
    return value != null
        && value.canonicalEmail.equals(command.canonicalEmail())
        && value.contextId.equals(command.contextId())
        && value.contextVersion.equals(command.contextVersion())
        && value.audience.equals(command.audience())
        && value.purpose.equals(command.purpose());
  }

  private static boolean matches(State value, EnrollmentVerificationCommand command) {
    return value != null
        && value.canonicalEmail.equals(command.canonicalEmail())
        && value.contextId.equals(command.contextId())
        && value.contextVersion.equals(command.contextVersion())
        && value.audience.equals(command.audience())
        && value.purpose.equals(command.purpose());
  }

  private static boolean matches(State value, EnrollmentRecoveryCommand command) {
    return value != null
        && value.canonicalEmail.equals(command.canonicalEmail())
        && value.contextId.equals(command.contextId())
        && value.contextVersion.equals(command.contextVersion())
        && value.audience.equals(command.audience())
        && value.purpose.equals(command.purpose());
  }

  private static boolean matches(State value, EnrollmentDeliveryOutcomeCommand command) {
    return value != null
        && value.canonicalEmail.equals(command.canonicalEmail())
        && value.contextId.equals(command.contextId())
        && value.contextVersion.equals(command.contextVersion())
        && value.audience.equals(command.audience())
        && value.purpose.equals(command.purpose())
        && value.lifecycleId.equals(command.lifecycleId());
  }

  private State find(EnrollmentStartCommand command) {
    return states.stream()
        .filter(EnrollmentAtomicStoreFake::isCurrent)
        .filter(candidate -> matches(candidate, command))
        .findFirst()
        .orElse(null);
  }

  private State find(EnrollmentVerificationCommand command) {
    return states.stream()
        .filter(EnrollmentAtomicStoreFake::isCurrent)
        .filter(candidate -> matches(candidate, command))
        .findFirst()
        .orElse(null);
  }

  private State find(EnrollmentRecoveryCommand command) {
    return states.stream()
        .filter(EnrollmentAtomicStoreFake::isCurrent)
        .filter(candidate -> matches(candidate, command))
        .findFirst()
        .orElse(null);
  }

  private State find(EnrollmentDeliveryOutcomeCommand command) {
    return states.stream()
        .filter(EnrollmentAtomicStoreFake::isCurrent)
        .filter(candidate -> matches(candidate, command))
        .findFirst()
        .orElse(null);
  }

  private State find(EnrollmentVerificationReceipt receipt) {
    return states.stream()
        .filter(EnrollmentAtomicStoreFake::isCurrent)
        .filter(candidate -> candidate.receipt != null)
        .filter(candidate -> candidate.receipt.receiptId().equals(receipt.receiptId()))
        .findFirst()
        .orElse(null);
  }

  private static boolean isCurrent(State value) {
    return value.status != EnrollmentStatus.SUPERSEDED;
  }

  private static boolean sameStableIdentity(State value, EnrollmentStartCommand command) {
    return value.contextId.equals(command.contextId())
        && value.audience.equals(command.audience())
        && value.purpose.equals(command.purpose());
  }

  private static Instant earliest(Instant first, Instant second) {
    return first.isBefore(second) ? first : second;
  }

  static final class State {
    final String canonicalEmail;
    final String contextId;
    final String contextVersion;
    final String audience;
    final String purpose;
    final UUID lifecycleId;
    final Instant startedAt;
    final Instant totalExpiresAt;
    String proofDigest;
    long generation;
    Instant proofExpiresAt;
    int resends;
    Instant lastSentAt;
    int attempts;
    EnrollmentStatus status;
    EnrollmentVerificationReceipt receipt;

    State(EnrollmentStartCommand command) {
      canonicalEmail = command.canonicalEmail();
      contextId = command.contextId();
      contextVersion = command.contextVersion();
      audience = command.audience();
      purpose = command.purpose();
      lifecycleId = UUID.randomUUID();
      startedAt = command.now();
      totalExpiresAt = command.totalExpiresAt();
      proofDigest = command.proofDigest();
      generation = 1;
      proofExpiresAt = command.proofExpiresAt();
      lastSentAt = command.now();
      status = EnrollmentStatus.PENDING;
    }
  }
}
