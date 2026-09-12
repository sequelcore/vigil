package io.github.sequelcore.vigil.enrollment;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.sequelcore.vigil.auth.VigilResetTokenService;
import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import io.github.sequelcore.vigil.blacklist.VigilBlacklistService;
import io.github.sequelcore.vigil.core.jwt.HmacTokenSigner;
import io.github.sequelcore.vigil.core.jwt.VigilTokenService;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class EnrollmentServiceTest {
  private static final String EMAIL = "Person@Example.test";
  private static final String CANONICAL_EMAIL = "person@example.test";
  private static final String CONTEXT = "invite-42";
  private static final String VERSION = "v3";
  private static final String JWT_SECRET =
      "enrollment-reset-test-secret-with-at-least-32-characters";
  private final MutableClock clock = new MutableClock(Instant.parse("2026-09-12T10:00:00Z"));
  private EnrollmentAtomicStoreFake store;
  private CapturingDelivery delivery;
  private RecordingIdentity identity;
  private EnrollmentAbuseControl abuseControl;
  private EnrollmentService service;

  @BeforeEach
  void setUp() {
    store = new EnrollmentAtomicStoreFake();
    delivery = new CapturingDelivery(EnrollmentDeliveryPort.DeliveryOutcome.ACCEPTED);
    identity = new RecordingIdentity();
    abuseControl = admission -> true;
    service = newService();
  }

  @Test
  void deliversOriginalAddressButStoresOnlyCanonicalDigest() {
    service.start(start());
    EnrollmentDelivery sent = delivery.latest();
    assertThat(sent.originalEmail()).isEqualTo(EMAIL);
    assertThat(sent.canonicalEmail()).isEqualTo(CANONICAL_EMAIL);
    assertThat(store.state.canonicalEmail).isEqualTo(CANONICAL_EMAIL);
    assertThat(store.state.proofDigest).isEqualTo(domainDigest(sent.proof()));
    assertThat(store.state.proofDigest).isNotEqualTo(sent.proof());
    assertThat(sent.toString()).doesNotContain(EMAIL).doesNotContain(sent.proof());
  }

  @Test
  void verifiesOnlyAfterCorrectBindingAndReplaysCompletionWithoutApplyingTwice() {
    service.start(start());
    String proof = delivery.latest().proof();
    assertThat(service.verify(new EnrollmentVerificationRequest(EMAIL, CONTEXT, "other", proof)))
        .isEqualTo(EnrollmentVerificationResult.REJECTED);
    assertThat(identity.receipts).isEmpty();
    assertThat(service.verify(verify(proof))).isEqualTo(EnrollmentVerificationResult.COMPLETED);
    assertThat(service.verify(verify(proof))).isEqualTo(EnrollmentVerificationResult.COMPLETED);
    assertThat(identity.receipts).hasSize(1);
  }

  @Test
  void rejectsMissingOrBlankContextBindingsBeforeStoreAccess() {
    int before = store.verificationCalls;

    assertThat(service.start(new EnrollmentStartRequest(EMAIL, " ", VERSION)))
        .isEqualTo(EnrollmentRequestResult.ACCEPTED);
    assertThat(
            service.verify(new EnrollmentVerificationRequest(EMAIL, CONTEXT, null, wrongProof())))
        .isEqualTo(EnrollmentVerificationResult.REJECTED);
    assertThat(service.recover(new EnrollmentRecoveryRequest(EMAIL, null, VERSION)))
        .isEqualTo(EnrollmentVerificationResult.REJECTED);

    assertThat(store.state).isNull();
    assertThat(store.verificationCalls).isEqualTo(before);
  }

  @Test
  void rejectsExpiredAndAttemptExhaustedProofs() {
    service.start(start());
    String expired = delivery.latest().proof();
    clock.advance(Duration.ofMinutes(16));
    assertThat(service.verify(verify(expired))).isEqualTo(EnrollmentVerificationResult.REJECTED);
    setUp();
    service.start(start());
    for (int attempt = 0; attempt < 3; attempt++) {
      assertThat(service.verify(verify(wrongProof())))
          .isEqualTo(EnrollmentVerificationResult.REJECTED);
    }
    assertThat(service.verify(verify(delivery.latest().proof())))
        .isEqualTo(EnrollmentVerificationResult.REJECTED);
  }

  @Test
  void rejectsMalformedProofsAndDeniedVerificationBeforeStoreAccess() {
    service.start(start());
    int before = store.verificationCalls;
    assertThat(service.verify(verify("bad"))).isEqualTo(EnrollmentVerificationResult.REJECTED);
    assertThat(service.verify(verify("a".repeat(44))))
        .isEqualTo(EnrollmentVerificationResult.REJECTED);
    assertThat(service.verify(verify(resetToken())))
        .isEqualTo(EnrollmentVerificationResult.REJECTED);
    abuseControl = admission -> false;
    service = newService();
    assertThat(service.verify(verify(delivery.latest().proof())))
        .isEqualTo(EnrollmentVerificationResult.REJECTED);
    abuseControl =
        admission -> {
          throw new IllegalStateException("abuse service unavailable");
        };
    service = newService();
    assertThat(service.verify(verify(delivery.latest().proof())))
        .isEqualTo(EnrollmentVerificationResult.REJECTED);
    assertThat(store.verificationCalls).isEqualTo(before);
    assertThat(identity.receipts).isEmpty();
  }

  @Test
  void resendRotatesProofAndDuplicateStartCannotResetLifecycleOrLimits() {
    service.start(start());
    EnrollmentDelivery first = delivery.latest();
    Instant startedAt = store.state.startedAt;
    Instant totalExpiresAt = store.state.totalExpiresAt;
    UUID lifecycleId = store.state.lifecycleId;
    service.verify(verify(wrongProof()));
    int attempts = store.state.attempts;
    service.start(start());
    assertThat(delivery.deliveries).hasSize(1);
    assertThat(store.state.startedAt).isEqualTo(startedAt);
    assertThat(store.state.totalExpiresAt).isEqualTo(totalExpiresAt);
    assertThat(store.state.lifecycleId).isEqualTo(lifecycleId);
    assertThat(store.state.attempts).isEqualTo(attempts);
    clock.advance(Duration.ofMinutes(1));
    service.resend(start());
    EnrollmentDelivery second = delivery.latest();
    assertThat(service.verify(verify(first.proof())))
        .isEqualTo(EnrollmentVerificationResult.REJECTED);
    assertThat(service.verify(verify(second.proof())))
        .isEqualTo(EnrollmentVerificationResult.COMPLETED);
    setUp();
    service.start(start());
    clock.advance(Duration.ofMinutes(1));
    service.resend(start());
    clock.advance(Duration.ofMinutes(1));
    service.resend(start());
    service.start(start());
    clock.advance(Duration.ofMinutes(1));
    service.resend(start());
    assertThat(delivery.deliveries).hasSize(3);
    assertThat(store.state.resends).isEqualTo(2);
  }

  @Test
  void emailChangeSupersedesThePreviousAddressAndContextVersion() {
    service.start(start());
    String previousProof = delivery.latest().proof();
    EnrollmentAtomicStoreFake.State previousLifecycle = store.state;
    String changedEmail = "changed@example.test";
    service.start(new EnrollmentStartRequest(changedEmail, CONTEXT, "v4"));
    String changedProof = delivery.latest().proof();

    assertThat(store.states).hasSize(2);
    assertThat(previousLifecycle.status).isEqualTo(EnrollmentStatus.SUPERSEDED);
    assertThat(service.verify(verify(previousProof)))
        .isEqualTo(EnrollmentVerificationResult.REJECTED);
    assertThat(
            service.verify(
                new EnrollmentVerificationRequest(changedEmail, CONTEXT, "v4", changedProof)))
        .isEqualTo(EnrollmentVerificationResult.COMPLETED);
  }

  @Test
  void totalLifecycleCutoffBoundsResendAndVerification() {
    service.start(start());
    clock.advance(Duration.ofHours(23).plusMinutes(59));
    service.resend(start());
    String finalProof = delivery.latest().proof();
    assertThat(store.state.proofExpiresAt).isEqualTo(store.state.totalExpiresAt);

    clock.advance(Duration.ofMinutes(1));
    service.resend(start());

    assertThat(delivery.deliveries).hasSize(2);
    assertThat(service.verify(verify(finalProof))).isEqualTo(EnrollmentVerificationResult.REJECTED);
    assertThat(store.state.status).isEqualTo(EnrollmentStatus.EXPIRED);
  }

  @Test
  void ignoresLateOutcomesFromAnEarlierLifecycle() {
    delivery.outcome = EnrollmentDeliveryPort.DeliveryOutcome.PERMANENT_FAILURE;
    service.start(start());
    EnrollmentDelivery stale = delivery.latest();
    delivery.outcome = EnrollmentDeliveryPort.DeliveryOutcome.ACCEPTED;
    service.start(start());
    EnrollmentDelivery current = delivery.latest();
    store.recordDeliveryOutcome(
        outcome(stale, EnrollmentDeliveryPort.DeliveryOutcome.PERMANENT_FAILURE));
    assertThat(current.lifecycleId()).isNotEqualTo(stale.lifecycleId());
    assertThat(store.state.status).isEqualTo(EnrollmentStatus.PENDING);
    assertThat(service.verify(verify(current.proof())))
        .isEqualTo(EnrollmentVerificationResult.COMPLETED);
  }

  @Test
  void ignoresLatePermanentDeliveryAfterVerificationOrCompletion() {
    service.start(start());
    EnrollmentDelivery deliveryRecord = delivery.latest();
    assertThat(service.verify(verify(deliveryRecord.proof())))
        .isEqualTo(EnrollmentVerificationResult.COMPLETED);
    store.recordDeliveryOutcome(
        outcome(deliveryRecord, EnrollmentDeliveryPort.DeliveryOutcome.PERMANENT_FAILURE));
    assertThat(store.state.status).isEqualTo(EnrollmentStatus.COMPLETED);

    setUp();
    identity.fail = true;
    service.start(start());
    deliveryRecord = delivery.latest();
    assertThat(service.verify(verify(deliveryRecord.proof())))
        .isEqualTo(EnrollmentVerificationResult.PENDING_RECOVERY);
    store.recordDeliveryOutcome(
        outcome(deliveryRecord, EnrollmentDeliveryPort.DeliveryOutcome.PERMANENT_FAILURE));
    assertThat(store.state.status).isEqualTo(EnrollmentStatus.VERIFIED_PENDING_APPLY);
    identity.fail = false;
    assertThat(service.recover(new EnrollmentRecoveryRequest(EMAIL, CONTEXT, VERSION)))
        .isEqualTo(EnrollmentVerificationResult.COMPLETED);
  }

  @Test
  void rejectsWrongProofAfterReceiptCreationAndCompletion() {
    service.start(start());
    String proof = delivery.latest().proof();
    identity.fail = true;
    assertThat(service.verify(verify(proof)))
        .isEqualTo(EnrollmentVerificationResult.PENDING_RECOVERY);
    identity.fail = false;
    assertThat(service.verify(verify(wrongProof())))
        .isEqualTo(EnrollmentVerificationResult.REJECTED);
    assertThat(service.recover(new EnrollmentRecoveryRequest(EMAIL, CONTEXT, VERSION)))
        .isEqualTo(EnrollmentVerificationResult.COMPLETED);
    assertThat(service.verify(verify(wrongProof())))
        .isEqualTo(EnrollmentVerificationResult.REJECTED);
    assertThat(identity.receipts).hasSize(1);
  }

  @Test
  void retryableAndExceptionalDeliveryLeaveTheProofVerifiable() {
    delivery.outcome = EnrollmentDeliveryPort.DeliveryOutcome.RETRYABLE_FAILURE;
    service.start(start());
    assertThat(service.verify(verify(delivery.latest().proof())))
        .isEqualTo(EnrollmentVerificationResult.COMPLETED);

    setUp();
    delivery.throwException = true;
    service.start(start());
    assertThat(service.verify(verify(delivery.latest().proof())))
        .isEqualTo(EnrollmentVerificationResult.COMPLETED);
  }

  @Test
  void createsOneReceiptConcurrentlyAndRecoversTheSameReceipt() throws Exception {
    service.start(start());
    String proof = delivery.latest().proof();
    ExecutorService executor = Executors.newFixedThreadPool(2);
    CountDownLatch ready = new CountDownLatch(2);
    CountDownLatch release = new CountDownLatch(1);
    EnrollmentService secondNode = newService();
    executor.submit(() -> verifyWhenReleased(service, ready, release, proof));
    executor.submit(() -> verifyWhenReleased(secondNode, ready, release, proof));
    ready.await();
    release.countDown();
    executor.shutdown();
    while (!executor.isTerminated()) {
      Thread.onSpinWait();
    }
    assertThat(store.createdReceiptIds).hasSize(1);
    setUp();
    identity.fail = true;
    service.start(start());
    String recoveryProof = delivery.latest().proof();
    assertThat(service.verify(verify(recoveryProof)))
        .isEqualTo(EnrollmentVerificationResult.PENDING_RECOVERY);
    UUID receiptId = store.state.receipt.receiptId();
    identity.fail = false;
    assertThat(service.recover(new EnrollmentRecoveryRequest(EMAIL, CONTEXT, VERSION)))
        .isEqualTo(EnrollmentVerificationResult.COMPLETED);
    assertThat(store.state.receipt.receiptId()).isEqualTo(receiptId);
  }

  private void verifyWhenReleased(
      EnrollmentService node, CountDownLatch ready, CountDownLatch release, String proof) {
    try {
      ready.countDown();
      release.await();
      node.verify(verify(proof));
    } catch (InterruptedException exception) {
      Thread.currentThread().interrupt();
    }
  }

  private EnrollmentService newService() {
    return new EnrollmentService(
        new EnrollmentProperties(true, "vigil-test", null, null, 3, 2, null),
        value -> value.trim().toLowerCase(java.util.Locale.ROOT),
        identity,
        delivery,
        abuseControl,
        store,
        clock);
  }

  private static EnrollmentStartRequest start() {
    return new EnrollmentStartRequest(EMAIL, CONTEXT, VERSION);
  }

  private static EnrollmentVerificationRequest verify(String proof) {
    return new EnrollmentVerificationRequest(EMAIL, CONTEXT, VERSION, proof);
  }

  private static EnrollmentDeliveryOutcomeCommand outcome(
      EnrollmentDelivery delivery, EnrollmentDeliveryPort.DeliveryOutcome value) {
    return new EnrollmentDeliveryOutcomeCommand(
        delivery.canonicalEmail(),
        delivery.contextId(),
        delivery.contextVersion(),
        delivery.audience(),
        delivery.purpose(),
        delivery.lifecycleId(),
        delivery.generation(),
        value);
  }

  private static String wrongProof() {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]);
  }

  private static String domainDigest(String proof) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      digest.update("vigil.enrollment.proof.v1\u0000".getBytes(StandardCharsets.UTF_8));
      digest.update(proof.getBytes(StandardCharsets.UTF_8));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(digest.digest());
    } catch (Exception exception) {
      throw new AssertionError(exception);
    }
  }

  private static String resetToken() {
    VigilProperties.Jwt jwt =
        new VigilProperties.Jwt(
            JWT_SECRET,
            Duration.ofMinutes(15),
            Duration.ofDays(7),
            null,
            null,
            null,
            null,
            null,
            null,
            null);
    VigilBlacklistService blacklist =
        new VigilBlacklistService(
            new VigilProperties.Blacklist(100, Duration.ofHours(1), Duration.ZERO));
    VigilTokenService tokens =
        new VigilTokenService(new HmacTokenSigner(JWT_SECRET), jwt, blacklist);
    return new VigilResetTokenService(
            tokens, blacklist, new VigilProperties.Reset(Duration.ofMinutes(10)))
        .generate(EMAIL);
  }

  private static final class RecordingIdentity implements EnrollmentIdentityPort {
    private final List<EnrollmentVerificationReceipt> receipts = new ArrayList<>();
    private boolean fail;

    @Override
    public synchronized EnrollmentIdentityPort.ApplyOutcome applyVerifiedContact(
        EnrollmentVerificationReceipt receipt) {
      if (fail) {
        throw new IllegalStateException("host unavailable");
      }
      if (receipts.stream().noneMatch(value -> value.receiptId().equals(receipt.receiptId()))) {
        receipts.add(receipt);
      }
      return EnrollmentIdentityPort.ApplyOutcome.APPLIED;
    }
  }

  private static final class CapturingDelivery implements EnrollmentDeliveryPort {
    private final List<EnrollmentDelivery> deliveries = new ArrayList<>();
    private DeliveryOutcome outcome;
    private boolean throwException;

    private CapturingDelivery(DeliveryOutcome outcome) {
      this.outcome = outcome;
    }

    @Override
    public DeliveryOutcome deliver(EnrollmentDelivery value) {
      deliveries.add(value);
      if (throwException) {
        throw new IllegalStateException("delivery unavailable");
      }
      return outcome;
    }

    private EnrollmentDelivery latest() {
      return deliveries.getLast();
    }
  }

  private static final class MutableClock extends Clock {
    private Instant instant;

    private MutableClock(Instant instant) {
      this.instant = instant;
    }

    @Override
    public ZoneOffset getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(java.time.ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return instant;
    }

    private void advance(Duration duration) {
      instant = instant.plus(duration);
    }
  }
}
