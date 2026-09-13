package io.github.sequelcore.vigil.enrollment;

import static org.assertj.core.api.Assertions.assertThat;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Test-only PostgreSQL contract fixture, not a production store or published schema.
 *
 * <p>Hosts must still validate their own store implementation and operational schema.
 */
@Testcontainers(disabledWithoutDocker = true)
class PostgresEnrollmentStoreContractTest {
  private static final String EMAIL = "person@example.test";
  private static final String CONTEXT = "postgres-contract";
  private static final String VERSION = "1";
  private static final String AUDIENCE = "postgres-contract";
  private static final String PURPOSE = "contact-enrollment";
  private static final Instant NOW = Instant.parse("2026-09-12T10:00:00Z");

  @Container
  static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

  private RecordingIdentity identity;
  private CapturingDelivery delivery;

  @BeforeEach
  void createSchema() throws SQLException {
    identity = new RecordingIdentity();
    delivery = new CapturingDelivery();
    try (Connection connection = connection();
        Statement statement = connection.createStatement()) {
      statement.execute("DROP TABLE IF EXISTS enrollment_contract");
      statement.execute(
          """
          CREATE TABLE enrollment_contract (
            canonical_email TEXT NOT NULL,
            context_id TEXT NOT NULL,
            context_version TEXT NOT NULL,
            audience TEXT NOT NULL,
            purpose TEXT NOT NULL,
            lifecycle_id UUID NOT NULL,
            generation BIGINT NOT NULL,
            proof_digest TEXT NOT NULL,
            status TEXT NOT NULL,
            started_at TIMESTAMPTZ NOT NULL,
            total_expires_at TIMESTAMPTZ NOT NULL,
            proof_expires_at TIMESTAMPTZ NOT NULL,
            last_sent_at TIMESTAMPTZ NOT NULL,
            resends INTEGER NOT NULL,
            attempts INTEGER NOT NULL,
            receipt_id UUID,
            verified_at TIMESTAMPTZ,
            PRIMARY KEY (context_id, audience, purpose)
          )
          """);
    }
  }

  @Test
  void createsOneReceiptAcrossIndependentJdbcAdaptersAndConnections() throws Exception {
    EnrollmentService firstNode = service(store());
    EnrollmentService secondNode = service(store());
    firstNode.start(new EnrollmentStartRequest(EMAIL, CONTEXT, VERSION));
    String proof = delivery.value.get().proof();

    ExecutorService executor = Executors.newFixedThreadPool(2);
    try {
      CountDownLatch ready = new CountDownLatch(2);
      CountDownLatch release = new CountDownLatch(1);
      Future<EnrollmentVerificationResult> first =
          executor.submit(() -> verifyAfterRelease(firstNode, proof, ready, release));
      Future<EnrollmentVerificationResult> second =
          executor.submit(() -> verifyAfterRelease(secondNode, proof, ready, release));
      ready.await();
      release.countDown();
      assertThat(first.get()).isEqualTo(EnrollmentVerificationResult.COMPLETED);
      assertThat(second.get()).isEqualTo(EnrollmentVerificationResult.COMPLETED);
    } finally {
      executor.shutdownNow();
    }

    assertThat(identity.appliedReceiptIds).hasSize(1);
    assertThat(storedState().status()).isEqualTo(EnrollmentStatus.COMPLETED);
  }

  @Test
  void changedEmailAndContextVersionAtomicallySupersedeThePreviousProof() throws Exception {
    EnrollmentService firstNode = service(store());
    EnrollmentService secondNode = service(store());
    firstNode.start(new EnrollmentStartRequest(EMAIL, CONTEXT, VERSION));
    String previousProof = delivery.value.get().proof();

    String changedEmail = "changed@example.test";
    String changedVersion = "2";
    secondNode.start(new EnrollmentStartRequest(changedEmail, CONTEXT, changedVersion));
    String currentProof = delivery.value.get().proof();

    assertThat(
            firstNode.verify(
                new EnrollmentVerificationRequest(EMAIL, CONTEXT, VERSION, previousProof)))
        .isEqualTo(EnrollmentVerificationResult.REJECTED);
    assertThat(
            secondNode.verify(
                new EnrollmentVerificationRequest(
                    changedEmail, CONTEXT, changedVersion, currentProof)))
        .isEqualTo(EnrollmentVerificationResult.COMPLETED);
    try (Connection connection = connection();
        PreparedStatement statement =
            connection.prepareStatement(
                "SELECT canonical_email, context_version, status FROM enrollment_contract");
        ResultSet result = statement.executeQuery()) {
      assertThat(result.next()).isTrue();
      assertThat(result.getString("canonical_email")).isEqualTo(changedEmail);
      assertThat(result.getString("context_version")).isEqualTo(changedVersion);
      assertThat(result.getString("status")).isEqualTo(EnrollmentStatus.COMPLETED.name());
      assertThat(result.next()).isFalse();
    }
  }

  @Test
  void resendRotatesTheProofWithoutResettingAttemptsOrTotalLifetime() {
    EnrollmentStore store = store();
    EnrollmentProofCodec codec = codec();
    Instant totalExpiresAt = NOW.plus(Duration.ofHours(1));
    store.start(startCommand(codec, "11111111", NOW, totalExpiresAt));
    assertThat(store.createVerificationReceipt(verifyCommand(codec, "99999999", NOW, 3)).kind())
        .isEqualTo(EnrollmentVerificationOutcome.Kind.REJECTED);

    Instant resendAt = NOW.plusSeconds(30);
    EnrollmentStartOutcome resent =
        store.resend(startCommand(codec, "22222222", resendAt, totalExpiresAt));
    assertThat(resent.created()).isTrue();
    assertThat(resent.generation()).isEqualTo(2);
    assertThat(
            store.createVerificationReceipt(verifyCommand(codec, "11111111", resendAt, 3)).kind())
        .isEqualTo(EnrollmentVerificationOutcome.Kind.REJECTED);
    assertThat(
            store.createVerificationReceipt(verifyCommand(codec, "88888888", resendAt, 3)).kind())
        .isEqualTo(EnrollmentVerificationOutcome.Kind.REJECTED);
    assertThat(
            store.createVerificationReceipt(verifyCommand(codec, "22222222", resendAt, 3)).kind())
        .isEqualTo(EnrollmentVerificationOutcome.Kind.REJECTED);

    StoredState state = storedState();
    assertThat(state.generation()).isEqualTo(2);
    assertThat(state.attempts()).isEqualTo(3);
    assertThat(state.status()).isEqualTo(EnrollmentStatus.EXPIRED);
    assertThat(state.totalExpiresAt()).isEqualTo(totalExpiresAt);
  }

  @Test
  void exactProofExpiryBoundaryRejectsAndExpiresTheEnrollment() {
    EnrollmentStore store = store();
    EnrollmentProofCodec codec = codec();
    store.start(startCommand(codec, "11111111", NOW, NOW.plus(Duration.ofHours(1))));

    EnrollmentVerificationOutcome outcome =
        store.createVerificationReceipt(
            verifyCommand(codec, "11111111", NOW.plus(Duration.ofMinutes(15)), 3));

    assertThat(outcome.kind()).isEqualTo(EnrollmentVerificationOutcome.Kind.REJECTED);
    assertThat(storedState().status()).isEqualTo(EnrollmentStatus.EXPIRED);
  }

  @Test
  void concurrentWrongAttemptsAtomicallyExhaustTheSharedBudget() throws Exception {
    EnrollmentProofCodec codec = codec();
    store().start(startCommand(codec, "11111111", NOW, NOW.plus(Duration.ofHours(1))));
    EnrollmentVerificationCommand firstWrong = verifyCommand(codec, "22222222", NOW, 2);
    EnrollmentVerificationCommand secondWrong = verifyCommand(codec, "33333333", NOW, 2);

    ExecutorService executor = Executors.newFixedThreadPool(2);
    try {
      CountDownLatch ready = new CountDownLatch(2);
      CountDownLatch release = new CountDownLatch(1);
      Future<EnrollmentVerificationOutcome> first =
          executor.submit(() -> verifyAfterRelease(store(), firstWrong, ready, release));
      Future<EnrollmentVerificationOutcome> second =
          executor.submit(() -> verifyAfterRelease(store(), secondWrong, ready, release));
      ready.await();
      release.countDown();
      assertThat(first.get().kind()).isEqualTo(EnrollmentVerificationOutcome.Kind.REJECTED);
      assertThat(second.get().kind()).isEqualTo(EnrollmentVerificationOutcome.Kind.REJECTED);
    } finally {
      executor.shutdownNow();
    }

    StoredState state = storedState();
    assertThat(state.attempts()).isEqualTo(2);
    assertThat(state.status()).isEqualTo(EnrollmentStatus.EXPIRED);
    assertThat(store().createVerificationReceipt(verifyCommand(codec, "11111111", NOW, 2)).kind())
        .isEqualTo(EnrollmentVerificationOutcome.Kind.REJECTED);
  }

  @Test
  void concurrentResendAndVerifyProduceOneSerializedLifecycle() throws Exception {
    EnrollmentProofCodec codec = codec();
    Instant totalExpiresAt = NOW.plus(Duration.ofHours(1));
    store().start(startCommand(codec, "11111111", NOW, totalExpiresAt));
    EnrollmentStartCommand resend =
        startCommand(codec, "22222222", NOW.plusSeconds(30), totalExpiresAt);
    EnrollmentVerificationCommand verify = verifyCommand(codec, "11111111", NOW.plusSeconds(30), 3);

    ExecutorService executor = Executors.newFixedThreadPool(2);
    EnrollmentStartOutcome resendOutcome;
    EnrollmentVerificationOutcome verifyOutcome;
    try {
      CountDownLatch ready = new CountDownLatch(2);
      CountDownLatch release = new CountDownLatch(1);
      Future<EnrollmentStartOutcome> resendFuture =
          executor.submit(
              () -> {
                ready.countDown();
                release.await();
                return store().resend(resend);
              });
      Future<EnrollmentVerificationOutcome> verifyFuture =
          executor.submit(() -> verifyAfterRelease(store(), verify, ready, release));
      ready.await();
      release.countDown();
      resendOutcome = resendFuture.get();
      verifyOutcome = verifyFuture.get();
    } finally {
      executor.shutdownNow();
    }

    StoredState state = storedState();
    boolean verificationWon =
        !resendOutcome.created()
            && verifyOutcome.kind() == EnrollmentVerificationOutcome.Kind.CREATED_RECEIPT
            && state.generation() == 1
            && state.status() == EnrollmentStatus.VERIFIED_PENDING_APPLY;
    boolean resendWon =
        resendOutcome.created()
            && verifyOutcome.kind() == EnrollmentVerificationOutcome.Kind.REJECTED
            && state.generation() == 2
            && state.attempts() == 1
            && state.status() == EnrollmentStatus.PENDING;
    assertThat(verificationWon || resendWon).isTrue();
  }

  private EnrollmentVerificationResult verifyAfterRelease(
      EnrollmentService service, String proof, CountDownLatch ready, CountDownLatch release)
      throws InterruptedException {
    ready.countDown();
    release.await();
    return service.verify(new EnrollmentVerificationRequest(EMAIL, CONTEXT, VERSION, proof));
  }

  private static EnrollmentVerificationOutcome verifyAfterRelease(
      EnrollmentStore store,
      EnrollmentVerificationCommand command,
      CountDownLatch ready,
      CountDownLatch release)
      throws InterruptedException {
    ready.countDown();
    release.await();
    return store.createVerificationReceipt(command);
  }

  private EnrollmentService service(EnrollmentStore store) {
    return new EnrollmentService(
        EnrollmentTestProperties.decimalCode(AUDIENCE, 3),
        value -> value,
        identity,
        delivery,
        admission -> true,
        store,
        Clock.fixed(NOW, ZoneOffset.UTC));
  }

  private static EnrollmentStore store() {
    return new PostgresEnrollmentStoreFixture(PostgresEnrollmentStoreContractTest::connection);
  }

  private static EnrollmentProofCodec codec() {
    return new EnrollmentProofCodec(EnrollmentTestProperties.decimalCode(AUDIENCE, 3));
  }

  private static EnrollmentStartCommand startCommand(
      EnrollmentProofCodec codec, String proof, Instant now, Instant totalExpiresAt) {
    return new EnrollmentStartCommand(
        EMAIL,
        CONTEXT,
        VERSION,
        AUDIENCE,
        PURPOSE,
        codec.digest(proof, EMAIL, CONTEXT, VERSION, AUDIENCE, PURPOSE),
        now,
        now.plus(Duration.ofMinutes(15)),
        totalExpiresAt,
        2,
        Duration.ZERO);
  }

  private static EnrollmentVerificationCommand verifyCommand(
      EnrollmentProofCodec codec, String proof, Instant now, int attemptLimit) {
    return new EnrollmentVerificationCommand(
        EMAIL,
        CONTEXT,
        VERSION,
        AUDIENCE,
        PURPOSE,
        codec.digest(proof, EMAIL, CONTEXT, VERSION, AUDIENCE, PURPOSE),
        now,
        attemptLimit);
  }

  private static StoredState storedState() {
    try (Connection connection = connection();
        PreparedStatement statement =
            connection.prepareStatement(
                "SELECT generation, attempts, status, total_expires_at FROM enrollment_contract");
        ResultSet result = statement.executeQuery()) {
      assertThat(result.next()).isTrue();
      return new StoredState(
          result.getLong("generation"),
          result.getInt("attempts"),
          EnrollmentStatus.valueOf(result.getString("status")),
          result.getTimestamp("total_expires_at").toInstant());
    } catch (SQLException exception) {
      throw new IllegalStateException("test contract state read failed", exception);
    }
  }

  private static Connection connection() throws SQLException {
    return DriverManager.getConnection(
        POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
  }

  private record StoredState(
      long generation, int attempts, EnrollmentStatus status, Instant totalExpiresAt) {}

  private static final class CapturingDelivery implements EnrollmentDeliveryPort {
    private final AtomicReference<EnrollmentDelivery> value = new AtomicReference<>();

    @Override
    public DeliveryOutcome deliver(EnrollmentDelivery delivery) {
      value.set(delivery);
      return DeliveryOutcome.ACCEPTED;
    }
  }

  private static final class RecordingIdentity implements EnrollmentIdentityPort {
    private final Set<UUID> appliedReceiptIds = java.util.concurrent.ConcurrentHashMap.newKeySet();

    @Override
    public ApplyOutcome applyVerifiedContact(EnrollmentVerificationReceipt receipt) {
      appliedReceiptIds.add(receipt.receiptId());
      return ApplyOutcome.APPLIED;
    }
  }
}
