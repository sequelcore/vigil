package io.github.sequelcore.vigil.enrollment;

import static org.assertj.core.api.Assertions.assertThat;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
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
 * <p>It proves receipt creation with independent JDBC adapter instances and connections. Hosts must
 * still validate their own store implementation and operational schema.
 */
@Testcontainers(disabledWithoutDocker = true)
class PostgresEnrollmentStoreContractTest {
  private static final String EMAIL = "person@example.test";
  private static final String CONTEXT = "postgres-contract";
  private static final String VERSION = "1";

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
            receipt_id UUID,
            verified_at TIMESTAMPTZ,
            PRIMARY KEY (context_id, audience, purpose)
          )
          """);
    }
  }

  @Test
  void createsOneReceiptAcrossIndependentJdbcAdaptersAndConnections() throws Exception {
    JdbcContractStore firstAdapter = new JdbcContractStore();
    JdbcContractStore secondAdapter = new JdbcContractStore();
    EnrollmentService firstNode = service(firstAdapter);
    EnrollmentService secondNode = service(secondAdapter);
    firstNode.start(new EnrollmentStartRequest(EMAIL, CONTEXT, VERSION));
    String proof = delivery.proof.get();
    assertThat(proof).isNotBlank();

    ExecutorService executor = Executors.newFixedThreadPool(2);
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
    executor.shutdown();

    assertThat(identity.appliedReceiptIds).hasSize(1);
    try (Connection connection = connection();
        PreparedStatement statement =
            connection.prepareStatement("SELECT receipt_id, status FROM enrollment_contract");
        ResultSet result = statement.executeQuery()) {
      assertThat(result.next()).isTrue();
      assertThat(result.getObject("receipt_id", UUID.class))
          .isEqualTo(identity.appliedReceiptIds.iterator().next());
      assertThat(result.getString("status")).isEqualTo(EnrollmentStatus.COMPLETED.name());
    }
  }

  @Test
  void changedEmailAndContextVersionAtomicallySupersedeThePreviousProof() throws Exception {
    EnrollmentService firstNode = service(new JdbcContractStore());
    EnrollmentService secondNode = service(new JdbcContractStore());
    firstNode.start(new EnrollmentStartRequest(EMAIL, CONTEXT, VERSION));
    String previousProof = delivery.proof.get();

    String changedEmail = "changed@example.test";
    String changedVersion = "2";
    secondNode.start(new EnrollmentStartRequest(changedEmail, CONTEXT, changedVersion));
    String currentProof = delivery.proof.get();

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

  private EnrollmentVerificationResult verifyAfterRelease(
      EnrollmentService service, String proof, CountDownLatch ready, CountDownLatch release)
      throws InterruptedException {
    ready.countDown();
    release.await();
    return service.verify(new EnrollmentVerificationRequest(EMAIL, CONTEXT, VERSION, proof));
  }

  private EnrollmentService service(EnrollmentStore store) {
    return new EnrollmentService(
        new EnrollmentProperties(true, "postgres-contract", null, null, 3, 2, null),
        value -> value,
        identity,
        delivery,
        admission -> true,
        store);
  }

  private static Connection connection() throws SQLException {
    return DriverManager.getConnection(
        POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
  }

  private static final class CapturingDelivery implements EnrollmentDeliveryPort {
    private final AtomicReference<String> proof = new AtomicReference<>();

    @Override
    public DeliveryOutcome deliver(EnrollmentDelivery delivery) {
      proof.set(delivery.proof());
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

  private static final class JdbcContractStore implements EnrollmentStore {
    @Override
    public EnrollmentStartOutcome start(EnrollmentStartCommand command) {
      UUID lifecycleId = UUID.randomUUID();
      try (Connection connection = connection();
          PreparedStatement statement =
              connection.prepareStatement(
                  """
                  INSERT INTO enrollment_contract
                    (canonical_email, context_id, context_version, audience, purpose, lifecycle_id,
                     generation, proof_digest, status)
                  VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
                  ON CONFLICT (context_id, audience, purpose) DO UPDATE SET
                    canonical_email = EXCLUDED.canonical_email,
                    context_version = EXCLUDED.context_version,
                    lifecycle_id = EXCLUDED.lifecycle_id,
                    generation = EXCLUDED.generation,
                    proof_digest = EXCLUDED.proof_digest,
                    status = EXCLUDED.status,
                    receipt_id = NULL,
                    verified_at = NULL
                  WHERE enrollment_contract.canonical_email <> EXCLUDED.canonical_email
                    OR enrollment_contract.context_version <> EXCLUDED.context_version
                    OR enrollment_contract.status NOT IN (?, ?)
                  RETURNING lifecycle_id, generation
                  """)) {
        bindKey(statement, command);
        statement.setObject(6, lifecycleId);
        statement.setString(7, command.proofDigest());
        statement.setString(8, EnrollmentStatus.PENDING.name());
        statement.setString(9, EnrollmentStatus.PENDING.name());
        statement.setString(10, EnrollmentStatus.VERIFIED_PENDING_APPLY.name());
        try (ResultSet result = statement.executeQuery()) {
          return result.next()
              ? new EnrollmentStartOutcome(
                  true,
                  result.getObject("lifecycle_id", UUID.class),
                  result.getLong("generation"),
                  command.proofExpiresAt())
              : EnrollmentStartOutcome.notCreated();
        }
      } catch (SQLException exception) {
        throw new IllegalStateException("test contract store failure", exception);
      }
    }

    @Override
    public EnrollmentStartOutcome resend(EnrollmentStartCommand command) {
      return EnrollmentStartOutcome.notCreated();
    }

    @Override
    public EnrollmentVerificationOutcome createVerificationReceipt(
        EnrollmentVerificationCommand command) {
      UUID receiptId = UUID.randomUUID();
      try (Connection connection = connection()) {
        connection.setAutoCommit(false);
        try {
          try (PreparedStatement update =
              connection.prepareStatement(
                  """
                  UPDATE enrollment_contract
                  SET status = ?, receipt_id = ?, verified_at = ?
                  WHERE canonical_email = ? AND context_id = ? AND context_version = ?
                    AND audience = ? AND purpose = ? AND status = ? AND proof_digest = ?
                  RETURNING lifecycle_id, generation
                  """)) {
            update.setString(1, EnrollmentStatus.VERIFIED_PENDING_APPLY.name());
            update.setObject(2, receiptId);
            update.setTimestamp(3, Timestamp.from(command.now()));
            bindKey(update, command, 4);
            update.setString(9, EnrollmentStatus.PENDING.name());
            update.setString(10, command.proofDigest());
            try (ResultSet updated = update.executeQuery()) {
              if (updated.next()) {
                EnrollmentVerificationReceipt receipt =
                    new EnrollmentVerificationReceipt(
                        receiptId,
                        command.canonicalEmail(),
                        command.contextId(),
                        command.contextVersion(),
                        command.audience(),
                        command.purpose(),
                        updated.getObject("lifecycle_id", UUID.class),
                        updated.getLong("generation"),
                        command.now());
                connection.commit();
                return new EnrollmentVerificationOutcome(
                    EnrollmentVerificationOutcome.Kind.CREATED_RECEIPT, receipt);
              }
            }
          }
          EnrollmentVerificationOutcome outcome = existingOutcome(connection, command);
          connection.commit();
          return outcome;
        } catch (SQLException exception) {
          connection.rollback();
          throw exception;
        }
      } catch (SQLException exception) {
        throw new IllegalStateException("test contract store failure", exception);
      }
    }

    @Override
    public EnrollmentVerificationReceipt recoverVerificationReceipt(
        EnrollmentRecoveryCommand command) {
      throw new UnsupportedOperationException("not needed by this contract fixture");
    }

    @Override
    public void recordDeliveryOutcome(EnrollmentDeliveryOutcomeCommand command) {}

    @Override
    public void acknowledgeCompletion(EnrollmentVerificationReceipt receipt) {
      settle(receipt, EnrollmentStatus.COMPLETED);
    }

    @Override
    public void rejectCompletion(EnrollmentVerificationReceipt receipt) {
      settle(receipt, EnrollmentStatus.REJECTED);
    }

    private EnrollmentVerificationOutcome existingOutcome(
        Connection connection, EnrollmentVerificationCommand command) throws SQLException {
      try (PreparedStatement select =
          connection.prepareStatement(
              """
              SELECT lifecycle_id, generation, proof_digest, status, receipt_id, verified_at
              FROM enrollment_contract
              WHERE canonical_email = ? AND context_id = ? AND context_version = ?
                AND audience = ? AND purpose = ?
              """)) {
        bindKey(select, command);
        try (ResultSet result = select.executeQuery()) {
          if (!result.next() || !command.proofDigest().equals(result.getString("proof_digest"))) {
            return EnrollmentVerificationOutcome.rejected();
          }
          EnrollmentStatus status = EnrollmentStatus.valueOf(result.getString("status"));
          if (status == EnrollmentStatus.COMPLETED) {
            return new EnrollmentVerificationOutcome(
                EnrollmentVerificationOutcome.Kind.COMPLETED, null);
          }
          if (status != EnrollmentStatus.VERIFIED_PENDING_APPLY) {
            return EnrollmentVerificationOutcome.rejected();
          }
          EnrollmentVerificationReceipt receipt =
              new EnrollmentVerificationReceipt(
                  result.getObject("receipt_id", UUID.class),
                  command.canonicalEmail(),
                  command.contextId(),
                  command.contextVersion(),
                  command.audience(),
                  command.purpose(),
                  result.getObject("lifecycle_id", UUID.class),
                  result.getLong("generation"),
                  result.getTimestamp("verified_at").toInstant());
          return new EnrollmentVerificationOutcome(
              EnrollmentVerificationOutcome.Kind.EXISTING_RECEIPT, receipt);
        }
      }
    }

    private void settle(EnrollmentVerificationReceipt receipt, EnrollmentStatus target) {
      try (Connection connection = connection();
          PreparedStatement statement =
              connection.prepareStatement(
                  """
                  UPDATE enrollment_contract SET status = ?
                  WHERE lifecycle_id = ? AND receipt_id = ? AND status = ?
                  """)) {
        statement.setString(1, target.name());
        statement.setObject(2, receipt.lifecycleId());
        statement.setObject(3, receipt.receiptId());
        statement.setString(4, EnrollmentStatus.VERIFIED_PENDING_APPLY.name());
        statement.executeUpdate();
      } catch (SQLException exception) {
        throw new IllegalStateException("test contract store failure", exception);
      }
    }

    private static void bindKey(PreparedStatement statement, EnrollmentStartCommand command)
        throws SQLException {
      statement.setString(1, command.canonicalEmail());
      statement.setString(2, command.contextId());
      statement.setString(3, command.contextVersion());
      statement.setString(4, command.audience());
      statement.setString(5, command.purpose());
    }

    private static void bindKey(PreparedStatement statement, EnrollmentVerificationCommand command)
        throws SQLException {
      bindKey(statement, command, 1);
    }

    private static void bindKey(
        PreparedStatement statement, EnrollmentVerificationCommand command, int offset)
        throws SQLException {
      statement.setString(offset, command.canonicalEmail());
      statement.setString(offset + 1, command.contextId());
      statement.setString(offset + 2, command.contextVersion());
      statement.setString(offset + 3, command.audience());
      statement.setString(offset + 4, command.purpose());
    }
  }
}
