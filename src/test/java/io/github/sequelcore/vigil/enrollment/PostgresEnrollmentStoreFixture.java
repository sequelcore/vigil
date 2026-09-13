package io.github.sequelcore.vigil.enrollment;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;

/** Test-only durable store used to exercise the enrollment contract against PostgreSQL. */
final class PostgresEnrollmentStoreFixture implements EnrollmentStore {
  private final ConnectionFactory connections;

  PostgresEnrollmentStoreFixture(ConnectionFactory connections) {
    this.connections = connections;
  }

  @Override
  public EnrollmentStartOutcome start(EnrollmentStartCommand command) {
    UUID lifecycleId = UUID.randomUUID();
    try (Connection connection = connections.open();
        PreparedStatement statement =
            connection.prepareStatement(
                """
                INSERT INTO enrollment_contract
                  (canonical_email, context_id, context_version, audience, purpose, lifecycle_id,
                   generation, proof_digest, status, started_at, total_expires_at,
                   proof_expires_at, last_sent_at, resends, attempts)
                 VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, 0, 0)
                ON CONFLICT (context_id, audience, purpose) DO UPDATE SET
                  canonical_email = EXCLUDED.canonical_email,
                  context_version = EXCLUDED.context_version,
                  lifecycle_id = EXCLUDED.lifecycle_id,
                  generation = EXCLUDED.generation,
                  proof_digest = EXCLUDED.proof_digest,
                  status = EXCLUDED.status,
                  started_at = EXCLUDED.started_at,
                  total_expires_at = EXCLUDED.total_expires_at,
                  proof_expires_at = EXCLUDED.proof_expires_at,
                  last_sent_at = EXCLUDED.last_sent_at,
                  resends = 0,
                  attempts = 0,
                  receipt_id = NULL,
                  verified_at = NULL
                 WHERE enrollment_contract.canonical_email <> EXCLUDED.canonical_email
                  OR enrollment_contract.context_version <> EXCLUDED.context_version
                  OR enrollment_contract.status NOT IN (?, ?)
                RETURNING lifecycle_id, generation
                """)) {
      bindKey(statement, command, 1);
      statement.setObject(6, lifecycleId);
      statement.setString(7, command.proofDigest());
      statement.setString(8, EnrollmentStatus.PENDING.name());
      statement.setTimestamp(9, Timestamp.from(command.now()));
      statement.setTimestamp(10, Timestamp.from(command.totalExpiresAt()));
      statement.setTimestamp(11, Timestamp.from(command.proofExpiresAt()));
      statement.setTimestamp(12, Timestamp.from(command.now()));
      statement.setString(13, EnrollmentStatus.PENDING.name());
      statement.setString(14, EnrollmentStatus.VERIFIED_PENDING_APPLY.name());
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
      throw failure(exception);
    }
  }

  @Override
  public EnrollmentStartOutcome resend(EnrollmentStartCommand command) {
    try (Connection connection = connections.open();
        PreparedStatement statement =
            connection.prepareStatement(
                """
                UPDATE enrollment_contract SET
                  generation = generation + 1,
                  proof_digest = ?,
                  proof_expires_at = LEAST(?, total_expires_at),
                  last_sent_at = ?,
                  resends = resends + 1
                WHERE canonical_email = ? AND context_id = ? AND context_version = ?
                  AND audience = ? AND purpose = ? AND status = ?
                  AND ? < total_expires_at AND resends < ?
                  AND ? >= last_sent_at + (? * INTERVAL '1 millisecond')
                RETURNING lifecycle_id, generation, proof_expires_at
                """)) {
      statement.setString(1, command.proofDigest());
      statement.setTimestamp(2, Timestamp.from(command.proofExpiresAt()));
      statement.setTimestamp(3, Timestamp.from(command.now()));
      bindKey(statement, command, 4);
      statement.setString(9, EnrollmentStatus.PENDING.name());
      statement.setTimestamp(10, Timestamp.from(command.now()));
      statement.setInt(11, command.resendLimit());
      statement.setTimestamp(12, Timestamp.from(command.now()));
      statement.setLong(13, command.resendCooldown().toMillis());
      try (ResultSet result = statement.executeQuery()) {
        return result.next()
            ? new EnrollmentStartOutcome(
                true,
                result.getObject("lifecycle_id", UUID.class),
                result.getLong("generation"),
                result.getTimestamp("proof_expires_at").toInstant())
            : EnrollmentStartOutcome.notCreated();
      }
    } catch (SQLException exception) {
      throw failure(exception);
    }
  }

  @Override
  public EnrollmentVerificationOutcome createVerificationReceipt(
      EnrollmentVerificationCommand command) {
    UUID receiptId = UUID.randomUUID();
    try (Connection connection = connections.open()) {
      connection.setAutoCommit(false);
      try {
        EnrollmentVerificationOutcome outcome = verifyLocked(connection, command, receiptId);
        connection.commit();
        return outcome;
      } catch (SQLException exception) {
        connection.rollback();
        throw exception;
      }
    } catch (SQLException exception) {
      throw failure(exception);
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

  private EnrollmentVerificationOutcome verifyLocked(
      Connection connection, EnrollmentVerificationCommand command, UUID receiptId)
      throws SQLException {
    try (PreparedStatement select =
        connection.prepareStatement(
            """
            SELECT lifecycle_id, generation, proof_digest, status, receipt_id, verified_at,
              proof_expires_at, total_expires_at, attempts
            FROM enrollment_contract
            WHERE canonical_email = ? AND context_id = ? AND context_version = ?
              AND audience = ? AND purpose = ?
            FOR UPDATE
            """)) {
      bindKey(select, command, 1);
      try (ResultSet result = select.executeQuery()) {
        if (!result.next()) {
          return EnrollmentVerificationOutcome.rejected();
        }
        EnrollmentStatus status = EnrollmentStatus.valueOf(result.getString("status"));
        if (!command.proofDigest().equals(result.getString("proof_digest"))) {
          recordFailedAttempt(connection, command, result.getInt("attempts"), status);
          return EnrollmentVerificationOutcome.rejected();
        }
        if (status == EnrollmentStatus.COMPLETED) {
          return new EnrollmentVerificationOutcome(
              EnrollmentVerificationOutcome.Kind.COMPLETED, null);
        }
        if (status == EnrollmentStatus.VERIFIED_PENDING_APPLY) {
          return new EnrollmentVerificationOutcome(
              EnrollmentVerificationOutcome.Kind.EXISTING_RECEIPT,
              receipt(command, result, result.getObject("receipt_id", UUID.class)));
        }
        if (status != EnrollmentStatus.PENDING
            || result.getInt("attempts") >= command.attemptLimit()
            || !command.now().isBefore(result.getTimestamp("proof_expires_at").toInstant())
            || !command.now().isBefore(result.getTimestamp("total_expires_at").toInstant())) {
          expire(connection, command);
          return EnrollmentVerificationOutcome.rejected();
        }
        createReceipt(connection, command, receiptId);
        return new EnrollmentVerificationOutcome(
            EnrollmentVerificationOutcome.Kind.CREATED_RECEIPT,
            receipt(command, result, receiptId));
      }
    }
  }

  private static void createReceipt(
      Connection connection, EnrollmentVerificationCommand command, UUID receiptId)
      throws SQLException {
    try (PreparedStatement update =
        connection.prepareStatement(
            """
            UPDATE enrollment_contract SET status = ?, receipt_id = ?, verified_at = ?
            WHERE context_id = ? AND audience = ? AND purpose = ?
            """)) {
      update.setString(1, EnrollmentStatus.VERIFIED_PENDING_APPLY.name());
      update.setObject(2, receiptId);
      update.setTimestamp(3, Timestamp.from(command.now()));
      update.setString(4, command.contextId());
      update.setString(5, command.audience());
      update.setString(6, command.purpose());
      update.executeUpdate();
    }
  }

  private static EnrollmentVerificationReceipt receipt(
      EnrollmentVerificationCommand command, ResultSet result, UUID receiptId) throws SQLException {
    Instant verifiedAt =
        result.getTimestamp("verified_at") == null
            ? command.now()
            : result.getTimestamp("verified_at").toInstant();
    return new EnrollmentVerificationReceipt(
        receiptId,
        command.canonicalEmail(),
        command.contextId(),
        command.contextVersion(),
        command.audience(),
        command.purpose(),
        result.getObject("lifecycle_id", UUID.class),
        result.getLong("generation"),
        verifiedAt);
  }

  private static void recordFailedAttempt(
      Connection connection,
      EnrollmentVerificationCommand command,
      int attempts,
      EnrollmentStatus status)
      throws SQLException {
    if (status != EnrollmentStatus.PENDING) {
      return;
    }
    int nextAttempts = attempts + 1;
    try (PreparedStatement update =
        connection.prepareStatement(
            """
            UPDATE enrollment_contract SET attempts = ?, status = ?
            WHERE context_id = ? AND audience = ? AND purpose = ?
            """)) {
      update.setInt(1, nextAttempts);
      update.setString(
          2,
          nextAttempts >= command.attemptLimit()
              ? EnrollmentStatus.EXPIRED.name()
              : EnrollmentStatus.PENDING.name());
      update.setString(3, command.contextId());
      update.setString(4, command.audience());
      update.setString(5, command.purpose());
      update.executeUpdate();
    }
  }

  private static void expire(Connection connection, EnrollmentVerificationCommand command)
      throws SQLException {
    try (PreparedStatement update =
        connection.prepareStatement(
            """
            UPDATE enrollment_contract SET status = ?
            WHERE context_id = ? AND audience = ? AND purpose = ? AND status = ?
            """)) {
      update.setString(1, EnrollmentStatus.EXPIRED.name());
      update.setString(2, command.contextId());
      update.setString(3, command.audience());
      update.setString(4, command.purpose());
      update.setString(5, EnrollmentStatus.PENDING.name());
      update.executeUpdate();
    }
  }

  private void settle(EnrollmentVerificationReceipt receipt, EnrollmentStatus target) {
    try (Connection connection = connections.open();
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
      throw failure(exception);
    }
  }

  private static void bindKey(
      PreparedStatement statement, EnrollmentStartCommand command, int offset) throws SQLException {
    statement.setString(offset, command.canonicalEmail());
    statement.setString(offset + 1, command.contextId());
    statement.setString(offset + 2, command.contextVersion());
    statement.setString(offset + 3, command.audience());
    statement.setString(offset + 4, command.purpose());
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

  private static IllegalStateException failure(SQLException exception) {
    return new IllegalStateException("test contract store failure", exception);
  }

  @FunctionalInterface
  interface ConnectionFactory {
    Connection open() throws SQLException;
  }
}
