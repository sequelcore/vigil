package io.github.sequelcore.vigil.blacklist;

import java.time.Instant;
import java.util.Optional;

/**
 * Backend interface for token blacklist storage.
 *
 * <p>Default implementation uses Caffeine (in-memory). Implement this interface for distributed
 * storage (Redis, database, etc.).
 */
public interface VigilBlacklistBackend {

  /**
   * Adds a token to the blacklist.
   *
   * @param token the token to blacklist
   */
  void blacklist(String token);

  /**
   * Checks if a token is blacklisted.
   *
   * @param token the token to check
   * @return true if blacklisted
   */
  boolean isBlacklisted(String token);

  /**
   * Blacklists all tokens for a subject issued before the given timestamp.
   *
   * <p>Used for invalidating all sessions when password changes.
   *
   * @param subject the user identifier
   * @param issuedBefore tokens issued before this time are invalid
   */
  void blacklistSubject(String subject, Instant issuedBefore);

  /**
   * Gets the invalidation timestamp for a subject.
   *
   * @param subject the user identifier
   * @return the timestamp if subject is invalidated
   */
  Optional<Instant> getSubjectInvalidation(String subject);

  /** Clears all entries. */
  void clear();

  /**
   * Returns approximate size.
   *
   * @return number of entries
   */
  long size();
}
