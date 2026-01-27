package io.github.sequelcore.vigil.blacklist;

import java.time.Duration;
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
   * Rotates a refresh token with grace period support.
   *
   * <p>The old token enters a grace period where it can still be reused (returns cached new
   * tokens). After grace period expires, reuse is rejected.
   *
   * @param oldToken the rotated refresh token
   * @param rotatedToken the rotation data with new tokens
   * @param gracePeriod how long the old token remains reusable
   */
  void rotate(String oldToken, RotatedToken rotatedToken, Duration gracePeriod);

  /**
   * Gets rotation data if the token was rotated and is within grace period.
   *
   * @param token the token to check
   * @return rotation data if in grace period, empty if not rotated or grace expired
   */
  Optional<RotatedToken> getRotation(String token);

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
