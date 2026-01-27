package io.github.sequelcore.vigil.blacklist;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * Service for managing token and subject blacklists.
 *
 * <p>Supports two types of blacklisting:
 *
 * <ul>
 *   <li>Token blacklist: Individual tokens (for logout, token rotation)
 *   <li>Subject blacklist: All tokens for a user issued before a timestamp (for password change)
 * </ul>
 *
 * <p>Delegates to a {@link VigilBlacklistBackend} implementation. Default is {@link
 * CaffeineBlacklistBackend} (in-memory).
 */
public class VigilBlacklistService {

  private final VigilBlacklistBackend backend;
  private final Duration gracePeriod;

  /**
   * Creates a blacklist service with Caffeine backend (default).
   *
   * @param config blacklist configuration
   */
  public VigilBlacklistService(VigilProperties.Blacklist config) {
    this.backend = new CaffeineBlacklistBackend(config);
    this.gracePeriod = config.gracePeriod();
  }

  /**
   * Creates a blacklist service with custom backend.
   *
   * @param backend the backend implementation
   * @param gracePeriod grace period for token rotation
   */
  public VigilBlacklistService(VigilBlacklistBackend backend, Duration gracePeriod) {
    this.backend = backend;
    this.gracePeriod = gracePeriod;
  }

  /**
   * Adds a token to the blacklist.
   *
   * @param token the token to blacklist
   */
  public void blacklist(String token) {
    backend.blacklist(token);
  }

  /**
   * Checks if a token is blacklisted.
   *
   * @param token the token to check
   * @return true if blacklisted
   */
  public boolean isBlacklisted(String token) {
    return backend.isBlacklisted(token);
  }

  /**
   * Rotates a refresh token with grace period support.
   *
   * <p>During the grace period, the old token can still be reused (returns cached new tokens). This
   * handles network issues where the client may not receive the new tokens.
   *
   * @param oldToken the rotated refresh token
   * @param rotatedToken the rotation data with new tokens
   */
  public void rotate(String oldToken, RotatedToken rotatedToken) {
    backend.rotate(oldToken, rotatedToken, gracePeriod);
  }

  /**
   * Gets rotation data if the token was rotated and is within grace period.
   *
   * @param token the token to check
   * @return rotation data if in grace period, empty if not rotated or grace expired
   */
  public Optional<RotatedToken> getRotation(String token) {
    return backend.getRotation(token);
  }

  /**
   * Blacklists all tokens for a subject issued before the given timestamp.
   *
   * <p>Use this to invalidate all sessions for a user after password change or account compromise.
   *
   * @param subject the user identifier (email, userId)
   * @param issuedBefore tokens issued before this time are invalid
   */
  public void blacklistSubject(String subject, Instant issuedBefore) {
    backend.blacklistSubject(subject, issuedBefore);
  }

  /**
   * Gets the invalidation timestamp for a subject.
   *
   * <p>Tokens issued before this timestamp should be rejected.
   *
   * @param subject the user identifier
   * @return the timestamp if subject has been invalidated
   */
  public Optional<Instant> getSubjectInvalidation(String subject) {
    return backend.getSubjectInvalidation(subject);
  }

  /**
   * Checks if a token is invalidated based on subject invalidation.
   *
   * @param subject the token subject
   * @param issuedAt when the token was issued
   * @return true if the token should be rejected
   */
  public boolean isSubjectInvalidated(String subject, Instant issuedAt) {
    return backend
        .getSubjectInvalidation(subject)
        .map(invalidatedAt -> issuedAt.isBefore(invalidatedAt))
        .orElse(false);
  }

  /** Clears all entries from both token and subject blacklists. */
  public void clear() {
    backend.clear();
  }

  /**
   * Returns approximate total size of all blacklists.
   *
   * @return number of entries
   */
  public long size() {
    return backend.size();
  }
}
