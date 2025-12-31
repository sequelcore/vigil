package io.github.sequelcore.vigil.blacklist;

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

  /** Clears all entries. */
  void clear();

  /**
   * Returns approximate size.
   *
   * @return number of entries
   */
  long size();
}
