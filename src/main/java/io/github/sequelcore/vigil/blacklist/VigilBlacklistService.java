package io.github.sequelcore.vigil.blacklist;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;

/**
 * Service for managing token blacklist.
 *
 * <p>Delegates to a {@link VigilBlacklistBackend} implementation. Default is {@link
 * CaffeineBlacklistBackend} (in-memory).
 */
public class VigilBlacklistService {

  private final VigilBlacklistBackend backend;

  /** Creates with Caffeine backend (default). */
  public VigilBlacklistService(VigilProperties.Blacklist config) {
    this.backend = new CaffeineBlacklistBackend(config);
  }

  /** Creates with custom backend. */
  public VigilBlacklistService(VigilBlacklistBackend backend) {
    this.backend = backend;
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

  /** Clears all entries. */
  public void clear() {
    backend.clear();
  }

  /**
   * Returns approximate size.
   *
   * @return number of entries
   */
  public long size() {
    return backend.size();
  }
}
