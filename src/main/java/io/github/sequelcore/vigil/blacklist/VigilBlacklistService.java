package io.github.sequelcore.vigil.blacklist;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.sequelcore.vigil.autoconfigure.VigilProperties;

/** Service for managing token blacklist using Caffeine cache. */
public class VigilBlacklistService {

  private final Cache<String, Boolean> blacklist;

  public VigilBlacklistService(VigilProperties.Blacklist blacklistConfig) {
    this.blacklist =
        Caffeine.newBuilder()
            .maximumSize(blacklistConfig.maxSize())
            .expireAfterWrite(blacklistConfig.ttl())
            .build();
  }

  /**
   * Adds a token to the blacklist.
   *
   * @param token the token to blacklist
   */
  public void blacklist(String token) {
    if (token != null && !token.isEmpty()) {
      blacklist.put(token, Boolean.TRUE);
    }
  }

  /**
   * Checks if a token is blacklisted.
   *
   * @param token the token to check
   * @return true if the token is blacklisted
   */
  public boolean isBlacklisted(String token) {
    if (token == null || token.isEmpty()) {
      return false;
    }
    return blacklist.getIfPresent(token) != null;
  }

  /**
   * Returns the current size of the blacklist.
   *
   * @return the number of blacklisted tokens
   */
  public long size() {
    return blacklist.estimatedSize();
  }

  /** Clears all entries from the blacklist. */
  public void clear() {
    blacklist.invalidateAll();
  }
}
