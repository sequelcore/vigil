package io.github.sequelcore.vigil.blacklist;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.sequelcore.vigil.autoconfigure.VigilProperties;

/** Caffeine-backed blacklist implementation (in-memory, single instance). */
public class CaffeineBlacklistBackend implements VigilBlacklistBackend {

  private final Cache<String, Boolean> cache;

  public CaffeineBlacklistBackend(VigilProperties.Blacklist config) {
    this.cache =
        Caffeine.newBuilder().maximumSize(config.maxSize()).expireAfterWrite(config.ttl()).build();
  }

  @Override
  public void blacklist(String token) {
    if (token != null && !token.isEmpty()) {
      cache.put(token, Boolean.TRUE);
    }
  }

  @Override
  public boolean isBlacklisted(String token) {
    if (token == null || token.isEmpty()) {
      return false;
    }
    return cache.getIfPresent(token) != null;
  }

  @Override
  public void clear() {
    cache.invalidateAll();
  }

  @Override
  public long size() {
    return cache.estimatedSize();
  }
}
