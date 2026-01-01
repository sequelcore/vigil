package io.github.sequelcore.vigil.blacklist;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import java.time.Instant;
import java.util.Optional;

/**
 * Caffeine-backed blacklist implementation (in-memory, single instance).
 *
 * <p>Provides fast in-memory token and subject blacklisting. For distributed deployments, implement
 * a Redis or database-backed backend.
 */
public class CaffeineBlacklistBackend implements VigilBlacklistBackend {

  private final Cache<String, Boolean> tokenCache;
  private final Cache<String, Instant> subjectCache;

  /**
   * Creates a Caffeine-backed blacklist with the given configuration.
   *
   * @param config blacklist configuration
   */
  public CaffeineBlacklistBackend(VigilProperties.Blacklist config) {
    this.tokenCache =
        Caffeine.newBuilder().maximumSize(config.maxSize()).expireAfterWrite(config.ttl()).build();
    this.subjectCache =
        Caffeine.newBuilder().maximumSize(config.maxSize()).expireAfterWrite(config.ttl()).build();
  }

  @Override
  public void blacklist(String token) {
    if (token != null && !token.isEmpty()) {
      tokenCache.put(token, Boolean.TRUE);
    }
  }

  @Override
  public boolean isBlacklisted(String token) {
    if (token == null || token.isEmpty()) {
      return false;
    }
    return tokenCache.getIfPresent(token) != null;
  }

  @Override
  public void blacklistSubject(String subject, Instant issuedBefore) {
    if (subject != null && !subject.isEmpty() && issuedBefore != null) {
      subjectCache.put(subject.toLowerCase(), issuedBefore);
    }
  }

  @Override
  public Optional<Instant> getSubjectInvalidation(String subject) {
    if (subject == null || subject.isEmpty()) {
      return Optional.empty();
    }
    return Optional.ofNullable(subjectCache.getIfPresent(subject.toLowerCase()));
  }

  @Override
  public void clear() {
    tokenCache.invalidateAll();
    subjectCache.invalidateAll();
  }

  @Override
  public long size() {
    return tokenCache.estimatedSize() + subjectCache.estimatedSize();
  }
}
