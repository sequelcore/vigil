package io.github.sequelcore.vigil.blacklist;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import java.time.Duration;
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
  private final Cache<String, RotationEntry> rotationCache;

  /** Internal entry for rotation cache with custom expiration. */
  private record RotationEntry(RotatedToken data, long expiresAtNanos) {}

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
    this.rotationCache =
        Caffeine.newBuilder()
            .maximumSize(config.maxSize())
            .expireAfter(
                new Expiry<String, RotationEntry>() {
                  @Override
                  public long expireAfterCreate(String key, RotationEntry value, long currentTime) {
                    return value.expiresAtNanos() - currentTime;
                  }

                  @Override
                  public long expireAfterUpdate(
                      String key, RotationEntry value, long currentTime, long currentDuration) {
                    return currentDuration;
                  }

                  @Override
                  public long expireAfterRead(
                      String key, RotationEntry value, long currentTime, long currentDuration) {
                    return currentDuration;
                  }
                })
            .build();
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
  public void rotate(String oldToken, RotatedToken rotatedToken, Duration gracePeriod) {
    if (oldToken == null || oldToken.isEmpty() || rotatedToken == null) {
      return;
    }
    long expiresAtNanos = System.nanoTime() + gracePeriod.toNanos();
    rotationCache.put(oldToken, new RotationEntry(rotatedToken, expiresAtNanos));
  }

  @Override
  public Optional<RotatedToken> getRotation(String token) {
    if (token == null || token.isEmpty()) {
      return Optional.empty();
    }
    RotationEntry entry = rotationCache.getIfPresent(token);
    return entry != null ? Optional.of(entry.data()) : Optional.empty();
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
    rotationCache.invalidateAll();
  }

  @Override
  public long size() {
    return tokenCache.estimatedSize()
        + subjectCache.estimatedSize()
        + rotationCache.estimatedSize();
  }
}
