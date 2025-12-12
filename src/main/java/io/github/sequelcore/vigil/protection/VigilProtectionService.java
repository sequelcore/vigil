package io.github.sequelcore.vigil.protection;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import java.time.Instant;

/** Service for tracking login attempts and managing account lockouts. */
public class VigilProtectionService {

  private final VigilProperties.Protection protectionConfig;
  private final Cache<String, LoginAttemptInfo> attempts;

  /**
   * Creates a protection service for tracking login attempts.
   *
   * @param protectionConfig login protection configuration properties
   */
  public VigilProtectionService(VigilProperties.Protection protectionConfig) {
    this.protectionConfig = protectionConfig;
    this.attempts =
        Caffeine.newBuilder()
            .maximumSize(protectionConfig.maxSize())
            .expireAfterWrite(protectionConfig.lockDuration().multipliedBy(2))
            .build();
  }

  /**
   * Records a failed login attempt for the given identifier.
   *
   * @param identifier the username or IP address
   */
  public void recordFailedAttempt(String identifier) {
    if (identifier == null || identifier.isEmpty()) {
      return;
    }

    String key = identifier.toLowerCase();
    LoginAttemptInfo info = attempts.getIfPresent(key);

    if (info == null) {
      info = new LoginAttemptInfo(1, null);
    } else if (info.isLocked()) {
      return;
    } else {
      int newCount = info.failedAttempts() + 1;
      Instant lockedUntil = null;

      if (newCount >= protectionConfig.maxAttempts()) {
        lockedUntil = Instant.now().plus(protectionConfig.lockDuration());
      }

      info = new LoginAttemptInfo(newCount, lockedUntil);
    }

    attempts.put(key, info);
  }

  /**
   * Records a successful login, resetting the attempt counter.
   *
   * @param identifier the username or IP address
   */
  public void recordSuccessfulLogin(String identifier) {
    if (identifier == null || identifier.isEmpty()) {
      return;
    }
    attempts.invalidate(identifier.toLowerCase());
  }

  /**
   * Checks if the given identifier is currently locked out.
   *
   * @param identifier the username or IP address
   * @return true if the identifier is locked
   */
  public boolean isLocked(String identifier) {
    if (identifier == null || identifier.isEmpty()) {
      return false;
    }

    LoginAttemptInfo info = attempts.getIfPresent(identifier.toLowerCase());
    if (info == null) {
      return false;
    }

    return info.isLocked();
  }

  /**
   * Returns the number of failed attempts for the given identifier.
   *
   * @param identifier the username or IP address
   * @return the number of failed attempts
   */
  public int getFailedAttempts(String identifier) {
    if (identifier == null || identifier.isEmpty()) {
      return 0;
    }

    LoginAttemptInfo info = attempts.getIfPresent(identifier.toLowerCase());
    return info != null ? info.failedAttempts() : 0;
  }

  /**
   * Manually unlocks the given identifier.
   *
   * @param identifier the username or IP address
   */
  public void unlock(String identifier) {
    if (identifier != null && !identifier.isEmpty()) {
      attempts.invalidate(identifier.toLowerCase());
    }
  }

  private record LoginAttemptInfo(int failedAttempts, Instant lockedUntil) {
    boolean isLocked() {
      return lockedUntil != null && Instant.now().isBefore(lockedUntil);
    }
  }
}
