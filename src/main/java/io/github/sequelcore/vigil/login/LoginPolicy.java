package io.github.sequelcore.vigil.login;

import java.time.Duration;

/**
 * Lockout policy for {@link PasswordLoginGuard}.
 *
 * <p>After {@code maxFailures} consecutive failures an identifier is locked for {@code baseLock}.
 * Each further failure after a lock expires doubles the lock, up to {@code maxLock}. Failures older
 * than {@code failureWindow} (measured from the last failure) are forgotten.
 *
 * @param maxFailures consecutive failures that trigger the first lock
 * @param baseLock first lock duration
 * @param maxLock upper bound for the doubling lock duration
 * @param failureWindow inactivity after which the failure count restarts
 * @param maxTrackedIdentifiers upper bound of identifiers tracked by the default store
 */
public record LoginPolicy(
    int maxFailures,
    Duration baseLock,
    Duration maxLock,
    Duration failureWindow,
    int maxTrackedIdentifiers) {

  /** Validates the policy. Invalid values fail fast instead of silently weakening protection. */
  public LoginPolicy {
    if (maxFailures <= 0) {
      throw new IllegalArgumentException("maxFailures must be positive");
    }
    if (baseLock == null || baseLock.isZero() || baseLock.isNegative()) {
      throw new IllegalArgumentException("baseLock must be positive");
    }
    if (maxLock == null || maxLock.compareTo(baseLock) < 0) {
      throw new IllegalArgumentException("maxLock must not be shorter than baseLock");
    }
    if (failureWindow == null || failureWindow.isZero() || failureWindow.isNegative()) {
      throw new IllegalArgumentException("failureWindow must be positive");
    }
    if (maxTrackedIdentifiers <= 0) {
      throw new IllegalArgumentException("maxTrackedIdentifiers must be positive");
    }
  }

  /**
   * Returns the default policy: 5 failures, 1 minute doubling to at most 15 minutes, 15 minute
   * window, 100,000 tracked identifiers.
   *
   * @return the default policy
   */
  public static LoginPolicy defaults() {
    return new LoginPolicy(
        5, Duration.ofMinutes(1), Duration.ofMinutes(15), Duration.ofMinutes(15), 100_000);
  }

  /**
   * Builds a policy, replacing omitted, non-positive or inconsistent values with the defaults.
   *
   * @param maxFailures consecutive failures that trigger the first lock
   * @param baseLock first lock duration
   * @param maxLock upper bound for the doubling lock duration
   * @param failureWindow inactivity after which the failure count restarts
   * @param maxTrackedIdentifiers upper bound of identifiers tracked by the default store
   * @return a valid policy
   */
  public static LoginPolicy withDefaults(
      int maxFailures,
      Duration baseLock,
      Duration maxLock,
      Duration failureWindow,
      int maxTrackedIdentifiers) {
    LoginPolicy defaults = defaults();
    Duration base = positive(baseLock) ? baseLock : defaults.baseLock;
    Duration max =
        maxLock != null && maxLock.compareTo(base) >= 0
            ? maxLock
            : (defaults.maxLock.compareTo(base) >= 0 ? defaults.maxLock : base);
    return new LoginPolicy(
        maxFailures > 0 ? maxFailures : defaults.maxFailures,
        base,
        max,
        positive(failureWindow) ? failureWindow : defaults.failureWindow,
        maxTrackedIdentifiers > 0 ? maxTrackedIdentifiers : defaults.maxTrackedIdentifiers);
  }

  private static boolean positive(Duration duration) {
    return duration != null && !duration.isZero() && !duration.isNegative();
  }

  /**
   * Computes the lock duration after the given consecutive failure count.
   *
   * @param failures consecutive failures recorded, including the latest
   * @return the lock duration, or {@link Duration#ZERO} below the threshold
   */
  Duration lockFor(int failures) {
    if (failures < maxFailures) {
      return Duration.ZERO;
    }
    int doublings = Math.min(failures - maxFailures, 30);
    Duration lock = baseLock;
    for (int i = 0; i < doublings && lock.compareTo(maxLock) < 0; i++) {
      lock = lock.multipliedBy(2);
    }
    return lock.compareTo(maxLock) > 0 ? maxLock : lock;
  }
}
