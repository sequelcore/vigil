package io.github.sequelcore.vigil.login;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.time.Instant;

/**
 * Single-node, bounded default store. A flood of distinct identifiers can evict counters (the cache
 * is size-bounded); use a shared implementation of {@link LoginAttemptStore} for clusters.
 */
public final class CaffeineLoginAttemptStore implements LoginAttemptStore {

  private final Cache<String, State> states;

  /**
   * Creates a store sized and expired from the policy.
   *
   * @param policy lockout policy
   */
  public CaffeineLoginAttemptStore(LoginPolicy policy) {
    this.states =
        Caffeine.newBuilder()
            .maximumSize(policy.maxTrackedIdentifiers())
            .expireAfterWrite(policy.failureWindow().plus(policy.maxLock()))
            .build();
  }

  @Override
  public boolean isLocked(String key, Instant now) {
    State state = states.getIfPresent(key);
    return state != null && state.isLocked(now);
  }

  @Override
  public void recordFailure(String key, Instant now, LoginPolicy policy) {
    states
        .asMap()
        .compute(
            key,
            (k, current) -> {
              if (current != null && current.isLocked(now)) {
                return current;
              }
              int failures =
                  current == null || now.isAfter(current.lastFailure().plus(policy.failureWindow()))
                      ? 1
                      : current.failures() + 1;
              var lock = policy.lockFor(failures);
              return new State(failures, now, lock.isZero() ? null : now.plus(lock));
            });
  }

  @Override
  public void reset(String key) {
    states.invalidate(key);
  }

  private record State(int failures, Instant lastFailure, Instant lockedUntil) {
    boolean isLocked(Instant now) {
      return lockedUntil != null && now.isBefore(lockedUntil);
    }
  }
}
