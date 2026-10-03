package io.github.sequelcore.vigil.login;

import java.time.Instant;

/**
 * Failure counters behind every failed-attempt lockout in Vigil: {@link PasswordLoginGuard} and
 * step-up PIN verification.
 *
 * <p>The default {@link CaffeineLoginAttemptStore} is node-local: with several instances each node
 * counts separately, so the effective limit is multiplied by the node count. Applications running
 * more than one instance should implement this port over shared storage. {@link #recordFailure}
 * must be atomic per key. Keys are namespaced by their caller (<code>password:</code> for password
 * login, <code>step-up:</code> for step-up PIN verification), so one credential's lock never
 * affects another's, and they carry no password material.
 */
public interface LoginAttemptStore {

  /**
   * Returns whether the key is locked at the given instant.
   *
   * @param key namespaced, normalized key
   * @param now current instant
   * @return true while a lock is in force
   */
  boolean isLocked(String key, Instant now);

  /**
   * Atomically records one failure and applies the policy's lock when the threshold is reached. A
   * failure for a key that is already locked must not extend the lock or grow the count.
   *
   * @param key namespaced, normalized key
   * @param now current instant
   * @param policy lockout policy
   */
  void recordFailure(String key, Instant now, LoginPolicy policy);

  /**
   * Clears the counter and any lock for the key.
   *
   * @param key namespaced, normalized key
   */
  void reset(String key);
}
