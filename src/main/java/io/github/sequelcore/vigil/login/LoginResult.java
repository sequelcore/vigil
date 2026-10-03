package io.github.sequelcore.vigil.login;

/**
 * Outcome of {@link PasswordLoginGuard#authenticate}. A rejection is a single value: it does not
 * say whether the identifier was locked, unknown, disabled or given a wrong password.
 *
 * @param authenticated true only when the password was verified for an active, unlocked account
 * @param subject the account subject on success, otherwise null
 * @param needsRehash true on success when the stored hash should be upgraded and saved by the
 *     application
 */
public record LoginResult(boolean authenticated, String subject, boolean needsRehash) {

  private static final LoginResult REJECTED = new LoginResult(false, null, false);

  /**
   * Returns the single rejection value.
   *
   * @return a rejected result
   */
  public static LoginResult rejected() {
    return REJECTED;
  }

  static LoginResult success(String subject, boolean needsRehash) {
    return new LoginResult(true, subject, needsRehash);
  }
}
