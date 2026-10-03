package io.github.sequelcore.vigil.login;

import java.util.Objects;

/**
 * The application's view of a user for one login attempt. The application owns lookup and status;
 * Vigil only verifies the hash.
 *
 * @param subject the identifier the application will issue tokens for
 * @param passwordHash the stored password hash
 * @param active false for disabled, suspended or otherwise not-permitted accounts
 */
public record LoginAccount(String subject, String passwordHash, boolean active) {

  /** Requires a subject and a hash. */
  public LoginAccount {
    Objects.requireNonNull(subject, "subject");
    Objects.requireNonNull(passwordHash, "passwordHash");
  }

  @Override
  public String toString() {
    return "LoginAccount[redacted]";
  }
}
