package io.github.sequelcore.vigil.core.password;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import lombok.Getter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/** Service for password hashing and validation. */
public class VigilPasswordService {

  @Getter private final BCryptPasswordEncoder encoder;

  /**
   * Creates a password service configured with the provided BCrypt strength.
   *
   * @param passwordConfig password configuration properties
   */
  public VigilPasswordService(VigilProperties.Password passwordConfig) {
    this.encoder = new BCryptPasswordEncoder(passwordConfig.strength());
  }

  /**
   * Hashes a raw password using BCrypt.
   *
   * @param rawPassword the plain text password
   * @return the hashed password
   */
  public String hash(String rawPassword) {
    return encoder.encode(rawPassword);
  }

  /**
   * Verifies a raw password against a hashed password.
   *
   * @param rawPassword the plain text password
   * @param hashedPassword the BCrypt hashed password
   * @return true if the passwords match
   */
  public boolean matches(String rawPassword, String hashedPassword) {
    return encoder.matches(rawPassword, hashedPassword);
  }

  /**
   * Checks if a password meets minimum strength requirements.
   *
   * @param password the password to validate
   * @return validation result with details
   */
  public PasswordValidationResult validate(String password) {
    if (password == null || password.isEmpty()) {
      return new PasswordValidationResult(false, "Password cannot be empty");
    }

    if (password.length() < 8) {
      return new PasswordValidationResult(false, "Password must be at least 8 characters");
    }

    if (password.length() > 128) {
      return new PasswordValidationResult(false, "Password cannot exceed 128 characters");
    }

    boolean hasUpper = password.chars().anyMatch(Character::isUpperCase);
    boolean hasLower = password.chars().anyMatch(Character::isLowerCase);
    boolean hasDigit = password.chars().anyMatch(Character::isDigit);
    boolean hasSpecial = password.chars().anyMatch(c -> !Character.isLetterOrDigit(c));

    if (!hasUpper) {
      return new PasswordValidationResult(false, "Password must contain an uppercase letter");
    }

    if (!hasLower) {
      return new PasswordValidationResult(false, "Password must contain a lowercase letter");
    }

    if (!hasDigit) {
      return new PasswordValidationResult(false, "Password must contain a digit");
    }

    if (!hasSpecial) {
      return new PasswordValidationResult(false, "Password must contain a special character");
    }

    return new PasswordValidationResult(true, null);
  }

  /**
   * Result of password validation.
   *
   * @param valid whether the password is valid
   * @param message optional validation message when invalid
   */
  public record PasswordValidationResult(boolean valid, String message) {}
}
