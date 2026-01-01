package io.github.sequelcore.vigil.core.password;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * Service for secure password hashing and validation.
 *
 * <p>Provides BCrypt hashing with configurable strength, password policy validation, strength
 * scoring, and security hygiene utilities like rehash detection.
 *
 * <p>Example usage:
 *
 * <pre>{@code
 * // Hash a password
 * String hash = passwordService.hash("MyP@ssw0rd!");
 *
 * // Verify a password
 * if (passwordService.matches("MyP@ssw0rd!", hash)) {
 *     // Rehash if using outdated strength
 *     if (passwordService.needsRehash(hash)) {
 *         String newHash = passwordService.hash("MyP@ssw0rd!");
 *         userRepository.updatePasswordHash(userId, newHash);
 *     }
 * }
 *
 * // Validate password strength before hashing
 * PasswordStrength strength = passwordService.strength("weak");
 * if (!strength.isAcceptable()) {
 *     throw new WeakPasswordException(strength.feedback());
 * }
 * }</pre>
 */
public class VigilPasswordService {

  private static final int MIN_LENGTH = 8;
  private static final int MAX_LENGTH = 128;
  private static final int STRONG_LENGTH = 12;
  private static final int VERY_STRONG_LENGTH = 16;

  private static final Pattern UPPERCASE = Pattern.compile("[A-Z]");
  private static final Pattern LOWERCASE = Pattern.compile("[a-z]");
  private static final Pattern DIGIT = Pattern.compile("[0-9]");
  private static final Pattern SPECIAL = Pattern.compile("[^a-zA-Z0-9]");

  private final BCryptPasswordEncoder encoder;
  private final int configuredStrength;

  /**
   * Creates a password service with the configured BCrypt strength.
   *
   * @param config password configuration properties
   */
  public VigilPasswordService(VigilProperties.Password config) {
    this.configuredStrength = config.strength();
    this.encoder = new BCryptPasswordEncoder(configuredStrength);
  }

  /**
   * Hashes a password using BCrypt.
   *
   * @param rawPassword the plain text password
   * @return the BCrypt hash
   * @throws IllegalArgumentException if password is null or empty
   */
  public String hash(String rawPassword) {
    if (rawPassword == null || rawPassword.isEmpty()) {
      throw new IllegalArgumentException("Password cannot be null or empty");
    }
    return encoder.encode(rawPassword);
  }

  /**
   * Verifies a password against a BCrypt hash.
   *
   * @param rawPassword the plain text password
   * @param hashedPassword the BCrypt hash
   * @return true if the password matches
   */
  public boolean matches(String rawPassword, String hashedPassword) {
    if (rawPassword == null || hashedPassword == null) {
      return false;
    }
    return encoder.matches(rawPassword, hashedPassword);
  }

  /**
   * Checks if a hash needs rehashing due to outdated strength.
   *
   * <p>Use this after successful authentication to upgrade hashes when BCrypt strength
   * configuration increases.
   *
   * @param hashedPassword the BCrypt hash to check
   * @return true if the hash uses a lower strength than configured
   */
  public boolean needsRehash(String hashedPassword) {
    if (hashedPassword == null || !hashedPassword.startsWith("$2")) {
      return true;
    }

    int hashStrength = extractStrength(hashedPassword);
    return hashStrength < configuredStrength;
  }

  /**
   * Evaluates password strength.
   *
   * <p>Scoring criteria:
   *
   * <ul>
   *   <li>Base score from character variety (uppercase, lowercase, digit, special)
   *   <li>Bonus for length exceeding minimums
   *   <li>Penalty for common passwords
   *   <li>Penalty for sequential/repeated characters
   * </ul>
   *
   * @param password the password to evaluate
   * @return strength assessment with score (0-4) and feedback
   */
  public PasswordStrength strength(String password) {
    if (password == null || password.isEmpty()) {
      return new PasswordStrength(0, List.of("Password cannot be empty"));
    }

    List<String> feedback = new ArrayList<>();
    int score = 0;

    // Check common passwords first
    if (CommonPasswords.contains(password)) {
      return new PasswordStrength(0, List.of("This password is too common"));
    }

    // Length checks
    if (password.length() < MIN_LENGTH) {
      feedback.add("Use at least " + MIN_LENGTH + " characters");
    } else {
      score++;
      if (password.length() >= STRONG_LENGTH) {
        score++;
      }
    }

    // Character variety
    boolean hasUpper = UPPERCASE.matcher(password).find();
    boolean hasLower = LOWERCASE.matcher(password).find();
    boolean hasDigit = DIGIT.matcher(password).find();
    boolean hasSpecial = SPECIAL.matcher(password).find();

    int varietyCount = 0;
    if (hasUpper) {
      varietyCount++;
    }
    if (hasLower) {
      varietyCount++;
    }
    if (hasDigit) {
      varietyCount++;
    }
    if (hasSpecial) {
      varietyCount++;
    }

    if (!hasUpper) {
      feedback.add("Add uppercase letters");
    }
    if (!hasLower) {
      feedback.add("Add lowercase letters");
    }
    if (!hasDigit) {
      feedback.add("Add numbers");
    }
    if (!hasSpecial) {
      feedback.add("Add special characters");
    }

    if (varietyCount >= 3) {
      score++;
    }
    if (varietyCount == 4 && password.length() >= VERY_STRONG_LENGTH) {
      score++;
    }

    // Penalty for patterns
    if (hasRepeatingChars(password)) {
      score = Math.max(0, score - 1);
      feedback.add("Avoid repeating characters");
    }

    if (hasSequentialChars(password)) {
      score = Math.max(0, score - 1);
      feedback.add("Avoid sequential characters");
    }

    return new PasswordStrength(score, feedback);
  }

  /**
   * Checks if a password appears in the common password dictionary.
   *
   * @param password the password to check
   * @return true if the password is commonly used
   */
  public boolean isCommon(String password) {
    return CommonPasswords.contains(password);
  }

  /**
   * Returns the BCrypt encoder for Spring Security integration.
   *
   * <p>Use when injecting into components that expect a PasswordEncoder:
   *
   * <pre>{@code
   * @Bean
   * public PasswordEncoder passwordEncoder(VigilPasswordService passwordService) {
   *     return passwordService.encoder();
   * }
   * }</pre>
   *
   * @return the BCrypt encoder
   */
  public BCryptPasswordEncoder encoder() {
    return encoder;
  }

  private int extractStrength(String hash) {
    // BCrypt format: $2a$XX$... where XX is the cost factor
    try {
      String[] parts = hash.split("\\$");
      if (parts.length >= 3) {
        return Integer.parseInt(parts[2]);
      }
    } catch (NumberFormatException ignored) {
      // Invalid format
    }
    return 0;
  }

  private boolean hasRepeatingChars(String password) {
    for (int i = 0; i < password.length() - 2; i++) {
      if (password.charAt(i) == password.charAt(i + 1)
          && password.charAt(i + 1) == password.charAt(i + 2)) {
        return true;
      }
    }
    return false;
  }

  private boolean hasSequentialChars(String password) {
    for (int i = 0; i < password.length() - 2; i++) {
      char c1 = password.charAt(i);
      char c2 = password.charAt(i + 1);
      char c3 = password.charAt(i + 2);

      // Check ascending sequence
      if (c2 == c1 + 1 && c3 == c2 + 1) {
        return true;
      }
      // Check descending sequence
      if (c2 == c1 - 1 && c3 == c2 - 1) {
        return true;
      }
    }
    return false;
  }
}
