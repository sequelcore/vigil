package io.github.sequelcore.vigil.core.password;

import java.util.List;

/**
 * Result of password strength evaluation.
 *
 * <p>Provides a numeric score and actionable feedback for improving password strength.
 *
 * <p>Score interpretation:
 *
 * <ul>
 *   <li>0 - Very weak: common password or critically short
 *   <li>1 - Weak: missing required character types
 *   <li>2 - Fair: meets minimum requirements
 *   <li>3 - Strong: good length and character variety
 *   <li>4 - Very strong: excellent entropy
 * </ul>
 *
 * @param score strength score from 0 (very weak) to 4 (very strong)
 * @param feedback suggestions for improving password strength (empty if score is 4)
 */
public record PasswordStrength(int score, List<String> feedback) {

  /** Minimum acceptable score for most applications. */
  public static final int MINIMUM_ACCEPTABLE = 2;

  /** Maximum possible score. */
  public static final int MAX_SCORE = 4;

  /**
   * Creates a password strength result.
   *
   * @param score strength score (clamped to 0-4)
   * @param feedback suggestions for improvement
   */
  public PasswordStrength {
    score = Math.max(0, Math.min(MAX_SCORE, score));
    feedback = feedback != null ? List.copyOf(feedback) : List.of();
  }

  /**
   * Checks if the password meets minimum strength requirements.
   *
   * @return true if score is at least {@link #MINIMUM_ACCEPTABLE}
   */
  public boolean isAcceptable() {
    return score >= MINIMUM_ACCEPTABLE;
  }

  /**
   * Checks if the password has maximum strength.
   *
   * @return true if score equals {@link #MAX_SCORE}
   */
  public boolean isStrong() {
    return score == MAX_SCORE;
  }
}
