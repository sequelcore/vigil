package io.github.sequelcore.vigil.auth;

import io.github.sequelcore.vigil.auth.VigilAuthException.AuthErrorCode;
import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import io.github.sequelcore.vigil.blacklist.VigilBlacklistService;
import io.github.sequelcore.vigil.core.jwt.TokenRequest;
import io.github.sequelcore.vigil.core.jwt.VigilTokenService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import java.time.Duration;
import java.util.UUID;

/**
 * Service for generating and validating password reset tokens.
 *
 * <p>Reset tokens are:
 *
 * <ul>
 *   <li>Cryptographically signed (tamper-proof)
 *   <li>Time-limited (configurable TTL)
 *   <li>Single-use (automatically blacklisted after consumption)
 * </ul>
 *
 * <p>Example password reset flow:
 *
 * <pre>{@code
 * // 1. User requests password reset
 * @PostMapping("/forgot-password")
 * public ResponseEntity<Void> forgotPassword(@RequestBody ForgotRequest request) {
 *     userRepository.findByEmail(request.email()).ifPresent(user -> {
 *         String token = resetTokenService.generate(user.getEmail());
 *         String resetUrl = frontendUrl + "/reset-password?token=" + token;
 *         emailService.sendPasswordReset(user.getEmail(), resetUrl);
 *     });
 *     return ResponseEntity.ok().build();  // Silent success for security
 * }
 *
 * // 2. User clicks link, frontend validates token
 * @GetMapping("/reset-password/validate")
 * public ResponseEntity<Void> validateToken(@RequestParam String token) {
 *     resetTokenService.validate(token);  // Throws if invalid
 *     return ResponseEntity.ok().build();
 * }
 *
 * // 3. User submits new password
 * @PostMapping("/reset-password")
 * public ResponseEntity<Void> resetPassword(@RequestBody ResetRequest request) {
 *     String email = resetTokenService.validateAndConsume(request.token());
 *     User user = userRepository.findByEmail(email).orElseThrow();
 *     user.setPasswordHash(passwordService.hash(request.newPassword()));
 *     userRepository.save(user);
 *     authService.invalidateAllSessions(email);
 *     return ResponseEntity.ok().build();
 * }
 * }</pre>
 */
public class VigilResetTokenService {

  private static final String TOKEN_TYPE = "reset";
  private static final String TYPE_CLAIM = "type";
  private static final String JTI_CLAIM = "jti";

  private final VigilTokenService tokenService;
  private final VigilBlacklistService blacklistService;
  private final Duration defaultTtl;

  /**
   * Creates a reset token service with the provided dependencies.
   *
   * @param tokenService the token service for JWT operations
   * @param blacklistService the blacklist service for single-use enforcement
   * @param config reset token configuration
   */
  public VigilResetTokenService(
      VigilTokenService tokenService,
      VigilBlacklistService blacklistService,
      VigilProperties.Reset config) {
    this.tokenService = tokenService;
    this.blacklistService = blacklistService;
    this.defaultTtl = config.ttl();
  }

  /**
   * Generates a password reset token with default TTL.
   *
   * @param subject the user identifier (typically email)
   * @return the reset token
   */
  public String generate(String subject) {
    return generate(subject, defaultTtl);
  }

  /**
   * Generates a password reset token with custom TTL.
   *
   * <p>The token contains:
   *
   * <ul>
   *   <li>Subject (email)
   *   <li>Expiration time
   *   <li>Unique token ID (jti) for single-use enforcement
   *   <li>Type claim ("reset")
   * </ul>
   *
   * @param subject the user identifier
   * @param ttl time until expiration
   * @return the reset token
   */
  public String generate(String subject, Duration ttl) {
    String jti = UUID.randomUUID().toString();

    TokenRequest request =
        TokenRequest.builder()
            .subject(subject)
            .claim(TYPE_CLAIM, TOKEN_TYPE)
            .claim(JTI_CLAIM, jti)
            .accessTtl(ttl)
            .build();

    return tokenService.generateAccessToken(request);
  }

  /**
   * Validates a reset token without consuming it.
   *
   * <p>Use this for pre-validation (e.g., showing the reset password form before the user submits).
   * Does not invalidate the token.
   *
   * @param token the reset token
   * @return the subject (email) from the token
   * @throws VigilAuthException with RESET_TOKEN_EXPIRED if expired
   * @throws VigilAuthException with RESET_TOKEN_USED if already consumed
   * @throws VigilAuthException with RESET_TOKEN_INVALID if malformed or wrong type
   */
  public String validate(String token) {
    Claims claims = validateClaims(token);
    return claims.getSubject();
  }

  /**
   * Validates and consumes a reset token.
   *
   * <p>After calling this method, the token is blacklisted and cannot be used again. This prevents
   * replay attacks.
   *
   * @param token the reset token
   * @return the subject (email) from the token
   * @throws VigilAuthException if token is invalid, expired, or already used
   */
  public String validateAndConsume(String token) {
    Claims claims = validateClaims(token);

    // Blacklist the token to prevent reuse
    blacklistService.blacklist(token);

    return claims.getSubject();
  }

  /**
   * Checks if a reset token has been consumed.
   *
   * @param token the reset token
   * @return true if the token has been used
   */
  public boolean isConsumed(String token) {
    return blacklistService.isBlacklisted(token);
  }

  private Claims validateClaims(String token) {
    // Check if already consumed
    if (blacklistService.isBlacklisted(token)) {
      throw new VigilAuthException(
          AuthErrorCode.RESET_TOKEN_USED, "Reset token has already been used");
    }

    Claims claims;
    try {
      claims = tokenService.validateAndGetClaims(token);
    } catch (ExpiredJwtException e) {
      throw new VigilAuthException(AuthErrorCode.RESET_TOKEN_EXPIRED, "Reset token has expired", e);
    } catch (JwtException e) {
      throw new VigilAuthException(AuthErrorCode.RESET_TOKEN_INVALID, "Invalid reset token", e);
    }

    // Verify token type
    String type = claims.get(TYPE_CLAIM, String.class);
    if (type == null || !TOKEN_TYPE.equals(type)) {
      throw new VigilAuthException(AuthErrorCode.RESET_TOKEN_INVALID, "Token is not a reset token");
    }

    // Verify jti exists
    String jti = claims.get(JTI_CLAIM, String.class);
    if (jti == null || jti.isEmpty()) {
      throw new VigilAuthException(
          AuthErrorCode.RESET_TOKEN_INVALID, "Reset token missing unique ID");
    }

    return claims;
  }
}
