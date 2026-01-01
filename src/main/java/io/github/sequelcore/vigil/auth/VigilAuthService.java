package io.github.sequelcore.vigil.auth;

import io.github.sequelcore.vigil.auth.VigilAuthException.AuthErrorCode;
import io.github.sequelcore.vigil.blacklist.VigilBlacklistService;
import io.github.sequelcore.vigil.core.cookie.VigilCookieService;
import io.github.sequelcore.vigil.core.jwt.TokenRefreshResult;
import io.github.sequelcore.vigil.core.jwt.VigilTokenClaims;
import io.github.sequelcore.vigil.core.jwt.VigilTokenService;
import io.github.sequelcore.vigil.tenant.VigilTenantContext;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * High-level authentication operations.
 *
 * <p>Provides convenient methods that orchestrate token service, cookie service, and blacklist
 * service for common auth flows.
 *
 * <p>Example usage:
 *
 * <pre>{@code
 * @PostMapping("/refresh")
 * public ResponseEntity<TokenResponse> refresh(
 *         HttpServletRequest request,
 *         HttpServletResponse response) {
 *     AuthResult result = authService.refresh(request, response, "staff");
 *     return ResponseEntity.ok(new TokenResponse(result));
 * }
 *
 * @PostMapping("/logout")
 * public ResponseEntity<Void> logout(
 *         HttpServletRequest request,
 *         HttpServletResponse response) {
 *     authService.logout(request, response, "staff");
 *     return ResponseEntity.ok().build();
 * }
 * }</pre>
 */
public class VigilAuthService {

  private final VigilTokenService tokenService;
  private final VigilCookieService cookieService;
  private final VigilBlacklistService blacklistService;

  /**
   * Creates an auth service with required dependencies.
   *
   * @param tokenService the token service for JWT operations
   * @param cookieService the cookie service for cookie management
   * @param blacklistService the blacklist service for token invalidation
   */
  public VigilAuthService(
      VigilTokenService tokenService,
      VigilCookieService cookieService,
      VigilBlacklistService blacklistService) {
    this.tokenService = tokenService;
    this.cookieService = cookieService;
    this.blacklistService = blacklistService;
  }

  /**
   * Refreshes tokens using the refresh token from cookies.
   *
   * <p>This method:
   *
   * <ol>
   *   <li>Extracts refresh token from cookie
   *   <li>Validates it's not blacklisted
   *   <li>Validates the JWT signature and expiration
   *   <li>Blacklists the old refresh token (rotation)
   *   <li>Generates new access and refresh tokens
   *   <li>Sets new cookies
   * </ol>
   *
   * @param request the HTTP request
   * @param response the HTTP response
   * @param profile the cookie profile (e.g., "staff", "customer")
   * @return the new tokens and expiration times
   * @throws VigilAuthException if refresh fails
   */
  public AuthResult refresh(
      HttpServletRequest request, HttpServletResponse response, String profile) {
    return refresh(request, response, profile, null);
  }

  /**
   * Refreshes tokens with updated claims.
   *
   * <p>Use this when user data has changed and tokens need new claims.
   *
   * @param request the HTTP request
   * @param response the HTTP response
   * @param profile the cookie profile
   * @param updatedClaims claims to add/update in new tokens (nullable)
   * @return the new tokens and expiration times
   * @throws VigilAuthException if refresh fails
   */
  public AuthResult refresh(
      HttpServletRequest request,
      HttpServletResponse response,
      String profile,
      @Nullable Map<String, Object> updatedClaims) {

    // Extract refresh token
    String refreshToken =
        cookieService
            .getRefreshToken(request, profile)
            .orElseThrow(
                () ->
                    new VigilAuthException(
                        AuthErrorCode.TOKEN_NOT_FOUND, "Refresh token not found"));

    // Check blacklist
    if (blacklistService.isBlacklisted(refreshToken)) {
      throw new VigilAuthException(AuthErrorCode.TOKEN_BLACKLISTED, "Token has been invalidated");
    }

    // Refresh tokens (validates JWT and rotates)
    TokenRefreshResult result;
    try {
      result = tokenService.refreshTokens(refreshToken, updatedClaims);
    } catch (ExpiredJwtException e) {
      throw new VigilAuthException(AuthErrorCode.TOKEN_EXPIRED, "Refresh token has expired", e);
    } catch (JwtException e) {
      throw new VigilAuthException(AuthErrorCode.TOKEN_INVALID, "Invalid refresh token", e);
    }

    // Set new cookies
    cookieService.setAccessTokenCookie(response, result.accessToken(), profile);
    cookieService.setRefreshTokenCookie(response, result.refreshToken(), profile);

    // Parse claims for response
    VigilTokenClaims claims =
        new VigilTokenClaims(tokenService.validateAndGetClaims(result.accessToken()));

    return new AuthResult(
        result.accessToken(),
        result.refreshToken(),
        result.accessExpiresAt(),
        result.refreshExpiresAt(),
        claims);
  }

  /**
   * Logs out by blacklisting tokens and clearing cookies.
   *
   * <p>This method:
   *
   * <ol>
   *   <li>Extracts access and refresh tokens from cookies
   *   <li>Blacklists both tokens
   *   <li>Clears the cookies
   * </ol>
   *
   * @param request the HTTP request
   * @param response the HTTP response
   * @param profile the cookie profile
   */
  public void logout(HttpServletRequest request, HttpServletResponse response, String profile) {
    // Blacklist access token if present
    cookieService.getAccessToken(request, profile).ifPresent(blacklistService::blacklist);

    // Blacklist refresh token if present
    cookieService.getRefreshToken(request, profile).ifPresent(blacklistService::blacklist);

    // Clear cookies
    cookieService.clearCookies(response, profile);
  }

  /**
   * Invalidates all active sessions for a user.
   *
   * <p>This works by recording the current timestamp against the subject. During token validation,
   * tokens issued before this timestamp should be rejected.
   *
   * <p>Note: This requires the blacklist service to support subject-based invalidation. Currently
   * uses token-based blacklisting as a fallback.
   *
   * @param subject the user identifier (typically email or userId)
   */
  public void invalidateAllSessions(String subject) {
    // Record invalidation timestamp for subject
    // Tokens issued before this time will be rejected
    blacklistService.blacklistSubject(subject, Instant.now());
  }

  /**
   * Gets the current authenticated principal from SecurityContext.
   *
   * @return the principal if authenticated
   */
  public Optional<VigilPrincipal> getCurrentPrincipal() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication == null || !authentication.isAuthenticated()) {
      return Optional.empty();
    }

    Object principal = authentication.getPrincipal();
    if (principal == null || "anonymousUser".equals(principal)) {
      return Optional.empty();
    }

    // Extract from authentication details if available
    Object details = authentication.getDetails();
    if (details instanceof VigilTokenClaims claims) {
      return Optional.of(buildPrincipalFromClaims(claims, authentication));
    }

    // Fallback: build minimal principal from authentication
    String subject = principal.toString();
    List<String> roles =
        authentication.getAuthorities().stream()
            .map(a -> a.getAuthority().replace("ROLE_", ""))
            .toList();

    return Optional.of(
        new VigilPrincipal(subject, getCurrentTenant().orElse(null), roles, Map.of()));
  }

  /**
   * Gets the current tenant ID from Vigil's tenant context.
   *
   * @return the tenant ID if set
   */
  public Optional<UUID> getCurrentTenant() {
    return VigilTenantContext.getTenant();
  }

  private VigilPrincipal buildPrincipalFromClaims(VigilTokenClaims claims, Authentication auth) {
    String subject = claims.getSubject();
    if (subject == null) {
      subject = auth.getName();
    }
    UUID tenantId = claims.getUuid("tenantId").orElse(null);
    List<String> roles = extractRoles(auth);

    return new VigilPrincipal(subject, tenantId, roles, claims.asMap());
  }

  private List<String> extractRoles(Authentication auth) {
    return auth.getAuthorities().stream()
        .map(a -> a.getAuthority())
        .map(r -> r.startsWith("ROLE_") ? r.substring(5) : r)
        .toList();
  }
}
