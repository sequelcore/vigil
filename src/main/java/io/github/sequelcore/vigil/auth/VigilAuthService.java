package io.github.sequelcore.vigil.auth;

import io.github.sequelcore.vigil.auth.VigilAuthException.AuthErrorCode;
import io.github.sequelcore.vigil.blacklist.VigilBlacklistService;
import io.github.sequelcore.vigil.core.cookie.VigilCookieService;
import io.github.sequelcore.vigil.core.jwt.TokenRefreshResult;
import io.github.sequelcore.vigil.core.jwt.TokenRequest;
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
 * <p>Orchestrates token service, cookie service, and blacklist service for the complete auth
 * lifecycle: login, refresh, and logout.
 *
 * <p>Supports two client types:
 *
 * <ul>
 *   <li><b>Web SPAs</b> - Use cookie-based methods with HttpServletRequest/Response
 *   <li><b>Native apps &amp; APIs</b> - Use token-based methods with raw token strings (RFC 6749)
 * </ul>
 *
 * <p>Example usage for web clients:
 *
 * <pre>{@code
 * @PostMapping("/auth/login")
 * public AuthResult login(@RequestBody LoginRequest req, HttpServletResponse response) {
 *     User user = userRepository.findByEmail(req.email())
 *         .filter(u -> passwordService.matches(req.password(), u.getPasswordHash()))
 *         .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));
 *
 *     return authService.login(response, user.getEmail(), "staff",
 *         Map.of("userId", user.getId(), "roles", user.getRoles()));
 * }
 *
 * @PostMapping("/auth/refresh")
 * public AuthResult refresh(HttpServletRequest request, HttpServletResponse response) {
 *     return authService.refresh(request, response, "staff");
 * }
 *
 * @PostMapping("/auth/logout")
 * public void logout(HttpServletRequest request, HttpServletResponse response) {
 *     authService.logout(request, response, "staff");
 * }
 * }</pre>
 *
 * <p>Example usage for native apps (RFC 6749):
 *
 * <pre>{@code
 * @PostMapping("/auth/login")
 * public AuthResult login(@RequestBody LoginRequest req) {
 *     User user = userRepository.findByEmail(req.email())
 *         .filter(u -> passwordService.matches(req.password(), u.getPasswordHash()))
 *         .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));
 *
 *     return authService.login(user.getEmail(),
 *         Map.of("userId", user.getId(), "roles", user.getRoles()));
 * }
 *
 * @PostMapping("/auth/refresh")
 * public AuthResult refresh(@RequestBody RefreshRequest req) {
 *     return authService.refresh(req.refreshToken());
 * }
 *
 * @PostMapping("/auth/logout")
 * public void logout(@RequestBody LogoutRequest req) {
 *     authService.logout(req.accessToken(), req.refreshToken());
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
   * Creates a new authenticated session.
   *
   * <p>Generates access and refresh tokens, sets HTTP-only cookies, and returns the result. The
   * application is responsible for validating credentials before calling this method.
   *
   * @param response the HTTP response to set cookies on
   * @param subject the token subject (typically user ID or email)
   * @param profile the cookie profile (e.g., "staff", "customer", "default")
   * @param claims additional claims to include in the tokens
   * @return the tokens and their expiration times
   */
  public AuthResult login(
      HttpServletResponse response, String subject, String profile, Map<String, Object> claims) {
    AuthResult result = loginInternal(subject, claims);

    cookieService.setAccessTokenCookie(response, result.accessToken(), profile);
    cookieService.setRefreshTokenCookie(response, result.refreshToken(), profile);

    return result;
  }

  /**
   * Creates a new authenticated session with a specific profile and no custom claims.
   *
   * @param response the HTTP response to set cookies on
   * @param subject the token subject (typically user ID or email)
   * @param profile the cookie profile (e.g., "staff", "customer", "default")
   * @return the tokens and their expiration times
   */
  public AuthResult login(HttpServletResponse response, String subject, String profile) {
    return login(response, subject, profile, Map.of());
  }

  /**
   * Creates a new authenticated session using the default cookie profile.
   *
   * @param response the HTTP response to set cookies on
   * @param subject the token subject (typically user ID or email)
   * @param claims additional claims to include in the tokens
   * @return the tokens and their expiration times
   */
  public AuthResult login(
      HttpServletResponse response, String subject, Map<String, Object> claims) {
    return login(response, subject, "default", claims);
  }

  /**
   * Creates a new authenticated session using the default cookie profile and no custom claims.
   *
   * @param response the HTTP response to set cookies on
   * @param subject the token subject (typically user ID or email)
   * @return the tokens and their expiration times
   */
  public AuthResult login(HttpServletResponse response, String subject) {
    return login(response, subject, "default", Map.of());
  }

  // ==========================================================================
  // Token-based login (native apps & APIs - RFC 6749)
  // ==========================================================================

  /**
   * Creates a new authenticated session without cookies.
   *
   * <p>For native apps (iOS, Android) and APIs that manage tokens themselves. Per RFC 6749, tokens
   * are returned in the response body and the client stores them securely (Keychain/Keystore).
   *
   * @param subject the token subject (typically user ID or email)
   * @param claims additional claims to include in the tokens
   * @return the tokens and their expiration times
   */
  public AuthResult login(String subject, Map<String, Object> claims) {
    return loginInternal(subject, claims);
  }

  /**
   * Creates a new authenticated session without cookies and no custom claims.
   *
   * @param subject the token subject (typically user ID or email)
   * @return the tokens and their expiration times
   */
  public AuthResult login(String subject) {
    return login(subject, Map.of());
  }

  /**
   * Refreshes tokens using the refresh token from cookies with the default profile.
   *
   * @param request the HTTP request
   * @param response the HTTP response
   * @return the new tokens and expiration times
   * @throws VigilAuthException if refresh fails
   */
  public AuthResult refresh(HttpServletRequest request, HttpServletResponse response) {
    return refresh(request, response, "default", null);
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

    String refreshToken =
        cookieService
            .getRefreshToken(request, profile)
            .orElseThrow(
                () ->
                    new VigilAuthException(
                        AuthErrorCode.TOKEN_NOT_FOUND, "Refresh token not found"));

    AuthResult result = refreshInternal(refreshToken, updatedClaims);

    cookieService.setAccessTokenCookie(response, result.accessToken(), profile);
    cookieService.setRefreshTokenCookie(response, result.refreshToken(), profile);

    return result;
  }

  // ==========================================================================
  // Token-based refresh (native apps & APIs - RFC 6749)
  // ==========================================================================

  /**
   * Refreshes tokens using a raw refresh token.
   *
   * <p>For native apps (iOS, Android) and APIs. Per RFC 6749 Section 6, the refresh token is sent
   * in the request body. No cookies are set; the client stores tokens securely.
   *
   * @param refreshToken the refresh token from the client
   * @return the new tokens and expiration times
   * @throws VigilAuthException if refresh fails
   */
  public AuthResult refresh(String refreshToken) {
    return refreshInternal(refreshToken, null);
  }

  /**
   * Refreshes tokens with updated claims using a raw refresh token.
   *
   * <p>Use this when user data has changed and tokens need new claims.
   *
   * @param refreshToken the refresh token from the client
   * @param updatedClaims claims to add/update in new tokens (nullable)
   * @return the new tokens and expiration times
   * @throws VigilAuthException if refresh fails
   */
  public AuthResult refresh(String refreshToken, @Nullable Map<String, Object> updatedClaims) {
    return refreshInternal(refreshToken, updatedClaims);
  }

  // ==========================================================================
  // Cookie-based logout (web clients)
  // ==========================================================================

  /**
   * Logs out by blacklisting tokens and clearing cookies using the default profile.
   *
   * @param request the HTTP request
   * @param response the HTTP response
   */
  public void logout(HttpServletRequest request, HttpServletResponse response) {
    logout(request, response, "default");
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
    cookieService.getAccessToken(request, profile).ifPresent(blacklistService::blacklist);
    cookieService.getRefreshToken(request, profile).ifPresent(blacklistService::blacklist);
    cookieService.clearCookies(response, profile);
  }

  // ==========================================================================
  // Token-based logout (native apps & APIs - RFC 6749)
  // ==========================================================================

  /**
   * Logs out by blacklisting tokens directly.
   *
   * <p>For native apps (iOS, Android) and APIs. The client sends tokens in the request body and
   * then discards them from local storage.
   *
   * @param accessToken the access token to blacklist (nullable)
   * @param refreshToken the refresh token to blacklist (nullable)
   */
  public void logout(@Nullable String accessToken, @Nullable String refreshToken) {
    if (accessToken != null && !accessToken.isEmpty()) {
      blacklistService.blacklist(accessToken);
    }
    if (refreshToken != null && !refreshToken.isEmpty()) {
      blacklistService.blacklist(refreshToken);
    }
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

  /**
   * Core login logic shared by cookie-based and token-based login methods.
   *
   * @param subject the token subject
   * @param claims additional claims to include
   * @return the tokens and their expiration times
   */
  private AuthResult loginInternal(String subject, Map<String, Object> claims) {
    TokenRequest request = TokenRequest.builder().subject(subject).claims(claims).build();

    String accessToken = tokenService.generateAccessToken(request);
    String refreshToken = tokenService.generateRefreshToken(request);

    VigilTokenClaims accessClaims =
        new VigilTokenClaims(tokenService.validateAndGetClaims(accessToken));
    VigilTokenClaims refreshClaims =
        new VigilTokenClaims(tokenService.validateAndGetClaims(refreshToken));

    return new AuthResult(
        accessToken,
        refreshToken,
        accessClaims.getExpiration(),
        refreshClaims.getExpiration(),
        accessClaims);
  }

  /**
   * Core refresh logic shared by cookie-based and token-based refresh methods.
   *
   * @param refreshToken the refresh token
   * @param updatedClaims claims to add/update (nullable)
   * @return the new tokens and expiration times
   * @throws VigilAuthException if refresh fails
   */
  private AuthResult refreshInternal(
      String refreshToken, @Nullable Map<String, Object> updatedClaims) {
    if (blacklistService.isBlacklisted(refreshToken)) {
      throw new VigilAuthException(AuthErrorCode.TOKEN_BLACKLISTED, "Token has been invalidated");
    }

    TokenRefreshResult result;
    try {
      result = tokenService.refreshTokens(refreshToken, updatedClaims);
    } catch (ExpiredJwtException e) {
      throw new VigilAuthException(AuthErrorCode.TOKEN_EXPIRED, "Refresh token has expired", e);
    } catch (JwtException e) {
      throw new VigilAuthException(AuthErrorCode.TOKEN_INVALID, "Invalid refresh token", e);
    }

    VigilTokenClaims claims =
        new VigilTokenClaims(tokenService.validateAndGetClaims(result.accessToken()));

    return new AuthResult(
        result.accessToken(),
        result.refreshToken(),
        result.accessExpiresAt(),
        result.refreshExpiresAt(),
        claims);
  }
}
