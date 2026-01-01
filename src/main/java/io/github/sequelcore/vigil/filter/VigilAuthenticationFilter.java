package io.github.sequelcore.vigil.filter;

import io.github.sequelcore.vigil.blacklist.VigilBlacklistService;
import io.github.sequelcore.vigil.core.cookie.VigilCookieService;
import io.github.sequelcore.vigil.core.jwt.VigilTokenClaims;
import io.github.sequelcore.vigil.core.jwt.VigilTokenService;
import io.github.sequelcore.vigil.session.VigilSessionProvider;
import io.github.sequelcore.vigil.session.VigilSessionService;
import io.github.sequelcore.vigil.tenant.VigilTenantContext;
import io.github.sequelcore.vigil.tenant.VigilTenantService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * JWT and session authentication filter.
 *
 * <p>Authentication flow:
 *
 * <ol>
 *   <li>Check if path is public → skip authentication
 *   <li>Try to extract JWT from Authorization header or cookie
 *   <li>If JWT found → validate and authenticate
 *   <li>If no JWT and session provider exists → try session token
 *   <li>If no authentication → call onMissingAuthentication()
 * </ol>
 *
 * <p>Extend this class to customize authentication behavior:
 *
 * <pre>{@code
 * @Component
 * public class MyAuthFilter extends VigilAuthenticationFilter {
 *
 *     @Override
 *     protected void onAuthenticationSuccess(
 *             HttpServletRequest request,
 *             HttpServletResponse response,
 *             VigilTokenClaims claims) {
 *         // Populate application-specific context
 *         MyUserContext.set(claims.getString("userId").orElse(null));
 *     }
 * }
 * }</pre>
 */
public class VigilAuthenticationFilter extends OncePerRequestFilter {

  private static final String BEARER_PREFIX = "Bearer ";
  private static final String AUTHORIZATION_HEADER = "Authorization";

  private final VigilTokenService tokenService;
  private final VigilCookieService cookieService;
  private final VigilBlacklistService blacklistService;
  @Nullable private final VigilTenantService tenantService;
  @Nullable private final VigilSessionService sessionService;
  @Nullable private final VigilSessionProvider<?> sessionProvider;

  private final PathMatcher publicPathMatcher;

  /**
   * Creates a new authentication filter with all dependencies.
   *
   * @param tokenService the token service for JWT validation
   * @param cookieService the cookie service for token extraction
   * @param blacklistService the blacklist service for token/subject invalidation
   * @param tenantService optional tenant service for multi-tenancy
   * @param sessionService optional session service for stateful sessions
   * @param sessionProvider optional session provider (application-implemented)
   * @param publicPaths list of public path patterns (supports * and ** wildcards)
   */
  public VigilAuthenticationFilter(
      VigilTokenService tokenService,
      VigilCookieService cookieService,
      VigilBlacklistService blacklistService,
      @Nullable VigilTenantService tenantService,
      @Nullable VigilSessionService sessionService,
      @Nullable VigilSessionProvider<?> sessionProvider,
      List<String> publicPaths) {
    this.tokenService = tokenService;
    this.cookieService = cookieService;
    this.blacklistService = blacklistService;
    this.tenantService = tenantService;
    this.sessionService = sessionService;
    this.sessionProvider = sessionProvider;
    this.publicPathMatcher = new PathMatcher(publicPaths);
  }

  /**
   * Backwards-compatible constructor without session support.
   *
   * @param tokenService the token service
   * @param cookieService the cookie service
   * @param blacklistService the blacklist service
   * @param tenantService optional tenant service
   * @param publicPaths public path patterns
   */
  public VigilAuthenticationFilter(
      VigilTokenService tokenService,
      VigilCookieService cookieService,
      VigilBlacklistService blacklistService,
      @Nullable VigilTenantService tenantService,
      List<String> publicPaths) {
    this(tokenService, cookieService, blacklistService, tenantService, null, null, publicPaths);
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {

    try {
      String path = request.getRequestURI();

      // Skip authentication for public paths
      if (isPublicPath(path)) {
        filterChain.doFilter(request, response);
        return;
      }

      // Try JWT authentication first
      Optional<String> tokenOpt = extractToken(request);

      if (tokenOpt.isPresent()) {
        if (authenticateJwt(request, response, tokenOpt.get())) {
          filterChain.doFilter(request, response);
          return;
        }
      }

      // Try session authentication if available
      if (sessionService != null && sessionProvider != null) {
        Optional<String> sessionTokenOpt = sessionService.extractToken(request);
        if (sessionTokenOpt.isPresent()) {
          if (authenticateSession(request, response, sessionTokenOpt.get())) {
            filterChain.doFilter(request, response);
            return;
          }
        }
      }

      // No authentication found
      onMissingToken(request, response);
      filterChain.doFilter(request, response);

    } finally {
      // Clean up tenant context
      if (tenantService != null) {
        VigilTenantContext.clear();
      }
    }
  }

  private boolean authenticateJwt(
      HttpServletRequest request, HttpServletResponse response, String token) {

    // Check token blacklist
    if (blacklistService.isBlacklisted(token)) {
      onBlacklistedToken(request, response, token);
      return false;
    }

    // Validate token and extract claims
    VigilTokenClaims claims;
    try {
      claims = new VigilTokenClaims(tokenService.validateAndGetClaims(token));
    } catch (ExpiredJwtException e) {
      onExpiredToken(request, response, token);
      return false;
    } catch (JwtException e) {
      onInvalidToken(request, response, token, e);
      return false;
    }

    // Check subject blacklist (for invalidateAllSessions)
    String subject = claims.getSubject();
    Instant issuedAt = claims.getIssuedAt();
    if (subject != null && issuedAt != null) {
      if (blacklistService.isSubjectInvalidated(subject, issuedAt)) {
        onBlacklistedToken(request, response, token);
        return false;
      }
    }

    // Handle tenant context if enabled
    if (tenantService != null) {
      if (!handleTenantContext(request, response, claims)) {
        return false;
      }
    }

    // Set up Spring Security context
    List<SimpleGrantedAuthority> authorities = extractAuthorities(claims);
    UsernamePasswordAuthenticationToken authentication =
        new UsernamePasswordAuthenticationToken(claims.getSubject(), null, authorities);
    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
    SecurityContextHolder.getContext().setAuthentication(authentication);

    // Notify subclasses of successful authentication
    onAuthenticationSuccess(request, response, claims);

    return true;
  }

  @SuppressWarnings("unchecked")
  private boolean authenticateSession(
      HttpServletRequest request, HttpServletResponse response, String sessionToken) {

    // Extract tenant ID
    UUID tenantId = null;
    if (tenantService != null) {
      tenantId = tenantService.extractTenantId(request).orElse(null);
      if (tenantId != null) {
        tenantService.setCurrentTenant(tenantId);
      }
    }

    // Find session entity
    VigilSessionProvider<Object> provider = (VigilSessionProvider<Object>) sessionProvider;
    Optional<?> sessionOpt = provider.findByToken(sessionToken, tenantId);

    if (sessionOpt.isEmpty()) {
      onSessionNotFound(request, response, sessionToken);
      return false;
    }

    Object session = sessionOpt.get();

    // Check expiration
    if (provider.isExpired(session)) {
      onSessionExpired(request, response, sessionToken, session);
      return false;
    }

    // Set up Spring Security context
    String principal = provider.getPrincipal(session);
    if (principal == null || principal.isEmpty()) {
      onSessionNotFound(request, response, sessionToken);
      return false;
    }

    List<SimpleGrantedAuthority> authorities =
        provider.getRoles(session).stream()
            .map(r -> r.startsWith("ROLE_") ? r : "ROLE_" + r)
            .map(SimpleGrantedAuthority::new)
            .toList();

    UsernamePasswordAuthenticationToken authentication =
        new UsernamePasswordAuthenticationToken(principal, null, authorities);
    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
    SecurityContextHolder.getContext().setAuthentication(authentication);

    // Let application populate its context
    provider.onAuthenticated(session, request);

    // Notify subclasses
    onSessionAuthenticated(request, response, session);

    return true;
  }

  private boolean handleTenantContext(
      HttpServletRequest request, HttpServletResponse response, VigilTokenClaims claims) {

    Optional<UUID> headerTenant = tenantService.extractTenantId(request);
    Optional<UUID> tokenTenant = claims.getUuid("tenantId");

    if (headerTenant.isPresent()) {
      if (tokenTenant.isPresent() && !headerTenant.get().equals(tokenTenant.get())) {
        onTenantMismatch(request, response, headerTenant.get(), tokenTenant.get());
        return false;
      }
      tenantService.setCurrentTenant(headerTenant.get());
    } else if (tokenTenant.isPresent()) {
      tenantService.setCurrentTenant(tokenTenant.get());
    }

    return true;
  }

  /**
   * Extracts the JWT token from the request. Checks Authorization header first, then cookies.
   *
   * @param request the HTTP request
   * @return the token if present and non-empty
   */
  protected Optional<String> extractToken(HttpServletRequest request) {
    // Try Authorization header first (mobile/API clients)
    String authHeader = request.getHeader(AUTHORIZATION_HEADER);
    if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)) {
      String token = authHeader.substring(BEARER_PREFIX.length()).trim();
      if (!token.isEmpty()) {
        return Optional.of(token);
      }
    }

    // Fall back to cookie (web clients)
    return cookieService.getAccessToken(request).filter(t -> !t.isEmpty());
  }

  /**
   * Extracts authorities from token claims.
   *
   * @param claims the token claims
   * @return list of granted authorities
   */
  protected List<SimpleGrantedAuthority> extractAuthorities(VigilTokenClaims claims) {
    List<String> roles = claims.getStringList("roles");
    if (roles.isEmpty()) {
      // Try single role claim
      Optional<String> role = claims.getString("role");
      if (role.isPresent()) {
        roles = List.of(role.get());
      }
    }

    return roles.stream()
        .map(r -> r.startsWith("ROLE_") ? r : "ROLE_" + r)
        .map(SimpleGrantedAuthority::new)
        .toList();
  }

  /**
   * Checks if the given path should skip authentication.
   *
   * @param path the request path
   * @return true if the path is public
   */
  protected boolean isPublicPath(String path) {
    return publicPathMatcher.matches(path);
  }

  // ==========================================================================
  // JWT Hooks
  // ==========================================================================

  /**
   * Called when JWT authentication succeeds.
   *
   * @param request the HTTP request
   * @param response the HTTP response
   * @param claims the validated token claims
   */
  protected void onAuthenticationSuccess(
      HttpServletRequest request, HttpServletResponse response, VigilTokenClaims claims) {
    // Default: no-op
  }

  /**
   * Called when no token is present in the request.
   *
   * @param request the HTTP request
   * @param response the HTTP response
   */
  protected void onMissingToken(HttpServletRequest request, HttpServletResponse response) {
    // Default: no-op
  }

  /**
   * Called when the token has expired.
   *
   * @param request the HTTP request
   * @param response the HTTP response
   * @param token the expired token
   */
  protected void onExpiredToken(
      HttpServletRequest request, HttpServletResponse response, String token) {
    // Default: no-op
  }

  /**
   * Called when the token is invalid.
   *
   * @param request the HTTP request
   * @param response the HTTP response
   * @param token the invalid token
   * @param exception the validation exception
   */
  protected void onInvalidToken(
      HttpServletRequest request,
      HttpServletResponse response,
      String token,
      JwtException exception) {
    // Default: no-op
  }

  /**
   * Called when the token is blacklisted.
   *
   * @param request the HTTP request
   * @param response the HTTP response
   * @param token the blacklisted token
   */
  protected void onBlacklistedToken(
      HttpServletRequest request, HttpServletResponse response, String token) {
    // Default: no-op
  }

  /**
   * Called when tenant ID in header doesn't match token.
   *
   * @param request the HTTP request
   * @param response the HTTP response
   * @param headerTenant tenant ID from header
   * @param tokenTenant tenant ID from token
   */
  protected void onTenantMismatch(
      HttpServletRequest request,
      HttpServletResponse response,
      UUID headerTenant,
      UUID tokenTenant) {
    // Default: no-op
  }

  // ==========================================================================
  // Session Hooks
  // ==========================================================================

  /**
   * Called when session authentication succeeds.
   *
   * @param request the HTTP request
   * @param response the HTTP response
   * @param session the authenticated session entity
   */
  protected void onSessionAuthenticated(
      HttpServletRequest request, HttpServletResponse response, Object session) {
    // Default: no-op
  }

  /**
   * Called when session token is not found in database.
   *
   * @param request the HTTP request
   * @param response the HTTP response
   * @param token the session token that was not found
   */
  protected void onSessionNotFound(
      HttpServletRequest request, HttpServletResponse response, String token) {
    // Default: no-op
  }

  /**
   * Called when session has expired.
   *
   * @param request the HTTP request
   * @param response the HTTP response
   * @param token the session token
   * @param session the expired session entity
   */
  protected void onSessionExpired(
      HttpServletRequest request, HttpServletResponse response, String token, Object session) {
    // Default: no-op
  }
}
