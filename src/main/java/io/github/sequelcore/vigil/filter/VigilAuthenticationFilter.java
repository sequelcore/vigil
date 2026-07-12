package io.github.sequelcore.vigil.filter;

import io.github.sequelcore.vigil.blacklist.VigilBlacklistService;
import io.github.sequelcore.vigil.context.VigilContextPopulator;
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
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * JWT and session authentication filter.
 *
 * <p>This filter separates authentication from authorization:
 *
 * <ul>
 *   <li><b>Ignored paths:</b> Skip all processing (no tenant, no auth, no populators)
 *   <li><b>Public paths:</b> Permit anonymous, but authenticate if credentials present
 *   <li><b>Protected paths:</b> Require authentication (Spring Security handles 401)
 * </ul>
 *
 * <p>Flow:
 *
 * <ol>
 *   <li>Check ignored paths - skip entirely if matched
 *   <li>Extract tenant context from header (if enabled)
 *   <li>Attempt JWT authentication (if credentials present)
 *   <li>Attempt session authentication (if JWT absent/failed and session enabled)
 *   <li>Authorization decision: proceed based on path type and auth status
 *   <li>Populate custom contexts via {@link VigilContextPopulator}
 * </ol>
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
  private final List<VigilContextPopulator> contextPopulators;
  private final PathMatcher ignoredPathMatcher;
  private final PathMatcher publicPathMatcher;
  private final ProfilePathMatcher profilePathMatcher;
  private SecurityContextRepository securityContextRepository =
      new RequestAttributeSecurityContextRepository();
  private final SecurityContextHolderStrategy securityContextHolderStrategy =
      SecurityContextHolder.getContextHolderStrategy();

  /** Creates a new authentication filter with all dependencies. */
  public VigilAuthenticationFilter(
      VigilTokenService tokenService,
      VigilCookieService cookieService,
      VigilBlacklistService blacklistService,
      @Nullable VigilTenantService tenantService,
      @Nullable VigilSessionService sessionService,
      @Nullable VigilSessionProvider<?> sessionProvider,
      List<VigilContextPopulator> contextPopulators,
      FilterConfig filterConfig) {
    this.tokenService = tokenService;
    this.cookieService = cookieService;
    this.blacklistService = blacklistService;
    this.tenantService = tenantService;
    this.sessionService = sessionService;
    this.sessionProvider = sessionProvider;
    this.contextPopulators =
        contextPopulators.stream()
            .sorted(Comparator.comparingInt(VigilContextPopulator::getOrder))
            .toList();
    this.ignoredPathMatcher = new PathMatcher(filterConfig.ignoredPaths());
    this.publicPathMatcher = new PathMatcher(filterConfig.publicPaths());
    this.profilePathMatcher = new ProfilePathMatcher(filterConfig.profilePaths());
  }

  /** Sets the repository used to preserve authentication within the same servlet request. */
  public void setSecurityContextRepository(SecurityContextRepository securityContextRepository) {
    this.securityContextRepository = Objects.requireNonNull(securityContextRepository);
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {

    String path = request.getRequestURI();

    // Step 1: Ignored paths - skip ALL processing (no tenant, no auth, no populators)
    if (isIgnoredPath(path)) {
      filterChain.doFilter(request, response);
      return;
    }

    VigilTokenClaims authenticatedClaims = null;
    boolean authenticated = false;

    try {
      // Step 2: Extract tenant context (always for non-ignored paths)
      if (tenantService != null) {
        tenantService.extractTenantId(request).ifPresent(tenantService::setCurrentTenant);
      }

      // Step 3: Try JWT authentication (if credentials present)
      Optional<String> tokenOpt = extractToken(request, path);
      if (tokenOpt.isPresent()) {
        authenticatedClaims = authenticateJwt(request, response, tokenOpt.get());
        authenticated = (authenticatedClaims != null);
      }

      // Step 4: Try session authentication if JWT failed/absent
      if (!authenticated && sessionService != null && sessionProvider != null) {
        Optional<String> sessionTokenOpt = sessionService.extractToken(request);
        if (sessionTokenOpt.isPresent()) {
          authenticated = authenticateSession(request, response, sessionTokenOpt.get());
        }
      }

      // Step 5: Authorization decision + context population
      if (authenticated) {
        // Authenticated - SecurityContext already set by authenticateJwt/authenticateSession
        populateContexts(request, authenticatedClaims);
      } else if (isPublicPath(path)) {
        // Public path - permit anonymous access
        populateContexts(request, null);
      } else {
        // Protected path without authentication
        onMissingToken(request, response);
        populateContexts(request, null);
      }

      filterChain.doFilter(request, response);

    } finally {
      clearContexts();
      if (tenantService != null) {
        VigilTenantContext.clear();
      }
    }
  }

  private void populateContexts(HttpServletRequest request, @Nullable VigilTokenClaims claims) {
    for (VigilContextPopulator populator : contextPopulators) {
      populator.populate(request, claims);
    }
  }

  private void clearContexts() {
    for (VigilContextPopulator populator : contextPopulators) {
      populator.clear();
    }
  }

  @Nullable
  private VigilTokenClaims authenticateJwt(
      HttpServletRequest request, HttpServletResponse response, String token) {

    // Check token blacklist
    if (blacklistService.isBlacklisted(token)) {
      onBlacklistedToken(request, response, token);
      return null;
    }

    // Validate token and extract claims
    VigilTokenClaims claims;
    try {
      claims = new VigilTokenClaims(tokenService.validateAndGetClaims(token));
    } catch (ExpiredJwtException e) {
      onExpiredToken(request, response, token);
      return null;
    } catch (JwtException e) {
      onInvalidToken(request, response, token, e);
      return null;
    }

    // Check subject blacklist (for invalidateAllSessions)
    String subject = claims.getSubject();
    Instant issuedAt = claims.getIssuedAt();
    if (subject != null && issuedAt != null) {
      if (blacklistService.isSubjectInvalidated(subject, issuedAt)) {
        onBlacklistedToken(request, response, token);
        return null;
      }
    }

    // Handle tenant context if enabled
    if (tenantService != null) {
      if (!handleTenantContext(request, response, claims)) {
        return null;
      }
    }

    // Set up Spring Security context
    List<SimpleGrantedAuthority> authorities = extractAuthorities(claims);
    UsernamePasswordAuthenticationToken authentication =
        new UsernamePasswordAuthenticationToken(claims.getSubject(), null, authorities);
    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
    saveAuthentication(request, response, authentication);

    // Notify subclasses of successful authentication
    onAuthenticationSuccess(request, response, claims);

    return claims;
  }

  @SuppressWarnings("unchecked")
  private boolean authenticateSession(
      HttpServletRequest request, HttpServletResponse response, String sessionToken) {

    // Tenant already set at filter start, just get the value for session lookup
    UUID tenantId = VigilTenantContext.getTenant().orElse(null);

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
    saveAuthentication(request, response, authentication);

    // Let application populate its context
    provider.onAuthenticated(session, request);

    // Notify subclasses
    onSessionAuthenticated(request, response, session);

    return true;
  }

  private void saveAuthentication(
      HttpServletRequest request,
      HttpServletResponse response,
      UsernamePasswordAuthenticationToken authentication) {
    var context = securityContextHolderStrategy.createEmptyContext();
    context.setAuthentication(authentication);
    securityContextHolderStrategy.setContext(context);
    securityContextRepository.saveContext(context, request, response);
  }

  private boolean handleTenantContext(
      HttpServletRequest request, HttpServletResponse response, VigilTokenClaims claims) {

    // Header tenant already set at filter start, now validate against token
    Optional<UUID> headerTenant = VigilTenantContext.getTenant();
    Optional<UUID> tokenTenant = claims.getUuid("tenantId");

    if (headerTenant.isPresent() && tokenTenant.isPresent()) {
      if (!headerTenant.get().equals(tokenTenant.get())) {
        onTenantMismatch(request, response, headerTenant.get(), tokenTenant.get());
        return false;
      }
    } else if (tokenTenant.isPresent()) {
      // No header tenant, use token tenant
      tenantService.setCurrentTenant(tokenTenant.get());
    }

    return true;
  }

  /** Extracts the JWT token from Authorization header or cookies. */
  protected Optional<String> extractToken(HttpServletRequest request, String path) {
    // Try Authorization header first (mobile/API clients)
    String authHeader = request.getHeader(AUTHORIZATION_HEADER);
    if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)) {
      String token = authHeader.substring(BEARER_PREFIX.length()).trim();
      if (!token.isEmpty()) {
        return Optional.of(token);
      }
    }

    // Fall back to cookie (web clients)
    // Use profile-paths mapping to determine which cookie to check
    Optional<String> profile = profilePathMatcher.findProfile(path);
    if (profile.isPresent()) {
      return cookieService.getAccessToken(request, profile.get()).filter(t -> !t.isEmpty());
    }

    // No profile mapping found, use default profile
    return cookieService.getAccessToken(request).filter(t -> !t.isEmpty());
  }

  /** Extracts authorities from token claims. */
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

  /** Checks if the given path should skip ALL processing (no tenant, no auth, no populators). */
  protected boolean isIgnoredPath(String path) {
    return ignoredPathMatcher.matches(path);
  }

  /**
   * Checks if the given path permits anonymous access (but authenticates if credentials present).
   */
  protected boolean isPublicPath(String path) {
    return publicPathMatcher.matches(path);
  }

  // JWT Hooks

  /** Called when JWT authentication succeeds. */
  protected void onAuthenticationSuccess(
      HttpServletRequest request, HttpServletResponse response, VigilTokenClaims claims) {}

  /**
   * Called when no token is present in the request.
   *
   * <p>Per RFC 6750, no error code should be set when the request lacks authentication information.
   */
  protected void onMissingToken(HttpServletRequest request, HttpServletResponse response) {
    // No error code per RFC 6750 Section 3:
    // "If the request lacks any authentication information...
    // the resource server SHOULD NOT include an error code"
  }

  /** Called when the token has expired. */
  protected void onExpiredToken(
      HttpServletRequest request, HttpServletResponse response, String token) {
    request.setAttribute("vigil.error.code", "invalid_token");
    request.setAttribute("vigil.error.description", "The access token has expired");
  }

  /** Called when the token is invalid. */
  protected void onInvalidToken(
      HttpServletRequest request, HttpServletResponse response, String token, JwtException e) {
    request.setAttribute("vigil.error.code", "invalid_token");
    request.setAttribute("vigil.error.description", "Invalid access token");
  }

  /** Called when the token is blacklisted. */
  protected void onBlacklistedToken(
      HttpServletRequest request, HttpServletResponse response, String token) {
    request.setAttribute("vigil.error.code", "invalid_token");
    request.setAttribute("vigil.error.description", "Token has been revoked");
  }

  /** Called when tenant ID in header doesn't match token. */
  protected void onTenantMismatch(
      HttpServletRequest request,
      HttpServletResponse response,
      UUID headerTenant,
      UUID tokenTenant) {}

  // Session Hooks

  /** Called when session authentication succeeds. */
  protected void onSessionAuthenticated(
      HttpServletRequest request, HttpServletResponse response, Object session) {}

  /** Called when session token is not found in database. */
  protected void onSessionNotFound(
      HttpServletRequest request, HttpServletResponse response, String token) {}

  /** Called when session has expired. */
  protected void onSessionExpired(
      HttpServletRequest request, HttpServletResponse response, String token, Object session) {}
}
