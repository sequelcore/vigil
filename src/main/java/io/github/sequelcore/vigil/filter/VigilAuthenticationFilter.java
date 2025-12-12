package io.github.sequelcore.vigil.filter;

import io.github.sequelcore.vigil.blacklist.VigilBlacklistService;
import io.github.sequelcore.vigil.core.cookie.VigilCookieService;
import io.github.sequelcore.vigil.core.jwt.VigilTokenClaims;
import io.github.sequelcore.vigil.core.jwt.VigilTokenService;
import io.github.sequelcore.vigil.tenant.VigilTenantContext;
import io.github.sequelcore.vigil.tenant.VigilTenantService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * JWT authentication filter that validates tokens from cookies or Authorization header.
 *
 * <p>Supports dual client mode:
 *
 * <ul>
 *   <li>Web clients: Token extracted from HttpOnly cookies
 *   <li>Mobile/API clients: Token extracted from Authorization Bearer header
 * </ul>
 *
 * <p>Extend this class to customize authentication behavior.
 */
public class VigilAuthenticationFilter extends OncePerRequestFilter {

  private static final String BEARER_PREFIX = "Bearer ";
  private static final String AUTHORIZATION_HEADER = "Authorization";

  private final VigilTokenService tokenService;
  private final VigilCookieService cookieService;
  @Nullable private final VigilBlacklistService blacklistService;
  @Nullable private final VigilTenantService tenantService;

  private final List<Pattern> publicPathPatterns;

  /**
   * Creates a new authentication filter.
   *
   * @param tokenService the token service for JWT validation
   * @param cookieService the cookie service for token extraction
   * @param blacklistService optional blacklist service
   * @param tenantService optional tenant service
   * @param publicPaths list of public path patterns (supports * and ** wildcards)
   */
  public VigilAuthenticationFilter(
      VigilTokenService tokenService,
      VigilCookieService cookieService,
      @Nullable VigilBlacklistService blacklistService,
      @Nullable VigilTenantService tenantService,
      List<String> publicPaths) {
    this.tokenService = tokenService;
    this.cookieService = cookieService;
    this.blacklistService = blacklistService;
    this.tenantService = tenantService;
    this.publicPathPatterns = compilePathPatterns(publicPaths);
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

      // Extract token from request
      Optional<String> tokenOpt = extractToken(request);

      if (tokenOpt.isEmpty()) {
        onMissingToken(request, response);
        filterChain.doFilter(request, response);
        return;
      }

      String token = tokenOpt.get();

      // Check blacklist if enabled
      if (blacklistService != null && blacklistService.isBlacklisted(token)) {
        onBlacklistedToken(request, response, token);
        filterChain.doFilter(request, response);
        return;
      }

      // Validate token and extract claims
      VigilTokenClaims claims;
      try {
        claims = new VigilTokenClaims(tokenService.validateAndGetClaims(token));
      } catch (ExpiredJwtException e) {
        onExpiredToken(request, response, token);
        filterChain.doFilter(request, response);
        return;
      } catch (JwtException e) {
        onInvalidToken(request, response, token, e);
        filterChain.doFilter(request, response);
        return;
      }

      // Handle tenant context if enabled
      if (tenantService != null) {
        Optional<UUID> headerTenant = tenantService.extractTenantId(request);
        Optional<UUID> tokenTenant = claims.getUuid("tenantId");

        if (headerTenant.isPresent()) {
          if (tokenTenant.isPresent() && !headerTenant.get().equals(tokenTenant.get())) {
            onTenantMismatch(request, response, headerTenant.get(), tokenTenant.get());
            filterChain.doFilter(request, response);
            return;
          }
          tenantService.setCurrentTenant(headerTenant.get());
        } else if (tokenTenant.isPresent()) {
          tenantService.setCurrentTenant(tokenTenant.get());
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

      filterChain.doFilter(request, response);
    } finally {
      // Clean up tenant context
      if (tenantService != null) {
        VigilTenantContext.clear();
      }
    }
  }

  /**
   * Extracts the JWT token from the request. Checks Authorization header first, then cookies.
   *
   * @param request the HTTP request
   * @return the token if present
   */
  protected Optional<String> extractToken(HttpServletRequest request) {
    // Try Authorization header first (mobile/API clients)
    String authHeader = request.getHeader(AUTHORIZATION_HEADER);
    if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)) {
      return Optional.of(authHeader.substring(BEARER_PREFIX.length()));
    }

    // Fall back to cookie (web clients)
    return cookieService.getAccessToken(request);
  }

  /**
   * Extracts authorities from token claims. Override to customize authority extraction.
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
    return publicPathPatterns.stream().anyMatch(pattern -> pattern.matcher(path).matches());
  }

  /**
   * Called when authentication succeeds. Override to add custom logic.
   *
   * @param request the HTTP request
   * @param response the HTTP response
   * @param claims the validated token claims
   */
  protected void onAuthenticationSuccess(
      HttpServletRequest request, HttpServletResponse response, VigilTokenClaims claims) {
    // Default: no-op. Override in subclass.
  }

  /**
   * Called when no token is present in the request.
   *
   * @param request the HTTP request
   * @param response the HTTP response
   */
  protected void onMissingToken(HttpServletRequest request, HttpServletResponse response) {
    // Default: no-op. Override in subclass if needed.
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
    // Default: no-op. Override in subclass if needed.
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
    // Default: no-op. Override in subclass if needed.
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
    // Default: no-op. Override in subclass if needed.
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
    // Default: no-op. Override in subclass if needed.
  }

  private List<Pattern> compilePathPatterns(List<String> paths) {
    if (paths == null || paths.isEmpty()) {
      return Collections.emptyList();
    }

    return paths.stream().map(this::pathToRegex).map(Pattern::compile).toList();
  }

  private String pathToRegex(String path) {
    // Escape regex special characters except * and **
    String regex =
        path.replace(".", "\\.")
            .replace("?", "\\?")
            .replace("+", "\\+")
            .replace("(", "\\(")
            .replace(")", "\\)")
            .replace("[", "\\[")
            .replace("]", "\\]")
            .replace("{", "\\{")
            .replace("}", "\\}")
            .replace("^", "\\^")
            .replace("$", "\\$")
            .replace("|", "\\|");

    // Convert ** to match any path segments
    regex = regex.replace("**", "@@DOUBLE_STAR@@");
    // Convert * to match single path segment
    regex = regex.replace("*", "[^/]*");
    // Convert ** placeholder to match anything
    regex = regex.replace("@@DOUBLE_STAR@@", ".*");

    return "^" + regex + "$";
  }
}
