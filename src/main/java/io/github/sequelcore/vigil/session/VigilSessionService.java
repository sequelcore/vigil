package io.github.sequelcore.vigil.session;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import io.github.sequelcore.vigil.core.cookie.VigilCookieService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Optional;
import java.util.UUID;

/**
 * Service for managing stateful session tokens and cookies.
 *
 * <p>Handles the infrastructure aspects of session authentication: token generation, cookie
 * management, and extraction. The application is responsible for persisting and looking up session
 * entities.
 *
 * <p>Example usage:
 *
 * <pre>{@code
 * @PostMapping("/guest-session")
 * public GuestResponse createGuestSession(HttpServletResponse response) {
 *     String token = sessionService.createSession(response);
 *     Customer customer = customerService.createGuest(token);
 *     return new GuestResponse(customer.getId(), token);
 * }
 * }</pre>
 */
public class VigilSessionService {

  private final VigilCookieService cookieService;
  private final String cookieName;
  private final int ttlSeconds;

  /**
   * Creates a session service with the provided configuration.
   *
   * @param cookieService the cookie service for cookie management
   * @param config session configuration properties
   */
  public VigilSessionService(VigilCookieService cookieService, VigilProperties.Session config) {
    this.cookieService = cookieService;
    this.cookieName = config.cookieName();
    this.ttlSeconds = (int) config.ttl().toSeconds();
  }

  /**
   * Generates a new session token.
   *
   * <p>Returns a random UUID string. Does not set any cookies or persist anything.
   *
   * @return new session token
   */
  public String generateToken() {
    return UUID.randomUUID().toString();
  }

  /**
   * Creates a session and sets the cookie.
   *
   * <p>Generates a token and sets it as an HTTP-only secure cookie.
   *
   * @param response the HTTP response
   * @return the generated session token
   */
  public String createSession(HttpServletResponse response) {
    String token = generateToken();
    cookieService.setCookie(response, cookieName, token, ttlSeconds);
    return token;
  }

  /**
   * Sets the session cookie with an existing token.
   *
   * <p>Use this when reusing an existing token (e.g., refreshing cookie expiration).
   *
   * @param response the HTTP response
   * @param token the session token
   */
  public void setSessionCookie(HttpServletResponse response, String token) {
    cookieService.setCookie(response, cookieName, token, ttlSeconds);
  }

  /**
   * Extracts the session token from the request cookie.
   *
   * @param request the HTTP request
   * @return the session token if present
   */
  public Optional<String> extractToken(HttpServletRequest request) {
    return cookieService.getCookieValue(request, cookieName);
  }

  /**
   * Clears the session cookie.
   *
   * @param response the HTTP response
   */
  public void clearSession(HttpServletResponse response) {
    cookieService.deleteCookie(response, cookieName);
  }

  /**
   * Returns the configured cookie name for session tokens.
   *
   * @return the cookie name
   */
  public String getCookieName() {
    return cookieName;
  }
}
