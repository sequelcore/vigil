package io.github.sequelcore.vigil.core.cookie;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Optional;

/**
 * Service for managing authentication cookies with profile support.
 *
 * <p>Profiles allow different cookie names for different user types (staff, customer, etc.).
 */
public class VigilCookieService {

  private final VigilProperties.Cookie cookieConfig;
  private final VigilProperties.Jwt jwtConfig;

  public VigilCookieService(VigilProperties.Cookie cookieConfig, VigilProperties.Jwt jwtConfig) {
    this.cookieConfig = cookieConfig;
    this.jwtConfig = jwtConfig;
  }

  // ==========================================================================
  // Profile-based methods
  // ==========================================================================

  /**
   * Sets the access token cookie for a specific profile.
   *
   * @param response HTTP response
   * @param token access token
   * @param profile profile name (e.g., "staff", "customer")
   */
  public void setAccessTokenCookie(HttpServletResponse response, String token, String profile) {
    var p = cookieConfig.getProfile(profile);
    setSecureCookie(response, p.accessTokenName(), token, (int) jwtConfig.accessTtl().toSeconds());
  }

  /**
   * Sets the refresh token cookie for a specific profile.
   *
   * @param response HTTP response
   * @param token refresh token
   * @param profile profile name
   */
  public void setRefreshTokenCookie(HttpServletResponse response, String token, String profile) {
    var p = cookieConfig.getProfile(profile);
    setSecureCookie(
        response, p.refreshTokenName(), token, (int) jwtConfig.refreshTtl().toSeconds());
  }

  /**
   * Clears all cookies for a specific profile.
   *
   * @param response HTTP response
   * @param profile profile name
   */
  public void clearCookies(HttpServletResponse response, String profile) {
    var p = cookieConfig.getProfile(profile);
    setSecureCookie(response, p.accessTokenName(), "", 0);
    setSecureCookie(response, p.refreshTokenName(), "", 0);
  }

  /**
   * Gets the access token from a specific profile's cookie.
   *
   * @param request HTTP request
   * @param profile profile name
   * @return access token if present
   */
  public Optional<String> getAccessToken(HttpServletRequest request, String profile) {
    var p = cookieConfig.getProfile(profile);
    return getCookieValue(request, p.accessTokenName());
  }

  /**
   * Gets the refresh token from a specific profile's cookie.
   *
   * @param request HTTP request
   * @param profile profile name
   * @return refresh token if present
   */
  public Optional<String> getRefreshToken(HttpServletRequest request, String profile) {
    var p = cookieConfig.getProfile(profile);
    return getCookieValue(request, p.refreshTokenName());
  }

  // ==========================================================================
  // Default profile methods (uses first configured profile)
  // ==========================================================================

  /** Sets access token cookie using default profile. */
  public void setAccessTokenCookie(HttpServletResponse response, String token) {
    var p = cookieConfig.getDefaultProfile();
    setSecureCookie(response, p.accessTokenName(), token, (int) jwtConfig.accessTtl().toSeconds());
  }

  /** Sets refresh token cookie using default profile. */
  public void setRefreshTokenCookie(HttpServletResponse response, String token) {
    var p = cookieConfig.getDefaultProfile();
    setSecureCookie(
        response, p.refreshTokenName(), token, (int) jwtConfig.refreshTtl().toSeconds());
  }

  /** Clears cookies using default profile. */
  public void clearCookies(HttpServletResponse response) {
    var p = cookieConfig.getDefaultProfile();
    setSecureCookie(response, p.accessTokenName(), "", 0);
    setSecureCookie(response, p.refreshTokenName(), "", 0);
  }

  /** Gets access token using default profile. */
  public Optional<String> getAccessToken(HttpServletRequest request) {
    var p = cookieConfig.getDefaultProfile();
    return getCookieValue(request, p.accessTokenName());
  }

  /** Gets refresh token using default profile. */
  public Optional<String> getRefreshToken(HttpServletRequest request) {
    var p = cookieConfig.getDefaultProfile();
    return getCookieValue(request, p.refreshTokenName());
  }

  // ==========================================================================
  // Custom cookie methods
  // ==========================================================================

  /**
   * Sets a custom cookie with security settings.
   *
   * @param response HTTP response
   * @param name cookie name
   * @param value cookie value
   * @param maxAgeSeconds max age in seconds
   */
  public void setCookie(
      HttpServletResponse response, String name, String value, int maxAgeSeconds) {
    setSecureCookie(response, name, value, maxAgeSeconds);
  }

  /**
   * Deletes a cookie by name.
   *
   * @param response HTTP response
   * @param name cookie name
   */
  public void deleteCookie(HttpServletResponse response, String name) {
    setSecureCookie(response, name, "", 0);
  }

  // ==========================================================================
  // Internal
  // ==========================================================================

  private void setSecureCookie(
      HttpServletResponse response, String name, String value, int maxAge) {
    StringBuilder cookie = new StringBuilder();
    cookie.append(name).append("=").append(value);
    cookie.append("; Max-Age=").append(maxAge);
    cookie.append("; Path=/");

    if (cookieConfig.httpOnly()) {
      cookie.append("; HttpOnly");
    }
    if (cookieConfig.secure()) {
      cookie.append("; Secure");
    }
    cookie.append("; SameSite=").append(cookieConfig.sameSite());

    response.addHeader("Set-Cookie", cookie.toString());
  }

  /**
   * Gets a cookie value by name.
   *
   * @param request HTTP request
   * @param name cookie name
   * @return cookie value if present
   */
  public Optional<String> getCookieValue(HttpServletRequest request, String name) {
    Cookie[] cookies = request.getCookies();
    if (cookies == null) {
      return Optional.empty();
    }
    return Arrays.stream(cookies)
        .filter(c -> name.equals(c.getName()))
        .map(Cookie::getValue)
        .findFirst();
  }
}
