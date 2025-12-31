package io.github.sequelcore.vigil.core.cookie;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Optional;

/** Service for managing authentication cookies. */
public class VigilCookieService {

  private final VigilProperties.Cookie cookieConfig;
  private final VigilProperties.Jwt jwtConfig;

  /**
   * Creates a cookie service using the provided configuration.
   *
   * @param cookieConfig cookie configuration properties
   * @param jwtConfig JWT configuration properties
   */
  public VigilCookieService(VigilProperties.Cookie cookieConfig, VigilProperties.Jwt jwtConfig) {
    this.cookieConfig = cookieConfig;
    this.jwtConfig = jwtConfig;
  }

  /**
   * Sets the access token cookie on the response.
   *
   * @param response the HTTP response
   * @param token the access token
   */
  public void setAccessTokenCookie(HttpServletResponse response, String token) {
    setSecureCookie(
        response, cookieConfig.accessTokenName(), token, (int) jwtConfig.accessTtl().toSeconds());
  }

  /**
   * Sets the refresh token cookie on the response.
   *
   * @param response the HTTP response
   * @param token the refresh token
   */
  public void setRefreshTokenCookie(HttpServletResponse response, String token) {
    setSecureCookie(
        response, cookieConfig.refreshTokenName(), token, (int) jwtConfig.refreshTtl().toSeconds());
  }

  /**
   * Clears all authentication cookies (access and refresh tokens).
   *
   * @param response the HTTP response
   */
  public void clearCookies(HttpServletResponse response) {
    setSecureCookie(response, cookieConfig.accessTokenName(), "", 0);
    setSecureCookie(response, cookieConfig.refreshTokenName(), "", 0);
  }

  /**
   * Extracts the access token from request cookies.
   *
   * @param request the HTTP request
   * @return the access token if present
   */
  public Optional<String> getAccessToken(HttpServletRequest request) {
    return getCookieValue(request, cookieConfig.accessTokenName());
  }

  /**
   * Extracts the refresh token from request cookies.
   *
   * @param request the HTTP request
   * @return the refresh token if present
   */
  public Optional<String> getRefreshToken(HttpServletRequest request) {
    return getCookieValue(request, cookieConfig.refreshTokenName());
  }

  /**
   * Sets a custom named cookie on the response.
   *
   * <p>Uses the same security settings (HttpOnly, Secure, SameSite) as configured for auth cookies.
   *
   * @param response the HTTP response
   * @param name the cookie name
   * @param value the cookie value
   * @param maxAgeSeconds the max age in seconds
   */
  public void setCookie(
      HttpServletResponse response, String name, String value, int maxAgeSeconds) {
    setSecureCookie(response, name, value, maxAgeSeconds);
  }

  /**
   * Deletes a specific cookie by name.
   *
   * @param response the HTTP response
   * @param name the cookie name to delete
   */
  public void deleteCookie(HttpServletResponse response, String name) {
    setSecureCookie(response, name, "", 0);
  }

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

  private Optional<String> getCookieValue(HttpServletRequest request, String name) {
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
