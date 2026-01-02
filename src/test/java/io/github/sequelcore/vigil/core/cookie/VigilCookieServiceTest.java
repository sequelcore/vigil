package io.github.sequelcore.vigil.core.cookie;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class VigilCookieServiceTest {

  private VigilCookieService cookieService;

  @Mock private HttpServletResponse response;
  @Mock private HttpServletRequest request;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
    var cookieConfig =
        new VigilProperties.Cookie(
            true,
            "Lax",
            true,
            Map.of("default", new VigilProperties.CookieProfile("access_token", "refresh_token")));
    var jwtConfig =
        new VigilProperties.Jwt(
            "01234567890123456789012345678901",
            Duration.ofMinutes(15),
            Duration.ofDays(7),
            null,
            null);
    cookieService = new VigilCookieService(cookieConfig, jwtConfig);
  }

  @Test
  @DisplayName("Set access token cookie with correct attributes")
  void setAccessTokenCookie() {
    ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);

    cookieService.setAccessTokenCookie(response, "abc");

    verify(response).addHeader(eq("Set-Cookie"), captor.capture());
    String header = captor.getValue();
    assertThat(header).startsWith("access_token=abc");
    assertThat(header).contains("Max-Age=900");
    assertThat(header).contains("Path=/");
    assertThat(header).contains("HttpOnly");
    assertThat(header).contains("Secure");
    assertThat(header).contains("SameSite=Lax");
  }

  @Test
  @DisplayName("Set refresh token cookie uses refresh TTL")
  void setRefreshTokenCookie() {
    ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);

    cookieService.setRefreshTokenCookie(response, "refresh-token");

    verify(response).addHeader(eq("Set-Cookie"), captor.capture());
    String header = captor.getValue();
    assertThat(header).startsWith("refresh_token=refresh-token");
    assertThat(header).contains("Max-Age=604800");
    assertThat(header).contains("HttpOnly");
    assertThat(header).contains("Secure");
  }

  @Test
  @DisplayName("Clear cookies sets Max-Age=0 for both cookies")
  void clearCookies() {
    ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);

    cookieService.clearCookies(response);

    verify(response, times(2)).addHeader(eq("Set-Cookie"), captor.capture());
    assertThat(captor.getAllValues().get(0)).startsWith("access_token=");
    assertThat(captor.getAllValues().get(0)).contains("Max-Age=0");
    assertThat(captor.getAllValues().get(1)).startsWith("refresh_token=");
    assertThat(captor.getAllValues().get(1)).contains("Max-Age=0");
  }

  @Test
  @DisplayName("Extract token from cookies")
  void getAccessTokenFromCookies() {
    when(request.getCookies())
        .thenReturn(
            new Cookie[] {new Cookie("access_token", "token123"), new Cookie("other", "x")});

    Optional<String> token = cookieService.getAccessToken(request);

    assertThat(token).contains("token123");
  }

  @Test
  @DisplayName("Handle null cookies array")
  void handleNullCookies() {
    when(request.getCookies()).thenReturn(null);

    assertThat(cookieService.getRefreshToken(request)).isEmpty();
  }

  @Test
  @DisplayName("Set access token with profile")
  void setAccessTokenWithProfile() {
    ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);

    cookieService.setAccessTokenCookie(response, "token123", "default");

    verify(response).addHeader(eq("Set-Cookie"), captor.capture());
    assertThat(captor.getValue()).startsWith("access_token=token123");
    assertThat(captor.getValue()).contains("Max-Age=900");
  }

  @Test
  @DisplayName("Set refresh token with profile")
  void setRefreshTokenWithProfile() {
    ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);

    cookieService.setRefreshTokenCookie(response, "refresh123", "default");

    verify(response).addHeader(eq("Set-Cookie"), captor.capture());
    assertThat(captor.getValue()).startsWith("refresh_token=refresh123");
    assertThat(captor.getValue()).contains("Max-Age=604800");
  }

  @Test
  @DisplayName("Clear cookies with profile")
  void clearCookiesWithProfile() {
    ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);

    cookieService.clearCookies(response, "default");

    verify(response, times(2)).addHeader(eq("Set-Cookie"), captor.capture());
    assertThat(captor.getAllValues().get(0)).startsWith("access_token=");
    assertThat(captor.getAllValues().get(0)).contains("Max-Age=0");
    assertThat(captor.getAllValues().get(1)).startsWith("refresh_token=");
    assertThat(captor.getAllValues().get(1)).contains("Max-Age=0");
  }

  @Test
  @DisplayName("Get access token with profile")
  void getAccessTokenWithProfile() {
    when(request.getCookies())
        .thenReturn(
            new Cookie[] {new Cookie("access_token", "token123"), new Cookie("other", "x")});

    Optional<String> token = cookieService.getAccessToken(request, "default");

    assertThat(token).contains("token123");
  }

  @Test
  @DisplayName("Get refresh token with profile")
  void getRefreshTokenWithProfile() {
    when(request.getCookies()).thenReturn(new Cookie[] {new Cookie("refresh_token", "refresh123")});

    Optional<String> token = cookieService.getRefreshToken(request, "default");

    assertThat(token).contains("refresh123");
  }

  @Test
  @DisplayName("Multiple profiles use different cookie names")
  void multipleProfiles() {
    var multiProfileConfig =
        new VigilProperties.Cookie(
            true,
            "Strict",
            true,
            Map.of(
                "staff",
                new VigilProperties.CookieProfile("staff_access", "staff_refresh"),
                "customer",
                new VigilProperties.CookieProfile("customer_access", "customer_refresh")));
    var jwtConfig =
        new VigilProperties.Jwt(
            "01234567890123456789012345678901",
            Duration.ofMinutes(15),
            Duration.ofDays(7),
            null,
            null);
    var multiService = new VigilCookieService(multiProfileConfig, jwtConfig);

    ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);

    multiService.setAccessTokenCookie(response, "stafftoken", "staff");
    multiService.setAccessTokenCookie(response, "custtoken", "customer");

    verify(response, times(2)).addHeader(eq("Set-Cookie"), captor.capture());
    assertThat(captor.getAllValues().get(0)).startsWith("staff_access=stafftoken");
    assertThat(captor.getAllValues().get(1)).startsWith("customer_access=custtoken");
  }

  @Test
  @DisplayName("Set custom cookie")
  void setCustomCookie() {
    ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);

    cookieService.setCookie(response, "custom", "value", 3600);

    verify(response).addHeader(eq("Set-Cookie"), captor.capture());
    assertThat(captor.getValue()).startsWith("custom=value");
    assertThat(captor.getValue()).contains("Max-Age=3600");
  }

  @Test
  @DisplayName("Delete cookie")
  void deleteCookie() {
    ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);

    cookieService.deleteCookie(response, "mycookie");

    verify(response).addHeader(eq("Set-Cookie"), captor.capture());
    assertThat(captor.getValue()).startsWith("mycookie=");
    assertThat(captor.getValue()).contains("Max-Age=0");
  }

  @Test
  @DisplayName("Non-secure cookies for development")
  void nonSecureCookies() {
    var devConfig =
        new VigilProperties.Cookie(
            false,
            "Lax",
            false,
            Map.of("default", new VigilProperties.CookieProfile("access", "refresh")));
    var jwtConfig =
        new VigilProperties.Jwt(
            "01234567890123456789012345678901",
            Duration.ofMinutes(15),
            Duration.ofDays(7),
            null,
            null);
    var devService = new VigilCookieService(devConfig, jwtConfig);

    ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);

    devService.setAccessTokenCookie(response, "token");

    verify(response).addHeader(eq("Set-Cookie"), captor.capture());
    assertThat(captor.getValue()).startsWith("access=token");
    assertThat(captor.getValue()).contains("Max-Age=900");
    assertThat(captor.getValue()).doesNotContain("HttpOnly");
    assertThat(captor.getValue()).doesNotContain("Secure");
  }
}
