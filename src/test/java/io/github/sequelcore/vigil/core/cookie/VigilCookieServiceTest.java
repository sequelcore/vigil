package io.github.sequelcore.vigil.core.cookie;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Duration;
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
        new VigilProperties.Cookie("access_token", "refresh_token", true, "Lax", true);
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
    assertThat(header)
        .isEqualTo("access_token=abc; Max-Age=900; Path=/; HttpOnly; Secure; SameSite=Lax");
    verifyNoMoreInteractions(response);
  }

  @Test
  @DisplayName("Set refresh token cookie uses refresh TTL")
  void setRefreshTokenCookie() {
    ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);

    cookieService.setRefreshTokenCookie(response, "refresh-token");

    verify(response).addHeader(eq("Set-Cookie"), captor.capture());
    String header = captor.getValue();
    assertThat(header)
        .isEqualTo(
            "refresh_token=refresh-token; Max-Age=604800; Path=/; HttpOnly; Secure; SameSite=Lax");
  }

  @Test
  @DisplayName("Clear cookies sets Max-Age=0 for both cookies")
  void clearCookies() {
    ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);

    cookieService.clearCookies(response);

    verify(response, times(2)).addHeader(eq("Set-Cookie"), captor.capture());
    assertThat(captor.getAllValues())
        .containsExactly(
            "access_token=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax",
            "refresh_token=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax");
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
}
