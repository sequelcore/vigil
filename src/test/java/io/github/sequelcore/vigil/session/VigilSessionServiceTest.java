package io.github.sequelcore.vigil.session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import io.github.sequelcore.vigil.core.cookie.VigilCookieService;
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

class VigilSessionServiceTest {

  private VigilSessionService sessionService;
  private VigilCookieService cookieService;

  @Mock private HttpServletRequest request;
  @Mock private HttpServletResponse response;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
    VigilProperties.Jwt jwtConfig =
        new VigilProperties.Jwt(
            "01234567890123456789012345678901",
            Duration.ofMinutes(15),
            Duration.ofDays(7),
            null,
            null);
    VigilProperties.Cookie cookieConfig =
        new VigilProperties.Cookie(
            true,
            "Lax",
            true,
            Map.of("default", new VigilProperties.CookieProfile("access_token", "refresh_token")));
    cookieService = new VigilCookieService(cookieConfig, jwtConfig);

    VigilProperties.Session sessionConfig =
        new VigilProperties.Session(true, "session_token", Duration.ofMinutes(30));
    sessionService = new VigilSessionService(cookieService, sessionConfig);
  }

  @Test
  @DisplayName("GenerateToken returns UUID string")
  void generateTokenReturnsUuid() {
    String token = sessionService.generateToken();

    assertThat(token).isNotNull();
    assertThat(token).matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
  }

  @Test
  @DisplayName("CreateSession generates token and sets cookie")
  void createSessionGeneratesTokenAndSetsCookie() {
    String token = sessionService.createSession(response);

    assertThat(token).isNotNull();
    ArgumentCaptor<String> headerCaptor = ArgumentCaptor.forClass(String.class);
    verify(response)
        .addHeader(org.mockito.ArgumentMatchers.eq("Set-Cookie"), headerCaptor.capture());
    assertThat(headerCaptor.getValue()).contains("session_token=" + token);
  }

  @Test
  @DisplayName("ExtractToken returns token from cookie")
  void extractTokenReturnsCookieValue() {
    String expectedToken = "test-session-token";
    when(request.getCookies())
        .thenReturn(new Cookie[] {new Cookie("session_token", expectedToken)});

    Optional<String> result = sessionService.extractToken(request);

    assertThat(result).contains(expectedToken);
  }

  @Test
  @DisplayName("ExtractToken returns empty when no cookie")
  void extractTokenReturnsEmptyWhenNoCookie() {
    when(request.getCookies()).thenReturn(null);

    Optional<String> result = sessionService.extractToken(request);

    assertThat(result).isEmpty();
  }

  @Test
  @DisplayName("GetCookieName returns configured name")
  void getCookieNameReturnsConfiguredName() {
    assertThat(sessionService.getCookieName()).isEqualTo("session_token");
  }

  @Test
  @DisplayName("ClearSession removes cookie")
  void clearSessionRemovesCookie() {
    sessionService.clearSession(response);

    ArgumentCaptor<String> headerCaptor = ArgumentCaptor.forClass(String.class);
    verify(response)
        .addHeader(org.mockito.ArgumentMatchers.eq("Set-Cookie"), headerCaptor.capture());
    assertThat(headerCaptor.getValue()).contains("session_token=");
    assertThat(headerCaptor.getValue()).contains("Max-Age=0");
  }
}
