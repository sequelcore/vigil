package io.github.sequelcore.vigil.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import io.github.sequelcore.vigil.blacklist.VigilBlacklistService;
import io.github.sequelcore.vigil.core.cookie.VigilCookieService;
import io.github.sequelcore.vigil.core.jwt.TokenRequest;
import io.github.sequelcore.vigil.core.jwt.VigilTokenService;
import io.github.sequelcore.vigil.tenant.VigilTenantContext;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class VigilAuthServiceTest {

  private static final String SECRET = "01234567890123456789012345678901";

  private VigilProperties.Jwt jwtConfig;
  private VigilProperties.Cookie cookieConfig;
  private VigilTokenService tokenService;
  private VigilCookieService cookieService;
  private VigilBlacklistService blacklistService;
  private VigilAuthService authService;

  @Mock private HttpServletRequest request;
  @Mock private HttpServletResponse response;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
    jwtConfig =
        new VigilProperties.Jwt(SECRET, Duration.ofMinutes(15), Duration.ofDays(7), null, null);
    cookieConfig =
        new VigilProperties.Cookie(
            true,
            "Lax",
            true,
            Map.of("default", new VigilProperties.CookieProfile("access_token", "refresh_token")));

    VigilProperties.Blacklist blacklistConfig =
        new VigilProperties.Blacklist(10000, Duration.ofHours(24));
    blacklistService = new VigilBlacklistService(blacklistConfig);
    tokenService = new VigilTokenService(jwtConfig, blacklistService);
    cookieService = new VigilCookieService(cookieConfig, jwtConfig);
    authService = new VigilAuthService(tokenService, cookieService, blacklistService);
  }

  @AfterEach
  void tearDown() {
    VigilTenantContext.clear();
  }

  @Test
  @DisplayName("Logout blacklists tokens and clears cookies")
  void logoutBlacklistsTokensAndClearsCookies() {
    String accessToken =
        tokenService.generateAccessToken(TokenRequest.builder().subject("test-user").build());
    String refreshToken =
        tokenService.generateRefreshToken(TokenRequest.builder().subject("test-user").build());

    when(request.getCookies())
        .thenReturn(
            new Cookie[] {
              new Cookie("access_token", accessToken), new Cookie("refresh_token", refreshToken)
            });

    authService.logout(request, response, "default");

    assertThat(blacklistService.isBlacklisted(accessToken)).isTrue();
    assertThat(blacklistService.isBlacklisted(refreshToken)).isTrue();
  }

  @Test
  @DisplayName("Refresh throws when token not found")
  void refreshThrowsWhenTokenNotFound() {
    when(request.getCookies()).thenReturn(null);

    assertThatThrownBy(() -> authService.refresh(request, response, "default"))
        .isInstanceOf(VigilAuthException.class)
        .hasFieldOrPropertyWithValue("code", VigilAuthException.AuthErrorCode.TOKEN_NOT_FOUND);
  }

  @Test
  @DisplayName("Refresh throws when token is blacklisted")
  void refreshThrowsWhenTokenBlacklisted() {
    String refreshToken =
        tokenService.generateRefreshToken(TokenRequest.builder().subject("test-user").build());
    blacklistService.blacklist(refreshToken);

    when(request.getCookies()).thenReturn(new Cookie[] {new Cookie("refresh_token", refreshToken)});

    assertThatThrownBy(() -> authService.refresh(request, response, "default"))
        .isInstanceOf(VigilAuthException.class)
        .hasFieldOrPropertyWithValue("code", VigilAuthException.AuthErrorCode.TOKEN_BLACKLISTED);
  }

  @Test
  @DisplayName("Refresh succeeds with valid token")
  void refreshSucceedsWithValidToken() {
    String refreshToken =
        tokenService.generateRefreshToken(
            TokenRequest.builder().subject("test-user").claim("role", "USER").build());

    when(request.getCookies()).thenReturn(new Cookie[] {new Cookie("refresh_token", refreshToken)});

    AuthResult result = authService.refresh(request, response, "default");

    assertThat(result.accessToken()).isNotNull();
    assertThat(result.refreshToken()).isNotNull();
    assertThat(result.claims().getSubject()).isEqualTo("test-user");
  }

  @Test
  @DisplayName("InvalidateAllSessions blacklists subject")
  void invalidateAllSessionsBlacklistsSubject() {
    String subject = "user@example.com";
    authService.invalidateAllSessions(subject);

    // Cannot directly verify since it's internal, but we can verify no exception
    assertThat(
            blacklistService.isSubjectInvalidated(subject, java.time.Instant.now().minusSeconds(1)))
        .isTrue();
  }

  @Test
  @DisplayName("GetCurrentTenant returns value from context")
  void getCurrentTenantReturnsContextValue() {
    UUID tenantId = UUID.randomUUID();
    VigilTenantContext.setTenant(tenantId);

    Optional<UUID> result = authService.getCurrentTenant();

    assertThat(result).contains(tenantId);
  }

  @Test
  @DisplayName("GetCurrentTenant returns empty when not set")
  void getCurrentTenantReturnsEmptyWhenNotSet() {
    Optional<UUID> result = authService.getCurrentTenant();
    assertThat(result).isEmpty();
  }

  @Test
  @DisplayName("Login generates tokens and returns result")
  void loginGeneratesTokensAndReturnsResult() {
    AuthResult result =
        authService.login(response, "test-user", "default", Map.of("role", "ADMIN"));

    assertThat(result.accessToken()).isNotNull();
    assertThat(result.refreshToken()).isNotNull();
    assertThat(result.accessExpiresAt()).isNotNull();
    assertThat(result.refreshExpiresAt()).isNotNull();
    assertThat(result.claims().getSubject()).isEqualTo("test-user");
    assertThat(result.claims().getString("role")).contains("ADMIN");
  }

  @Test
  @DisplayName("Login with default profile")
  void loginWithDefaultProfile() {
    AuthResult result = authService.login(response, "test-user", Map.of("userId", "123"));

    assertThat(result.accessToken()).isNotNull();
    assertThat(result.claims().getSubject()).isEqualTo("test-user");
    assertThat(result.claims().getString("userId")).contains("123");
  }

  @Test
  @DisplayName("Login tokens are valid and can be validated")
  void loginTokensAreValid() {
    AuthResult result = authService.login(response, "test-user", "default", Map.of());

    // Tokens should be valid
    assertThat(tokenService.isTokenExpired(result.accessToken())).isFalse();
    assertThat(tokenService.isTokenExpired(result.refreshToken())).isFalse();

    // Claims should match
    var claims = tokenService.validateAndGetClaims(result.accessToken());
    assertThat(claims.getSubject()).isEqualTo("test-user");
  }

  @Test
  @DisplayName("Login with profile only (no claims)")
  void loginWithProfileOnly() {
    AuthResult result = authService.login(response, "test-user", "default");

    assertThat(result.accessToken()).isNotNull();
    assertThat(result.claims().getSubject()).isEqualTo("test-user");
  }

  @Test
  @DisplayName("Login with subject only (default profile, no claims)")
  void loginWithSubjectOnly() {
    AuthResult result = authService.login(response, "test-user");

    assertThat(result.accessToken()).isNotNull();
    assertThat(result.claims().getSubject()).isEqualTo("test-user");
  }

  @Test
  @DisplayName("Login expiration times come from actual tokens")
  void loginExpirationTimesFromTokens() {
    AuthResult result = authService.login(response, "test-user", "default", Map.of());

    // Expiration should match what's in the token
    var accessClaims = tokenService.validateAndGetClaims(result.accessToken());
    var refreshClaims = tokenService.validateAndGetClaims(result.refreshToken());

    assertThat(result.accessExpiresAt()).isEqualTo(accessClaims.getExpiration().toInstant());
    assertThat(result.refreshExpiresAt()).isEqualTo(refreshClaims.getExpiration().toInstant());
  }

  @Test
  @DisplayName("Refresh with default profile")
  void refreshWithDefaultProfile() {
    String refreshToken =
        tokenService.generateRefreshToken(
            TokenRequest.builder().subject("test-user").claim("role", "USER").build());

    when(request.getCookies()).thenReturn(new Cookie[] {new Cookie("refresh_token", refreshToken)});

    AuthResult result = authService.refresh(request, response);

    assertThat(result.accessToken()).isNotNull();
    assertThat(result.claims().getSubject()).isEqualTo("test-user");
  }

  @Test
  @DisplayName("Logout with default profile")
  void logoutWithDefaultProfile() {
    String accessToken =
        tokenService.generateAccessToken(TokenRequest.builder().subject("test-user").build());
    String refreshToken =
        tokenService.generateRefreshToken(TokenRequest.builder().subject("test-user").build());

    when(request.getCookies())
        .thenReturn(
            new Cookie[] {
              new Cookie("access_token", accessToken), new Cookie("refresh_token", refreshToken)
            });

    authService.logout(request, response);

    assertThat(blacklistService.isBlacklisted(accessToken)).isTrue();
    assertThat(blacklistService.isBlacklisted(refreshToken)).isTrue();
  }
}
