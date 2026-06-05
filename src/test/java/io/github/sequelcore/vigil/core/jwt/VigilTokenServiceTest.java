package io.github.sequelcore.vigil.core.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import io.github.sequelcore.vigil.blacklist.VigilBlacklistService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class VigilTokenServiceTest {

  private VigilTokenService tokenService;
  private VigilProperties.Jwt jwtConfig;
  private VigilBlacklistService blacklistService;

  @BeforeEach
  void setUp() {
    jwtConfig =
        new VigilProperties.Jwt(
            "01234567890123456789012345678901",
            Duration.ofMinutes(15),
            Duration.ofDays(7),
            "vigil",
            "audience",
            null,
            null,
            null,
            null,
            null);
    blacklistService =
        new VigilBlacklistService(
            new VigilProperties.Blacklist(1000, Duration.ofHours(1), Duration.ofSeconds(30)));
    tokenService =
        new VigilTokenService(new HmacTokenSigner(jwtConfig.secret()), jwtConfig, blacklistService);
  }

  @Test
  @DisplayName("Generate access token with claims and validate")
  void generateAccessTokenWithClaims() {
    String token =
        tokenService.generateAccessToken(
            TokenRequest.builder().subject("alice").claim("role", "admin").build());

    Claims claims = tokenService.validateAndGetClaims(token);

    assertThat(claims.getSubject()).isEqualTo("alice");
    assertThat(claims.get("role", String.class)).isEqualTo("admin");
    assertThat(claims.getIssuer()).isEqualTo("vigil");
    assertThat(claims.getAudience()).containsExactly("audience");
  }

  @Test
  @DisplayName("Generate refresh token sets refresh type claim")
  void generateRefreshToken() {
    String token = tokenService.generateRefreshToken("bob");

    Claims claims = tokenService.validateAndGetClaims(token);

    assertThat(claims.getSubject()).isEqualTo("bob");
    assertThat(claims.get("type", String.class)).isEqualTo("refresh");
  }

  @Test
  @DisplayName("Validate returns claims for valid token")
  void validateAndGetClaimsReturnsClaims() {
    String token =
        tokenService.generateAccessToken(TokenRequest.builder().subject("carol").build());

    Claims claims = tokenService.validateAndGetClaims(token);

    assertThat(claims).isNotNull();
    assertThat(claims.getSubject()).isEqualTo("carol");
  }

  @Test
  @DisplayName("Validate expired token throws ExpiredJwtException")
  void validateExpiredTokenThrows() {
    String token = buildExpiredToken("dave");

    assertThatThrownBy(() -> tokenService.validateAndGetClaims(token))
        .isInstanceOf(ExpiredJwtException.class);
  }

  @Test
  @DisplayName("Validate malformed token throws JwtException")
  void validateInvalidTokenThrows() {
    assertThatThrownBy(() -> tokenService.validateAndGetClaims("not.a.valid.token"))
        .isInstanceOf(JwtException.class);
  }

  @Test
  @DisplayName("Extract subject from expired token")
  void getSubjectFromExpiredTokenReturnsSubject() {
    String token = buildExpiredToken("erin");

    assertThat(tokenService.getSubjectFromExpiredToken(token)).isEqualTo("erin");
  }

  @Nested
  @DisplayName("isTokenExpired")
  class IsTokenExpired {

    @Test
    @DisplayName("Returns true for expired token")
    void returnsTrueForExpiredToken() {
      String token = buildExpiredToken("frank");

      assertThat(tokenService.isTokenExpired(token)).isTrue();
    }

    @Test
    @DisplayName("Returns false for active token")
    void returnsFalseForValidToken() {
      String token =
          tokenService.generateAccessToken(TokenRequest.builder().subject("george").build());

      assertThat(tokenService.isTokenExpired(token)).isFalse();
    }
  }

  private String buildExpiredToken(String subject) {
    Instant now = Instant.now();
    return new HmacTokenSigner(jwtConfig.secret())
        .sign(
            Jwts.builder()
                .subject(subject)
                .issuedAt(Date.from(now.minusSeconds(120)))
                .expiration(Date.from(now.minusSeconds(60))));
  }

  @Nested
  @DisplayName("Custom TTL")
  class CustomTtl {

    @Test
    @DisplayName("Access token with custom TTL")
    void accessTokenWithCustomTtl() {
      Instant before = Instant.now();

      String token =
          tokenService.generateAccessToken(
              TokenRequest.builder().subject("alice").accessTtl(Duration.ofHours(24)).build());

      Claims claims = tokenService.validateAndGetClaims(token);
      Instant expiration = claims.getExpiration().toInstant();
      assertThat(expiration).isAfter(before.plus(Duration.ofHours(23)));
      assertThat(expiration).isBefore(before.plus(Duration.ofHours(25)));
    }

    @Test
    @DisplayName("Refresh token with custom TTL")
    void refreshTokenWithCustomTtl() {
      Instant before = Instant.now();

      String token =
          tokenService.generateRefreshToken(
              TokenRequest.builder().subject("bob").refreshTtl(Duration.ofDays(30)).build());

      Claims claims = tokenService.validateAndGetClaims(token);
      Instant expiration = claims.getExpiration().toInstant();
      assertThat(expiration).isAfter(before.plus(Duration.ofDays(29)));
      assertThat(expiration).isBefore(before.plus(Duration.ofDays(31)));
    }
  }

  @Nested
  @DisplayName("Refresh with claims")
  class RefreshWithClaims {

    @Test
    @DisplayName("Generate refresh token with claims")
    void generateRefreshTokenWithClaims() {
      String token =
          tokenService.generateRefreshToken(
              TokenRequest.builder()
                  .subject("carol")
                  .claim("role", "admin")
                  .claim("tenant", "acme")
                  .build());

      Claims claims = tokenService.validateAndGetClaims(token);
      assertThat(claims.getSubject()).isEqualTo("carol");
      assertThat(claims.get("type", String.class)).isEqualTo("refresh");
      assertThat(claims.get("role", String.class)).isEqualTo("admin");
      assertThat(claims.get("tenant", String.class)).isEqualTo("acme");
    }
  }

  @Nested
  @DisplayName("Token refresh rotation")
  class TokenRefresh {

    @Test
    @DisplayName("Refresh tokens generates new token pair")
    void refreshTokensGeneratesNewTokenPair() {
      String refreshToken = tokenService.generateRefreshToken("dave");

      TokenRefreshResult result = tokenService.refreshTokens(refreshToken);

      assertThat(result.accessToken()).isNotBlank();
      assertThat(result.refreshToken()).isNotBlank();
      // Access token should be different type than refresh token
      Claims accessClaims = tokenService.validateAndGetClaims(result.accessToken());
      Claims refreshClaims = tokenService.validateAndGetClaims(result.refreshToken());
      assertThat(accessClaims.get("type")).isNull(); // access tokens don't have type
      assertThat(refreshClaims.get("type")).isEqualTo("refresh");
      // Note: Token rotation/blacklisting is now handled by VigilAuthService with grace period
    }

    @Test
    @DisplayName("Refresh tokens preserves claims")
    void refreshTokensPreservesClaims() {
      String refreshToken =
          tokenService.generateRefreshToken(
              TokenRequest.builder().subject("eve").claim("role", "manager").build());

      TokenRefreshResult result = tokenService.refreshTokens(refreshToken);

      Claims accessClaims = tokenService.validateAndGetClaims(result.accessToken());
      assertThat(accessClaims.getSubject()).isEqualTo("eve");
      assertThat(accessClaims.get("role", String.class)).isEqualTo("manager");
      assertThat(accessClaims.get("type")).isNull();
    }

    @Test
    @DisplayName("Refresh tokens with updated claims")
    void refreshTokensWithUpdatedClaims() {
      String refreshToken =
          tokenService.generateRefreshToken(
              TokenRequest.builder().subject("frank").claim("role", "user").build());

      TokenRefreshResult result =
          tokenService.refreshTokens(refreshToken, Map.of("role", "admin", "upgraded", true));

      Claims accessClaims = tokenService.validateAndGetClaims(result.accessToken());
      assertThat(accessClaims.get("role", String.class)).isEqualTo("admin");
      assertThat(accessClaims.get("upgraded", Boolean.class)).isTrue();
    }

    @Test
    @DisplayName("Refresh tokens returns expiration times")
    void refreshTokensReturnsExpirationTimes() {
      String refreshToken = tokenService.generateRefreshToken("grace");
      Instant before = Instant.now();

      TokenRefreshResult result = tokenService.refreshTokens(refreshToken);

      assertThat(result.accessExpiresAt()).isAfter(before);
      assertThat(result.refreshExpiresAt()).isAfter(result.accessExpiresAt());
    }

    @Test
    @DisplayName("Refresh with access token throws")
    void refreshWithAccessTokenThrows() {
      String accessToken =
          tokenService.generateAccessToken(TokenRequest.builder().subject("hank").build());

      assertThatThrownBy(() -> tokenService.refreshTokens(accessToken))
          .isInstanceOf(JwtException.class)
          .hasMessageContaining("not a refresh token");
    }

    @Test
    @DisplayName("Refresh with invalid token throws")
    void refreshWithInvalidTokenThrows() {
      assertThatThrownBy(() -> tokenService.refreshTokens("invalid.token.here"))
          .isInstanceOf(JwtException.class);
    }
  }

  @Nested
  @DisplayName("Without blacklist service")
  class WithoutBlacklist {

    @Test
    @DisplayName("Refresh tokens works without blacklist")
    void refreshTokensWithoutBlacklist() {
      VigilTokenService serviceWithoutBlacklist =
          new VigilTokenService(new HmacTokenSigner(jwtConfig.secret()), jwtConfig);
      String refreshToken = serviceWithoutBlacklist.generateRefreshToken("ivan");

      TokenRefreshResult result = serviceWithoutBlacklist.refreshTokens(refreshToken);

      assertThat(result.accessToken()).isNotBlank();
      assertThat(result.refreshToken()).isNotBlank();
    }
  }

  @Nested
  @DisplayName("Expiration helpers")
  class ExpirationHelpers {

    @Test
    @DisplayName("Get access token expiration")
    void getAccessTokenExpiration() {
      Instant before = Instant.now();

      Instant expiration = tokenService.getAccessTokenExpiration();

      assertThat(expiration).isAfter(before.plus(Duration.ofMinutes(14)));
      assertThat(expiration).isBefore(before.plus(Duration.ofMinutes(16)));
    }

    @Test
    @DisplayName("Get refresh token expiration")
    void getRefreshTokenExpiration() {
      Instant before = Instant.now();

      Instant expiration = tokenService.getRefreshTokenExpiration();

      assertThat(expiration).isAfter(before.plus(Duration.ofDays(6)));
      assertThat(expiration).isBefore(before.plus(Duration.ofDays(8)));
    }
  }

  @Nested
  @DisplayName("No issuer or audience")
  class NoIssuerOrAudience {

    @Test
    @DisplayName("Token without issuer or audience")
    void tokenWithoutIssuerOrAudience() {
      VigilProperties.Jwt minimalConfig =
          new VigilProperties.Jwt(
              "01234567890123456789012345678901",
              Duration.ofMinutes(15),
              Duration.ofDays(7),
              null,
              null,
              null,
              null,
              null,
              null,
              null);
      VigilTokenService minimalService =
          new VigilTokenService(new HmacTokenSigner(minimalConfig.secret()), minimalConfig);

      String token =
          minimalService.generateAccessToken(TokenRequest.builder().subject("jake").build());

      Claims claims = minimalService.validateAndGetClaims(token);
      assertThat(claims.getIssuer()).isNull();
      assertThat(claims.getAudience()).isNullOrEmpty();
    }
  }
}
