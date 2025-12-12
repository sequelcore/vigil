package io.github.sequelcore.vigil.core.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class VigilTokenServiceTest {

  private VigilTokenService tokenService;
  private VigilProperties.Jwt jwtConfig;

  @BeforeEach
  void setUp() {
    jwtConfig =
        new VigilProperties.Jwt(
            "01234567890123456789012345678901",
            Duration.ofMinutes(15),
            Duration.ofDays(7),
            "vigil",
            "audience");
    tokenService = new VigilTokenService(jwtConfig);
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
    return Jwts.builder()
        .subject(subject)
        .issuedAt(Date.from(now.minusSeconds(120)))
        .expiration(Date.from(now.minusSeconds(60)))
        .signWith(tokenService.getSigningKey())
        .compact();
  }
}
