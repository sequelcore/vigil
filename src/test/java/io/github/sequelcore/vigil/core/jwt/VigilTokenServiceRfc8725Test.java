package io.github.sequelcore.vigil.core.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.IncorrectClaimException;
import java.time.Duration;
import org.junit.jupiter.api.Test;

/** Tests for RFC 8725bis compliance in {@link VigilTokenService}. */
class VigilTokenServiceRfc8725Test {

  @Test
  void shouldRejectSecretShorterThan32Characters() {
    assertThatThrownBy(
            () ->
                new VigilProperties.Jwt(
                    "short-secret", // Only 12 chars
                    Duration.ofMinutes(15),
                    Duration.ofDays(7),
                    null,
                    null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("must be at least 32 characters")
        .hasMessageContaining("Current length: 12");
  }

  @Test
  void shouldAcceptSecretWith32Characters() {
    var jwt =
        new VigilProperties.Jwt(
            "this-is-a-valid-32-chars-secret!", // Exactly 32 chars
            Duration.ofMinutes(15),
            Duration.ofDays(7),
            null,
            null);

    assertThat(jwt.secret()).hasSize(32);
  }

  @Test
  void shouldAcceptSecretLongerThan32Characters() {
    var jwt =
        new VigilProperties.Jwt(
            "this-is-a-very-long-secret-key-that-exceeds-32-characters",
            Duration.ofMinutes(15),
            Duration.ofDays(7),
            null,
            null);

    assertThat(jwt.secret()).hasSizeGreaterThan(32);
  }

  @Test
  void shouldValidateIssuerClaim() {
    var jwt =
        new VigilProperties.Jwt(
            "this-is-a-valid-32-chars-secret!",
            Duration.ofMinutes(15),
            Duration.ofDays(7),
            "vigil-test", // issuer
            null);

    var service = new VigilTokenService(jwt);

    String token =
        service.generateAccessToken(TokenRequest.builder().subject("user@test.com").build());

    // Token with correct issuer should validate
    Claims claims = service.validateAndGetClaims(token);
    assertThat(claims.getIssuer()).isEqualTo("vigil-test");
  }

  @Test
  void shouldRejectTokenWithWrongIssuer() {
    var jwt =
        new VigilProperties.Jwt(
            "this-is-a-valid-32-chars-secret!",
            Duration.ofMinutes(15),
            Duration.ofDays(7),
            "vigil-test",
            null);

    var service = new VigilTokenService(jwt);

    // Create token with different issuer by manually constructing
    var otherJwt =
        new VigilProperties.Jwt(
            "this-is-a-valid-32-chars-secret!",
            Duration.ofMinutes(15),
            Duration.ofDays(7),
            "other-issuer",
            null);

    var otherService = new VigilTokenService(otherJwt);
    String token =
        otherService.generateAccessToken(TokenRequest.builder().subject("user@test.com").build());

    // Should reject when validating with service expecting different issuer
    assertThatThrownBy(() -> service.validateAndGetClaims(token))
        .isInstanceOf(IncorrectClaimException.class);
  }

  @Test
  void shouldValidateAudienceClaim() {
    var jwt =
        new VigilProperties.Jwt(
            "this-is-a-valid-32-chars-secret!",
            Duration.ofMinutes(15),
            Duration.ofDays(7),
            null,
            "vigil-api"); // audience

    var service = new VigilTokenService(jwt);

    String token =
        service.generateAccessToken(TokenRequest.builder().subject("user@test.com").build());

    Claims claims = service.validateAndGetClaims(token);
    assertThat(claims.getAudience()).contains("vigil-api");
  }

  @Test
  void shouldRejectTokenWithWrongAudience() {
    var jwt =
        new VigilProperties.Jwt(
            "this-is-a-valid-32-chars-secret!",
            Duration.ofMinutes(15),
            Duration.ofDays(7),
            null,
            "vigil-api");

    var service = new VigilTokenService(jwt);

    var otherJwt =
        new VigilProperties.Jwt(
            "this-is-a-valid-32-chars-secret!",
            Duration.ofMinutes(15),
            Duration.ofDays(7),
            null,
            "other-api");

    var otherService = new VigilTokenService(otherJwt);
    String token =
        otherService.generateAccessToken(TokenRequest.builder().subject("user@test.com").build());

    assertThatThrownBy(() -> service.validateAndGetClaims(token))
        .isInstanceOf(IncorrectClaimException.class);
  }

  @Test
  void shouldIncludeNotBeforeClaim() {
    var jwt =
        new VigilProperties.Jwt(
            "this-is-a-valid-32-chars-secret!",
            Duration.ofMinutes(15),
            Duration.ofDays(7),
            null,
            null);

    var service = new VigilTokenService(jwt);

    String token =
        service.generateAccessToken(TokenRequest.builder().subject("user@test.com").build());

    Claims claims = service.validateAndGetClaims(token);

    // RFC 8725bis: nbf (not before) should be set
    assertThat(claims.getNotBefore()).isNotNull();
    assertThat(claims.getNotBefore()).isBeforeOrEqualTo(claims.getIssuedAt());
  }

  @Test
  void shouldWorkWithoutIssuerAndAudience() {
    var jwt =
        new VigilProperties.Jwt(
            "this-is-a-valid-32-chars-secret!",
            Duration.ofMinutes(15),
            Duration.ofDays(7),
            null, // no issuer
            null); // no audience

    var service = new VigilTokenService(jwt);

    String token =
        service.generateAccessToken(TokenRequest.builder().subject("user@test.com").build());

    Claims claims = service.validateAndGetClaims(token);
    assertThat(claims.getSubject()).isEqualTo("user@test.com");
    assertThat(claims.getIssuer()).isNull();
    // Audience may be null or empty when not configured
    if (claims.getAudience() != null) {
      assertThat(claims.getAudience()).isEmpty();
    }
  }
}
