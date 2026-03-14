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

  private static final String SECRET_32 = "this-is-a-valid-32-chars-secret!";

  private static VigilProperties.Jwt jwt(String secret, String issuer, String audience) {
    return new VigilProperties.Jwt(
        secret, Duration.ofMinutes(15), Duration.ofDays(7), issuer, audience, null, null, null);
  }

  private static VigilTokenService service(VigilProperties.Jwt config) {
    return new VigilTokenService(new HmacTokenSigner(config.secret()), config);
  }

  @Test
  void shouldRejectSecretShorterThan32Characters() {
    assertThatThrownBy(() -> jwt("short-secret", null, null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("must be at least 32 characters")
        .hasMessageContaining("Current length: 12");
  }

  @Test
  void shouldAcceptSecretWith32Characters() {
    var config = jwt(SECRET_32, null, null);
    assertThat(config.secret()).hasSize(32);
  }

  @Test
  void shouldAcceptSecretLongerThan32Characters() {
    var config = jwt("this-is-a-very-long-secret-key-that-exceeds-32-characters", null, null);
    assertThat(config.secret()).hasSizeGreaterThan(32);
  }

  @Test
  void shouldValidateIssuerClaim() {
    var config = jwt(SECRET_32, "vigil-test", null);
    var svc = service(config);

    String token = svc.generateAccessToken(TokenRequest.builder().subject("user@test.com").build());

    Claims claims = svc.validateAndGetClaims(token);
    assertThat(claims.getIssuer()).isEqualTo("vigil-test");
  }

  @Test
  void shouldRejectTokenWithWrongIssuer() {
    var svc = service(jwt(SECRET_32, "vigil-test", null));
    var otherSvc = service(jwt(SECRET_32, "other-issuer", null));

    String token =
        otherSvc.generateAccessToken(TokenRequest.builder().subject("user@test.com").build());

    assertThatThrownBy(() -> svc.validateAndGetClaims(token))
        .isInstanceOf(IncorrectClaimException.class);
  }

  @Test
  void shouldValidateAudienceClaim() {
    var config = jwt(SECRET_32, null, "vigil-api");
    var svc = service(config);

    String token = svc.generateAccessToken(TokenRequest.builder().subject("user@test.com").build());

    Claims claims = svc.validateAndGetClaims(token);
    assertThat(claims.getAudience()).contains("vigil-api");
  }

  @Test
  void shouldRejectTokenWithWrongAudience() {
    var svc = service(jwt(SECRET_32, null, "vigil-api"));
    var otherSvc = service(jwt(SECRET_32, null, "other-api"));

    String token =
        otherSvc.generateAccessToken(TokenRequest.builder().subject("user@test.com").build());

    assertThatThrownBy(() -> svc.validateAndGetClaims(token))
        .isInstanceOf(IncorrectClaimException.class);
  }

  @Test
  void shouldIncludeNotBeforeClaim() {
    var svc = service(jwt(SECRET_32, null, null));

    String token = svc.generateAccessToken(TokenRequest.builder().subject("user@test.com").build());

    Claims claims = svc.validateAndGetClaims(token);

    assertThat(claims.getNotBefore()).isNotNull();
    assertThat(claims.getNotBefore()).isBeforeOrEqualTo(claims.getIssuedAt());
  }

  @Test
  void shouldWorkWithoutIssuerAndAudience() {
    var svc = service(jwt(SECRET_32, null, null));

    String token = svc.generateAccessToken(TokenRequest.builder().subject("user@test.com").build());

    Claims claims = svc.validateAndGetClaims(token);
    assertThat(claims.getSubject()).isEqualTo("user@test.com");
    assertThat(claims.getIssuer()).isNull();
    if (claims.getAudience() != null) {
      assertThat(claims.getAudience()).isEmpty();
    }
  }
}
