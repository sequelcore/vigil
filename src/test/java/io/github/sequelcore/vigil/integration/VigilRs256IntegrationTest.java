package io.github.sequelcore.vigil.integration;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import io.github.sequelcore.vigil.core.jwt.HmacTokenSigner;
import io.github.sequelcore.vigil.core.jwt.RsaTokenSigner;
import io.github.sequelcore.vigil.core.jwt.TokenRequest;
import io.github.sequelcore.vigil.core.jwt.VigilTokenService;
import io.github.sequelcore.vigil.integration.testapp.TestApplication;
import io.jsonwebtoken.Jwts;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    classes = TestApplication.class)
class VigilRs256IntegrationTest {

  @LocalServerPort private int port;
  @Autowired private TestRestTemplate restTemplate;
  @Autowired private VigilTokenService tokenService;
  @Autowired private VigilProperties properties;

  // Key pair is initialized in a static block so it's available to both
  // @DynamicPropertySource (runs before context start) and test methods.
  private static final RSAPrivateKey privateKey;
  private static final RSAPublicKey publicKey;
  private static final String privatePem;
  private static final String publicPem;

  static {
    try {
      KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
      gen.initialize(2048);
      KeyPair pair = gen.generateKeyPair();
      privateKey = (RSAPrivateKey) pair.getPrivate();
      publicKey = (RSAPublicKey) pair.getPublic();

      byte[] lineBreak = new byte[]{'\n'};
      String enc64 = Base64.getMimeEncoder(64, lineBreak).encodeToString(privateKey.getEncoded());
      privatePem = "-----BEGIN PRIVATE KEY-----\n" + enc64 + "\n-----END PRIVATE KEY-----";

      String pub64 = Base64.getMimeEncoder(64, lineBreak).encodeToString(publicKey.getEncoded());
      publicPem = "-----BEGIN PUBLIC KEY-----\n" + pub64 + "\n-----END PUBLIC KEY-----";
    } catch (Exception e) {
      throw new ExceptionInInitializerError(e);
    }
  }

  @DynamicPropertySource
  static void rs256Properties(DynamicPropertyRegistry registry) {
    registry.add("vigil.jwt.algorithm", () -> "RS256");
    registry.add("vigil.jwt.rsa-private-key", () -> privatePem);
    registry.add("vigil.jwt.rsa-public-key", () -> publicPem);
    registry.add("vigil.jwt.secret", () -> "placeholder-not-used-for-rs256-signing");
    // Include JWKS endpoint in public-paths so Spring Security permits it without auth.
    // The Vigil filter also adds it to ignored-paths automatically for RS256.
    registry.add("vigil.filter.public-paths[0]", () -> "/public/**");
    registry.add("vigil.filter.public-paths[1]", () -> "/auth/**");
    registry.add("vigil.filter.public-paths[2]", () -> "/.well-known/jwks.json");
  }

  @Test
  @DisplayName("Algorithm is configured as RS256")
  void algorithmIsRs256() {
    assertThat(properties.jwt().algorithm()).isEqualTo(VigilProperties.Jwt.Algorithm.RS256);
  }

  @Test
  @DisplayName("RS256 token can be generated and validated")
  void tokenGenerationAndValidation() {
    String token =
        tokenService.generateAccessToken(
            TokenRequest.builder().subject("rs256-user").claim("role", "ADMIN").build());

    var claims = tokenService.validateAndGetClaims(token);
    assertThat(claims.getSubject()).isEqualTo("rs256-user");
    assertThat(claims.get("role", String.class)).isEqualTo("ADMIN");
  }

  @Test
  @DisplayName("Protected endpoint with RS256 token returns 200")
  void protectedEndpointWithRs256TokenReturnsOk() {
    String token =
        tokenService.generateAccessToken(
            TokenRequest.builder().subject("rs256-user").claim("role", "USER").build());

    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);

    ResponseEntity<String> response =
        restTemplate.exchange(url("/protected/hello"), HttpMethod.GET, new HttpEntity<>(headers), String.class);

    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(response.getBody()).isEqualTo("rs256-user");
  }

  @Test
  @DisplayName("Protected endpoint without token returns 401")
  void protectedEndpointWithoutTokenReturns401() {
    ResponseEntity<String> response = restTemplate.getForEntity(url("/protected/hello"), String.class);

    assertThat(response.getStatusCode()).isIn(HttpStatus.UNAUTHORIZED, HttpStatus.FORBIDDEN);
  }

  @Test
  @DisplayName("JWKS endpoint is accessible without authentication")
  void jwksEndpointIsPublic() {
    ResponseEntity<String> response = restTemplate.getForEntity(url("/.well-known/jwks.json"), String.class);

    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
  }

  @Test
  @DisplayName("JWKS endpoint returns valid RSA JWK set")
  void jwksEndpointReturnsValidJwkSet() {
    ResponseEntity<java.util.Map> response = restTemplate.getForEntity(url("/.well-known/jwks.json"), java.util.Map.class);

    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(response.getBody()).containsKey("keys");
    @SuppressWarnings("unchecked")
    var keys = (java.util.List<java.util.Map<String, Object>>) response.getBody().get("keys");
    assertThat(keys).hasSize(1);
    var jwk = keys.get(0);
    assertThat(jwk.get("kty")).isEqualTo("RSA");
    assertThat(jwk.get("alg")).isEqualTo("RS256");
    assertThat(jwk.get("kid")).isNotNull();
    assertThat(jwk.get("n")).isNotNull();
    assertThat(jwk.get("e")).isNotNull();
  }

  @Test
  @DisplayName("JWKS response has Cache-Control: public header")
  void jwksHasCacheControlHeader() {
    ResponseEntity<String> response = restTemplate.getForEntity(url("/.well-known/jwks.json"), String.class);

    String cacheControl = response.getHeaders().getCacheControl();
    assertThat(cacheControl).isNotNull();
    assertThat(cacheControl).contains("max-age=3600");
  }

  @Test
  @DisplayName("HS256 token is rejected when RS256 is configured")
  void hs256TokenRejectedWithRs256Config() {
    // Sign a token with HMAC — it has no kid header matching the RS256 signer
    String hmacSecret = "fallback-hmac-secret-for-testing-32chars";
    Instant now = Instant.now();
    String hmacToken =
        new HmacTokenSigner(hmacSecret)
            .sign(
                Jwts.builder()
                    .subject("hs256-user")
                    .issuedAt(Date.from(now))
                    .expiration(Date.from(now.plusSeconds(300))));

    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(hmacToken);

    ResponseEntity<String> response =
        restTemplate.exchange(url("/protected/hello"), HttpMethod.GET, new HttpEntity<>(headers), String.class);

    assertThat(response.getStatusCode()).isIn(HttpStatus.UNAUTHORIZED, HttpStatus.FORBIDDEN);
  }

  private String url(String path) {
    return "http://localhost:" + port + path;
  }
}
