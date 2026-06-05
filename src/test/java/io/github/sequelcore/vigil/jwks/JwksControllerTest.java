package io.github.sequelcore.vigil.jwks;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.sequelcore.vigil.core.jwt.RsaTokenSigner;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

class JwksControllerTest {

  private static JwksController controller;
  private static RsaTokenSigner signer;

  @BeforeAll
  static void setUp() throws Exception {
    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
    gen.initialize(2048);
    KeyPair pair = gen.generateKeyPair();
    signer = new RsaTokenSigner((RSAPrivateKey) pair.getPrivate(), (RSAPublicKey) pair.getPublic());
    controller = new JwksController(signer);
  }

  @Test
  @DisplayName("GET /.well-known/jwks.json returns 200 OK")
  void returns200() {
    ResponseEntity<Map<String, Object>> response = controller.jwks();

    assertThat(response.getStatusCode().value()).isEqualTo(200);
  }

  @Test
  @DisplayName("Response body contains 'keys' array with one JWK")
  void responseBodyContainsKeys() {
    ResponseEntity<Map<String, Object>> response = controller.jwks();

    Map<String, Object> body = response.getBody();
    assertThat(body).isNotNull();
    assertThat(body).containsKey("keys");

    @SuppressWarnings("unchecked")
    List<Map<String, Object>> keys = (List<Map<String, Object>>) body.get("keys");
    assertThat(keys).hasSize(1);
  }

  @Test
  @DisplayName("Response body contains active and additional public keys")
  void responseBodyContainsAdditionalKeys() throws Exception {
    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
    gen.initialize(2048);
    KeyPair activePair = gen.generateKeyPair();
    KeyPair previousPair = gen.generateKeyPair();
    RsaTokenSigner rotatingSigner =
        new RsaTokenSigner(
            (RSAPrivateKey) activePair.getPrivate(),
            (RSAPublicKey) activePair.getPublic(),
            List.of((RSAPublicKey) previousPair.getPublic()));
    JwksController rotatingController = new JwksController(rotatingSigner);

    @SuppressWarnings("unchecked")
    List<Map<String, Object>> keys =
        (List<Map<String, Object>>) rotatingController.jwks().getBody().get("keys");

    assertThat(keys).hasSize(2);
    assertThat(keys).extracting(jwk -> jwk.get("kid")).contains(rotatingSigner.getKid());
  }

  @Test
  @DisplayName("JWK contains required RSA fields")
  void jwkContainsRequiredFields() {
    ResponseEntity<Map<String, Object>> response = controller.jwks();

    @SuppressWarnings("unchecked")
    List<Map<String, Object>> keys = (List<Map<String, Object>>) response.getBody().get("keys");
    Map<String, Object> jwk = keys.get(0);

    assertThat(jwk.get("kty")).isEqualTo("RSA");
    assertThat(jwk.get("use")).isEqualTo("sig");
    assertThat(jwk.get("alg")).isEqualTo("RS256");
    assertThat(jwk.get("kid")).isEqualTo(signer.getKid());
    assertThat((String) jwk.get("n")).isNotBlank();
    assertThat((String) jwk.get("e")).isNotBlank();
  }

  @Test
  @DisplayName("Response has Cache-Control: public, max-age=3600")
  void hasCacheControlHeader() {
    ResponseEntity<Map<String, Object>> response = controller.jwks();

    String cacheControl = response.getHeaders().getCacheControl();
    assertThat(cacheControl).isNotNull();
    assertThat(cacheControl).contains("max-age=3600");
    assertThat(cacheControl).contains("public");
  }

  @Test
  @DisplayName("Response is pre-built (same instance on repeated calls)")
  void responseIsCached() {
    ResponseEntity<Map<String, Object>> first = controller.jwks();
    ResponseEntity<Map<String, Object>> second = controller.jwks();

    assertThat(first).isSameAs(second);
  }
}
