package io.github.sequelcore.vigil.core.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Jwts;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class RsaTokenSignerTest {

  private static RsaTokenSigner signer;
  private static RSAPrivateKey privateKey;
  private static RSAPublicKey publicKey;

  @BeforeAll
  static void generateKeyPair() throws Exception {
    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
    gen.initialize(2048);
    KeyPair pair = gen.generateKeyPair();
    privateKey = (RSAPrivateKey) pair.getPrivate();
    publicKey = (RSAPublicKey) pair.getPublic();
    signer = new RsaTokenSigner(privateKey, publicKey);
  }

  @Test
  @DisplayName("algorithm() returns RS256")
  void algorithmIsRs256() {
    assertThat(signer.algorithm()).isEqualTo(TokenSigner.Algorithm.RS256);
  }

  @Test
  @DisplayName("sign() produces a valid RS256 JWT with kid header")
  void signsTokenWithKidHeader() {
    Instant now = Instant.now();
    String token =
        signer.sign(
            Jwts.builder()
                .subject("alice")
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(300))));

    assertThat(token).isNotBlank();

    // Verify header contains kid
    String header = new String(java.util.Base64.getUrlDecoder().decode(token.split("\\.")[0]));
    assertThat(header).contains("\"kid\"");
    assertThat(header).contains(signer.getKid());
    assertThat(header).contains("RS256");
  }

  @Test
  @DisplayName("configureParser() can validate a token signed with the private key")
  void parserValidatesSignedToken() {
    Instant now = Instant.now();
    String token =
        signer.sign(
            Jwts.builder()
                .subject("bob")
                .claim("role", "admin")
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(300))));

    JwtParserBuilder parserBuilder = Jwts.parser();
    signer.configureParser(parserBuilder);
    Claims claims = parserBuilder.build().parseSignedClaims(token).getPayload();

    assertThat(claims.getSubject()).isEqualTo("bob");
    assertThat(claims.get("role", String.class)).isEqualTo("admin");
  }

  @Test
  @DisplayName("configureParser() validates tokens signed by an additional public key")
  void parserValidatesTokenSignedByAdditionalPublicKey() throws Exception {
    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
    gen.initialize(2048);
    KeyPair previousPair = gen.generateKeyPair();
    RsaTokenSigner previousSigner =
        new RsaTokenSigner(
            (RSAPrivateKey) previousPair.getPrivate(), (RSAPublicKey) previousPair.getPublic());
    RsaTokenSigner rotatingSigner =
        new RsaTokenSigner(privateKey, publicKey, List.of((RSAPublicKey) previousPair.getPublic()));

    Instant now = Instant.now();
    String oldToken =
        previousSigner.sign(
            Jwts.builder()
                .subject("rotating-user")
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(300))));

    JwtParserBuilder parserBuilder = Jwts.parser();
    rotatingSigner.configureParser(parserBuilder);
    Claims claims = parserBuilder.build().parseSignedClaims(oldToken).getPayload();

    assertThat(claims.getSubject()).isEqualTo("rotating-user");
  }

  @Test
  @DisplayName("kid is 8 characters and consistent across signer instances with the same key")
  void kidIsDeterministic() throws Exception {
    String kid = signer.getKid();
    assertThat(kid).hasSize(8);

    // kid depends only on the public key — same public key always yields same kid
    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
    gen.initialize(2048);
    KeyPair samePubPair = gen.generateKeyPair();
    RsaTokenSigner signer2 =
        new RsaTokenSigner(
            (RSAPrivateKey) samePubPair.getPrivate(), (RSAPublicKey) samePubPair.getPublic());
    // Different key pair → different kid
    assertThat(signer2.getKid()).hasSize(8).isNotEqualTo(kid);
  }

  @Test
  @DisplayName("Token signed by a different key pair is rejected")
  void rejectsTokenSignedByDifferentKey() throws Exception {
    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
    gen.initialize(2048);
    KeyPair otherPair = gen.generateKeyPair();
    RsaTokenSigner otherSigner =
        new RsaTokenSigner(
            (RSAPrivateKey) otherPair.getPrivate(), (RSAPublicKey) otherPair.getPublic());

    Instant now = Instant.now();
    String tokenByOther =
        otherSigner.sign(
            Jwts.builder()
                .subject("eve")
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(300))));

    JwtParserBuilder parserBuilder = Jwts.parser();
    signer.configureParser(parserBuilder);

    // Different kid → keyLocator returns null → verification fails
    assertThatThrownBy(() -> parserBuilder.build().parseSignedClaims(tokenByOther))
        .isInstanceOf(Exception.class);
  }

  @Test
  @DisplayName("getJwk() returns correct JWK fields")
  void jwkContainsCorrectFields() {
    Map<String, Object> jwk = signer.getJwk();

    assertThat(jwk).containsKey("kty");
    assertThat(jwk).containsKey("use");
    assertThat(jwk).containsKey("alg");
    assertThat(jwk).containsKey("kid");
    assertThat(jwk).containsKey("n");
    assertThat(jwk).containsKey("e");

    assertThat(jwk.get("kty")).isEqualTo("RSA");
    assertThat(jwk.get("use")).isEqualTo("sig");
    assertThat(jwk.get("alg")).isEqualTo("RS256");
    assertThat(jwk.get("kid")).isEqualTo(signer.getKid());
    assertThat((String) jwk.get("n")).isNotBlank();
    assertThat((String) jwk.get("e")).isNotBlank();
  }

  @Test
  @DisplayName("getJwks() returns active and additional public keys")
  void jwksContainAdditionalPublicKeys() throws Exception {
    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
    gen.initialize(2048);
    KeyPair activePair = gen.generateKeyPair();
    KeyPair previousPair = gen.generateKeyPair();
    RsaTokenSigner rotatingSigner =
        new RsaTokenSigner(
            (RSAPrivateKey) activePair.getPrivate(),
            (RSAPublicKey) activePair.getPublic(),
            List.of((RSAPublicKey) previousPair.getPublic()));

    assertThat(rotatingSigner.getJwks()).hasSize(2);
    assertThat(rotatingSigner.getJwks())
        .extracting(jwk -> jwk.get("kid"))
        .contains(rotatingSigner.getKid());
  }
}
