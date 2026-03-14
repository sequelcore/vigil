package io.github.sequelcore.vigil.core.jwt;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Jwts;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

/**
 * RS256 (RSA-SHA256) implementation of {@link TokenSigner}.
 *
 * <p>Uses an asymmetric key pair: the private key signs tokens, the public key verifies them. This
 * separates signing authority from verification — services can validate tokens using only the
 * public key (distributed via {@code /.well-known/jwks.json}) without the ability to mint new ones.
 *
 * <p>A {@code kid} (key ID) derived from the public key fingerprint is added to every token header,
 * enabling key rotation: multiple public keys can be published in the JWKS, and the parser resolves
 * the correct key by {@code kid}.
 */
public final class RsaTokenSigner implements TokenSigner {

  private final RSAPrivateKey privateKey;
  private final RSAPublicKey publicKey;
  private final String kid;

  /**
   * Creates an RS256 signer from an RSA key pair.
   *
   * <p>The {@code kid} is derived deterministically from the public key: SHA-256 of the DER-encoded
   * public key, base64url-encoded, first 8 characters.
   *
   * @param privateKey RSA private key for signing
   * @param publicKey RSA public key for verification and JWKS export
   */
  public RsaTokenSigner(RSAPrivateKey privateKey, RSAPublicKey publicKey) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.kid = computeKid(publicKey);
  }

  @Override
  public Algorithm algorithm() {
    return Algorithm.RS256;
  }

  @Override
  public String sign(JwtBuilder builder) {
    return builder.header().keyId(kid).and().signWith(privateKey, Jwts.SIG.RS256).compact();
  }

  @Override
  public void configureParser(JwtParserBuilder builder) {
    builder.keyLocator(header -> kid.equals(header.get("kid")) ? publicKey : null);
  }

  /**
   * Returns the JWK (JSON Web Key) representation of the public key for JWKS endpoint exposure.
   *
   * @return a map containing the standard JWK fields for the RSA public key
   */
  public Map<String, Object> getJwk() {
    return Map.of(
        "kty",
        "RSA",
        "use",
        "sig",
        "alg",
        "RS256",
        "kid",
        kid,
        "n",
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(toUnsignedBytes(publicKey.getModulus())),
        "e",
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(toUnsignedBytes(publicKey.getPublicExponent())));
  }

  /** Returns the key ID used in token headers and JWKS. */
  public String getKid() {
    return kid;
  }

  private static String computeKid(RSAPublicKey publicKey) {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded());
      return Base64.getUrlEncoder().withoutPadding().encodeToString(digest).substring(0, 8);
    } catch (NoSuchAlgorithmException e) {
      // SHA-256 is always available in Java
      throw new IllegalStateException("SHA-256 not available", e);
    }
  }

  /**
   * Converts a BigInteger to an unsigned byte array, stripping the leading zero byte that Java uses
   * to indicate a positive sign for two's complement representation.
   */
  private static byte[] toUnsignedBytes(java.math.BigInteger n) {
    byte[] bytes = n.toByteArray();
    return bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes;
  }
}
