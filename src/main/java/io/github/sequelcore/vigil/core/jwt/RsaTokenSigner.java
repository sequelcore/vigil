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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

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
  private final Map<String, RSAPublicKey> publicKeysByKid;
  private final List<Map<String, Object>> jwks;

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
    this(privateKey, publicKey, List.of());
  }

  /**
   * Creates an RS256 signer with additional verification-only public keys.
   *
   * <p>The active key pair signs new tokens. Additional public keys are published through JWKS and
   * accepted by the parser so deployments can rotate RSA keys without invalidating still-valid
   * tokens signed by a previous private key.
   *
   * @param privateKey active RSA private key for signing
   * @param publicKey active RSA public key for verification and JWKS export
   * @param additionalPublicKeys previous or staged RSA public keys accepted for verification
   */
  public RsaTokenSigner(
      RSAPrivateKey privateKey, RSAPublicKey publicKey, List<RSAPublicKey> additionalPublicKeys) {
    this.privateKey = Objects.requireNonNull(privateKey, "privateKey cannot be null");
    this.publicKey = Objects.requireNonNull(publicKey, "publicKey cannot be null");
    this.kid = computeKid(publicKey);

    Map<String, RSAPublicKey> keys = new LinkedHashMap<>();
    keys.put(kid, publicKey);
    List<RSAPublicKey> verificationKeys =
        additionalPublicKeys == null ? List.of() : List.copyOf(additionalPublicKeys);
    for (RSAPublicKey additionalPublicKey : verificationKeys) {
      RSAPublicKey key =
          Objects.requireNonNull(additionalPublicKey, "additional public key cannot be null");
      keys.putIfAbsent(computeKid(key), key);
    }
    this.publicKeysByKid = Map.copyOf(keys);
    this.jwks =
        keys.entrySet().stream().map(entry -> toJwk(entry.getKey(), entry.getValue())).toList();
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
    builder.keyLocator(header -> publicKeysByKid.get(String.valueOf(header.get("kid"))));
  }

  /**
   * Returns the JWK (JSON Web Key) representation of the public key for JWKS endpoint exposure.
   *
   * @return a map containing the standard JWK fields for the RSA public key
   */
  public Map<String, Object> getJwk() {
    return toJwk(kid, publicKey);
  }

  /**
   * Returns all JWK public keys accepted by this signer.
   *
   * @return active key first, followed by additional verification-only public keys
   */
  public List<Map<String, Object>> getJwks() {
    return jwks;
  }

  private static Map<String, Object> toJwk(String kid, RSAPublicKey publicKey) {
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
