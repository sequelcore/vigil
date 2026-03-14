package io.github.sequelcore.vigil.core.jwt;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;

/**
 * HS256 (HMAC-SHA256) implementation of {@link TokenSigner}.
 *
 * <p>Uses a shared symmetric secret — every holder of the secret can both sign and verify. This is
 * the default algorithm. For separation between signers and verifiers, use {@link RsaTokenSigner}.
 */
public final class HmacTokenSigner implements TokenSigner {

  private final SecretKey secretKey;

  /**
   * Creates an HMAC signer from the configured secret.
   *
   * @param secret the signing secret (minimum 32 characters per RFC 8725bis)
   * @throws IllegalArgumentException if the secret is shorter than 32 characters
   */
  public HmacTokenSigner(String secret) {
    if (secret == null || secret.length() < 32) {
      throw new IllegalArgumentException(
          "JWT secret must be at least 32 characters (256 bits) per RFC 8725bis");
    }
    this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
  }

  @Override
  public Algorithm algorithm() {
    return Algorithm.HS256;
  }

  @Override
  public String sign(JwtBuilder builder) {
    return builder.signWith(secretKey).compact();
  }

  @Override
  public void configureParser(JwtParserBuilder builder) {
    builder.verifyWith(secretKey);
  }

  /**
   * Returns the underlying secret key.
   *
   * <p>Exposed for use in tests that need to construct tokens directly (e.g., expired tokens).
   *
   * @return the HMAC secret key
   */
  SecretKey getSecretKey() {
    return secretKey;
  }
}
