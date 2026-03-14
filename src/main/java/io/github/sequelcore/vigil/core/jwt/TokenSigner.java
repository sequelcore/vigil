package io.github.sequelcore.vigil.core.jwt;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParserBuilder;

/**
 * Strategy for JWT signing and parser configuration.
 *
 * <p>Implementations encapsulate algorithm-specific key handling: {@link HmacTokenSigner} for HS256
 * and {@link RsaTokenSigner} for RS256. Auto-configuration selects the implementation based on
 * {@code vigil.jwt.algorithm}.
 */
public interface TokenSigner {

  /**
   * Signing algorithm supported by this implementation.
   *
   * @return the algorithm enum value
   */
  Algorithm algorithm();

  /**
   * Applies signing to the builder and returns the compact JWT string.
   *
   * <p>Implementations add the algorithm-specific signing header and key, then call {@code
   * compact()}.
   *
   * @param builder a fully configured {@link JwtBuilder} (claims, subject, dates already set)
   * @return the signed, compact JWT string
   */
  String sign(JwtBuilder builder);

  /**
   * Configures the parser builder with the key material needed for signature verification.
   *
   * <p>HMAC: sets {@code verifyWith(secretKey)}. RSA: sets a {@code keyLocator} that resolves by
   * {@code kid} header.
   *
   * @param builder the parser builder to configure
   */
  void configureParser(JwtParserBuilder builder);

  /** JWT signing algorithm. */
  enum Algorithm {
    /** HMAC-SHA256. Symmetric — any holder of the secret can both sign and verify. */
    HS256,

    /**
     * RSA-SHA256. Asymmetric — private key signs, public key verifies. Enables JWKS distribution
     * and key rotation.
     */
    RS256
  }
}
