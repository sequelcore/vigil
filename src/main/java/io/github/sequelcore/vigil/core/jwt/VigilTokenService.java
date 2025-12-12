package io.github.sequelcore.vigil.core.jwt;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import javax.crypto.SecretKey;
import lombok.Getter;

/** Service for JWT token generation and validation. */
public class VigilTokenService {

  private final VigilProperties.Jwt jwtConfig;
  @Getter private final SecretKey signingKey;

  /**
   * Creates a token service with the provided JWT configuration.
   *
   * @param jwtConfig JWT configuration properties
   */
  public VigilTokenService(VigilProperties.Jwt jwtConfig) {
    this.jwtConfig = jwtConfig;
    this.signingKey = Keys.hmacShaKeyFor(jwtConfig.secret().getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Generates an access token with the specified claims.
   *
   * @param request the token request containing subject and claims
   * @return the generated JWT token
   */
  public String generateAccessToken(TokenRequest request) {
    return generateToken(request, jwtConfig.accessTtl().toMillis());
  }

  /**
   * Generates a refresh token for the specified subject.
   *
   * @param subject the token subject (typically username)
   * @return the generated refresh token
   */
  public String generateRefreshToken(String subject) {
    return generateToken(
        TokenRequest.builder().subject(subject).claim("type", "refresh").build(),
        jwtConfig.refreshTtl().toMillis());
  }

  /**
   * Validates a token and returns its claims.
   *
   * @param token the JWT token to validate
   * @return the token claims
   * @throws ExpiredJwtException if the token has expired
   * @throws io.jsonwebtoken.JwtException if the token is invalid
   */
  public Claims validateAndGetClaims(String token) {
    return Jwts.parser().verifyWith(signingKey).build().parseSignedClaims(token).getPayload();
  }

  /**
   * Extracts the subject from a token without validating expiration.
   *
   * @param token the JWT token
   * @return the token subject
   */
  public String getSubjectFromExpiredToken(String token) {
    try {
      return validateAndGetClaims(token).getSubject();
    } catch (ExpiredJwtException e) {
      return e.getClaims().getSubject();
    }
  }

  /**
   * Checks if a token is expired.
   *
   * @param token the JWT token
   * @return true if the token is expired
   */
  public boolean isTokenExpired(String token) {
    try {
      validateAndGetClaims(token);
      return false;
    } catch (ExpiredJwtException e) {
      return true;
    }
  }

  private String generateToken(TokenRequest request, long expirationMs) {
    Instant now = Instant.now();
    Instant expiration = now.plusMillis(expirationMs);

    var builder =
        Jwts.builder()
            .subject(request.subject())
            .issuedAt(Date.from(now))
            .expiration(Date.from(expiration));

    if (jwtConfig.issuer() != null) {
      builder.issuer(jwtConfig.issuer());
    }

    if (jwtConfig.audience() != null) {
      builder.audience().add(jwtConfig.audience());
    }

    if (request.claims() != null) {
      for (Map.Entry<String, Object> entry : request.claims().entrySet()) {
        builder.claim(entry.getKey(), entry.getValue());
      }
    }

    return builder.signWith(signingKey).compact();
  }
}
