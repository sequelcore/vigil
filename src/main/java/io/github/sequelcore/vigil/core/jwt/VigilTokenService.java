package io.github.sequelcore.vigil.core.jwt;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import io.github.sequelcore.vigil.blacklist.VigilBlacklistService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Jwts;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.springframework.lang.Nullable;

/** Service for JWT token generation, validation, and refresh with rotation. */
public class VigilTokenService {

  private final VigilProperties.Jwt jwtConfig;
  private final TokenSigner signer;
  @Nullable private final VigilBlacklistService blacklistService;

  /**
   * Creates token service without blacklist (refresh rotation disabled).
   *
   * @param signer the signing strategy (HS256 or RS256)
   * @param jwtConfig JWT configuration (TTLs, issuer, audience)
   */
  public VigilTokenService(TokenSigner signer, VigilProperties.Jwt jwtConfig) {
    this(signer, jwtConfig, null);
  }

  /**
   * Creates token service with blacklist for refresh rotation.
   *
   * @param signer the signing strategy (HS256 or RS256)
   * @param jwtConfig JWT configuration (TTLs, issuer, audience)
   * @param blacklistService blacklist service for token invalidation
   */
  public VigilTokenService(
      TokenSigner signer,
      VigilProperties.Jwt jwtConfig,
      @Nullable VigilBlacklistService blacklistService) {
    this.signer = signer;
    this.jwtConfig = jwtConfig;
    this.blacklistService = blacklistService;
  }

  /**
   * Generates an access token.
   *
   * @param request token request with subject, claims, and optional custom TTL
   * @return the signed JWT access token
   */
  public String generateAccessToken(TokenRequest request) {
    long ttlMs =
        request.accessTtl() != null
            ? request.accessTtl().toMillis()
            : jwtConfig.accessTtl().toMillis();
    return generateToken(request, ttlMs);
  }

  /**
   * Generates a refresh token.
   *
   * @param subject the token subject
   * @return the signed JWT refresh token
   */
  public String generateRefreshToken(String subject) {
    return generateToken(
        TokenRequest.builder().subject(subject).claim("type", "refresh").build(),
        jwtConfig.refreshTtl().toMillis());
  }

  /**
   * Generates a refresh token with claims.
   *
   * @param request token request (claims will have type=refresh added)
   * @return the signed JWT refresh token
   */
  public String generateRefreshToken(TokenRequest request) {
    long ttlMs =
        request.refreshTtl() != null
            ? request.refreshTtl().toMillis()
            : jwtConfig.refreshTtl().toMillis();

    Map<String, Object> claims = new HashMap<>(request.claims());
    claims.put("type", "refresh");

    return generateToken(
        TokenRequest.builder().subject(request.subject()).claims(claims).build(), ttlMs);
  }

  /**
   * Refreshes tokens with rotation.
   *
   * @param refreshToken the current refresh token
   * @return new token pair with expiration times
   * @throws JwtException if refresh token is invalid or not a refresh token
   */
  public TokenRefreshResult refreshTokens(String refreshToken) {
    return refreshTokens(refreshToken, null);
  }

  /**
   * Refreshes tokens with rotation and updated claims.
   *
   * <p>Note: Token rotation (blacklisting the old token) is handled by {@link
   * io.github.sequelcore.vigil.auth.VigilAuthService} with grace period support.
   *
   * @param refreshToken the current refresh token
   * @param updatedClaims claims to update (merged with existing)
   * @return new token pair with expiration times
   * @throws JwtException if refresh token is invalid or not a refresh token
   */
  public TokenRefreshResult refreshTokens(String refreshToken, Map<String, Object> updatedClaims) {
    Claims claims = validateAndGetClaims(refreshToken);

    String type = claims.get("type", String.class);
    if (!"refresh".equals(type)) {
      throw new JwtException("Token is not a refresh token");
    }

    Map<String, Object> newClaims = new HashMap<>();
    claims.forEach(
        (key, value) -> {
          if (!isReservedClaim(key)) {
            newClaims.put(key, value);
          }
        });

    if (updatedClaims != null) {
      newClaims.putAll(updatedClaims);
    }

    newClaims.remove("type");

    String subject = claims.getSubject();
    Instant now = Instant.now();
    Instant accessExp = now.plusMillis(jwtConfig.accessTtl().toMillis());
    Instant refreshExp = now.plusMillis(jwtConfig.refreshTtl().toMillis());

    String newAccessToken =
        generateAccessToken(TokenRequest.builder().subject(subject).claims(newClaims).build());

    String newRefreshToken =
        generateRefreshToken(TokenRequest.builder().subject(subject).claims(newClaims).build());

    return new TokenRefreshResult(newAccessToken, newRefreshToken, accessExp, refreshExp);
  }

  /**
   * Validates a token and returns its claims.
   *
   * <p>Per RFC 8725bis, validates issuer and audience if configured.
   *
   * @param token the JWT token
   * @return the token claims
   * @throws ExpiredJwtException if expired
   * @throws JwtException if invalid
   */
  public Claims validateAndGetClaims(String token) {
    JwtParserBuilder parserBuilder = Jwts.parser();
    signer.configureParser(parserBuilder);

    if (jwtConfig.issuer() != null && !jwtConfig.issuer().isEmpty()) {
      parserBuilder.requireIssuer(jwtConfig.issuer());
    }

    if (jwtConfig.audience() != null && !jwtConfig.audience().isEmpty()) {
      parserBuilder.requireAudience(jwtConfig.audience());
    }

    return parserBuilder.build().parseSignedClaims(token).getPayload();
  }

  /**
   * Extracts subject from an expired token.
   *
   * @param token the JWT token
   * @return the subject
   */
  public String getSubjectFromExpiredToken(String token) {
    try {
      return validateAndGetClaims(token).getSubject();
    } catch (ExpiredJwtException e) {
      return e.getClaims().getSubject();
    }
  }

  /**
   * Checks if token is expired.
   *
   * @param token the JWT token
   * @return true if expired
   */
  public boolean isTokenExpired(String token) {
    try {
      validateAndGetClaims(token);
      return false;
    } catch (ExpiredJwtException e) {
      return true;
    }
  }

  /** Gets configured access token TTL. */
  public Instant getAccessTokenExpiration() {
    return Instant.now().plusMillis(jwtConfig.accessTtl().toMillis());
  }

  /** Gets configured refresh token TTL. */
  public Instant getRefreshTokenExpiration() {
    return Instant.now().plusMillis(jwtConfig.refreshTtl().toMillis());
  }

  private String generateToken(TokenRequest request, long expirationMs) {
    Instant now = Instant.now();
    Instant expiration = now.plusMillis(expirationMs);

    var builder =
        Jwts.builder()
            .subject(request.subject())
            .issuedAt(Date.from(now))
            .notBefore(Date.from(now))
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

    return signer.sign(builder);
  }

  private boolean isReservedClaim(String key) {
    return "iss".equals(key)
        || "sub".equals(key)
        || "aud".equals(key)
        || "exp".equals(key)
        || "nbf".equals(key)
        || "iat".equals(key)
        || "jti".equals(key);
  }
}
