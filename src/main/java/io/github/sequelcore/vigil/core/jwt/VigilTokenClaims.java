package io.github.sequelcore.vigil.core.jwt;

import io.jsonwebtoken.Claims;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Wrapper for JWT claims providing type-safe access to common authentication data.
 *
 * @param claims the underlying JWT claims
 */
public record VigilTokenClaims(Claims claims) {

  /**
   * Gets the token subject (typically username or user ID).
   *
   * @return the subject
   */
  public String getSubject() {
    return claims.getSubject();
  }

  /**
   * Gets the token issuer.
   *
   * @return the issuer if present
   */
  public Optional<String> getIssuer() {
    return Optional.ofNullable(claims.getIssuer());
  }

  /**
   * Gets the token audience.
   *
   * @return the audience set
   */
  public List<String> getAudience() {
    var audience = claims.getAudience();
    return audience != null ? List.copyOf(audience) : Collections.emptyList();
  }

  /**
   * Gets the token expiration time.
   *
   * @return the expiration instant
   */
  public Instant getExpiration() {
    Date exp = claims.getExpiration();
    return exp != null ? exp.toInstant() : null;
  }

  /**
   * Gets the token issued-at time.
   *
   * @return the issued-at instant
   */
  public Instant getIssuedAt() {
    Date iat = claims.getIssuedAt();
    return iat != null ? iat.toInstant() : null;
  }

  /**
   * Gets a claim as a String.
   *
   * @param key the claim key
   * @return the claim value if present
   */
  public Optional<String> getString(String key) {
    return Optional.ofNullable(claims.get(key, String.class));
  }

  /**
   * Gets a claim as a UUID.
   *
   * @param key the claim key
   * @return the claim value if present and valid
   */
  public Optional<UUID> getUuid(String key) {
    String value = claims.get(key, String.class);
    if (value == null) {
      return Optional.empty();
    }
    try {
      return Optional.of(UUID.fromString(value));
    } catch (IllegalArgumentException e) {
      return Optional.empty();
    }
  }

  /**
   * Gets a claim as a Long.
   *
   * @param key the claim key
   * @return the claim value if present
   */
  public Optional<Long> getLong(String key) {
    Object value = claims.get(key);
    if (value == null) {
      return Optional.empty();
    }
    if (value instanceof Long l) {
      return Optional.of(l);
    }
    if (value instanceof Integer i) {
      return Optional.of(i.longValue());
    }
    return Optional.empty();
  }

  /**
   * Gets a claim as a list of strings.
   *
   * @param key the claim key
   * @return the claim values
   */
  @SuppressWarnings("unchecked")
  public List<String> getStringList(String key) {
    Object value = claims.get(key);
    if (value instanceof List<?> list) {
      return list.stream().filter(String.class::isInstance).map(String.class::cast).toList();
    }
    return Collections.emptyList();
  }

  /**
   * Gets a claim value by key.
   *
   * @param key the claim key
   * @return the raw claim value if present
   */
  public Optional<Object> get(String key) {
    return Optional.ofNullable(claims.get(key));
  }

  /**
   * Gets all claims as a map.
   *
   * @return unmodifiable map of all claims
   */
  public Map<String, Object> getAllClaims() {
    return Collections.unmodifiableMap(claims);
  }

  /**
   * Checks if the token has expired.
   *
   * @return true if the token is expired
   */
  public boolean isExpired() {
    Instant exp = getExpiration();
    return exp != null && Instant.now().isAfter(exp);
  }

  /**
   * Checks if the token is a refresh token.
   *
   * @return true if this is a refresh token
   */
  public boolean isRefreshToken() {
    return "refresh".equals(claims.get("type", String.class));
  }
}
