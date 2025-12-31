package io.github.sequelcore.vigil.core.jwt;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import lombok.Builder;
import lombok.Singular;

/**
 * Request object for generating JWT tokens.
 *
 * @param subject the token subject (typically username or user ID)
 * @param claims additional claims to include in the token
 * @param accessTtl custom access token TTL (null = use config default)
 * @param refreshTtl custom refresh token TTL (null = use config default)
 */
@Builder
public record TokenRequest(
    String subject, @Singular Map<String, Object> claims, Duration accessTtl, Duration refreshTtl) {

  /** Ensures claims map is initialized. */
  public TokenRequest {
    if (claims == null) {
      claims = new HashMap<>();
    }
  }
}
