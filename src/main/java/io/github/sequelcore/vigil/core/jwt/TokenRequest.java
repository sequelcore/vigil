package io.github.sequelcore.vigil.core.jwt;

import java.util.HashMap;
import java.util.Map;
import lombok.Builder;
import lombok.Singular;

/**
 * Request object for generating JWT tokens.
 *
 * @param subject the token subject (typically username or user ID)
 * @param claims additional claims to include in the token
 */
@Builder
public record TokenRequest(String subject, @Singular Map<String, Object> claims) {

  /**
   * Ensures the claims map is initialized when not provided.
   *
   * @param subject the token subject
   * @param claims additional claims to include in the token
   */
  public TokenRequest {
    if (claims == null) {
      claims = new HashMap<>();
    }
  }
}
