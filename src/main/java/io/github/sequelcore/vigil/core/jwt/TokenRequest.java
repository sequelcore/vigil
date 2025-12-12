package io.github.sequelcore.vigil.core.jwt;

import java.util.HashMap;
import java.util.Map;
import lombok.Builder;
import lombok.Singular;

/** Request object for generating JWT tokens. */
@Builder
public record TokenRequest(String subject, @Singular Map<String, Object> claims) {

  public TokenRequest {
    if (claims == null) {
      claims = new HashMap<>();
    }
  }
}
