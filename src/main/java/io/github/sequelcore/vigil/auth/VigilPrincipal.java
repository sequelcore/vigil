package io.github.sequelcore.vigil.auth;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Authenticated principal extracted from token claims.
 *
 * <p>Provides type-safe access to common authentication properties and custom claims.
 *
 * @param subject the principal identifier (user ID, email, etc.)
 * @param tenantId the tenant ID if multi-tenancy is enabled
 * @param roles the granted roles (without ROLE_ prefix)
 * @param claims all token claims for custom access
 */
public record VigilPrincipal(
    String subject, UUID tenantId, List<String> roles, Map<String, Object> claims) {

  /**
   * Creates a principal with immutable collections.
   *
   * @param subject the principal identifier
   * @param tenantId the tenant ID
   * @param roles the granted roles
   * @param claims all token claims
   */
  public VigilPrincipal {
    roles = roles != null ? List.copyOf(roles) : List.of();
    claims = claims != null ? Map.copyOf(claims) : Map.of();
  }

  /**
   * Gets a string claim value.
   *
   * @param key the claim key
   * @return the claim value if present and is a string
   */
  public Optional<String> getClaim(String key) {
    Object value = claims.get(key);
    return value instanceof String s ? Optional.of(s) : Optional.empty();
  }

  /**
   * Gets a claim value as a specific type.
   *
   * @param key the claim key
   * @param type the expected type
   * @param <T> the type parameter
   * @return the claim value if present and matches type
   */
  public <T> Optional<T> getClaim(String key, Class<T> type) {
    Object value = claims.get(key);
    return type.isInstance(value) ? Optional.of(type.cast(value)) : Optional.empty();
  }

  /**
   * Checks if the principal has a specific role.
   *
   * @param role the role name (without ROLE_ prefix)
   * @return true if the principal has the role
   */
  public boolean hasRole(String role) {
    return roles.contains(role);
  }

  /**
   * Checks if the principal has any of the specified roles.
   *
   * @param rolesToCheck roles to check
   * @return true if the principal has at least one of the roles
   */
  public boolean hasAnyRole(String... rolesToCheck) {
    for (String role : rolesToCheck) {
      if (roles.contains(role)) {
        return true;
      }
    }
    return false;
  }
}
