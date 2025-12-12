package io.github.sequelcore.vigil.tenant;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Optional;
import java.util.UUID;

/** Service for managing multi-tenant context. */
public class VigilTenantService {

  private final VigilProperties.Tenant tenantConfig;

  /**
   * Creates a tenant service with the provided configuration.
   *
   * @param tenantConfig tenant configuration properties
   */
  public VigilTenantService(VigilProperties.Tenant tenantConfig) {
    this.tenantConfig = tenantConfig;
  }

  /**
   * Extracts the tenant ID from the request header.
   *
   * @param request the HTTP request
   * @return the tenant ID if present and valid
   */
  public Optional<UUID> extractTenantId(HttpServletRequest request) {
    String headerValue = request.getHeader(tenantConfig.headerName());
    if (headerValue == null || headerValue.isEmpty()) {
      return Optional.empty();
    }

    try {
      return Optional.of(UUID.fromString(headerValue));
    } catch (IllegalArgumentException e) {
      return Optional.empty();
    }
  }

  /**
   * Sets the tenant context for the current thread.
   *
   * @param tenantId the tenant ID
   */
  public void setCurrentTenant(UUID tenantId) {
    VigilTenantContext.setTenant(tenantId);
  }

  /**
   * Gets the tenant ID for the current thread.
   *
   * @return the current tenant ID
   */
  public Optional<UUID> getCurrentTenant() {
    return VigilTenantContext.getTenant();
  }

  /** Clears the tenant context for the current thread. */
  public void clearCurrentTenant() {
    VigilTenantContext.clear();
  }

  /**
   * Validates that the tenant ID in the token matches the current context.
   *
   * @param tokenTenantId the tenant ID from the JWT token
   * @return true if the tenant IDs match
   */
  public boolean validateTenantConsistency(UUID tokenTenantId) {
    Optional<UUID> currentTenant = getCurrentTenant();
    if (currentTenant.isEmpty()) {
      return false;
    }
    return currentTenant.get().equals(tokenTenantId);
  }

  /**
   * Returns the configured header name for tenant ID.
   *
   * @return the header name
   */
  public String getHeaderName() {
    return tenantConfig.headerName();
  }
}
