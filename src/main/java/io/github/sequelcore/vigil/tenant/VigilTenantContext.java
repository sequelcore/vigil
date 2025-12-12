package io.github.sequelcore.vigil.tenant;

import java.util.Optional;
import java.util.UUID;

/** Thread-local storage for tenant context. */
public final class VigilTenantContext {

  private static final ThreadLocal<UUID> CURRENT_TENANT = new ThreadLocal<>();

  private VigilTenantContext() {
    // Utility class
  }

  /**
   * Sets the tenant ID for the current thread.
   *
   * @param tenantId the tenant ID
   */
  public static void setTenant(UUID tenantId) {
    CURRENT_TENANT.set(tenantId);
  }

  /**
   * Gets the tenant ID for the current thread.
   *
   * @return the tenant ID if set
   */
  public static Optional<UUID> getTenant() {
    return Optional.ofNullable(CURRENT_TENANT.get());
  }

  /**
   * Gets the tenant ID for the current thread, throwing if not set.
   *
   * @return the tenant ID
   * @throws IllegalStateException if no tenant is set
   */
  public static UUID requireTenant() {
    UUID tenantId = CURRENT_TENANT.get();
    if (tenantId == null) {
      throw new IllegalStateException("No tenant context set for current thread");
    }
    return tenantId;
  }

  /** Clears the tenant context for the current thread. */
  public static void clear() {
    CURRENT_TENANT.remove();
  }

  /**
   * Executes a runnable within a tenant context.
   *
   * @param tenantId the tenant ID
   * @param runnable the code to execute
   */
  public static void withTenant(UUID tenantId, Runnable runnable) {
    UUID previous = CURRENT_TENANT.get();
    try {
      setTenant(tenantId);
      runnable.run();
    } finally {
      if (previous != null) {
        setTenant(previous);
      } else {
        clear();
      }
    }
  }
}
