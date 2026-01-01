package io.github.sequelcore.vigil.session;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Provider for stateful session authentication.
 *
 * <p>Implement this interface to enable guest/anonymous session support. Vigil handles token
 * generation, cookies, and filter integration. The application handles entity persistence and
 * domain logic.
 *
 * <p>Example implementation:
 *
 * <pre>{@code
 * @Component
 * @RequiredArgsConstructor
 * public class CustomerSessionProvider implements VigilSessionProvider<Customer> {
 *
 *     private final CustomerRepository repository;
 *
 *     @Override
 *     public Optional<Customer> findByToken(String token, UUID tenantId) {
 *         return repository.findBySessionToken(token, tenantId);
 *     }
 *
 *     @Override
 *     public boolean isExpired(Customer customer) {
 *         return customer.getSessionExpiresAt().isBefore(LocalDateTime.now());
 *     }
 *
 *     @Override
 *     public String getPrincipal(Customer customer) {
 *         return customer.getId().toString();
 *     }
 *
 *     @Override
 *     public void onAuthenticated(Customer customer, HttpServletRequest request) {
 *         CustomerContext.set(customer);
 *     }
 * }
 * }</pre>
 *
 * @param <T> the session entity type
 */
public interface VigilSessionProvider<T> {

  /**
   * Finds a session entity by token.
   *
   * @param token the session token (UUID string)
   * @param tenantId the tenant ID, or null if multi-tenancy is disabled
   * @return the session entity if found
   */
  Optional<T> findByToken(String token, UUID tenantId);

  /**
   * Checks if the session has expired.
   *
   * @param session the session entity
   * @return true if the session is expired
   */
  boolean isExpired(T session);

  /**
   * Returns the principal identifier for Spring Security context.
   *
   * <p>Typically the entity ID as a string.
   *
   * @param session the session entity
   * @return the principal identifier
   */
  String getPrincipal(T session);

  /**
   * Returns the granted authorities for the session.
   *
   * <p>Default implementation returns {@code ["GUEST"]}.
   *
   * @param session the session entity
   * @return list of role names (without ROLE_ prefix)
   */
  default List<String> getRoles(T session) {
    return List.of("GUEST");
  }

  /**
   * Called after successful session authentication.
   *
   * <p>Use this to populate application-specific thread-local contexts.
   *
   * @param session the authenticated session entity
   * @param request the HTTP request
   */
  default void onAuthenticated(T session, HttpServletRequest request) {
    // Default: no-op
  }
}
