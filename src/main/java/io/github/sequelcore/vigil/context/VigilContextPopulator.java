package io.github.sequelcore.vigil.context;

import io.github.sequelcore.vigil.core.jwt.VigilTokenClaims;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Populates application-specific security contexts after authentication.
 *
 * <p>Implement this interface to set up ThreadLocal contexts when Vigil authenticates a request.
 * Vigil auto-discovers all beans implementing this interface and calls them after successful
 * authentication.
 *
 * <p>Example:
 *
 * <pre>{@code
 * @Component
 * public class UserContextPopulator implements VigilContextPopulator {
 *
 *     @Override
 *     public void populate(HttpServletRequest request, VigilTokenClaims claims) {
 *         UserContext.set(
 *             claims.getString("userId").orElse(null),
 *             claims.getString("role").orElse(null)
 *         );
 *     }
 *
 *     @Override
 *     public void clear() {
 *         UserContext.clear();
 *     }
 * }
 * }</pre>
 */
public interface VigilContextPopulator {

  /**
   * Populates the security context after successful authentication.
   *
   * <p>Called after JWT or session authentication succeeds. The claims parameter is null for
   * session-based authentication.
   *
   * @param request the HTTP request
   * @param claims the validated token claims, or null for session auth
   */
  void populate(HttpServletRequest request, VigilTokenClaims claims);

  /** Clears the security context after request processing. */
  void clear();

  /**
   * Returns the execution order. Lower values execute first.
   *
   * @return the order value, default 0
   */
  default int getOrder() {
    return 0;
  }
}
