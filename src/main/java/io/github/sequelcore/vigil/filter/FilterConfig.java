package io.github.sequelcore.vigil.filter;

import java.util.List;
import java.util.Map;

/**
 * Configuration for the authentication filter.
 *
 * @param publicPaths list of paths that bypass authentication
 * @param profilePaths mapping of profile name to path patterns
 */
public record FilterConfig(List<String> publicPaths, Map<String, List<String>> profilePaths) {

  /** Creates a config with only public paths (no profile path mapping). */
  public FilterConfig(List<String> publicPaths) {
    this(publicPaths, Map.of());
  }
}
