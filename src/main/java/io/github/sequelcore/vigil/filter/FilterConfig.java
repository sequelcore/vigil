package io.github.sequelcore.vigil.filter;

import java.util.List;
import java.util.Map;

/**
 * Configuration for the authentication filter.
 *
 * @param ignoredPaths paths that bypass ALL processing (no tenant, no auth, no populators)
 * @param publicPaths paths that permit anonymous but authenticate if credentials present
 * @param profilePaths mapping of profile name to path patterns for cookie resolution
 */
public record FilterConfig(
    List<String> ignoredPaths, List<String> publicPaths, Map<String, List<String>> profilePaths) {

  /** Creates a config with only public paths (no ignored paths, no profile mapping). */
  public FilterConfig(List<String> publicPaths) {
    this(List.of(), publicPaths, Map.of());
  }

  /** Creates a config with ignored and public paths (no profile mapping). */
  public FilterConfig(List<String> ignoredPaths, List<String> publicPaths) {
    this(ignoredPaths, publicPaths, Map.of());
  }
}
