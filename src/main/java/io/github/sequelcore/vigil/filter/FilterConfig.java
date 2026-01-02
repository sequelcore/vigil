package io.github.sequelcore.vigil.filter;

import java.util.List;

/**
 * Configuration for the authentication filter.
 *
 * @param publicPaths list of paths that bypass authentication
 * @param checkAllProfiles whether to check all cookie profiles for tokens
 */
public record FilterConfig(List<String> publicPaths, boolean checkAllProfiles) {

  /** Creates a config with only public paths (checkAllProfiles defaults to false). */
  public FilterConfig(List<String> publicPaths) {
    this(publicPaths, false);
  }
}
