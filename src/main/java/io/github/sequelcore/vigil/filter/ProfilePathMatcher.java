package io.github.sequelcore.vigil.filter;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Matches request paths to cookie profile names. */
public class ProfilePathMatcher {

  private final Map<String, PathMatcher> profileMatchers;

  /**
   * Creates a profile path matcher.
   *
   * @param profilePaths mapping of profile name to path patterns
   */
  public ProfilePathMatcher(Map<String, List<String>> profilePaths) {
    this.profileMatchers = new HashMap<>();
    profilePaths.forEach(
        (profile, patterns) -> profileMatchers.put(profile, new PathMatcher(patterns)));
  }

  /**
   * Finds the profile that matches the given path.
   *
   * @param path the request path
   * @return the matching profile name, or empty if no match
   */
  public Optional<String> findProfile(String path) {
    for (Map.Entry<String, PathMatcher> entry : profileMatchers.entrySet()) {
      if (entry.getValue().matches(path)) {
        return Optional.of(entry.getKey());
      }
    }
    return Optional.empty();
  }
}
