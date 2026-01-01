package io.github.sequelcore.vigil.filter;

import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Utility for matching request paths against configured public path patterns.
 *
 * <p>Supports wildcard patterns:
 *
 * <ul>
 *   <li>{@code *} - matches any single path segment (e.g., {@code /api/*} matches {@code /api/foo}
 *       but not {@code /api/foo/bar})
 *   <li>{@code **} - matches any path segments (e.g., {@code /public/**} matches {@code
 *       /public/a/b/c})
 * </ul>
 */
final class PathMatcher {

  private final List<Pattern> patterns;

  /**
   * Creates a path matcher with the given path patterns.
   *
   * @param paths list of path patterns (supports * and ** wildcards)
   */
  PathMatcher(List<String> paths) {
    this.patterns = compilePatterns(paths);
  }

  /**
   * Checks if the given path matches any of the configured patterns.
   *
   * @param path the request path to check
   * @return true if the path matches any pattern
   */
  boolean matches(String path) {
    return patterns.stream().anyMatch(pattern -> pattern.matcher(path).matches());
  }

  private List<Pattern> compilePatterns(List<String> paths) {
    if (paths == null || paths.isEmpty()) {
      return Collections.emptyList();
    }
    return paths.stream().map(this::pathToRegex).map(Pattern::compile).toList();
  }

  private String pathToRegex(String path) {
    String regex =
        path.replace(".", "\\.")
            .replace("?", "\\?")
            .replace("+", "\\+")
            .replace("(", "\\(")
            .replace(")", "\\)")
            .replace("[", "\\[")
            .replace("]", "\\]")
            .replace("{", "\\{")
            .replace("}", "\\}")
            .replace("^", "\\^")
            .replace("$", "\\$")
            .replace("|", "\\|");

    // Convert ** to match any path segments
    regex = regex.replace("**", "@@DOUBLE_STAR@@");
    // Convert * to match single path segment
    regex = regex.replace("*", "[^/]*");
    // Convert ** placeholder to match anything
    regex = regex.replace("@@DOUBLE_STAR@@", ".*");

    return "^" + regex + "$";
  }
}
