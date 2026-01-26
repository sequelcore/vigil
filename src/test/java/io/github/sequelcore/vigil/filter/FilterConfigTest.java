package io.github.sequelcore.vigil.filter;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class FilterConfigTest {

  @Test
  @DisplayName(
      "Convenience constructor with only publicPaths sets empty ignoredPaths and profilePaths")
  void convenienceConstructorSetsEmptyIgnoredAndProfilePaths() {
    FilterConfig config = new FilterConfig(List.of("/public/**"));

    assertThat(config.ignoredPaths()).isEmpty();
    assertThat(config.publicPaths()).containsExactly("/public/**");
    assertThat(config.profilePaths()).isEmpty();
  }

  @Test
  @DisplayName("Two-argument constructor sets empty profilePaths")
  void twoArgumentConstructorSetsEmptyProfilePaths() {
    FilterConfig config = new FilterConfig(List.of("/actuator/**"), List.of("/public/**"));

    assertThat(config.ignoredPaths()).containsExactly("/actuator/**");
    assertThat(config.publicPaths()).containsExactly("/public/**");
    assertThat(config.profilePaths()).isEmpty();
  }

  @Test
  @DisplayName("Full constructor preserves all values")
  void fullConstructorPreservesAllValues() {
    Map<String, List<String>> profilePaths =
        Map.of(
            "staff", List.of("/api/console/**"),
            "customer", List.of("/api/box/**"));

    FilterConfig config =
        new FilterConfig(List.of("/actuator/**", "/health"), List.of("/api/**"), profilePaths);

    assertThat(config.ignoredPaths()).containsExactly("/actuator/**", "/health");
    assertThat(config.publicPaths()).containsExactly("/api/**");
    assertThat(config.profilePaths()).containsKeys("staff", "customer");
  }
}
