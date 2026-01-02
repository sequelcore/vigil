package io.github.sequelcore.vigil.filter;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class FilterConfigTest {

  @Test
  @DisplayName("Default constructor sets empty profilePaths")
  void defaultConstructorSetsEmptyProfilePaths() {
    FilterConfig config = new FilterConfig(List.of("/public/**"));

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

    FilterConfig config = new FilterConfig(List.of("/api/**", "/health"), profilePaths);

    assertThat(config.publicPaths()).containsExactly("/api/**", "/health");
    assertThat(config.profilePaths()).containsKeys("staff", "customer");
  }
}
