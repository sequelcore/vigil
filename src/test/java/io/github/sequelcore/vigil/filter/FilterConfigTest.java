package io.github.sequelcore.vigil.filter;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class FilterConfigTest {

  @Test
  @DisplayName("Default constructor sets checkAllProfiles to false")
  void defaultConstructorSetsCheckAllProfilesToFalse() {
    FilterConfig config = new FilterConfig(List.of("/public/**"));

    assertThat(config.publicPaths()).containsExactly("/public/**");
    assertThat(config.checkAllProfiles()).isFalse();
  }

  @Test
  @DisplayName("Full constructor preserves all values")
  void fullConstructorPreservesAllValues() {
    FilterConfig config = new FilterConfig(List.of("/api/**", "/health"), true);

    assertThat(config.publicPaths()).containsExactly("/api/**", "/health");
    assertThat(config.checkAllProfiles()).isTrue();
  }
}
