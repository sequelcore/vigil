package io.github.sequelcore.vigil.filter;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class ProfilePathMatcherTest {

  @Test
  @DisplayName("Match path to correct profile")
  void matchPathToCorrectProfile() {
    Map<String, List<String>> profilePaths =
        Map.of(
            "staff", List.of("/api/console/**"),
            "customer", List.of("/api/box/**"));

    ProfilePathMatcher matcher = new ProfilePathMatcher(profilePaths);

    assertThat(matcher.findProfile("/api/console/dashboard")).contains("staff");
    assertThat(matcher.findProfile("/api/box/orders")).contains("customer");
  }

  @Test
  @DisplayName("Return empty when no profile matches")
  void returnEmptyWhenNoMatch() {
    Map<String, List<String>> profilePaths = Map.of("staff", List.of("/api/console/**"));

    ProfilePathMatcher matcher = new ProfilePathMatcher(profilePaths);

    assertThat(matcher.findProfile("/api/other")).isEmpty();
  }

  @Test
  @DisplayName("Handle multiple patterns per profile")
  void handleMultiplePatternsPerProfile() {
    Map<String, List<String>> profilePaths =
        Map.of("staff", List.of("/api/console/**", "/api/admin/**"));

    ProfilePathMatcher matcher = new ProfilePathMatcher(profilePaths);

    assertThat(matcher.findProfile("/api/console/users")).contains("staff");
    assertThat(matcher.findProfile("/api/admin/settings")).contains("staff");
  }

  @Test
  @DisplayName("Handle empty profile paths")
  void handleEmptyProfilePaths() {
    ProfilePathMatcher matcher = new ProfilePathMatcher(Map.of());

    assertThat(matcher.findProfile("/api/anything")).isEmpty();
  }
}
