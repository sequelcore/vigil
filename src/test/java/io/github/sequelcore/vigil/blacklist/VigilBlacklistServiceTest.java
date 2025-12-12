package io.github.sequelcore.vigil.blacklist;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import java.time.Duration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class VigilBlacklistServiceTest {

  private VigilBlacklistService blacklistService;

  @BeforeEach
  void setUp() {
    blacklistService =
        new VigilBlacklistService(new VigilProperties.Blacklist(true, 100, Duration.ofMinutes(30)));
  }

  @Test
  @DisplayName("Blacklist token adds entry")
  void blacklistTokenAddsEntry() {
    blacklistService.blacklist("token-1");

    assertThat(blacklistService.isBlacklisted("token-1")).isTrue();
    assertThat(blacklistService.size()).isEqualTo(1);
  }

  @Test
  @DisplayName("isBlacklisted returns false for unknown token")
  void unknownTokenReturnsFalse() {
    assertThat(blacklistService.isBlacklisted("unknown")).isFalse();
  }

  @Test
  @DisplayName("Handle null or empty tokens gracefully")
  void handleNullOrEmpty() {
    blacklistService.blacklist(null);
    blacklistService.blacklist("");

    assertThat(blacklistService.size()).isZero();
    assertThat(blacklistService.isBlacklisted(null)).isFalse();
    assertThat(blacklistService.isBlacklisted("")).isFalse();
  }
}
