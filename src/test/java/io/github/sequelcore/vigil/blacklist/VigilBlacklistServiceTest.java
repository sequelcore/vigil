package io.github.sequelcore.vigil.blacklist;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class VigilBlacklistServiceTest {

  private VigilBlacklistService blacklistService;

  @BeforeEach
  void setUp() {
    blacklistService =
        new VigilBlacklistService(
            new VigilProperties.Blacklist(100, Duration.ofMinutes(30), Duration.ofSeconds(30)));
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

  @Nested
  @DisplayName("Grace period for token rotation")
  class GracePeriod {

    @Test
    @DisplayName("Rotated token is retrievable during grace period")
    void rotatedTokenRetrievableDuringGracePeriod() {
      Instant now = Instant.now();
      RotatedToken rotatedToken =
          new RotatedToken(
              now,
              "new-access-token",
              "new-refresh-token",
              now.plusSeconds(900),
              now.plus(Duration.ofDays(7)));

      blacklistService.rotate("old-refresh-token", rotatedToken);

      assertThat(blacklistService.getRotation("old-refresh-token")).isPresent();
      assertThat(blacklistService.getRotation("old-refresh-token").get().newAccessToken())
          .isEqualTo("new-access-token");
      assertThat(blacklistService.getRotation("old-refresh-token").get().newRefreshToken())
          .isEqualTo("new-refresh-token");
    }

    @Test
    @DisplayName("Non-rotated token returns empty")
    void nonRotatedTokenReturnsEmpty() {
      assertThat(blacklistService.getRotation("never-rotated")).isEmpty();
    }

    @Test
    @DisplayName("Rotated token expires after grace period")
    void rotatedTokenExpiresAfterGracePeriod() throws InterruptedException {
      // Use a very short grace period for testing
      VigilBlacklistService shortGraceService =
          new VigilBlacklistService(
              new VigilProperties.Blacklist(100, Duration.ofMinutes(30), Duration.ofMillis(50)));

      Instant now = Instant.now();
      RotatedToken rotatedToken =
          new RotatedToken(
              now,
              "new-access-token",
              "new-refresh-token",
              now.plusSeconds(900),
              now.plus(Duration.ofDays(7)));

      shortGraceService.rotate("old-refresh-token", rotatedToken);

      // Should be present immediately
      assertThat(shortGraceService.getRotation("old-refresh-token")).isPresent();

      // Wait for grace period to expire
      Thread.sleep(100);

      // Should be gone after grace period
      assertThat(shortGraceService.getRotation("old-refresh-token")).isEmpty();
    }

    @Test
    @DisplayName("Handle null or empty rotation gracefully")
    void handleNullOrEmptyRotation() {
      Instant now = Instant.now();
      RotatedToken rotatedToken =
          new RotatedToken(
              now, "access", "refresh", now.plusSeconds(900), now.plus(Duration.ofDays(7)));

      blacklistService.rotate(null, rotatedToken);
      blacklistService.rotate("", rotatedToken);
      blacklistService.rotate("token", null);

      assertThat(blacklistService.getRotation(null)).isEmpty();
      assertThat(blacklistService.getRotation("")).isEmpty();
    }
  }
}
