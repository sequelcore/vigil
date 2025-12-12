package io.github.sequelcore.vigil.protection;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import java.time.Duration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class VigilProtectionServiceTest {

  private VigilProtectionService protectionService;

  @BeforeEach
  void setUp() {
    protectionService =
        new VigilProtectionService(
            new VigilProperties.Protection(true, 3, Duration.ofMinutes(1), 50));
  }

  @Test
  @DisplayName("Record failed attempt increments counter")
  void recordFailedAttemptIncrements() {
    protectionService.recordFailedAttempt("user1");

    assertThat(protectionService.getFailedAttempts("user1")).isEqualTo(1);
  }

  @Test
  @DisplayName("Account locks after max attempts")
  void accountLocksAfterMaxAttempts() {
    protectionService.recordFailedAttempt("user2");
    protectionService.recordFailedAttempt("user2");
    protectionService.recordFailedAttempt("user2");

    assertThat(protectionService.isLocked("user2")).isTrue();
  }

  @Test
  @DisplayName("Successful login resets counter")
  void successfulLoginResetsCounter() {
    protectionService.recordFailedAttempt("user3");
    protectionService.recordFailedAttempt("user3");

    protectionService.recordSuccessfulLogin("user3");

    assertThat(protectionService.getFailedAttempts("user3")).isZero();
    assertThat(protectionService.isLocked("user3")).isFalse();
  }

  @Test
  @DisplayName("Unlock clears lock and attempts")
  void unlockClearsLock() {
    protectionService.recordFailedAttempt("user4");
    protectionService.recordFailedAttempt("user4");
    protectionService.recordFailedAttempt("user4");

    protectionService.unlock("user4");

    assertThat(protectionService.isLocked("user4")).isFalse();
    assertThat(protectionService.getFailedAttempts("user4")).isZero();
  }
}
