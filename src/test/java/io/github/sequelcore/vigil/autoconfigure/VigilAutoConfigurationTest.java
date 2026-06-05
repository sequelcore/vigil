package io.github.sequelcore.vigil.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.sequelcore.vigil.blacklist.RotatedToken;
import io.github.sequelcore.vigil.blacklist.VigilBlacklistBackend;
import io.github.sequelcore.vigil.blacklist.VigilBlacklistService;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;

class VigilAutoConfigurationTest {

  private static final String SECRET = "01234567890123456789012345678901";

  @Test
  @DisplayName("Uses application-provided blacklist backend when present")
  void usesApplicationProvidedBlacklistBackend() {
    VigilProperties properties = properties();
    VigilBlacklistBackend backend = mock(VigilBlacklistBackend.class);
    ObjectProvider<VigilBlacklistBackend> backendProvider = backendProvider(backend);
    VigilBlacklistService service =
        new VigilAutoConfiguration().vigilBlacklistService(properties, backendProvider);
    RotatedToken rotatedToken = rotatedToken();

    service.blacklist("token");
    service.rotate("refresh-token", rotatedToken);

    verify(backend).blacklist("token");
    verify(backend).rotate("refresh-token", rotatedToken, properties.blacklist().gracePeriod());
  }

  @Test
  @DisplayName("Falls back to Caffeine blacklist backend when no custom backend exists")
  void fallsBackToCaffeineBlacklistBackend() {
    VigilBlacklistService service =
        new VigilAutoConfiguration().vigilBlacklistService(properties(), backendProvider(null));

    service.blacklist("token");

    assertThat(service.isBlacklisted("token")).isTrue();
  }

  @SuppressWarnings("unchecked")
  private static ObjectProvider<VigilBlacklistBackend> backendProvider(
      VigilBlacklistBackend backend) {
    ObjectProvider<VigilBlacklistBackend> provider = mock(ObjectProvider.class);
    when(provider.getIfAvailable()).thenReturn(backend);
    return provider;
  }

  private static VigilProperties properties() {
    return new VigilProperties(
        new VigilProperties.Jwt(
            SECRET,
            Duration.ofMinutes(15),
            Duration.ofDays(7),
            null,
            null,
            null,
            null,
            null,
            null,
            null),
        null,
        null,
        new VigilProperties.Blacklist(100, Duration.ofMinutes(30), Duration.ofSeconds(15)),
        null,
        null,
        null,
        null,
        null,
        null);
  }

  private static RotatedToken rotatedToken() {
    Instant now = Instant.now();
    return new RotatedToken(
        now, "access-token", "refresh-token", now.plusSeconds(900), now.plusSeconds(3600));
  }
}
