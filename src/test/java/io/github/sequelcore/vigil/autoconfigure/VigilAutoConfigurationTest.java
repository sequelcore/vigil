package io.github.sequelcore.vigil.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.sequelcore.vigil.auth.VigilAuthService;
import io.github.sequelcore.vigil.auth.VigilResetTokenService;
import io.github.sequelcore.vigil.blacklist.RotatedToken;
import io.github.sequelcore.vigil.blacklist.VigilBlacklistBackend;
import io.github.sequelcore.vigil.blacklist.VigilBlacklistService;
import io.github.sequelcore.vigil.core.cookie.VigilCookieService;
import io.github.sequelcore.vigil.core.jwt.HmacTokenSigner;
import io.github.sequelcore.vigil.core.jwt.TokenSigner;
import io.github.sequelcore.vigil.core.jwt.VigilTokenService;
import io.github.sequelcore.vigil.core.password.VigilPasswordService;
import io.github.sequelcore.vigil.entrypoint.VigilAuthenticationEntryPoint;
import io.github.sequelcore.vigil.filter.VigilAuthenticationFilter;
import io.github.sequelcore.vigil.protection.VigilProtectionService;
import io.github.sequelcore.vigil.session.VigilSessionService;
import io.github.sequelcore.vigil.tenant.VigilTenantService;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.core.userdetails.UserDetailsService;
import tools.jackson.databind.ObjectMapper;

class VigilAutoConfigurationTest {

  private static final String SECRET = "01234567890123456789012345678901";
  private static final String VIGIL_SECRET_PROPERTY = "vigil.jwt.secret=" + SECRET;

  private final ApplicationContextRunner contextRunner =
      new ApplicationContextRunner()
          .withConfiguration(AutoConfigurations.of(VigilAutoConfiguration.class))
          .withBean(ObjectMapper.class, ObjectMapper::new)
          .withPropertyValues(VIGIL_SECRET_PROPERTY);

  @Test
  @DisplayName("Auto-configures starter beans without product user lifecycle beans")
  void autoConfiguresStarterBeansWithoutProductUserLifecycleBeans() {
    contextRunner.run(
        context -> {
          assertThat(context).hasSingleBean(VigilProperties.class);
          assertThat(context).hasSingleBean(TokenSigner.class);
          assertThat(context).hasSingleBean(HmacTokenSigner.class);
          assertThat(context).hasSingleBean(VigilBlacklistService.class);
          assertThat(context).hasSingleBean(VigilTokenService.class);
          assertThat(context).hasSingleBean(VigilPasswordService.class);
          assertThat(context).hasSingleBean(VigilCookieService.class);
          assertThat(context).hasSingleBean(VigilProtectionService.class);
          assertThat(context).hasSingleBean(VigilAuthService.class);
          assertThat(context).hasSingleBean(VigilResetTokenService.class);
          assertThat(context).hasSingleBean(VigilAuthenticationEntryPoint.class);
          assertThat(context).hasSingleBean(VigilAuthenticationFilter.class);
          assertThat(context).doesNotHaveBean(UserDetailsService.class);
        });
  }

  @Test
  @DisplayName("Keeps tenant and session beans conditional")
  void keepsTenantAndSessionBeansConditional() {
    contextRunner.run(
        context -> {
          assertThat(context).doesNotHaveBean(VigilTenantService.class);
          assertThat(context).doesNotHaveBean(VigilSessionService.class);
        });

    contextRunner
        .withPropertyValues("vigil.tenant.enabled=true", "vigil.session.enabled=true")
        .run(
            context -> {
              assertThat(context).hasSingleBean(VigilTenantService.class);
              assertThat(context).hasSingleBean(VigilSessionService.class);
            });
  }

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
