package io.github.sequelcore.vigil.test;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import io.github.sequelcore.vigil.blacklist.VigilBlacklistService;
import io.github.sequelcore.vigil.core.cookie.VigilCookieService;
import io.github.sequelcore.vigil.core.jwt.VigilTokenService;
import io.github.sequelcore.vigil.core.password.VigilPasswordService;
import io.github.sequelcore.vigil.protection.VigilProtectionService;
import io.github.sequelcore.vigil.tenant.VigilTenantService;
import java.time.Duration;
import java.util.Map;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

/**
 * Test configuration providing Vigil beans with test-friendly defaults.
 *
 * <p>Usage:
 *
 * <pre>
 * &#64;Import(VigilTestConfiguration.class)
 * class MyControllerTest {
 *   // Vigil beans are available
 * }
 * </pre>
 */
@TestConfiguration
public class VigilTestConfiguration {

  /** Deterministic test secret (32+ chars). */
  public static final String TEST_SECRET = "vigil-test-secret-key-for-jwt-token-generation-32chars";

  @Bean
  @Primary
  public VigilProperties.Jwt testJwtProperties() {
    return new VigilProperties.Jwt(
        TEST_SECRET, Duration.ofMinutes(15), Duration.ofDays(7), "vigil-test", null);
  }

  @Bean
  @Primary
  public VigilProperties.Cookie testCookieProperties() {
    return new VigilProperties.Cookie(
        false,
        "Lax",
        true,
        Map.of("default", new VigilProperties.CookieProfile("access_token", "refresh_token")));
  }

  @Bean
  @Primary
  public VigilProperties.Blacklist testBlacklistProperties() {
    return new VigilProperties.Blacklist(1000, Duration.ofHours(1));
  }

  @Bean
  @Primary
  public VigilProperties.Protection testProtectionProperties() {
    return new VigilProperties.Protection(5, Duration.ofMinutes(1), 1000);
  }

  @Bean
  @Primary
  public VigilProperties.Password testPasswordProperties() {
    return new VigilProperties.Password(4); // Fast for tests
  }

  @Bean
  @Primary
  public VigilProperties.Tenant testTenantProperties() {
    return new VigilProperties.Tenant(true, "X-Tenant-ID");
  }

  @Bean
  @Primary
  public VigilBlacklistService testBlacklistService() {
    return new VigilBlacklistService(testBlacklistProperties());
  }

  @Bean
  @Primary
  public VigilTokenService testTokenService() {
    return new VigilTokenService(testJwtProperties(), testBlacklistService());
  }

  @Bean
  @Primary
  public VigilCookieService testCookieService() {
    return new VigilCookieService(testCookieProperties(), testJwtProperties());
  }

  @Bean
  @Primary
  public VigilPasswordService testPasswordService() {
    return new VigilPasswordService(testPasswordProperties());
  }

  @Bean
  @Primary
  public VigilProtectionService testProtectionService() {
    return new VigilProtectionService(testProtectionProperties());
  }

  @Bean
  @Primary
  public VigilTenantService testTenantService() {
    return new VigilTenantService(testTenantProperties());
  }
}
