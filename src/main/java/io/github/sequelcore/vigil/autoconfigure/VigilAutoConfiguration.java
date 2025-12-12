package io.github.sequelcore.vigil.autoconfigure;

import io.github.sequelcore.vigil.blacklist.VigilBlacklistService;
import io.github.sequelcore.vigil.core.cookie.VigilCookieService;
import io.github.sequelcore.vigil.core.jwt.VigilTokenService;
import io.github.sequelcore.vigil.core.password.VigilPasswordService;
import io.github.sequelcore.vigil.filter.VigilAuthenticationFilter;
import io.github.sequelcore.vigil.protection.VigilProtectionService;
import io.github.sequelcore.vigil.tenant.VigilTenantService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.lang.Nullable;

/**
 * Auto-configuration for the Vigil authentication starter.
 *
 * <p>Registers core services, optional modules (blacklist, tenant, protection), and the
 * authentication filter based on {@code vigil.*} configuration properties.
 */
@AutoConfiguration
@EnableConfigurationProperties(VigilProperties.class)
public class VigilAutoConfiguration {

  /** Creates the Vigil auto-configuration. */
  public VigilAutoConfiguration() {}

  /**
   * Creates the token service used to generate and validate JWTs.
   *
   * @param properties the loaded Vigil properties
   * @return configured token service
   */
  @Bean
  @ConditionalOnMissingBean
  public VigilTokenService vigilTokenService(VigilProperties properties) {
    return new VigilTokenService(properties.jwt());
  }

  /**
   * Creates the password service for hashing and validation.
   *
   * @param properties the loaded Vigil properties
   * @return configured password service
   */
  @Bean
  @ConditionalOnMissingBean
  public VigilPasswordService vigilPasswordService(VigilProperties properties) {
    return new VigilPasswordService(properties.password());
  }

  /**
   * Creates the cookie service that manages access and refresh token cookies.
   *
   * @param properties the loaded Vigil properties
   * @return configured cookie service
   */
  @Bean
  @ConditionalOnMissingBean
  public VigilCookieService vigilCookieService(VigilProperties properties) {
    return new VigilCookieService(properties.cookie(), properties.jwt());
  }

  /**
   * Creates the blacklist service when token blacklisting is enabled.
   *
   * @param properties the loaded Vigil properties
   * @return configured blacklist service
   */
  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnProperty(prefix = "vigil.blacklist", name = "enabled", havingValue = "true")
  public VigilBlacklistService vigilBlacklistService(VigilProperties properties) {
    return new VigilBlacklistService(properties.blacklist());
  }

  /**
   * Creates the tenant service when multi-tenancy is enabled.
   *
   * @param properties the loaded Vigil properties
   * @return configured tenant service
   */
  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnProperty(prefix = "vigil.tenant", name = "enabled", havingValue = "true")
  public VigilTenantService vigilTenantService(VigilProperties properties) {
    return new VigilTenantService(properties.tenant());
  }

  /**
   * Creates the protection service when brute-force protection is enabled.
   *
   * @param properties the loaded Vigil properties
   * @return configured protection service
   */
  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnProperty(prefix = "vigil.protection", name = "enabled", havingValue = "true")
  public VigilProtectionService vigilProtectionService(VigilProperties properties) {
    return new VigilProtectionService(properties.protection());
  }

  /**
   * Creates the authentication filter when enabled.
   *
   * @param properties the loaded Vigil properties
   * @param tokenService the token service for JWT validation
   * @param cookieService the cookie service for token extraction
   * @param blacklistService optional blacklist service
   * @param tenantService optional tenant service
   * @return configured authentication filter
   */
  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnProperty(prefix = "vigil.filter", name = "enabled", havingValue = "true")
  public VigilAuthenticationFilter vigilAuthenticationFilter(
      VigilProperties properties,
      VigilTokenService tokenService,
      VigilCookieService cookieService,
      @Nullable VigilBlacklistService blacklistService,
      @Nullable VigilTenantService tenantService) {
    return new VigilAuthenticationFilter(
        tokenService,
        cookieService,
        blacklistService,
        tenantService,
        properties.filter().publicPaths());
  }
}
