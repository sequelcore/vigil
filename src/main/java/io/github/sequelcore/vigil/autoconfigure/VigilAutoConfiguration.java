package io.github.sequelcore.vigil.autoconfigure;

import io.github.sequelcore.vigil.auth.VigilAuthService;
import io.github.sequelcore.vigil.auth.VigilResetTokenService;
import io.github.sequelcore.vigil.blacklist.VigilBlacklistService;
import io.github.sequelcore.vigil.context.VigilContextPopulator;
import io.github.sequelcore.vigil.core.cookie.VigilCookieService;
import io.github.sequelcore.vigil.core.jwt.VigilTokenService;
import io.github.sequelcore.vigil.core.password.VigilPasswordService;
import io.github.sequelcore.vigil.filter.FilterConfig;
import io.github.sequelcore.vigil.filter.VigilAuthenticationFilter;
import io.github.sequelcore.vigil.protection.VigilProtectionService;
import io.github.sequelcore.vigil.session.VigilSessionProvider;
import io.github.sequelcore.vigil.session.VigilSessionService;
import io.github.sequelcore.vigil.tenant.VigilTenantService;
import java.util.List;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.lang.Nullable;

/**
 * Auto-configuration for the Vigil authentication starter.
 *
 * <p>Registers core services and the authentication filter. Optional features:
 *
 * <ul>
 *   <li>Multi-tenancy: {@code vigil.tenant.enabled=true}
 *   <li>Session auth: {@code vigil.session.enabled=true}
 * </ul>
 */
@AutoConfiguration
@EnableConfigurationProperties(VigilProperties.class)
public class VigilAutoConfiguration {

  /** Creates the Vigil auto-configuration. */
  public VigilAutoConfiguration() {}

  /**
   * Creates the blacklist service for token invalidation.
   *
   * @param properties the loaded Vigil properties
   * @return configured blacklist service
   */
  @Bean
  @ConditionalOnMissingBean
  public VigilBlacklistService vigilBlacklistService(VigilProperties properties) {
    return new VigilBlacklistService(properties.blacklist());
  }

  /**
   * Creates the token service for JWT generation and validation.
   *
   * @param properties the loaded Vigil properties
   * @param blacklistService the blacklist service for token rotation
   * @return configured token service
   */
  @Bean
  @ConditionalOnMissingBean
  public VigilTokenService vigilTokenService(
      VigilProperties properties, VigilBlacklistService blacklistService) {
    return new VigilTokenService(properties.jwt(), blacklistService);
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
   * Creates the cookie service for token cookies.
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
   * Creates the protection service for brute-force prevention.
   *
   * @param properties the loaded Vigil properties
   * @return configured protection service
   */
  @Bean
  @ConditionalOnMissingBean
  public VigilProtectionService vigilProtectionService(VigilProperties properties) {
    return new VigilProtectionService(properties.protection());
  }

  /**
   * Creates the high-level auth service.
   *
   * @param tokenService the token service
   * @param cookieService the cookie service
   * @param blacklistService the blacklist service
   * @return configured auth service
   */
  @Bean
  @ConditionalOnMissingBean
  public VigilAuthService vigilAuthService(
      VigilTokenService tokenService,
      VigilCookieService cookieService,
      VigilBlacklistService blacklistService) {
    return new VigilAuthService(tokenService, cookieService, blacklistService);
  }

  /**
   * Creates the reset token service for password recovery.
   *
   * @param tokenService the token service
   * @param blacklistService the blacklist service
   * @param properties the loaded Vigil properties
   * @return configured reset token service
   */
  @Bean
  @ConditionalOnMissingBean
  public VigilResetTokenService vigilResetTokenService(
      VigilTokenService tokenService,
      VigilBlacklistService blacklistService,
      VigilProperties properties) {
    return new VigilResetTokenService(tokenService, blacklistService, properties.reset());
  }

  /**
   * Creates the session service when session auth is enabled.
   *
   * @param cookieService the cookie service
   * @param properties the loaded Vigil properties
   * @return configured session service
   */
  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnProperty(prefix = "vigil.session", name = "enabled", havingValue = "true")
  public VigilSessionService vigilSessionService(
      VigilCookieService cookieService, VigilProperties properties) {
    return new VigilSessionService(cookieService, properties.session());
  }

  /**
   * Creates the authentication filter.
   *
   * @param properties the loaded Vigil properties
   * @param tokenService the token service for JWT validation
   * @param cookieService the cookie service for token extraction
   * @param blacklistService the blacklist service for token invalidation
   * @param tenantService optional tenant service
   * @param sessionService optional session service
   * @param sessionProvider optional session provider (application-provided)
   * @param contextPopulators list of context populators (auto-discovered)
   * @return configured authentication filter
   */
  @Bean
  @ConditionalOnMissingBean
  public VigilAuthenticationFilter vigilAuthenticationFilter(
      VigilProperties properties,
      VigilTokenService tokenService,
      VigilCookieService cookieService,
      VigilBlacklistService blacklistService,
      @Nullable VigilTenantService tenantService,
      @Nullable VigilSessionService sessionService,
      @Nullable VigilSessionProvider<?> sessionProvider,
      List<VigilContextPopulator> contextPopulators) {
    FilterConfig filterConfig =
        new FilterConfig(properties.filter().publicPaths(), properties.filter().checkAllProfiles());
    return new VigilAuthenticationFilter(
        tokenService,
        cookieService,
        blacklistService,
        tenantService,
        sessionService,
        sessionProvider,
        contextPopulators,
        filterConfig);
  }
}
