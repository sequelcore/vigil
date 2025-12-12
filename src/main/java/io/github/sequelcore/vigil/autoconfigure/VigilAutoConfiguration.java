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

/** Auto-configuration for Vigil authentication starter. */
@AutoConfiguration
@EnableConfigurationProperties(VigilProperties.class)
public class VigilAutoConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public VigilTokenService vigilTokenService(VigilProperties properties) {
    return new VigilTokenService(properties.jwt());
  }

  @Bean
  @ConditionalOnMissingBean
  public VigilPasswordService vigilPasswordService(VigilProperties properties) {
    return new VigilPasswordService(properties.password());
  }

  @Bean
  @ConditionalOnMissingBean
  public VigilCookieService vigilCookieService(VigilProperties properties) {
    return new VigilCookieService(properties.cookie(), properties.jwt());
  }

  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnProperty(prefix = "vigil.blacklist", name = "enabled", havingValue = "true")
  public VigilBlacklistService vigilBlacklistService(VigilProperties properties) {
    return new VigilBlacklistService(properties.blacklist());
  }

  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnProperty(prefix = "vigil.tenant", name = "enabled", havingValue = "true")
  public VigilTenantService vigilTenantService(VigilProperties properties) {
    return new VigilTenantService(properties.tenant());
  }

  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnProperty(prefix = "vigil.protection", name = "enabled", havingValue = "true")
  public VigilProtectionService vigilProtectionService(VigilProperties properties) {
    return new VigilProtectionService(properties.protection());
  }

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
