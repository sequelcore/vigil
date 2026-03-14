package io.github.sequelcore.vigil.filter;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import io.github.sequelcore.vigil.blacklist.VigilBlacklistService;
import io.github.sequelcore.vigil.core.cookie.VigilCookieService;
import io.github.sequelcore.vigil.core.jwt.HmacTokenSigner;
import io.github.sequelcore.vigil.core.jwt.VigilTokenService;
import io.github.sequelcore.vigil.tenant.VigilTenantContext;
import io.github.sequelcore.vigil.tenant.VigilTenantService;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.core.context.SecurityContextHolder;

/** Base class for filter tests with common setup. */
abstract class VigilAuthenticationFilterBaseTest {

  protected static final String SECRET = "01234567890123456789012345678901";

  protected VigilProperties.Jwt jwtConfig;
  protected VigilProperties.Cookie cookieConfig;
  protected VigilTokenService tokenService;
  protected VigilCookieService cookieService;

  @Mock protected VigilBlacklistService blacklistService;
  @Mock protected VigilTenantService tenantService;
  @Mock protected HttpServletRequest request;
  @Mock protected HttpServletResponse response;
  @Mock protected FilterChain filterChain;

  @BeforeEach
  void setUpBase() {
    MockitoAnnotations.openMocks(this);
    jwtConfig =
        new VigilProperties.Jwt(SECRET, Duration.ofMinutes(15), Duration.ofDays(7), null, null, null, null, null);
    cookieConfig =
        new VigilProperties.Cookie(
            true,
            "Lax",
            true,
            Map.of("default", new VigilProperties.CookieProfile("access_token", "refresh_token")));
    tokenService = new VigilTokenService(new HmacTokenSigner(jwtConfig.secret()), jwtConfig);
    cookieService = new VigilCookieService(cookieConfig, jwtConfig);

    // Default: tokens not blacklisted
    when(blacklistService.isBlacklisted(anyString())).thenReturn(false);
    when(blacklistService.isSubjectInvalidated(anyString(), any())).thenReturn(false);
  }

  @AfterEach
  void tearDownBase() {
    SecurityContextHolder.clearContext();
    VigilTenantContext.clear();
  }

  protected String buildExpiredToken(String subject) {
    Instant now = Instant.now();
    return new HmacTokenSigner(jwtConfig.secret())
        .sign(
            Jwts.builder()
                .subject(subject)
                .issuedAt(java.util.Date.from(now.minusSeconds(120)))
                .expiration(java.util.Date.from(now.minusSeconds(30))));
  }

  /** Testable filter subclass that captures callback invocations. */
  protected static class TestableFilter extends VigilAuthenticationFilter {

    boolean expiredTokenCalled;
    boolean blacklistedTokenCalled;
    boolean tenantMismatchCalled;
    boolean invalidTokenCalled;

    TestableFilter(
        VigilTokenService tokenService,
        VigilCookieService cookieService,
        VigilBlacklistService blacklistService,
        VigilTenantService tenantService,
        FilterConfig filterConfig) {
      super(
          tokenService,
          cookieService,
          blacklistService,
          tenantService,
          null,
          null,
          List.of(),
          filterConfig);
    }

    @Override
    protected void onExpiredToken(
        HttpServletRequest request, HttpServletResponse response, String token) {
      this.expiredTokenCalled = true;
      super.onExpiredToken(request, response, token);
    }

    @Override
    protected void onBlacklistedToken(
        HttpServletRequest request, HttpServletResponse response, String token) {
      this.blacklistedTokenCalled = true;
      super.onBlacklistedToken(request, response, token);
    }

    @Override
    protected void onTenantMismatch(
        HttpServletRequest request,
        HttpServletResponse response,
        UUID headerTenant,
        UUID tokenTenant) {
      this.tenantMismatchCalled = true;
      super.onTenantMismatch(request, response, headerTenant, tokenTenant);
    }

    @Override
    protected void onInvalidToken(
        HttpServletRequest request, HttpServletResponse response, String token, JwtException e) {
      this.invalidTokenCalled = true;
      super.onInvalidToken(request, response, token, e);
    }
  }
}
