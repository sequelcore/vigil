package io.github.sequelcore.vigil.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import io.github.sequelcore.vigil.blacklist.VigilBlacklistService;
import io.github.sequelcore.vigil.core.cookie.VigilCookieService;
import io.github.sequelcore.vigil.core.jwt.TokenRequest;
import io.github.sequelcore.vigil.core.jwt.VigilTokenService;
import io.github.sequelcore.vigil.tenant.VigilTenantContext;
import io.github.sequelcore.vigil.tenant.VigilTenantService;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.core.context.SecurityContextHolder;

class VigilAuthenticationFilterTest {

  private static final String SECRET = "01234567890123456789012345678901";

  private VigilProperties.Jwt jwtConfig;
  private VigilProperties.Cookie cookieConfig;
  private VigilTokenService tokenService;
  private VigilCookieService cookieService;

  @Mock private VigilBlacklistService blacklistService;
  @Mock private VigilTenantService tenantService;
  @Mock private HttpServletRequest request;
  @Mock private HttpServletResponse response;
  @Mock private FilterChain filterChain;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
    jwtConfig =
        new VigilProperties.Jwt(SECRET, Duration.ofMinutes(15), Duration.ofDays(7), null, null);
    cookieConfig =
        new VigilProperties.Cookie(
            true,
            "Lax",
            true,
            Map.of("default", new VigilProperties.CookieProfile("access_token", "refresh_token")));
    tokenService = new VigilTokenService(jwtConfig);
    cookieService = new VigilCookieService(cookieConfig, jwtConfig);

    // Default: tokens not blacklisted
    when(blacklistService.isBlacklisted(anyString())).thenReturn(false);
    when(blacklistService.isSubjectInvalidated(anyString(), any())).thenReturn(false);
  }

  @AfterEach
  void tearDown() {
    SecurityContextHolder.clearContext();
    VigilTenantContext.clear();
  }

  @Test
  @DisplayName("Skip public paths without authentication")
  void skipPublicPaths() throws ServletException, IOException {
    TestableFilter filter =
        new TestableFilter(
            tokenService, cookieService, blacklistService, null, List.of("/public/**"));
    when(request.getRequestURI()).thenReturn("/public/health");

    filter.doFilterInternal(request, response, filterChain);

    verify(filterChain, times(1)).doFilter(request, response);
    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
  }

  @Test
  @DisplayName("Extract token from Authorization header and authenticate")
  void extractFromAuthorizationHeader() throws ServletException, IOException {
    TestableFilter filter =
        new TestableFilter(tokenService, cookieService, blacklistService, null, List.of());
    when(request.getRequestURI()).thenReturn("/api/data");
    String token =
        tokenService.generateAccessToken(
            TokenRequest.builder().subject("alice").claim("roles", List.of("ADMIN")).build());
    when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

    filter.doFilterInternal(request, response, filterChain);

    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
    assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo("alice");
    assertThat(SecurityContextHolder.getContext().getAuthentication().getAuthorities())
        .extracting("authority")
        .containsExactly("ROLE_ADMIN");
    verify(filterChain, times(1)).doFilter(request, response);
  }

  @Test
  @DisplayName("Extract token from cookie when Authorization header missing")
  void extractFromCookie() throws ServletException, IOException {
    TestableFilter filter =
        new TestableFilter(tokenService, cookieService, blacklistService, null, List.of());
    when(request.getRequestURI()).thenReturn("/api/data");
    String token =
        tokenService.generateAccessToken(
            TokenRequest.builder().subject("cookie-user").claim("role", "USER").build());
    when(request.getHeader("Authorization")).thenReturn(null);
    when(request.getCookies()).thenReturn(new Cookie[] {new Cookie("access_token", token)});

    filter.doFilterInternal(request, response, filterChain);

    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
    assertThat(SecurityContextHolder.getContext().getAuthentication().getName())
        .isEqualTo("cookie-user");
  }

  @Test
  @DisplayName("Handle expired token via callback and skip authentication")
  void handleExpiredToken() throws ServletException, IOException {
    TestableFilter filter =
        new TestableFilter(tokenService, cookieService, blacklistService, null, List.of());
    when(request.getRequestURI()).thenReturn("/api/data");
    String token = buildExpiredToken("expired-user");
    when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

    filter.doFilterInternal(request, response, filterChain);

    assertThat(filter.expiredTokenCalled).isTrue();
    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    verify(filterChain, times(1)).doFilter(request, response);
  }

  @Test
  @DisplayName("Handle blacklisted token")
  void handleBlacklistedToken() throws ServletException, IOException {
    when(blacklistService.isBlacklisted("black-token")).thenReturn(true);
    TestableFilter filter =
        new TestableFilter(tokenService, cookieService, blacklistService, null, List.of());
    when(request.getRequestURI()).thenReturn("/api/data");
    when(request.getHeader("Authorization")).thenReturn("Bearer black-token");

    filter.doFilterInternal(request, response, filterChain);

    assertThat(filter.blacklistedTokenCalled).isTrue();
    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    verify(blacklistService, times(1)).isBlacklisted("black-token");
  }

  @Test
  @DisplayName("Handle tenant mismatch between header and token")
  void handleTenantMismatch() throws ServletException, IOException {
    UUID headerTenant = UUID.randomUUID();
    UUID tokenTenant = UUID.randomUUID();
    TestableFilter filter =
        new TestableFilter(tokenService, cookieService, blacklistService, tenantService, List.of());
    when(request.getRequestURI()).thenReturn("/api/data");
    String token =
        tokenService.generateAccessToken(
            TokenRequest.builder()
                .subject("tenant-user")
                .claim("tenantId", tokenTenant.toString())
                .build());
    when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
    when(tenantService.extractTenantId(request)).thenReturn(java.util.Optional.of(headerTenant));

    filter.doFilterInternal(request, response, filterChain);

    assertThat(filter.tenantMismatchCalled).isTrue();
    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    verify(tenantService, never()).setCurrentTenant(any());
  }

  @Test
  @DisplayName("Extract token from second profile when checkAllProfiles is enabled")
  void extractFromSecondProfileWhenCheckAllProfiles() throws ServletException, IOException {
    // Set up multi-profile cookie config
    VigilProperties.Cookie multiProfileConfig =
        new VigilProperties.Cookie(
            true,
            "Lax",
            true,
            Map.of(
                "staff", new VigilProperties.CookieProfile("staff_token", "staff_refresh"),
                "customer",
                    new VigilProperties.CookieProfile("customer_token", "customer_refresh")));
    VigilCookieService multiCookieService = new VigilCookieService(multiProfileConfig, jwtConfig);

    TestableFilter filter =
        new TestableFilter(
            tokenService,
            multiCookieService,
            blacklistService,
            null,
            List.of(),
            true); // checkAllProfiles enabled
    when(request.getRequestURI()).thenReturn("/api/data");
    when(request.getHeader("Authorization")).thenReturn(null);

    // Token is in 'customer' profile cookie, not 'staff'
    String token =
        tokenService.generateAccessToken(
            TokenRequest.builder().subject("customer-user").claim("role", "CUSTOMER").build());
    when(request.getCookies()).thenReturn(new Cookie[] {new Cookie("customer_token", token)});

    filter.doFilterInternal(request, response, filterChain);

    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
    assertThat(SecurityContextHolder.getContext().getAuthentication().getName())
        .isEqualTo("customer-user");
  }

  @Test
  @DisplayName("Prefer first profile token when checkAllProfiles finds multiple")
  void preferFirstProfileWhenCheckAllProfiles() throws ServletException, IOException {
    VigilProperties.Cookie multiProfileConfig =
        new VigilProperties.Cookie(
            true,
            "Lax",
            true,
            Map.of(
                "staff", new VigilProperties.CookieProfile("staff_token", "staff_refresh"),
                "customer",
                    new VigilProperties.CookieProfile("customer_token", "customer_refresh")));
    VigilCookieService multiCookieService = new VigilCookieService(multiProfileConfig, jwtConfig);

    TestableFilter filter =
        new TestableFilter(
            tokenService, multiCookieService, blacklistService, null, List.of(), true);
    when(request.getRequestURI()).thenReturn("/api/data");
    when(request.getHeader("Authorization")).thenReturn(null);

    String staffToken =
        tokenService.generateAccessToken(
            TokenRequest.builder().subject("staff-user").claim("role", "STAFF").build());
    String customerToken =
        tokenService.generateAccessToken(
            TokenRequest.builder().subject("customer-user").claim("role", "CUSTOMER").build());
    when(request.getCookies())
        .thenReturn(
            new Cookie[] {
              new Cookie("staff_token", staffToken), new Cookie("customer_token", customerToken)
            });

    filter.doFilterInternal(request, response, filterChain);

    // Should authenticate with first found token
    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
  }

  @Test
  @DisplayName("Use only default profile when checkAllProfiles is disabled")
  void useDefaultProfileWhenCheckAllProfilesDisabled() throws ServletException, IOException {
    // Use only default profile - token in different cookie should not be found
    VigilProperties.Cookie singleProfileConfig =
        new VigilProperties.Cookie(
            true,
            "Lax",
            true,
            Map.of("default", new VigilProperties.CookieProfile("access_token", "refresh_token")));
    VigilCookieService singleCookieService = new VigilCookieService(singleProfileConfig, jwtConfig);

    TestableFilter filter =
        new TestableFilter(
            tokenService, singleCookieService, blacklistService, null, List.of(), false);
    when(request.getRequestURI()).thenReturn("/api/data");
    when(request.getHeader("Authorization")).thenReturn(null);

    // Token in a different cookie name (not access_token)
    String token =
        tokenService.generateAccessToken(TokenRequest.builder().subject("other-user").build());
    when(request.getCookies()).thenReturn(new Cookie[] {new Cookie("other_token", token)});

    filter.doFilterInternal(request, response, filterChain);

    // Should NOT authenticate because other_token is not the configured cookie name
    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
  }

  private String buildExpiredToken(String subject) {
    Instant now = Instant.now();
    return Jwts.builder()
        .subject(subject)
        .issuedAt(java.util.Date.from(now.minusSeconds(120)))
        .expiration(java.util.Date.from(now.minusSeconds(30)))
        .signWith(tokenService.getSigningKey())
        .compact();
  }

  private static class TestableFilter extends VigilAuthenticationFilter {

    boolean expiredTokenCalled;
    boolean blacklistedTokenCalled;
    boolean tenantMismatchCalled;

    TestableFilter(
        VigilTokenService tokenService,
        VigilCookieService cookieService,
        VigilBlacklistService blacklistService,
        VigilTenantService tenantService,
        java.util.List<String> publicPaths) {
      super(tokenService, cookieService, blacklistService, tenantService, publicPaths);
    }

    TestableFilter(
        VigilTokenService tokenService,
        VigilCookieService cookieService,
        VigilBlacklistService blacklistService,
        VigilTenantService tenantService,
        java.util.List<String> publicPaths,
        boolean checkAllProfiles) {
      super(
          tokenService,
          cookieService,
          blacklistService,
          tenantService,
          null,
          null,
          List.of(),
          new FilterConfig(publicPaths, checkAllProfiles));
    }

    @Override
    protected void onExpiredToken(
        HttpServletRequest request, HttpServletResponse response, String token) {
      this.expiredTokenCalled = true;
    }

    @Override
    protected void onBlacklistedToken(
        HttpServletRequest request, HttpServletResponse response, String token) {
      this.blacklistedTokenCalled = true;
    }

    @Override
    protected void onTenantMismatch(
        HttpServletRequest request,
        HttpServletResponse response,
        UUID headerTenant,
        UUID tokenTenant) {
      this.tenantMismatchCalled = true;
    }
  }
}
