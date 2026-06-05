package io.github.sequelcore.vigil.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import io.github.sequelcore.vigil.context.VigilContextPopulator;
import io.github.sequelcore.vigil.core.cookie.VigilCookieService;
import io.github.sequelcore.vigil.core.jwt.TokenRequest;
import io.github.sequelcore.vigil.tenant.VigilTenantContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.core.context.SecurityContextHolder;

class VigilAuthenticationFilterTest extends VigilAuthenticationFilterBaseTest {

  @Nested
  @DisplayName("Ignored Paths")
  class IgnoredPathTests {

    @Test
    @DisplayName("Ignored path skips all processing")
    void skipsAllProcessing() throws ServletException, IOException {
      when(tenantService.extractTenantId(request))
          .thenReturn(java.util.Optional.of(UUID.randomUUID()));
      TestableFilter filter =
          new TestableFilter(
              tokenService,
              cookieService,
              blacklistService,
              tenantService,
              new FilterConfig(List.of("/actuator/**"), List.of()));
      when(request.getRequestURI()).thenReturn("/actuator/health");
      String token =
          tokenService.generateAccessToken(TokenRequest.builder().subject("ignored").build());
      when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

      filter.doFilterInternal(request, response, filterChain);

      verify(tenantService, never()).extractTenantId(any());
      verify(tenantService, never()).setCurrentTenant(any());
      assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
      verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    @DisplayName("Ignored path skips context populators")
    void skipsContextPopulators() throws ServletException, IOException {
      VigilContextPopulator mockPopulator = Mockito.mock(VigilContextPopulator.class);
      when(mockPopulator.getOrder()).thenReturn(0);
      VigilAuthenticationFilter filter =
          new VigilAuthenticationFilter(
              tokenService,
              cookieService,
              blacklistService,
              null,
              null,
              null,
              List.of(mockPopulator),
              new FilterConfig(List.of("/ignored/**"), List.of()));
      when(request.getRequestURI()).thenReturn("/ignored/path");

      filter.doFilterInternal(request, response, filterChain);

      verify(mockPopulator, never()).populate(any(), any());
      verify(mockPopulator, never()).clear();
    }
  }

  @Nested
  @DisplayName("Public Paths")
  class PublicPathTests {

    @Test
    @DisplayName("Without credentials permits anonymous")
    void permitsAnonymous() throws ServletException, IOException {
      TestableFilter filter =
          new TestableFilter(
              tokenService,
              cookieService,
              blacklistService,
              null,
              new FilterConfig(List.of("/public/**")));
      when(request.getRequestURI()).thenReturn("/public/health");

      filter.doFilterInternal(request, response, filterChain);

      assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
      verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    @DisplayName("With valid token authenticates user")
    void authenticatesWithValidToken() throws ServletException, IOException {
      TestableFilter filter =
          new TestableFilter(
              tokenService,
              cookieService,
              blacklistService,
              null,
              new FilterConfig(List.of("/public/**")));
      when(request.getRequestURI()).thenReturn("/public/profile");
      String token =
          tokenService.generateAccessToken(
              TokenRequest.builder().subject("alice").claim("role", "USER").build());
      when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

      filter.doFilterInternal(request, response, filterChain);

      assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
      assertThat(SecurityContextHolder.getContext().getAuthentication().getName())
          .isEqualTo("alice");
    }

    @Test
    @DisplayName("With invalid token permits anonymous")
    void permitsAnonymousOnInvalidToken() throws ServletException, IOException {
      TestableFilter filter =
          new TestableFilter(
              tokenService,
              cookieService,
              blacklistService,
              null,
              new FilterConfig(List.of("/public/**")));
      when(request.getRequestURI()).thenReturn("/public/data");
      when(request.getHeader("Authorization")).thenReturn("Bearer invalid.token.here");

      filter.doFilterInternal(request, response, filterChain);

      assertThat(filter.invalidTokenCalled).isTrue();
      assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("With expired token permits anonymous")
    void permitsAnonymousOnExpiredToken() throws ServletException, IOException {
      TestableFilter filter =
          new TestableFilter(
              tokenService,
              cookieService,
              blacklistService,
              null,
              new FilterConfig(List.of("/public/**")));
      when(request.getRequestURI()).thenReturn("/public/data");
      when(request.getHeader("Authorization")).thenReturn("Bearer " + buildExpiredToken("user"));

      filter.doFilterInternal(request, response, filterChain);

      assertThat(filter.expiredTokenCalled).isTrue();
      assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("With tenant header sets context")
    void setsTenantContext() throws ServletException, IOException {
      UUID tenantId = UUID.randomUUID();
      when(tenantService.extractTenantId(request)).thenReturn(java.util.Optional.of(tenantId));
      Mockito.doAnswer(
              inv -> {
                VigilTenantContext.setTenant(inv.getArgument(0));
                return null;
              })
          .when(tenantService)
          .setCurrentTenant(any());
      java.util.concurrent.atomic.AtomicReference<UUID> captured =
          new java.util.concurrent.atomic.AtomicReference<>();
      Mockito.doAnswer(
              inv -> {
                captured.set(VigilTenantContext.getTenant().orElse(null));
                return null;
              })
          .when(filterChain)
          .doFilter(any(), any());
      TestableFilter filter =
          new TestableFilter(
              tokenService,
              cookieService,
              blacklistService,
              tenantService,
              new FilterConfig(List.of("/public/**")));
      when(request.getRequestURI()).thenReturn("/public/login");

      filter.doFilterInternal(request, response, filterChain);

      assertThat(captured.get()).isEqualTo(tenantId);
    }

    @Test
    @DisplayName("Without tenant header has empty context")
    void emptyTenantContext() throws ServletException, IOException {
      when(tenantService.extractTenantId(request)).thenReturn(java.util.Optional.empty());
      TestableFilter filter =
          new TestableFilter(
              tokenService,
              cookieService,
              blacklistService,
              tenantService,
              new FilterConfig(List.of("/public/**")));
      when(request.getRequestURI()).thenReturn("/public/health");

      filter.doFilterInternal(request, response, filterChain);

      verify(tenantService, never()).setCurrentTenant(any());
      assertThat(VigilTenantContext.getTenant()).isEmpty();
    }

    @Test
    @DisplayName("Calls context populators with null claims when anonymous")
    void callsPopulatorsWithNullClaims() throws ServletException, IOException {
      VigilContextPopulator mockPopulator = Mockito.mock(VigilContextPopulator.class);
      when(mockPopulator.getOrder()).thenReturn(0);
      VigilAuthenticationFilter filter =
          new VigilAuthenticationFilter(
              tokenService,
              cookieService,
              blacklistService,
              null,
              null,
              null,
              List.of(mockPopulator),
              new FilterConfig(List.of("/public/**")));
      when(request.getRequestURI()).thenReturn("/public/login");

      filter.doFilterInternal(request, response, filterChain);

      verify(mockPopulator, times(1)).populate(request, null);
      verify(mockPopulator, times(1)).clear();
    }
  }

  @Nested
  @DisplayName("Protected Paths")
  class ProtectedPathTests {

    @Test
    @DisplayName("Extract token from Authorization header")
    void extractFromHeader() throws ServletException, IOException {
      TestableFilter filter =
          new TestableFilter(
              tokenService, cookieService, blacklistService, null, new FilterConfig(List.of()));
      when(request.getRequestURI()).thenReturn("/api/data");
      String token =
          tokenService.generateAccessToken(
              TokenRequest.builder().subject("alice").claim("roles", List.of("ADMIN")).build());
      when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

      filter.doFilterInternal(request, response, filterChain);

      assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
      assertThat(SecurityContextHolder.getContext().getAuthentication().getName())
          .isEqualTo("alice");
      assertThat(SecurityContextHolder.getContext().getAuthentication().getAuthorities())
          .extracting("authority")
          .containsExactly("ROLE_ADMIN");
    }

    @Test
    @DisplayName("Extract token from cookie")
    void extractFromCookie() throws ServletException, IOException {
      TestableFilter filter =
          new TestableFilter(
              tokenService, cookieService, blacklistService, null, new FilterConfig(List.of()));
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
    @DisplayName("Handle expired token")
    void handleExpiredToken() throws ServletException, IOException {
      TestableFilter filter =
          new TestableFilter(
              tokenService, cookieService, blacklistService, null, new FilterConfig(List.of()));
      when(request.getRequestURI()).thenReturn("/api/data");
      when(request.getHeader("Authorization")).thenReturn("Bearer " + buildExpiredToken("user"));

      filter.doFilterInternal(request, response, filterChain);

      assertThat(filter.expiredTokenCalled).isTrue();
      assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("Handle blacklisted token")
    void handleBlacklistedToken() throws ServletException, IOException {
      when(blacklistService.isBlacklisted("black-token")).thenReturn(true);
      TestableFilter filter =
          new TestableFilter(
              tokenService, cookieService, blacklistService, null, new FilterConfig(List.of()));
      when(request.getRequestURI()).thenReturn("/api/data");
      when(request.getHeader("Authorization")).thenReturn("Bearer black-token");

      filter.doFilterInternal(request, response, filterChain);

      assertThat(filter.blacklistedTokenCalled).isTrue();
      assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("Invalid token exposes sanitized error description")
    void invalidTokenExposesSanitizedDescription() throws ServletException, IOException {
      TestableFilter filter =
          new TestableFilter(
              tokenService, cookieService, blacklistService, null, new FilterConfig(List.of()));
      when(request.getRequestURI()).thenReturn("/api/data");
      when(request.getHeader("Authorization")).thenReturn("Bearer invalid.token.here");

      filter.doFilterInternal(request, response, filterChain);

      assertThat(filter.invalidTokenCalled).isTrue();
      verify(request).setAttribute("vigil.error.code", "invalid_token");
      verify(request).setAttribute("vigil.error.description", "Invalid access token");
      assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("Handle tenant mismatch")
    void handleTenantMismatch() throws ServletException, IOException {
      UUID headerTenant = UUID.randomUUID();
      UUID tokenTenant = UUID.randomUUID();
      TestableFilter filter =
          new TestableFilter(
              tokenService,
              cookieService,
              blacklistService,
              tenantService,
              new FilterConfig(List.of()));
      when(request.getRequestURI()).thenReturn("/api/data");
      String token =
          tokenService.generateAccessToken(
              TokenRequest.builder()
                  .subject("tenant-user")
                  .claim("tenantId", tokenTenant.toString())
                  .build());
      when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
      when(tenantService.extractTenantId(request)).thenReturn(java.util.Optional.of(headerTenant));
      Mockito.doAnswer(
              inv -> {
                VigilTenantContext.setTenant(inv.getArgument(0));
                return null;
              })
          .when(tenantService)
          .setCurrentTenant(any());

      filter.doFilterInternal(request, response, filterChain);

      assertThat(filter.tenantMismatchCalled).isTrue();
      assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }
  }

  @Nested
  @DisplayName("Profile Paths")
  class ProfilePathTests {

    @Test
    @DisplayName("Resolve customer cookie for box paths")
    void resolveCustomerCookie() throws ServletException, IOException {
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
      Map<String, List<String>> profilePaths =
          Map.of("staff", List.of("/api/console/**"), "customer", List.of("/api/box/**"));
      TestableFilter filter =
          new TestableFilter(
              tokenService,
              multiCookieService,
              blacklistService,
              null,
              new FilterConfig(List.of(), List.of(), profilePaths));
      when(request.getRequestURI()).thenReturn("/api/box/orders");
      when(request.getHeader("Authorization")).thenReturn(null);
      String customerToken =
          tokenService.generateAccessToken(
              TokenRequest.builder().subject("customer-user").claim("role", "CUSTOMER").build());
      when(request.getCookies())
          .thenReturn(new Cookie[] {new Cookie("customer_token", customerToken)});

      filter.doFilterInternal(request, response, filterChain);

      assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
      assertThat(SecurityContextHolder.getContext().getAuthentication().getName())
          .isEqualTo("customer-user");
    }

    @Test
    @DisplayName("Resolve staff cookie for console paths")
    void resolveStaffCookie() throws ServletException, IOException {
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
      Map<String, List<String>> profilePaths =
          Map.of("staff", List.of("/api/console/**"), "customer", List.of("/api/box/**"));
      TestableFilter filter =
          new TestableFilter(
              tokenService,
              multiCookieService,
              blacklistService,
              null,
              new FilterConfig(List.of(), List.of(), profilePaths));
      when(request.getRequestURI()).thenReturn("/api/console/dashboard");
      when(request.getHeader("Authorization")).thenReturn(null);
      String staffToken =
          tokenService.generateAccessToken(
              TokenRequest.builder().subject("staff-user").claim("role", "STAFF").build());
      when(request.getCookies()).thenReturn(new Cookie[] {new Cookie("staff_token", staffToken)});

      filter.doFilterInternal(request, response, filterChain);

      assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
      assertThat(SecurityContextHolder.getContext().getAuthentication().getName())
          .isEqualTo("staff-user");
    }

    @Test
    @DisplayName("Use default profile when no mapping")
    void useDefaultProfile() throws ServletException, IOException {
      VigilProperties.Cookie singleProfileConfig =
          new VigilProperties.Cookie(
              true,
              "Lax",
              true,
              Map.of(
                  "default", new VigilProperties.CookieProfile("access_token", "refresh_token")));
      VigilCookieService singleCookieService =
          new VigilCookieService(singleProfileConfig, jwtConfig);
      TestableFilter filter =
          new TestableFilter(
              tokenService,
              singleCookieService,
              blacklistService,
              null,
              new FilterConfig(List.of(), List.of(), Map.of()));
      when(request.getRequestURI()).thenReturn("/api/other");
      when(request.getHeader("Authorization")).thenReturn(null);
      String token =
          tokenService.generateAccessToken(TokenRequest.builder().subject("default-user").build());
      when(request.getCookies()).thenReturn(new Cookie[] {new Cookie("access_token", token)});

      filter.doFilterInternal(request, response, filterChain);

      assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
      assertThat(SecurityContextHolder.getContext().getAuthentication().getName())
          .isEqualTo("default-user");
    }
  }
}
