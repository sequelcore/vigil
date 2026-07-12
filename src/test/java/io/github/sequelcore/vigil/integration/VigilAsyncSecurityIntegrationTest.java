package io.github.sequelcore.vigil.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import io.github.sequelcore.vigil.context.VigilContextPopulator;
import io.github.sequelcore.vigil.core.jwt.HmacTokenSigner;
import io.github.sequelcore.vigil.core.jwt.TokenRequest;
import io.github.sequelcore.vigil.core.jwt.VigilTokenClaims;
import io.github.sequelcore.vigil.core.jwt.VigilTokenService;
import io.github.sequelcore.vigil.integration.testapp.TestApplication;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.Nullable;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@SpringBootTest(classes = TestApplication.class)
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestPropertySource(
    properties =
        "spring.config.import=classpath:io/github/sequelcore/vigil/integration/testapp/application-test.yml")
@Import(VigilAsyncSecurityIntegrationTest.ProbeConfiguration.class)
class VigilAsyncSecurityIntegrationTest {

  @Autowired private MockMvc mvc;
  @Autowired private VigilTokenService tokenService;
  @Autowired private AuthenticationProbe authenticationProbe;
  @Autowired private VigilProperties properties;

  @BeforeEach
  void resetProbe() {
    authenticationProbe.reset();
  }

  @Test
  void authenticatedDeferredResultRetainsAuthenticationAcrossAsyncDispatch() throws Exception {
    String token =
        tokenService.generateAccessToken(
            TokenRequest.builder().subject("async-user").claim("role", "USER").build());

    MvcResult initial =
        mvc.perform(get("/protected/deferred").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
            .andExpect(request().asyncStarted())
            .andReturn();
    assertThat(initial.getRequest().getSession(false)).isNull();

    MvcResult completed =
        mvc.perform(asyncDispatch(initial)).andExpect(status().isOk()).andReturn();
    assertThat(completed.getRequest().getSession(false)).isNull();
    assertThat(authenticationProbe.populationCount()).isEqualTo(1);
    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
  }

  @Test
  void authenticatedStreamingTypesRetainAuthenticationWithoutReauthentication() throws Exception {
    for (String path :
        new String[] {"/protected/emitter", "/protected/sse", "/protected/streaming"}) {
      authenticationProbe.reset();
      MvcResult initial =
          mvc.perform(authenticatedGet(path, "stream-user"))
              .andExpect(request().asyncStarted())
              .andReturn();
      mvc.perform(asyncDispatch(initial)).andExpect(status().isOk());
      assertThat(authenticationProbe.populationCount()).isEqualTo(1);
    }
  }

  @Test
  void fabricatedAsyncAndErrorDispatchesFailClosed() throws Exception {
    mvc.perform(
            get("/protected/deferred")
                .with(
                    request -> {
                      request.setDispatcherType(DispatcherType.ASYNC);
                      return request;
                    }))
        .andExpect(status().isForbidden());
    mvc.perform(
            get("/protected/deferred")
                .with(
                    request -> {
                      request.setDispatcherType(DispatcherType.ERROR);
                      return request;
                    }))
        .andExpect(status().isForbidden());
  }

  @Test
  void statelessAsyncSupportDoesNotCreateOrReuseHttpSession() throws Exception {
    mvc.perform(authenticatedGet("/protected/session-state", "stateless-user"))
        .andExpect(status().isOk())
        .andExpect(content().string("false"));
    mvc.perform(get("/protected/session-state")).andExpect(status().isForbidden());
  }

  @Test
  void authorizationRulesApplyBeforeAndDuringAsyncDispatch() throws Exception {
    mvc.perform(authenticatedGet("/protected/admin/deferred", "ordinary-user", "USER"))
        .andExpect(status().isForbidden())
        .andExpect(request().asyncNotStarted());

    MvcResult initial =
        mvc.perform(authenticatedGet("/protected/admin/deferred", "admin-user", "ADMIN"))
            .andExpect(request().asyncStarted())
            .andReturn();
    mvc.perform(asyncDispatch(initial))
        .andExpect(status().isOk())
        .andExpect(content().string("admin-user"));
  }

  @Test
  void invalidAndExpiredTokensAreRejectedBeforeAsyncStarts() throws Exception {
    for (String token : List.of("not-a-valid-jwt", expiredToken())) {
      mvc.perform(get("/protected/deferred").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
          .andExpect(status().isForbidden())
          .andExpect(request().asyncNotStarted());
    }
  }

  @Test
  void concurrentAsyncRequestsKeepPrincipalsIsolatedAndClearThreadLocals() throws Exception {
    List<Callable<Void>> requests = new ArrayList<>();
    for (int index = 0; index < 12; index++) {
      String subject = "concurrent-user-" + index;
      requests.add(
          () -> {
            MvcResult initial =
                mvc.perform(authenticatedGet("/protected/deferred", subject))
                    .andExpect(request().asyncStarted())
                    .andReturn();
            mvc.perform(asyncDispatch(initial))
                .andExpect(status().isOk())
                .andExpect(content().string(subject));
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
            return null;
          });
    }

    try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
      for (var result : executor.invokeAll(requests)) {
        result.get();
      }
    }
    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
  }

  private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder
      authenticatedGet(String path, String subject) {
    return authenticatedGet(path, subject, "USER");
  }

  private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder
      authenticatedGet(String path, String subject, String role) {
    String token =
        tokenService.generateAccessToken(
            TokenRequest.builder().subject(subject).claim("role", role).build());
    return get(path).header(HttpHeaders.AUTHORIZATION, "Bearer " + token);
  }

  private String expiredToken() {
    Instant now = Instant.now();
    return new HmacTokenSigner(properties.jwt().secret())
        .sign(
            Jwts.builder()
                .subject("expired-async-user")
                .issuedAt(Date.from(now.minusSeconds(120)))
                .expiration(Date.from(now.minusSeconds(60))));
  }

  @TestConfiguration
  static class ProbeConfiguration {
    @Bean
    AuthenticationProbe authenticationProbe() {
      return new AuthenticationProbe();
    }

    @Bean
    VigilContextPopulator probeContextPopulator(AuthenticationProbe probe) {
      return new VigilContextPopulator() {
        @Override
        public void populate(HttpServletRequest request, @Nullable VigilTokenClaims claims) {
          probe.recordPopulation();
        }

        @Override
        public void clear() {}
      };
    }
  }

  static final class AuthenticationProbe {
    private final AtomicInteger populations = new AtomicInteger();

    void recordPopulation() {
      populations.incrementAndGet();
    }

    int populationCount() {
      return populations.get();
    }

    void reset() {
      populations.set(0);
    }
  }
}
