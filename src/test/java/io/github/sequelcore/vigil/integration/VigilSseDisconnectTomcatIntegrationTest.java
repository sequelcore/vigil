package io.github.sequelcore.vigil.integration;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.sequelcore.vigil.context.VigilContextPopulator;
import io.github.sequelcore.vigil.core.jwt.TokenRequest;
import io.github.sequelcore.vigil.core.jwt.VigilTokenClaims;
import io.github.sequelcore.vigil.core.jwt.VigilTokenService;
import io.github.sequelcore.vigil.filter.VigilAuthenticationFilter;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.lang.Nullable;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

@SpringBootTest(
    classes = VigilSseDisconnectTomcatIntegrationTest.DisconnectTestApplication.class,
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@TestPropertySource(
    properties =
        "spring.config.import=classpath:io/github/sequelcore/vigil/integration/testapp/application-test.yml")
class VigilSseDisconnectTomcatIntegrationTest {

  @LocalServerPort private int port;
  @Autowired private VigilTokenService tokenService;
  @Autowired private DisconnectProbe probe;

  @BeforeEach
  void resetProbe() {
    probe.reset();
  }

  @Test
  @Timeout(45)
  void clientDisconnectCompletesCommittedSseWithoutSecondarySecurityFailure() throws Exception {
    UUID streamId = UUID.randomUUID();
    String token =
        tokenService.generateAccessToken(
            TokenRequest.builder().subject("disconnect-user").claim("role", "USER").build());

    try (Socket socket = new Socket(InetAddress.getLoopbackAddress(), port)) {
      socket.setSoTimeout((int) Duration.ofSeconds(10).toMillis());
      writeRequest(socket.getOutputStream(), streamId, token);
      String response = readThroughReadyEvent(socket);

      assertThat(response).contains("200").contains("text/event-stream").contains("data:ready");
      assertThat(probe.awaitRegistered(streamId)).isTrue();

      socket.setSoLinger(true, 0);
    }

    IOException disconnect = probe.writeUntilDisconnected(streamId);

    assertThat(disconnect).isNotNull();
    assertThat(probe.awaitReleased(streamId)).isTrue();
    assertThat(probe.error(streamId)).isPresent();
    assertThat(probe.entryPointCount()).isZero();
    assertThat(probe.accessDeniedCount()).isZero();
    assertThat(probe.authenticationCount()).isEqualTo(1);
    assertThat(probe.controllerCount()).isEqualTo(1);
    assertThat(probe.controllerPrincipals()).containsExactly("disconnect-user");
    assertThat(probe.dispatches())
        .anySatisfy(
            dispatch -> {
              assertThat(dispatch.type()).isEqualTo(DispatcherType.ASYNC);
              assertThat(dispatch.principal()).isEqualTo("disconnect-user");
              assertThat(dispatch.committed()).isTrue();
              assertThat(dispatch.hasSession()).isFalse();
            });
    assertThat(
            probe.dispatches().stream()
                .filter(dispatch -> dispatch.type() == DispatcherType.ASYNC)
                .toList())
        .hasSize(1);
    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    assertThat(probe.hasActiveStream(streamId)).isFalse();
  }

  @Test
  @Timeout(45)
  void containerErrorDispatchKeepsAuthenticationWithoutBypassOrRecursion() throws Exception {
    String token =
        tokenService.generateAccessToken(
            TokenRequest.builder().subject("error-user").claim("role", "USER").build());

    try (Socket socket = new Socket(InetAddress.getLoopbackAddress(), port)) {
      socket.setSoTimeout((int) Duration.ofSeconds(10).toMillis());
      writeRequest(socket.getOutputStream(), "/protected/container-error", token);
      readUntilClosed(socket);
    }

    assertThat(probe.awaitErrorDispatch()).isTrue();
    assertThat(probe.entryPointCount()).isZero();
    assertThat(probe.accessDeniedCount()).isZero();
    assertThat(probe.authenticationCount()).isEqualTo(1);
    assertThat(probe.dispatches())
        .anySatisfy(
            dispatch -> {
              assertThat(dispatch.type()).isEqualTo(DispatcherType.ERROR);
              assertThat(dispatch.principal()).isEqualTo("error-user");
              assertThat(dispatch.hasSession()).isFalse();
            });
    assertThat(
            probe.dispatches().stream()
                .filter(dispatch -> dispatch.type() == DispatcherType.ERROR)
                .toList())
        .hasSize(1);
    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
  }

  private void writeRequest(OutputStream output, UUID streamId, String token) throws IOException {
    writeRequest(output, "/protected/disconnect-sse/" + streamId, token);
  }

  private void writeRequest(OutputStream output, String path, String token) throws IOException {
    String request =
        "GET "
            + path
            + " HTTP/1.1\r\nHost: localhost:"
            + port
            + "\r\nAccept: text/event-stream\r\nAuthorization: Bearer "
            + token
            + "\r\nConnection: keep-alive\r\n\r\n";
    output.write(request.getBytes(StandardCharsets.US_ASCII));
    output.flush();
  }

  private void readUntilClosed(Socket socket) throws IOException {
    BufferedInputStream input = new BufferedInputStream(socket.getInputStream());
    input.transferTo(OutputStream.nullOutputStream());
  }

  private String readThroughReadyEvent(Socket socket) throws IOException {
    BufferedInputStream input = new BufferedInputStream(socket.getInputStream());
    StringBuilder response = new StringBuilder();
    while (!response.toString().contains("data:ready")) {
      int next = input.read();
      if (next < 0) {
        break;
      }
      response.append((char) next);
    }
    return response.toString();
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @Import({DisconnectSecurityConfiguration.class, DisconnectSseController.class})
  static class DisconnectTestApplication {}

  @Configuration(proxyBeanMethods = false)
  static class DisconnectSecurityConfiguration {

    @Bean
    DisconnectProbe disconnectProbe() {
      return new DisconnectProbe();
    }

    @Bean
    VigilContextPopulator disconnectAuthenticationProbe(DisconnectProbe probe) {
      return new VigilContextPopulator() {
        @Override
        public void populate(HttpServletRequest request, @Nullable VigilTokenClaims claims) {
          probe.recordAuthentication();
        }

        @Override
        public void clear() {}
      };
    }

    @Bean
    SecurityFilterChain disconnectSecurityFilterChain(
        HttpSecurity http, VigilAuthenticationFilter authenticationFilter, DisconnectProbe probe)
        throws Exception {
      RequestAttributeSecurityContextRepository repository =
          new RequestAttributeSecurityContextRepository();
      authenticationFilter.setSecurityContextRepository(repository);
      http.sessionManagement(
              session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
          .securityContext(context -> context.securityContextRepository(repository))
          .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
          .exceptionHandling(
              exceptions ->
                  exceptions
                      .authenticationEntryPoint(
                          (request, response, exception) -> {
                            probe.recordEntryPoint();
                            if (!response.isCommitted()) {
                              response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                            }
                          })
                      .accessDeniedHandler(
                          (request, response, exception) -> {
                            probe.recordAccessDenied();
                            if (!response.isCommitted()) {
                              response.sendError(HttpServletResponse.SC_FORBIDDEN);
                            }
                          }))
          .addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class)
          .addFilterAfter(new DispatchProbeFilter(probe), AuthorizationFilter.class);
      return http.build();
    }
  }

  @RestController
  static class DisconnectSseController {
    private final DisconnectProbe probe;

    DisconnectSseController(DisconnectProbe probe) {
      this.probe = probe;
    }

    @GetMapping(
        value = "/protected/disconnect-sse/{streamId}",
        produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    SseEmitter connect(@PathVariable UUID streamId, Authentication authentication)
        throws IOException {
      return probe.open(streamId, authentication.getName());
    }

    @GetMapping("/protected/container-error")
    void containerError(HttpServletResponse response) throws IOException {
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }
  }

  static final class DispatchProbeFilter extends GenericFilterBean {
    private final DisconnectProbe probe;

    DispatchProbeFilter(DisconnectProbe probe) {
      this.probe = probe;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException {
      HttpServletRequest httpRequest = (HttpServletRequest) request;
      HttpServletResponse httpResponse = (HttpServletResponse) response;
      Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
      probe.recordDispatch(
          new DispatchObservation(
              httpRequest.getDispatcherType(),
              authentication == null ? null : authentication.getName(),
              httpResponse.isCommitted(),
              httpRequest.getSession(false) != null));
      chain.doFilter(request, response);
    }
  }

  record DispatchObservation(
      DispatcherType type, @Nullable String principal, boolean committed, boolean hasSession) {}

  static final class DisconnectProbe {
    private static final String LARGE_EVENT = "x".repeat(256 * 1024);
    private final Map<UUID, StreamState> streams = new ConcurrentHashMap<>();
    private final List<DispatchObservation> dispatches = new CopyOnWriteArrayList<>();
    private final AtomicInteger entryPoints = new AtomicInteger();
    private final AtomicInteger accessDenied = new AtomicInteger();
    private final AtomicInteger authentications = new AtomicInteger();
    private final AtomicInteger controllers = new AtomicInteger();
    private final List<String> controllerPrincipals = new CopyOnWriteArrayList<>();
    private final Map<UUID, Throwable> terminalErrors = new ConcurrentHashMap<>();

    void reset() {
      streams.clear();
      dispatches.clear();
      entryPoints.set(0);
      accessDenied.set(0);
      authentications.set(0);
      controllers.set(0);
      controllerPrincipals.clear();
      terminalErrors.clear();
    }

    SseEmitter open(UUID id, String principal) throws IOException {
      controllers.incrementAndGet();
      controllerPrincipals.add(principal);
      SseEmitter emitter = new SseEmitter(Duration.ofSeconds(20).toMillis());
      StreamState state = new StreamState(emitter);
      streams.put(id, state);
      emitter.onError(
          error -> {
            terminalErrors.put(id, error);
            state.errored.countDown();
          });
      emitter.onCompletion(
          () -> {
            streams.remove(id, state);
            state.completed.countDown();
          });
      emitter.send(SseEmitter.event().name("ready").data("ready"));
      state.registered.countDown();
      return emitter;
    }

    IOException writeUntilDisconnected(UUID id) throws InterruptedException {
      StreamState state = streams.get(id);
      if (state == null) {
        return null;
      }
      for (int attempt = 0; attempt < 32; attempt++) {
        try {
          state.emitter.send(SseEmitter.event().name("data").data(LARGE_EVENT));
        } catch (IOException exception) {
          return exception;
        }
        TimeUnit.MILLISECONDS.sleep(10);
      }
      return null;
    }

    boolean awaitRegistered(UUID id) throws InterruptedException {
      StreamState state = streams.get(id);
      return state != null && state.registered.await(5, TimeUnit.SECONDS);
    }

    boolean awaitReleased(UUID id) throws InterruptedException {
      StreamState state = streams.get(id);
      if (state == null) {
        return true;
      }
      return state.errored.await(20, TimeUnit.SECONDS)
          && state.completed.await(20, TimeUnit.SECONDS);
    }

    boolean awaitErrorDispatch() throws InterruptedException {
      long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
      while (System.nanoTime() < deadline) {
        if (dispatches.stream().anyMatch(dispatch -> dispatch.type() == DispatcherType.ERROR)) {
          return true;
        }
        TimeUnit.MILLISECONDS.sleep(10);
      }
      return false;
    }

    void recordEntryPoint() {
      entryPoints.incrementAndGet();
    }

    void recordAccessDenied() {
      accessDenied.incrementAndGet();
    }

    void recordAuthentication() {
      authentications.incrementAndGet();
    }

    void recordDispatch(DispatchObservation observation) {
      dispatches.add(observation);
    }

    int entryPointCount() {
      return entryPoints.get();
    }

    int accessDeniedCount() {
      return accessDenied.get();
    }

    int authenticationCount() {
      return authentications.get();
    }

    int controllerCount() {
      return controllers.get();
    }

    List<String> controllerPrincipals() {
      return List.copyOf(controllerPrincipals);
    }

    java.util.Optional<Throwable> error(UUID id) {
      return java.util.Optional.ofNullable(terminalErrors.get(id));
    }

    List<DispatchObservation> dispatches() {
      return List.copyOf(dispatches);
    }

    boolean hasActiveStream(UUID id) {
      return streams.containsKey(id);
    }
  }

  static final class StreamState {
    private final SseEmitter emitter;
    private final CountDownLatch registered = new CountDownLatch(1);
    private final CountDownLatch errored = new CountDownLatch(1);
    private final CountDownLatch completed = new CountDownLatch(1);

    StreamState(SseEmitter emitter) {
      this.emitter = emitter;
    }
  }
}
