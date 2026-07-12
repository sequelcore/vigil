package io.github.sequelcore.vigil.integration.testapp;

import io.github.sequelcore.vigil.core.cookie.VigilCookieService;
import io.github.sequelcore.vigil.core.jwt.TokenRequest;
import io.github.sequelcore.vigil.core.jwt.VigilTokenService;
import io.github.sequelcore.vigil.tenant.VigilTenantContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.async.DeferredResult;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyEmitter;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

@RestController
@RequiredArgsConstructor
public class TestController {

  private final VigilTokenService tokenService;
  private final VigilCookieService cookieService;

  @GetMapping("/public/hello")
  public String publicHello() {
    return "public";
  }

  @GetMapping("/health")
  public String health() {
    return "ok";
  }

  @GetMapping("/protected/hello")
  public String protectedHello(Authentication authentication) {
    return authentication.getName();
  }

  @GetMapping("/protected/deferred")
  public DeferredResult<String> protectedDeferred(Authentication authentication) {
    DeferredResult<String> result = new DeferredResult<>();
    result.setResult(authentication.getName());
    return result;
  }

  @GetMapping("/protected/emitter")
  public ResponseBodyEmitter protectedEmitter(Authentication authentication) throws IOException {
    ResponseBodyEmitter emitter = new ResponseBodyEmitter();
    emitter.send(authentication.getName());
    emitter.complete();
    return emitter;
  }

  @GetMapping(value = "/protected/sse", produces = "text/event-stream")
  public SseEmitter protectedSse(Authentication authentication) throws IOException {
    SseEmitter emitter = new SseEmitter();
    emitter.send(SseEmitter.event().data(authentication.getName()));
    emitter.complete();
    return emitter;
  }

  @GetMapping("/protected/streaming")
  public StreamingResponseBody protectedStreaming(Authentication authentication) {
    String principal = authentication.getName();
    return output -> output.write(principal.getBytes(StandardCharsets.UTF_8));
  }

  @GetMapping("/protected/admin/deferred")
  public DeferredResult<String> protectedAdminDeferred(Authentication authentication) {
    DeferredResult<String> result = new DeferredResult<>();
    result.setResult(authentication.getName());
    return result;
  }

  @GetMapping("/protected/session-state")
  public String sessionState(HttpServletRequest request) {
    return Boolean.toString(request.getSession(false) != null);
  }

  @GetMapping("/protected/tenant")
  public ResponseEntity<String> tenant() {
    return VigilTenantContext.getTenant()
        .map(UUID::toString)
        .map(ResponseEntity::ok)
        .orElseGet(() -> ResponseEntity.noContent().build());
  }

  @PostMapping("/auth/login")
  public ResponseEntity<Void> login(HttpServletResponse response) {
    String accessToken =
        tokenService.generateAccessToken(
            TokenRequest.builder().subject("test-user").claim("role", "USER").build());
    String refreshToken = tokenService.generateRefreshToken("test-user");
    cookieService.setAccessTokenCookie(response, accessToken);
    cookieService.setRefreshTokenCookie(response, refreshToken);
    return ResponseEntity.ok().build();
  }
}
