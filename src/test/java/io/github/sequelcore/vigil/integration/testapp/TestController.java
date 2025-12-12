package io.github.sequelcore.vigil.integration.testapp;

import io.github.sequelcore.vigil.core.cookie.VigilCookieService;
import io.github.sequelcore.vigil.core.jwt.TokenRequest;
import io.github.sequelcore.vigil.core.jwt.VigilTokenService;
import io.github.sequelcore.vigil.tenant.VigilTenantContext;
import jakarta.servlet.http.HttpServletResponse;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

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
