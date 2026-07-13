package io.github.sequelcore.vigil.integration;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import io.github.sequelcore.vigil.blacklist.VigilBlacklistService;
import io.github.sequelcore.vigil.core.jwt.HmacTokenSigner;
import io.github.sequelcore.vigil.core.jwt.TokenRequest;
import io.github.sequelcore.vigil.core.jwt.VigilTokenService;
import io.github.sequelcore.vigil.integration.testapp.TestApplication;
import io.github.sequelcore.vigil.protection.VigilProtectionService;
import io.jsonwebtoken.Jwts;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    classes = TestApplication.class)
@AutoConfigureTestRestTemplate
@ActiveProfiles("test")
@TestPropertySource(
    properties =
        "spring.config.import=classpath:io/github/sequelcore/vigil/integration/testapp/application-test.yml")
class VigilIntegrationTest {

  @LocalServerPort private int port;

  @Autowired private TestRestTemplate restTemplate;
  @Autowired private VigilTokenService tokenService;
  @Autowired private VigilBlacklistService blacklistService;
  @Autowired private VigilProtectionService protectionService;
  @Autowired private VigilProperties properties;

  @Test
  void autoConfigurationLoadsBeansAndBindsProperties() {
    assertThat(tokenService).isNotNull();
    assertThat(blacklistService).isNotNull();
    assertThat(protectionService).isNotNull();
    assertThat(properties.tenant().enabled()).isTrue();
    assertThat(properties.protection().maxAttempts()).isEqualTo(3);
    assertThat(properties.filter().ignoredPaths()).contains("/actuator/**", "/health");
    assertThat(properties.filter().publicPaths()).contains("/public/**");
  }

  @Test
  void publicPathAllowsAnonymous() {
    ResponseEntity<String> response = restTemplate.getForEntity(url("/public/hello"), String.class);

    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(response.getBody()).isEqualTo("public");
  }

  @Test
  void protectedWithoutTokenReturnsUnauthorized() {
    ResponseEntity<String> response =
        restTemplate.getForEntity(url("/protected/hello"), String.class);

    assertThat(response.getStatusCode()).isIn(HttpStatus.UNAUTHORIZED, HttpStatus.FORBIDDEN);
  }

  @Test
  void authorizationHeaderWithValidTokenReturnsOk() {
    String token = accessToken("auth-user");
    HttpHeaders headers = bearerHeaders(token);

    ResponseEntity<String> response = exchangeGet("/protected/hello", headers);

    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(response.getBody()).isEqualTo("auth-user");
  }

  @Test
  void expiredTokenReturnsUnauthorized() {
    HttpHeaders headers = bearerHeaders(expiredAccessToken());

    ResponseEntity<String> response = exchangeGet("/protected/hello", headers);

    assertThat(response.getStatusCode()).isIn(HttpStatus.UNAUTHORIZED, HttpStatus.FORBIDDEN);
  }

  @Test
  void cookieBasedAuthenticationSucceeds() {
    String token = accessToken("cookie-user");
    HttpHeaders headers = cookieHeaders(token);

    ResponseEntity<String> response = exchangeGet("/protected/hello", headers);

    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(response.getBody()).isEqualTo("cookie-user");
  }

  @Test
  void loginEndpointSetsHttpOnlySecureCookies() {
    ResponseEntity<String> csrf = restTemplate.getForEntity(url("/csrf"), String.class);
    assertThat(csrf.getHeaders().get(HttpHeaders.SET_COOKIE))
        .noneMatch(header -> header.startsWith("JSESSIONID="));
    String csrfCookie =
        csrf.getHeaders().get(HttpHeaders.SET_COOKIE).stream()
            .filter(header -> header.startsWith("XSRF-TOKEN="))
            .findFirst()
            .orElseThrow()
            .split(";", 2)[0];
    HttpHeaders headers = new HttpHeaders();
    headers.add(HttpHeaders.COOKIE, csrfCookie);
    headers.add("X-XSRF-TOKEN", csrf.getBody());

    ResponseEntity<Void> response =
        restTemplate.postForEntity(url("/auth/login"), new HttpEntity<>(headers), Void.class);

    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    List<String> setCookie = response.getHeaders().get(HttpHeaders.SET_COOKIE);
    assertThat(setCookie).isNotNull();
    assertThat(setCookie).anyMatch(header -> header.startsWith("access_token="));
    assertThat(setCookie).anyMatch(header -> header.startsWith("refresh_token="));
    assertThat(setCookie).allMatch(header -> header.contains("HttpOnly"));
    assertThat(setCookie).allMatch(header -> header.contains("Secure"));
    assertThat(setCookie).allMatch(header -> header.contains("SameSite=Lax"));
    assertThat(setCookie).noneMatch(header -> header.startsWith("JSESSIONID="));
  }

  @Test
  void blacklistedTokenIsRejected() {
    String token = accessToken("blocked-user");
    blacklistService.blacklist(token);
    HttpHeaders headers = bearerHeaders(token);

    ResponseEntity<String> response = exchangeGet("/protected/hello", headers);

    assertThat(response.getStatusCode()).isIn(HttpStatus.UNAUTHORIZED, HttpStatus.FORBIDDEN);
  }

  @Test
  void tenantHeaderSetsContextFromHeader() {
    UUID tenantId = UUID.randomUUID();
    HttpHeaders headers = bearerHeaders(accessToken("tenant-user"));
    headers.add("X-Tenant-ID", tenantId.toString());

    ResponseEntity<String> response = exchangeGet("/protected/tenant", headers);

    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(response.getBody()).isEqualTo(tenantId.toString());
  }

  @Test
  void tenantMismatchIsRejected() {
    UUID tokenTenant = UUID.randomUUID();
    UUID headerTenant = UUID.randomUUID();
    String token = accessTokenWithTenant("tenant-mismatch", tokenTenant);
    HttpHeaders headers = bearerHeaders(token);
    headers.add("X-Tenant-ID", headerTenant.toString());

    ResponseEntity<String> response = exchangeGet("/protected/hello", headers);

    assertThat(response.getStatusCode()).isIn(HttpStatus.UNAUTHORIZED, HttpStatus.FORBIDDEN);
  }

  @Test
  void protectionLocksAfterMaxAttempts() {
    String identifier = "user@example.com";
    protectionService.recordFailedAttempt(identifier);
    protectionService.recordFailedAttempt(identifier);
    protectionService.recordFailedAttempt(identifier);

    assertThat(protectionService.isLocked(identifier)).isTrue();
    assertThat(protectionService.getFailedAttempts(identifier))
        .isGreaterThanOrEqualTo(properties.protection().maxAttempts());
  }

  private ResponseEntity<String> exchangeGet(String path, HttpHeaders headers) {
    return restTemplate.exchange(
        url(path), HttpMethod.GET, new HttpEntity<>(headers), String.class);
  }

  private HttpHeaders bearerHeaders(String token) {
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);
    return headers;
  }

  private HttpHeaders cookieHeaders(String token) {
    HttpHeaders headers = new HttpHeaders();
    headers.add(HttpHeaders.COOKIE, "access_token=" + token);
    return headers;
  }

  private String accessToken(String subject) {
    return tokenService.generateAccessToken(
        TokenRequest.builder().subject(subject).claim("role", "USER").build());
  }

  private String accessTokenWithTenant(String subject, UUID tenantId) {
    return tokenService.generateAccessToken(
        TokenRequest.builder()
            .subject(subject)
            .claim("role", "USER")
            .claim("tenantId", tenantId.toString())
            .build());
  }

  private String expiredAccessToken() {
    Instant now = Instant.now();
    return new HmacTokenSigner(properties.jwt().secret())
        .sign(
            Jwts.builder()
                .subject("expired-user")
                .issuedAt(Date.from(now.minusSeconds(120)))
                .expiration(Date.from(now.minusSeconds(60))));
  }

  private String url(String path) {
    return "http://localhost:" + port + path;
  }
}
