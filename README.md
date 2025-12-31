# Vigil

Opinionated JWT authentication for Spring Boot. Security by default, not by configuration.

[![Maven Central](https://img.shields.io/maven-central/v/io.github.sequelcore/vigil-spring-boot-starter.svg)](https://central.sonatype.com/artifact/io.github.sequelcore/vigil-spring-boot-starter)
[![Java 21](https://img.shields.io/badge/Java-21-orange.svg)](https://openjdk.org/projects/jdk/21/)
[![Spring Boot 3.5](https://img.shields.io/badge/Spring%20Boot-3.5-green.svg)](https://spring.io/projects/spring-boot)

## Install

```kotlin
implementation("io.github.sequelcore:vigil-spring-boot-starter:2.0.0")
```

## Configure

```yaml
vigil:
  jwt:
    secret: ${JWT_SECRET}
  cookie:
    profiles:
      default:
        access-token-name: access_token
        refresh-token-name: refresh_token
  filter:
    public-paths:
      - /auth/**
      - /public/**
```

## Use

```java
@RestController
@RequiredArgsConstructor
public class AuthController {

    private final VigilTokenService tokenService;
    private final VigilPasswordService passwordService;
    private final VigilCookieService cookieService;
    private final VigilProtectionService protectionService;

    @PostMapping("/auth/login")
    public AuthResponse login(@RequestBody LoginRequest req, HttpServletResponse res) {
        if (protectionService.isLocked(req.email())) {
            throw new AccountLockedException("Too many attempts");
        }

        User user = userRepository.findByEmail(req.email())
            .filter(u -> passwordService.matches(req.password(), u.getPasswordHash()))
            .orElseThrow(() -> {
                protectionService.recordFailedAttempt(req.email());
                return new BadCredentialsException("Invalid credentials");
            });

        protectionService.recordSuccessfulLogin(req.email());

        String access = tokenService.generateAccessToken(
            TokenRequest.builder()
                .subject(user.getId().toString())
                .claim("role", user.getRole())
                .build());
        String refresh = tokenService.generateRefreshToken(user.getId().toString());

        cookieService.setAccessTokenCookie(res, access);
        cookieService.setRefreshTokenCookie(res, refresh);

        return new AuthResponse(user);
    }

    @PostMapping("/auth/refresh")
    public AuthResponse refresh(HttpServletRequest req, HttpServletResponse res) {
        String refreshToken = cookieService.getRefreshToken(req)
            .orElseThrow(() -> new BadCredentialsException("No refresh token"));

        // Rotate tokens (blacklists old refresh token)
        TokenRefreshResult result = tokenService.refreshTokens(refreshToken);

        cookieService.setAccessTokenCookie(res, result.accessToken());
        cookieService.setRefreshTokenCookie(res, result.refreshToken());

        return new AuthResponse(result.accessExpiresAt());
    }

    @PostMapping("/auth/logout")
    public void logout(HttpServletResponse res) {
        cookieService.clearCookies(res);
    }
}
```

## Cookie Profiles

For apps with multiple user types (staff, customers):

```yaml
vigil:
  cookie:
    secure: true
    http-only: true
    same-site: Lax
    profiles:
      staff:
        access-token-name: staff_access_token
        refresh-token-name: staff_refresh_token
      customer:
        access-token-name: customer_access_token
        refresh-token-name: customer_refresh_token
```

```java
// Use specific profile
cookieService.setAccessTokenCookie(response, token, "staff");
cookieService.getAccessToken(request, "customer");
```

## Custom Token TTL

Override TTL for specific tokens:

```java
// Email verification token (24 hours)
String token = tokenService.generateAccessToken(
    TokenRequest.builder()
        .subject(email)
        .claim("purpose", "email-verification")
        .accessTtl(Duration.ofHours(24))
        .build());
```

## Security Features (Always On)

| Feature | Why |
|---------|-----|
| Token blacklist | Real logout |
| Brute-force protection | Credential stuffing defense |
| Refresh token rotation | Stolen tokens expire immediately |
| HttpOnly cookies | XSS protection |
| Secure cookies | MITM protection |
| SameSite=Lax | CSRF protection |

## Configuration Reference

```yaml
vigil:
  jwt:
    secret: ${JWT_SECRET}       # Required (32+ chars)
    access-ttl: 15m             # Default
    refresh-ttl: 7d             # Default

  cookie:
    secure: true                # Default
    http-only: true             # Default
    same-site: Lax              # Default
    profiles:
      default:
        access-token-name: access_token
        refresh-token-name: refresh_token

  password:
    strength: 12                # BCrypt cost (4-31)

  protection:
    max-attempts: 5
    lock-duration: 15m

  blacklist:
    max-size: 10000
    ttl: 24h

  filter:
    public-paths: []

  tenant:
    enabled: false
    header-name: X-Tenant-ID
```

## Testing

```java
@Import(VigilTestConfiguration.class)
class MyControllerTest {
    @Autowired VigilTokenService tokenService;
    // All Vigil beans available with test defaults
}
```

## Custom Blacklist Backend

Default uses Caffeine (in-memory). For distributed deployments:

```java
public class RedisBlacklistBackend implements VigilBlacklistBackend {
    // Implement: blacklist(), isBlacklisted(), clear(), size()
}

@Bean
public VigilBlacklistService blacklistService(RedisBlacklistBackend backend) {
    return new VigilBlacklistService(backend);
}
```

## Multi-Tenant

```yaml
vigil:
  tenant:
    enabled: true
```

```java
UUID tenantId = VigilTenantContext.requireTenant();
```

## License

Apache 2.0
