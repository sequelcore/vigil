# Vigil

Opinionated JWT authentication for Spring Boot. Security by default, not by configuration.

[![Maven Central](https://img.shields.io/maven-central/v/io.github.sequelcore/vigil-spring-boot-starter.svg)](https://central.sonatype.com/artifact/io.github.sequelcore/vigil-spring-boot-starter)
[![Java 21](https://img.shields.io/badge/Java-21-orange.svg)](https://openjdk.org/projects/jdk/21/)
[![Spring Boot 3.5](https://img.shields.io/badge/Spring%20Boot-3.5-green.svg)](https://spring.io/projects/spring-boot)

## Install

```kotlin
implementation("io.github.sequelcore:vigil-spring-boot-starter:1.0.0")
```

## Configure

```yaml
vigil:
  jwt:
    secret: ${JWT_SECRET}
  filter:
    public-paths:
      - /auth/**
      - /public/**
```

That's it. Everything else is secure by default.

## Use

```java
@RestController
@RequiredArgsConstructor
public class AuthController {

    private final VigilTokenService tokenService;
    private final VigilPasswordService passwordService;
    private final VigilCookieService cookieService;
    private final VigilBlacklistService blacklistService;
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

        protectionService.recordSuccess(req.email());

        String access = tokenService.generateAccessToken(
            TokenRequest.builder()
                .subject(user.getId().toString())
                .claim("role", user.getRole())
                .build());
        String refresh = tokenService.generateRefreshToken(user.getId().toString());

        cookieService.setAccessTokenCookie(res, access);
        cookieService.setRefreshTokenCookie(res, refresh);

        return new AuthResponse(access, refresh);
    }

    @PostMapping("/auth/logout")
    public void logout(HttpServletRequest req, HttpServletResponse res) {
        cookieService.getRefreshToken(req).ifPresent(blacklistService::blacklist);
        cookieService.clearCookies(res);
    }

    @PostMapping("/auth/refresh")
    public AuthResponse refresh(HttpServletRequest req, HttpServletResponse res) {
        String refresh = cookieService.getRefreshToken(req)
            .orElseThrow(() -> new BadCredentialsException("No refresh token"));

        var claims = tokenService.validateToken(refresh);
        String access = tokenService.generateAccessToken(
            TokenRequest.builder()
                .subject(claims.getSubject())
                .claims(claims.getAllClaims())
                .build());

        cookieService.setAccessTokenCookie(res, access);
        return new AuthResponse(access, null);
    }
}
```

## Security Features (Always On)

| Feature | Why |
|---------|-----|
| Auth filter | Core functionality |
| Token blacklist | Real logout requires it |
| Brute-force protection | Basic security |
| HttpOnly cookies | XSS protection |
| Secure cookies | MITM protection |
| SameSite=Lax | CSRF protection |

## Customization

```yaml
vigil:
  jwt:
    secret: ${JWT_SECRET}       # Required
    access-ttl: 15m             # Default: 15m, max 60m
    refresh-ttl: 7d             # Default: 7d, max 30d

  filter:
    public-paths: [/auth/**, /public/**]

  password:
    strength: 12                # BCrypt cost (10-14)

  protection:
    max-attempts: 5             # Before lockout
    lock-duration: 15m
```

## Multi-Tenant (Optional)

```yaml
vigil:
  tenant:
    enabled: true
```

```java
UUID tenantId = VigilTenantContext.getCurrentTenant();
```

## Roadmap

- **v1.1.0**: Native token rotation, algorithm enforcement, sidejacking prevention
- **v1.2.0**: Argon2id, session management, observability
- **v2.0.0**: Key rotation, JWKS, asymmetric keys

See [ROADMAP.md](ROADMAP.md) for security research and philosophy.

## License

Apache 2.0
