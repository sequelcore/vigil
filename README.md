# Vigil

Opinionated JWT authentication starter for Spring Boot. Stop copy-pasting auth boilerplate.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Java](https://img.shields.io/badge/Java-21-orange.svg)](https://openjdk.org/projects/jdk/21/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5-green.svg)](https://spring.io/projects/spring-boot)

## Features

- JWT token generation and validation with configurable TTL
- Refresh token rotation
- Password hashing with BCrypt (configurable strength)
- Cookie management with dual client support (web/mobile)
- Security filter with public path exclusion
- Optional: Token blacklist (Caffeine-based)
- Optional: Login attempt tracking and account lockout
- Optional: Multi-tenant context management

## Installation

```kotlin
// build.gradle.kts
dependencies {
    implementation("io.github.sequelcore:vigil-spring-boot-starter:1.0.0")
}
```

```xml
<!-- pom.xml -->
<dependency>
    <groupId>io.github.sequelcore</groupId>
    <artifactId>vigil-spring-boot-starter</artifactId>
    <version>1.0.0</version>
</dependency>
```

## Quick Start

### 1. Add configuration

```yaml
# application.yml
vigil:
  jwt:
    secret: ${JWT_SECRET}  # Required: 256+ bit secret
    access-ttl: 15m
    refresh-ttl: 7d
```

### 2. Use the services

```java
@RestController
@RequiredArgsConstructor
public class AuthController {

    private final VigilTokenService tokenService;
    private final VigilPasswordService passwordService;
    private final VigilCookieService cookieService;

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @RequestBody LoginRequest request,
            HttpServletResponse response) {

        // Validate password
        User user = userRepository.findByUsername(request.username());
        if (!passwordService.matches(request.password(), user.getPasswordHash())) {
            throw new BadCredentialsException("Invalid credentials");
        }

        // Generate tokens
        String accessToken = tokenService.generateAccessToken(
            TokenRequest.builder()
                .subject(user.getUsername())
                .claim("userId", user.getId())
                .claim("role", user.getRole())
                .build()
        );

        String refreshToken = tokenService.generateRefreshToken(user.getUsername());

        // Set cookies (for web clients)
        cookieService.setAccessTokenCookie(response, accessToken);
        cookieService.setRefreshTokenCookie(response, refreshToken);

        return ResponseEntity.ok(new LoginResponse(accessToken, refreshToken));
    }
}
```

## Configuration Reference

```yaml
vigil:
  jwt:
    secret: ${JWT_SECRET}           # Required
    access-ttl: 15m                 # Default: 15 minutes
    refresh-ttl: 7d                 # Default: 7 days
    issuer: my-app                  # Optional
    audience: my-app                # Optional

  cookie:
    access-token-name: access_token
    refresh-token-name: refresh_token
    secure: true                    # Set false for local development
    same-site: Lax                  # Lax, Strict, or None
    http-only: true

  password:
    strength: 12                    # BCrypt cost factor (10-14 recommended)

  blacklist:
    enabled: false                  # Enable token blacklist
    max-size: 10000
    ttl: 24h

  tenant:
    enabled: false                  # Enable multi-tenant support
    header-name: X-Tenant-ID

  protection:
    enabled: false                  # Enable login attempt tracking
    max-attempts: 5
    lock-duration: 15m
```

## Optional Modules

### Token Blacklist

Enable to support immediate token revocation:

```yaml
vigil:
  blacklist:
    enabled: true
```

```java
@Autowired
private VigilBlacklistService blacklistService;

public void logout(String refreshToken) {
    blacklistService.blacklist(refreshToken);
}
```

### Multi-Tenant Support

Enable for SaaS applications with tenant isolation:

```yaml
vigil:
  tenant:
    enabled: true
    header-name: X-Tenant-ID
```

```java
// Tenant automatically extracted from header and validated against JWT
UUID tenantId = VigilTenantContext.getCurrentTenant();
```

### Login Protection

Enable to prevent brute force attacks:

```yaml
vigil:
  protection:
    enabled: true
    max-attempts: 5
    lock-duration: 15m
```

```java
@Autowired
private VigilProtectionService protectionService;

public void onLoginFailure(String username) {
    protectionService.recordFailedAttempt(username);
}

public void beforeLogin(String username) {
    if (protectionService.isLocked(username)) {
        throw new AccountLockedException("Account is locked");
    }
}
```

## Extending the Filter

```java
@Component
public class CustomAuthFilter extends VigilAuthenticationFilter {

    @Override
    protected void onAuthenticationSuccess(
            HttpServletRequest request,
            VigilTokenClaims claims) {
        // Custom logic after successful authentication
    }

    @Override
    protected boolean isPublicPath(String path) {
        return super.isPublicPath(path)
            || path.startsWith("/public/");
    }
}
```

## Requirements

- Java 21+
- Spring Boot 3.5+
- Spring Security

## License

[Apache License 2.0](LICENSE)

## Contributing

Contributions are welcome. Please open an issue first to discuss what you would like to change.
