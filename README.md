# Vigil

JWT authentication for Spring Boot. Security by default.

[![Maven Central](https://img.shields.io/maven-central/v/io.github.sequelcore/vigil-spring-boot-starter.svg)](https://central.sonatype.com/artifact/io.github.sequelcore/vigil-spring-boot-starter)

## Install

```kotlin
implementation("io.github.sequelcore:vigil-spring-boot-starter:2.3.1")
```

## Configure

```yaml
vigil:
  jwt:
    secret: ${JWT_SECRET}
    access-ttl: 15m
    refresh-ttl: 7d
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

## Services

| Service | Purpose |
|---------|---------|
| `VigilTokenService` | JWT generation, validation, refresh with rotation |
| `VigilPasswordService` | BCrypt hashing, strength scoring, rehash detection |
| `VigilCookieService` | HTTP-Only cookie management with profiles |
| `VigilBlacklistService` | Token and subject invalidation |
| `VigilProtectionService` | Brute-force prevention, account lockout |
| `VigilAuthService` | High-level logout, refresh, session invalidation |
| `VigilResetTokenService` | Single-use password reset tokens |
| `VigilSessionService` | Guest/anonymous session tokens |
| `VigilTenantService` | Multi-tenant context management |

## Basic Usage

```java
@RestController
@RequiredArgsConstructor
public class AuthController {

    private final VigilTokenService tokenService;
    private final VigilPasswordService passwordService;
    private final VigilCookieService cookieService;
    private final VigilAuthService authService;

    @PostMapping("/login")
    public void login(@RequestBody LoginRequest req, HttpServletResponse res) {
        User user = userRepository.findByEmail(req.email())
            .filter(u -> passwordService.matches(req.password(), u.getPasswordHash()))
            .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));

        String token = tokenService.generateAccessToken(
            TokenRequest.builder()
                .subject(user.getId().toString())
                .claim("role", user.getRole())
                .build());

        cookieService.setAccessTokenCookie(res, token);
    }

    @PostMapping("/logout")
    public void logout(HttpServletRequest req, HttpServletResponse res) {
        authService.logout(req, res, "default");
    }
}
```

## Cookie Profiles

For apps with multiple user types:

```yaml
vigil:
  cookie:
    profiles:
      staff:
        access-token-name: staff_token
        refresh-token-name: staff_refresh
      customer:
        access-token-name: customer_token
        refresh-token-name: customer_refresh
```

```java
cookieService.setAccessTokenCookie(response, token, "staff");
cookieService.getAccessToken(request, "customer");
```

## Guest Sessions

For anonymous/guest users (e.g., checkout without account):

```yaml
vigil:
  session:
    enabled: true
    cookie-name: guest_session
    ttl: 30m
```

Implement the provider:

```java
@Component
public class GuestSessionProvider implements VigilSessionProvider<Guest> {

    @Override
    public Optional<Guest> findByToken(String token, UUID tenantId) {
        return guestRepository.findBySessionToken(token);
    }

    @Override
    public boolean isExpired(Guest guest) {
        return guest.isExpired();
    }

    @Override
    public String getPrincipal(Guest guest) {
        return guest.getId().toString();
    }
}
```

## Custom Security Context

Populate your app's security context after Vigil authenticates:

```java
@Component
public class UserContextPopulator implements VigilContextPopulator {

    @Override
    public void populate(HttpServletRequest request, VigilTokenClaims claims) {
        UserContext.set(
            claims.getString("userId").orElse(null),
            claims.getString("role").orElse(null)
        );
    }

    @Override
    public void clear() {
        UserContext.clear();
    }
}
```

Vigil auto-discovers all `VigilContextPopulator` beans and calls them after authentication.

## Password Strength

```java
PasswordStrength strength = passwordService.strength("weak123");
if (!strength.isAcceptable()) {
    throw new ValidationException(strength.feedback());
}

String hash = passwordService.hash("StrongP@ss1!");
boolean matches = passwordService.matches("StrongP@ss1!", hash);
boolean needsUpgrade = passwordService.needsRehash(hash);
```

## Multi-Tenant

```yaml
vigil:
  tenant:
    enabled: true
    header-name: X-Tenant-ID
```

```java
UUID tenantId = VigilTenantContext.requireTenant();
```

## Password Reset

```java
// Generate reset token
String token = resetTokenService.generate(user.getEmail());
emailService.send(user.getEmail(), "Reset: " + frontendUrl + "?token=" + token);

// Validate and consume (single-use)
String email = resetTokenService.validateAndConsume(token);
user.setPasswordHash(passwordService.hash(newPassword));
authService.invalidateAllSessions(email);
```

## Configuration Reference

```yaml
vigil:
  jwt:
    secret: ${JWT_SECRET}       # Required (min 32 chars)
    access-ttl: 15m
    refresh-ttl: 7d
    issuer: my-app              # Optional
    audience: my-app            # Optional

  cookie:
    secure: true
    http-only: true
    same-site: Lax
    profiles:
      default:
        access-token-name: access_token
        refresh-token-name: refresh_token

  password:
    strength: 12                # BCrypt cost (4-31)

  blacklist:
    max-size: 10000
    ttl: 24h

  protection:
    max-attempts: 5
    lock-duration: 15m

  session:
    enabled: false
    cookie-name: session_token
    ttl: 30m

  tenant:
    enabled: false
    header-name: X-Tenant-ID

  filter:
    public-paths: []
    check-all-profiles: false   # Try all cookie profiles for tokens

  reset:
    ttl: 1h                     # Password reset token TTL
```

## License

Apache 2.0
