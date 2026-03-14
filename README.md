# Vigil

JWT authentication for Spring Boot. Security by default.

[![Maven Central](https://img.shields.io/maven-central/v/io.github.sequelcore/vigil-spring-boot-starter.svg)](https://central.sonatype.com/artifact/io.github.sequelcore/vigil-spring-boot-starter)

## Scope

Vigil handles **token lifecycle**, not **user lifecycle**.

| Vigil does | Application does |
|------------|------------------|
| Generate/validate/refresh tokens | Store/load users |
| Manage HTTP-only cookies | Validate credentials |
| Authenticate requests via filter | Define user model |
| Blacklist tokens on logout | Implement login endpoint |

Same pattern as Auth0/Okta starters.

## Install

```kotlin
implementation("io.github.sequelcore:vigil-spring-boot-starter:5.0.0")
```

## Configure

### HS256 (default)

Symmetric signing — any service with the secret can sign and verify.

```yaml
vigil:
  jwt:
    secret: ${JWT_SECRET}       # Required: min 32 chars (256 bits per RFC 8725bis)
    access-ttl: 15m
    refresh-ttl: 7d
  cookie:
    profiles:
      default:
        access-token-name: access_token
        refresh-token-name: refresh_token
  filter:
    ignored-paths:       # Skip ALL processing (no tenant, no auth, no populators)
      - /actuator/**
      - /health
    public-paths:        # Permit anonymous, authenticate if credentials present
      - /auth/**
      - /public/**
```

### RS256

Asymmetric signing — private key signs, public key verifies. Services can validate tokens without the ability to mint them.

```yaml
vigil:
  jwt:
    algorithm: RS256
    rsa-private-key: ${RSA_PRIVATE_KEY}   # PEM string, file:/path, or classpath:path
    rsa-public-key: ${RSA_PUBLIC_KEY}
    issuer: my-app
    audience: my-app
    access-ttl: 15m
    refresh-ttl: 7d
```

When `algorithm: RS256` is active:
- A `/.well-known/jwks.json` endpoint is registered automatically
- The endpoint is added to `ignored-paths` — no authentication required to access it
- Every token includes a `kid` header (key fingerprint) for key rotation support

Key generation:

```bash
openssl genrsa -out vigil-private.pem 2048
openssl rsa -in vigil-private.pem -pubout -out vigil-public.pem
```

For Doppler/secrets managers, paste PEM content directly as environment variables.

## Usage

### Web Clients (SPAs)

Tokens stored in HTTP-only cookies. Automatic CSRF protection via SameSite.

```java
@RestController
@RequiredArgsConstructor
public class AuthController {

    private final VigilAuthService authService;
    private final VigilPasswordService passwordService;
    private final UserRepository userRepository;

    @PostMapping("/auth/login")
    public AuthResult login(@RequestBody LoginRequest req, HttpServletResponse res) {
        User user = userRepository.findByEmail(req.email())
            .filter(u -> passwordService.matches(req.password(), u.getPasswordHash()))
            .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));

        return authService.login(res, user.getEmail(),
            Map.of("userId", user.getId(), "roles", user.getRoles()));
    }

    @PostMapping("/auth/refresh")
    public AuthResult refresh(HttpServletRequest req, HttpServletResponse res) {
        return authService.refresh(req, res);
    }

    @PostMapping("/auth/logout")
    public void logout(HttpServletRequest req, HttpServletResponse res) {
        authService.logout(req, res);
    }
}
```

### Native Apps & APIs (RFC 6749)

Tokens returned in response body. Client stores in Keychain/Keystore.

```java
@RestController
@RequiredArgsConstructor
public class MobileAuthController {

    private final VigilAuthService authService;
    private final VigilPasswordService passwordService;
    private final UserRepository userRepository;

    @PostMapping("/auth/login")
    public AuthResult login(@RequestBody LoginRequest req) {
        User user = userRepository.findByEmail(req.email())
            .filter(u -> passwordService.matches(req.password(), u.getPasswordHash()))
            .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));

        return authService.login(user.getEmail(),
            Map.of("userId", user.getId(), "roles", user.getRoles()));
    }

    @PostMapping("/auth/refresh")
    public AuthResult refresh(@RequestBody RefreshRequest req) {
        return authService.refresh(req.refreshToken());
    }

    @PostMapping("/auth/logout")
    public void logout(@RequestBody LogoutRequest req) {
        authService.logout(req.accessToken(), req.refreshToken());
    }
}
```

## Filter Behavior

The authentication filter separates **authentication** (who are you?) from **authorization** (can you access this?).

| Path Type | Credentials | Behavior |
|-----------|-------------|----------|
| Ignored | Any | Skip all processing, proceed |
| Public | None | Permit anonymous |
| Public | Valid | Authenticate user |
| Public | Invalid | Permit anonymous (hook called) |
| Protected | None | 401 Unauthorized |
| Protected | Valid | Authenticate user |
| Protected | Invalid | 401 Unauthorized |

This allows public pages to optionally show user info when logged in (e.g., "Welcome, Alice").

## Services

| Service | Purpose |
|---------|---------|
| `VigilAuthService` | Login, logout, refresh orchestration |
| `VigilTokenService` | JWT generation, validation, refresh |
| `VigilPasswordService` | BCrypt hashing, strength scoring |
| `VigilCookieService` | HTTP-only cookie management |
| `VigilBlacklistService` | Token and subject invalidation |
| `VigilProtectionService` | Brute-force prevention |
| `VigilResetTokenService` | Password reset tokens |
| `VigilSessionService` | Guest session tokens |
| `VigilTenantService` | Multi-tenant context |
| `VigilAuthenticationEntryPoint` | RFC 6750 compliant 401 responses |

## Multi-Portal Authentication

For apps with multiple user types (admin/customer):

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
  filter:
    profile-paths:
      staff:
        - /api/console/**
      customer:
        - /api/box/**
```

```java
// Staff login
authService.login(response, user.getEmail(), "staff", claims);

// Customer login
authService.login(response, user.getEmail(), "customer", claims);
```

Requests to `/api/console/**` use `staff_token`. Requests to `/api/box/**` use `customer_token`.

## Custom Security Context

Populate app-specific context after authentication:

```java
@Component
public class UserContextPopulator implements VigilContextPopulator {

    @Override
    public void populate(HttpServletRequest request, VigilTokenClaims claims) {
        UserContext.set(
            claims.getString("userId").orElse(null),
            claims.getStringList("roles")
        );
    }

    @Override
    public void clear() {
        UserContext.clear();
    }
}
```

## Password Strength

```java
PasswordStrength strength = passwordService.strength("weak123");
if (!strength.isAcceptable()) {
    throw new ValidationException(strength.feedback());
}

String hash = passwordService.hash("StrongP@ss1!");
boolean matches = passwordService.matches("StrongP@ss1!", hash);
```

## Password Reset

```java
// Generate token
String token = resetTokenService.generate(user.getEmail());
emailService.send(user.getEmail(), "Reset: " + url + "?token=" + token);

// Validate and consume (single-use)
String email = resetTokenService.validateAndConsume(token);
user.setPasswordHash(passwordService.hash(newPassword));
authService.invalidateAllSessions(email);
```

## Guest Sessions

```yaml
vigil:
  session:
    enabled: true
    cookie-name: guest_session
    ttl: 30m
```

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

## Configuration Reference

```yaml
vigil:
  jwt:
    # HS256 (default) — symmetric, shared secret
    secret: ${JWT_SECRET}         # Required for HS256: min 32 chars (RFC 8725bis)
    access-ttl: 15m
    refresh-ttl: 7d
    issuer: my-app                # Optional: validated on parse when set (RFC 8725bis)
    audience: my-app              # Optional: validated on parse when set (RFC 8725bis)

    # RS256 (opt-in) — asymmetric, private signs / public verifies
    algorithm: RS256              # HS256 (default) or RS256
    rsa-private-key: ${RSA_PRIVATE_KEY}   # PEM: file:/path, classpath:path, or inline
    rsa-public-key: ${RSA_PUBLIC_KEY}     # Required when algorithm=RS256

  auth:
    realm: my-app               # WWW-Authenticate realm (RFC 6750)

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
    grace-period: 30s           # Reuse window for rotated tokens (0-60s)

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
    ignored-paths: []           # Skip ALL processing
    public-paths: []            # Permit anonymous, authenticate if present
    profile-paths:
      staff:
        - /api/console/**
      customer:
        - /api/box/**

  reset:
    ttl: 1h
```

## License

Apache 2.0
