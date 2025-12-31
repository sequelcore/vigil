# Vigil Roadmap

## Phase 1: Core Foundation (v1.0.x) - Released

### v1.0.0 - Initial Release
- [x] `VigilTokenService` - JWT generation and validation
- [x] `VigilPasswordService` - Password hashing and validation
- [x] `VigilCookieService` - Cookie management
- [x] `VigilAuthenticationFilter` - Base JWT filter with extension hooks
- [x] `VigilTokenClaims` - Type-safe JWT claims wrapper
- [x] `VigilBlacklistService` - Token blacklist (Caffeine)
- [x] `VigilProtectionService` - Brute-force prevention
- [x] `VigilTenantService` - Multi-tenant support (optional)
- [x] Auto-configuration with `@ConditionalOnMissingBean`
- [x] 80% test coverage

### v1.0.1 - API Cleanup
- [x] Removed `enabled` flags from Blacklist/Protection/Filter records
- [x] Updated maven.publish plugin to 0.34.0

### v1.0.2 - Cookie API Enhancement
- [x] Added public `setCookie(response, name, value, maxAge)` method
- [x] Added public `deleteCookie(response, name)` method

---

## Phase 2: Integration Ready (v2.0.0) - In Progress

> **Goal:** Make Vigil practical for multi-user-type applications (staff + customers).
> **Breaking Changes:** Yes. Only SHRAD partially integrated, safe to break.

### 2.1 Cookie Profiles
Multiple named cookie configurations for different user types.

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
// API
cookieService.setAccessTokenCookie(response, token);           // Uses first profile
cookieService.setAccessTokenCookie(response, token, "staff");  // Uses "staff" profile
cookieService.getAccessToken(request, "customer");             // Reads from "customer" profile
```

- [ ] `CookieProfile` record with name pair
- [ ] `VigilProperties.Cookie.profiles` map
- [ ] Profile-aware methods in `VigilCookieService`
- [ ] Backward compatible: no profile = first/default profile

### 2.2 Token Refresh with Rotation
Secure token refresh with one-time-use refresh tokens.

```java
public record TokenRefreshResult(
    String accessToken,
    String refreshToken,      // New rotated token
    Instant accessExpiresAt,
    Instant refreshExpiresAt
)

// VigilTokenService
TokenRefreshResult refreshTokens(String refreshToken);
TokenRefreshResult refreshTokens(String refreshToken, Map<String, Object> updatedClaims);
```

- [ ] Validate refresh token type (`type: "refresh"` claim)
- [ ] Blacklist old refresh token immediately (strict rotation)
- [ ] Generate new access + refresh token pair
- [ ] Preserve original claims, allow updates
- [ ] Return both tokens with expiration times

### 2.3 Custom TTL per Token
Override default TTL for specific tokens (email verification, password reset).

```java
TokenRequest.builder()
    .subject("user@example.com")
    .claim("purpose", "email-verification")
    .accessTtl(Duration.ofHours(24))  // Override
    .build();
```

- [ ] `accessTtl` field in `TokenRequest`
- [ ] `refreshTtl` field in `TokenRequest`
- [ ] Null = use config default

### 2.4 Blacklist Backend Interface
Prepare for distributed deployments without implementing Redis.

```java
public interface VigilBlacklistBackend {
    void blacklist(String token, Duration ttl);
    boolean isBlacklisted(String token);
    void clear();
}

// Default implementation
public class CaffeineBlacklistBackend implements VigilBlacklistBackend { ... }
```

- [ ] Extract interface from current `VigilBlacklistService`
- [ ] `CaffeineBlacklistBackend` as default
- [ ] `VigilBlacklistService` delegates to backend
- [ ] Document: "Implement interface for Redis/database"

### 2.5 Test Configuration
Reduce test boilerplate for consumers.

```java
@TestConfiguration
public class VigilTestConfiguration {
    @Bean public VigilTokenService vigilTokenService() { ... }
    @Bean public VigilCookieService vigilCookieService() { ... }
    @Bean public VigilBlacklistService vigilBlacklistService() { ... }
    @Bean public VigilProtectionService vigilProtectionService() { ... }
    @Bean public VigilPasswordService vigilPasswordService() { ... }
    // All with test-friendly defaults (test secret, short TTLs)
}
```

- [ ] `VigilTestConfiguration` class
- [ ] Test JWT secret (deterministic for assertions)
- [ ] Short TTLs for fast tests
- [ ] Document usage: `@Import(VigilTestConfiguration.class)`

### 2.6 API Cleanup
- [ ] Rename `VigilTokenClaims.isRefreshToken()` to `isRefresh()`
- [ ] Add `VigilTokenService.generateAccessToken(String subject, VigilClaims claims)`
- [ ] Deprecate raw `Map<String, Object>` claims methods
- [ ] Remove any unused internal methods

---

## Phase 3: Security Hardening (v2.1.0) - Planned

> **Goal:** OWASP/NIST compliance for production deployments.

### 3.1 Algorithm Enforcement
- [ ] Reject `alg: none` tokens
- [ ] Server-side algorithm enforcement (never trust JWT header)
- [ ] Whitelist: HS256, HS384, HS512

### 3.2 Claims Validation
- [ ] `iss` (issuer) validation against config
- [ ] `aud` (audience) validation against config
- [ ] `nbf` (not before) with clock skew tolerance
- [ ] `iat` (issued at) - reject future tokens

### 3.3 TTL Ceilings
- [ ] Access TTL max: 60 minutes
- [ ] Refresh TTL max: 30 days
- [ ] Fail-fast validation at startup

### 3.4 Audit Events
```java
public class VigilAuthenticationSuccessEvent extends ApplicationEvent { ... }
public class VigilAuthenticationFailureEvent extends ApplicationEvent { ... }
public class VigilTokenBlacklistedEvent extends ApplicationEvent { ... }
public class VigilAccountLockedEvent extends ApplicationEvent { ... }
```

- [ ] Spring ApplicationEvent publishing
- [ ] Events from filter and services
- [ ] Document listener patterns

---

## Phase 4: Advanced Security (v2.2.0) - Future

### 4.1 Token Sidejacking Prevention
- [ ] Fingerprint in HttpOnly cookie
- [ ] SHA256(fingerprint) in JWT claim
- [ ] Validate on every request

### 4.2 Key Rotation
- [ ] `kid` (key ID) in JWT header
- [ ] Multiple keys during rotation
- [ ] JWKS endpoint

### 4.3 Asymmetric Keys
- [ ] RS256, ES256, EdDSA support
- [ ] Public key validation mode

### 4.4 Redis Adapters
- [ ] `RedisBlacklistBackend`
- [ ] `RedisProtectionBackend`
- [ ] Auto-detect via Spring Data Redis

---

## Phase 5: Extended Features (v3.0.0) - Future

- [ ] IP/Device tracking
- [ ] Anomaly detection
- [ ] Session management
- [ ] Argon2id password hashing
- [ ] OAuth wrappers

---

## Non-Goals

- Guest sessions (application logic)
- Email verification (provider-specific)
- Full OAuth2 server (use Spring Authorization Server)
- SMS/2FA (provider-specific)
- User management (application domain)

---

## Version History

| Version | Status | Highlights |
|---------|--------|------------|
| 1.0.0 | Released | Core JWT, cookies, blacklist, protection, tenant |
| 1.0.1 | Released | API cleanup, removed enabled flags |
| 1.0.2 | Released | Public setCookie/deleteCookie methods |
| 2.0.0 | In Progress | Cookie profiles, token refresh rotation, custom TTL, test config |
| 2.1.0 | Planned | OWASP compliance, audit events |
| 2.2.0 | Future | Sidejacking prevention, key rotation, asymmetric keys |
| 3.0.0 | Future | IP/device security, anomaly detection |
