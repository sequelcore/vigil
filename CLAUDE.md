# CLAUDE.md

## Project

**Vigil** - JWT authentication for Spring Boot. Security by default.

| Field | Value |
|-------|-------|
| Group ID | io.github.sequelcore |
| Artifact ID | vigil-spring-boot-starter |
| Version | 7.0.0 |
| Java | 25 |
| Spring Boot | 4.1.x |

## Scope

Vigil handles **token lifecycle**, not **user lifecycle**.

**What Vigil does:**
- Token generation, validation, refresh, blacklisting
- Password hashing and strength validation
- HTTP-only cookie management (web clients)
- Bearer token support (native apps, APIs)
- Request authentication via filter
- Multi-tenant context
- Guest sessions
- RS256 asymmetric signing + JWKS public key distribution
- RS256 public-key rotation with verification-only previous keys

**What Vigil does NOT do:**
- User storage or lookup
- `UserDetailsService` implementation
- Login/registration endpoints
- Email/SMS sending

This follows the same pattern as Auth0/Okta starters: validate tokens, delegate user management to the application.

## Commands

```bash
./gradlew build
./gradlew test
./gradlew qualityCheck       # Spotless + Checkstyle + JaCoCo
./gradlew spotlessApply
```

## Package Structure

```
io.github.sequelcore.vigil/
├── autoconfigure/           # Spring Boot auto-configuration + VigilProperties
├── auth/                    # VigilAuthService, VigilResetTokenService
├── blacklist/               # Token blacklist (Caffeine default, custom shared backend SPI)
├── context/                 # VigilContextPopulator interface
├── core/
│   ├── cookie/              # VigilCookieService
│   ├── jwt/                 # VigilTokenService, TokenSigner, HmacTokenSigner,
│   │                        # RsaTokenSigner, PemKeyLoader, TokenRequest, VigilTokenClaims
│   └── password/            # VigilPasswordService, PasswordStrength
├── entrypoint/              # VigilAuthenticationEntryPoint (RFC 6750)
├── filter/                  # VigilAuthenticationFilter
├── jwks/                    # JwksController (/.well-known/jwks.json, RS256 only)
├── protection/              # VigilProtectionService (brute-force)
├── session/                 # VigilSessionService, VigilSessionProvider
└── tenant/                  # VigilTenantService, VigilTenantContext
```

## Signing Architecture

`TokenSigner` is a strategy interface with two implementations:

| Implementation | Algorithm | When active |
|----------------|-----------|-------------|
| `HmacTokenSigner` | HS256 | `algorithm` omitted or `HS256` (default) |
| `RsaTokenSigner` | RS256 | `algorithm: RS256` |

`VigilAutoConfiguration` selects the correct implementation based on `vigil.jwt.algorithm` and registers it as a `TokenSigner` bean. `VigilTokenService` receives the signer via constructor injection and delegates all sign/verify operations to it.

`RsaTokenSigner` computes a deterministic `kid` (SHA-256 of public key DER, base64url, first 8 chars) added to every token header. `JwksController` exposes the public key at `/.well-known/jwks.json` per RFC 7517, cached with `Cache-Control: public, max-age=3600`.

`PemKeyLoader` accepts three source formats:
- `file:/absolute/path/to/key.pem`
- `classpath:path/to/key.pem`
- Inline PEM string (PKCS#8 private, X.509 public)

## Services

| Service | Purpose |
|---------|---------|
| `VigilTokenService` | JWT generation, validation, refresh |
| `VigilPasswordService` | BCrypt hashing, strength scoring, rehash detection |
| `VigilCookieService` | HTTP-Only cookie management with profiles |
| `VigilBlacklistService` | Token and subject invalidation |
| `VigilProtectionService` | Brute-force prevention, account lockout |
| `VigilAuthService` | Login, logout, refresh orchestration |
| `VigilSessionService` | Guest session token management |
| `VigilTenantService` | Multi-tenant header validation |
| `VigilResetTokenService` | Single-use password reset tokens |
| `VigilAuthenticationEntryPoint` | RFC 6750 compliant 401 responses |

## VigilAuthService

Central orchestration for auth operations. Supports two client types:

### Web Clients (SPAs) - Cookie-based

```java
// Full control
authService.login(response, subject, profile, claims);
authService.refresh(request, response, profile);
authService.logout(request, response, profile);

// Default profile
authService.login(response, subject, claims);
authService.refresh(request, response);
authService.logout(request, response);
```

### Native Apps & APIs (RFC 6749) - Token-based

```java
// Login returns tokens in response body
authService.login(subject, claims);
authService.login(subject);

// Refresh with raw token
authService.refresh(refreshToken);
authService.refresh(refreshToken, updatedClaims);

// Logout with raw tokens
authService.logout(accessToken, refreshToken);
```

### Session Management

```java
authService.invalidateAllSessions(subject);
```

The app validates credentials, Vigil handles token orchestration.

## Interfaces

| Interface | Purpose |
|-----------|---------|
| `TokenSigner` | Strategy for JWT signing and parser configuration (HS256 / RS256) |
| `VigilSessionProvider<T>` | Application implements for guest session lookup |
| `VigilContextPopulator` | Application implements for custom security context |
| `VigilBlacklistBackend` | Implement for Redis/DB blacklist storage; auto-detected as a bean |

## Configuration

### HS256 (default)

```yaml
vigil:
  jwt:
    secret: ${JWT_SECRET}        # Required: min 32 chars (RFC 8725bis)
    access-ttl: 15m
    refresh-ttl: 7d
    issuer: your-app             # Optional — validated on parse when set
    audience: your-audience      # Optional — validated on parse when set
```

### RS256

```yaml
vigil:
  jwt:
    algorithm: RS256
    rsa-private-key: ${RSA_PRIVATE_KEY}   # PEM: file:/path, classpath:path, or inline
    rsa-public-key: ${RSA_PUBLIC_KEY}
    rsa-public-keys: []                   # Optional previous public keys for rotation
    issuer: your-app
    audience: your-audience
    access-ttl: 15m
    refresh-ttl: 7d
    clock-skew: 0s                        # Optional, max 5m
```

When `algorithm: RS256`:
- `secret` is not required and is ignored
- `GET /.well-known/jwks.json` is auto-registered (no auth)
- Every token header includes `kid` for key rotation

### Full Reference

```yaml
vigil:
  jwt:
    secret: your-256-bit-secret-key-here   # HS256 only
    algorithm: HS256                        # HS256 (default) or RS256
    rsa-private-key: ${RSA_PRIVATE_KEY}     # RS256 only
    rsa-public-key: ${RSA_PUBLIC_KEY}       # RS256 only
    rsa-public-keys: []                     # RS256 verification-only previous keys
    access-ttl: 15m
    refresh-ttl: 7d
    issuer: your-app-name
    audience: your-audience
    clock-skew: 0s

  auth:
    realm: your-app-name     # For WWW-Authenticate header (RFC 6750)

  cookie:
    secure: true
    http-only: true
    same-site: Lax
    profiles:
      staff:
        access-token-name: staff_access_token
        refresh-token-name: staff_refresh_token

  filter:
    ignored-paths:           # Skip ALL processing (no tenant, no auth, no populators)
      - /actuator/**
      - /health
    public-paths:            # Permit anonymous, but authenticate if credentials present
      - /api/auth/login
      - /api/auth/register
    profile-paths:
      staff: ["/api/admin/**", "/api/staff/**"]
      customer: ["/api/customer/**"]

  blacklist:
    max-size: 10000          # Maximum cached entries
    ttl: 24h                 # Time-to-live for blacklisted tokens
    grace-period: 30s        # Grace period for token rotation (0-60s)

  # Multi-instance deployments should expose a shared VigilBlacklistBackend bean.
  # Without one, Vigil uses the in-memory Caffeine backend.

  tenant:
    enabled: false
    header-name: X-Tenant-ID

  session:
    enabled: false
    cookie-name: session_token
    ttl: 30m

  reset:
    ttl: 1h
```

### Grace Period for Token Rotation

When a refresh token is rotated, the old token enters a grace period where it can still be reused. This handles race conditions when:
- Network issues prevent the client from receiving the new tokens
- Client crashes before persisting the new tokens
- Mobile apps lose signal mid-refresh

During the grace period, reusing the old token returns the same cached new tokens. After grace period expires, the old token is rejected.

## Code Standards

- Google Java Format (Spotless)
- 80% test coverage (JaCoCo)
- Javadoc on public APIs

## Publishing

Maven Central via GitHub Actions. Publishing is manual and guarded by the
release workflow.

```bash
# 1. Update version in build.gradle.kts
version = "X.Y.Z"

# 2. Commit, tag, and push
git add build.gradle.kts
git commit -m "chore: bump version to X.Y.Z"
git push origin main
git tag vX.Y.Z
git push origin vX.Y.Z

# 3. Run the Release workflow with:
# operation=validate, release_ref=vX.Y.Z, release_version=X.Y.Z
#
# 4. Publish only after validation passes:
# operation=publish, release_ref=vX.Y.Z, release_version=X.Y.Z,
# confirmation="publish X.Y.Z"
```
