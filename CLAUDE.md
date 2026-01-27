# CLAUDE.md

## Project

**Vigil** - JWT authentication for Spring Boot. Security by default.

| Field | Value |
|-------|-------|
| Group ID | io.github.sequelcore |
| Artifact ID | vigil-spring-boot-starter |
| Version | 4.1.0 |
| Java | 21 |
| Spring Boot | 3.5.x |

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
├── autoconfigure/           # Spring Boot auto-configuration
├── auth/                    # VigilAuthService, VigilResetTokenService
├── blacklist/               # Token blacklist (Caffeine)
├── context/                 # VigilContextPopulator interface
├── core/
│   ├── cookie/              # VigilCookieService
│   ├── jwt/                 # VigilTokenService, TokenRequest, VigilTokenClaims
│   └── password/            # VigilPasswordService, PasswordStrength
├── entrypoint/              # VigilAuthenticationEntryPoint (RFC 6750)
├── filter/                  # VigilAuthenticationFilter
├── protection/              # VigilProtectionService (brute-force)
├── session/                 # VigilSessionService, VigilSessionProvider
└── tenant/                  # VigilTenantService, VigilTenantContext
```

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
| `VigilSessionProvider<T>` | Application implements for guest session lookup |
| `VigilContextPopulator` | Application implements for custom security context |
| `VigilBlacklistBackend` | Implement for Redis/DB blacklist storage |

## Configuration

```yaml
vigil:
  jwt:
    secret: your-256-bit-secret-key-here
    access-ttl: 15m
    refresh-ttl: 7d
    issuer: your-app-name    # Optional
    audience: your-audience  # Optional

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

  tenant:
    enabled: false
    header-name: X-Tenant-ID

  session:
    enabled: false
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

Maven Central via GitHub Actions. Triggered by version tags.

```bash
# 1. Update version in build.gradle.kts
version = "X.Y.Z"

# 2. Commit, tag, and push
git add build.gradle.kts
git commit -m "chore: bump version to X.Y.Z"
git push origin main
git tag vX.Y.Z
git push origin vX.Y.Z
```
