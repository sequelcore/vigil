# CLAUDE.md

## Project

**Vigil** - JWT authentication for Spring Boot. Security by default.

| Field | Value |
|-------|-------|
| Group ID | io.github.sequelcore |
| Artifact ID | vigil-spring-boot-starter |
| Version | 2.6.1 |
| Java | 21 |
| Spring Boot | 3.5.x |

## Scope

Vigil handles **token lifecycle**, not **user lifecycle**.

**What Vigil does:**
- Token generation, validation, refresh, blacklisting
- Password hashing and strength validation
- HTTP-only cookie management
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

## VigilAuthService

Central orchestration for auth operations:

```java
// Full control
authService.login(response, subject, profile, claims);
authService.refresh(request, response, profile);
authService.logout(request, response, profile);

// Default profile (single-portal apps)
authService.login(response, subject, claims);
authService.login(response, subject);
authService.refresh(request, response);
authService.logout(request, response);

// Session management
authService.invalidateAllSessions(subject);
```

The app validates credentials, Vigil handles token orchestration.

## Interfaces

| Interface | Purpose |
|-----------|---------|
| `VigilSessionProvider<T>` | Application implements for guest session lookup |
| `VigilContextPopulator` | Application implements for custom security context |
| `VigilBlacklistBackend` | Implement for Redis/DB blacklist storage |

## Code Standards

- Google Java Format (Spotless)
- 80% test coverage (JaCoCo)
- Javadoc on public APIs

## Publishing

Maven Central via GitHub Actions. Triggered by version tags.

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```
