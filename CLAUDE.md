# CLAUDE.md

## Project

**Vigil** - JWT authentication for Spring Boot. Security by default.

| Field | Value |
|-------|-------|
| Group ID | io.github.sequelcore |
| Artifact ID | vigil-spring-boot-starter |
| Version | 2.3.1 |
| Java | 21 |
| Spring Boot | 3.5.x |

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
| `VigilBlacklistService` | Token invalidation for logout |
| `VigilProtectionService` | Brute-force prevention, account lockout |
| `VigilAuthService` | High-level logout, refresh, session invalidation |
| `VigilSessionService` | Guest session token management |
| `VigilTenantService` | Multi-tenant header validation |

## Interfaces

| Interface | Purpose |
|-----------|---------|
| `VigilSessionProvider<T>` | Application implements to enable guest sessions |
| `VigilContextPopulator` | Application implements to populate custom security contexts |
| `VigilBlacklistBackend` | Implement for Redis/DB blacklist storage |

## Code Standards

- Google Java Format (Spotless)
- 80% test coverage (JaCoCo)
- Javadoc on public APIs

## Publishing

Maven Central via GitHub Actions. Triggered by version tags.

```bash
# Publish new version
git tag v2.3.1
git push origin v2.3.1
```

Workflow: `.github/workflows/publish.yml`
- Validates tag format (v*.*.*)
- Builds and tests
- Publishes to Maven Central
- Creates GitHub release

Secrets in Doppler (`sequel-core/prd`):
- `MAVEN_USERNAME` / `MAVEN_PASSWORD` - Central Portal token
- `GPG_PRIVATE_KEY` / `GPG_PASSPHRASE` - Package signing
