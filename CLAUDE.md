# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Overview

**Vigil** is an opinionated JWT authentication starter for Spring Boot. It eliminates boilerplate auth code by providing pre-configured JWT handling, password services, cookie management, and optional modules for multi-tenancy, token blacklisting, and brute-force protection.

## Project Information

- **Group ID:** io.github.sequelcore
- **Artifact ID:** vigil-spring-boot-starter
- **License:** Apache 2.0
- **Java:** 21 LTS
- **Spring Boot:** 3.5.x

## Reference Projects

These Sequel projects use patterns that Vigil extracts and standardizes:

- **SHRAD:** `C:\Proyectos\Sequel\Shrad\shrad\backend`
  - Multi-tenant JWT with `X-Tenant-ID` header
  - Separate staff/customer token flows
  - Cookie-based token storage (HttpOnly)
  - BCrypt with cost factor 12
  - `TenantContext` ThreadLocal pattern

- **Quesoro:** `C:\Proyectos\Sequel\quesoro\backend`
  - Token blacklist with Caffeine cache
  - Login attempt tracking and account lockout
  - Device/session management
  - Dual client support (web cookies / mobile tokens)
  - Token rotation on refresh

## Commands

```bash
# Build
./gradlew build

# Run tests
./gradlew test

# Code quality
./gradlew qualityCheck
./gradlew spotlessApply

# Publish to Maven Central (requires Doppler)
doppler run --project sequel-core --config prd -- ./gradlew publish
```

## Architecture

Single module with feature flags via `@ConditionalOnProperty`:

```
src/main/java/io/github/sequelcore/vigil/
├── core/
│   ├── jwt/           # Token generation, validation, claims
│   ├── password/      # BCrypt hashing, strength validation
│   └── cookie/        # Cookie creation, dual client support
├── filter/            # Base security filter
├── blacklist/         # Token blacklist (Caffeine) - optional
├── protection/        # Login attempt tracking - optional
├── tenant/            # Multi-tenant context - optional
└── autoconfigure/     # Spring Boot auto-configuration
    ├── VigilAutoConfiguration.java
    └── VigilProperties.java
```

## Configuration

```yaml
vigil:
  jwt:
    secret: ${JWT_SECRET}
    access-ttl: 15m
    refresh-ttl: 7d
    issuer: my-app
  cookie:
    access-token-name: access_token
    refresh-token-name: refresh_token
    secure: true
    same-site: Lax
  blacklist:
    enabled: false
    max-size: 10000
    ttl: 24h
  tenant:
    enabled: false
    header-name: X-Tenant-ID
  protection:
    enabled: false
    max-attempts: 5
    lock-duration: 15m
```

## Code Standards

- **Formatting:** Google Java Format via Spotless
- **Style:** Google Checkstyle rules
- **Coverage:** 80% minimum (JaCoCo)
- **No wildcard imports**
- **Use Lombok:** `@Getter`, `@Setter`, `@Builder`, `@RequiredArgsConstructor`
- **Use Java Records** for DTOs and configuration properties
- **No emojis in code or documentation**

## Publishing

- **Registry:** Maven Central
- **Namespace:** io.github.sequelcore
- **Secrets:** Doppler (sequel-core/prd)
  - `MAVEN_USERNAME` - Sonatype token username
  - `MAVEN_PASSWORD` - Sonatype token password
  - `GPG_PRIVATE_KEY` - Signing key (armored)
  - `GPG_PASSPHRASE` - Key passphrase

For full setup instructions, see [docs/PUBLISHING_SETUP.md](docs/PUBLISHING_SETUP.md).

## Dependencies

Core (always included):
- `io.jsonwebtoken:jjwt-api:0.12.6`
- `com.github.ben-manes.caffeine:caffeine:3.1.8`

Provided (user brings):
- `spring-boot-starter-security`
- `spring-boot-starter-web`

## Naming Conventions

- **Services:** `Vigil{Function}Service` (e.g., `VigilTokenService`, `VigilPasswordService`)
- **Properties:** `VigilProperties`, nested records for modules
- **Filters:** `Vigil{Purpose}Filter` (e.g., `VigilAuthenticationFilter`)
- **Exceptions:** `Vigil{Error}Exception` (e.g., `VigilTokenExpiredException`)

## Testing

- Unit tests with JUnit 5, AssertJ, Mockito
- Integration tests with `@SpringBootTest`
- Test coverage enforced at 80%

## Git Workflow

- **Main branch:** main
- **Commit format:** Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`)
- **Releases:** Git tags trigger GitHub Actions publish workflow
