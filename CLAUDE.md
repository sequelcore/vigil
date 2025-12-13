# CLAUDE.md

## Overview

**Vigil** - Opinionated JWT authentication for Spring Boot. Security by default, not by configuration.

## Project Info

| Field | Value |
|-------|-------|
| Group ID | io.github.sequelcore |
| Artifact ID | vigil-spring-boot-starter |
| Version | 1.0.0 |
| Java | 21 LTS |
| Spring Boot | 3.5.x |

## Commands

```bash
./gradlew build              # Build
./gradlew test               # Tests
./gradlew qualityCheck       # Spotless + Checkstyle + JaCoCo
./gradlew spotlessApply      # Format code
```

## Architecture

```
src/main/java/io/github/sequelcore/vigil/
├── autoconfigure/     # Spring Boot auto-configuration
├── core/
│   ├── jwt/           # Token generation, validation
│   ├── password/      # BCrypt hashing
│   └── cookie/        # Cookie management
├── filter/            # JWT auth filter
├── blacklist/         # Token blacklist (Caffeine)
├── protection/        # Brute-force protection
└── tenant/            # Multi-tenant context (optional)
```

## Security Philosophy

**Enabled by default** (can't accidentally deploy insecure):
- Auth filter
- Token blacklist (for real logout)
- Brute-force protection
- HttpOnly, Secure, SameSite cookies

**Configurable with ceilings** (NIST/OWASP limits):
- Access TTL: default 15m, max 60m
- Refresh TTL: default 7d, max 30d
- BCrypt cost: default 12, min 10

**Optional** (architecture-specific):
- Multi-tenant support

## Minimal Config

```yaml
vigil:
  jwt:
    secret: ${JWT_SECRET}
  filter:
    public-paths: [/auth/**, /public/**]
```

## Code Standards

- Google Java Format (Spotless)
- Google Checkstyle
- 80% coverage (JaCoCo)
- Lombok: `@Getter`, `@Builder`, `@RequiredArgsConstructor`
- Java Records for DTOs

## Naming

- Services: `Vigil{Function}Service`
- Properties: `VigilProperties` with nested records
- Filters: `Vigil{Purpose}Filter`

## Publishing

Maven Central via vanniktech plugin + Central Portal.

Secrets in Doppler (`sequel-core/prd`):
- `MAVEN_USERNAME` / `MAVEN_PASSWORD`
- `GPG_PRIVATE_KEY` / `GPG_PASSPHRASE`

## Reference Projects

- **SHRAD**: Multi-tenant JWT, cookie auth, BCrypt 12
- **Quesoro**: Token blacklist, login protection, dual client support
