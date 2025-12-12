# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Overview

**Vigil** is an opinionated JWT authentication starter for Spring Boot. It eliminates boilerplate auth code by providing pre-configured JWT handling, password services, cookie management, and optional modules for multi-tenancy, token blacklisting, and brute-force protection.

## Project Information

- **Group ID:** io.github.sequelcore
- **Artifact ID:** vigil-spring-boot-starter
- **Version:** 1.0.0
- **License:** Apache 2.0
- **Java:** 21 LTS
- **Spring Boot:** 3.5.x

## Commands

```bash
# Build
./gradlew build

# Run tests
./gradlew test

# Code quality
./gradlew qualityCheck
./gradlew spotlessApply

# Publish to Maven Central (CI only - requires secrets)
./gradlew publishAllPublicationsToMavenCentralRepository
```

## Architecture

Single module with feature flags via `@ConditionalOnProperty`:

```
src/main/java/io/github/sequelcore/vigil/
├── autoconfigure/     # Spring Boot auto-configuration
├── core/
│   ├── jwt/           # Token generation, validation, claims
│   ├── password/      # BCrypt hashing, strength validation
│   └── cookie/        # Cookie creation, dual client support
├── filter/            # JWT authentication filter
├── blacklist/         # Token blacklist (Caffeine) - optional
├── protection/        # Login attempt tracking - optional
└── tenant/            # Multi-tenant context - optional
```

## Configuration

```yaml
vigil:
  jwt:
    secret: ${JWT_SECRET}    # Required (min 32 chars)
    access-ttl: 15m
    refresh-ttl: 7d
  filter:
    enabled: true
    public-paths:
      - /public/**
  blacklist:
    enabled: false
  tenant:
    enabled: false
  protection:
    enabled: false
```

## Code Standards

- **Formatting:** Google Java Format via Spotless
- **Style:** Google Checkstyle rules
- **Coverage:** 80% minimum (JaCoCo)
- **No wildcard imports**
- **Use Lombok:** `@Getter`, `@Builder`, `@RequiredArgsConstructor`
- **Use Java Records** for DTOs and configuration properties

## Publishing

Uses `com.vanniktech.maven.publish` plugin with Central Portal.

- **Registry:** Maven Central (Central Portal)
- **Plugin:** vanniktech/gradle-maven-publish-plugin v0.30.0
- **Secrets:** Doppler (sequel-core/prd)
  - `MAVEN_USERNAME` - Central Portal token username
  - `MAVEN_PASSWORD` - Central Portal token password
  - `GPG_PRIVATE_KEY` - Signing key (armored)
  - `GPG_PASSPHRASE` - Key passphrase

CI workflow maps Doppler secrets to Gradle properties:
- `ORG_GRADLE_PROJECT_mavenCentralUsername`
- `ORG_GRADLE_PROJECT_mavenCentralPassword`
- `ORG_GRADLE_PROJECT_signingInMemoryKey`
- `ORG_GRADLE_PROJECT_signingInMemoryKeyPassword`

## Naming Conventions

- **Services:** `Vigil{Function}Service`
- **Properties:** `VigilProperties`, nested records for modules
- **Filters:** `Vigil{Purpose}Filter`

## Testing

- Unit tests: 47 tests, 80%+ coverage
- Integration tests: 12 scenarios
- Framework: JUnit 5, AssertJ, Mockito

## Git Workflow

- **Main branch:** main
- **Commit format:** Conventional Commits
- **Releases:** Git tags (`v*`) trigger publish workflow
