# Changelog

All notable changes to Vigil will be documented in this file.

Vigil follows semantic versioning for public releases. Breaking changes must
include migration notes.

## Unreleased

- Added generic step-up authorization: short-lived, opaque, one-time proofs bound to tenant,
  audience, purpose, current actor, authorizing actor, method, and audit ID without mutating the
  current session.
- Added extensible credential verifier and shared-state SPIs, plus personal numeric PIN support
  with BCrypt hashing, configurable policy, rotation/revocation helpers, lockout reuse, and
  single-node Caffeine defaults.
- Added step-up integration, security, migration, and multi-instance deployment documentation.
- Reorganized the public documentation around a canonical index, architecture, API contracts,
  security, operations, development verification, and release guidance.
- Consolidated duplicated integration and configuration prose into a concise package README, a
  task-focused authentication guide, and one configuration reference.

- Certified Vigil for Spring Boot 4.1.x, Spring Framework 7.x, Spring Security
  7.1.x, Java 25, Gradle 9.1.x, and Jackson 3.
- Updated build tooling to Spring Boot 4.1.0, Java 25 toolchains, Gradle 9.1.0,
  JaCoCo 0.8.14, Checkstyle 13.6.0, and google-java-format 1.28.0.
- Added starter auto-configuration compatibility tests that prove Vigil core
  beans load without product-owned user lifecycle beans.
- Migrated Vigil's JSON entry point constructor from Jackson 2
  `com.fasterxml.jackson.databind.ObjectMapper` to Jackson 3
  `tools.jackson.databind.ObjectMapper`.
- Updated integration tests for Spring Boot 4's `spring-boot-resttestclient`
  package and explicit test client auto-configuration.
- Recommended a new `7.0.0` release for Spring Boot 4.1 consumers. Vigil
  `6.0.x` was the final Spring Boot 3.5 / Java 21 line, not a
  backward-compatibility target for `7.0.x`.

## 6.0.0 - 2026-06-05

- Hardened public release documentation with security, contribution, usage,
  release, roadmap, and changelog coverage.
- Added guarded manual Maven Central release automation with validation-only
  default behavior, exact release ref checks, explicit publish confirmation,
  protected release environment, and Doppler-backed runtime secret fetch.
- Added CodeQL security analysis.
- Updated CI to run the full `qualityCheck` gate.
- Sanitized invalid JWT parser errors so raw parser details are not exposed to
  clients.
- Added bounded JWT `clock-skew` configuration.
- Added RS256 public-key rotation through verification-only previous public
  keys and JWKS publication.
- Added auto-detection of application-provided `VigilBlacklistBackend` beans
  for shared multi-instance revocation storage.

## 5.0.1 - 2026-06-05

- Normalized escaped newline handling in inline PEM strings loaded from
  environment variables.
