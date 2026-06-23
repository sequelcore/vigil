# Roadmap

Vigil handles token lifecycle, not user lifecycle. The roadmap should keep that
boundary intact.

Completed work is tracked in `CHANGELOG.md`. This document only describes the
current supported scope and future candidates.

## Current Scope

- Java 25 and Spring Boot 4.1.x.
- HS256 JWT signing with minimum 256-bit secret validation.
- RS256 JWT signing with JWKS publication.
- RS256 public-key rotation through verification-only previous keys.
- Access and refresh token generation, validation, and refresh rotation.
- HTTP-only cookie profiles for browser clients.
- Bearer token flows for native clients and APIs.
- Token and subject invalidation through `VigilBlacklistService`.
- Application-provided shared `VigilBlacklistBackend` beans for multi-instance
  revocation storage.
- Spring Security authentication filter integration.
- Tenant context validation.
- Guest session hooks.
- BCrypt password helpers and single-use reset tokens.

Vigil does not claim OAuth authorization-server support, OIDC provider support,
hosted identity management, user storage, credential validation ownership, MFA
or delivery-channel ownership, or application authorization policy.

## Candidate Work

Future work must stay within Vigil's token lifecycle boundary:

- packaged Redis blacklist backend adapter as an optional integration module;
- ES256 signing through the existing `TokenSigner` extension point;
- DPoP proof-of-possession support if the API boundary can stay small;
- additional reset-token or session hardening driven by real application use.

Do not add these before a release unless they are release-blocking. New features
need tests and docs when they change architecture or public contracts.

## Release Discipline

Every completed roadmap slice must update:

- `CHANGELOG.md` for user-visible changes;
- `docs/usage-guide.md` when behavior or configuration changes;
- `docs/release.md` when release policy changes;
- the relevant public guide when the architecture boundary changes.
