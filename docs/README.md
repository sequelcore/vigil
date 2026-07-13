# Vigil documentation

Vigil is a Spring Boot starter for application-owned JWT authentication. Read
[system boundaries](architecture/system-boundaries.md) before integrating it into an application.

## Start here

- [Authentication guide](guides/authentication.md) — configure JWTs, cookies, Spring Security, tenants, and reset tokens.
- [Async and streaming security](guides/async-streaming-security.md) — preserve stateless authentication across MVC redispatches.
- [Configuration reference](reference/configuration.md) — every `vigil.*` property and its defaults.
- [Compatibility reference](reference/compatibility.md) — certified platform and dependency versions.
- [System boundaries](architecture/system-boundaries.md) — understand ownership and extension points before integrating.
- [Java API contract](api/java-api.md) — public services, SPIs, and compatibility expectations.
- [Step-up proof decision](adr/0001-step-up-opaque-one-time-proofs.md) — why approvals are opaque and server-consumed.

## Security and operations

- [Security model](security/security-model.md) — security controls, threat assumptions, and secret-handling rules.
- [Step-up authorization](security/step-up-authorization.md) — one-time authorization proofs and personal PIN integration.
- [Deployment and operations](operations/deployment.md) — production configuration, key rotation, and multi-instance requirements.

## Development and releases

- [Testing and verification](development/testing.md) — local gates and integration coverage.
- [Release policy](releases/release-policy.md) — compatibility, versioning, and publication controls.

The root [README](../README.md) is the concise package landing page. This index is the canonical navigation surface for repository documentation.
