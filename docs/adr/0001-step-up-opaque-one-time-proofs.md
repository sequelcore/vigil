# ADR 0001: Use opaque, one-time proofs for step-up authorization

**Status:** Accepted
**Date:** 2026-07-10

## Context

An application may need a recently verified second actor to approve a sensitive action while preserving the current actor's session. The evidence must be scoped to the application operation, expire quickly, and resist replay across routes and service instances.

Embedding approval claims in the current actor's access token would mutate or conflate identities. A self-contained signed approval JWT would still require shared replay state to guarantee one-time use and would expose authorization metadata to clients.

## Decision

Vigil issues a 256-bit opaque proof after a successful step-up credential verification. It stores only the SHA-256 digest and authorization evidence server-side. The business backend consumes the proof atomically with an exact tenant, audience, and purpose binding.

The API remains credential-neutral through `StepUpCredentialVerifier`. PIN is the first verifier; applications provide personal PIN storage through `PinCredentialStore`. Vigil does not evaluate the business policy that decides whether an approval is required or sufficient.

## Consequences

- A proof cannot be independently validated offline; the consuming backend needs access to the same `StepUpStore`.
- Multi-instance deployments must provide a shared store with atomic consume semantics.
- The current actor's session, cookie, token, and `SecurityContext` remain unchanged.
- The consuming application can record both actors and Vigil's `auditId` with its business decision.
- Future authenticators such as passkeys can reuse the same proof lifecycle without changing product integrations.

See [step-up authorization](../security/step-up-authorization.md) for integration and security details.
