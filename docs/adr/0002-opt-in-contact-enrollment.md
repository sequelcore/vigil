# ADR 0002: Keep self-service enrollment contact-only and host-owned

**Status:** Accepted
**Date:** 2026-09-12

## Context

Applications need a reusable email-verification primitive during self-service enrollment, but they own user records, context/version checks, authorization policy, email infrastructure, and any credentials or sessions. A starter-provided route, user table, mail provider, or in-memory store would blur those boundaries and fail under multi-instance delivery and verification races.

## Decision

Vigil exposes a route-free `io.github.sequelcore.vigil.enrollment` module only when `vigil.enrollment.enabled=true`. It creates no bean, route, provider dependency, or table by default, and it supplies no storage or delivery implementation when enabled.

An application must supply all five ports: `EmailCanonicalizer`, `EnrollmentIdentityPort`, `EnrollmentDeliveryPort`, `EnrollmentAbuseControl`, and a durable atomic `EnrollmentStore`. Missing ports fail startup. `EnrollmentIdentityPort.applyVerifiedContact(receipt)` must be transactional, receipt-ID idempotent, and recheck the opaque context ID/version before changing application state.

The default proof is a 256-bit Base64URL value whose domain-separated SHA-256 digest is persisted
through the store. [ADR 0003](0003-opt-in-human-entered-enrollment-codes.md) adds a closed opt-in
decimal-code representation with a keyed digest without changing this lifecycle or its default.
Every proof is bound to the fixed enrollment purpose, configured trusted audience, canonical email
key, host context ID/version, generation, proof TTL, and total lifecycle. The store, rather than a
process-local lock, atomically handles start/resend, receipt creation, delivery outcomes, and
completion acknowledgment.

The original requested email is retained separately only for the delivery adapter; the canonical
email is the storage, proof-binding, and abuse-control key. A duplicate start for an active
lifecycle is a no-op and cannot reset its lifetime, attempts, resend count, generation, or
cooldown. Verification itself is admitted fail-closed before proof hashing or store access and
accepts only a canonical configured proof representation.

Context ID, audience, and purpose form the stable enrollment identity. Email and context version
are mutable bindings: an atomic start with either changed supersedes every earlier lifecycle for
that stable identity, including replay and recovery visibility, before the new proof is current.

Verification is contact-only. It never accepts a password, creates a session/token/credential, or auto-links users by email. It moves `PENDING` to `VERIFIED_PENDING_APPLY` by creating one durable receipt, invokes the host identity transaction outside the store transaction, and then acknowledges `COMPLETED` only after an `APPLIED` result. An authoritative host `REJECTED` result is durably settled terminally; an exception or ambiguous result retains the same receipt for `recover`, whose retry cannot mint another receipt.

## Consequences

- Applications implement a durable shared store with conditional generation updates, resend cooldown/count/total-lifetime enforcement, proof attempt limits, and replay-safe receipt creation. An in-memory store is intentionally absent.
- A test-only PostgreSQL contract fixture verifies atomic receipt creation through independent JDBC adapter instances and connections. It is not a published schema or production adapter; hosts remain responsible for validating their own storage implementation.
- Delivery happens outside a transaction. Retryable failures retain a pending proof; permanent failures may invalidate only the current generation; late outcomes must be conditional on generation.
- Request-facing start/resend responses are deliberately generic and never contain a proof. Delivery adapters receive the proof and must avoid logging it or full email addresses.
- This is an email-contact verification primitive, not hosted registration, password enrollment, account linking, or an authentication/authorization service.
- Hosts use GET only to render a verification page and an explicit POST to consume a proof. They persist a fresh password only after `COMPLETED`; existing accounts are never auto-linked by Vigil. `recover` retries a durable pending receipt but cannot repair a lost/expired store record.
- A repeated `COMPLETED` result is idempotent acknowledgement, not renewed authority. Host password
  completion is first-write-wins by the receipt recorded in the identity transaction, so replay or
  concurrent requests cannot replace a credential or mint another session.
