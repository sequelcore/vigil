# Security model

## Security invariants

- Validate signed JWTs, configured issuer, and configured audience before trusting claims.
- Keep HS256 secrets at least 32 characters, generated from at least 256 bits of random entropy,
  and limit signing authority to trusted services.
- Prefer RS256 and JWKS where multiple services verify tokens but should not sign them.
- Use HTTP-only, Secure cookies over HTTPS for browser flows.
- Keep access tokens short-lived; use bounded clock skew only for known clock drift.
- Treat user storage, credential verification, business authorization, and recovery delivery as application responsibilities.
- Never log raw tokens, keys, PINs, credential hashes, reset tokens, step-up proof values,
  enrollment proofs, or full enrollment email addresses.

## Trust assumptions

Vigil trusts application-supplied credential validation, user lookup, and shared state adapters. A
custom `VigilBlacklistBackend` must preserve TTLs and make revocation state visible across nodes. A
custom `StepUpStore` must additionally consume proofs atomically.

An enabled `EnrollmentStore` must atomically create one verification receipt, retain it across host
apply failure, enforce generation-conditional delivery outcomes, and acknowledge completion only
for that receipt. `EnrollmentIdentityPort` must make receipt application transactional and
idempotent; Vigil deliberately does not issue an identity/session after email proof verification.
A repeated completion is only an idempotent acknowledgement. A receipt is durable evidence that
Vigil accepted the bound contact proof, not that the host applied it or granted credential
authority. Before a host submits a proof for a pending
password verifier, it must validate a server-protected, CSRF-bound registration ceremony and derive
the enrollment binding from that state. Without it, including cross-device proof presentation, it
must not call `verify` for that pending lifecycle; it may start an independent ceremony without
inheriting authority. An unauthenticated request cannot retire another ceremony. After
`COMPLETED`, a credential-finalizing host revalidates that ceremony and consumes any receipt-bound
permission first-write-wins. Keep
pending verifier and ceremony data out of logs, telemetry, support exports, and unnecessary
backups. Email equality never authorizes account linking; federated linking requires explicit host
proof of both identities. See [ADR 0004](../adr/0004-host-owned-pending-password-state.md).

Opaque enrollment tokens retain their domain-separated SHA-256 digest. Human-entered decimal codes
use HMAC-SHA-256 with a dedicated 32-byte key and bind the format, canonical email, context
ID/version, audience, and purpose into the MAC. This protects the small code space from offline
enumeration after a store-only disclosure; it does not replace the five-attempt lifecycle budget or
application-owned abuse controls. Every node must share the key, which must remain separate from
JWT signing material and absent from state, logs, errors, and metrics.

`VigilResetTokenService.validateAndConsume` invalidates a reset token after validation, but the current
blacklist contract does not provide an atomic consume operation. Applications that can process the
same reset token concurrently must serialize reset completion or enforce uniqueness in shared
storage. Do not treat reset tokens as equivalent to step-up proofs, whose store contract requires
atomic consumption.

## Step-up controls

Step-up proofs are opaque, 256-bit random values. Vigil stores a SHA-256 digest, binds the resulting authorization to a tenant, audience, purpose, identities, method, timestamps, and audit ID, and deletes it on successful consumption. Details are in [step-up authorization](step-up-authorization.md).

## Incident response

Follow the repository [security policy](../../SECURITY.md) for private vulnerability reporting. For signing-key compromise, rotate signing material, retain only verification keys needed for the maximum token lifetime, revoke affected sessions where the application can identify them, and publish a patched release through the guarded release workflow.
