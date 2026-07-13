# Security model

## Security invariants

- Validate signed JWTs, configured issuer, and configured audience before trusting claims.
- Keep HS256 secrets at least 32 characters, generated from at least 256 bits of random entropy,
  and limit signing authority to trusted services.
- Prefer RS256 and JWKS where multiple services verify tokens but should not sign them.
- Use HTTP-only, Secure cookies over HTTPS for browser flows.
- Keep access tokens short-lived; use bounded clock skew only for known clock drift.
- Treat user storage, credential verification, business authorization, and recovery delivery as application responsibilities.
- Never log raw tokens, keys, PINs, credential hashes, reset tokens, or step-up proof values.

## Trust assumptions

Vigil trusts application-supplied credential validation, user lookup, and shared state adapters. A
custom `VigilBlacklistBackend` must preserve TTLs and make revocation state visible across nodes. A
custom `StepUpStore` must additionally consume proofs atomically.

`VigilResetTokenService.validateAndConsume` invalidates a reset token after validation, but the current
blacklist contract does not provide an atomic consume operation. Applications that can process the
same reset token concurrently must serialize reset completion or enforce uniqueness in shared
storage. Do not treat reset tokens as equivalent to step-up proofs, whose store contract requires
atomic consumption.

## Step-up controls

Step-up proofs are opaque, 256-bit random values. Vigil stores a SHA-256 digest, binds the resulting authorization to a tenant, audience, purpose, identities, method, timestamps, and audit ID, and deletes it on successful consumption. Details are in [step-up authorization](step-up-authorization.md).

## Incident response

Follow the repository [security policy](../../SECURITY.md) for private vulnerability reporting. For signing-key compromise, rotate signing material, retain only verification keys needed for the maximum token lifetime, revoke affected sessions where the application can identify them, and publish a patched release through the guarded release workflow.
