# Java API contract

This guide names Vigil's public integration contracts. It is not generated Javadoc; public type Javadoc remains the source for exact method signatures.

## Authentication services

| Type | Consumer responsibility |
| --- | --- |
| `VigilAuthService` | Validate application credentials before issuing, refreshing, or revoking tokens. |
| `VigilTokenService` | Use only when a lower-level token integration is genuinely needed. |
| `VigilResetTokenService` | Deliver the token, serialize concurrent completion in application/shared storage, and update the password only after successful consumption. See the [security model](../security/security-model.md). |
| `VigilPasswordService` | Store its returned hash; own password policy and user persistence. |
| `VigilTenantContext` | Read the validated request tenant. |

## Step-up authorization

`StepUpAuthorizationService` implements this sequence:

1. `createChallenge(StepUpChallengeRequest)` binds intent to a current actor, tenant, audience, purpose, allowed methods, and self-authorization policy.
2. `authorize(challengeId, authorizingActorId, credential)` verifies a credential without changing the current session and returns an opaque proof.
3. `consume(proof, StepUpAuthorizationRequest)` atomically checks the binding and consumes the proof exactly once.

The returned `StepUpAuthorization` is evidence, not a business decision. See the full [step-up contract](../security/step-up-authorization.md).

## Contact enrollment

`EnrollmentService` is available only with `vigil.enrollment.enabled=true` and all five
application-owned ports. It exposes `start`, `resend`, `verify`, and `recover`; it creates no HTTP
route. Start/resend return a generic result and send no proof to their caller. `verify` and
`recover` create or reuse a durable `EnrollmentVerificationReceipt` before calling
`EnrollmentIdentityPort.applyVerifiedContact`. Host implementations must apply that receipt
transactionally and idempotently by receipt ID, while rechecking its context ID/version. An
`APPLIED` outcome reaches `COMPLETED`; an authoritative `REJECTED` outcome is durably terminal.
Exceptions and ambiguous outcomes remain recoverable rather than being marked complete. A
repeated `COMPLETED` result is an idempotent acknowledgement only; the host must consume any later
credential-enrollment permission first-write-wins by the receipt recorded in its identity
transaction.

`EnrollmentProofFormat` is the closed proof representation contract. `OPAQUE_TOKEN` remains the
default; `DECIMAL_CODE` is an opt-in eight-digit value. `EnrollmentDelivery.proofFormat()` lets the
application select its template without taking ownership of generation or validation. Both formats
use the same `proof` field and `EnrollmentService` operations; there are no parallel code-specific
methods or proof-strategy SPI.

Vigil 8.0 has one canonical constructor for each enrollment contract. Direct
`EnrollmentProperties` construction includes `proofFormat` and `codeHmacKey`, and direct
`EnrollmentDelivery` construction includes `proofFormat`. The configured format governs both
generation and verification; there is no cross-format transition fallback.

No enrollment API accepts a password or returns/creates a session, token, credential, or account
link. `EnrollmentStore` must provide the atomic operations named by its interface; it cannot be
implemented as a load/save repository or local lock. See
[ADR 0002](../adr/0002-opt-in-contact-enrollment.md) and
[ADR 0003](../adr/0003-opt-in-human-entered-enrollment-codes.md).

## Configuration

All configuration uses `vigil.*`. The canonical properties, defaults, and validation notes are in the [configuration reference](../reference/configuration.md).

## Error handling

Use Vigil's typed exceptions to map failures at an application HTTP boundary; do not expose their causes or credential data. `VigilAuthException` represents token and reset failures. `StepUpException` represents challenge, credential, lockout, proof, and binding failures. The application owns HTTP status, error-body format, localization, and audit logging.
