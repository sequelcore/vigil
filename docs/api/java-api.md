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

## Configuration

All configuration uses `vigil.*`. The canonical properties, defaults, and validation notes are in the [configuration reference](../reference/configuration.md).

## Error handling

Use Vigil's typed exceptions to map failures at an application HTTP boundary; do not expose their causes or credential data. `VigilAuthException` represents token and reset failures. `StepUpException` represents challenge, credential, lockout, proof, and binding failures. The application owns HTTP status, error-body format, localization, and audit logging.
