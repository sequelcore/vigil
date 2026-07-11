# Step-up authorization

This is Vigil's canonical guide for the reusable step-up authorization contract. Start with the [system boundaries](../architecture/system-boundaries.md) when deciding whether a responsibility belongs in Vigil or the consuming application.

Vigil's step-up API verifies a second (or, when the application explicitly allows it, the same) actor in an already-authenticated flow. It never creates, replaces, refreshes, or clears the current actor's session.

The feature is intentionally generic: Vigil verifies a credential and produces evidence; the consuming application decides which business operation needs that evidence and evaluates its roles, permissions, limits, and separation-of-duties rules.

## Flow

1. The application's backend obtains the current actor and tenant from its authenticated request.
2. It calls `createChallenge`, binding an audience and purpose such as `admit-api` and `refund`.
3. The local UI collects the authorizing actor identifier and credential, then submits them once to the application's backend.
4. The backend calls `authorize` and returns the opaque proof to the UI. No Vigil session is altered.
5. The business backend calls `consume` with the expected tenant, audience, and purpose immediately before its state transition.

`consume` is one-time: successful consumption atomically deletes the proof. The returned `StepUpAuthorization` records the current actor, authorizing actor, method, timestamps, and a correlation-safe `auditId`.

```java
StepUpChallenge challenge = stepUp.createChallenge(new StepUpChallengeRequest(
    currentActor.id(), tenantId, "admit-api", "refund", false, Set.of(StepUpMethod.PIN)));

try (PinCredential pin = new PinCredential(request.pinCharacters())) {
  StepUpAuthorizationProof proof = stepUp.authorize(challenge.id(), request.supervisorId(), pin);
  // Return proof.value() only to the local flow; never log or persist it client-side.
}

StepUpAuthorization approval = stepUp.consume(
    request.proof(), new StepUpAuthorizationRequest(tenantId, "admit-api", "refund"));
// Application now evaluates its own supervisor permissions and performs the refund transaction.
```

Vigil has no HTTP controller for this flow. Applications own their routes, request DTOs, CSRF posture, business authorization, and audit decision. This prevents POS or product vocabulary from entering the starter.

## PINs

Implement `PinCredentialStore` with the application's tenant-scoped user persistence, then register a `PinStepUpCredentialVerifier` bean. `VigilPinService` enrolls, rotates, revokes, validates, and BCrypt-hashes personal numeric PINs; only `PinCredentialRecord.hash` is stored.

```java
@Bean
PinStepUpCredentialVerifier pinVerifier(PinCredentialStore store, VigilPinService pins) {
  return new PinStepUpCredentialVerifier(store, pins);
}
```

PIN configuration is deliberately separate from password policy:

```yaml
vigil:
  step-up:
    challenge-ttl: 2m
    proof-ttl: 5m
    max-size: 10000
    pin:
      min-length: 6
      max-length: 12
      bcrypt-strength: 12
      reject-common-patterns: true
```

Do not deserialize a PIN into an immutable `String` if the application can avoid it. Use a short-lived `char[]`, construct `PinCredential`, and close it as shown. Vigil never logs credentials, proof values, hashes, or verification exceptions.

## Operations and multi-instance deployments

The default `CaffeineStepUpStore` is suitable only for a single application instance. A cluster must provide one shared `StepUpStore` whose challenge and proof consumption are atomic across nodes. Store only the SHA-256 digest of the opaque proof, preserve expiry, and retain a used-proof marker through the proof TTL to return `PROOF_ALREADY_USED` deterministically.

The existing `VigilProtectionService` applies failed-attempt counters and lockout per `{tenant}:step-up:{authorizingActor}`. For clustered brute-force protection, applications should already replace or front this in-memory mechanism with shared rate limiting; otherwise lockouts are node-local.

## Threat model

| Threat | Control |
| --- | --- |
| Proof replay | 256-bit opaque proof, server-side digest storage, atomic one-time consumption |
| Cross-service reuse | exact tenant, audience, and purpose binding |
| Stale approval | independent short challenge and proof TTLs |
| PIN guessing | BCrypt, configurable numeric policy, failed-attempt counter and lockout |
| Session substitution | no cookie, JWT, or `SecurityContext` mutation by this API |
| Secret exposure | no PIN/hash/proof logging; close `PinCredential` promptly |
| Distributed races | required shared store with atomic consume for multi-instance deployments |

The design follows the principle behind audience-restricted, replay-resistant tokens in [RFC 9700](https://www.rfc-editor.org/info/rfc9700/) and NIST's requirement to rate-limit low-entropy activation secrets in [SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html). A future credential verifier can support origin-bound public-key credentials such as [WebAuthn](https://www.w3.org/TR/webauthn-3/); WebAuthn is not implemented by Vigil today.

## Migration

Replace product endpoints that directly compare a supervisor PIN with this sequence:

1. Move the personal PIN hash to tenant-scoped application storage behind `PinCredentialStore`.
2. Enroll or rotate it through `VigilPinService`; revoke by writing a revoked record.
3. Replace direct comparison with `createChallenge` and `authorize`.
4. Require `consume` inside the business transaction before the sensitive transition.
5. Record the returned `auditId` and both actor IDs in the application's business audit trail.

Do not accept a user ID, role, or boolean approval flag in place of a consumed proof, and do not make a proof reusable for a batch of actions.
