# Contact enrollment integration

Vigil's enrollment module is a contact-proof primitive, not a registration controller. Enable it only after your application supplies `EmailCanonicalizer`, `EnrollmentIdentityPort`, `EnrollmentDeliveryPort`, `EnrollmentAbuseControl`, and a durable atomic `EnrollmentStore`.

```yaml
vigil:
  enrollment:
    enabled: true
    audience: my-enrollment-service
```

## Host flow

1. A host `POST` start or resend endpoint calls `EnrollmentService.start` or `resend` and always returns the same generic response, whether the request is suppressed, an account exists, or delivery has a retryable failure.
2. A `GET` verification-link endpoint only renders the host page. It must not consume the proof.
3. An explicit host `POST` submits email, opaque context ID/version, and proof to `verify`. The service applies a verified receipt through the host identity transaction before returning `COMPLETED`.
4. Only after `COMPLETED` may the host open a host-owned password-enrollment step. Persist the
   credential with a first-write-wins transaction keyed by the receipt recorded by
   `applyVerifiedContact`; replay or concurrent requests for that receipt must not replace it.

Enrollment has no session, cookie, token, or credential-issuance API. The host must invalidate or
keep untrusted every credential and session established before proof, and keep its existing session
policy independent of this contact-only lifecycle.

`EnrollmentDelivery` contains both the original requested email for display/delivery and the canonical email key. Use the original address only in the delivery adapter; use the canonical key only for storage, proof binding, and abuse policy. Do not log either value, and do not return either in generic request responses.

The host owns one canonicalization policy and must use it consistently for enrollment, login, and
recovery. Preserve the original address separately, and do not add provider-specific dot removal,
plus-address rewriting, or other transformations that can merge distinct mailboxes.

Existing accounts are not linked by Vigil. The host's `EnrollmentIdentityPort` rechecks its context/version in its transaction and returns `APPLIED` or an authoritative `REJECTED` outcome. `APPLIED` is receipt-ID idempotent and reaches `COMPLETED`; `REJECTED` is durably settled terminally and cannot enter an endless recovery loop. It must not treat a verified email alone as authority to attach a contact to an existing account. Exceptions and ambiguous outcomes remain `PENDING_RECOVERY` for retry.

## Store and recovery requirements

The store is a production integration responsibility. It must make each named `EnrollmentStore` operation durable and atomic across processes; Vigil includes no shared-storage adapter. The test suite contains a non-production PostgreSQL Testcontainers contract fixture that races two independent JDBC adapter instances/connections and proves one durable receipt ID. That fixture is evidence for the contract design only; it does not validate a host's production schema, lock behavior, retries, or adapter.

`total-lifetime` is the hard validity cutoff for the complete lifecycle: duplicate start and resend
cannot extend it, and neither resend nor verification succeeds at or after the cutoff. Physical
cleanup of expired and terminal rows is host-owned and must follow a bounded retention policy;
cleanup must never extend proof validity or recreate credential-enrollment permission.

A duplicate start for an active lifecycle must be a no-op: it cannot reset the original start/total-expiry, attempts, resend count, proof generation, or cooldown. Resend rotates only the current generation. Delivery outcomes must include the complete lifecycle binding and be conditional on lifecycle ID and generation, so a late result cannot invalidate a later lifecycle with the same email/context.

Verification is separately admitted through `EnrollmentAbuseControl` before proof hashing or store access. The service accepts only a canonical 43-character Base64URL, no-padding encoding of 32 random bytes. JWT reset tokens and other opaque values are not interchangeable with enrollment proofs because their domain-separated digest and binding do not match.

An email change starts a new lifecycle with a new context version. `EnrollmentStore.start` treats
context ID, audience, and purpose as the stable enrollment identity and must atomically make the
new email/version lifecycle its only current lifecycle. Resend rotates only the current address and
generation; proofs and receipts from an earlier generation, address, or context version remain
invalid. Purpose and audience remain required proof bindings. Verification pages, redirects, and
callback destinations must come from trusted host configuration, never from enrollment request
parameters.

If host receipt application fails after verification, `recover` can retry the same receipt. Recovery cannot repair a missing, expired, superseded, or incorrectly implemented store record; hosts need an operational process to retry durable `VERIFIED_PENDING_APPLY` receipts.
