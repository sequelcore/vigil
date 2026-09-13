# Contact enrollment integration

Vigil's enrollment module is a contact-proof primitive, not a registration controller. Enable it only after your application supplies `EmailCanonicalizer`, `EnrollmentIdentityPort`, `EnrollmentDeliveryPort`, `EnrollmentAbuseControl`, and a durable atomic `EnrollmentStore`.

```yaml
vigil:
  enrollment:
    enabled: true
    audience: my-enrollment-service
```

The default `OPAQUE_TOKEN` proof is suitable for an application-owned verification link. To send a
human-entered code instead:

```yaml
vigil:
  enrollment:
    enabled: true
    audience: my-enrollment-service
    proof-format: decimal-code
    code-hmac-key: ${ENROLLMENT_CODE_HMAC_KEY} # canonical Base64URL encoding of 32 random bytes
```

`DECIMAL_CODE` is exactly eight ASCII digits. Its TTL cannot exceed 15 minutes and its attempt
limit cannot exceed five. Use a dedicated HMAC key shared by every Vigil node; never reuse a JWT
key or store this key beside enrollment rows. A coordinated key change invalidates pending decimal
codes. A resend can rotate them only when the existing cooldown, resend, attempt, and lifetime
limits allow it; otherwise follow the host lifecycle expiry or retirement policy without resetting
budgets. Existing receipts remain recoverable without the key.

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

`EnrollmentDelivery` contains the proof format, original requested email for display/delivery, and
canonical email key. Use `proofFormat()` to select the host template; it does not transfer proof
policy to the adapter. Use the original address only for delivery, and the canonical key only for
storage, proof binding, and abuse policy. Do not log either email, the proof, its digest, or the code
HMAC key, and do not return them in generic request responses.

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

Verification is separately admitted through `EnrollmentAbuseControl` before proof hashing or store
access. The service accepts only the configured representation: a canonical 43-character Base64URL
token or an eight-character ASCII decimal code. Changing the configured format invalidates pending
proofs. Resend remains subject to the existing lifecycle limits, and duplicate start remains a
no-op; otherwise follow the host lifecycle expiry or retirement policy without resetting budgets.
The service never operates both formats concurrently. Decimal-code attempts remain cumulative
across resend. Application abuse
control must also prevent callers from bypassing that budget by creating unbounded contexts or
lifecycles. JWT reset tokens and other values are not interchangeable with enrollment proofs
because their digest and binding do not match.

An email change starts a new lifecycle with a new context version. `EnrollmentStore.start` treats
context ID, audience, and purpose as the stable enrollment identity and must atomically make the
new email/version lifecycle its only current lifecycle. Resend rotates only the current address and
generation; proofs and receipts from an earlier generation, address, or context version remain
invalid. Purpose and audience remain required proof bindings. Verification pages, redirects, and
callback destinations must come from trusted host configuration, never from enrollment request
parameters.

If host receipt application fails after verification, `recover` can retry the same receipt. Recovery cannot repair a missing, expired, superseded, or incorrectly implemented store record; hosts need an operational process to retry durable `VERIFIED_PENDING_APPLY` receipts.

## Migration

Vigil 8.0 removes the former convenience constructors. Direct `EnrollmentProperties` callers must
supply `proofFormat` and `codeHmacKey`; direct `EnrollmentDelivery` callers must supply
`proofFormat`. Configuration-bound applications keep `opaque-token` as the default. To adopt
enrollment, enable `vigil.enrollment`, set a
trusted audience, provide all five host-owned ports, and expose application-owned POST endpoints
for start, resend, verification, and any receipt recovery workflow. Do not enable the module with a
process-local store or advisory-only abuse control.
