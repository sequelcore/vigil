# ADR 0004: Keep pending password state host-owned and ceremony-bound

**Status:** Accepted
**Date:** 2026-09-13

## Context

Contact enrollment proves control of an email address. It does not prove that the person who
completed the proof chose a previously submitted password, nor does it establish account-linking
authority. Activating an attacker-supplied pending password after a victim completes an email proof
enables pre-account hijacking.

Hosts need different form orders. Some collect a password after contact verification; others
collect it before sending or entering the proof. Vigil must remain neutral to that presentation
choice while keeping contact verification separate from credential activation. A receipt is durable
evidence that Vigil accepted the bound contact proof; it is not evidence that the host applied the
contact or of the host registration ceremony, user intent, or credential authority.

## Decision

The host may collect a password before or after verification. A pre-verification value may be kept
only as a protected, inert pending password verifier in host registration state. It is unavailable
to authentication, recovery, session issuance, account linking, and every other credential path.

For a registration with a pending verifier, the host issues and rotates a cryptographically random,
unguessable ceremony secret that the client cannot choose or fix. The secret is independent of and
not derivable from the email, context, version, or proof, and must not travel in the verification
email. The host stores the registration binding server-side and requires the secret with CSRF
protection on the explicit verification POST. Host state, not client request parameters, supplies
canonical email, context ID, and context version.

Every host entry point that can call `EnrollmentService.verify` for pending password state must
first validate the ceremony secret and CSRF protection, load the matching server-side registration
binding, and require the user's explicit completion intent in that ceremony. Only then may it
present the proof to Vigil. This makes proof presentation and intent part of the same host
ceremony. A proof, receipt, email, link, browser state, `contextId`, or `contextVersion` alone never
establishes continuity.

If the ceremony is missing or invalid, including cross-device completion, the host must not call
`verify` or finalize that pending lifecycle. It may begin an independent registration on the
current device with a new context ID and version, a fresh password, a new ceremony secret, and a
new proof, without inheriting proof, receipt, verifier, or finalization state. An unauthenticated
request must not retire another ceremony merely by naming its email or context; the old pending
state is retired only by authorized host action or bounded expiry and cleanup policy.

`EnrollmentIdentityPort.applyVerifiedContact(receipt)` remains contact-only. Its host transaction
rechecks the receipt binding and applies verified contact state. A host that supports credential
finalization may also record a receipt-bound finalization permission, based on prior admission of
the valid ceremony. It never creates or activates a credential, session, token, or account link.
`APPLIED` means the host applied the receipt; Vigil acknowledges `COMPLETED` only after that result.
The receipt remains evidence of proof acceptance, and `COMPLETED` is Vigil's lifecycle
acknowledgement rather than independent credential authority.

After `COMPLETED`, a credential-finalizing host revalidates the ceremony and current registration
binding, then atomically consumes its receipt-bound permission and activates the credential
first-write-wins. A contact-only host has no credential-finalization permission to record or
consume. Distinct receipts targeting the same host registration or account must also compete on
the host's identity/registration uniqueness invariant, so concurrent activation and replay cannot
replace a credential or create another session.

The host invalidates pending verifiers and finalization permissions on expiry, authorized
abandonment or cancellation, supersession, email/context-version/password change, or an outdated
password-cost policy. Recovery may retry the same receipt application, but does not authenticate a
ceremony, grant credential authority, or reactivate invalidated pending state. Pending verifiers
and ceremony evidence have bounded retention and are excluded from logs, telemetry, analytics,
support exports, and unnecessary backups. Restoring a backup must not reactivate expired,
consumed, or invalidated state.

Email equality never authorizes linking to an existing account. A social or federated identity is
linked only after the host proves control of both the current account and the stable provider
identity under its own linking policy.

Proof transport does not change these rules:

- `OPAQUE_TOKEN` may use a GET interstitial followed by an explicit POST. A link opened on another
  device lacks the host ceremony unless the host can validate it before verification.
- `DECIMAL_CODE` uses a host form and explicit POST. Entering a code in the same browser is not
  proof of continuity or intent.

## Consequences

- Vigil retains no password, verifier, ceremony, session, account, or linking state. Its API and
  runtime lifecycle are unchanged.
- Hosts can offer either form order without treating a verified email as a credential capability.
- Host integration tests must prove rejected ceremony secrets do not invoke verification or activate
  pending state, valid ceremonies complete, and cross-device attempts restart without inheritance.

## Alternatives

1. **Require password capture only after verification.** Safe, but unnecessarily constrains hosts
   that need to collect it earlier.
2. **Validate continuity only when activating a credential.** Rejected because an invalid ceremony
   would already have consumed or completed the pending contact lifecycle.
3. **Validate a protected host ceremony before proof verification.** Selected because it prevents
   an attacker or cross-device user from advancing another ceremony's lifecycle.

This decision is informed by the pre-account-takeover analysis in
[USENIX Security 2022](https://www.usenix.org/system/files/sec22-sudhodanan.pdf). Vigil's
contact-only boundary remains defined by [ADR 0002](0002-opt-in-contact-enrollment.md), and proof
representation by [ADR 0003](0003-opt-in-human-entered-enrollment-codes.md).
