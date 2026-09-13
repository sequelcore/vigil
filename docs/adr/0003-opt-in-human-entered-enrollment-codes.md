# ADR 0003: Add a closed opt-in enrollment proof format

**Status:** Accepted
**Date:** 2026-09-12

## Context

The original enrollment proof is a 256-bit Base64URL token intended for an
application-owned verification link. The host flow already prevents mail scanners from consuming
that proof by using GET only to render a page and an explicit POST to verify. Some applications also
need deliberate manual entry, particularly when enrollment begins and email is read on different
devices.

A short code cannot safely reuse the token's unkeyed SHA-256 digest: anyone who obtains the store
can enumerate a small decimal keyspace. Allowing hosts to supply arbitrary proof strategies would
also move generation and validation policy outside Vigil and create a public extension surface
without a second demonstrated format.

## Decision

Vigil provides one closed `EnrollmentProofFormat` choice configured by
`vigil.enrollment.proof-format`:

- `OPAQUE_TOKEN` is the default link representation: a 32-byte canonical Base64URL value with a
  version-one domain-separated digest.
- `DECIMAL_CODE` is opt-in and contains exactly eight uniformly generated ASCII digits, including
  leading zeroes. It has approximately 26.58 bits of effective entropy.

Decimal codes use HMAC-SHA-256 with a dedicated, canonical 32-byte Base64URL key from
`vigil.enrollment.code-hmac-key`. The MAC input uses a versioned domain and unambiguous
length-prefixed encoding of the proof format, canonical email, context ID/version, trusted
audience, purpose, and code. The key must not be stored with enrollment state, logged, returned, or
silently derived from a JWT key.

The existing proof TTL, total lifetime, resend limit, cooldown, attempt counter, atomic receipt,
and recovery lifecycle remain canonical. Decimal-code TTL is at most 15 minutes and its attempt
limit is at most five. Attempts remain cumulative across resend. A resend replaces the current
digest without extending total lifetime, so a prior generation no longer verifies.

Rotation invalidates the stored prior generation, but finite random representations can
theoretically repeat. If a newly generated decimal code equals an earlier value, the text is a new
proof for the current generation and cannot be distinguished from the old text. Vigil accepts this
quantified probability rather than adding a challenge identifier, durable proof history, or a
two-phase generation protocol solely to promise absolute textual uniqueness.

`EnrollmentDelivery.proofFormat()` tells the application how to render the secret. The delivery
port still owns provider, template, link, route, and UI concerns. Public start, resend, verify,
store, receipt, and recovery operations do not gain parallel code-specific variants. The configured
format governs both generation and verification; another representation is rejected without a
migration fallback.

## Alternatives

1. **Keep opaque tokens only.** This remains suitable when an explicit interstitial solves the
   application's mail-prefetch concern, but it does not provide manual entry.
2. **Add the closed opt-in format.** Selected because Vigil keeps proof policy and hosts gain the
   required presentation with no second lifecycle.
3. **Expose a proof strategy SPI.** Rejected because it permits inconsistent entropy, digest, and
   validation policy while adding permanent API complexity without evidenced consumers.

## Consequences

- Changing the configured format invalidates pending proofs. A deployment may resend only within
  the existing lifecycle limits; otherwise the host must follow its lifecycle expiry or retirement
  policy without resetting budgets. Both representations are never accepted concurrently.
- The store continues to receive a 32-byte digest encoded as 43-character Base64URL; no new store
  command, schema field, or lifecycle state is required.
- Every node generating or verifying decimal codes needs the same dedicated key. Rotating or
  removing it invalidates pending decimal codes; a coordinated resend remains subject to the
  existing cooldown, resend, attempt, and lifetime limits. Receipt recovery does not require the
  proof key.
- Eight digits and five lifecycle-wide attempts bound a uniform online guess to at most
  `5 / 100,000,000` before application-owned abuse controls across addresses, contexts, and network
  sources.
- A code confirms access to a contact channel only. It creates no credential, session, membership,
  account link, or authorization.

The control baseline is informed by
[NIST SP 800-63A-4 confirmation codes](https://pages.nist.gov/800-63-4/sp800-63a/ial-general/#requirements-for-confirmation-codes),
whose identity-proofing scope permits manual numeric or printable codes of at least six decimal
digits, requires approved randomness and one-time use, and caps email delivery at 24 hours.
