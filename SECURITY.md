# Security Policy

## Supported Versions

Until a stable public support policy is adopted, only the current `main` branch receives security fixes.

## Reporting A Vulnerability

Do not open a public issue for vulnerabilities.

Report privately through GitHub Security Advisories when the repository is public, or directly to the Sequel maintainer when it is not. Include:

- affected version or commit;
- reproduction steps;
- impact assessment;
- whether tokens, signing keys, tenant identifiers, user claims, or reset tokens can leak;
- whether the issue affects HS256, RS256, cookie, bearer-token, tenant, blacklist, refresh, or reset-token flows;
- suggested fix, if known.

## Security Principles

Vigil must:

- validate token signatures and configured issuer/audience before trusting claims;
- require strong HS256 secrets and RSA key material at configuration boundaries;
- avoid logging or returning raw tokens, signing keys, reset tokens, or parser internals;
- expose stable client-facing authentication errors;
- keep JWT clock skew explicit and bounded;
- publish previous RS256 public keys only for verification during rotation;
- keep cookie defaults production-safe (`HttpOnly`, `Secure`, and explicit `SameSite`);
- keep user lifecycle and authorization decisions in the application;
- use an application-provided shared `VigilBlacklistBackend` bean for multi-instance revocation;
- consume step-up proofs atomically and bind them to tenant, audience, purpose, and TTL;
- never log PINs, PIN hashes, or step-up proof values;
- keep JWKS public-key exposure separate from private signing keys.

## Disclosure

Confirmed vulnerabilities should receive:

- a patched release or documented mitigation;
- release notes with affected versions and upgrade guidance;
- migration notes when public APIs or configuration change;
- a CVE request when severity and distribution justify it.
