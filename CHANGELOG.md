# Changelog

All notable changes to Vigil will be documented in this file.

Vigil follows semantic versioning for public releases. Breaking changes must
include migration notes.

## Unreleased

- No unreleased changes.

## 6.0.0 - 2026-06-05

- Hardened public release documentation with security, contribution, usage,
  release, roadmap, and changelog coverage.
- Added guarded manual Maven Central release automation with validation-only
  default behavior, exact release ref checks, explicit publish confirmation,
  protected release environment, and Doppler-backed runtime secret fetch.
- Added CodeQL security analysis.
- Updated CI to run the full `qualityCheck` gate.
- Sanitized invalid JWT parser errors so raw parser details are not exposed to
  clients.
- Added bounded JWT `clock-skew` configuration.
- Added RS256 public-key rotation through verification-only previous public
  keys and JWKS publication.
- Added auto-detection of application-provided `VigilBlacklistBackend` beans
  for shared multi-instance revocation storage.

## 5.0.1 - 2026-06-05

- Normalized escaped newline handling in inline PEM strings loaded from
  environment variables.
