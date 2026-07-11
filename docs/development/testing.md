# Testing and verification

## Required local gate

Run from the repository root:

```bat
gradlew.bat qualityCheck --no-daemon
gradlew.bat build --no-daemon
```

`qualityCheck` runs formatting, Checkstyle, unit/integration tests, and the JaCoCo coverage threshold. Run focused tests first while iterating:

```bat
gradlew.bat test --tests io.github.sequelcore.vigil.stepup.StepUpAuthorizationServiceTest --no-daemon
```

## Behavioral coverage

Changes must prove the behavior at the owning boundary:

- token parsing and signing: algorithm, claims, issuer, audience, expiration, and rotation;
- filter behavior: protected, anonymous, ignored, invalid-token, and tenant-mismatch paths;
- shared-state behavior: blacklist, reset tokens, sessions, and replay-sensitive state;
- step-up: actor separation, credential failure/lockout, tenant/audience/purpose binding, expiry, and one-time consumption;
- configuration: invalid security settings fail fast at startup.

Use application integration tests for application-owned routes and user persistence. Vigil tests do not replace product authorization or user-lifecycle tests.
