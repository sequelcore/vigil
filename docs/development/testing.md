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

Async security changes additionally require the real filter chain tests in
`VigilAsyncSecurityIntegrationTest` and the embedded-Tomcat socket tests in
`VigilSseDisconnectTomcatIntegrationTest`. The latter verifies a committed SSE response, a client
RST followed by `IOException`, final `ASYNC` processing, `ERROR` dispatch, callback cleanup, and
the absence of a secondary authentication entry point or access-denied response.

The certified dependency combination is resolved by the Spring Boot BOM in `build.gradle.kts`.
Documentation must name the exact versions exercised by the full gate; an untested `4.1.x`, `7.x`,
or `7.1.x` range is not a supported compatibility claim.

Use application integration tests for application-owned routes and user persistence. Vigil tests do not replace product authorization or user-lifecycle tests.
