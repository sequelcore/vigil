# Vigil

JWT authentication infrastructure for Spring Boot applications.

[![Maven Central](https://img.shields.io/maven-central/v/io.github.sequelcore/vigil-spring-boot-starter.svg)](https://central.sonatype.com/artifact/io.github.sequelcore/vigil-spring-boot-starter)

Vigil provides JWT lifecycle, request authentication, cookie helpers, tenant consistency,
revocation, reset tokens, and reusable step-up credential verification. Applications retain
ownership of users and business authorization; the complete boundary is documented in
[system boundaries](docs/architecture/system-boundaries.md).

An optional, route-free contact-enrollment primitive is also available for applications that
provide durable storage, email delivery, identity application, canonicalization, and abuse-control
ports. It never creates credentials or sessions; see the [enrollment decision](docs/adr/0002-opt-in-contact-enrollment.md).

## Compatibility

Vigil `9.0.0` is certified with Java 25 and Spring Boot 4.1.1. See the
[compatibility reference](docs/reference/compatibility.md) for the complete tested combination.

`9.0.0` is the current release line. Public consumers should pin an exact version and review the release notes before upgrading.

## Install

```kotlin
dependencies {
    implementation("io.github.sequelcore:vigil-spring-boot-starter:9.0.0")
}
```

The application supplies Spring Web, Spring Security, JWT signing configuration, and its `SecurityFilterChain`.

## Minimal integration

```yaml
vigil:
  jwt:
    secret: ${JWT_SECRET}
    issuer: my-service
    audience: my-api
```

Follow the complete [authentication guide](docs/guides/authentication.md) to install the filter,
request-scoped security repository, stateless session policy, and application authorization rules.
`ignored-paths` skips Vigil processing; it does not grant anonymous access.

## Password-login guard

`PasswordLoginGuard` is the single owner of failed-attempt protection in Vigil. The application
keeps its login route, user lookup, and account status; the guard adds per-identifier lockout with
backoff, equal-cost verification for unknown users, and a result that does not reveal why a login
failed. Step-up PIN verification uses the same `LoginPolicy` and `LoginAttemptStore` under a
separate key namespace, so a PIN lock and a password lock are independent.

Vigil auto-configures `LoginPolicy` (from `vigil.login.*`), a node-local `LoginAttemptStore`, and
the `PasswordLoginGuard`; an application replaces any of them by declaring its own bean. Clusters
must supply a shared `LoginAttemptStore`. See
[password-login protection](docs/security/login-protection.md).

```yaml
vigil:
  login:
    max-failures: 5
    base-lock: 1m
    max-lock: 15m
```

```java
@PostMapping("/auth/login")
ResponseEntity<?> login(@RequestBody LoginRequest request, HttpServletResponse response) {
  LoginResult result = guard.authenticate(request.email(), request.password(),
      email -> users.findByEmail(email)
          .map(u -> new LoginAccount(u.id().toString(), u.passwordHash(), u.enabled())));
  if (!result.authenticated()) {
    return ResponseEntity.status(401).body("Invalid credentials"); // same for every cause
  }
  return ResponseEntity.ok(authService.login(response, result.subject(), Map.of()));
}
```

## Documentation

Start at the [documentation index](docs/README.md). The primary integration references are:

- [Authentication guide](docs/guides/authentication.md)
- [Async and streaming security](docs/guides/async-streaming-security.md)
- [Configuration reference](docs/reference/configuration.md)

## Verification

```bat
gradlew.bat qualityCheck --no-daemon
```

## Security and contribution

Read [SECURITY.md](SECURITY.md) for private vulnerability reporting and [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## License

Apache 2.0. See [LICENSE](LICENSE).
