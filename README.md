# Vigil

JWT authentication infrastructure for Spring Boot applications.

[![Maven Central](https://img.shields.io/maven-central/v/io.github.sequelcore/vigil-spring-boot-starter.svg)](https://central.sonatype.com/artifact/io.github.sequelcore/vigil-spring-boot-starter)

Vigil provides JWT lifecycle, request authentication, cookie helpers, tenant consistency,
revocation, reset tokens, and reusable step-up credential verification. Applications retain
ownership of users and business authorization; the complete boundary is documented in
[system boundaries](docs/architecture/system-boundaries.md).

## Compatibility

Vigil `7.2.0` is certified with Java 25 and Spring Boot 4.1.0. See the
[compatibility reference](docs/reference/compatibility.md) for the complete tested combination.

`7.2.0` is the current release line. Public consumers should pin an exact version and review the release notes before upgrading.

## Install

```kotlin
dependencies {
    implementation("io.github.sequelcore:vigil-spring-boot-starter:7.2.0")
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
