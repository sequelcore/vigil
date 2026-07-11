# Vigil

JWT authentication infrastructure for Spring Boot applications.

[![Maven Central](https://img.shields.io/maven-central/v/io.github.sequelcore/vigil-spring-boot-starter.svg)](https://central.sonatype.com/artifact/io.github.sequelcore/vigil-spring-boot-starter)

Vigil provides JWT lifecycle, request authentication, cookie helpers, tenant consistency, revocation, reset tokens, and reusable step-up credential verification. Applications retain ownership of users, login routes, credentials, recovery delivery, and business authorization.

## Compatibility

Vigil `7.1.x` supports Java 25, Spring Boot 4.1.x, Spring Framework 7.x, Spring Security 7.1.x, Gradle 9.6.x, and Jackson 3. Vigil `6.0.x` was the final Java 21 / Spring Boot 3.5 line.

`7.1.0` is the current release line. Public consumers should pin an exact version and review the release notes before upgrading.

## Install

```kotlin
dependencies {
    implementation("io.github.sequelcore:vigil-spring-boot-starter:7.0.0")
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

```java
http.addFilterBefore(vigilAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
```

The application must still configure route authorization. `ignored-paths` skips Vigil processing; it does not grant anonymous access.

## Documentation

Start at the [documentation index](docs/README.md).

- [Authentication guide](docs/guides/authentication.md)
- [Configuration reference](docs/reference/configuration.md)
- [System boundaries](docs/architecture/system-boundaries.md)
- [Security model](docs/security/security-model.md)
- [Step-up authorization](docs/security/step-up-authorization.md)
- [Deployment and operations](docs/operations/deployment.md)
- [Java API contract](docs/api/java-api.md)
- [Testing and verification](docs/development/testing.md)
- [Release policy](docs/releases/release-policy.md)

## Verification

```bat
gradlew.bat qualityCheck --no-daemon
```

## Security and contribution

Read [SECURITY.md](SECURITY.md) for private vulnerability reporting and [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## License

Apache 2.0. See [LICENSE](LICENSE).
