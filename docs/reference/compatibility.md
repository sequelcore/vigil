# Compatibility reference

Vigil certifies the platform components that define its runtime contract. A version range is not
supported until that combination passes the complete repository gate.

## Current line

| Component | Certified version |
| --- | --- |
| Vigil | 7.2.1 |
| Java | 25 |
| Spring Boot BOM | 4.1.0 |
| Spring Framework MVC | 7.0.8 |
| Spring Security Web | 7.1.0 |
| Jackson Databind | 3.1.4, through `tools.jackson` packages |
| Gradle wrapper | 9.6.1 |
| Embedded test container | Tomcat 11.0.22, implementing Servlet 6.1 |

Vigil 6.0.x was the final Java 21 and Spring Boot 3.5 line. It is not a compatibility target for
Spring Boot 4 applications. The Jackson 2 to Jackson 3 constructor change was released in Vigil
7.0.0 and is recorded in the [changelog](../../CHANGELOG.md#700---2026-06-23).

## Certification rule

The Spring Boot BOM selects Framework, Security, Jackson, validation, and container dependencies.
Do not override individual managed versions and describe the result as certified. To certify a new
combination, update the BOM, run the focused integration tests, then run:

```bat
gradlew.bat clean check --no-daemon
gradlew.bat qualityCheck build --no-daemon
```

Async certification includes a real embedded-Tomcat client disconnect, final `ASYNC` processing,
container `ERROR` dispatch, concurrency isolation, and absence of `HttpSession`.
