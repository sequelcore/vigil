# Release Policy

Vigil is published as a Spring Boot starter for JWT authentication. Version
`7.2.0` is the current release line and Spring Boot 4.1 certification baseline.

Vigil is used by Sequel applications, but public consumers should pin exact
versions, read release notes, and review migration notes before upgrades.

## Versioning

Vigil follows semantic versioning for public releases:

- MAJOR for incompatible API or configuration changes;
- MINOR for backwards-compatible functionality;
- PATCH for backwards-compatible bug fixes and hardening.

Every breaking change must include migration notes that identify the affected
package, public type, method, property, replacement path, and automation status.

## Public Compatibility Surface

Vigil treats these as public compatibility surfaces:

- Maven coordinates `io.github.sequelcore:vigil-spring-boot-starter`;
- public types under `io.github.sequelcore.vigil`;
- Spring Boot configuration properties under `vigil.*`;
- JWT signing and validation behavior documented in the README and usage guide;
- cookie, blacklist, tenant, session, reset-token, and filter integration
  contracts documented in public docs;
- `/.well-known/jwks.json` response shape when RS256 is active.

Implementation details that are not documented as public contracts may change
between releases when tests and public behavior remain stable.

Current tested compatibility envelope:

- Java 25;
- Spring Boot 4.1.0;
- Spring Framework 7.0.8 through the Spring Boot 4.1.0 BOM;
- Spring Security 7.1.0 through the Spring Boot 4.1.0 BOM;
- Jackson 3 through `tools.jackson` packages;
- Gradle 9.6.x wrapper;
- HS256 with a configured 256-bit minimum secret;
- RS256 with configured PEM private/public keys and JWKS publication.

Vigil `7.2.x` is the active supported platform line. Vigil `6.0.x` was the
final Spring Boot 3.5.x / Java 21 line and is not supported for Spring Boot
4.1 consumers. Do not add compatibility shims between the two lines; Boot 4
changes the default JSON stack to Jackson 3 and modularizes several Boot
support packages.

The `7.0.0` line intentionally changes
`VigilAuthenticationEntryPoint(String, ObjectMapper)` from Jackson 2
`com.fasterxml.jackson.databind.ObjectMapper` to Jackson 3
`tools.jackson.databind.ObjectMapper`. This is a public constructor type change
and therefore requires a major release.

Untested compatibility must not be described as supported in release notes,
README, Maven metadata, or examples.

## Artifact Policy

Java artifacts use group `io.github.sequelcore`.

Public artifact:

- `vigil-spring-boot-starter`

Publish only the starter artifact to Maven Central. Do not publish local test
fixtures, generated reports, examples, or build output.

## Release Readiness Checklist

Before a public release:

1. `README.md` documents the current version and supported integration path.
2. The relevant guide reflects current behavior and `docs/reference/configuration.md` reflects every configuration change.
3. `CHANGELOG.md` contains user-visible changes.
4. Public API or configuration changes have migration notes.
5. Architecture changes are documented in the relevant public guide or roadmap.
6. Security changes are covered by focused tests.
7. `gradlew.bat clean check --no-daemon` passes locally.
8. `gradlew.bat qualityCheck --no-daemon` passes locally.
9. Maven local publication evidence exists.
10. Release automation uses scoped permissions, manual dispatch, protected
    environment gates, explicit confirmation, and runtime secret fetch before
    any upload step.
11. Release notes are drafted from verified repository changes.

## Dry-Run Commands

Quality gate:

```bash
gradlew.bat clean check --no-daemon
gradlew.bat qualityCheck --no-daemon
```

Maven local publication:

```bash
gradlew.bat publishToMavenLocal --no-daemon
```

## Publication Policy

Release automation is manual and guarded. The default workflow operation is
`validate`, which checks the release candidate without fetching publisher
credentials or uploading artifacts. Maven Central upload requires a separate
`operation=publish` workflow dispatch.

Publishing requires:

- `release_ref` equal to `v<release_version>`;
- `confirmation` equal to `publish <release_version>`;
- the protected GitHub `release` environment;
- a repository `DOPPLER_TOKEN` secret that can fetch release credentials from
  Doppler project `sequel-releases`, config `prd`, at runtime.

The workflow does not publish on pushes, branch updates, pull requests, or tag
creation. It does not create GitHub releases.

Maven Central publishing must use the current Central Portal path, validated
POM metadata, sources, Javadocs, license metadata, SCM metadata, developer
metadata, signatures, and CI-provided credentials.

Before any future publication action, verify:

1. Sonatype Central namespace ownership, Central Portal token access, and
   signing credentials.
2. Protected release controls for publication credentials, including branch
   protection or rulesets and a protected environment or equivalent approval
   gate.
3. A release workflow `validate` run for the exact release tag before any
   `publish` operation.

Required Doppler release secrets:

- `MAVEN_USERNAME`
- `MAVEN_PASSWORD`
- `GPG_PRIVATE_KEY`
- `GPG_PASSPHRASE`

The GitHub repository should store only the Doppler service token needed by the
release workflow. Do not copy registry tokens, signing keys, or passphrases into
repository secrets, docs, logs, or prompts.
