# Contributing To Vigil

Contributions are welcome when they keep Vigil small, explicit, tested, and security-focused.

## Development Requirements

- Java 25.
- Use the exact platform versions in the [compatibility reference](docs/reference/compatibility.md).
- Use the Gradle wrapper, not a system Gradle requirement.

## Quality Gates

Run these before opening a pull request:

```bash
./gradlew qualityCheck --no-daemon
./gradlew build --no-daemon
```

On Windows:

```bat
gradlew.bat qualityCheck --no-daemon
gradlew.bat build --no-daemon
```

## Code Standards

- No wildcard imports.
- No dead code.
- Public APIs need Javadoc.
- Behavior changes need tests first.
- Security-sensitive errors must not expose secrets, raw tokens, or parser internals.
- Configuration should fail fast at startup when required security inputs are missing.
- Architecture changes should update the relevant public docs in the same change.
- Completed user-visible work belongs in `CHANGELOG.md`; speculative features belong in GitHub
  Issues or Projects, not the active documentation tree.

## Scope Rules

Vigil owns token lifecycle, request authentication, cookies, blacklisting, tenant context, guest sessions, reset tokens, and JWT signing/validation helpers.

Vigil does not own user storage, registration, login endpoint design, email/SMS delivery, account recovery UX, OAuth authorization-server protocol endpoints, OIDC identity-provider behavior, or application authorization policy.

## Commit Format

Use:

```text
type(scope): description
```

Allowed types:

- `feat`
- `fix`
- `refactor`
- `chore`
- `docs`
- `test`

Examples:

```text
fix(filter): sanitize invalid token errors
docs(readme): add security filter chain example
test(jwt): cover audience validation failure
```

## Pull Request Checklist

- Tests or verification gates were run.
- Public docs were updated for user-facing behavior.
- Security behavior changes include focused tests.
- Architecture notes were updated when behavior or boundaries changed.
- No unrelated files were changed.
