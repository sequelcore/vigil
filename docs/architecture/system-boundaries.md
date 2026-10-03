# System boundaries

## Purpose

Vigil is authentication infrastructure for Spring Boot applications. It standardizes secure token handling while preserving the application's ownership of users and business authorization.

## Ownership

| Vigil owns | Application owns |
| --- | --- |
| JWT generation, validation, signing-key handling, JWKS, refresh rotation, and revocation | User persistence, lookup, registration, and credential enrollment UI |
| Cookie and bearer-token extraction | Login, logout, reset, and recovery routes |
| Request authentication filter and tenant consistency | `SecurityFilterChain` authorization rules and tenant membership |
| Password hashing helpers and reset-token validation/invalidation | Password policy, recovery delivery, concurrent reset serialization, and account recovery UX |
| Step-up challenge/proof lifecycle and credential-verifier SPI | Business approval policy, roles, limits, segregation of duties, and audit decision |
| `PasswordLoginGuard`: lockout with backoff, equal-cost verification, and a result that hides the failure cause | The login route, user lookup, account status, the single generic error response, per-IP/global rate limits, CAPTCHA/MFA, recovery, and shared counters when running several instances |
| Opt-in contact-proof lifecycle and receipt orchestration | Enrollment routes, user records, email delivery, canonicalization, abuse controls, durable atomic state, and receipt application |

Vigil is not an OAuth authorization server, OpenID Connect provider, hosted identity platform, user-management system, or business authorization engine.

## Runtime shape

```text
Client
  -> application route / SecurityFilterChain
       -> VigilAuthenticationFilter (token/cookie extraction, validation, tenant consistency)
       -> application controller and authorization policy
            -> VigilAuthService / VigilResetTokenService / StepUpAuthorizationService
            -> application user and business persistence
```

Applications add `VigilAuthenticationFilter` inside Spring Security's filter chain. The filter establishes authentication from a validated token; it does not authorize a route. Controllers and services must continue to enforce application permissions.

## Extension points

| Extension point | Use it for | Do not use it for |
| --- | --- | --- |
| `VigilBlacklistBackend` | shared revocation and refresh-rotation state | application session or user storage |
| `VigilContextPopulator` | copying validated claims into request context | granting business permissions |
| `VigilSessionProvider` | application-owned guest/session lookup | replacing token validation |
| `StepUpStore` | atomic shared step-up challenge/proof state | storing PINs or users |
| `StepUpCredentialVerifier` | a credential method such as PIN or a future passkey | product-specific approval logic |
| `PinCredentialStore` | tenant-scoped personal PIN hashes | raw PIN storage |
| `LoginAttemptStore` | atomic failure counters for password login and step-up PIN verification, shared across instances (the default is node-local) | users, passwords, or account status |
| `EnrollmentStore` | atomic, durable contact-proof and receipt lifecycle | users, credentials, an in-memory/single-node implementation, or load/save coordination |
| `EnrollmentIdentityPort` | transactionally applying a verified receipt and, when supported, recording finalization permission | user lookup, auto-linking by email, session issuance, credential creation, or credential activation |
| `EnrollmentDeliveryPort` | application-owned proof delivery | logging proof values or full email addresses |

## Password-login guard

`PasswordLoginGuard`, with `LoginPolicy` and `LoginAttemptStore`, is the single owner of failed-attempt protection in Vigil; step-up PIN verification (`StepUpAuthorizationService`) uses the same policy and store under a separate key namespace. Vigil auto-configures all three, configured under `vigil.login.*`, and an application may replace any of them with its own bean.

The guard is a library call, not a route or filter. The application's route passes the identifier, the password, and a lookup function that returns the user's subject, hash, and active status; Vigil never reads users. A locked identifier is rejected before lookup or hashing, an unknown identifier is verified against a dummy hash and counted like a known one, and every rejection is the same `LoginResult`. The application must return one generic error for it. Design rationale, sources, and known limits: [password-login protection](../security/login-protection.md).

## Compatibility boundary

The public types under `io.github.sequelcore.vigil`, `vigil.*` configuration, documented HTTP behavior, and published artifact coordinates are compatibility surfaces. Details and release policy are defined in [the release policy](../releases/release-policy.md).
