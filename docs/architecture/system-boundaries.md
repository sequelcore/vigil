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
| `EnrollmentStore` | atomic, durable contact-proof and receipt lifecycle | users, credentials, an in-memory/single-node implementation, or load/save coordination |
| `EnrollmentIdentityPort` | transactionally applying a verified receipt | user lookup, auto-linking by email, session issuance, or credential creation |
| `EnrollmentDeliveryPort` | application-owned proof delivery | logging proof values or full email addresses |

## Compatibility boundary

The public types under `io.github.sequelcore.vigil`, `vigil.*` configuration, documented HTTP behavior, and published artifact coordinates are compatibility surfaces. Details and release policy are defined in [the release policy](../releases/release-policy.md).
