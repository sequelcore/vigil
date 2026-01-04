# Vigil Roadmap

## Scope

Vigil handles **token lifecycle**, not **user lifecycle**.

**In scope:** Token generation, validation, refresh, blacklisting, cookies, password hashing, request authentication.

**Out of scope:** User storage, `UserDetailsService`, login endpoints, OAuth2 server, email/SMS.

---

## Released

### v1.0.0 - Core
- `VigilTokenService` - JWT generation and validation
- `VigilPasswordService` - BCrypt hashing
- `VigilCookieService` - Cookie management
- `VigilBlacklistService` - Token blacklist
- `VigilProtectionService` - Brute-force prevention
- `VigilTenantService` - Multi-tenant support
- `VigilAuthenticationFilter` - JWT filter

### v2.0.0 - Integration Ready
- Cookie profiles (staff, customer, etc.)
- Token refresh with rotation
- Custom TTL per token
- `VigilBlacklistBackend` interface
- Test configuration

### v2.2.0 - Password & Sessions
- `VigilPasswordService` enhanced (strength scoring, rehash detection)
- `VigilSessionService` - Guest session tokens
- `VigilSessionProvider<T>` - Application implements for session lookup
- `VigilAuthService` - Logout, refresh, session invalidation
- `VigilResetTokenService` - Password reset tokens

### v2.3.0 - Context Populator
- `VigilContextPopulator` interface for custom security context
- Auto-discovery of all `VigilContextPopulator` beans

### v2.4.0 - Profile Paths
- Path-based cookie profile resolution via `profile-paths`
- `ProfilePathMatcher` for request path → cookie profile mapping

### v2.4.1 - Cookie Hardening
- Spring `ResponseCookie` builder for RFC-compliant cookies

### v2.5.0 - Strict Filter
- `VigilAuthenticationFilter` always auto-registered (no override)
- Apps customize via `VigilContextPopulator` only

### v2.6.0 - Login Orchestration
- `VigilAuthService.login()` - Generate tokens + set cookies in one call
- Completes the auth lifecycle: login → refresh → logout

### v2.6.1 - Public Path Tenant Context (Current)
- Tenant context populated for public paths when `tenant.enabled=true`
- `VigilContextPopulator.populate()` called for public paths with `claims=null`
- Enables login/registration endpoints to access tenant context

---

## Planned

### v2.7.0 - Audit Events
- `VigilAuthenticationSuccessEvent`
- `VigilAuthenticationFailureEvent`
- `VigilTokenBlacklistedEvent`
- `VigilAccountLockedEvent`

### v3.0.0 - Security Hardening
- Algorithm enforcement (reject `alg: none`)
- Claims validation (`iss`, `aud`, `nbf`)
- TTL ceilings (access max 60m, refresh max 30d)
- Token fingerprint binding

### Future
- Key rotation (`kid` header, JWKS)
- Asymmetric keys (RS256, ES256)
- Redis adapters for blacklist/protection
