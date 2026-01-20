# Vigil Roadmap

## Scope

Vigil handles **token lifecycle**, not **user lifecycle**.

**In scope:** Token generation, validation, refresh, blacklisting, cookies, password hashing, request authentication.

**Out of scope:** User storage, `UserDetailsService`, login endpoints, OAuth2 server, email/SMS.

---

## Standards Compliance

| Standard | Description | Target |
|----------|-------------|--------|
| RFC 7519 | JWT Specification | v1.0.0 ✅ |
| RFC 6750 | Bearer Token Usage | v2.7.0 |
| RFC 8725bis | JWT Best Current Practices (2025) | v3.0.0 |
| RFC 9700 | OAuth 2.0 Security BCP (2025) | v2.0.0 ✅ |

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
- Token refresh with rotation (RFC 9700)
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

### v2.6.1 - Public Path Tenant Context
- Tenant context populated for public paths when `tenant.enabled=true`
- `VigilContextPopulator.populate()` called for public paths with `claims=null`
- Enables login/registration endpoints to access tenant context

### v2.7.0 - RFC 6750 Compliance
- `VigilAuthenticationEntryPoint` with `WWW-Authenticate` header
- Error codes per RFC 6750 Section 3:
  - No token → `Bearer realm="app"` (no error code)
  - Expired → `error="invalid_token", error_description="The access token has expired"`
  - Invalid → `error="invalid_token", error_description="..."`
  - Revoked → `error="invalid_token", error_description="Token has been revoked"`
- Configurable realm via `vigil.auth.realm`
- Filter hooks propagate error info to entry point

### v3.0.0 - RFC 8725bis Compliance (Current)
- **Secret key validation** - Minimum 32 characters (256 bits) enforced at startup
- **Claims validation** - `iss` and `aud` validated when configured
- **Algorithm security** - HMAC-SHA256 enforced by jjwt (no `alg:none`)
- **`nbf` (not before) claim** - Generated and validated automatically

Breaking changes:
- Apps with secrets < 32 chars will fail at startup
- Tokens from other issuers/audiences rejected when `iss`/`aud` configured

---

## Planned

---

## Future

- Key rotation (`kid` header, JWKS)
- Asymmetric keys (RS256, ES256)
- Redis adapters for blacklist/protection
- DPoP support (RFC 9449)
