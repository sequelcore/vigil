# Vigil Roadmap

## Scope

Vigil handles **token lifecycle**, not **user lifecycle**.

**In scope:** Token generation, validation, refresh, blacklisting, cookies, password hashing, request authentication.

**Out of scope:** User storage, `UserDetailsService`, login endpoints, OAuth2 server, email/SMS.

---

## Standards Compliance

| Standard | Description | Target |
|----------|-------------|--------|
| RFC 7519 | JWT Specification | v1.0.0 |
| RFC 7517 | JSON Web Key (JWK) | v5.0.0 |
| RFC 6749 | OAuth 2.0 Token Refresh | v3.1.0 |
| RFC 6750 | Bearer Token Usage | v2.7.0 |
| RFC 8252 | OAuth 2.0 for Native Apps | v3.1.0 |
| RFC 8725bis | JWT Best Current Practices (2025) | v3.0.0 |
| RFC 9700 | OAuth 2.0 Security BCP (2025) | v2.0.0 |

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
- `ProfilePathMatcher` for request path -> cookie profile mapping

### v2.4.1 - Cookie Hardening
- Spring `ResponseCookie` builder for RFC-compliant cookies

### v2.5.0 - Strict Filter
- `VigilAuthenticationFilter` always auto-registered (no override)
- Apps customize via `VigilContextPopulator` only

### v2.6.0 - Login Orchestration
- `VigilAuthService.login()` - Generate tokens + set cookies in one call
- Completes the auth lifecycle: login -> refresh -> logout

### v2.6.1 - Public Path Tenant Context
- Tenant context populated for public paths when `tenant.enabled=true`
- `VigilContextPopulator.populate()` called for public paths with `claims=null`
- Enables login/registration endpoints to access tenant context

### v2.7.0 - RFC 6750 Compliance
- `VigilAuthenticationEntryPoint` with `WWW-Authenticate` header
- Error codes per RFC 6750 Section 3:
  - No token: `Bearer realm="app"` (no error code)
  - Expired: `error="invalid_token", error_description="The access token has expired"`
  - Invalid: `error="invalid_token", error_description="..."`
  - Revoked: `error="invalid_token", error_description="Token has been revoked"`
- Configurable realm via `vigil.auth.realm`
- Filter hooks propagate error info to entry point

### v3.0.0 - RFC 8725bis Compliance
- **Secret key validation** - Minimum 32 characters (256 bits) enforced at startup
- **Claims validation** - `iss` and `aud` validated when configured
- **Algorithm security** - HMAC-SHA256 enforced by jjwt (no `alg:none`)
- **`nbf` (not before) claim** - Generated and validated automatically

Breaking changes:
- Apps with secrets < 32 chars will fail at startup
- Tokens from other issuers/audiences rejected when `iss`/`aud` configured

### v3.1.0 - Native App & API Support
- **Bearer token login** - `VigilAuthService.login(subject, claims)` returns tokens without cookies
- **Bearer token refresh** - `VigilAuthService.refresh(refreshToken)` for native apps and APIs
- **Bearer token logout** - `VigilAuthService.logout(accessToken, refreshToken)` for stateless clients
- **Transport-agnostic design** - Token operations work regardless of transport (cookie, header, body)
- **Unified API** - Same `AuthResult` response for all client types
- **DRY refactor** - Shared `loginInternal()` and `refreshInternal()` methods

Per RFC 6749 Section 6, refresh tokens are transmitted in the request body, not cookies.
Native apps (iOS, Android) and APIs use Authorization headers per RFC 8252.

### v4.0.0 - Authentication/Authorization Separation
- **`ignored-paths`** - New config for paths that skip ALL processing (no tenant, no auth, no populators)
- **`public-paths` semantics change** - Now permits anonymous but authenticates if credentials present
- **Filter flow redesign** - Separates authentication (who?) from authorization (can access?)
- **Optional session enrichment** - Public paths can now show user info when logged in

Breaking changes:
- `public-paths` behavior changed — previously skipped all auth, now attempts auth if credentials present
- Apps relying on old `public-paths` behavior should move those paths to `ignored-paths`

| Path Type | Credentials | v3.x Behavior | v4.0 Behavior |
|-----------|-------------|---------------|---------------|
| public-paths | Valid token | Ignored | Authenticated |
| public-paths | Invalid token | Ignored | Permit anonymous |
| ignored-paths | Any | N/A | Skip all processing |

Migration:
```yaml
# v3.x
vigil:
  filter:
    public-paths:
      - /actuator/**
      - /health
      - /api/public/**

# v4.0
vigil:
  filter:
    ignored-paths:
      - /actuator/**
      - /health
    public-paths:
      - /api/public/**
```

### v4.1.0 - Grace Period for Token Rotation
- **`grace-period` config** - Configurable reuse window for rotated refresh tokens (default 30s, max 60s)
- **Race condition fix** - Handles client crashes/network issues during token refresh
- **Industry standard** - Same pattern as Auth0/Okta refresh token rotation with reuse detection

When a refresh token is rotated, the old token enters a grace period where reuse returns the cached new tokens. This prevents session loss when:
- Network issues prevent client from receiving new tokens
- Client crashes before persisting new tokens
- Mobile apps lose signal mid-refresh

```yaml
vigil:
  blacklist:
    grace-period: 30s   # 0-60 seconds
```

### v5.0.0 - RS256 & JWKS (Current)
- **`algorithm` config** - `HS256` (default, unchanged) or `RS256` (opt-in)
- **`RsaTokenSigner`** - RSA-SHA256 signing with private key; verification with public key
- **`HmacTokenSigner`** - HS256 extracted into strategy; zero behavior change for existing deployments
- **`TokenSigner` interface** - Strategy pattern enabling clean algorithm selection and future extension (ES256)
- **`PemKeyLoader`** - Load RSA keys from `file:` path, `classpath:` resource, or inline PEM string
- **`kid` header** - Deterministic key ID (SHA-256 of public key DER, base64url, first 8 chars) on every RS256 token
- **JWKS endpoint** - `GET /.well-known/jwks.json` per RFC 7517; auto-registered when `algorithm=RS256`
- **Auto-excluded path** - `/.well-known/jwks.json` added to `ignored-paths` automatically; no auth required
- **Cache-Control** - JWKS response includes `public, max-age=3600`

Breaking changes (direct instantiation only; YAML-configured apps are unaffected):
- `VigilProperties.Jwt` canonical constructor expanded from 5 to 8 fields (`algorithm`, `rsaPrivateKey`, `rsaPublicKey` added)
- `VigilTokenService` constructors require `TokenSigner` as first argument; `getSigningKey()` removed

What this unlocks:
- **Gateway verification** — API gateways (e.g., Kiln) can validate tokens by fetching JWKS without holding the signing secret
- **Zero-trust inter-service auth** — Services verify tokens with only the public key
- **Key rotation** — Publish old + new public keys in JWKS simultaneously; remove old key after one TTL cycle

---

## Future

- Redis adapters for blacklist/protection
- ES256 (ECDSA) signing via `TokenSigner` extension point
- DPoP support (RFC 9449)
