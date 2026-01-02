# Vigil Roadmap

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

### v2.2.0 - Complete Auth Solution
- `VigilPasswordService` enhanced (strength scoring, rehash detection, common password check)
- `VigilSessionService` - Guest session tokens
- `VigilSessionProvider<T>` - Application implements for session lookup
- `VigilAuthService` - High-level login/logout/refresh
- `VigilResetTokenService` - Password reset tokens

### v2.3.0 - Context Populator
- `VigilContextPopulator` interface for custom security context population
- `FilterConfig` for cleaner filter configuration
- `checkAllProfiles` option to try all cookie profiles for token extraction
- Auto-discovery of all `VigilContextPopulator` beans
- Eliminates need to extend `VigilAuthenticationFilter`

### v2.3.1 - Cleanup (Current)
- Remove convenience constructors from `VigilAuthenticationFilter`
- Single constructor with `FilterConfig` parameter
- No dead code policy enforcement

## Planned

### v2.4.0 - Audit Events
- `VigilAuthenticationSuccessEvent`
- `VigilAuthenticationFailureEvent`
- `VigilTokenBlacklistedEvent`
- `VigilAccountLockedEvent`

### v3.0.0 - Security Hardening
- Algorithm enforcement (reject `alg: none`)
- Claims validation (`iss`, `aud`, `nbf`)
- TTL ceilings (access max 60m, refresh max 30d)
- Token sidejacking prevention (fingerprint binding)

### Future
- Key rotation (`kid` header, JWKS)
- Asymmetric keys (RS256, ES256)
- Redis adapters for blacklist/protection

## Non-Goals

- OAuth2 server (use Spring Authorization Server)
- User management (application domain)
- Email/SMS sending (provider-specific)
