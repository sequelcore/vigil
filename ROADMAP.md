# Vigil Roadmap

## Phase 1: Core Foundation (v1.0.0) - Released

### 1.1 Project Setup
- [x] Initialize project structure
- [x] Configure Gradle build with Kotlin DSL
- [x] Set up Spotless, Checkstyle, JaCoCo
- [x] Configure Maven Central publishing (vanniktech plugin + Central Portal)
- [x] Set up GitHub Actions CI/CD
  - CI workflow (build, test, quality checks on push/PR)
  - Publish workflow (Maven Central publishing on tags)
  - Doppler integration for secret management

### 1.2 Core Module
- [x] `VigilTokenService` - JWT generation and validation
- [x] `VigilPasswordService` - Password hashing and validation
- [x] `VigilCookieService` - Cookie management

### 1.3 Security Filter
- [x] `VigilAuthenticationFilter` - Base JWT filter
- [x] `VigilTokenClaims` - Type-safe JWT claims wrapper

### 1.4 Auto-Configuration
- [x] `VigilAutoConfiguration` - Spring Boot auto-config
- [x] `VigilProperties` - Configuration properties with validation
- [x] Conditional bean creation based on properties

### 1.5 Security Modules (enabled by default)
- [x] Token Blacklist - real logout support
- [x] Login Protection - brute-force prevention
- [x] Multi-Tenant Support (optional, `vigil.tenant.enabled`)

### 1.6 Testing and Documentation
- [x] Unit tests (80% coverage, 47 tests)
- [x] Integration tests (12 scenarios)
- [x] README with quick start guide
- [x] Javadoc for public APIs

---

## Phase 2: Security Hardening (v1.1.0) - Planned

> **Research:** [docs/SECURITY_RESEARCH.md](docs/SECURITY_RESEARCH.md)
> **Standards:** OWASP JWT Cheat Sheet 2025, NIST SP 800-63-4 (July 2025)

### 2.1 Native Token Rotation (Non-Configurable)

> "Refresh token rotation ensures compromised tokens lose utility almost immediately." — [Auth0](https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation)

- [ ] One-time use refresh tokens (rotate on every refresh)
- [ ] Token family tracking (associate all tokens from same login)
- [ ] Reuse detection → invalidate entire family + force re-auth
- [ ] `VigilTokenRotationService` with atomic operations
- [ ] Caffeine storage (default), Redis adapter (optional)

**Why native?** Auth0 and Okta make this optional. We don't. Token reuse is an attack indicator—making it configurable allows insecure deployments.

### 2.2 Algorithm Security (Native)

Prevents CVEs: CVE-2024-54150, CVE-2024-37568, CVE-2023-48223, CVE-2015-9235

- [ ] Reject `alg: none` tokens (verify current implementation)
- [ ] Server-side algorithm enforcement (never trust JWT header)
- [ ] Block key confusion attacks (symmetric key used as asymmetric)
- [ ] Whitelist: HS256, HS384, HS512 (v1.x), RS256, ES256, EdDSA (v2.x)

```java
// WRONG: Trust the token header
String alg = jwt.getHeader().getAlgorithm();

// CORRECT: Server decides algorithm
.setSigningKey(key)
.requireSignedWith(SignatureAlgorithm.HS256)
```

### 2.3 Claims Validation (Native)

Per [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html):

- [ ] `iss` (issuer) - must match `vigil.jwt.issuer`
- [ ] `aud` (audience) - must include `vigil.jwt.audience`
- [ ] `exp` (expiration) - ✅ already implemented
- [ ] `nbf` (not before) - clock skew tolerance (30s default)
- [ ] `iat` (issued at) - reject tokens from the future

### 2.4 Token Sidejacking Prevention (OWASP)

> "A SHA256 hash of a random string stored in the token, with the raw value in an HttpOnly cookie, prevents token reuse by attackers." — OWASP

- [ ] Generate fingerprint on login (random 32-byte string)
- [ ] Store SHA256(fingerprint) in JWT `fgp` claim
- [ ] Send fingerprint in `__Secure-Fgp` cookie (HttpOnly, Secure, SameSite=Strict)
- [ ] Validate: SHA256(cookie) === JWT claim on each request
- [ ] Optional feature (performance tradeoff for high-security apps)

### 2.5 TTL Ceiling Enforcement

Per [NIST SP 800-63-4](https://csrc.nist.gov/pubs/sp/800/63/4/final) AAL2:

- [ ] Access TTL: max 60 minutes (even if configured higher)
- [ ] Refresh TTL: max 30 days
- [ ] Inactivity timeout: max 30 minutes
- [ ] Validation at startup (fail fast on invalid config)

### 2.6 Key ID Support

Preparation for key rotation in v2.0.0:

- [ ] Add `kid` (key ID) to JWT header
- [ ] `vigil.jwt.key-id` configuration property
- [ ] Support multiple keys during rotation grace period

---

## Phase 3: Advanced Features (v1.2.0) - Planned

### 3.1 Argon2id Password Hashing

> "Argon2id should be the first choice for password hashing. BCrypt should only be used for legacy systems." — [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

- [ ] Add `VigilArgon2Service` (19 MiB memory, 2 iterations, 1 parallelism)
- [ ] `vigil.password.algorithm` config (argon2id | bcrypt)
- [ ] Automatic migration: re-hash on login if BCrypt detected
- [ ] BCrypt 72-byte limit warning

### 3.2 Session Management
- [ ] Session ID (`sid`) claim in tokens
- [ ] Per-session revocation support
- [ ] Device/session tracking interfaces
- [ ] Concurrent session limits (configurable)

### 3.3 Observability
- [ ] Micrometer metrics for auth events
- [ ] `vigil.auth.login.success` / `vigil.auth.login.failure` counters
- [ ] `vigil.token.generation.time` / `vigil.token.validation.time` timers
- [ ] Security event logging (token reuse detected, lockout triggered)

### 3.4 Redis Adapters
- [ ] Redis-based token blacklist (alternative to Caffeine)
- [ ] Redis-based login attempt tracking
- [ ] Redis-based token family storage (for rotation)
- [ ] Optional dependency, auto-detected via Spring Data Redis

---

## Phase 4: Extended Integrations (v2.0.0) - Future

### 4.1 Full Key Rotation with JWKS

> "A robust key rotation process: generate new key, publish to JWKS, grace period, switch signing, retire old key." — [Zalando Engineering](https://engineering.zalando.com/posts/2025/01/automated-json-web-key-rotation.html)

- [ ] `VigilKeyRotationService` - automated key lifecycle
- [ ] JWKS endpoint (`/.well-known/jwks.json`)
- [ ] Grace period configuration (default: 24h)
- [ ] Old key removal after max token lifetime + buffer
- [ ] HSM/KMS integration (AWS KMS, Azure Key Vault, HashiCorp Vault)

### 4.2 Asymmetric Key Support

> "In 2025: EdDSA (newest, quantum-resistant properties), ES256 (ECDSA P-256), RS256 (widely supported), PS256 (more secure than RS256)." — Industry consensus

- [ ] RS256 (RSA 2048-bit minimum)
- [ ] ES256 (ECDSA with P-256 curve)
- [ ] EdDSA (Ed25519) - recommended for new projects
- [ ] PS256 (RSA-PSS) for high-security requirements

### 4.3 Event Hooks
- [ ] `onLoginSuccess` callback
- [ ] `onLoginFailure` callback
- [ ] `onTokenRefresh` callback
- [ ] `onTokenReuseDetected` callback (security alert)
- [ ] `onAccountLocked` callback

### 4.4 Simplified OAuth Wrappers
- [ ] Google OAuth simplified configuration
- [ ] GitHub OAuth simplified configuration
- [ ] Microsoft Entra ID support

---

## Native vs Configurable Philosophy

Vigil follows an **opinionated security-first** approach. While Auth0/Okta let you disable security features, we don't—you can't accidentally deploy an insecure configuration.

### Native (Non-Configurable) - Security Invariants

These are **always enforced** because disabling them creates vulnerabilities:

| Feature | CVE/Standard | Rationale |
|---------|--------------|-----------|
| Auth filter | Core architecture | JWT validation on every request |
| Token blacklist | Auth0/Okta best practice | Real logout requires invalidation |
| Brute-force protection | OWASP Authentication | Credential stuffing defense |
| Refresh token rotation (v1.1) | Auth0/Okta best practice | Token reuse = theft indicator |
| Token reuse detection (v1.1) | Auth0/Okta best practice | Attack early warning |
| Algorithm `none` rejection | CVE-2015-9235 | Critical bypass vulnerability |
| Algorithm enforcement (v1.1) | CVE-2024-54150, CVE-2024-37568 | Key confusion attacks |
| Claims validation (v1.1) | OWASP JWT Cheat Sheet | Basic JWT security |
| HttpOnly cookies | MDN Security Guide | XSS protection |
| Secure flag in production | MDN Security Guide | MITM protection |
| SameSite cookie attribute | MDN Security Guide | CSRF protection |
| BCrypt minimum cost (10) | OWASP Password Storage | Brute-force resistance |
| TTL ceilings | NIST SP 800-63-4 | Session management |

### Configurable with Enforced Ceilings

These have **sensible defaults** with **maximum limits** that cannot be exceeded:

| Feature | Default | Max Allowed | Standard |
|---------|---------|-------------|----------|
| Access token TTL | 15 min | 60 min | OWASP |
| Refresh token TTL | 7 days | 30 days | NIST AAL2 |
| Inactivity timeout | 30 min | 30 min | NIST AAL2 |
| BCrypt cost factor | 12 | 31 | OWASP |
| Login attempts | 5 | 10 | Industry practice |
| Clock skew tolerance | 30s | 60s | OWASP |

### Fully Configurable - Application-Specific

These depend on the application's requirements:

| Feature | Default | Why Configurable |
|---------|---------|------------------|
| Public paths | `[]` | Varies per API design |
| Multi-tenant | Off | Architecture decision |
| Cookie names | `vigil_*` | Integration requirements |
| Issuer/Audience | app name | Deployment-specific |
| Storage backend | Caffeine | Infrastructure varies |


---

## Non-Goals

- **Guest sessions** - Application-specific business logic
- **Email verification** - Too many variables (provider, templates)
- **Full OAuth2 server** - Use Spring Authorization Server
- **SMS/2FA** - Provider-specific, consider for v3+
- **User management** - Application's domain, not auth infrastructure

---

## Version History

| Version | Status | Description |
|---------|--------|-------------|
| 1.0.0 | Released | Core JWT, password, cookies with native filter, blacklist, and brute-force protection |
| 1.1.0 | Planned | Native token rotation, algorithm enforcement, claims validation, sidejacking prevention |
| 1.2.0 | Planned | Argon2id, sessions, observability, Redis adapters |
| 2.0.0 | Future | Key rotation, JWKS, asymmetric keys, OAuth wrappers, event hooks |
