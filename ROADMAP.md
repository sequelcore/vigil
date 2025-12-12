# Vigil Roadmap

## Phase 1: Core Foundation (v1.0.0)

### 1.1 Project Setup
- [x] Initialize project structure
- [x] Configure Gradle build with Kotlin DSL
- [x] Set up Spotless, Checkstyle, JaCoCo
- [x] Configure Maven Central publishing
- [x] Set up GitHub Actions CI/CD
  - CI workflow (build, test, quality checks on push/PR) ✅ passing
  - Publish workflow (Maven Central publishing on tags)
  - Doppler integration for secret management

### 1.2 Core Module
- [x] `VigilTokenService` - JWT generation and validation
  - Access token generation with configurable claims
  - Refresh token generation with rotation support
  - Token validation and parsing
  - Configurable TTL, issuer, audience
  - Reference: SHRAD `TokenManagementService`, Quesoro `JwtUtil`

- [x] `VigilPasswordService` - Password hashing and validation
  - BCrypt hashing with configurable cost factor
  - Password strength validation rules
  - Reference: SHRAD `BCryptPasswordService`

- [x] `VigilCookieService` - Cookie management
  - HttpOnly secure cookie creation
  - Dual client support (web cookies / mobile tokens)
  - Configurable cookie names, secure flag, SameSite
  - Reference: SHRAD `CookieUtil`, Quesoro `CookieUtil`

### 1.3 Security Filter
- [x] `VigilAuthenticationFilter` - Base JWT filter
  - Token extraction from cookies or Authorization header
  - Token validation and SecurityContext population
  - Public path exclusion
  - Extensible for custom logic (override hooks)
  - `VigilTokenClaims` type-safe wrapper for JWT claims
  - Reference: SHRAD `JwtRequestFilter`, Quesoro `JwtAuthenticationFilter`

### 1.4 Auto-Configuration
- [x] `VigilAutoConfiguration` - Spring Boot auto-config
- [x] `VigilProperties` - Configuration properties with validation
- [x] Conditional bean creation based on properties

### 1.5 Testing and Documentation
- [x] Unit tests (80% coverage minimum)
  - 8 test classes, 47 test methods
  - 80% instruction coverage (JaCoCo verified)
  - Comprehensive edge case testing
- [ ] Integration tests with sample Spring Boot app
- [x] README with quick start guide
- [ ] Javadoc for public APIs

---

## Phase 2: Optional Modules (v1.1.0)

### 2.1 Token Blacklist Module
- [x] Caffeine-based token blacklist
- [x] Configurable max size and TTL
- [x] `vigil.blacklist.enabled` feature flag
- [x] Reference: Quesoro `TokenBlacklistService`

### 2.2 Login Protection Module
- [x] Login attempt tracking
- [x] Automatic account lockout after N failures
- [x] Configurable thresholds and lock duration
- [x] `vigil.protection.enabled` feature flag
- [x] Reference: Quesoro `LoginAttemptService`

### 2.3 Multi-Tenant Module
- [x] `TenantContext` ThreadLocal management
- [x] Tenant extraction from header
- [x] Tenant claim in JWT
- [x] Tenant validation (token vs header)
- [x] `vigil.tenant.enabled` feature flag
- [x] Reference: SHRAD `TenantContext`, `JwtRequestFilter`

---

## Phase 3: Advanced Features (v1.2.0)

### 3.1 Session Management
- [ ] Session ID in JWT claims
- [ ] Per-session revocation support
- [ ] Device/session tracking interfaces
- [ ] Reference: Quesoro `DeviceService`

### 3.2 Observability
- [ ] Micrometer metrics for auth events
  - Login success/failure counters
  - Token generation/validation timers
  - Blacklist hit/miss rates
- [ ] Reference: Quesoro metrics pattern

### 3.3 Redis Adapters
- [ ] Redis-based token blacklist (alternative to Caffeine)
- [ ] Redis-based login attempt tracking
- [ ] Optional dependency, auto-detected

---

## Phase 4: Extended Integrations (v2.0.0)

### 4.1 Simplified OAuth Wrappers
- [ ] Google OAuth simplified configuration
- [ ] GitHub OAuth simplified configuration
- [ ] Wrapper around Spring Security OAuth2 Client

### 4.2 Event Hooks
- [ ] `onLoginSuccess` callback
- [ ] `onLoginFailure` callback
- [ ] `onTokenRefresh` callback
- [ ] `onSuspiciousActivity` callback

---

## Non-Goals

These features are explicitly out of scope for Vigil:

- **Guest sessions** - Application-specific business logic
- **Email verification** - Too many variables (provider, templates)
- **Full OAuth2 server** - Use Spring Authorization Server
- **SMS/2FA** - Provider-specific, consider for v3+
- **User management** - Application's domain, not auth infrastructure

---

## Version History

| Version | Status | Description |
|---------|--------|-------------|
| 1.0.0 | In Progress | Core JWT, password, cookies, filter |
| 1.1.0 | In Progress | Blacklist, protection, tenant modules |
| 1.2.0 | Planned | Sessions, metrics, Redis adapters |
| 2.0.0 | Future | OAuth wrappers, event hooks |
