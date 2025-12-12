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

### 1.5 Optional Modules (included in v1.0.0)
- [x] Token Blacklist (`vigil.blacklist.enabled`)
- [x] Login Protection (`vigil.protection.enabled`)
- [x] Multi-Tenant Support (`vigil.tenant.enabled`)

### 1.6 Testing and Documentation
- [x] Unit tests (80% coverage, 47 tests)
- [x] Integration tests (12 scenarios)
- [x] README with quick start guide
- [x] Javadoc for public APIs

---

## Phase 2: Advanced Features (v1.1.0) - Planned

### 2.1 Session Management
- [ ] Session ID in JWT claims
- [ ] Per-session revocation support
- [ ] Device/session tracking interfaces

### 2.2 Observability
- [ ] Micrometer metrics for auth events
- [ ] Login success/failure counters
- [ ] Token generation/validation timers

### 2.3 Redis Adapters
- [ ] Redis-based token blacklist (alternative to Caffeine)
- [ ] Redis-based login attempt tracking
- [ ] Optional dependency, auto-detected

---

## Phase 3: Extended Integrations (v2.0.0) - Future

### 3.1 Simplified OAuth Wrappers
- [ ] Google OAuth simplified configuration
- [ ] GitHub OAuth simplified configuration

### 3.2 Event Hooks
- [ ] `onLoginSuccess` callback
- [ ] `onLoginFailure` callback
- [ ] `onTokenRefresh` callback

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
| 1.0.0 | Released | Core JWT, password, cookies, filter, optional modules |
| 1.1.0 | Planned | Sessions, metrics, Redis adapters |
| 2.0.0 | Future | OAuth wrappers, event hooks |
