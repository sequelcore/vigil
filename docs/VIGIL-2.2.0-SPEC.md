# Vigil v2.2.0 Specification

**Status**: Draft
**Author**: Sequel Engineering
**Date**: 2024-12-31

## Overview

Vigil v2.2.0 elevates the library from "JWT utilities" to "complete authentication solution". This release adds:

1. **Enhanced Password Service** - Production-grade password validation and security
2. **Session Authentication** - First-class support for stateful guest/anonymous sessions
3. **Auth Convenience Layer** - High-level operations for login, logout, refresh
4. **Password Reset Tokens** - Secure, single-use tokens for password recovery flows

### Design Principles

- **Zero boilerplate**: One interface to implement, everything else is automatic
- **Clean separation**: Vigil owns auth infrastructure, application owns domain entities
- **No dead code**: Every line serves a purpose
- **Professional documentation**: Javadoc on all public APIs

---

## 1. Enhanced Password Service

### Current State

```java
public class VigilPasswordService {
    String hash(String rawPassword);
    boolean matches(String rawPassword, String hashedPassword);
    PasswordValidationResult validate(String password);
}
```

### New API

```java
package io.github.sequelcore.vigil.core.password;

/**
 * Service for secure password hashing and validation.
 *
 * <p>Provides BCrypt hashing with configurable strength, password policy
 * validation, and security hygiene utilities like rehash detection.
 *
 * <p>Example usage:
 * <pre>{@code
 * // Hash a password
 * String hash = passwordService.hash("MyP@ssw0rd!");
 *
 * // Verify a password
 * if (passwordService.matches("MyP@ssw0rd!", hash)) {
 *     // Rehash if using outdated strength
 *     if (passwordService.needsRehash(hash)) {
 *         String newHash = passwordService.hash("MyP@ssw0rd!");
 *         userRepository.updatePasswordHash(userId, newHash);
 *     }
 * }
 *
 * // Validate password strength before hashing
 * PasswordStrength strength = passwordService.strength("weak");
 * if (strength.score() < 3) {
 *     throw new WeakPasswordException(strength.feedback());
 * }
 * }</pre>
 */
public class VigilPasswordService {

    /**
     * Hashes a password using BCrypt.
     *
     * @param rawPassword the plain text password
     * @return the BCrypt hash
     * @throws IllegalArgumentException if password is null or empty
     */
    public String hash(String rawPassword);

    /**
     * Verifies a password against a BCrypt hash.
     *
     * @param rawPassword the plain text password
     * @param hashedPassword the BCrypt hash
     * @return true if the password matches
     */
    public boolean matches(String rawPassword, String hashedPassword);

    /**
     * Checks if a hash needs rehashing due to outdated strength.
     *
     * <p>Use this after successful authentication to upgrade hashes
     * when BCrypt strength configuration increases.
     *
     * @param hashedPassword the BCrypt hash to check
     * @return true if the hash uses a lower strength than configured
     */
    public boolean needsRehash(String hashedPassword);

    /**
     * Evaluates password strength.
     *
     * <p>Returns a score from 0-4:
     * <ul>
     *   <li>0 - Very weak (common password, too short)
     *   <li>1 - Weak (missing character variety)
     *   <li>2 - Fair (meets minimum requirements)
     *   <li>3 - Strong (good length and variety)
     *   <li>4 - Very strong (excellent entropy)
     * </ul>
     *
     * @param password the password to evaluate
     * @return strength assessment with score and feedback
     */
    public PasswordStrength strength(String password);

    /**
     * Checks if a password appears in the common password dictionary.
     *
     * <p>Uses an embedded dictionary of 10,000 most common passwords.
     *
     * @param password the password to check
     * @return true if the password is commonly used
     */
    public boolean isCommon(String password);

    /**
     * Returns the underlying BCryptPasswordEncoder for Spring Security integration.
     *
     * <p>Use this when injecting into components that expect a PasswordEncoder:
     * <pre>{@code
     * @Bean
     * public PasswordEncoder passwordEncoder(VigilPasswordService passwordService) {
     *     return passwordService.encoder();
     * }
     * }</pre>
     *
     * @return the BCrypt encoder
     */
    public BCryptPasswordEncoder encoder();
}
```

### Supporting Types

```java
/**
 * Result of password strength evaluation.
 *
 * @param score strength score from 0 (very weak) to 4 (very strong)
 * @param feedback human-readable suggestions for improvement
 */
public record PasswordStrength(int score, List<String> feedback) {

    /** Minimum acceptable score for most applications. */
    public static final int MINIMUM_ACCEPTABLE = 2;

    /**
     * Checks if the password meets minimum strength requirements.
     *
     * @return true if score >= MINIMUM_ACCEPTABLE
     */
    public boolean isAcceptable() {
        return score >= MINIMUM_ACCEPTABLE;
    }
}
```

### Configuration

```yaml
vigil:
  password:
    strength: 12                    # BCrypt cost factor (default: 12)
    min-length: 8                   # Minimum password length (default: 8)
    require-uppercase: true         # Require uppercase letter (default: true)
    require-lowercase: true         # Require lowercase letter (default: true)
    require-digit: true             # Require digit (default: true)
    require-special: true           # Require special character (default: true)
    reject-common: true             # Reject common passwords (default: true)
```

---

## 2. Session Authentication

### Concept

Session authentication provides stateful identity for anonymous/guest users. Unlike JWT (stateless, self-contained), sessions require database lookup but enable:

- Guest checkout flows
- Anonymous trials/demos
- Temporary access before registration

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Application                              │
├─────────────────────────────────────────────────────────────────┤
│  CustomerSessionProvider implements VigilSessionProvider<Customer>
│  ├── findByToken(token, tenantId) → customerRepository.find...  │
│  ├── isExpired(customer) → customer.isSessionExpired()          │
│  ├── getPrincipal(customer) → customer.getId().toString()       │
│  └── onAuthenticated(customer, request) → set CustomerContext   │
├─────────────────────────────────────────────────────────────────┤
│                         Vigil                                    │
│  VigilSessionService                                             │
│  ├── generateToken() → UUID.randomUUID()                        │
│  ├── createSession(response) → generate + set cookie            │
│  ├── extractToken(request) → read cookie                        │
│  └── clearSession(response) → delete cookie                     │
│                                                                  │
│  VigilAuthenticationFilter                                       │
│  ├── Try JWT first                                              │
│  ├── If no JWT and sessionProvider exists → try session token   │
│  └── Call sessionProvider.onAuthenticated() on success          │
└─────────────────────────────────────────────────────────────────┘
```

### API

```java
package io.github.sequelcore.vigil.session;

/**
 * Provider for stateful session authentication.
 *
 * <p>Implement this interface to enable guest/anonymous session support.
 * Vigil handles token generation, cookies, and filter integration.
 * The application handles entity persistence and domain logic.
 *
 * <p>Example implementation:
 * <pre>{@code
 * @Component
 * @RequiredArgsConstructor
 * public class CustomerSessionProvider implements VigilSessionProvider<Customer> {
 *
 *     private final CustomerRepository repository;
 *
 *     @Override
 *     public Optional<Customer> findByToken(String token, UUID tenantId) {
 *         return repository.findBySessionToken(token, tenantId);
 *     }
 *
 *     @Override
 *     public boolean isExpired(Customer customer) {
 *         return customer.getSessionExpiresAt().isBefore(LocalDateTime.now());
 *     }
 *
 *     @Override
 *     public String getPrincipal(Customer customer) {
 *         return customer.getId().toString();
 *     }
 *
 *     @Override
 *     public void onAuthenticated(Customer customer, HttpServletRequest request) {
 *         CustomerContext.set(customer);
 *     }
 * }
 * }</pre>
 *
 * @param <T> the session entity type
 */
public interface VigilSessionProvider<T> {

    /**
     * Finds a session entity by token.
     *
     * @param token the session token (UUID string)
     * @param tenantId the tenant ID, or null if multi-tenancy is disabled
     * @return the session entity if found and valid
     */
    Optional<T> findByToken(String token, UUID tenantId);

    /**
     * Checks if the session has expired.
     *
     * @param session the session entity
     * @return true if the session is expired
     */
    boolean isExpired(T session);

    /**
     * Returns the principal identifier for Spring Security context.
     *
     * <p>Typically the entity ID as a string.
     *
     * @param session the session entity
     * @return the principal identifier
     */
    String getPrincipal(T session);

    /**
     * Returns the granted authorities for the session.
     *
     * <p>Default implementation returns {@code ["GUEST"]}.
     *
     * @param session the session entity
     * @return list of role names (without ROLE_ prefix)
     */
    default List<String> getRoles(T session) {
        return List.of("GUEST");
    }

    /**
     * Called after successful session authentication.
     *
     * <p>Use this to populate application-specific thread-local contexts.
     *
     * @param session the authenticated session entity
     * @param request the HTTP request
     */
    default void onAuthenticated(T session, HttpServletRequest request) {
        // Default: no-op
    }
}
```

```java
package io.github.sequelcore.vigil.session;

/**
 * Service for managing session tokens and cookies.
 *
 * <p>Handles the infrastructure aspects of session authentication:
 * token generation, cookie management, and extraction.
 *
 * <p>Example usage:
 * <pre>{@code
 * @PostMapping("/guest-session")
 * public GuestResponse createGuestSession(HttpServletResponse response) {
 *     String token = sessionService.createSession(response);
 *     Customer customer = customerService.createGuest(token);
 *     return new GuestResponse(customer.getId(), token);
 * }
 * }</pre>
 */
public class VigilSessionService {

    /**
     * Generates a new session token.
     *
     * <p>Returns a random UUID. Does not set any cookies or persist anything.
     *
     * @return new session token
     */
    public String generateToken();

    /**
     * Creates a session and sets the cookie.
     *
     * <p>Generates a token and sets it as an HTTP-only cookie.
     *
     * @param response the HTTP response
     * @return the generated session token
     */
    public String createSession(HttpServletResponse response);

    /**
     * Extracts the session token from the request cookie.
     *
     * @param request the HTTP request
     * @return the session token if present
     */
    public Optional<String> extractToken(HttpServletRequest request);

    /**
     * Clears the session cookie.
     *
     * @param response the HTTP response
     */
    public void clearSession(HttpServletResponse response);
}
```

### Configuration

```yaml
vigil:
  session:
    enabled: true                   # Enable session authentication (default: false)
    cookie-name: session_token      # Cookie name (default: session_token)
    ttl: 30m                        # Cookie max-age (default: 30m)
```

---

## 3. Auth Convenience Layer

### Problem

Currently, applications must manually orchestrate multiple Vigil services:

```java
// Current: 30+ lines for token refresh
String refreshToken = cookieService.getRefreshToken(request, profile).orElseThrow(...);
if (blacklistService.isBlacklisted(refreshToken)) throw ...;
Claims claims = tokenService.validateAndGetClaims(refreshToken);
String tenantId = claims.get("tenantId", String.class);
// ... validate tenant, lookup user, generate new tokens, set cookies ...
```

### Solution

```java
package io.github.sequelcore.vigil.auth;

/**
 * High-level authentication operations.
 *
 * <p>Provides convenient methods that orchestrate token service,
 * cookie service, and blacklist service for common auth flows.
 *
 * <p>Example usage:
 * <pre>{@code
 * @PostMapping("/refresh")
 * public ResponseEntity<TokenResponse> refresh(
 *         HttpServletRequest request,
 *         HttpServletResponse response) {
 *     AuthResult result = authService.refresh(request, response, "staff");
 *     return ResponseEntity.ok(new TokenResponse(result));
 * }
 *
 * @PostMapping("/logout")
 * public ResponseEntity<Void> logout(
 *         HttpServletRequest request,
 *         HttpServletResponse response) {
 *     authService.logout(request, response, "staff");
 *     return ResponseEntity.ok().build();
 * }
 * }</pre>
 */
public class VigilAuthService {

    /**
     * Refreshes the access token using the refresh token from cookies.
     *
     * <p>This method:
     * <ol>
     *   <li>Extracts refresh token from cookie
     *   <li>Validates it's not blacklisted
     *   <li>Validates the JWT signature and expiration
     *   <li>Blacklists the old refresh token (rotation)
     *   <li>Generates new access and refresh tokens
     *   <li>Sets new cookies
     * </ol>
     *
     * @param request the HTTP request
     * @param response the HTTP response
     * @param profile the cookie profile (e.g., "staff", "customer")
     * @return the new tokens and expiration times
     * @throws VigilAuthException if refresh fails
     */
    public AuthResult refresh(HttpServletRequest request,
                              HttpServletResponse response,
                              String profile);

    /**
     * Refreshes tokens with updated claims.
     *
     * <p>Use this when user data has changed and tokens need new claims.
     *
     * @param request the HTTP request
     * @param response the HTTP response
     * @param profile the cookie profile
     * @param updatedClaims claims to add/update in new tokens
     * @return the new tokens and expiration times
     * @throws VigilAuthException if refresh fails
     */
    public AuthResult refresh(HttpServletRequest request,
                              HttpServletResponse response,
                              String profile,
                              Map<String, Object> updatedClaims);

    /**
     * Logs out by blacklisting tokens and clearing cookies.
     *
     * <p>This method:
     * <ol>
     *   <li>Extracts access and refresh tokens from cookies
     *   <li>Blacklists both tokens
     *   <li>Clears the cookies
     * </ol>
     *
     * @param request the HTTP request
     * @param response the HTTP response
     * @param profile the cookie profile
     */
    public void logout(HttpServletRequest request,
                       HttpServletResponse response,
                       String profile);

    /**
     * Gets the current authenticated principal from SecurityContext.
     *
     * @return the principal if authenticated
     */
    public Optional<VigilPrincipal> getCurrentPrincipal();

    /**
     * Gets the current tenant ID from Vigil's tenant context.
     *
     * @return the tenant ID if set
     */
    public Optional<UUID> getCurrentTenant();

    /**
     * Invalidates all active sessions for a user.
     *
     * <p>Use this after password change or account compromise to force re-authentication.
     * Works by adding a user-level blacklist entry that rejects all tokens issued before now.
     *
     * <p>Example usage:
     * <pre>{@code
     * // After password change
     * user.setPasswordHash(passwordService.hash(newPassword));
     * userRepository.save(user);
     * authService.invalidateAllSessions(user.getEmail());
     * }</pre>
     *
     * @param subject the user identifier (typically email or userId)
     */
    public void invalidateAllSessions(String subject);
}
```

### Supporting Types

```java
/**
 * Result of a successful authentication or refresh operation.
 *
 * @param accessToken the new access token
 * @param refreshToken the new refresh token
 * @param accessExpiresAt when the access token expires
 * @param refreshExpiresAt when the refresh token expires
 * @param claims the token claims
 */
public record AuthResult(
    String accessToken,
    String refreshToken,
    Instant accessExpiresAt,
    Instant refreshExpiresAt,
    VigilTokenClaims claims
) {}

/**
 * Authenticated principal extracted from token claims.
 */
public record VigilPrincipal(
    String subject,
    UUID tenantId,
    List<String> roles,
    Map<String, Object> claims
) {
    /**
     * Gets a claim value.
     *
     * @param key the claim key
     * @return the claim value if present
     */
    public Optional<String> getClaim(String key);

    /**
     * Checks if the principal has a specific role.
     *
     * @param role the role name (without ROLE_ prefix)
     * @return true if the principal has the role
     */
    public boolean hasRole(String role);
}

/**
 * Exception thrown when authentication operations fail.
 */
public class VigilAuthException extends RuntimeException {

    private final AuthErrorCode code;

    public enum AuthErrorCode {
        TOKEN_NOT_FOUND,
        TOKEN_EXPIRED,
        TOKEN_BLACKLISTED,
        TOKEN_INVALID,
        TENANT_MISMATCH,
        SESSION_EXPIRED,
        SESSION_NOT_FOUND,
        RESET_TOKEN_EXPIRED,
        RESET_TOKEN_INVALID,
        RESET_TOKEN_USED
    }
}
```

---

## 4. Password Reset Tokens

### Concept

Password reset requires secure, single-use tokens that:
- Are cryptographically signed (tamper-proof)
- Expire after a configured duration
- Can only be used once (prevent replay attacks)
- Contain minimal information (just subject/email)

Vigil handles the **token infrastructure**. Application handles the **workflow** (email sending, user lookup, password update).

### API

```java
package io.github.sequelcore.vigil.auth;

/**
 * Service for generating and validating password reset tokens.
 *
 * <p>Reset tokens are:
 * <ul>
 *   <li>Cryptographically signed (tamper-proof)
 *   <li>Time-limited (configurable TTL)
 *   <li>Single-use (automatically blacklisted after validation)
 * </ul>
 *
 * <p>Example password reset flow:
 * <pre>{@code
 * // 1. User requests password reset
 * @PostMapping("/forgot-password")
 * public ResponseEntity<Void> forgotPassword(@RequestBody ForgotRequest request) {
 *     userRepository.findByEmail(request.email()).ifPresent(user -> {
 *         String token = resetTokenService.generate(user.getEmail());
 *         String resetUrl = frontendUrl + "/reset-password?token=" + token;
 *         emailService.sendPasswordReset(user.getEmail(), resetUrl);
 *     });
 *     return ResponseEntity.ok().build();  // Silent success for security
 * }
 *
 * // 2. User clicks link, frontend shows form
 * @GetMapping("/reset-password/validate")
 * public ResponseEntity<Void> validateToken(@RequestParam String token) {
 *     resetTokenService.validate(token);  // Throws if invalid
 *     return ResponseEntity.ok().build();
 * }
 *
 * // 3. User submits new password
 * @PostMapping("/reset-password")
 * public ResponseEntity<Void> resetPassword(@RequestBody ResetRequest request) {
 *     String email = resetTokenService.validateAndConsume(request.token());
 *     User user = userRepository.findByEmail(email).orElseThrow();
 *
 *     PasswordStrength strength = passwordService.strength(request.newPassword());
 *     if (!strength.isAcceptable()) {
 *         throw new ValidationException(strength.feedback());
 *     }
 *
 *     user.setPasswordHash(passwordService.hash(request.newPassword()));
 *     userRepository.save(user);
 *     authService.invalidateAllSessions(email);
 *
 *     return ResponseEntity.ok().build();
 * }
 * }</pre>
 */
public class VigilResetTokenService {

    /**
     * Generates a password reset token.
     *
     * <p>The token is a signed JWT containing:
     * <ul>
     *   <li>Subject (email)
     *   <li>Expiration time
     *   <li>Unique token ID (jti) for single-use enforcement
     *   <li>Type claim ("reset")
     * </ul>
     *
     * @param subject the user identifier (typically email)
     * @return the reset token
     */
    public String generate(String subject);

    /**
     * Generates a password reset token with custom TTL.
     *
     * @param subject the user identifier
     * @param ttl time until expiration
     * @return the reset token
     */
    public String generate(String subject, Duration ttl);

    /**
     * Validates a reset token without consuming it.
     *
     * <p>Use this for pre-validation (e.g., showing the reset password form
     * before the user submits). Does not invalidate the token.
     *
     * @param token the reset token
     * @return the subject (email) from the token
     * @throws VigilAuthException with RESET_TOKEN_EXPIRED if expired
     * @throws VigilAuthException with RESET_TOKEN_USED if already consumed
     * @throws VigilAuthException with RESET_TOKEN_INVALID if malformed
     */
    public String validate(String token);

    /**
     * Validates and consumes a reset token.
     *
     * <p>After calling this method, the token is blacklisted and cannot
     * be used again. This prevents replay attacks.
     *
     * @param token the reset token
     * @return the subject (email) from the token
     * @throws VigilAuthException if token is invalid, expired, or already used
     */
    public String validateAndConsume(String token);

    /**
     * Checks if a reset token has been consumed.
     *
     * @param token the reset token
     * @return true if the token has been used
     */
    public boolean isConsumed(String token);
}
```

### Configuration

```yaml
vigil:
  reset:
    ttl: 1h                         # Reset token TTL (default: 1h)
```

### Security Considerations

1. **Silent failures** - Never reveal if an email exists in the system
2. **Rate limiting** - Use `VigilProtectionService` to limit reset requests per email/IP
3. **Secure transport** - Reset links must use HTTPS
4. **Token in URL** - Acceptable because tokens are single-use and short-lived
5. **Invalidate sessions** - Always call `authService.invalidateAllSessions()` after password change

---

## 5. Filter Updates

### Enhanced VigilAuthenticationFilter

```java
/**
 * JWT and session authentication filter.
 *
 * <p>Authentication flow:
 * <ol>
 *   <li>Check if path is public → skip authentication
 *   <li>Try to extract JWT from Authorization header or cookie
 *   <li>If JWT found → validate and authenticate
 *   <li>If no JWT and session provider exists → try session token
 *   <li>If no authentication → call onMissingAuthentication()
 * </ol>
 *
 * <p>Extend this class to customize authentication behavior:
 * <pre>{@code
 * @Component
 * public class MyAuthFilter extends VigilAuthenticationFilter {
 *
 *     @Override
 *     protected void onAuthenticationSuccess(
 *             HttpServletRequest request,
 *             HttpServletResponse response,
 *             VigilTokenClaims claims) {
 *         // Populate application-specific context
 *         MyUserContext.set(claims.getString("userId").orElse(null));
 *     }
 * }
 * }</pre>
 */
public class VigilAuthenticationFilter extends OncePerRequestFilter {

    // ... existing methods ...

    // New session-related hooks

    /**
     * Called when session authentication succeeds.
     *
     * @param request the HTTP request
     * @param response the HTTP response
     * @param session the authenticated session entity
     */
    protected void onSessionAuthenticated(HttpServletRequest request,
                                          HttpServletResponse response,
                                          Object session) {}

    /**
     * Called when session token is not found in database.
     *
     * @param request the HTTP request
     * @param response the HTTP response
     * @param token the session token that was not found
     */
    protected void onSessionNotFound(HttpServletRequest request,
                                     HttpServletResponse response,
                                     String token) {}

    /**
     * Called when session has expired.
     *
     * @param request the HTTP request
     * @param response the HTTP response
     * @param token the session token
     * @param session the expired session entity
     */
    protected void onSessionExpired(HttpServletRequest request,
                                    HttpServletResponse response,
                                    String token,
                                    Object session) {}
}
```

---

## 5. Updated Configuration

### Complete Configuration Example

```yaml
vigil:
  # JWT Configuration
  jwt:
    secret: ${JWT_SECRET}           # Required: min 32 characters
    access-ttl: 15m                 # Access token TTL (default: 15m)
    refresh-ttl: 7d                 # Refresh token TTL (default: 7d)
    issuer: my-app                  # Optional: token issuer claim
    audience: my-app                # Optional: token audience claim

  # Cookie Configuration
  cookie:
    secure: true                    # Secure flag (default: true)
    http-only: true                 # HttpOnly flag (default: true)
    same-site: Lax                  # SameSite policy (default: Lax)
    profiles:
      staff:
        access-token-name: staff_access_token
        refresh-token-name: staff_refresh_token
      customer:
        access-token-name: customer_access_token
        refresh-token-name: customer_refresh_token

  # Password Configuration
  password:
    strength: 12                    # BCrypt cost factor (default: 12)
    min-length: 8                   # Minimum length (default: 8)
    require-uppercase: true
    require-lowercase: true
    require-digit: true
    require-special: true
    reject-common: true             # Reject common passwords (default: true)

  # Session Configuration
  session:
    enabled: true                   # Enable session auth (default: false)
    cookie-name: session_token      # Cookie name (default: session_token)
    ttl: 30m                        # Session TTL (default: 30m)

  # Password Reset Configuration
  reset:
    ttl: 1h                         # Reset token TTL (default: 1h)

  # Token Blacklist Configuration
  blacklist:
    max-size: 10000                 # Max entries (default: 10000)
    ttl: 24h                        # Entry TTL (default: 24h)

  # Brute-force Protection Configuration
  protection:
    max-attempts: 5                 # Failed attempts before lockout (default: 5)
    lock-duration: 15m              # Lockout duration (default: 15m)
    max-size: 10000                 # Max tracked identifiers (default: 10000)

  # Multi-tenancy Configuration
  tenant:
    enabled: true                   # Enable multi-tenancy (default: false)
    header-name: X-Tenant-ID        # Header name (default: X-Tenant-ID)

  # Filter Configuration
  filter:
    public-paths:                   # Paths that skip authentication
      - /actuator/health
      - /api/v1/auth/**
      - /api/v1/public/**
```

---

## 6. Auto-Configuration

### Bean Registration

```java
@AutoConfiguration
@EnableConfigurationProperties(VigilProperties.class)
public class VigilAutoConfiguration {

    // Existing beans...

    @Bean
    @ConditionalOnMissingBean
    public VigilAuthService vigilAuthService(
            VigilTokenService tokenService,
            VigilCookieService cookieService,
            VigilBlacklistService blacklistService,
            VigilProperties properties) {
        return new VigilAuthService(tokenService, cookieService, blacklistService, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "vigil.session", name = "enabled", havingValue = "true")
    public VigilSessionService vigilSessionService(
            VigilCookieService cookieService,
            VigilProperties properties) {
        return new VigilSessionService(cookieService, properties.session());
    }

    @Bean
    @ConditionalOnMissingBean
    public VigilResetTokenService vigilResetTokenService(
            VigilTokenService tokenService,
            VigilBlacklistService blacklistService,
            VigilProperties properties) {
        return new VigilResetTokenService(tokenService, blacklistService, properties.reset());
    }

    // VigilSessionProvider is provided by application, not auto-configured
}
```

---

## 7. Migration Guide

### From SHRAD Custom Auth to Vigil 2.2.0

#### Step 1: Update Dependency

```gradle
implementation 'io.github.sequelcore:vigil-spring-boot-starter:2.2.0'
```

#### Step 2: Implement VigilSessionProvider (if using guest sessions)

```java
@Component
@RequiredArgsConstructor
public class CustomerSessionProvider implements VigilSessionProvider<Customer> {

    private final CustomerRepository repository;

    @Override
    public Optional<Customer> findByToken(String token, UUID tenantId) {
        return repository.findBySessionToken(
            SessionToken.of(token),
            TenantId.of(tenantId.toString()));
    }

    @Override
    public boolean isExpired(Customer customer) {
        return customer.isSessionExpired();
    }

    @Override
    public String getPrincipal(Customer customer) {
        return customer.getId().value().toString();
    }

    @Override
    public void onAuthenticated(Customer customer, HttpServletRequest request) {
        CustomerSecurityContext.setContext(new CustomerSecurityInfo(
            customer.getId(),
            customer.getTenantId(),
            customer.getType(),
            customer.getEmail() != null ? customer.getEmail().value() : null));
    }
}
```

#### Step 3: Simplify Controllers

Before:
```java
@PostMapping("/refresh")
public ResponseEntity<TokenResponse> refresh(HttpServletRequest request, HttpServletResponse response) {
    String refreshToken = cookieService.getRefreshToken(request, "staff")
        .orElseThrow(() -> new UserValidationException("Refresh token not found"));
    if (blacklistService.isBlacklisted(refreshToken)) {
        throw new UserValidationException("Token invalidated");
    }
    VigilTokenClaims claims = new VigilTokenClaims(tokenService.validateAndGetClaims(refreshToken));
    // ... 30 more lines ...
}
```

After:
```java
@PostMapping("/refresh")
public ResponseEntity<TokenResponse> refresh(HttpServletRequest request, HttpServletResponse response) {
    AuthResult result = authService.refresh(request, response, "staff");
    return ResponseEntity.ok(new TokenResponse(result));
}
```

#### Step 4: Delete Deprecated Code

- `BCryptPasswordService.java`
- `PasswordService.java` (domain interface)
- Guest session handling in `ShradAuthenticationFilter`
- Cookie extraction methods in controllers

---

## 8. File Structure

```
vigil/src/main/java/io/github/sequelcore/vigil/
├── auth/
│   ├── VigilAuthService.java           # NEW: High-level auth operations
│   ├── VigilResetTokenService.java     # NEW: Password reset tokens
│   ├── AuthResult.java                 # NEW: Auth operation result
│   ├── VigilPrincipal.java             # NEW: Type-safe principal
│   └── VigilAuthException.java         # NEW: Auth exception with codes
├── autoconfigure/
│   ├── VigilAutoConfiguration.java     # UPDATED: New beans
│   └── VigilProperties.java            # UPDATED: New config sections
├── blacklist/
│   ├── VigilBlacklistBackend.java
│   ├── VigilBlacklistService.java
│   └── CaffeineBlacklistBackend.java
├── core/
│   ├── cookie/
│   │   └── VigilCookieService.java
│   ├── jwt/
│   │   ├── VigilTokenService.java
│   │   ├── VigilTokenClaims.java
│   │   ├── TokenRequest.java
│   │   └── TokenRefreshResult.java
│   └── password/
│       ├── VigilPasswordService.java   # UPDATED: Enhanced API
│       ├── PasswordStrength.java       # NEW: Strength result
│       └── CommonPasswords.java        # NEW: Embedded dictionary
├── filter/
│   └── VigilAuthenticationFilter.java  # UPDATED: Session support
├── protection/
│   └── VigilProtectionService.java
├── session/
│   ├── VigilSessionService.java        # NEW: Session management
│   └── VigilSessionProvider.java       # NEW: Provider interface
├── tenant/
│   ├── VigilTenantService.java
│   └── VigilTenantContext.java
└── package-info.java
```

---

## 9. Testing Requirements

### Unit Tests

- `VigilPasswordServiceTest` - hash, matches, needsRehash, strength, isCommon
- `VigilSessionServiceTest` - generateToken, createSession, extractToken, clearSession
- `VigilAuthServiceTest` - refresh, logout, invalidateAllSessions, getCurrentPrincipal
- `VigilResetTokenServiceTest` - generate, validate, validateAndConsume, isConsumed
- `PasswordStrengthTest` - score calculation, feedback messages

### Integration Tests

- **Complete JWT auth flow**: login → use protected endpoint → refresh → logout
- **Session auth flow**: create guest → use protected endpoint → expire → reject
- **Password reset flow**: generate token → validate → consume → reject reuse
- **Session invalidation**: login → change password → old tokens rejected
- **Multi-tenant isolation**: tokens from tenant A rejected in tenant B context

### Test Coverage

- Minimum: 80% line coverage
- Critical paths: 100% coverage (token validation, blacklist checks)

---

## 10. Documentation

- Javadoc on all public classes and methods
- README.md update with new features
- Migration guide from v2.0.x to v2.2.0
- Example project demonstrating all features

---

## Appendix A: Common Passwords Dictionary

Embed top 10,000 common passwords from SecLists. Store as compressed resource file, load lazily on first use.

## Appendix B: Breaking Changes

None. v2.2.0 is fully backward compatible with v2.0.x.
