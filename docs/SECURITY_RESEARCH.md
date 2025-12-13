# Vigil Security Research (December 2025)

> Research base for Phase 2: Security Hardening (v1.1.0)

## Sources

### Official Standards
- [OWASP JWT Cheat Sheet for Java](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [NIST SP 800-63-4 Digital Identity Guidelines](https://csrc.nist.gov/pubs/sp/800/63/4/final) (Final, July 2025)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [MDN Cookie Security Guide](https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/Cookies)

### Industry Leaders
- [Auth0 Refresh Token Rotation](https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation)
- [Okta Key Rotation](https://developer.okta.com/docs/concepts/key-rotation/)
- [Zalando JWK Rotation](https://engineering.zalando.com/posts/2025/01/automated-json-web-key-rotation.html)

---

## 1. JWT Algorithm Security

### CVEs to Prevent

| CVE | Library | Attack | Impact |
|-----|---------|--------|--------|
| CVE-2024-54150 | cjwt | Algorithm confusion (RS256→HS256) | Token forgery |
| CVE-2024-37568 | Authlib | Missing `alg` defaults to HMAC | Token forgery |
| CVE-2023-48223 | fast-jwt | Public key format bypass | Token forgery |
| CVE-2015-9235 | Multiple | `alg: none` accepted | Complete bypass |

### Root Cause

> "A relying party must verify the integrity of the JWT based on its own configuration or hard-coded logic. It must not rely on the information of the JWT header to select the verification algorithm." — OWASP

### Mitigation Strategy

```java
// WRONG: Trust the token header
String alg = jwt.getHeader().getAlgorithm();
verify(jwt, alg);

// CORRECT: Enforce expected algorithm
verify(jwt, Algorithm.HS256); // Server decides, not token
```

### Algorithm Recommendations (2025)

| Algorithm | Use Case | Notes |
|-----------|----------|-------|
| **EdDSA** | New projects | Fastest, quantum-resistant properties |
| **ES256** | Modern systems | ECDSA with P-256 curve |
| **RS256** | Legacy/compatibility | Widely supported |
| **PS256** | High security | More secure than RS256 |
| HS256 | Internal only | Symmetric, shared secret risk |

### Vigil Decision
- **v1.0.0**: HS256 (symmetric) - simple, single service
- **v1.1.0**: Add algorithm enforcement (native, non-configurable)
- **v2.0.0**: Add RS256/ES256/EdDSA support

---

## 2. Refresh Token Rotation

### Why It's Critical

> "Refresh token rotation is a security mechanism designed to minimize the risks associated with token theft. Each time a refresh token is used, a new one is generated and the previous one is invalidated. This ensures compromised tokens lose utility almost immediately." — Auth0

### Token Family Tracking

When rotation is enabled, tokens form a "family":

```
Login → RT₁
       ↓ (refresh)
       RT₂ (RT₁ invalidated)
       ↓ (refresh)
       RT₃ (RT₂ invalidated)
```

### Reuse Detection Attack Scenario

```
Attacker steals RT₁
                    User refreshes: RT₁ → RT₂
Attacker uses RT₁ → DETECTED! Entire family revoked
                    User forced to re-authenticate
```

### Implementation Requirements

1. **One-time use**: Each refresh token can only be used once
2. **Family tracking**: Associate all tokens from same login session
3. **Reuse detection**: If old token used, revoke entire family
4. **Atomic operations**: Token swap must be atomic (no race conditions)

### Storage Options

| Backend | Pros | Cons |
|---------|------|------|
| Caffeine (in-memory) | Fast, no deps | Lost on restart, single node |
| Redis | Distributed, persistent | External dependency |
| Database | Persistent, auditable | Slower |

### Vigil Decision
- **Native**: Token rotation always enabled (non-configurable)
- **Configurable**: Storage backend (Caffeine default, Redis optional)

---

## 3. Token Sidejacking Prevention (OWASP)

### The Problem

Even with HttpOnly cookies, tokens can be stolen via:
- XSS reading response body before cookie is set
- Man-in-the-middle on non-HTTPS
- Malware accessing browser storage

### OWASP Solution: Fingerprint Cookie

1. On login, generate random string (fingerprint)
2. Store SHA256(fingerprint) in JWT payload
3. Send fingerprint in hardened cookie (HttpOnly, Secure, SameSite)
4. On each request, verify: SHA256(cookie) === JWT claim

```java
// Login flow
String fingerprint = generateRandomString(32);
String fingerprintHash = sha256(fingerprint);

String jwt = Jwts.builder()
    .claim("fgp", fingerprintHash)  // Hash in token
    .signWith(key)
    .compact();

Cookie cookie = new Cookie("__Secure-Fgp", fingerprint);
cookie.setHttpOnly(true);
cookie.setSecure(true);
cookie.setSameSite(SameSite.STRICT);
```

### Why This Works

- Attacker steals JWT via XSS → Can't read HttpOnly cookie
- Attacker steals cookie → Can't modify JWT (signed)
- Both needed for valid request

### Vigil Decision
- **v1.1.0**: Implement fingerprint as optional (performance tradeoff)
- **v1.2.0**: Make native for web clients, skip for API-only

---

## 4. Claims Validation

### Required Claims (OWASP)

| Claim | Purpose | Validation |
|-------|---------|------------|
| `iss` | Issuer | Must match configured issuer |
| `aud` | Audience | Must include this application |
| `exp` | Expiration | Current time < exp |
| `nbf` | Not before | Current time >= nbf |
| `iat` | Issued at | iat <= current time |

### Clock Skew Tolerance

Systems may have slightly different clocks. Allow small tolerance:

```java
.setAllowedClockSkewSeconds(30)
```

### Vigil Decision
- **Native**: All claims validation (non-configurable)
- **Configurable**: `iss` and `aud` values, clock skew tolerance

---

## 5. Key Rotation

### Why Rotate Keys

> "Static secrets are ticking time bombs. The same is true for cryptographic key material in the context of JWTs." — Zalando Engineering

### Rotation Process (Zalando)

1. Generate new key pair
2. Publish public key to JWKS endpoint
3. Grace period (clients fetch new keys)
4. Switch signing to new key
5. Keep old public key for verification
6. Remove old key after max token lifetime

### JWKS Endpoint

```json
{
  "keys": [
    {
      "kid": "key-2025-12",
      "kty": "RSA",
      "use": "sig",
      "n": "...",
      "e": "AQAB"
    },
    {
      "kid": "key-2025-09",
      "kty": "RSA",
      "use": "sig",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

### JWT with Key ID

```json
{
  "alg": "RS256",
  "kid": "key-2025-12",
  "typ": "JWT"
}
```

### Vigil Decision
- **v1.1.0**: Add `kid` header support
- **v2.0.0**: Full key rotation with JWKS endpoint

---

## 6. Password Hashing

### OWASP 2025 Recommendations

| Priority | Algorithm | Configuration |
|----------|-----------|---------------|
| 1 | **Argon2id** | 19 MiB memory, 2 iterations, 1 parallelism |
| 2 | scrypt | N=2^17, r=8, p=1 |
| 3 | bcrypt | Work factor 10+ (we use 12) |
| 4 | PBKDF2 | Only if FIPS required |

### BCrypt Limitation

> "bcrypt has a maximum length input of 72 bytes for most implementations"

### Migration Path

Vigil v1.0.0 uses BCrypt (widely supported). Migration to Argon2id:

```java
// On login, if hash is BCrypt format:
if (passwordService.verify(password, storedHash)) {
    if (isBcryptHash(storedHash)) {
        String newHash = argon2Service.hash(password);
        userRepository.updatePasswordHash(userId, newHash);
    }
}
```

### Vigil Decision
- **v1.0.0**: BCrypt with cost factor 12 (current)
- **v1.2.0**: Add Argon2id support (optional)
- **v2.0.0**: Argon2id as default, BCrypt for legacy

---

## 7. Cookie Security

### Required Attributes (MDN 2025)

| Attribute | Value | Purpose |
|-----------|-------|---------|
| `HttpOnly` | true | Block XSS access |
| `Secure` | true | HTTPS only |
| `SameSite` | Lax/Strict | CSRF protection |
| `Path` | / | Scope limitation |
| `Max-Age` | <token TTL> | Expiration |

### Cookie Prefixes

```
__Secure-  → Requires Secure attribute
__Host-    → Requires Secure, no Domain, Path=/
```

### SameSite Values

| Value | Cross-site Requests | Use Case |
|-------|---------------------|----------|
| Strict | Never sent | High security |
| Lax | Only top-level nav | Balance (default) |
| None | Always (requires Secure) | Cross-origin APIs |

### Vigil Decision
- **Native**: HttpOnly=true, SameSite=Lax
- **Native in production**: Secure=true
- **Configurable**: Cookie names, path, domain

---

## 8. Session Timeouts (NIST SP 800-63-4)

### Requirements by Assurance Level

| Level | Inactivity Timeout | Absolute Lifetime |
|-------|-------------------|-------------------|
| AAL1 | 30 minutes | 12 hours |
| AAL2 | 30 minutes | 12 hours (or re-auth) |
| AAL3 | 15 minutes | 12 hours (or re-auth) |

### Vigil Decision

Apply AAL2 as baseline:

| Setting | Default | Max Allowed | Rationale |
|---------|---------|-------------|-----------|
| Access TTL | 15 min | 60 min | Short-lived |
| Refresh TTL | 7 days | 30 days | With rotation |
| Inactivity | 30 min | 30 min | NIST AAL2 |

---

## 9. Native vs Configurable Summary

### Native (Non-Configurable)

These are **security invariants** - disabling them creates vulnerabilities:

| Feature | Standard | Rationale |
|---------|----------|-----------|
| Algorithm enforcement | OWASP | CVE-2024-54150, CVE-2015-9235 |
| `alg: none` rejection | OWASP | Critical vulnerability |
| Claims validation | OWASP | Basic JWT security |
| Refresh token rotation | Auth0/Okta | Token theft mitigation |
| Reuse detection | Auth0 | Attack indicator |
| HttpOnly cookies | MDN | XSS protection |
| Secure flag (prod) | MDN | MITM protection |
| SameSite attribute | MDN | CSRF protection |
| BCrypt min cost (10) | OWASP | Brute-force resistance |
| Max TTL ceilings | NIST | Session limits |

### Configurable (With Sensible Defaults)

| Feature | Default | Why Configurable |
|---------|---------|------------------|
| Access TTL | 15 min | App-specific needs |
| Refresh TTL | 7 days | App-specific needs |
| BCrypt cost | 12 | Performance tuning |
| Public paths | [] | API design varies |
| Cookie names | vigil_* | Integration needs |
| Issuer/Audience | app name | Deployment-specific |
| Blacklist storage | Caffeine | Infrastructure varies |

---

## 10. Competitive Analysis

### What Leaders Do

| Feature | Auth0 | Okta | Keycloak | Vigil Target |
|---------|-------|------|----------|--------------|
| Token rotation | ✅ | ✅ | ✅ | v1.1.0 |
| Reuse detection | ✅ | ✅ | ✅ | v1.1.0 |
| JWKS endpoint | ✅ | ✅ | ✅ | v2.0.0 |
| Key rotation | ✅ | ✅ | ✅ | v2.0.0 |
| Asymmetric signing | ✅ | ✅ | ✅ | v2.0.0 |
| Fingerprint cookies | ✅ | - | - | v1.1.0 |
| Argon2id | - | - | ✅ | v1.2.0 |

### Vigil Differentiator

**Opinionated security-first**: While Auth0/Okta make rotation optional, Vigil enforces it. We trade flexibility for safety - you can't accidentally deploy an insecure configuration.

---

## 11. Implementation Priority

### v1.1.0 (Security Hardening)
1. Native token rotation with reuse detection
2. Algorithm enforcement (server-side)
3. Full claims validation (iss, aud, exp, nbf, iat)
4. Token sidejacking prevention (fingerprint)
5. `kid` header support
6. TTL ceiling enforcement

### v1.2.0 (Advanced Security)
1. Argon2id password hashing
2. Session ID tracking
3. Security event logging
4. Redis storage adapters

### v2.0.0 (Enterprise)
1. Full key rotation with JWKS
2. Asymmetric algorithms (RS256, ES256, EdDSA)
3. HSM/KMS integration

---

## References

1. OWASP. "JSON Web Token for Java Cheat Sheet." 2024. https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
2. NIST. "SP 800-63-4 Digital Identity Guidelines." July 2025. https://csrc.nist.gov/pubs/sp/800/63/4/final
3. Auth0. "Refresh Token Rotation." 2024. https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation
4. Okta. "Key Rotation." 2024. https://developer.okta.com/docs/concepts/key-rotation/
5. Zalando. "JSON Web Keys: Rotating Cryptographic Keys." January 2025. https://engineering.zalando.com/posts/2025/01/automated-json-web-key-rotation.html
6. PortSwigger. "JWT Attacks." 2024. https://portswigger.net/web-security/jwt
7. OWASP. "Password Storage Cheat Sheet." 2024. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
