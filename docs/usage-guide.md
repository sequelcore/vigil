# Usage Guide

Vigil is for Spring applications that want explicit JWT authentication without
turning authentication into a user-management framework. It owns token
lifecycle, request authentication, cookies, reset tokens, tenant context, guest
session hooks, and blacklist-backed revocation.

Vigil does not own user storage, credential validation, registration flows,
authorization policy, OAuth authorization-server endpoints, OIDC provider
behavior, email delivery, SMS delivery, or MFA orchestration.

## Choosing The Client Path

Use cookie-based flows for browser clients that can rely on HTTP-only cookies:

```java
AuthResult result = authService.login(
    response,
    user.email(),
    Map.of("userId", user.id(), "roles", user.roles()));
```

The application validates credentials before calling Vigil. Vigil issues the
tokens, writes cookies through the configured cookie profile, and applies the
configured access and refresh TTLs.

Use token-body flows for native applications, CLIs, service clients, and APIs
that should receive tokens in the response body:

```java
AuthResult result = authService.login(
    user.email(),
    Map.of("userId", user.id(), "roles", user.roles()));
```

Native clients should store returned tokens in platform secure storage. Browser
clients should prefer HTTP-only cookies unless the application has a deliberate
reason to expose bearer tokens to JavaScript.

## Spring Security Wiring

Vigil auto-configures a `VigilAuthenticationFilter` bean. The application still
owns the `SecurityFilterChain` and must place the filter inside that chain:

```java
http.addFilterBefore(
    vigilAuthenticationFilter,
    UsernamePasswordAuthenticationFilter.class);
```

`ignored-paths` skip Vigil processing only. They do not grant Spring Security
access by themselves. Permit anonymous routes in `authorizeHttpRequests` when
health, login, registration, public content, or JWKS endpoints should be
reachable without authentication.

Use `public-paths` for endpoints that may be accessed anonymously but should
still see an authenticated context when valid credentials are present.

## Signing Mode

Use HS256 when a single application signs and verifies tokens, and every holder
of the secret is trusted to sign:

```yaml
vigil:
  jwt:
    secret: ${JWT_SECRET}
    access-ttl: 15m
    refresh-ttl: 7d
```

The HS256 secret must be at least 32 characters. Configuration fails fast when
the secret is missing or too short.

Use RS256 when one service signs tokens and other services only verify them:

```yaml
vigil:
  jwt:
    algorithm: RS256
    rsa-private-key: ${RSA_PRIVATE_KEY}
    rsa-public-key: ${RSA_PUBLIC_KEY}
    rsa-public-keys:
      - ${PREVIOUS_RSA_PUBLIC_KEY}
```

When RS256 is active, Vigil publishes `/.well-known/jwks.json` and signs tokens
with a deterministic `kid` header. `rsa-public-keys` are verification-only keys
for rotation; they do not sign new tokens.

During key rotation, deploy the new private/public pair as `rsa-private-key`
and `rsa-public-key`, then keep previous public keys in `rsa-public-keys` until
all tokens signed by the previous private key have expired.

## Token Lifetime And Clock Skew

Keep access tokens short-lived and refresh tokens longer-lived:

```yaml
vigil:
  jwt:
    access-ttl: 15m
    refresh-ttl: 7d
    clock-skew: 0s
```

`clock-skew` defaults to zero and is capped at five minutes. Use it only to
absorb known clock drift between trusted systems. Do not use clock skew to
extend token lifetime.

## Refresh Rotation And Revocation

Refresh rotation is handled by `VigilAuthService`. When a refresh token is
rotated, the previous token enters a short grace period so a retried request can
receive the same new token pair:

```yaml
vigil:
  blacklist:
    max-size: 10000
    ttl: 24h
    grace-period: 30s
```

The default backend is Caffeine and is appropriate for single-instance
deployments. Multi-instance deployments should expose a shared
`VigilBlacklistBackend` bean:

```java
@Bean
VigilBlacklistBackend sharedBlacklistBackend(MyRedisClient redis) {
  return new MyRedisBlacklistBackend(redis);
}
```

Vigil auto-configuration detects the bean and wraps it with the configured
rotation grace period. The backend must preserve token blacklist entries,
rotation entries, and subject invalidation timestamps across application
instances.

## Multi-Portal Cookies

Use cookie profiles when one application serves different client surfaces:

```yaml
vigil:
  cookie:
    profiles:
      staff:
        access-token-name: staff_access_token
        refresh-token-name: staff_refresh_token
      customer:
        access-token-name: customer_access_token
        refresh-token-name: customer_refresh_token
  filter:
    profile-paths:
      staff: ["/api/admin/**", "/api/staff/**"]
      customer: ["/api/customer/**"]
```

The route profile decides which cookie names are used for extraction and
writing. Security settings such as `secure`, `http-only`, and `same-site` are
shared across profiles.

## Tenant Context

Enable tenant validation when requests carry a tenant header:

```yaml
vigil:
  tenant:
    enabled: true
    header-name: X-Tenant-ID
```

If both token and request contain a tenant, Vigil rejects authentication when
they differ. If only the token contains a tenant, Vigil uses the token tenant
for request context.

Application authorization still owns tenant membership and resource ownership.
Vigil validates consistency; it does not decide whether a user may access a
tenant resource.

## Custom Context

Implement `VigilContextPopulator` to copy validated claims into application
context:

```java
@Component
class UserContextPopulator implements VigilContextPopulator {

  @Override
  public void populate(HttpServletRequest request, VigilTokenClaims claims) {
    UserContext.set(
        claims == null ? null : claims.getString("userId").orElse(null),
        claims == null ? List.of() : claims.getStringList("roles"));
  }

  @Override
  public void clear() {
    UserContext.clear();
  }
}
```

Keep business authorization checks outside the populator. The populator should
copy request context, not grant access.

## Reset Tokens

Vigil reset tokens are single-use JWTs. The application still owns account
lookup, email or SMS delivery, password policy, and reset UX.

```java
String token = resetTokenService.generate(user.email());
String subject = resetTokenService.validateAndConsume(token);
authService.invalidateAllSessions(subject);
```

Consume reset tokens before accepting a new password. After a successful
password change, invalidate existing sessions for the subject.

## Testing Integrations

Test authentication at the adapter boundary:

- login endpoints validate credentials before calling `VigilAuthService`;
- refresh endpoints reject blacklisted or expired refresh tokens;
- logout endpoints blacklist both access and refresh tokens;
- protected routes require Spring Security authentication;
- public routes behave correctly with no credentials, valid credentials, and
  invalid credentials;
- multi-tenant routes reject tenant mismatches.

Run the project gate before release:

```bash
gradlew.bat qualityCheck --no-daemon
gradlew.bat build --no-daemon
```
