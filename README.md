# Vigil

JWT authentication for Spring Boot. Security by default.

[![Maven Central](https://img.shields.io/maven-central/v/io.github.sequelcore/vigil-spring-boot-starter.svg)](https://central.sonatype.com/artifact/io.github.sequelcore/vigil-spring-boot-starter)

Status: Spring Boot 4.1 certification candidate. Version `7.0.0` is the current repository version. Vigil is used by Sequel applications, but public consumers should pin exact versions and review release notes before upgrades.

## Compatibility

Vigil `7.0.0` is the Spring Boot 4.1.x / Java 25 certification line.

| Component | Supported line |
|-----------|----------------|
| Java | 25 |
| Spring Boot | 4.1.x |
| Spring Framework | 7.x through Spring Boot |
| Spring Security | 7.1.x through Spring Boot |
| Gradle wrapper | 9.1.x |
| JSON support | Jackson 3 (`tools.jackson`) |

Vigil `7.0.x` is the active supported platform line. Vigil `6.0.x` was the
final Spring Boot 3.5.x / Java 21 line and is not supported for Spring Boot
4.1 consumers. Do not add compatibility shims between the two lines; Boot 4
moves to Jackson 3 and modular test/client support.

The only intentional public API break in `7.0.0` is the JSON mapper type used
by `VigilAuthenticationEntryPoint`: Spring Boot 4 defaults to Jackson 3, so the
constructor now accepts `tools.jackson.databind.ObjectMapper` instead of
Jackson 2's `com.fasterxml.jackson.databind.ObjectMapper`.

## Scope

Vigil handles token lifecycle, not user lifecycle.

| Vigil owns | Application owns |
|------------|------------------|
| Access and refresh token generation | User storage and lookup |
| JWT validation and refresh rotation | Credential validation |
| HTTP-only cookie helpers | Login, registration, and account endpoints |
| Bearer token and cookie extraction | User domain model and authorization rules |
| Spring Security authentication filter | `SecurityFilterChain` route policy |
| Token and subject blacklisting | Email, SMS, MFA, and recovery delivery |
| Tenant context validation | Tenant ownership model |
| Guest session token hooks | Guest/session persistence |
| RS256 signing and JWKS endpoint | OAuth/OIDC authorization server duties |

Vigil is not an OAuth authorization server, OpenID Connect provider, user management system, or hosted identity product.

## Documentation

- [Usage guide](docs/usage-guide.md)
- [Release policy](docs/release.md)
- [Roadmap](docs/roadmap.md)
- [Changelog](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)

## Install

```kotlin
dependencies {
    implementation("io.github.sequelcore:vigil-spring-boot-starter:7.0.0")
}
```

Vigil expects the application to provide Spring Web and Spring Security.

## Spring Security Integration

Vigil auto-configures a `VigilAuthenticationFilter` bean. The application must add it to its Spring Security filter chain and keep authorization rules in application code.

```java
@Configuration
class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            VigilAuthenticationFilter vigilAuthenticationFilter,
            VigilAuthenticationEntryPoint vigilAuthenticationEntryPoint,
            VigilProperties vigilProperties) throws Exception {

        String[] ignoredPaths = vigilProperties.filter().ignoredPaths().toArray(String[]::new);
        String[] publicPaths = vigilProperties.filter().publicPaths().toArray(String[]::new);

        http.csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .exceptionHandling(exceptions ->
                exceptions.authenticationEntryPoint(vigilAuthenticationEntryPoint))
            .authorizeHttpRequests(auth -> {
                if (ignoredPaths.length > 0) {
                    auth.requestMatchers(ignoredPaths).permitAll();
                }
                if (publicPaths.length > 0) {
                    auth.requestMatchers(publicPaths).permitAll();
                }
                auth.requestMatchers("/.well-known/jwks.json").permitAll()
                    .anyRequest().authenticated();
            })
            .addFilterBefore(
                vigilAuthenticationFilter,
                UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
```

Place the filter inside Spring Security's filter chain. Spring Security clears `SecurityContextHolder` when the security chain completes; adding Vigil as an unmanaged servlet filter is not the supported integration path.

`ignored-paths` only means "skip Vigil"; it does not grant Spring Security access by itself. Permit health, actuator, JWKS, or other anonymous routes in `authorizeHttpRequests` when they should be reachable without authentication.

## Configure

### HS256

Use HS256 only when every service that has the secret is trusted to sign tokens.

```yaml
vigil:
  jwt:
    secret: ${JWT_SECRET}       # Required for HS256, min 32 characters
    issuer: ${JWT_ISSUER}
    audience: ${JWT_AUDIENCE}
    access-ttl: 15m
    refresh-ttl: 7d

  auth:
    realm: my-api

  cookie:
    secure: true
    http-only: true
    same-site: Lax
    profiles:
      default:
        access-token-name: access_token
        refresh-token-name: refresh_token

  filter:
    ignored-paths:
      - /actuator/**
      - /health
    public-paths:
      - /auth/**
      - /public/**
```

### RS256 And JWKS

Use RS256 when one service signs tokens and other services only need to verify them.

```yaml
vigil:
  jwt:
    algorithm: RS256
    rsa-private-key: ${RSA_PRIVATE_KEY}
    rsa-public-key: ${RSA_PUBLIC_KEY}
    rsa-public-keys:
      - ${PREVIOUS_RSA_PUBLIC_KEY}
    issuer: my-auth-service
    audience: my-api
    access-ttl: 15m
    refresh-ttl: 7d
    clock-skew: 30s
```

When `algorithm: RS256` is active:

- `/.well-known/jwks.json` is registered automatically.
- The JWKS endpoint exposes the public key only.
- Every signed token includes a deterministic `kid` header.
- Additional `rsa-public-keys` are verification-only keys for rotation.
- The HS256 `secret` property is ignored.

Key generation:

```bash
openssl genrsa -out vigil-private.pem 2048
openssl rsa -in vigil-private.pem -pubout -out vigil-public.pem
```

`rsa-private-key` and `rsa-public-key` accept `file:/absolute/path.pem`, `classpath:path.pem`, or inline PEM content from a secrets manager.

During RS256 rotation, deploy the new private/public key pair as `rsa-private-key` and `rsa-public-key`, and keep previous public keys in `rsa-public-keys` until all tokens signed by the previous private key have expired.

## Usage

### Web Clients

Tokens are stored in HTTP-only cookies. Set `secure: true` in production and use HTTPS.

```java
@RestController
@RequiredArgsConstructor
class AuthController {

    private final VigilAuthService authService;
    private final VigilPasswordService passwordService;
    private final UserRepository userRepository;

    @PostMapping("/auth/login")
    AuthResult login(@RequestBody LoginRequest request, HttpServletResponse response) {
        User user = userRepository.findByEmail(request.email())
            .filter(candidate -> passwordService.matches(
                request.password(),
                candidate.passwordHash()))
            .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));

        return authService.login(
            response,
            user.email(),
            Map.of("userId", user.id(), "roles", user.roles()));
    }

    @PostMapping("/auth/refresh")
    AuthResult refresh(HttpServletRequest request, HttpServletResponse response) {
        return authService.refresh(request, response);
    }

    @PostMapping("/auth/logout")
    void logout(HttpServletRequest request, HttpServletResponse response) {
        authService.logout(request, response);
    }
}
```

### Native Apps And APIs

Tokens are returned in the response body. Native clients should store them in platform secure storage.

```java
@PostMapping("/auth/login")
AuthResult login(@RequestBody LoginRequest request) {
    User user = validateCredentials(request);
    return authService.login(user.email(), Map.of("userId", user.id(), "roles", user.roles()));
}

@PostMapping("/auth/refresh")
AuthResult refresh(@RequestBody RefreshRequest request) {
    return authService.refresh(request.refreshToken());
}

@PostMapping("/auth/logout")
void logout(@RequestBody LogoutRequest request) {
    authService.logout(request.accessToken(), request.refreshToken());
}
```

## Filter Behavior

| Path type | Credentials | Behavior |
|-----------|-------------|----------|
| Ignored | Any | Skip all Vigil processing |
| Public | None | Continue anonymous |
| Public | Valid | Authenticate and continue |
| Public | Invalid | Continue anonymous after hook |
| Protected | None | Leave unauthenticated for Spring Security 401 |
| Protected | Valid | Authenticate and continue |
| Protected | Invalid | Leave unauthenticated for Spring Security 401 |

`ignored-paths` bypass tenant extraction, token parsing, session lookup, and context populators. `public-paths` still run Vigil so public endpoints can optionally see authenticated users.

## Token Lifecycle

Refresh rotation is enabled through `VigilAuthService`. When a refresh token is rotated, the old token is stored with a grace period so retrying the same refresh request can return the same new tokens during network races.

```yaml
vigil:
  blacklist:
    max-size: 10000
    ttl: 24h
    grace-period: 30s   # Clamped to max 60s
```

The default blacklist backend is in-memory Caffeine for single-instance deployments. In multi-instance deployments, expose a shared `VigilBlacklistBackend` bean backed by Redis, a database, or another shared store. Vigil auto-configuration wraps that backend with the configured rotation grace period.

```java
@Bean
VigilBlacklistBackend sharedBlacklistBackend(MyRedisClient redis) {
  return new MyRedisBlacklistBackend(redis);
}
```

## Multi-Portal Cookies

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
      staff:
        - /api/console/**
      customer:
        - /api/customer/**
```

```java
authService.login(response, staff.email(), "staff", staffClaims);
authService.login(response, customer.email(), "customer", customerClaims);
```

## Multi-Tenant Requests

```yaml
vigil:
  tenant:
    enabled: true
    header-name: X-Tenant-ID
```

If a token has a `tenantId` claim and the request has `X-Tenant-ID`, Vigil rejects the authentication when they differ. If only the token has a tenant, Vigil uses the token tenant for the request context.

```java
UUID tenantId = VigilTenantContext.requireTenant();
```

## Custom Request Context

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

## Passwords And Reset Tokens

Vigil provides BCrypt hashing, password strength feedback, and single-use reset tokens. The application still owns account lookup, new password validation policy, and email/SMS delivery.

```java
PasswordStrength strength = passwordService.strength(newPassword);
if (!strength.isAcceptable()) {
    throw new ValidationException(strength.feedback().toString());
}

String token = resetTokenService.generate(user.email());
String subject = resetTokenService.validateAndConsume(token);
authService.invalidateAllSessions(subject);
```

## Configuration Reference

```yaml
vigil:
  jwt:
    secret: ${JWT_SECRET}
    algorithm: HS256
    rsa-private-key: ${RSA_PRIVATE_KEY}
    rsa-public-key: ${RSA_PUBLIC_KEY}
    rsa-public-keys: []
    access-ttl: 15m
    refresh-ttl: 7d
    issuer: my-auth-service
    audience: my-api
    clock-skew: 0s

  auth:
    realm: my-api

  cookie:
    secure: true
    http-only: true
    same-site: Lax
    profiles:
      default:
        access-token-name: access_token
        refresh-token-name: refresh_token

  password:
    strength: 12

  blacklist:
    max-size: 10000
    ttl: 24h
    grace-period: 30s

  protection:
    max-attempts: 5
    lock-duration: 15m

  session:
    enabled: false
    cookie-name: session_token
    ttl: 30m

  tenant:
    enabled: false
    header-name: X-Tenant-ID

  filter:
    ignored-paths: []
    public-paths: []
    profile-paths: {}

  reset:
    ttl: 1h
```

## Verify

```bat
gradlew.bat clean check --no-daemon
gradlew.bat qualityCheck --no-daemon
gradlew.bat publishToMavenLocal --no-daemon
```

## Release Policy

Publishing is manual through the release workflow. A publish operation requires an exact `v<version>` ref, explicit `publish <version>` confirmation, scoped release secrets, and the protected `release` environment. Do not publish from local machines.

## License

Apache 2.0. See [LICENSE](LICENSE).
