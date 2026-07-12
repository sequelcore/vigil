# Authentication guide

Use this guide to connect Vigil to an application's login routes and Spring Security chain. Before integrating, read the [system boundaries](../architecture/system-boundaries.md): Vigil issues and validates tokens, while the application validates credentials and authorizes its own routes.

## 1. Configure token signing

Start with a JWT signing mode and an explicit issuer and audience:

```yaml
vigil:
  jwt:
    secret: ${JWT_SECRET}
    issuer: my-service
    audience: my-api
```

Use RS256 when verifiers must not hold signing authority. The complete property set, defaults, and key-source formats are in the [configuration reference](../reference/configuration.md).

## 2. Install the authentication filter

Vigil auto-configures `VigilAuthenticationFilter`. Add it inside the application's `SecurityFilterChain` and keep route policy in the application:

```java
@Bean
SecurityFilterChain securityFilterChain(
    HttpSecurity http,
    VigilAuthenticationFilter vigilAuthenticationFilter) throws Exception {
  var requestSecurityContextRepository = new RequestAttributeSecurityContextRepository();
  vigilAuthenticationFilter.setSecurityContextRepository(requestSecurityContextRepository);
  return http
      .securityContext(context ->
          context.securityContextRepository(requestSecurityContextRepository))
      .authorizeHttpRequests(authorize -> authorize
          .requestMatchers("/auth/**").permitAll()
          .anyRequest().authenticated())
      .addFilterBefore(vigilAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
      .build();
}
```

The request-scoped repository is required for MVC async and streaming return types. See
[async and streaming security](async-streaming-security.md) for the stateless lifecycle and
dispatcher authorization model.

`ignored-paths` bypasses Vigil entirely. `public-paths` permits an anonymous request while making a valid existing authentication available to the application. Neither setting replaces `authorizeHttpRequests`.

## 3. Issue tokens after application credential validation

For browser clients, validate the credential in the application and let Vigil write HTTP-only cookies:

```java
AuthResult login(LoginRequest request, HttpServletResponse response) {
  User user = users.findByEmail(request.email())
      .filter(candidate -> passwords.matches(request.password(), candidate.passwordHash()))
      .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));

  return authService.login(response, user.id().toString(), Map.of("tenantId", user.tenantId()));
}
```

For native clients and APIs, call `authService.login(subject, claims)` and return the `AuthResult` through the application's own route. Store native tokens in platform secure storage.

## 4. Select the relevant follow-up guide

| Need | Canonical document |
| --- | --- |
| Browser cookies, native tokens, refresh, logout, tenants, reset tokens | [Configuration reference](../reference/configuration.md) and public API Javadoc |
| Key rotation, JWKS, clusters, and operational checks | [Deployment and operations](../operations/deployment.md) |
| Security assumptions and incident response | [Security model](../security/security-model.md) |
| Additional approval without changing the current session | [Step-up authorization](../security/step-up-authorization.md) |
| Contract and extension points | [Java API contract](../api/java-api.md) |

Run the checks in [testing and verification](../development/testing.md) before release.
