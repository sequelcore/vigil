# Async and streaming security

Vigil preserves an authenticated Spring Security context for the lifetime of one servlet request,
including its `ASYNC` and `ERROR` redispatches. It does not create an `HttpSession`, revalidate a
JWT during redispatch, or weaken the application's authorization rules.

## Secure stateless configuration

Use Vigil's request-scoped repository in the application's filter chain. Keep authorization rules
application-owned and continue authorizing every dispatcher type.

```java
@Bean
SecurityFilterChain securityFilterChain(
    HttpSecurity http,
    VigilAuthenticationFilter vigilAuthenticationFilter) throws Exception {
  var requestSecurityContextRepository = new RequestAttributeSecurityContextRepository();
  vigilAuthenticationFilter.setSecurityContextRepository(requestSecurityContextRepository);
  return http
      .sessionManagement(session ->
          session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
      .securityContext(context ->
          context.securityContextRepository(requestSecurityContextRepository))
      .authorizeHttpRequests(authorize -> authorize
          .requestMatchers("/auth/**").permitAll()
          .anyRequest().authenticated())
      .addFilterBefore(vigilAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
      .build();
}
```

Vigil validates credentials and runs authentication hooks and context populators only on the
initial `REQUEST`. After successful authentication it saves the `SecurityContext` in a
`RequestAttributeSecurityContextRepository`. Spring Security's `SecurityContextHolderFilter`
loads that context for a legitimate redispatch and clears its thread-local holder afterward. A
new request, or a fabricated `ASYNC`/`ERROR` dispatch without the request attribute, has no saved
identity and remains subject to normal authorization.

Do not globally `permitAll` `ASYNC` or `ERROR` merely to avoid a secondary authorization failure.
That can bypass application policy. Any deliberate narrow exception remains application-owned.

## MVC lifecycle

`DeferredResult`, `ResponseBodyEmitter`, `SseEmitter`, and `StreamingResponseBody` use Servlet
async processing. MVC leaves the response open after the initial dispatch and later performs an
`ASYNC` dispatch to finish processing. When an emitter write fails because the client disconnected,
the application must not call `complete` or `completeWithError`; the container notifies Spring MVC,
which performs the final error dispatch and cleanup.

A Broken pipe is a normal network event and cannot be prevented. Record expected disconnects
separately from integrity failures. Monitor emitter completion, timeout, active connections, and
unexpected exception-resolver failures. The application owns MVC executors, timeouts, heartbeats,
resource cleanup, and propagation of domain context. Vigil preserves the Spring Security principal,
not arbitrary application `ThreadLocal` values.

## Responsibility matrix

| Vigil | Consuming application |
| --- | --- |
| Validate the initial credential and save its authenticated context on the same request | Define HTTP and business authorization rules |
| Avoid reauthentication and authentication side effects on redispatch | Configure MVC async lifecycle and resource cleanup |
| Save into Spring Security's request-attribute repository contract | Install a `RequestAttributeSecurityContextRepository` in `HttpSecurity` |
| Fail closed without evidence of an authenticated initial request | Decide and test any narrow dispatcher-type exceptions |
| Preserve the Spring Security principal across dispatch threads | Propagate additional tenant/domain context when required |

## Source-backed decisions

The complete auditable research record, including upstream source/tests, issue evidence, and the
alternatives matrix, is in [async and streaming security research](../research/async-streaming-security-sources.md).

- [Jakarta Servlet 6.1](https://jakarta.ee/specifications/servlet/6.1/jakarta-servlet-spec-6.1.pdf): `ASYNC` is a dispatch of the same request, supporting request attributes rather than token replay or sessions.
- [Spring Framework async MVC](https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-ann-async.html): documents final dispatch and emitter `IOException` handling.
- [Spring Security context persistence](https://docs.spring.io/spring-security/reference/7.0/servlet/authentication/persistence.html): defines request-attribute persistence and explicit saving for custom authentication.
- [Spring Security authorization](https://docs.spring.io/spring-security/reference/7.0/servlet/authorization/authorize-http-requests.html): dispatcher authorization remains application policy.
- [Spring Security issue 12758](https://github.com/spring-projects/spring-security/issues/12758): maintainers prescribe this repository for the equivalent JWT and `StreamingResponseBody` failure.
- [Spring Framework issue 33439](https://github.com/spring-projects/spring-framework/issues/33439): disconnect timing is network/container dependent.

## Migration

Synchronous integrations keep their behavior. Async applications must install a
`RequestAttributeSecurityContextRepository` in `HttpSecurity` as shown above. Remove broad
`dispatcherTypeMatchers(ASYNC, ERROR).permitAll()` workarounds after verifying application error
routes. No token, cookie, route, or authorization contract changes are required.
