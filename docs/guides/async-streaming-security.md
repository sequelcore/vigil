# Async and streaming security

Vigil preserves an authenticated Spring Security context for the lifetime of one servlet request,
including its `ASYNC` and `ERROR` redispatches. It does not create an `HttpSession`, revalidate a
JWT during redispatch, or weaken the application's authorization rules.

## Required security-chain configuration

Use the complete stateless `SecurityFilterChain` in the
[authentication guide](authentication.md#2-install-the-authentication-filter). The filter and
Spring Security must use the same `RequestAttributeSecurityContextRepository`. Keep authorization
rules application-owned and continue authorizing every dispatcher type.

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
alternatives matrix, is in [async and streaming security evidence](../architecture/async-streaming-evidence.md).

## Migration

Synchronous integrations keep their behavior. Async applications must install a
`RequestAttributeSecurityContextRepository` in `HttpSecurity` as shown in the authentication
guide. Remove broad
`dispatcherTypeMatchers(ASYNC, ERROR).permitAll()` workarounds after verifying application error
routes. No token, cookie, route, or authorization contract changes are required.
