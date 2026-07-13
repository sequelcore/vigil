# Async and streaming security evidence

Research cutoff: 2026-07-12. Primary specifications, official documentation, upstream source,
tests, and issue discussions take precedence over secondary guidance.

## Contract evidence and architectural consequences

| Primary evidence | Contract used by Vigil | Architectural consequence |
| --- | --- | --- |
| [Servlet 6.1 specification](https://jakarta.ee/specifications/servlet/6.1/jakarta-servlet-spec-6.1.pdf), [AsyncContext](https://jakarta.ee/specifications/servlet/6.1/apidocs/jakarta.servlet/jakarta/servlet/asynccontext), [AsyncListener](https://jakarta.ee/specifications/servlet/6.1/apidocs/jakarta.servlet/jakarta/servlet/asynclistener) | `startAsync` lets the filter/servlet chain return while the same response remains open. Async error and timeout notifications belong to the container lifecycle; a new async cycle requires listener registration again. | Preserve security evidence on the servlet request. Do not replay credentials, manually complete an emitter after failed send, or equate return from the initial chain with request completion. |
| [DispatcherType](https://jakarta.ee/specifications/servlet/6.1/apidocs/jakarta.servlet/jakarta/servlet/dispatchertype), [ServletRequest.getDispatcherType](https://jakarta.ee/specifications/servlet/6.1/apidocs/jakarta.servlet/jakarta/servlet/servletrequest#getDispatcherType()) | `REQUEST`, `ASYNC`, and `ERROR` are distinct filter-chain invocations. `ASYNC` is produced by `AsyncContext.dispatch`; `ERROR` is container error handling. | Authenticate credentials only during the initial request. Continue authorization on redispatch using saved request evidence. A dispatch without that evidence fails closed. |
| [ServletResponse](https://jakarta.ee/specifications/servlet/6.1/apidocs/jakarta.servlet/jakarta/servlet/servletresponse) | Flushing commits status and headers; reset after commit is illegal and later status/header changes cannot repair the response. | Prevent the secondary authorization failure. Do not attempt to render a new 401/403 over committed SSE output. |
| [Spring MVC async processing](https://docs.spring.io/spring-framework/reference/7.0/web/webmvc/mvc-ann-async.html), [ResponseBodyEmitter 7.0.8](https://docs.spring.io/spring-framework/docs/7.0.8/javadoc-api/org/springframework/web/servlet/mvc/method/annotation/ResponseBodyEmitter.html), [SseEmitter 7.0.8](https://docs.spring.io/spring-framework/docs/7.0.8/javadoc-api/org/springframework/web/servlet/mvc/method/annotation/SseEmitter.html) | `DeferredResult` and streaming return types finish through an `ASYNC` dispatch. An emitter `IOException` caused by client disconnect must be left to the container and MVC, which perform error notification, final dispatch, exception resolution, and completion. | Broken pipe remains an expected network event. Vigil preserves authentication for the final dispatch instead of catching or suppressing the `IOException`. |
| [OncePerRequestFilter 7.0.8](https://docs.spring.io/spring-framework/docs/7.0.8/javadoc-api/org/springframework/web/filter/OncePerRequestFilter.html) | Async and error dispatch participation is opt-in; both can run on different threads. | Vigil keeps the authentication filter out of redispatch. JWT validation, blacklist lookup, tenant extraction, hooks, and context populators execute once. |
| [Spring Security context persistence](https://docs.spring.io/spring-security/reference/7.0/servlet/authentication/persistence.html), [RequestAttributeSecurityContextRepository API](https://docs.spring.io/spring-security/reference/7.1/api/java/org/springframework/security/web/context/RequestAttributeSecurityContextRepository.html) | Custom authentication must explicitly save. The request-attribute repository restores one request across dispatch types and never persists to later requests. `SecurityContextHolderFilter` loads and clears the holder. | Save the authenticated context explicitly to a request-attribute repository configured in the application chain. This is stateless and creates no `HttpSession`. |
| [Servlet authorization](https://docs.spring.io/spring-security/reference/7.0/servlet/authorization/authorize-http-requests.html), [Servlet async integration](https://docs.spring.io/spring-security/reference/7.0/servlet/integrations/servlet-api.html) | Authorization applies to dispatcher types by default. Async task propagation and redispatch persistence are related but distinct mechanisms. | Vigil does not install dispatcher `permitAll` rules. The application continues to own HTTP authorization, including any narrow error-rendering exception. |

## Upstream implementation and test evidence

- Spring Framework 7.0.8:
  - [`ResponseBodyEmitterReturnValueHandler`](https://github.com/spring-projects/spring-framework/blob/v7.0.8/spring-webmvc/src/main/java/org/springframework/web/servlet/mvc/method/annotation/ResponseBodyEmitterReturnValueHandler.java)
  - [`DeferredResultMethodReturnValueHandler`](https://github.com/spring-projects/spring-framework/blob/v7.0.8/spring-webmvc/src/main/java/org/springframework/web/servlet/mvc/method/annotation/DeferredResultMethodReturnValueHandler.java)
  - [`ResponseBodyEmitterReturnValueHandlerTests`](https://github.com/spring-projects/spring-framework/blob/v7.0.8/spring-webmvc/src/test/java/org/springframework/web/servlet/mvc/method/annotation/ResponseBodyEmitterReturnValueHandlerTests.java)
  - [`StreamingResponseBodyReturnValueHandlerTests`](https://github.com/spring-projects/spring-framework/blob/v7.0.8/spring-webmvc/src/test/java/org/springframework/web/servlet/mvc/method/annotation/StreamingResponseBodyReturnValueHandlerTests.java)
- Spring Security 7.1.0:
  - [`RequestAttributeSecurityContextRepository`](https://github.com/spring-projects/spring-security/blob/7.1.0/web/src/main/java/org/springframework/security/web/context/RequestAttributeSecurityContextRepository.java) and [tests](https://github.com/spring-projects/spring-security/blob/7.1.0/web/src/test/java/org/springframework/security/web/context/RequestAttributeSecurityContextRepositoryTests.java)
  - [`SecurityContextHolderFilter`](https://github.com/spring-projects/spring-security/blob/7.1.0/web/src/main/java/org/springframework/security/web/context/SecurityContextHolderFilter.java) and [tests](https://github.com/spring-projects/spring-security/blob/7.1.0/web/src/test/java/org/springframework/security/web/context/SecurityContextHolderFilterTests.java)
  - [`AuthorizationFilter`](https://github.com/spring-projects/spring-security/blob/7.1.0/web/src/main/java/org/springframework/security/web/access/intercept/AuthorizationFilter.java) and [tests](https://github.com/spring-projects/spring-security/blob/7.1.0/web/src/test/java/org/springframework/security/web/access/intercept/AuthorizationFilterTests.java)
  - [`ExceptionTranslationFilter`](https://github.com/spring-projects/spring-security/blob/7.1.0/web/src/main/java/org/springframework/security/web/access/ExceptionTranslationFilter.java) and [tests](https://github.com/spring-projects/spring-security/blob/7.1.0/web/src/test/java/org/springframework/security/web/access/ExceptionTranslationFilterTests.java)
- Spring Boot 4.1.0:
  - [`SecurityFilterAutoConfiguration`](https://github.com/spring-projects/spring-boot/blob/v4.1.0/module/spring-boot-security/src/main/java/org/springframework/boot/security/autoconfigure/web/servlet/SecurityFilterAutoConfiguration.java)
  - [`SecurityFilterAutoConfigurationTests`](https://github.com/spring-projects/spring-boot/blob/v4.1.0/module/spring-boot-security/src/test/java/org/springframework/boot/security/autoconfigure/web/servlet/SecurityFilterAutoConfigurationTests.java)

The local executable baseline resolves Spring Boot 4.1.0, Spring Framework MVC 7.0.8, Spring
Security Web 7.1.0, Tomcat 11.0.22, and Servlet 6.1. Vigil does not claim unexecuted version ranges.

## Official issue evidence

| Issue | Relevance and decision |
| --- | --- |
| [spring-security#12758](https://github.com/spring-projects/spring-security/issues/12758) | Direct match: custom JWT filter plus `StreamingResponseBody`, final async authorization without saved authentication. A Spring Security maintainer prescribes explicit `RequestAttributeSecurityContextRepository.saveContext`. This is the primary precedent for Vigil's implementation. |
| [spring-security#11962](https://github.com/spring-projects/spring-security/issues/11962) | Records the loss of authentication around async dispatch and `SecurityContextHolderFilter`; reinforces that redispatch restoration belongs to the context repository rather than token replay. |
| [spring-security#5273](https://github.com/spring-projects/spring-security/issues/5273) | Documents why exception translation cannot safely start a second security response after commitment. Vigil prevents the secondary denial instead of swallowing it. |
| [spring-framework#32042](https://github.com/spring-projects/spring-framework/issues/32042) and [#32340](https://github.com/spring-projects/spring-framework/issues/32340) | Cover client-abort async dispatch and concurrent error-handling protection. Vigil tests lifecycle outcomes rather than container-specific exception names. |
| [spring-framework#33439](https://github.com/spring-projects/spring-framework/issues/33439) and [#32629](https://github.com/spring-projects/spring-framework/issues/32629) | Show that disconnect timing and exception shape vary by container and transport. Vigil does not promise to eliminate Broken pipe and uses a real Tomcat/RST test. |

## Alternatives evaluated

| Alternative | Decision |
| --- | --- |
| `RequestAttributeSecurityContextRepository` | Selected. It preserves one physical servlet request across dispatches and cannot authenticate a later independent request. |
| `DelegatingSecurityContextRepository` with `HttpSessionSecurityContextRepository` | Rejected as a Vigil stateless default. It adds cross-request session persistence and can create session coupling. An explicitly stateful application may choose it, but that is outside this support contract. |
| Re-run `VigilAuthenticationFilter` for `ASYNC` and `ERROR` | Rejected. It repeats signature validation, revocation checks, tenant extraction, session lookup, populators, hooks, metrics, and audit effects, and may depend on credentials unavailable during redispatch. |
| Restore context inside the Vigil filter during redispatch | Rejected. It duplicates `SecurityContextHolderFilter` and filter-order responsibilities already owned by Spring Security. |
| Globally permit `ASYNC` or `ERROR` | Rejected. It changes application authorization and permits a dispatch without proof of a previously authenticated request. |
| Auto-configure an application `SecurityFilterChain` or dispatcher rules | Rejected. Vigil does not own product HTTP authorization. The repository is explicit in the consumer's chain. |
| Publish a Vigil-specific DSL/configurer | Not selected. The official `HttpSecurity.securityContext` configuration is smaller and clearer; a wrapper would add API without additional behavior. |
| Startup introspection/diagnostics of consumer filter chains | Not automated. Spring applications may have multiple chains and repositories; guessing compatibility can produce false assurance. The requirement is documented and proven by integration tests. |
| Preserve tenant or arbitrary application `ThreadLocal` state | Not automated. The request principal is Vigil's contract; application domain context and async executor propagation remain application-owned. |

## Responsibility conclusion

Vigil owns initial credential authentication, explicit request-scoped context saving, single
execution of authentication effects, and fail-closed absence of evidence. Applications own the
`SecurityFilterChain`, authorization policy, MVC executor/timeouts, stream resource lifecycle,
heartbeats, exception rendering, and any non-Spring domain context propagation.
