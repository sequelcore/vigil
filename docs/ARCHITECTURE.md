# Vigil Architecture

> Version: 1.2.0 (Planned)
> Status: Draft

## Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Spring Boot Application                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐          │
│  │   Request    │───▶│    Filter    │───▶│  Controller  │          │
│  └──────────────┘    └──────┬───────┘    └──────────────┘          │
│                             │                                        │
│         ┌───────────────────┼───────────────────┐                   │
│         ▼                   ▼                   ▼                   │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐             │
│  │   Token     │    │   Session   │    │   Anomaly   │             │
│  │   Service   │    │   Service   │    │   Service   │             │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘             │
│         │                  │                  │                     │
│         └────────────┬─────┴────────┬─────────┘                     │
│                      ▼              ▼                               │
│               ┌─────────────┐ ┌─────────────┐                       │
│               │   Storage   │ │   Events    │                       │
│               │  (Caffeine/ │ │  (Spring)   │                       │
│               │   Redis)    │ │             │                       │
│               └─────────────┘ └─────────────┘                       │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Package Structure

```
io.github.sequelcore.vigil/
├── autoconfigure/
│   ├── VigilAutoConfiguration.java
│   └── VigilProperties.java
│
├── core/
│   ├── jwt/
│   │   ├── VigilTokenService.java
│   │   ├── VigilTokenClaims.java
│   │   └── TokenRequest.java
│   ├── password/
│   │   ├── VigilPasswordService.java
│   │   └── VigilArgon2Service.java          # v1.2.0
│   └── cookie/
│       └── VigilCookieService.java
│
├── filter/
│   └── VigilAuthenticationFilter.java
│
├── session/                                  # v1.2.0
│   ├── VigilSessionService.java
│   ├── Session.java
│   ├── SessionMetadata.java
│   └── store/
│       ├── SessionStore.java
│       ├── CaffeineSessionStore.java
│       └── RedisSessionStore.java
│
├── ip/                                       # v1.2.0
│   ├── VigilIpService.java
│   ├── IpExtractor.java
│   ├── GeoLocation.java
│   └── geo/
│       ├── GeoProvider.java
│       ├── MaxMindGeoProvider.java
│       └── NoOpGeoProvider.java
│
├── device/                                   # v1.2.0
│   ├── VigilDeviceService.java
│   ├── DeviceInfo.java
│   ├── DeviceFingerprint.java
│   └── store/
│       ├── DeviceStore.java
│       ├── CaffeineDeviceStore.java
│       └── RedisDeviceStore.java
│
├── anomaly/                                  # v1.2.0
│   ├── VigilAnomalyService.java
│   ├── AnomalyDetector.java
│   ├── AnomalyResult.java
│   ├── Anomaly.java
│   └── rules/
│       ├── AnomalyRule.java
│       ├── ImpossibleTravelRule.java
│       ├── RapidContextChangeRule.java
│       └── MultipleIpRule.java
│
├── blacklist/
│   ├── VigilBlacklistService.java
│   └── store/
│       ├── BlacklistStore.java
│       ├── CaffeineBlacklistStore.java
│       └── RedisBlacklistStore.java
│
├── protection/
│   └── VigilProtectionService.java
│
├── tenant/
│   ├── VigilTenantService.java
│   └── VigilTenantContext.java
│
├── event/                                    # v1.2.0
│   ├── AnomalyDetectedEvent.java
│   ├── NewDeviceEvent.java
│   ├── IpChangeEvent.java
│   ├── SessionCreatedEvent.java
│   └── SessionRevokedEvent.java
│
└── metrics/                                  # v1.2.0
    └── VigilMetrics.java
```

---

## Component Responsibilities

### Core Services (v1.0.0)

| Service | Responsibility |
|---------|----------------|
| `VigilTokenService` | JWT generation, validation, claims extraction |
| `VigilPasswordService` | BCrypt hashing, password validation |
| `VigilCookieService` | Cookie creation, extraction, clearing |
| `VigilBlacklistService` | Token invalidation (logout) |
| `VigilProtectionService` | Brute-force prevention, lockouts |
| `VigilTenantService` | Multi-tenant context management |

### New Services (v1.2.0)

| Service | Responsibility |
|---------|----------------|
| `VigilSessionService` | Session lifecycle, metadata, revocation |
| `VigilIpService` | IP extraction, geolocation, validation |
| `VigilDeviceService` | Fingerprinting, trust management |
| `VigilAnomalyService` | Detection rules, action determination |

---

## Request Flow (v1.2.0)

```
Request
   │
   ▼
┌─────────────────────────────────────────────────────────────┐
│                  VigilAuthenticationFilter                   │
├─────────────────────────────────────────────────────────────┤
│  1. Extract token (header or cookie)                        │
│  2. Validate token (signature, expiration)                  │
│  3. Check blacklist                                         │
│  4. Extract session ID from claims                          │
│  5. Load session metadata                                   │
│  6. Extract current IP                                      │
│  7. Run anomaly detection                                   │
│  8. If anomaly → take action (logout, challenge, flag)      │
│  9. Update session activity                                 │
│  10. Set SecurityContext                                    │
└─────────────────────────────────────────────────────────────┘
   │
   ▼
Controller
```

### Filter Implementation

```java
@Component
public class VigilAuthenticationFilter extends OncePerRequestFilter {

    private final VigilTokenService tokenService;
    private final VigilCookieService cookieService;
    private final VigilBlacklistService blacklistService;
    private final VigilSessionService sessionService;
    private final VigilIpService ipService;
    private final VigilAnomalyService anomalyService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain) throws ServletException, IOException {

        // 1. Skip public paths
        if (isPublicPath(request)) {
            chain.doFilter(request, response);
            return;
        }

        // 2. Extract and validate token
        String token = extractToken(request);
        if (token == null) {
            response.sendError(401);
            return;
        }

        VigilTokenClaims claims;
        try {
            claims = tokenService.validateToken(token);
        } catch (Exception e) {
            response.sendError(401);
            return;
        }

        // 3. Check blacklist
        if (blacklistService.isBlacklisted(token)) {
            response.sendError(401);
            return;
        }

        // 4. Load session and check anomalies
        String sessionId = claims.getSessionId();
        Session session = sessionService.getSession(sessionId);
        String currentIp = ipService.extractIp(request);

        SessionContext context = SessionContext.builder()
            .session(session)
            .currentIp(currentIp)
            .currentRequest(request)
            .build();

        AnomalyResult result = anomalyService.analyze(context);

        // 5. Handle anomalies
        switch (result.action()) {
            case LOGOUT -> {
                sessionService.revoke(sessionId);
                blacklistService.blacklist(token);
                response.sendError(401, "Session terminated");
                return;
            }
            case CHALLENGE -> {
                response.sendError(403, "Re-authentication required");
                return;
            }
            case FLAG -> session.markSuspicious();
        }

        // 6. Update session
        sessionService.recordActivity(sessionId, currentIp);

        // 7. Set security context
        setSecurityContext(claims, session);

        chain.doFilter(request, response);
    }
}
```

---

## Login Flow (v1.2.0)

```
Login Request
   │
   ▼
┌─────────────────────────────────────────────────────────────┐
│                    AuthController.login()                    │
├─────────────────────────────────────────────────────────────┤
│  1. Check brute-force protection                            │
│  2. Validate credentials                                    │
│  3. Extract IP and device info                              │
│  4. Check if new device                                     │
│  5. Create session with metadata                            │
│  6. Generate tokens (include session ID)                    │
│  7. Emit events (NewDeviceEvent if applicable)              │
│  8. Set cookies                                             │
│  9. Return response                                         │
└─────────────────────────────────────────────────────────────┘
```

### Login Implementation

```java
@PostMapping("/auth/login")
public AuthResponse login(
        @RequestBody LoginRequest req,
        HttpServletRequest request,
        HttpServletResponse response) {

    // 1. Brute-force check
    if (protectionService.isLocked(req.email())) {
        throw new AccountLockedException();
    }

    // 2. Validate credentials
    User user = authenticate(req);
    protectionService.recordSuccess(req.email());

    // 3. Extract context
    String ip = ipService.extractIp(request);
    DeviceInfo device = deviceService.extractDeviceInfo(request);

    // 4. Check new device
    boolean isNewDevice = !deviceService.isKnownDevice(user.getId(), device.deviceId());
    if (isNewDevice) {
        eventPublisher.publish(new NewDeviceEvent(user.getId(), device, ip));
    }

    // 5. Create session
    Session session = sessionService.createSession(
        SessionRequest.builder()
            .userId(user.getId())
            .ip(ip)
            .device(device)
            .newDevice(isNewDevice)
            .build()
    );

    // 6. Generate tokens
    String access = tokenService.generateAccessToken(
        TokenRequest.builder()
            .subject(user.getId())
            .claim("sid", session.sessionId())
            .claim("ip", ip)
            .build()
    );

    String refresh = tokenService.generateRefreshToken(
        user.getId(),
        session.sessionId()
    );

    // 7. Set cookies and return
    cookieService.setAccessTokenCookie(response, access);
    cookieService.setRefreshTokenCookie(response, refresh);

    return new AuthResponse(access, refresh, isNewDevice);
}
```

---

## Storage Architecture

### Interface Pattern

```java
// Generic store interface
public interface Store<K, V> {
    void put(K key, V value);
    void put(K key, V value, Duration ttl);
    Optional<V> get(K key);
    void remove(K key);
    boolean exists(K key);
}

// Specialized stores
public interface SessionStore extends Store<String, Session> {
    List<Session> findByUser(String userId);
    void revokeAllByUser(String userId);
}

public interface DeviceStore extends Store<String, DeviceInfo> {
    List<DeviceInfo> findByUser(String userId);
}
```

### Caffeine Implementation (Default)

```java
@Component
@ConditionalOnMissingBean(SessionStore.class)
public class CaffeineSessionStore implements SessionStore {

    private final Cache<String, Session> cache;

    public CaffeineSessionStore(VigilProperties props) {
        this.cache = Caffeine.newBuilder()
            .expireAfterWrite(props.session().ttl())
            .maximumSize(props.session().maxSize())
            .build();
    }

    @Override
    public void put(String key, Session value) {
        cache.put(key, value);
    }
}
```

### Redis Implementation (Optional)

```java
@Component
@ConditionalOnClass(RedisTemplate.class)
@ConditionalOnProperty(prefix = "vigil.session", name = "storage", havingValue = "redis")
public class RedisSessionStore implements SessionStore {

    private final RedisTemplate<String, Session> redis;
    private static final String PREFIX = "vigil:session:";

    @Override
    public void put(String key, Session value, Duration ttl) {
        redis.opsForValue().set(PREFIX + key, value, ttl);
    }
}
```

---

## Event System

### Event Flow

```
Action (login, anomaly, etc.)
   │
   ▼
ApplicationEventPublisher.publish(event)
   │
   ▼
┌─────────────────────────────────────────────────────────────┐
│                    @EventListener methods                    │
├─────────────────────────────────────────────────────────────┤
│  • VigilMetrics.onAnomalyDetected()   → increment counter   │
│  • SecurityLogger.onAnomalyDetected() → log to SIEM         │
│  • EmailService.onNewDevice()         → send notification   │
│  • Your custom handlers...                                  │
└─────────────────────────────────────────────────────────────┘
```

### Event Handling Example

```java
@Component
public class SecurityEventHandler {

    @EventListener
    public void onAnomalyDetected(AnomalyDetectedEvent event) {
        log.warn("Anomaly detected: {} for user {} from IP {}",
            event.anomaly(),
            event.userId(),
            event.context().currentIp()
        );

        // Send to SIEM, alert security team, etc.
    }

    @EventListener
    public void onNewDevice(NewDeviceEvent event) {
        // Send email notification
        emailService.sendNewDeviceAlert(
            event.userId(),
            event.device(),
            event.ip()
        );
    }
}
```

---

## Configuration Binding

```java
@ConfigurationProperties(prefix = "vigil")
public record VigilProperties(
    Jwt jwt,
    Cookie cookie,
    Password password,
    Blacklist blacklist,
    Tenant tenant,
    Protection protection,
    Filter filter,
    Session session,     // v1.2.0
    Ip ip,               // v1.2.0
    Device device,       // v1.2.0
    Anomaly anomaly      // v1.2.0
) {

    public record Session(
        String storage,           // caffeine | redis
        Duration ttl,             // default: 7d
        int maxPerUser            // default: 10
    ) {}

    public record Ip(
        boolean trustProxyHeaders,
        List<String> trustedProxies,
        String geolocationProvider  // maxmind | ip-api | none
    ) {}

    public record Device(
        boolean enabled,
        Duration trustDuration,
        int maxDevicesPerUser
    ) {}

    public record Anomaly(
        int impossibleTravelSpeedKmh,
        int rapidChangeWindowMinutes,
        int multipleIpThreshold,
        int multipleIpWindowMinutes
    ) {}
}
```

---

## Auto-Configuration

```java
@AutoConfiguration
@EnableConfigurationProperties(VigilProperties.class)
public class VigilAutoConfiguration {

    // Core services (v1.0.0)
    @Bean
    @ConditionalOnMissingBean
    public VigilTokenService vigilTokenService(VigilProperties props) { }

    @Bean
    @ConditionalOnMissingBean
    public VigilPasswordService vigilPasswordService(VigilProperties props) { }

    // ... other v1.0.0 beans

    // New services (v1.2.0)
    @Bean
    @ConditionalOnMissingBean
    public VigilIpService vigilIpService(VigilProperties props, GeoProvider geo) { }

    @Bean
    @ConditionalOnMissingBean
    public VigilSessionService vigilSessionService(
            VigilProperties props, SessionStore store) { }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "vigil.device", name = "enabled", havingValue = "true")
    public VigilDeviceService vigilDeviceService(
            VigilProperties props, DeviceStore store) { }

    @Bean
    @ConditionalOnMissingBean
    public VigilAnomalyService vigilAnomalyService(
            VigilProperties props,
            VigilIpService ipService,
            ApplicationEventPublisher events) { }
}
```

---

## Testing Strategy

### Unit Tests

```java
@Test
void detectsImpossibleTravel() {
    // Given: Session started in New York
    Session session = createSession("203.0.113.1", "US");

    // When: Request from Tokyo 10 minutes later
    SessionContext ctx = SessionContext.builder()
        .session(session)
        .currentIp("198.51.100.1")  // Tokyo
        .timeSinceLastActivity(Duration.ofMinutes(10))
        .build();

    // Then: Impossible travel detected
    AnomalyResult result = anomalyService.analyze(ctx);
    assertThat(result.anomalies()).contains(Anomaly.IMPOSSIBLE_TRAVEL);
    assertThat(result.action()).isEqualTo(AnomalyAction.LOGOUT);
}
```

### Integration Tests

```java
@SpringBootTest
@AutoConfigureMockMvc
class AnomalyIntegrationTest {

    @Test
    void forceLogoutOnImpossibleTravel() {
        // Login and get token
        String token = login("user@test.com", "password");

        // Simulate request from different continent
        mockMvc.perform(get("/api/protected")
                .header("Authorization", "Bearer " + token)
                .header("X-Forwarded-For", "198.51.100.1"))  // Different location
            .andExpect(status().isUnauthorized());
    }
}
```

---

## Implementation Order

### Phase 1: Foundation
1. `VigilIpService` - IP extraction and validation
2. `SessionStore` interface + Caffeine impl
3. `VigilSessionService` - basic session management
4. Update `VigilAuthenticationFilter` to use sessions

### Phase 2: Anomaly Detection
5. `AnomalyRule` interface
6. Implement detection rules
7. `VigilAnomalyService`
8. Integrate into filter

### Phase 3: Device Tracking
9. `DeviceStore` interface + Caffeine impl
10. `VigilDeviceService`
11. Device fingerprinting logic
12. Trusted device management

### Phase 4: Events & Observability
13. Event classes
14. `VigilMetrics`
15. Event publishing in services

### Phase 5: Redis Support
16. `RedisSessionStore`
17. `RedisDeviceStore`
18. Auto-detection logic
