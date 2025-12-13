# IP & Device Security Specification

> Version: 1.2.0 (Planned)
> Status: Draft

## Overview

This specification defines IP tracking, device fingerprinting, and anomaly detection for Vigil. These features detect session hijacking, credential theft, and suspicious login patterns.

---

## 1. IP Protection

### 1.1 IP Extraction

**Service:** `VigilIpService`

```java
public interface VigilIpService {
    String extractIp(HttpServletRequest request);
    String getCountryCode(String ip);
    GeoLocation getLocation(String ip);
    boolean isSameRegion(String ip1, String ip2);
}
```

**IP Extraction Priority:**
1. `X-Forwarded-For` (first IP, if trusted proxy)
2. `X-Real-IP`
3. `request.getRemoteAddr()`

**Configuration:**
```yaml
vigil:
  ip:
    trust-proxy-headers: true       # Trust X-Forwarded-For
    trusted-proxies: [10.0.0.0/8]   # Only trust these ranges
```

### 1.2 IP Logging (Native)

**Always captured in session metadata:**
```java
record SessionMetadata(
    String sessionId,
    String userId,
    String ip,
    String countryCode,
    String userAgent,
    String deviceId,
    Instant createdAt,
    Instant lastActivity
) {}
```

**Stored in:**
- JWT claims (subset): `ip`, `sid`
- Session storage (full): Caffeine/Redis

### 1.3 IP Change Detection (Native)

**Trigger:** IP changes mid-session

**Actions:**
| Scenario | Action |
|----------|--------|
| Same country | Log, continue |
| Different country | Log warning, optional re-auth |
| Impossible travel | Force logout, alert |

**Implementation:**
```java
public class VigilIpValidator {
    public IpChangeResult validateIpChange(String originalIp, String currentIp) {
        if (originalIp.equals(currentIp)) {
            return IpChangeResult.NO_CHANGE;
        }

        GeoLocation orig = ipService.getLocation(originalIp);
        GeoLocation curr = ipService.getLocation(currentIp);

        double distanceKm = calculateDistance(orig, curr);
        Duration timeDelta = Duration.between(session.lastActivity(), Instant.now());
        double speedKmH = distanceKm / timeDelta.toHours();

        if (speedKmH > 500) {
            return IpChangeResult.IMPOSSIBLE_TRAVEL;
        }
        if (!orig.countryCode().equals(curr.countryCode())) {
            return IpChangeResult.COUNTRY_CHANGE;
        }
        return IpChangeResult.REGION_CHANGE;
    }
}
```

---

## 2. Device Tracking

### 2.1 Device Fingerprinting

**Service:** `VigilDeviceService`

```java
public interface VigilDeviceService {
    String generateDeviceId(HttpServletRequest request);
    DeviceInfo extractDeviceInfo(HttpServletRequest request);
    boolean isTrustedDevice(String userId, String deviceId);
    void trustDevice(String userId, String deviceId, Duration ttl);
    void revokeDevice(String userId, String deviceId);
    List<DeviceInfo> getUserDevices(String userId);
}
```

**Fingerprint Components:**
```java
record DeviceInfo(
    String deviceId,        // SHA256 hash of fingerprint
    String userAgent,
    String platform,        // Windows, macOS, iOS, Android
    String browser,         // Chrome, Firefox, Safari
    String browserVersion,
    Instant firstSeen,
    Instant lastSeen,
    boolean trusted
) {}
```

**Fingerprint Generation:**
```java
String fingerprint = SHA256(
    userAgent +
    acceptLanguage +
    acceptEncoding +
    platform
);
```

### 2.2 Trusted Devices (Optional)

**Configuration:**
```yaml
vigil:
  device:
    enabled: true
    trust-duration: 30d         # How long to remember devices
    max-devices-per-user: 10    # Limit stored devices
    require-verification: true  # Require action for new devices
```

**Flow:**
```
1. Login from new device
2. Generate deviceId from fingerprint
3. Check if deviceId in trusted list
4. If not trusted:
   - Flag session as "new_device"
   - Emit NewDeviceEvent
   - Application can: send email, require 2FA, etc.
5. User marks device as trusted (optional)
6. Store deviceId with TTL
```

### 2.3 Device Storage

**Interface:**
```java
public interface DeviceStore {
    void save(String userId, DeviceInfo device);
    Optional<DeviceInfo> find(String userId, String deviceId);
    List<DeviceInfo> findByUser(String userId);
    void delete(String userId, String deviceId);
    void deleteAllByUser(String userId);
}
```

**Implementations:**
- `CaffeineDeviceStore` (default)
- `RedisDeviceStore` (distributed)

---

## 3. Anomaly Detection

### 3.1 Detection Rules

**Service:** `VigilAnomalyService`

```java
public interface VigilAnomalyService {
    AnomalyResult analyze(SessionContext context);
    void recordActivity(String sessionId, ActivityType type);
}
```

**Rules (Native - Always Enforced):**

| Rule | Trigger | Action |
|------|---------|--------|
| Impossible Travel | >500 km/h between requests | Force logout |
| IP + Device Change | Both change within 5 min | Force re-auth |
| Multiple IPs | >3 IPs in 10 min | Flag suspicious |
| Concurrent Sessions | Same user, different locations | Alert |

**Implementation:**
```java
public class VigilAnomalyDetector {

    public AnomalyResult analyze(SessionContext ctx) {
        List<Anomaly> anomalies = new ArrayList<>();

        // Rule 1: Impossible travel
        if (detectImpossibleTravel(ctx)) {
            anomalies.add(Anomaly.IMPOSSIBLE_TRAVEL);
        }

        // Rule 2: IP + Device change
        if (ctx.ipChanged() && ctx.deviceChanged()) {
            Duration since = ctx.timeSinceLastActivity();
            if (since.toMinutes() < 5) {
                anomalies.add(Anomaly.RAPID_CONTEXT_CHANGE);
            }
        }

        // Rule 3: Multiple IPs
        if (ctx.uniqueIpsInWindow(Duration.ofMinutes(10)) > 3) {
            anomalies.add(Anomaly.MULTIPLE_IPS);
        }

        return new AnomalyResult(anomalies, determineAction(anomalies));
    }
}
```

### 3.2 Anomaly Actions

```java
enum AnomalyAction {
    NONE,           // Continue normally
    LOG,            // Log warning
    FLAG,           // Mark session as suspicious
    CHALLENGE,      // Require re-authentication
    LOGOUT,         // Force logout
    LOCK            // Lock account temporarily
}
```

**Action Mapping:**
```java
AnomalyAction determineAction(List<Anomaly> anomalies) {
    if (anomalies.contains(IMPOSSIBLE_TRAVEL)) {
        return AnomalyAction.LOGOUT;
    }
    if (anomalies.contains(RAPID_CONTEXT_CHANGE)) {
        return AnomalyAction.CHALLENGE;
    }
    if (anomalies.contains(MULTIPLE_IPS)) {
        return AnomalyAction.FLAG;
    }
    return AnomalyAction.NONE;
}
```

### 3.3 Events

```java
// Emitted via Spring ApplicationEventPublisher
record AnomalyDetectedEvent(
    String sessionId,
    String userId,
    Anomaly anomaly,
    AnomalyAction action,
    SessionContext context,
    Instant timestamp
) {}

record NewDeviceEvent(
    String userId,
    DeviceInfo device,
    String ip,
    Instant timestamp
) {}

record IpChangeEvent(
    String sessionId,
    String userId,
    String previousIp,
    String newIp,
    IpChangeResult result,
    Instant timestamp
) {}
```

---

## 4. Session Metadata

### 4.1 JWT Claims (Minimal)

```json
{
  "sub": "user-123",
  "sid": "session-456",
  "ip": "203.0.113.42",
  "iat": 1702483200,
  "exp": 1702484100
}
```

### 4.2 Session Storage (Full)

```java
record Session(
    String sessionId,
    String userId,
    String tokenFamily,

    // IP & Location
    String ip,
    String countryCode,
    GeoLocation location,

    // Device
    String deviceId,
    String userAgent,
    String platform,
    String browser,

    // Timestamps
    Instant createdAt,
    Instant lastActivity,
    Instant expiresAt,

    // Flags
    boolean suspicious,
    boolean newDevice,
    List<String> ipHistory
) {}
```

---

## 5. Configuration

```yaml
vigil:
  # IP Protection (Native - always on)
  ip:
    trust-proxy-headers: true
    trusted-proxies: []
    geolocation-provider: maxmind  # or: ip-api, none
    maxmind-database: /path/to/GeoLite2-City.mmdb

  # Device Tracking (Optional)
  device:
    enabled: false
    trust-duration: 30d
    max-devices-per-user: 10
    fingerprint-components: [user-agent, accept-language]

  # Anomaly Detection (Native - always on)
  anomaly:
    impossible-travel-speed-kmh: 500
    rapid-change-window-minutes: 5
    multiple-ip-threshold: 3
    multiple-ip-window-minutes: 10

  # Session Storage
  session:
    storage: caffeine  # or: redis
    ttl: 7d
    max-per-user: 10
```

---

## 6. API

### 6.1 Session Management

```java
@RestController
@RequestMapping("/api/sessions")
public class SessionController {

    @GetMapping
    public List<SessionInfo> getMySessions() { }

    @DeleteMapping("/{sessionId}")
    public void revokeSession(@PathVariable String sessionId) { }

    @DeleteMapping
    public void revokeAllSessions() { }
}
```

### 6.2 Device Management

```java
@RestController
@RequestMapping("/api/devices")
public class DeviceController {

    @GetMapping
    public List<DeviceInfo> getMyDevices() { }

    @PostMapping("/{deviceId}/trust")
    public void trustDevice(@PathVariable String deviceId) { }

    @DeleteMapping("/{deviceId}")
    public void revokeDevice(@PathVariable String deviceId) { }

    @DeleteMapping
    public void revokeAllDevices() { }
}
```

---

## 7. Native vs Optional Summary

| Feature | Type | Rationale |
|---------|------|-----------|
| IP extraction | Native | Required for all features |
| IP logging | Native | Audit compliance |
| IP change detection | Native | Session hijacking defense |
| Impossible travel | Native | Attack detection |
| Anomaly detection | Native | Security invariant |
| Device fingerprinting | Optional | Privacy concerns |
| Trusted devices | Optional | UX feature |
| New device alerts | Optional | Requires email/notification |

---

## 8. Dependencies

**Required:**
- None (pure Java implementation)

**Optional:**
- MaxMind GeoLite2 (geolocation)
- Spring Data Redis (distributed storage)
- Micrometer (metrics)
