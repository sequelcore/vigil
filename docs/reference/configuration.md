# Configuration reference

This is the canonical reference for `vigil.*` properties. Values below reflect `VigilProperties`; omitted optional sections use the stated defaults.

## Required JWT configuration

Configure exactly one signing mode.

```yaml
vigil:
  jwt:
    algorithm: HS256 # default
    secret: ${JWT_SECRET} # required for HS256; at least 32 characters
    access-ttl: 15m
    refresh-ttl: 7d
    issuer: my-service # optional
    audience: my-api # optional
    clock-skew: 0s # maximum 5m
```

For RS256, replace the HS256 secret with the active private/public pair. Additional public keys only verify existing tokens during key rotation.

```yaml
vigil:
  jwt:
    algorithm: RS256
    rsa-private-key: ${RSA_PRIVATE_KEY}
    rsa-public-key: ${RSA_PUBLIC_KEY}
    rsa-public-keys: []
```

`rsa-private-key`, `rsa-public-key`, and `rsa-public-keys` accept inline PEM, `classpath:` or `file:` locations. RS256 automatically registers `/.well-known/jwks.json`.

The HS256 length check counts characters; it does not measure entropy. Generate random key material
with at least 256 bits of entropy and encode it without truncation. Do not use a human password or
repeated text merely because it reaches 32 characters.

## Optional configuration

```yaml
vigil:
  auth:
    realm: app

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
    grace-period: 30s # maximum 60s

  protection:
    max-attempts: 5
    lock-duration: 15m
    max-size: 10000

  tenant:
    enabled: false
    header-name: X-Tenant-ID

  filter:
    ignored-paths: []
    public-paths: []
    profile-paths: {}

  session:
    enabled: false
    cookie-name: session_token
    ttl: 30m

  reset:
    ttl: 1h

  step-up:
    challenge-ttl: 2m
    proof-ttl: 5m
    max-size: 10000
    pin:
      min-length: 6
      max-length: 12
      bcrypt-strength: 12
      reject-common-patterns: true
```

## Validation and deployment notes

Spring Boot duration syntax is accepted for duration properties, for example `30s`, `15m`, and
`7d`. Lists and maps use standard YAML binding.

| Property | Validation or normalization |
| --- | --- |
| `jwt.secret` | Required for HS256; at least 32 characters |
| `jwt.clock-skew` | Between `0s` and `5m` |
| `jwt.rsa-private-key`, `jwt.rsa-public-key` | Both required for RS256 |
| `password.strength` | BCrypt cost `4`–`31`; invalid values normalize to `12` |
| `blacklist.max-size` | Non-positive values normalize to `10000` |
| `blacklist.grace-period` | Values above `60s` normalize to `60s` |
| `protection.max-attempts`, `protection.max-size` | Non-positive values normalize to their defaults |
| `step-up.challenge-ttl`, `step-up.proof-ttl` | Non-positive values normalize to their defaults |
| `step-up.pin.min-length` | Values below `4` normalize to `6` |
| `step-up.pin.max-length` | Must be at least `min-length` and at most `128`; otherwise normalizes to `12` |
| `step-up.pin.bcrypt-strength` | BCrypt cost `4`–`31`; invalid values normalize to `12` |

- Invalid JWT signing configuration fails at application startup.
- `secure: true` requires HTTPS for browser clients.
- The built-in blacklist, protection, and step-up stores are node-local. See [deployment and operations](../operations/deployment.md) before running more than one instance.
- `public-paths` changes Vigil credential processing only. The application must configure its own
  anonymous authorization rules.
- Ownership details are canonical in [system boundaries](../architecture/system-boundaries.md).
