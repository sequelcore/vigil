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

- Invalid JWT signing configuration fails at application startup.
- `secure: true` requires HTTPS for browser clients.
- The built-in blacklist, protection, and step-up stores are node-local. See [deployment and operations](../operations/deployment.md) before running more than one instance.
- Configuration only controls authentication infrastructure. Route authorization, user lifecycle, credential lookup, and business approval policy remain application-owned.
