# Deployment and operations

## Production baseline

- Run the supported Java and Spring Boot line stated in the root README.
- Terminate or pass through TLS so browser cookies can be `Secure`.
- Supply JWT keys from a secret manager or protected runtime environment; never commit them.
- Set a specific JWT issuer and audience when services have a stable trust boundary.
- Use short access-token TTLs and a refresh TTL appropriate to the application risk profile.

## Signing modes and rotation

HS256 is suitable only when every service holding the secret is authorized to sign. Use RS256 when verifiers must not hold the private key. RS256 exposes `/.well-known/jwks.json`; during rotation, deploy the new private/public pair and keep previous public keys in `rsa-public-keys` until all tokens signed by them expire.

## Stateful features in a cluster

The built-in Caffeine implementations are single-node defaults.

| Feature | Production cluster requirement |
| --- | --- |
| blacklist and refresh rotation | provide a shared `VigilBlacklistBackend` |
| step-up authorization | provide a shared `StepUpStore` with atomic challenge/proof consumption |
| failed-attempt protection | place a shared rate limiter or equivalent protection in front of the application when node-local lockout is insufficient |

Do not use eventually consistent state for one-time proof consumption. A proof must be consumed at most once across all nodes.

## Operational checks

Before deploying a configuration change:

1. Validate the Spring context starts with the intended JWT algorithm and keys.
2. Exercise a protected route, an anonymous route, refresh rotation, and logout/revocation.
3. For RS256, fetch and validate the JWKS endpoint from a verifier environment.
4. For tenant-aware routes, test matching and mismatched tenant headers.
5. For step-up, test success, invalid credential, expired proof, binding mismatch, and concurrent replay.

Run the repository verification commands in [testing and verification](../development/testing.md) before a release.
