package io.github.sequelcore.vigil.auth;

import io.github.sequelcore.vigil.core.jwt.VigilTokenClaims;
import java.time.Instant;

/**
 * Result of a successful authentication or token refresh operation.
 *
 * <p>Contains the new tokens, their expiration times, and the claims from the access token.
 *
 * @param accessToken the new access token
 * @param refreshToken the new refresh token
 * @param accessExpiresAt when the access token expires
 * @param refreshExpiresAt when the refresh token expires
 * @param claims the claims from the access token
 */
public record AuthResult(
    String accessToken,
    String refreshToken,
    Instant accessExpiresAt,
    Instant refreshExpiresAt,
    VigilTokenClaims claims) {}
