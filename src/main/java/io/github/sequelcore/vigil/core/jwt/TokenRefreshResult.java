package io.github.sequelcore.vigil.core.jwt;

import java.time.Instant;

/**
 * Result of a token refresh operation with rotation.
 *
 * @param accessToken the new access token
 * @param refreshToken the new rotated refresh token
 * @param accessExpiresAt when the access token expires
 * @param refreshExpiresAt when the refresh token expires
 */
public record TokenRefreshResult(
    String accessToken, String refreshToken, Instant accessExpiresAt, Instant refreshExpiresAt) {}
