package io.github.sequelcore.vigil.blacklist;

import java.time.Instant;

/**
 * Holds rotation data for a refresh token during grace period.
 *
 * @param rotatedAt when the token was rotated
 * @param newAccessToken the new access token issued
 * @param newRefreshToken the new refresh token issued
 * @param accessExpiration expiration of the new access token
 * @param refreshExpiration expiration of the new refresh token
 */
public record RotatedToken(
    Instant rotatedAt,
    String newAccessToken,
    String newRefreshToken,
    Instant accessExpiration,
    Instant refreshExpiration) {}
