package io.github.sequelcore.vigil.stepup;

import java.time.Instant;
import java.util.UUID;

/** Verified authorization evidence, returned only after a proof is consumed. */
public record StepUpAuthorization(
    UUID authorizationId,
    String currentActorId,
    String authorizingActorId,
    UUID tenantId,
    String audience,
    String purpose,
    StepUpMethod method,
    Instant issuedAt,
    Instant expiresAt,
    UUID auditId) {}
