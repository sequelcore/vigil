package io.github.sequelcore.vigil.stepup;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

/** Public, non-secret handle for a single step-up authorization ceremony. */
public record StepUpChallenge(
    UUID id,
    String currentActorId,
    UUID tenantId,
    String audience,
    String purpose,
    boolean allowSelfAuthorization,
    Set<StepUpMethod> allowedMethods,
    Instant issuedAt,
    Instant expiresAt) {}
