package io.github.sequelcore.vigil.stepup;

import java.time.Instant;
import java.util.UUID;

/** Opaque bearer proof. Send it once to the business backend and never persist it in a client. */
public record StepUpAuthorizationProof(
    UUID authorizationId, String value, Instant expiresAt, UUID auditId) {}
