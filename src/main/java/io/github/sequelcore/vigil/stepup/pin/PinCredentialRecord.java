package io.github.sequelcore.vigil.stepup.pin;

import java.time.Instant;

/** Stored PIN metadata. The hash must be BCrypt; raw PINs must never be persisted. */
public record PinCredentialRecord(String hash, Instant rotatedAt, boolean revoked) {}
