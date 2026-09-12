package io.github.sequelcore.vigil.enrollment;

import java.time.Instant;
import java.util.UUID;

/** Secret-bearing message passed only to the application delivery adapter. */
public final class EnrollmentDelivery {
  private final String originalEmail;
  private final String canonicalEmail;
  private final String contextId;
  private final String contextVersion;
  private final String audience;
  private final String purpose;
  private final UUID lifecycleId;
  private final long generation;
  private final String proof;
  private final Instant expiresAt;

  public EnrollmentDelivery(
      EnrollmentStartRequest request,
      String canonicalEmail,
      String audience,
      String purpose,
      EnrollmentStartOutcome outcome,
      String proof) {
    this.originalEmail = request.email();
    this.canonicalEmail = canonicalEmail;
    this.contextId = request.contextId();
    this.contextVersion = request.contextVersion();
    this.audience = audience;
    this.purpose = purpose;
    this.lifecycleId = outcome.lifecycleId();
    this.generation = outcome.generation();
    this.proof = proof;
    this.expiresAt = outcome.proofExpiresAt();
  }

  public String canonicalEmail() {
    return canonicalEmail;
  }

  /** The original requested address, retained only for application delivery/display. */
  public String originalEmail() {
    return originalEmail;
  }

  public String contextId() {
    return contextId;
  }

  public String contextVersion() {
    return contextVersion;
  }

  public String audience() {
    return audience;
  }

  public String purpose() {
    return purpose;
  }

  public UUID lifecycleId() {
    return lifecycleId;
  }

  public long generation() {
    return generation;
  }

  public String proof() {
    return proof;
  }

  public Instant expiresAt() {
    return expiresAt;
  }

  @Override
  public String toString() {
    return "EnrollmentDelivery[redacted]";
  }
}
