package io.github.sequelcore.vigil.stepup;

import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** Declares the security context to which a step-up challenge is bound. */
public record StepUpChallengeRequest(
    String currentActorId,
    UUID tenantId,
    String audience,
    String purpose,
    boolean allowSelfAuthorization,
    Set<StepUpMethod> allowedMethods) {

  public StepUpChallengeRequest {
    requireText(currentActorId, "currentActorId");
    Objects.requireNonNull(tenantId, "tenantId is required");
    requireText(audience, "audience");
    requireText(purpose, "purpose");
    allowedMethods = allowedMethods == null ? Set.of() : Set.copyOf(allowedMethods);
    if (allowedMethods.isEmpty()) {
      throw new IllegalArgumentException("allowedMethods must not be empty");
    }
  }

  private static void requireText(String value, String name) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(name + " is required");
    }
  }
}
