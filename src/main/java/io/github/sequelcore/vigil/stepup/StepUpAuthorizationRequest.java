package io.github.sequelcore.vigil.stepup;

import java.util.Objects;
import java.util.UUID;

/** Expected binding when a business backend consumes a proof. */
public record StepUpAuthorizationRequest(UUID tenantId, String audience, String purpose) {
  public StepUpAuthorizationRequest {
    Objects.requireNonNull(tenantId, "tenantId is required");
    if (audience == null || audience.isBlank() || purpose == null || purpose.isBlank()) {
      throw new IllegalArgumentException("audience and purpose are required");
    }
  }
}
