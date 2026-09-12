package io.github.sequelcore.vigil.enrollment;

import java.util.UUID;

/** Conditional, generation-scoped recording of an external delivery outcome. */
public record EnrollmentDeliveryOutcomeCommand(
    String canonicalEmail,
    String contextId,
    String contextVersion,
    String audience,
    String purpose,
    UUID lifecycleId,
    long generation,
    EnrollmentDeliveryPort.DeliveryOutcome outcome) {
  @Override
  public String toString() {
    return "EnrollmentDeliveryOutcomeCommand[redacted]";
  }
}
