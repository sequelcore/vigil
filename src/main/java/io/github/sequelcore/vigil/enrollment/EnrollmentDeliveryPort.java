package io.github.sequelcore.vigil.enrollment;

/** Delivers a proof through an application-owned channel, normally email. */
@FunctionalInterface
public interface EnrollmentDeliveryPort {
  DeliveryOutcome deliver(EnrollmentDelivery delivery);

  /** Classification used to retain a proof for transient delivery failures. */
  enum DeliveryOutcome {
    ACCEPTED,
    RETRYABLE_FAILURE,
    PERMANENT_FAILURE
  }
}
