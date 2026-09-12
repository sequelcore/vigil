package io.github.sequelcore.vigil.enrollment;

/** Internal marker that forces every enabled enrollment boundary to be present at startup. */
final class EnrollmentRequiredPorts {
  private final EmailCanonicalizer canonicalizer;
  private final EnrollmentIdentityPort identityPort;
  private final EnrollmentDeliveryPort deliveryPort;
  private final EnrollmentAbuseControl abuseControl;
  private final EnrollmentStore store;

  EnrollmentRequiredPorts(
      EmailCanonicalizer canonicalizer,
      EnrollmentIdentityPort identityPort,
      EnrollmentDeliveryPort deliveryPort,
      EnrollmentAbuseControl abuseControl,
      EnrollmentStore store) {
    this.canonicalizer = canonicalizer;
    this.identityPort = identityPort;
    this.deliveryPort = deliveryPort;
    this.abuseControl = abuseControl;
    this.store = store;
  }

  EmailCanonicalizer canonicalizer() {
    return canonicalizer;
  }

  EnrollmentIdentityPort identityPort() {
    return identityPort;
  }

  EnrollmentDeliveryPort deliveryPort() {
    return deliveryPort;
  }

  EnrollmentAbuseControl abuseControl() {
    return abuseControl;
  }

  EnrollmentStore store() {
    return store;
  }
}
