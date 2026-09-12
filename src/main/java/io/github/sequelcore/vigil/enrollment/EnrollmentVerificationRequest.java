package io.github.sequelcore.vigil.enrollment;

/** Contact-only proof submission. It deliberately has no credential or session fields. */
public final class EnrollmentVerificationRequest {
  private final String email;
  private final String contextId;
  private final String contextVersion;
  private final String proof;

  public EnrollmentVerificationRequest(
      String email, String contextId, String contextVersion, String proof) {
    this.email = email;
    this.contextId = contextId;
    this.contextVersion = contextVersion;
    this.proof = proof;
  }

  public String email() {
    return email;
  }

  public String contextId() {
    return contextId;
  }

  public String contextVersion() {
    return contextVersion;
  }

  public String proof() {
    return proof;
  }

  @Override
  public String toString() {
    return "EnrollmentVerificationRequest[redacted]";
  }
}
