package io.github.sequelcore.vigil.enrollment;

/** Retries application of an already-created verification receipt without creating another one. */
public final class EnrollmentRecoveryRequest {
  private final String email;
  private final String contextId;
  private final String contextVersion;

  public EnrollmentRecoveryRequest(String email, String contextId, String contextVersion) {
    this.email = email;
    this.contextId = contextId;
    this.contextVersion = contextVersion;
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

  @Override
  public String toString() {
    return "EnrollmentRecoveryRequest[redacted]";
  }
}
