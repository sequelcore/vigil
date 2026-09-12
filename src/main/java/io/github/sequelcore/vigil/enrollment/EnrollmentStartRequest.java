package io.github.sequelcore.vigil.enrollment;

/** Request supplied by an application route or job. Vigil supplies no route. */
public final class EnrollmentStartRequest {
  private final String email;
  private final String contextId;
  private final String contextVersion;

  public EnrollmentStartRequest(String email, String contextId, String contextVersion) {
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
    return "EnrollmentStartRequest[redacted]";
  }
}
