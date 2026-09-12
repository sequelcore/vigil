package io.github.sequelcore.vigil.enrollment;

/** Minimal admission input. This value must not be logged by an adapter. */
public record EnrollmentAdmission(
    String canonicalEmail, String contextId, String contextVersion, EnrollmentOperation operation) {
  @Override
  public String toString() {
    return "EnrollmentAdmission[redacted]";
  }
}
