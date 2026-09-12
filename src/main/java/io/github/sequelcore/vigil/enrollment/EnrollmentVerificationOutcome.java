package io.github.sequelcore.vigil.enrollment;

/** Store result for an atomic verification attempt. */
public record EnrollmentVerificationOutcome(Kind kind, EnrollmentVerificationReceipt receipt) {
  public enum Kind {
    CREATED_RECEIPT,
    EXISTING_RECEIPT,
    COMPLETED,
    REJECTED
  }

  public static EnrollmentVerificationOutcome rejected() {
    return new EnrollmentVerificationOutcome(Kind.REJECTED, null);
  }
}
