package io.github.sequelcore.vigil.enrollment;

/** Application-owned abuse admission boundary for enrollment sends. */
@FunctionalInterface
public interface EnrollmentAbuseControl {
  /** Returns whether the request may create or rotate a proof. Failures are denied by Vigil. */
  boolean admit(EnrollmentAdmission admission);
}
