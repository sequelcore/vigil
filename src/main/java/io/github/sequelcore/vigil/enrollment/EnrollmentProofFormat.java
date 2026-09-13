package io.github.sequelcore.vigil.enrollment;

/** Canonical representation of a contact-enrollment proof delivered by the application. */
public enum EnrollmentProofFormat {
  /** Existing 256-bit Base64URL token, normally embedded in an application-owned link. */
  OPAQUE_TOKEN,

  /** Eight uniformly generated ASCII decimal digits intended for deliberate manual entry. */
  DECIMAL_CODE
}
