package io.github.sequelcore.vigil.stepup;

/** Authentication method used to approve a short-lived step-up authorization. */
public enum StepUpMethod {
  PIN,
  PASSWORD,
  PASSKEY,
  NFC,
  OTP
}
