package io.github.sequelcore.vigil.stepup;

/** Stable, secret-free failures from the step-up authorization boundary. */
public class StepUpException extends RuntimeException {
  private final Code code;

  public StepUpException(Code code, String message) {
    super(message);
    this.code = code;
  }

  public Code getCode() {
    return code;
  }

  public enum Code {
    CHALLENGE_EXPIRED,
    CREDENTIAL_INVALID,
    ACTOR_LOCKED,
    METHOD_NOT_ALLOWED,
    SELF_AUTHORIZATION_NOT_ALLOWED,
    PROOF_INVALID,
    PROOF_EXPIRED,
    PROOF_ALREADY_USED,
    BINDING_MISMATCH
  }
}
