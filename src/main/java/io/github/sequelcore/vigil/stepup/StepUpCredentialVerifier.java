package io.github.sequelcore.vigil.stepup;

import java.util.UUID;

/** Application-extensible verifier for a particular step-up credential method. */
public interface StepUpCredentialVerifier {
  StepUpMethod method();

  boolean verify(UUID tenantId, String actorId, StepUpCredential credential);
}
