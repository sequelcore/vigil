package io.github.sequelcore.vigil.stepup.pin;

import io.github.sequelcore.vigil.stepup.StepUpCredential;
import io.github.sequelcore.vigil.stepup.StepUpCredentialVerifier;
import io.github.sequelcore.vigil.stepup.StepUpMethod;
import java.util.UUID;

/** PIN verifier backed by application-owned credential storage. */
public final class PinStepUpCredentialVerifier implements StepUpCredentialVerifier {
  private final PinCredentialStore store;
  private final VigilPinService pinService;

  public PinStepUpCredentialVerifier(PinCredentialStore store, VigilPinService pinService) {
    this.store = store;
    this.pinService = pinService;
  }

  @Override
  public StepUpMethod method() {
    return StepUpMethod.PIN;
  }

  @Override
  public boolean verify(UUID tenantId, String actorId, StepUpCredential credential) {
    if (!(credential instanceof PinCredential pin)) {
      return false;
    }
    return store
        .find(tenantId, actorId)
        .map(record -> pinService.matches(pin, record))
        .orElse(false);
  }
}
