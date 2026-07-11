package io.github.sequelcore.vigil.stepup.pin;

import java.util.Optional;
import java.util.UUID;

/** Application persistence SPI for personal PINs. Vigil intentionally does not own user storage. */
public interface PinCredentialStore {
  Optional<PinCredentialRecord> find(UUID tenantId, String actorId);

  void save(UUID tenantId, String actorId, PinCredentialRecord credential);
}
