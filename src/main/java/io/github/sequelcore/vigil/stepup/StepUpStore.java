package io.github.sequelcore.vigil.stepup;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Predicate;

/** Shared-state SPI. Production clusters must provide an atomic distributed implementation. */
public interface StepUpStore {
  void saveChallenge(StepUpChallenge challenge);

  Optional<StepUpChallenge> consumeChallenge(UUID challengeId, Instant now);

  void saveProof(String proofHash, StepUpAuthorization authorization);

  Optional<StepUpAuthorization> consumeProof(
      String proofHash, Predicate<StepUpAuthorization> expectedBinding, Instant now);

  boolean hasProof(String proofHash, Instant now);

  boolean wasProofUsed(String proofHash);
}
