package io.github.sequelcore.vigil.stepup;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Predicate;

/** Single-node default store. It deliberately stores only a digest of opaque proofs. */
public final class CaffeineStepUpStore implements StepUpStore {
  private final Cache<UUID, StepUpChallenge> challenges;
  private final Cache<String, StepUpAuthorization> proofs;
  private final Cache<String, Boolean> usedProofs;

  public CaffeineStepUpStore(long maxSize, Duration maximumTtl) {
    challenges = Caffeine.newBuilder().maximumSize(maxSize).expireAfterWrite(maximumTtl).build();
    proofs = Caffeine.newBuilder().maximumSize(maxSize).expireAfterWrite(maximumTtl).build();
    usedProofs = Caffeine.newBuilder().maximumSize(maxSize).expireAfterWrite(maximumTtl).build();
  }

  @Override
  public void saveChallenge(StepUpChallenge challenge) {
    challenges.put(challenge.id(), challenge);
  }

  @Override
  public Optional<StepUpChallenge> consumeChallenge(UUID challengeId, Instant now) {
    StepUpChallenge challenge = challenges.asMap().remove(challengeId);
    return challenge == null || !now.isBefore(challenge.expiresAt())
        ? Optional.empty()
        : Optional.of(challenge);
  }

  @Override
  public void saveProof(String proofHash, StepUpAuthorization authorization) {
    proofs.put(proofHash, authorization);
  }

  @Override
  public Optional<StepUpAuthorization> consumeProof(
      String proofHash, Predicate<StepUpAuthorization> expectedBinding, Instant now) {
    AtomicReference<StepUpAuthorization> consumed = new AtomicReference<>();
    proofs
        .asMap()
        .computeIfPresent(
            proofHash,
            (key, authorization) -> {
              if (!now.isBefore(authorization.expiresAt())) {
                return null;
              }
              if (!expectedBinding.test(authorization)) {
                return authorization;
              }
              consumed.set(authorization);
              usedProofs.put(proofHash, Boolean.TRUE);
              return null;
            });
    return Optional.ofNullable(consumed.get());
  }

  @Override
  public boolean hasProof(String proofHash, Instant now) {
    StepUpAuthorization authorization = proofs.getIfPresent(proofHash);
    return authorization != null && now.isBefore(authorization.expiresAt());
  }

  @Override
  public boolean wasProofUsed(String proofHash) {
    return usedProofs.getIfPresent(proofHash) != null;
  }
}
