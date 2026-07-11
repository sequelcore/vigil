package io.github.sequelcore.vigil.stepup;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import io.github.sequelcore.vigil.protection.VigilProtectionService;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Creates and consumes generic, one-time step-up authorization evidence without altering a session.
 */
public final class StepUpAuthorizationService {
  private static final SecureRandom RANDOM = new SecureRandom();

  private final VigilProperties.StepUp config;
  private final StepUpStore store;
  private final VigilProtectionService protectionService;
  private final Map<StepUpMethod, StepUpCredentialVerifier> verifiers;
  private final Clock clock;

  public StepUpAuthorizationService(
      VigilProperties.StepUp config,
      StepUpStore store,
      VigilProtectionService protectionService,
      java.util.List<StepUpCredentialVerifier> verifiers) {
    this(config, store, protectionService, verifiers, Clock.systemUTC());
  }

  StepUpAuthorizationService(
      VigilProperties.StepUp config,
      StepUpStore store,
      VigilProtectionService protectionService,
      java.util.List<StepUpCredentialVerifier> verifiers,
      Clock clock) {
    this.config = config;
    this.store = store;
    this.protectionService = protectionService;
    this.clock = clock;
    this.verifiers =
        verifiers.stream()
            .collect(
                Collectors.toUnmodifiableMap(
                    StepUpCredentialVerifier::method, verifier -> verifier));
  }

  /** Creates a short-lived, non-secret challenge bound to the current actor and business intent. */
  public StepUpChallenge createChallenge(StepUpChallengeRequest request) {
    Instant issuedAt = Instant.now(clock);
    StepUpChallenge challenge =
        new StepUpChallenge(
            UUID.randomUUID(),
            request.currentActorId(),
            request.tenantId(),
            request.audience(),
            request.purpose(),
            request.allowSelfAuthorization(),
            request.allowedMethods(),
            issuedAt,
            issuedAt.plus(config.challengeTtl()));
    store.saveChallenge(challenge);
    return challenge;
  }

  /**
   * Verifies one credential submission and returns an opaque proof. This method never changes the
   * current Spring Security authentication or writes cookies/tokens.
   */
  public StepUpAuthorizationProof authorize(
      UUID challengeId, String authorizingActorId, StepUpCredential credential) {
    Instant now = Instant.now(clock);
    StepUpChallenge challenge =
        store
            .consumeChallenge(challengeId, now)
            .orElseThrow(
                () ->
                    new StepUpException(
                        StepUpException.Code.CHALLENGE_EXPIRED, "Challenge expired"));
    try (credential) {
      if (!challenge.allowedMethods().contains(credential.method())) {
        throw new StepUpException(StepUpException.Code.METHOD_NOT_ALLOWED, "Method is not allowed");
      }
      if (!challenge.allowSelfAuthorization()
          && challenge.currentActorId().equals(authorizingActorId)) {
        throw new StepUpException(
            StepUpException.Code.SELF_AUTHORIZATION_NOT_ALLOWED,
            "Self-authorization is not allowed");
      }
      String protectionKey = challenge.tenantId() + ":step-up:" + authorizingActorId;
      if (protectionService.isLocked(protectionKey)) {
        throw new StepUpException(StepUpException.Code.ACTOR_LOCKED, "Authorizing actor is locked");
      }
      StepUpCredentialVerifier verifier = verifiers.get(credential.method());
      if (verifier == null
          || !verifier.verify(challenge.tenantId(), authorizingActorId, credential)) {
        protectionService.recordFailedAttempt(protectionKey);
        throw new StepUpException(StepUpException.Code.CREDENTIAL_INVALID, "Credential is invalid");
      }
      protectionService.recordSuccessfulLogin(protectionKey);
      UUID authorizationId = UUID.randomUUID();
      UUID auditId = UUID.randomUUID();
      StepUpAuthorization authorization =
          new StepUpAuthorization(
              authorizationId,
              challenge.currentActorId(),
              authorizingActorId,
              challenge.tenantId(),
              challenge.audience(),
              challenge.purpose(),
              credential.method(),
              now,
              now.plus(config.proofTtl()),
              auditId);
      String value = randomProof();
      store.saveProof(hash(value), authorization);
      return new StepUpAuthorizationProof(
          authorizationId, value, authorization.expiresAt(), auditId);
    }
  }

  /** Atomically verifies the expected binding and consumes the proof exactly once. */
  public StepUpAuthorization consume(
      String proof, StepUpAuthorizationRequest expectedAuthorization) {
    String proofHash = hash(proof);
    StepUpAuthorization authorization =
        store
            .consumeProof(
                proofHash,
                candidate -> bindingMatches(candidate, expectedAuthorization),
                Instant.now(clock))
            .orElse(null);
    if (authorization == null) {
      if (store.wasProofUsed(proofHash)) {
        throw new StepUpException(
            StepUpException.Code.PROOF_ALREADY_USED, "Proof has already been used");
      }
      if (store.hasProof(proofHash, Instant.now(clock))) {
        throw new StepUpException(
            StepUpException.Code.BINDING_MISMATCH, "Proof binding does not match");
      }
      throw new StepUpException(StepUpException.Code.PROOF_INVALID, "Proof is invalid or expired");
    }
    return authorization;
  }

  private static boolean bindingMatches(
      StepUpAuthorization authorization, StepUpAuthorizationRequest expectedAuthorization) {
    return authorization.tenantId().equals(expectedAuthorization.tenantId())
        && authorization.audience().equals(expectedAuthorization.audience())
        && authorization.purpose().equals(expectedAuthorization.purpose());
  }

  private static String randomProof() {
    byte[] bytes = new byte[32];
    RANDOM.nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  private static String hash(String value) {
    if (value == null || value.isBlank()) {
      throw new StepUpException(StepUpException.Code.PROOF_INVALID, "Proof is invalid");
    }
    try {
      return Base64.getUrlEncoder()
          .withoutPadding()
          .encodeToString(
              MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }
}
