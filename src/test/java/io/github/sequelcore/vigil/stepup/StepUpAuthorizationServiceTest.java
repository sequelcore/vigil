package io.github.sequelcore.vigil.stepup;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import io.github.sequelcore.vigil.protection.VigilProtectionService;
import io.github.sequelcore.vigil.stepup.pin.PinCredential;
import io.github.sequelcore.vigil.stepup.pin.PinCredentialRecord;
import io.github.sequelcore.vigil.stepup.pin.PinCredentialStore;
import io.github.sequelcore.vigil.stepup.pin.PinStepUpCredentialVerifier;
import io.github.sequelcore.vigil.stepup.pin.VigilPinService;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class StepUpAuthorizationServiceTest {
  private static final UUID TENANT = UUID.randomUUID();
  private StepUpAuthorizationService service;
  private VigilPinService pins;
  private InMemoryPinStore pinStore;

  @BeforeEach
  void setUp() {
    VigilProperties.StepUp config =
        new VigilProperties.StepUp(Duration.ofMinutes(2), Duration.ofMinutes(5), 100, null);
    pins = new VigilPinService(config.pin());
    pinStore = new InMemoryPinStore();
    service =
        new StepUpAuthorizationService(
            config,
            new CaffeineStepUpStore(100, Duration.ofMinutes(10)),
            new VigilProtectionService(
                new VigilProperties.Protection(3, Duration.ofMinutes(1), 100)),
            java.util.List.of(new PinStepUpCredentialVerifier(pinStore, pins)));
    try (PinCredential pin = new PinCredential("482915".toCharArray())) {
      pins.enroll(pinStore, TENANT, "supervisor", pin);
    }
  }

  @Test
  void authorizesASecondActorAndConsumesTheProofOnlyOnce() {
    StepUpChallenge challenge = challenge(false);
    StepUpAuthorizationProof proof;
    try (PinCredential pin = new PinCredential("482915".toCharArray())) {
      proof = service.authorize(challenge.id(), "supervisor", pin);
    }

    StepUpAuthorization authorization =
        service.consume(
            proof.value(), new StepUpAuthorizationRequest(TENANT, "admit-api", "refund"));

    assertThat(authorization.currentActorId()).isEqualTo("cashier");
    assertThat(authorization.authorizingActorId()).isEqualTo("supervisor");
    assertThat(authorization.method()).isEqualTo(StepUpMethod.PIN);
    assertThatThrownBy(
            () ->
                service.consume(
                    proof.value(), new StepUpAuthorizationRequest(TENANT, "admit-api", "refund")))
        .isInstanceOf(StepUpException.class)
        .extracting(exception -> ((StepUpException) exception).getCode())
        .isEqualTo(StepUpException.Code.PROOF_ALREADY_USED);
  }

  @Test
  void rejectsSelfAuthorizationWhenPolicyDisallowsIt() {
    StepUpChallenge challenge = challenge(false);
    try (PinCredential pin = new PinCredential("482915".toCharArray())) {
      assertThatThrownBy(() -> service.authorize(challenge.id(), "cashier", pin))
          .isInstanceOf(StepUpException.class)
          .extracting(exception -> ((StepUpException) exception).getCode())
          .isEqualTo(StepUpException.Code.SELF_AUTHORIZATION_NOT_ALLOWED);
    }
  }

  @Test
  void rejectsAWrongPurposeWithoutConsumingTheProof() {
    StepUpChallenge challenge = challenge(false);
    StepUpAuthorizationProof proof;
    try (PinCredential pin = new PinCredential("482915".toCharArray())) {
      proof = service.authorize(challenge.id(), "supervisor", pin);
    }

    assertThatThrownBy(
            () ->
                service.consume(
                    proof.value(), new StepUpAuthorizationRequest(TENANT, "admit-api", "cancel")))
        .isInstanceOf(StepUpException.class)
        .extracting(exception -> ((StepUpException) exception).getCode())
        .isEqualTo(StepUpException.Code.BINDING_MISMATCH);
    assertThat(
            service.consume(
                proof.value(), new StepUpAuthorizationRequest(TENANT, "admit-api", "refund")))
        .isNotNull();
  }

  @Test
  void locksTheAuthorizingActorAfterRepeatedInvalidPins() {
    for (int attempt = 0; attempt < 3; attempt++) {
      StepUpChallenge challenge = challenge(false);
      try (PinCredential pin = new PinCredential("000000".toCharArray())) {
        assertThatThrownBy(() -> service.authorize(challenge.id(), "supervisor", pin))
            .isInstanceOf(StepUpException.class);
      }
    }
    StepUpChallenge challenge = challenge(false);
    try (PinCredential pin = new PinCredential("482915".toCharArray())) {
      assertThatThrownBy(() -> service.authorize(challenge.id(), "supervisor", pin))
          .isInstanceOf(StepUpException.class)
          .extracting(exception -> ((StepUpException) exception).getCode())
          .isEqualTo(StepUpException.Code.ACTOR_LOCKED);
    }
  }

  private StepUpChallenge challenge(boolean allowSelfAuthorization) {
    return service.createChallenge(
        new StepUpChallengeRequest(
            "cashier",
            TENANT,
            "admit-api",
            "refund",
            allowSelfAuthorization,
            Set.of(StepUpMethod.PIN)));
  }

  private static final class InMemoryPinStore implements PinCredentialStore {
    private final Map<String, PinCredentialRecord> values = new HashMap<>();

    @Override
    public Optional<PinCredentialRecord> find(UUID tenantId, String actorId) {
      return Optional.ofNullable(values.get(key(tenantId, actorId)));
    }

    @Override
    public void save(UUID tenantId, String actorId, PinCredentialRecord credential) {
      values.put(key(tenantId, actorId), credential);
    }

    private String key(UUID tenantId, String actorId) {
      return tenantId + ":" + actorId;
    }
  }
}
