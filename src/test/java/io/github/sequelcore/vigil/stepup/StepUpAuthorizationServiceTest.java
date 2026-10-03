package io.github.sequelcore.vigil.stepup;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import io.github.sequelcore.vigil.login.CaffeineLoginAttemptStore;
import io.github.sequelcore.vigil.login.LoginAccount;
import io.github.sequelcore.vigil.login.LoginAttemptStore;
import io.github.sequelcore.vigil.login.LoginPolicy;
import io.github.sequelcore.vigil.login.PasswordLoginGuard;
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
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

class StepUpAuthorizationServiceTest {
  private static final UUID TENANT = UUID.randomUUID();
  private StepUpAuthorizationService service;
  private static final LoginPolicy POLICY =
      new LoginPolicy(3, Duration.ofMinutes(1), Duration.ofMinutes(4), Duration.ofMinutes(10), 100);

  private LoginAttemptStore attempts;
  private VigilPinService pins;
  private InMemoryPinStore pinStore;

  @BeforeEach
  void setUp() {
    VigilProperties.StepUp config =
        new VigilProperties.StepUp(Duration.ofMinutes(2), Duration.ofMinutes(5), 100, null);
    attempts = new CaffeineLoginAttemptStore(POLICY);
    pins = new VigilPinService(config.pin());
    pinStore = new InMemoryPinStore();
    service =
        new StepUpAuthorizationService(
            config,
            new CaffeineStepUpStore(100, Duration.ofMinutes(10)),
            attempts,
            POLICY,
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

  @Test
  void recordsTheLockAfterSlowVerificationNotAtRequestStart() {
    AdvancingClock clock = new AdvancingClock();
    StepUpCredentialVerifier slowReject =
        new StepUpCredentialVerifier() {
          @Override
          public StepUpMethod method() {
            return StepUpMethod.PIN;
          }

          @Override
          public boolean verify(UUID tenantId, String actorId, StepUpCredential credential) {
            clock.advance(Duration.ofMinutes(2));
            return false;
          }
        };
    StepUpAuthorizationService slow =
        new StepUpAuthorizationService(
            new VigilProperties.StepUp(Duration.ofHours(1), Duration.ofHours(1), 100, null),
            new CaffeineStepUpStore(100, Duration.ofHours(3)),
            new CaffeineLoginAttemptStore(POLICY),
            POLICY,
            java.util.List.of(slowReject),
            clock);
    for (int attempt = 0; attempt < 3; attempt++) {
      StepUpChallenge challenge = challenge(slow);
      try (PinCredential pin = new PinCredential("000000".toCharArray())) {
        assertThatThrownBy(() -> slow.authorize(challenge.id(), "supervisor", pin))
            .isInstanceOf(StepUpException.class);
      }
    }
    StepUpChallenge challenge = challenge(slow);
    try (PinCredential pin = new PinCredential("000000".toCharArray())) {
      assertThatThrownBy(() -> slow.authorize(challenge.id(), "supervisor", pin))
          .extracting(exception -> ((StepUpException) exception).getCode())
          .isEqualTo(StepUpException.Code.ACTOR_LOCKED);
    }
  }

  private static final class AdvancingClock extends java.time.Clock {
    private java.time.Instant now = java.time.Instant.parse("2026-01-01T00:00:00Z");

    void advance(Duration duration) {
      now = now.plus(duration);
    }

    @Override
    public java.time.ZoneId getZone() {
      return java.time.ZoneOffset.UTC;
    }

    @Override
    public java.time.Clock withZone(java.time.ZoneId zone) {
      return this;
    }

    @Override
    public java.time.Instant instant() {
      return now;
    }
  }

  private StepUpChallenge challenge(StepUpAuthorizationService target) {
    return target.createChallenge(
        new StepUpChallengeRequest(
            "cashier", TENANT, "admit-api", "refund", false, Set.of(StepUpMethod.PIN)));
  }

  @Test
  void aPinLockAndAPasswordLockDoNotAffectEachOther() {
    PasswordLoginGuard guard =
        new PasswordLoginGuard(new BCryptPasswordEncoder(4), attempts, POLICY);
    for (int attempt = 0; attempt < 3; attempt++) {
      StepUpChallenge challenge = challenge(false);
      try (PinCredential pin = new PinCredential("000000".toCharArray())) {
        assertThatThrownBy(() -> service.authorize(challenge.id(), "supervisor", pin))
            .isInstanceOf(StepUpException.class);
      }
    }
    // The PIN is locked; the password for the same identifier is not.
    String hash = new BCryptPasswordEncoder(4).encode("pw");
    assertThat(
            guard
                .authenticate(
                    "supervisor", "pw", id -> Optional.of(new LoginAccount("s", hash, true)))
                .authenticated())
        .isTrue();

    // Lock the password, then confirm the PIN still verifies for another actor's namespace.
    for (int attempt = 0; attempt < 3; attempt++) {
      guard.authenticate("cashier", "bad", id -> Optional.empty());
    }
    try (PinCredential enrolled = new PinCredential("482915".toCharArray())) {
      pins.enroll(pinStore, TENANT, "cashier", enrolled);
    }
    StepUpChallenge challenge = challenge(true);
    try (PinCredential pin = new PinCredential("482915".toCharArray())) {
      assertThat(service.authorize(challenge.id(), "cashier", pin)).isNotNull();
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
