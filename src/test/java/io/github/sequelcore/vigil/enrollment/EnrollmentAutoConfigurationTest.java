package io.github.sequelcore.vigil.enrollment;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class EnrollmentAutoConfigurationTest {
  private final ApplicationContextRunner contextRunner =
      new ApplicationContextRunner()
          .withConfiguration(AutoConfigurations.of(EnrollmentAutoConfiguration.class));

  @Test
  void isDisabledByDefaultAndRegistersNoEnrollmentBeans() {
    contextRunner.run(
        context -> {
          assertThat(context).doesNotHaveBean(EnrollmentService.class);
          assertThat(context).doesNotHaveBean(EnrollmentProperties.class);
        });
  }

  @Test
  void failsStartupWhenEnabledWithoutEveryApplicationOwnedPort() {
    contextRunner
        .withPropertyValues("vigil.enrollment.enabled=true", "vigil.enrollment.audience=app")
        .run(
            context -> {
              assertThat(context).hasFailed();
              assertThat(context.getStartupFailure())
                  .hasMessageContaining(EmailCanonicalizer.class.getName());
            });
  }

  @Test
  void stillRequiresPortsWhenTheApplicationOverridesEnrollmentService() {
    contextRunner
        .withPropertyValues("vigil.enrollment.enabled=true", "vigil.enrollment.audience=app")
        .withBean(EnrollmentService.class, () -> mock(EnrollmentService.class))
        .run(
            context -> {
              assertThat(context).hasFailed();
              assertThat(context.getStartupFailure())
                  .hasMessageContaining(EmailCanonicalizer.class.getName());
            });
  }

  @Test
  void validatesAudienceWhenTheApplicationOverridesEnrollmentService() {
    configuredPorts("vigil.enrollment.enabled=true")
        .withBean(EnrollmentService.class, () -> mock(EnrollmentService.class))
        .run(
            context -> {
              assertThat(context).hasFailed();
              assertThat(context.getStartupFailure()).hasMessageContaining("audience is required");
            });
  }

  @Test
  void registersTheServiceOnlyWithAllPortsAndTrustedAudience() {
    configuredPorts("vigil.enrollment.enabled=true", "vigil.enrollment.audience=app")
        .run(context -> assertThat(context).hasSingleBean(EnrollmentService.class));
  }

  @Test
  void rejectsEnabledEnrollmentWithoutATrustedAudience() {
    configuredPorts("vigil.enrollment.enabled=true")
        .run(
            context -> {
              assertThat(context).hasFailed();
              assertThat(context.getStartupFailure()).hasMessageContaining("audience is required");
            });
  }

  @Test
  void rejectsDecimalCodesWithoutAValidDedicatedHmacKey() {
    configuredPorts(
            "vigil.enrollment.enabled=true",
            "vigil.enrollment.audience=app",
            "vigil.enrollment.proof-format=decimal-code")
        .run(
            context -> {
              assertThat(context).hasFailed();
              assertThat(context.getStartupFailure()).hasMessageContaining("code-hmac-key");
            });
  }

  @Test
  void rejectsNonCanonicalOrWrongLengthDecimalCodeHmacKeys() {
    configuredPorts(
            "vigil.enrollment.enabled=true",
            "vigil.enrollment.audience=app",
            "vigil.enrollment.proof-format=decimal-code",
            "vigil.enrollment.code-hmac-key=short")
        .run(
            context -> {
              assertThat(context).hasFailed();
              assertThat(context.getStartupFailure())
                  .hasRootCauseMessage(
                      "vigil.enrollment.code-hmac-key must be canonical Base64URL for exactly 32 bytes when decimal codes are enabled");
            });
  }

  @Test
  void rejectsDecimalCodePolicyThatExpandsTheGuessingWindow() {
    configuredPorts(
            "vigil.enrollment.enabled=true",
            "vigil.enrollment.audience=app",
            "vigil.enrollment.proof-format=decimal-code",
            "vigil.enrollment.code-hmac-key=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            "vigil.enrollment.attempt-limit=6")
        .run(
            context -> {
              assertThat(context).hasFailed();
              assertThat(context.getStartupFailure())
                  .hasRootCauseMessage(
                      "vigil.enrollment.attempt-limit must be at most 5 for decimal codes");
            });
  }

  @Test
  void registersDecimalCodeModeWithItsBoundedPolicy() {
    configuredPorts(
            "vigil.enrollment.enabled=true",
            "vigil.enrollment.audience=app",
            "vigil.enrollment.proof-format=decimal-code",
            "vigil.enrollment.code-hmac-key=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
        .run(context -> assertThat(context).hasSingleBean(EnrollmentService.class));
  }

  @Test
  void rejectsDecimalCodeTtlLongerThanFifteenMinutes() {
    configuredPorts(
            "vigil.enrollment.enabled=true",
            "vigil.enrollment.audience=app",
            "vigil.enrollment.proof-format=decimal-code",
            "vigil.enrollment.code-hmac-key=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            "vigil.enrollment.proof-ttl=16m")
        .run(
            context -> {
              assertThat(context).hasFailed();
              assertThat(context.getStartupFailure())
                  .hasRootCauseMessage(
                      "vigil.enrollment.proof-ttl must be at most 15m for decimal codes");
            });
  }

  private ApplicationContextRunner configuredPorts(String... properties) {
    return contextRunner
        .withPropertyValues(properties)
        .withBean(EmailCanonicalizer.class, () -> value -> value)
        .withBean(
            EnrollmentIdentityPort.class, () -> EnrollmentAutoConfigurationTest::ignoreReceipt)
        .withBean(
            EnrollmentDeliveryPort.class,
            () -> delivery -> EnrollmentDeliveryPort.DeliveryOutcome.ACCEPTED)
        .withBean(EnrollmentAbuseControl.class, () -> admission -> true)
        .withBean(EnrollmentStore.class, NoopStore::new);
  }

  private static final class NoopStore implements EnrollmentStore {
    @Override
    public EnrollmentStartOutcome start(EnrollmentStartCommand command) {
      return EnrollmentStartOutcome.notCreated();
    }

    @Override
    public EnrollmentStartOutcome resend(EnrollmentStartCommand command) {
      return EnrollmentStartOutcome.notCreated();
    }

    @Override
    public EnrollmentVerificationOutcome createVerificationReceipt(
        EnrollmentVerificationCommand command) {
      return EnrollmentVerificationOutcome.rejected();
    }

    @Override
    public EnrollmentVerificationReceipt recoverVerificationReceipt(
        EnrollmentRecoveryCommand command) {
      return null;
    }

    @Override
    public void recordDeliveryOutcome(EnrollmentDeliveryOutcomeCommand command) {}

    @Override
    public void acknowledgeCompletion(EnrollmentVerificationReceipt receipt) {}

    @Override
    public void rejectCompletion(EnrollmentVerificationReceipt receipt) {}
  }

  private static EnrollmentIdentityPort.ApplyOutcome ignoreReceipt(
      EnrollmentVerificationReceipt receipt) {
    // The auto-configuration test needs a host port but does not exercise receipt application.
    return EnrollmentIdentityPort.ApplyOutcome.APPLIED;
  }
}
