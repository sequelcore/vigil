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
