package io.github.sequelcore.vigil.enrollment;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/** Opt-in auto-configuration for the route-free enrollment lifecycle. */
@AutoConfiguration
@ConditionalOnProperty(prefix = "vigil.enrollment", name = "enabled", havingValue = "true")
@EnableConfigurationProperties(EnrollmentProperties.class)
public class EnrollmentAutoConfiguration {

  /** Forces all enabled application-owned ports to resolve even when the service is overridden. */
  @Bean
  EnrollmentRequiredPorts enrollmentRequiredPorts(
      EnrollmentProperties properties,
      EmailCanonicalizer canonicalizer,
      EnrollmentIdentityPort identityPort,
      EnrollmentDeliveryPort deliveryPort,
      EnrollmentAbuseControl abuseControl,
      EnrollmentStore store) {
    properties.validatedForEnabledUse();
    return new EnrollmentRequiredPorts(
        canonicalizer, identityPort, deliveryPort, abuseControl, store);
  }

  /**
   * Creates enrollment orchestration only when every application-owned boundary is supplied.
   * Missing ports intentionally fail startup instead of silently weakening enrollment.
   */
  @Bean
  @ConditionalOnMissingBean
  public EnrollmentService enrollmentService(
      EnrollmentProperties properties, EnrollmentRequiredPorts requiredPorts) {
    return new EnrollmentService(
        properties,
        requiredPorts.canonicalizer(),
        requiredPorts.identityPort(),
        requiredPorts.deliveryPort(),
        requiredPorts.abuseControl(),
        requiredPorts.store());
  }
}
