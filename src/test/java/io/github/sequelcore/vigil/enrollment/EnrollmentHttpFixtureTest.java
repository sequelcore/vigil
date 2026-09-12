package io.github.sequelcore.vigil.enrollment;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.Base64;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Test-only host surface: Vigil itself deliberately has no enrollment controller. */
@WebMvcTest(controllers = EnrollmentHttpFixtureTest.HostEnrollmentController.class)
@AutoConfigureMockMvc(addFilters = false)
@Import({
  EnrollmentHttpFixtureTest.FixtureConfiguration.class,
  EnrollmentHttpFixtureTest.HostEnrollmentController.class
})
class EnrollmentHttpFixtureTest {
  private static final String EMAIL = "Existing.User@example.test";
  private static final String CONTEXT = "host-context";
  private static final String VERSION = "1";

  @Autowired private MockMvc mockMvc;
  @Autowired private FixtureHost host;

  @BeforeEach
  void reset() {
    host.reset();
  }

  @Test
  void keepsStartAndResendResponsesGenericForExistingSuppressedAndDeliveryFailedRequests()
      throws Exception {
    String initial = start(CONTEXT);
    String existing = start(CONTEXT);
    host.deliveryOutcome = EnrollmentDeliveryPort.DeliveryOutcome.RETRYABLE_FAILURE;
    String deliveryFailed = resend("another-context");

    assertThat(existing).isEqualTo(initial);
    assertThat(deliveryFailed).isEqualTo(initial);
  }

  @Test
  void onlyExplicitPostVerificationConsumesAndCompletesAFreshHostPassword() throws Exception {
    start(CONTEXT);
    String proof = host.lastDelivery.proof();

    mockMvc
        .perform(get("/host/enrollment/verify").param("email", EMAIL).param("proof", proof))
        .andExpect(status().isOk());
    assertThat(host.applied).isEmpty();
    assertThat(host.completedPasswords).isEmpty();

    mockMvc
        .perform(
            post("/host/enrollment/verify")
                .param("email", EMAIL)
                .param("context", CONTEXT)
                .param("version", VERSION)
                .param("proof", proof)
                .param("newPassword", "fresh-host-password"))
        .andExpect(status().isAccepted());
    assertThat(host.applied).hasSize(1);
    assertThat(host.completedPasswords).containsExactly("fresh-host-password");
    assertThat(host.status).isEqualTo(EnrollmentStatus.COMPLETED);

    mockMvc
        .perform(
            post("/host/enrollment/verify")
                .param("email", EMAIL)
                .param("context", CONTEXT)
                .param("version", VERSION)
                .param("proof", proof)
                .param("newPassword", "replay-password"))
        .andExpect(status().isAccepted());
    assertThat(host.completedPasswords).containsExactly("fresh-host-password");
  }

  @Test
  void doesNotAutoLinkExistingAccounts() throws Exception {
    host.existingAccount = true;
    start(CONTEXT);
    mockMvc
        .perform(
            post("/host/enrollment/verify")
                .param("email", EMAIL)
                .param("context", CONTEXT)
                .param("version", VERSION)
                .param("proof", wrongProof())
                .param("newPassword", "attacker-chosen"))
        .andExpect(status().isAccepted());
    assertThat(host.applied).isEmpty();
    assertThat(host.completedPasswords).isEmpty();

    mockMvc
        .perform(
            post("/host/enrollment/verify")
                .param("email", EMAIL)
                .param("context", CONTEXT)
                .param("version", VERSION)
                .param("proof", host.lastDelivery.proof())
                .param("newPassword", "fresh-host-password"))
        .andExpect(status().isAccepted());
    assertThat(host.applied).isEmpty();
    assertThat(host.completedPasswords).isEmpty();
    assertThat(host.autoLinkCount).isZero();
    assertThat(host.status).isEqualTo(EnrollmentStatus.REJECTED);

    mockMvc
        .perform(
            post("/host/enrollment/verify")
                .param("email", EMAIL)
                .param("context", CONTEXT)
                .param("version", VERSION)
                .param("proof", host.lastDelivery.proof())
                .param("newPassword", "another-password"))
        .andExpect(status().isAccepted());
    assertThat(host.applied).isEmpty();
    assertThat(host.completedPasswords).isEmpty();
  }

  @Test
  void invalidatesPreProofCredentialAndSessionBeforeAllowingOneFreshPassword() throws Exception {
    host.stageUntrustedPreProofState();
    start(CONTEXT);

    mockMvc
        .perform(
            post("/host/enrollment/verify")
                .param("email", EMAIL)
                .param("context", CONTEXT)
                .param("version", VERSION)
                .param("proof", host.lastDelivery.proof())
                .param("newPassword", "fresh-host-password"))
        .andExpect(status().isAccepted());

    assertThat(host.preProofCredentialActive).isFalse();
    assertThat(host.preProofSessionActive).isFalse();
    assertThat(host.completedPasswords).containsExactly("fresh-host-password");
  }

  @Test
  void concurrentProofReplayCompletesOnlyOneReceiptBoundPassword() throws Exception {
    start(CONTEXT);
    String proof = host.lastDelivery.proof();
    ExecutorService executor = Executors.newFixedThreadPool(2);
    CountDownLatch ready = new CountDownLatch(2);
    CountDownLatch release = new CountDownLatch(1);

    try {
      Future<?> first =
          executor.submit(() -> verifyWhenReleased(ready, release, proof, "first-password"));
      Future<?> second =
          executor.submit(() -> verifyWhenReleased(ready, release, proof, "second-password"));
      assertThat(ready.await(5, TimeUnit.SECONDS)).isTrue();
      release.countDown();
      first.get(10, TimeUnit.SECONDS);
      second.get(10, TimeUnit.SECONDS);
    } finally {
      executor.shutdownNow();
    }

    assertThat(host.applied).hasSize(1);
    assertThat(host.completedCredentialReceipts).hasSize(1);
    assertThat(host.completedPasswords).hasSize(1);
    assertThat(host.completedPasswords.getFirst()).isIn("first-password", "second-password");
  }

  private Void verifyWhenReleased(
      CountDownLatch ready, CountDownLatch release, String proof, String password)
      throws Exception {
    ready.countDown();
    release.await();
    mockMvc
        .perform(
            post("/host/enrollment/verify")
                .param("email", EMAIL)
                .param("context", CONTEXT)
                .param("version", VERSION)
                .param("proof", proof)
                .param("newPassword", password))
        .andExpect(status().isAccepted());
    return null;
  }

  private String start(String context) throws Exception {
    return mockMvc
        .perform(
            post("/host/enrollment/start")
                .param("email", EMAIL)
                .param("context", context)
                .param("version", VERSION))
        .andExpect(status().isAccepted())
        .andReturn()
        .getResponse()
        .getContentAsString();
  }

  private String resend(String context) throws Exception {
    return mockMvc
        .perform(
            post("/host/enrollment/resend")
                .param("email", EMAIL)
                .param("context", context)
                .param("version", VERSION))
        .andExpect(status().isAccepted())
        .andReturn()
        .getResponse()
        .getContentAsString();
  }

  private static String wrongProof() {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]);
  }

  @TestConfiguration
  static class FixtureConfiguration {
    @Bean
    FixtureHost fixtureHost() {
      return new FixtureHost();
    }

    @Bean
    EnrollmentService enrollmentService(FixtureHost host) {
      EnrollmentProperties properties =
          new EnrollmentProperties(true, "host-enrollment", null, null, 3, 2, null);
      return new EnrollmentService(properties, host, host, host, host, host);
    }
  }

  @RestController
  static class HostEnrollmentController {
    private final EnrollmentService enrollmentService;
    private final FixtureHost host;

    HostEnrollmentController(EnrollmentService enrollmentService, FixtureHost host) {
      this.enrollmentService = enrollmentService;
      this.host = host;
    }

    @PostMapping("/host/enrollment/start")
    ResponseEntity<Map<String, String>> start(
        @RequestParam String email, @RequestParam String context, @RequestParam String version) {
      enrollmentService.start(new EnrollmentStartRequest(email, context, version));
      return accepted();
    }

    @PostMapping("/host/enrollment/resend")
    ResponseEntity<Map<String, String>> resend(
        @RequestParam String email, @RequestParam String context, @RequestParam String version) {
      enrollmentService.resend(new EnrollmentStartRequest(email, context, version));
      return accepted();
    }

    @GetMapping("/host/enrollment/verify")
    ResponseEntity<Map<String, String>> viewVerification() {
      return ResponseEntity.ok(Map.of("status", "verify"));
    }

    @PostMapping("/host/enrollment/verify")
    ResponseEntity<Map<String, String>> verify(
        @RequestParam String email,
        @RequestParam String context,
        @RequestParam String version,
        @RequestParam String proof,
        @RequestParam String newPassword) {
      EnrollmentVerificationResult result =
          enrollmentService.verify(
              new EnrollmentVerificationRequest(email, context, version, proof));
      if (result == EnrollmentVerificationResult.COMPLETED) {
        host.completeFreshPassword(newPassword);
      }
      return accepted();
    }

    private static ResponseEntity<Map<String, String>> accepted() {
      return ResponseEntity.accepted().body(Map.of("status", "accepted"));
    }
  }

  static final class FixtureHost
      implements EmailCanonicalizer,
          EnrollmentIdentityPort,
          EnrollmentDeliveryPort,
          EnrollmentAbuseControl,
          EnrollmentStore {
    private EnrollmentDelivery lastDelivery;
    private EnrollmentDeliveryPort.DeliveryOutcome deliveryOutcome;
    private EnrollmentVerificationReceipt receipt;
    private String digest;
    private String contextId;
    private EnrollmentStatus status;
    private UUID lifecycleId;
    private java.util.List<EnrollmentVerificationReceipt> applied = new java.util.ArrayList<>();
    private java.util.List<String> completedPasswords = new java.util.ArrayList<>();
    private Set<UUID> completedCredentialReceipts = new HashSet<>();
    private boolean existingAccount;
    private int autoLinkCount;
    private boolean preProofCredentialActive;
    private boolean preProofSessionActive;

    void reset() {
      lastDelivery = null;
      deliveryOutcome = EnrollmentDeliveryPort.DeliveryOutcome.ACCEPTED;
      receipt = null;
      digest = null;
      contextId = null;
      status = null;
      lifecycleId = null;
      applied = new java.util.ArrayList<>();
      completedPasswords = new java.util.ArrayList<>();
      completedCredentialReceipts = new HashSet<>();
      existingAccount = false;
      autoLinkCount = 0;
      preProofCredentialActive = false;
      preProofSessionActive = false;
    }

    @Override
    public String canonicalize(String email) {
      return email.trim().toLowerCase(java.util.Locale.ROOT);
    }

    @Override
    public synchronized EnrollmentIdentityPort.ApplyOutcome applyVerifiedContact(
        EnrollmentVerificationReceipt value) {
      if (existingAccount) {
        return EnrollmentIdentityPort.ApplyOutcome.REJECTED;
      }
      if (applied.stream().noneMatch(item -> item.receiptId().equals(value.receiptId()))) {
        applied.add(value);
        preProofCredentialActive = false;
        preProofSessionActive = false;
      }
      return EnrollmentIdentityPort.ApplyOutcome.APPLIED;
    }

    @Override
    public DeliveryOutcome deliver(EnrollmentDelivery delivery) {
      lastDelivery = delivery;
      return deliveryOutcome;
    }

    @Override
    public boolean admit(EnrollmentAdmission admission) {
      return true;
    }

    @Override
    public EnrollmentStartOutcome start(EnrollmentStartCommand command) {
      if (status == EnrollmentStatus.PENDING && command.contextId().equals(contextId)) {
        return EnrollmentStartOutcome.notCreated();
      }
      lifecycleId = UUID.randomUUID();
      contextId = command.contextId();
      digest = command.proofDigest();
      status = EnrollmentStatus.PENDING;
      return new EnrollmentStartOutcome(true, lifecycleId, 1, command.proofExpiresAt());
    }

    @Override
    public EnrollmentStartOutcome resend(EnrollmentStartCommand command) {
      return start(command);
    }

    @Override
    public synchronized EnrollmentVerificationOutcome createVerificationReceipt(
        EnrollmentVerificationCommand command) {
      if (digest == null || !digest.equals(command.proofDigest())) {
        return EnrollmentVerificationOutcome.rejected();
      }
      if (status == EnrollmentStatus.COMPLETED) {
        return new EnrollmentVerificationOutcome(
            EnrollmentVerificationOutcome.Kind.COMPLETED, null);
      }
      if (status == EnrollmentStatus.VERIFIED_PENDING_APPLY) {
        return new EnrollmentVerificationOutcome(
            EnrollmentVerificationOutcome.Kind.EXISTING_RECEIPT, receipt);
      }
      if (status != EnrollmentStatus.PENDING) {
        return EnrollmentVerificationOutcome.rejected();
      }
      receipt =
          new EnrollmentVerificationReceipt(
              UUID.randomUUID(),
              command.canonicalEmail(),
              command.contextId(),
              command.contextVersion(),
              command.audience(),
              command.purpose(),
              lifecycleId,
              1,
              Instant.now());
      status = EnrollmentStatus.VERIFIED_PENDING_APPLY;
      return new EnrollmentVerificationOutcome(
          EnrollmentVerificationOutcome.Kind.CREATED_RECEIPT, receipt);
    }

    @Override
    public EnrollmentVerificationReceipt recoverVerificationReceipt(
        EnrollmentRecoveryCommand command) {
      return status == EnrollmentStatus.VERIFIED_PENDING_APPLY ? receipt : null;
    }

    @Override
    public void recordDeliveryOutcome(EnrollmentDeliveryOutcomeCommand command) {}

    @Override
    public synchronized void acknowledgeCompletion(EnrollmentVerificationReceipt value) {
      if (receipt != null && receipt.receiptId().equals(value.receiptId())) {
        status = EnrollmentStatus.COMPLETED;
      }
    }

    @Override
    public synchronized void rejectCompletion(EnrollmentVerificationReceipt value) {
      if (receipt != null && receipt.receiptId().equals(value.receiptId())) {
        status = EnrollmentStatus.REJECTED;
      }
    }

    synchronized void completeFreshPassword(String password) {
      if (status == EnrollmentStatus.COMPLETED
          && receipt != null
          && completedCredentialReceipts.add(receipt.receiptId())) {
        completedPasswords.add(password);
      }
    }

    void stageUntrustedPreProofState() {
      preProofCredentialActive = true;
      preProofSessionActive = true;
    }
  }
}
