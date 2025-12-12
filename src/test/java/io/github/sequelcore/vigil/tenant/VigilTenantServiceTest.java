package io.github.sequelcore.vigil.tenant;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class VigilTenantServiceTest {

  private VigilTenantService tenantService;

  @Mock private HttpServletRequest request;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
    tenantService = new VigilTenantService(new VigilProperties.Tenant(true, "X-Tenant-ID"));
  }

  @AfterEach
  void tearDown() {
    VigilTenantContext.clear();
  }

  @Test
  @DisplayName("Extract tenant ID from header")
  void extractTenantId() {
    UUID tenantId = UUID.randomUUID();
    org.mockito.Mockito.when(request.getHeader("X-Tenant-ID")).thenReturn(tenantId.toString());

    Optional<UUID> result = tenantService.extractTenantId(request);

    assertThat(result).contains(tenantId);
  }

  @Test
  @DisplayName("Handle invalid UUID gracefully")
  void handleInvalidUuid() {
    org.mockito.Mockito.when(request.getHeader("X-Tenant-ID")).thenReturn("not-a-uuid");

    assertThat(tenantService.extractTenantId(request)).isEmpty();
  }

  @Test
  @DisplayName("Set, get, and clear tenant context")
  void setGetClearTenantContext() {
    UUID tenantId = UUID.randomUUID();

    tenantService.setCurrentTenant(tenantId);

    assertThat(tenantService.getCurrentTenant()).contains(tenantId);

    tenantService.clearCurrentTenant();

    assertThat(tenantService.getCurrentTenant()).isEmpty();
  }

  @Test
  @DisplayName("Validate tenant consistency")
  void validateTenantConsistency() {
    UUID tenantId = UUID.randomUUID();
    UUID otherTenant = UUID.randomUUID();
    tenantService.setCurrentTenant(tenantId);

    assertThat(tenantService.validateTenantConsistency(tenantId)).isTrue();
    assertThat(tenantService.validateTenantConsistency(otherTenant)).isFalse();
  }
}
