package io.github.sequelcore.vigil.core.jwt;

import static org.assertj.core.api.Assertions.assertThat;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class VigilTokenClaimsTest {

  @Test
  @DisplayName("Expose common claims with type safety")
  void exposesCommonClaims() {
    Instant iat = Instant.ofEpochMilli(1_000_000L);
    Instant exp = Instant.ofEpochMilli(2_000_000L);
    Claims claims =
        Jwts.claims()
            .subject("user123")
            .issuer("issuer-1")
            .audience()
            .add("web")
            .add("mobile")
            .and()
            .add("custom", "value")
            .issuedAt(java.util.Date.from(iat))
            .expiration(java.util.Date.from(exp))
            .build();

    VigilTokenClaims tokenClaims = new VigilTokenClaims(claims);

    assertThat(tokenClaims.getSubject()).isEqualTo("user123");
    assertThat(tokenClaims.getIssuer()).contains("issuer-1");
    assertThat(tokenClaims.getAudience()).containsExactly("web", "mobile");
    assertThat(tokenClaims.getIssuedAt()).isEqualTo(iat);
    assertThat(tokenClaims.getExpiration()).isEqualTo(exp);
    assertThat(tokenClaims.get("custom")).contains("value");
    assertThat(tokenClaims.getAllClaims())
        .containsEntry("custom", "value")
        .containsEntry("sub", "user123");
  }

  @Nested
  @DisplayName("String and UUID claim helpers")
  class StringAndUuidHelpers {

    @Test
    @DisplayName("Return Optional.empty for missing values")
    void emptyWhenMissing() {
      VigilTokenClaims tokenClaims = new VigilTokenClaims(Jwts.claims().build());

      assertThat(tokenClaims.getString("missing")).isEmpty();
      assertThat(tokenClaims.getUuid("missing")).isEmpty();
    }

    @Test
    @DisplayName("Parse UUID and ignore invalid formats")
    void parseUuid() {
      UUID id = UUID.randomUUID();
      Claims claims =
          Jwts.claims().add("tenantId", id.toString()).add("badUuid", "not-a-uuid").build();

      VigilTokenClaims tokenClaims = new VigilTokenClaims(claims);

      assertThat(tokenClaims.getUuid("tenantId")).contains(id);
      assertThat(tokenClaims.getUuid("badUuid")).isEmpty();
    }
  }

  @Nested
  @DisplayName("Long and list helpers")
  class LongAndListHelpers {

    @Test
    @DisplayName("Handle Long and Integer values")
    void getLongHandlesInteger() {
      Claims claims = Jwts.claims().add("longValue", 42L).add("intValue", 7).build();

      VigilTokenClaims tokenClaims = new VigilTokenClaims(claims);

      assertThat(tokenClaims.getLong("longValue")).contains(42L);
      assertThat(tokenClaims.getLong("intValue")).contains(7L);
      assertThat(tokenClaims.getLong("missing")).isEmpty();
    }

    @Test
    @DisplayName("Extract string list safely")
    void getStringListFiltersNonStrings() {
      java.util.List<Object> roles = new java.util.ArrayList<>();
      roles.add("ADMIN");
      roles.add(123);
      roles.add("USER");
      Claims claims = Jwts.claims().add("roles", roles).build();

      VigilTokenClaims tokenClaims = new VigilTokenClaims(claims);

      assertThat(tokenClaims.getStringList("roles")).containsExactly("ADMIN", "USER");
      assertThat(tokenClaims.getStringList("other")).isEmpty();
    }
  }

  @Nested
  @DisplayName("Token state helpers")
  class TokenStateHelpers {

    @Test
    @DisplayName("isExpired respects expiration time")
    void isExpired() {
      Claims claims =
          Jwts.claims().expiration(java.util.Date.from(Instant.now().minusSeconds(30))).build();

      VigilTokenClaims tokenClaims = new VigilTokenClaims(claims);

      assertThat(tokenClaims.isExpired()).isTrue();
    }

    @Test
    @DisplayName("isRefreshToken checks type claim")
    void isRefreshToken() {
      Claims claims = Jwts.claims().add("type", "refresh").build();

      VigilTokenClaims tokenClaims = new VigilTokenClaims(claims);

      assertThat(tokenClaims.isRefreshToken()).isTrue();
    }
  }
}
