package io.github.sequelcore.vigil.enrollment;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

class EnrollmentProofCodecTest {
  @Test
  void codeDigestIsDeterministicAndBoundToEveryEnrollmentAuthority() {
    EnrollmentProofCodec codec =
        new EnrollmentProofCodec(EnrollmentTestProperties.decimalCode("audience", 5));
    String digest =
        codec.digest(
            "12345678", "person@example.test", "context", "v1", "audience", "contact-enrollment");

    assertThat(digest).isEqualTo("RKRpOaqvca6-CiNOCjjSSWl9fR6ptT9jptglX15N26k");
    assertThat(
            codec.digest(
                "12345678",
                "person@example.test",
                "context",
                "v1",
                "audience",
                "contact-enrollment"))
        .isEqualTo(digest);
    assertThat(
            codec.digest(
                "12345678",
                "other@example.test",
                "context",
                "v1",
                "audience",
                "contact-enrollment"))
        .isNotEqualTo(digest);
    assertThat(
            codec.digest(
                "12345678", "person@example.test", "other", "v1", "audience", "contact-enrollment"))
        .isNotEqualTo(digest);
    assertThat(
            codec.digest(
                "12345678",
                "person@example.test",
                "context",
                "v2",
                "audience",
                "contact-enrollment"))
        .isNotEqualTo(digest);
    assertThat(
            codec.digest(
                "12345678", "person@example.test", "context", "v1", "other", "contact-enrollment"))
        .isNotEqualTo(digest);
    assertThat(
            codec.digest("12345678", "person@example.test", "context", "v1", "audience", "other"))
        .isNotEqualTo(digest);
  }

  @Test
  void preservesLeadingZeroesInTheEightDigitCode() {
    SecureRandom random =
        new SecureRandom() {
          @Override
          public int nextInt(int bound) {
            return 42;
          }
        };
    EnrollmentProofCodec codec =
        new EnrollmentProofCodec(EnrollmentTestProperties.decimalCode("audience", 5), random);

    assertThat(codec.generate()).isEqualTo("00000042");
  }

  @Test
  void rejectsNonCanonicalProofRepresentations() {
    EnrollmentProofCodec codec =
        new EnrollmentProofCodec(EnrollmentTestProperties.decimalCode("audience", 5));

    assertThat(codec.digest("1234567", "email", "context", "v1", "audience", "purpose")).isNull();
    assertThat(codec.digest("1234 5678", "email", "context", "v1", "audience", "purpose")).isNull();
    assertThat(codec.digest("１２３４５６７８", "email", "context", "v1", "audience", "purpose")).isNull();
  }

  @Test
  void rejectsAValidRepresentationOfTheUnconfiguredFormat() {
    EnrollmentProofCodec decimalCodec =
        new EnrollmentProofCodec(EnrollmentTestProperties.decimalCode("audience", 5));
    EnrollmentProofCodec opaqueCodec =
        new EnrollmentProofCodec(EnrollmentTestProperties.opaqueToken("audience", 5));
    String opaqueToken = opaqueCodec.generate();

    assertThat(decimalCodec.digest(opaqueToken, "email", "context", "v1", "audience", "purpose"))
        .isNull();
    assertThat(opaqueCodec.digest("12345678", "email", "context", "v1", "audience", "purpose"))
        .isNull();
  }

  @Test
  void enrollmentPropertiesNeverRenderTheHmacKey() {
    String key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    EnrollmentProperties properties =
        new EnrollmentProperties(
            true, "audience", EnrollmentProofFormat.DECIMAL_CODE, key, null, null, 5, 3, null);

    assertThat(properties.toString())
        .doesNotContain(key)
        .isEqualTo("EnrollmentProperties[redacted]");
  }
}
