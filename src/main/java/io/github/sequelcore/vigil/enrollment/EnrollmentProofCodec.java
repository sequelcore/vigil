package io.github.sequelcore.vigil.enrollment;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Locale;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Internal owner of enrollment proof generation, canonical validation, and digesting. */
final class EnrollmentProofCodec {
  private static final byte[] TOKEN_DIGEST_DOMAIN =
      "vigil.enrollment.proof.v1\u0000".getBytes(StandardCharsets.UTF_8);
  private static final byte[] CODE_DIGEST_DOMAIN =
      "vigil.enrollment.proof.decimal-code.v1\u0000".getBytes(StandardCharsets.UTF_8);
  private static final int OPAQUE_PROOF_BYTES = 32;
  private static final int OPAQUE_PROOF_LENGTH = 43;
  private static final int DECIMAL_CODE_LENGTH = 8;
  private static final int DECIMAL_CODE_BOUND = 100_000_000;

  private final EnrollmentProofFormat format;
  private final SecureRandom random;
  private final SecretKeySpec codeHmacKey;

  EnrollmentProofCodec(EnrollmentProperties properties) {
    this(properties, new SecureRandom());
  }

  EnrollmentProofCodec(EnrollmentProperties properties, SecureRandom random) {
    this.format = properties.proofFormat();
    this.random = random;
    byte[] key = properties.decodedCodeHmacKey();
    this.codeHmacKey = key == null ? null : new SecretKeySpec(key, "HmacSHA256");
  }

  String generate() {
    return switch (format) {
      case OPAQUE_TOKEN -> randomOpaqueToken();
      case DECIMAL_CODE -> String.format(Locale.ROOT, "%08d", random.nextInt(DECIMAL_CODE_BOUND));
    };
  }

  String digest(
      String proof,
      String canonicalEmail,
      String contextId,
      String contextVersion,
      String audience,
      String purpose) {
    return switch (format) {
      case OPAQUE_TOKEN -> isOpaqueToken(proof) ? tokenDigest(proof) : null;
      case DECIMAL_CODE ->
          isDecimalCode(proof)
              ? codeDigest(proof, canonicalEmail, contextId, contextVersion, audience, purpose)
              : null;
    };
  }

  private String randomOpaqueToken() {
    byte[] bytes = new byte[OPAQUE_PROOF_BYTES];
    random.nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  private String codeDigest(
      String proof,
      String canonicalEmail,
      String contextId,
      String contextVersion,
      String audience,
      String purpose) {
    if (codeHmacKey == null) {
      return null;
    }
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(codeHmacKey);
      mac.update(CODE_DIGEST_DOMAIN);
      update(mac, EnrollmentProofFormat.DECIMAL_CODE.name());
      update(mac, canonicalEmail);
      update(mac, contextId);
      update(mac, contextVersion);
      update(mac, audience);
      update(mac, purpose);
      update(mac, proof);
      return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal());
    } catch (GeneralSecurityException exception) {
      throw new IllegalStateException("Required enrollment proof MAC unavailable", exception);
    }
  }

  private static String tokenDigest(String proof) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      digest.update(TOKEN_DIGEST_DOMAIN);
      digest.update(proof.getBytes(StandardCharsets.UTF_8));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(digest.digest());
    } catch (GeneralSecurityException exception) {
      throw new IllegalStateException("Required enrollment proof digest unavailable", exception);
    }
  }

  private static boolean isDecimalCode(String proof) {
    if (proof == null || proof.length() != DECIMAL_CODE_LENGTH) {
      return false;
    }
    for (int index = 0; index < proof.length(); index++) {
      char character = proof.charAt(index);
      if (character < '0' || character > '9') {
        return false;
      }
    }
    return true;
  }

  private static boolean isOpaqueToken(String proof) {
    if (proof == null || proof.length() != OPAQUE_PROOF_LENGTH) {
      return false;
    }
    try {
      byte[] bytes = Base64.getUrlDecoder().decode(proof);
      return bytes.length == OPAQUE_PROOF_BYTES
          && Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(proof);
    } catch (IllegalArgumentException exception) {
      return false;
    }
  }

  private static void update(Mac mac, String value) {
    byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
    mac.update(ByteBuffer.allocate(Integer.BYTES).putInt(bytes.length).array());
    mac.update(bytes);
  }
}
