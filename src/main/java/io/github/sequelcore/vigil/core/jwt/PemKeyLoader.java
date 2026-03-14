package io.github.sequelcore.vigil.core.jwt;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.springframework.core.io.ClassPathResource;

/**
 * Loads RSA keys from PEM-encoded sources.
 *
 * <p>Supports three source formats:
 *
 * <ul>
 *   <li>{@code file:/absolute/path/to/key.pem} — absolute file path
 *   <li>{@code classpath:key.pem} — classpath resource
 *   <li>Inline PEM string — {@code -----BEGIN ...-----\n...\n-----END ...-----}
 * </ul>
 */
public final class PemKeyLoader {

  private PemKeyLoader() {}

  /**
   * Loads an RSA private key from a PEM-encoded source.
   *
   * <p>The key must be PKCS#8 encoded ({@code -----BEGIN PRIVATE KEY-----}). To convert a
   * traditional PKCS#1 key: {@code openssl pkcs8 -topk8 -nocrypt -in private.pem -out
   * private_pkcs8.pem}
   *
   * @param source file path, classpath resource, or inline PEM string
   * @return the RSA private key
   * @throws IllegalArgumentException if the source cannot be parsed
   */
  public static RSAPrivateKey loadPrivateKey(String source) {
    try {
      byte[] der = decodePem(resolveContent(source));
      KeyFactory kf = KeyFactory.getInstance("RSA");
      return (RSAPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(der));
    } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
      throw new IllegalArgumentException("Failed to load RSA private key: " + e.getMessage(), e);
    }
  }

  /**
   * Loads an RSA public key from a PEM-encoded source.
   *
   * <p>The key must be X.509/SubjectPublicKeyInfo encoded ({@code -----BEGIN PUBLIC KEY-----}).
   *
   * @param source file path, classpath resource, or inline PEM string
   * @return the RSA public key
   * @throws IllegalArgumentException if the source cannot be parsed
   */
  public static RSAPublicKey loadPublicKey(String source) {
    try {
      byte[] der = decodePem(resolveContent(source));
      KeyFactory kf = KeyFactory.getInstance("RSA");
      return (RSAPublicKey) kf.generatePublic(new X509EncodedKeySpec(der));
    } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
      throw new IllegalArgumentException("Failed to load RSA public key: " + e.getMessage(), e);
    }
  }

  private static String resolveContent(String source) throws IOException {
    if (source == null || source.isBlank()) {
      throw new IllegalArgumentException("PEM source must not be blank");
    }
    if (source.startsWith("file:")) {
      Path path = Path.of(source.substring(5));
      return Files.readString(path, StandardCharsets.UTF_8);
    }
    if (source.startsWith("classpath:")) {
      String resource = source.substring(10);
      try (InputStream is = new ClassPathResource(resource).getInputStream()) {
        return new String(is.readAllBytes(), StandardCharsets.UTF_8);
      }
    }
    // Treat as inline PEM content
    return source;
  }

  private static byte[] decodePem(String pem) {
    // Normalize escaped newlines that arrive from env vars (literal \n → real newline)
    String normalized = pem.replace("\\n", "\n");
    String stripped =
        normalized
            .replaceAll("-----BEGIN [^-]+-----", "")
            .replaceAll("-----END [^-]+-----", "")
            .replaceAll("\\s+", "");
    return Base64.getDecoder().decode(stripped);
  }
}
