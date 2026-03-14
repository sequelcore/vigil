package io.github.sequelcore.vigil.core.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PemKeyLoaderTest {

  @TempDir static File tempDir;

  private static String privatePem;
  private static String publicPem;
  private static RSAPrivateKey originalPrivateKey;
  private static RSAPublicKey originalPublicKey;

  @BeforeAll
  static void generatePemStrings() throws Exception {
    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
    gen.initialize(2048);
    KeyPair pair = gen.generateKeyPair();

    originalPrivateKey = (RSAPrivateKey) pair.getPrivate();
    originalPublicKey = (RSAPublicKey) pair.getPublic();

    String encodedPrivate = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(originalPrivateKey.getEncoded());
    privatePem = "-----BEGIN PRIVATE KEY-----\n" + encodedPrivate + "\n-----END PRIVATE KEY-----";

    String encodedPublic = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(originalPublicKey.getEncoded());
    publicPem = "-----BEGIN PUBLIC KEY-----\n" + encodedPublic + "\n-----END PUBLIC KEY-----";
  }

  @Test
  @DisplayName("loadPrivateKey() loads from inline PEM string")
  void loadsPrivateKeyFromInlinePem() {
    RSAPrivateKey key = PemKeyLoader.loadPrivateKey(privatePem);

    assertThat(key).isNotNull();
    assertThat(key.getEncoded()).isEqualTo(originalPrivateKey.getEncoded());
  }

  @Test
  @DisplayName("loadPublicKey() loads from inline PEM string")
  void loadsPublicKeyFromInlinePem() {
    RSAPublicKey key = PemKeyLoader.loadPublicKey(publicPem);

    assertThat(key).isNotNull();
    assertThat(key.getEncoded()).isEqualTo(originalPublicKey.getEncoded());
  }

  @Test
  @DisplayName("loadPrivateKey() loads from file: path")
  void loadsPrivateKeyFromFilePath() throws Exception {
    File keyFile = new File(tempDir, "private.pem");
    try (FileWriter writer = new FileWriter(keyFile)) {
      writer.write(privatePem);
    }

    RSAPrivateKey key = PemKeyLoader.loadPrivateKey("file:" + keyFile.getAbsolutePath());

    assertThat(key).isNotNull();
    assertThat(key.getEncoded()).isEqualTo(originalPrivateKey.getEncoded());
  }

  @Test
  @DisplayName("loadPublicKey() loads from file: path")
  void loadsPublicKeyFromFilePath() throws Exception {
    File keyFile = new File(tempDir, "public.pem");
    try (FileWriter writer = new FileWriter(keyFile)) {
      writer.write(publicPem);
    }

    RSAPublicKey key = PemKeyLoader.loadPublicKey("file:" + keyFile.getAbsolutePath());

    assertThat(key).isNotNull();
    assertThat(key.getEncoded()).isEqualTo(originalPublicKey.getEncoded());
  }

  @Test
  @DisplayName("loadPrivateKey() throws on invalid PEM")
  void throwsOnInvalidPrivatePem() {
    assertThatThrownBy(() -> PemKeyLoader.loadPrivateKey("not-a-pem-at-all"))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  @DisplayName("loadPublicKey() throws on invalid PEM")
  void throwsOnInvalidPublicPem() {
    assertThatThrownBy(() -> PemKeyLoader.loadPublicKey("-----BEGIN PUBLIC KEY-----\nbaddata\n-----END PUBLIC KEY-----"))
        .isInstanceOf(Exception.class);
  }

  @Test
  @DisplayName("loadPrivateKey() throws on non-existent file: path")
  void throwsOnMissingFile() {
    assertThatThrownBy(() -> PemKeyLoader.loadPrivateKey("file:/nonexistent/path/key.pem"))
        .isInstanceOf(Exception.class);
  }
}
