package io.github.sequelcore.vigil.core.password;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.sequelcore.vigil.autoconfigure.VigilProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class VigilPasswordServiceTest {

  private VigilPasswordService passwordService;

  @BeforeEach
  void setUp() {
    passwordService = new VigilPasswordService(new VigilProperties.Password(10));
  }

  @Nested
  @DisplayName("Password hashing")
  class Hashing {

    @Test
    @DisplayName("Hash returns BCrypt hash different from raw password")
    void hashReturnsBcrypt() {
      String hash = passwordService.hash("P@ssw0rd!");

      assertThat(hash).startsWith("$2").isNotEqualTo("P@ssw0rd!");
    }

    @Test
    @DisplayName("Hash throws on null password")
    void hashRejectsNull() {
      assertThatThrownBy(() -> passwordService.hash(null))
          .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Hash throws on empty password")
    void hashRejectsEmpty() {
      assertThatThrownBy(() -> passwordService.hash(""))
          .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Matches returns true for correct password")
    void matchesTrue() {
      String hash = passwordService.hash("MyPassw0rd!");

      assertThat(passwordService.matches("MyPassw0rd!", hash)).isTrue();
    }

    @Test
    @DisplayName("Matches returns false for wrong password")
    void matchesFalse() {
      String hash = passwordService.hash("MyPassw0rd!");

      assertThat(passwordService.matches("wrongPass1!", hash)).isFalse();
    }

    @Test
    @DisplayName("Matches returns false for null inputs")
    void matchesRejectsNull() {
      assertThat(passwordService.matches(null, "hash")).isFalse();
      assertThat(passwordService.matches("password", null)).isFalse();
    }
  }

  @Nested
  @DisplayName("Rehash detection")
  class RehashDetection {

    @Test
    @DisplayName("NeedsRehash returns false for current strength")
    void currentStrengthNoRehash() {
      String hash = passwordService.hash("Test1@Pass");

      assertThat(passwordService.needsRehash(hash)).isFalse();
    }

    @Test
    @DisplayName("NeedsRehash returns true for weaker hash")
    void weakerHashNeedsRehash() {
      // Create a hash with strength 4 (weaker than our configured 10)
      var weakService = new VigilPasswordService(new VigilProperties.Password(4));
      String weakHash = weakService.hash("Test1@Pass");

      assertThat(passwordService.needsRehash(weakHash)).isTrue();
    }

    @Test
    @DisplayName("NeedsRehash returns true for null hash")
    void nullHashNeedsRehash() {
      assertThat(passwordService.needsRehash(null)).isTrue();
    }

    @Test
    @DisplayName("NeedsRehash returns true for invalid hash")
    void invalidHashNeedsRehash() {
      assertThat(passwordService.needsRehash("not-a-bcrypt-hash")).isTrue();
    }
  }

  @Nested
  @DisplayName("Password strength evaluation")
  class StrengthEvaluation {

    @Test
    @DisplayName("Empty password returns score 0")
    void emptyPassword() {
      var result = passwordService.strength("");

      assertThat(result.score()).isZero();
      assertThat(result.isAcceptable()).isFalse();
    }

    @Test
    @DisplayName("Common password returns score 0")
    void commonPassword() {
      var result = passwordService.strength("password123");

      assertThat(result.score()).isZero();
      assertThat(result.feedback()).contains("This password is too common");
    }

    @Test
    @DisplayName("Short password gets feedback")
    void shortPassword() {
      var result = passwordService.strength("A1!");

      assertThat(result.score()).isLessThan(PasswordStrength.MINIMUM_ACCEPTABLE);
      assertThat(result.feedback()).anyMatch(f -> f.contains("8 characters"));
    }

    @Test
    @DisplayName("Strong password returns high score")
    void strongPassword() {
      var result = passwordService.strength("MyStr0ng@P4ssword!");

      assertThat(result.score()).isGreaterThanOrEqualTo(3);
      assertThat(result.isAcceptable()).isTrue();
    }

    @Test
    @DisplayName("Password with repeating characters gets penalty")
    void repeatingChars() {
      var result = passwordService.strength("Passsword1!");

      assertThat(result.feedback()).anyMatch(f -> f.contains("repeating"));
    }

    @Test
    @DisplayName("Password with sequential characters gets penalty")
    void sequentialChars() {
      var result = passwordService.strength("Pass123abc!");

      assertThat(result.feedback()).anyMatch(f -> f.contains("sequential"));
    }
  }

  @Nested
  @DisplayName("Common password detection")
  class CommonPasswordDetection {

    @Test
    @DisplayName("Detects common password")
    void detectsCommonPassword() {
      assertThat(passwordService.isCommon("password")).isTrue();
      assertThat(passwordService.isCommon("123456")).isTrue();
      assertThat(passwordService.isCommon("qwerty")).isTrue();
    }

    @Test
    @DisplayName("Case insensitive detection")
    void caseInsensitive() {
      assertThat(passwordService.isCommon("PASSWORD")).isTrue();
      assertThat(passwordService.isCommon("Password")).isTrue();
    }

    @Test
    @DisplayName("Returns false for unique passwords")
    void uniquePassword() {
      assertThat(passwordService.isCommon("xK9#mP2$vL5@")).isFalse();
    }
  }

  @Nested
  @DisplayName("Encoder access")
  class EncoderAccess {

    @Test
    @DisplayName("Returns BCrypt encoder")
    void returnsBCryptEncoder() {
      var encoder = passwordService.encoder();

      assertThat(encoder).isNotNull();
      assertThat(encoder.encode("test")).startsWith("$2");
    }
  }
}
