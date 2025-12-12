package io.github.sequelcore.vigil.core.password;

import static org.assertj.core.api.Assertions.assertThat;

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

  @Test
  @DisplayName("Hash returns BCrypt hash different from raw password")
  void hashReturnsBcrypt() {
    String hash = passwordService.hash("P@ssw0rd!");

    assertThat(hash).startsWith("$2").isNotEqualTo("P@ssw0rd!");
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

  @Nested
  @DisplayName("Password validation rules")
  class ValidationRules {

    @Test
    @DisplayName("Reject empty password")
    void rejectEmpty() {
      var result = passwordService.validate("");

      assertThat(result.valid()).isFalse();
      assertThat(result.message()).isEqualTo("Password cannot be empty");
    }

    @Test
    @DisplayName("Reject too short password")
    void rejectTooShort() {
      var result = passwordService.validate("A1!");

      assertThat(result.valid()).isFalse();
      assertThat(result.message()).isEqualTo("Password must be at least 8 characters");
    }

    @Test
    @DisplayName("Reject missing uppercase")
    void rejectMissingUppercase() {
      var result = passwordService.validate("lowercase1!");

      assertThat(result.valid()).isFalse();
      assertThat(result.message()).isEqualTo("Password must contain an uppercase letter");
    }

    @Test
    @DisplayName("Reject missing lowercase")
    void rejectMissingLowercase() {
      var result = passwordService.validate("UPPERCASE1!");

      assertThat(result.valid()).isFalse();
      assertThat(result.message()).isEqualTo("Password must contain a lowercase letter");
    }

    @Test
    @DisplayName("Reject missing digit")
    void rejectMissingDigit() {
      var result = passwordService.validate("NoDigits!!");

      assertThat(result.valid()).isFalse();
      assertThat(result.message()).isEqualTo("Password must contain a digit");
    }

    @Test
    @DisplayName("Reject missing special character")
    void rejectMissingSpecial() {
      var result = passwordService.validate("NoSpecial1");

      assertThat(result.valid()).isFalse();
      assertThat(result.message()).isEqualTo("Password must contain a special character");
    }

    @Test
    @DisplayName("Accept strong password")
    void acceptValidPassword() {
      var result = passwordService.validate("Valid1@Pass");

      assertThat(result.valid()).isTrue();
      assertThat(result.message()).isNull();
    }
  }
}
