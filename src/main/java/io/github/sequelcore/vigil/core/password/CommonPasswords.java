package io.github.sequelcore.vigil.core.password;

import java.util.Set;

/**
 * Dictionary of common passwords for rejection during validation.
 *
 * <p>Contains the most frequently used passwords that should be rejected regardless of complexity
 * requirements. This list is intentionally kept small for fast lookups while covering the most
 * critical cases.
 */
final class CommonPasswords {

  private CommonPasswords() {}

  /** Set of common passwords that should be rejected. */
  static final Set<String> DICTIONARY =
      Set.of(
          // Top 100 most common passwords (lowercase for case-insensitive matching)
          "123456",
          "password",
          "12345678",
          "qwerty",
          "123456789",
          "12345",
          "1234",
          "111111",
          "1234567",
          "dragon",
          "123123",
          "baseball",
          "abc123",
          "football",
          "monkey",
          "letmein",
          "shadow",
          "master",
          "666666",
          "qwertyuiop",
          "123321",
          "mustang",
          "1234567890",
          "michael",
          "654321",
          "superman",
          "1qaz2wsx",
          "7777777",
          "121212",
          "000000",
          "qazwsx",
          "123qwe",
          "killer",
          "trustno1",
          "jordan",
          "jennifer",
          "zxcvbnm",
          "asdfgh",
          "hunter",
          "buster",
          "soccer",
          "harley",
          "batman",
          "andrew",
          "tigger",
          "sunshine",
          "iloveyou",
          "2000",
          "charlie",
          "robert",
          "thomas",
          "hockey",
          "ranger",
          "daniel",
          "starwars",
          "klaster",
          "112233",
          "george",
          "computer",
          "michelle",
          "jessica",
          "pepper",
          "1111",
          "zxcvbn",
          "555555",
          "11111111",
          "131313",
          "freedom",
          "777777",
          "pass",
          "maggie",
          "159753",
          "aaaaaa",
          "ginger",
          "princess",
          "joshua",
          "cheese",
          "amanda",
          "summer",
          "love",
          "ashley",
          "nicole",
          "chelsea",
          "biteme",
          "matthew",
          "access",
          "yankees",
          "987654321",
          "dallas",
          "austin",
          "thunder",
          "taylor",
          "matrix",
          "mobilemail",
          "mom",
          "monitor",
          "monitoring",
          "montana",
          "moon",
          "moscow",
          // Common patterns
          "password1",
          "password123",
          "admin",
          "admin123",
          "root",
          "toor",
          "pass123",
          "test",
          "test123",
          "guest",
          "guest123",
          "changeme",
          "welcome",
          "welcome1",
          "welcome123",
          "login",
          "default",
          "password1!",
          // Keyboard patterns
          "qwerty123",
          "asdfghjkl",
          "zxcvbnm123",
          "1q2w3e4r",
          "1q2w3e4r5t",
          "qwer1234",
          "asdf1234");

  /**
   * Checks if a password is in the common passwords dictionary.
   *
   * @param password the password to check (case-insensitive)
   * @return true if the password is common
   */
  static boolean contains(String password) {
    if (password == null || password.isEmpty()) {
      return false;
    }
    return DICTIONARY.contains(password.toLowerCase());
  }
}
