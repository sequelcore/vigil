package io.github.sequelcore.vigil.autoconfigure;

import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Configuration properties for the Vigil authentication starter.
 *
 * @param jwt JWT token configuration
 * @param cookie cookie storage configuration
 * @param password password hashing configuration
 * @param blacklist token blacklist configuration
 * @param tenant multi-tenant configuration
 * @param protection login protection configuration
 * @param filter authentication filter configuration
 * @param session session authentication configuration
 * @param reset password reset configuration
 * @param auth authentication behavior configuration
 */
@ConfigurationProperties(prefix = "vigil")
@Validated
public record VigilProperties(
    Jwt jwt,
    Cookie cookie,
    Password password,
    Blacklist blacklist,
    Tenant tenant,
    Protection protection,
    Filter filter,
    Session session,
    Reset reset,
    Auth auth,
    StepUp stepUp) {

  /**
   * Applies defaults when configuration sections are omitted.
   *
   * @param jwt JWT token configuration (nullable)
   * @param cookie cookie storage configuration (nullable)
   * @param password password hashing configuration (nullable)
   * @param blacklist token blacklist configuration (nullable)
   * @param tenant multi-tenant configuration (nullable)
   * @param protection login protection configuration (nullable)
   * @param filter authentication filter configuration (nullable)
   * @param session session authentication configuration (nullable)
   * @param reset password reset configuration (nullable)
   * @param auth authentication behavior configuration (nullable)
   */
  public VigilProperties {
    if (jwt == null) {
      throw new IllegalArgumentException(
          "vigil.jwt must be configured. Set vigil.jwt.secret (HS256) or"
              + " vigil.jwt.algorithm=RS256 with rsa-private-key and rsa-public-key.");
    }
    if (cookie == null) {
      cookie = new Cookie(true, "Lax", true, null);
    }
    if (password == null) {
      password = new Password(12);
    }
    if (blacklist == null) {
      blacklist = new Blacklist(10000, Duration.ofHours(24), Duration.ofSeconds(30));
    }
    if (tenant == null) {
      tenant = new Tenant(false, "X-Tenant-ID");
    }
    if (protection == null) {
      protection = new Protection(5, Duration.ofMinutes(15), 10000);
    }
    if (filter == null) {
      filter = new Filter(Collections.emptyList(), Collections.emptyList(), Collections.emptyMap());
    }
    if (session == null) {
      session = new Session(false, "session_token", Duration.ofMinutes(30));
    }
    if (reset == null) {
      reset = new Reset(Duration.ofHours(1));
    }
    if (auth == null) {
      auth = new Auth(null);
    }
    if (stepUp == null) {
      stepUp = new StepUp(Duration.ofMinutes(2), Duration.ofMinutes(5), 10000, null);
    }
  }

  /**
   * JWT token configuration.
   *
   * @param secret HMAC signing secret, at least 32 characters; required when {@code
   *     algorithm=HS256}. Use randomly generated key material with at least 256 bits of entropy.
   * @param accessTtl access token time-to-live
   * @param refreshTtl refresh token time-to-live
   * @param issuer optional token issuer claim ({@code iss}); validated on parse when set
   * @param audience optional token audience claim ({@code aud}); validated on parse when set
   * @param algorithm signing algorithm; defaults to {@link Algorithm#HS256}
   * @param rsaPrivateKey PEM-encoded RSA private key — {@code file:/path}, {@code classpath:path},
   *     or inline PEM; required when {@code algorithm=RS256}
   * @param rsaPublicKey active PEM-encoded RSA public key; required when {@code algorithm=RS256}
   * @param rsaPublicKeys additional verification-only RSA public keys for key rotation
   * @param clockSkew allowed JWT validation clock skew, default zero, maximum five minutes
   */
  public record Jwt(
      String secret,
      Duration accessTtl,
      Duration refreshTtl,
      String issuer,
      String audience,
      Algorithm algorithm,
      String rsaPrivateKey,
      String rsaPublicKey,
      List<String> rsaPublicKeys,
      Duration clockSkew) {

    /** JWT signing algorithm. */
    public enum Algorithm {
      /** HMAC-SHA256. Symmetric — any secret holder can sign and verify. */
      HS256,

      /**
       * RSA-SHA256. Asymmetric — private key signs, public key verifies. Enables JWKS distribution
       * and key rotation without sharing the signing secret.
       */
      RS256
    }

    /**
     * Applies defaults and validates algorithm-specific requirements.
     *
     * @param secret HMAC secret
     * @param accessTtl access TTL
     * @param refreshTtl refresh TTL
     * @param issuer issuer claim
     * @param audience audience claim
     * @param algorithm signing algorithm
     * @param rsaPrivateKey RSA private key PEM
     * @param rsaPublicKey RSA public key PEM
     * @param rsaPublicKeys additional RSA public keys for verification during rotation
     * @param clockSkew allowed validation clock skew
     */
    public Jwt {
      if (algorithm == null) {
        algorithm = Algorithm.HS256;
      }
      if (accessTtl == null) {
        accessTtl = Duration.ofMinutes(15);
      }
      if (refreshTtl == null) {
        refreshTtl = Duration.ofDays(7);
      }
      if (rsaPublicKeys == null) {
        rsaPublicKeys = List.of();
      } else {
        rsaPublicKeys = List.copyOf(rsaPublicKeys);
      }
      if (clockSkew == null) {
        clockSkew = Duration.ZERO;
      }
      if (clockSkew.isNegative()) {
        throw new IllegalArgumentException("vigil.jwt.clock-skew cannot be negative");
      }
      if (clockSkew.compareTo(Duration.ofMinutes(5)) > 0) {
        throw new IllegalArgumentException("vigil.jwt.clock-skew cannot exceed 5 minutes");
      }

      if (algorithm == Algorithm.HS256) {
        if (secret == null || secret.length() < 32) {
          throw new IllegalArgumentException(
              "vigil.jwt.secret must be at least 32 characters."
                  + (secret != null ? " Current length: " + secret.length() : " Value is null."));
        }
      }

      if (algorithm == Algorithm.RS256) {
        if (rsaPrivateKey == null || rsaPrivateKey.isBlank()) {
          throw new IllegalArgumentException(
              "vigil.jwt.rsa-private-key is required when vigil.jwt.algorithm=RS256");
        }
        if (rsaPublicKey == null || rsaPublicKey.isBlank()) {
          throw new IllegalArgumentException(
              "vigil.jwt.rsa-public-key is required when vigil.jwt.algorithm=RS256");
        }
      }
    }
  }

  /**
   * Cookie configuration with named profiles.
   *
   * <p>Profiles define cookie names for different user types (e.g., staff, customer). Security
   * settings are shared across all profiles.
   *
   * <p>Example:
   *
   * <pre>
   * vigil:
   *   cookie:
   *     secure: true
   *     http-only: true
   *     same-site: Lax
   *     profiles:
   *       staff:
   *         access-token-name: staff_access_token
   *         refresh-token-name: staff_refresh_token
   *       customer:
   *         access-token-name: customer_access_token
   *         refresh-token-name: customer_refresh_token
   * </pre>
   *
   * @param secure whether to mark cookies as Secure
   * @param sameSite SameSite policy
   * @param httpOnly whether to mark cookies as HttpOnly
   * @param profiles named cookie profiles (required, at least one)
   */
  public record Cookie(
      boolean secure, String sameSite, boolean httpOnly, Map<String, CookieProfile> profiles) {

    /** Applies defaults. */
    public Cookie {
      if (sameSite == null) {
        sameSite = "Lax";
      }
      if (profiles == null || profiles.isEmpty()) {
        // Default profile if none configured
        profiles = Map.of("default", new CookieProfile("access_token", "refresh_token"));
      }
    }

    /**
     * Gets a profile by name.
     *
     * @param name profile name
     * @return the profile
     * @throws IllegalArgumentException if profile not found
     */
    public CookieProfile getProfile(String name) {
      CookieProfile profile = profiles.get(name);
      if (profile == null) {
        throw new IllegalArgumentException("Cookie profile not found: " + name);
      }
      return profile;
    }

    /**
     * Gets the first/default profile.
     *
     * @return the first profile
     */
    public CookieProfile getDefaultProfile() {
      return profiles.values().iterator().next();
    }
  }

  /**
   * Cookie profile for a specific user type.
   *
   * @param accessTokenName cookie name for access tokens
   * @param refreshTokenName cookie name for refresh tokens
   */
  public record CookieProfile(String accessTokenName, String refreshTokenName) {
    /** Applies defaults. */
    public CookieProfile {
      if (accessTokenName == null) {
        accessTokenName = "access_token";
      }
      if (refreshTokenName == null) {
        refreshTokenName = "refresh_token";
      }
    }
  }

  /**
   * Password hashing configuration.
   *
   * @param strength BCrypt cost factor (4-31)
   */
  public record Password(int strength) {
    /**
     * Validates and normalizes the configured strength.
     *
     * @param strength BCrypt cost factor (4-31)
     */
    public Password {
      if (strength < 4 || strength > 31) {
        strength = 12;
      }
    }
  }

  /**
   * Token blacklist configuration.
   *
   * @param maxSize maximum number of tokens to keep
   * @param ttl time-to-live for blacklisted tokens
   * @param gracePeriod grace period for rotated refresh tokens (allows reuse during network issues)
   */
  public record Blacklist(int maxSize, Duration ttl, Duration gracePeriod) {
    /**
     * Validates and normalizes blacklist settings.
     *
     * @param maxSize maximum number of tokens to keep
     * @param ttl time-to-live for blacklisted tokens
     * @param gracePeriod grace period for rotated tokens (default 30s, max 60s)
     */
    public Blacklist {
      if (maxSize <= 0) {
        maxSize = 10000;
      }
      if (ttl == null) {
        ttl = Duration.ofHours(24);
      }
      if (gracePeriod == null) {
        gracePeriod = Duration.ofSeconds(30);
      } else if (gracePeriod.toSeconds() > 60) {
        gracePeriod = Duration.ofSeconds(60);
      }
    }
  }

  /**
   * Multi-tenant configuration.
   *
   * @param enabled whether tenant support is enabled
   * @param headerName HTTP header used to carry tenant ID
   */
  public record Tenant(boolean enabled, String headerName) {
    /**
     * Applies defaults when tenant header is not provided.
     *
     * @param enabled whether tenant support is enabled
     * @param headerName HTTP header used to carry tenant ID
     */
    public Tenant {
      if (headerName == null) {
        headerName = "X-Tenant-ID";
      }
    }
  }

  /**
   * Login protection configuration.
   *
   * @param maxAttempts number of attempts before lockout
   * @param lockDuration how long a lockout lasts
   * @param maxSize maximum entries to track in cache
   */
  public record Protection(int maxAttempts, Duration lockDuration, int maxSize) {
    /**
     * Validates and normalizes protection settings.
     *
     * @param maxAttempts number of attempts before lockout
     * @param lockDuration how long a lockout lasts
     * @param maxSize maximum entries to track in cache
     */
    public Protection {
      if (maxAttempts <= 0) {
        maxAttempts = 5;
      }
      if (lockDuration == null) {
        lockDuration = Duration.ofMinutes(15);
      }
      if (maxSize <= 0) {
        maxSize = 10000;
      }
    }
  }

  /**
   * Authentication filter configuration.
   *
   * @param ignoredPaths paths that bypass ALL processing (no tenant, no auth, no populators)
   * @param publicPaths paths that continue without credentials but authenticate them when present;
   *     application authorization rules still decide access
   * @param profilePaths mapping of profile name to path patterns for cookie resolution
   */
  public record Filter(
      List<String> ignoredPaths, List<String> publicPaths, Map<String, List<String>> profilePaths) {
    /** Applies defaults. */
    public Filter {
      if (ignoredPaths == null) {
        ignoredPaths = Collections.emptyList();
      }
      if (publicPaths == null) {
        publicPaths = Collections.emptyList();
      }
      if (profilePaths == null) {
        profilePaths = Collections.emptyMap();
      }
    }
  }

  /**
   * Session authentication configuration.
   *
   * @param enabled whether session auth is enabled
   * @param cookieName cookie name for session tokens
   * @param ttl session token TTL
   */
  public record Session(boolean enabled, String cookieName, Duration ttl) {
    /**
     * Applies defaults.
     *
     * @param enabled whether session auth is enabled
     * @param cookieName cookie name for session tokens
     * @param ttl session token TTL
     */
    public Session {
      if (cookieName == null || cookieName.isEmpty()) {
        cookieName = "session_token";
      }
      if (ttl == null) {
        ttl = Duration.ofMinutes(30);
      }
    }
  }

  /**
   * Password reset configuration.
   *
   * @param ttl reset token TTL
   */
  public record Reset(Duration ttl) {
    /**
     * Applies defaults.
     *
     * @param ttl reset token TTL
     */
    public Reset {
      if (ttl == null) {
        ttl = Duration.ofHours(1);
      }
    }
  }

  /**
   * Authentication behavior configuration.
   *
   * @param realm the realm name for WWW-Authenticate header (RFC 6750)
   */
  public record Auth(String realm) {
    /**
     * Applies defaults.
     *
     * @param realm the realm name
     */
    public Auth {
      if (realm == null || realm.isEmpty()) {
        realm = "app";
      }
    }
  }

  /** Step-up authorization configuration. */
  public record StepUp(Duration challengeTtl, Duration proofTtl, int maxSize, Pin pin) {
    public StepUp {
      if (challengeTtl == null || challengeTtl.isNegative() || challengeTtl.isZero()) {
        challengeTtl = Duration.ofMinutes(2);
      }
      if (proofTtl == null || proofTtl.isNegative() || proofTtl.isZero()) {
        proofTtl = Duration.ofMinutes(5);
      }
      if (maxSize <= 0) {
        maxSize = 10000;
      }
      if (pin == null) {
        pin = new Pin(6, 12, 12, true);
      }
    }

    /** Numeric PIN policy. */
    public record Pin(
        int minLength, int maxLength, int bcryptStrength, boolean rejectCommonPatterns) {
      public Pin {
        if (minLength < 4) {
          minLength = 6;
        }
        if (maxLength < minLength || maxLength > 128) {
          maxLength = 12;
        }
        if (bcryptStrength < 4 || bcryptStrength > 31) {
          bcryptStrength = 12;
        }
      }
    }
  }
}
