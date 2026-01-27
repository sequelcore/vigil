package io.github.sequelcore.vigil.autoconfigure;

import jakarta.validation.constraints.NotBlank;
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
    Auth auth) {

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
      jwt = new Jwt(null, Duration.ofMinutes(15), Duration.ofDays(7), null, null);
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
  }

  /**
   * JWT token configuration.
   *
   * @param secret the signing secret (minimum 32 characters per RFC 8725bis)
   * @param accessTtl access token time-to-live
   * @param refreshTtl refresh token time-to-live
   * @param issuer optional token issuer claim
   * @param audience optional token audience claim
   */
  public record Jwt(
      @NotBlank String secret,
      Duration accessTtl,
      Duration refreshTtl,
      String issuer,
      String audience) {
    /**
     * Applies defaults and validates configuration.
     *
     * @param secret the signing secret
     * @param accessTtl access token time-to-live
     * @param refreshTtl refresh token time-to-live
     * @param issuer optional token issuer claim
     * @param audience optional token audience claim
     */
    public Jwt {
      // RFC 8725bis: Minimum 256 bits (32 bytes) for HMAC-SHA algorithms
      if (secret != null && secret.length() < 32) {
        throw new IllegalArgumentException(
            "JWT secret must be at least 32 characters (256 bits) per RFC 8725bis. Current length: "
                + secret.length());
      }

      if (accessTtl == null) {
        accessTtl = Duration.ofMinutes(15);
      }
      if (refreshTtl == null) {
        refreshTtl = Duration.ofDays(7);
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
   * @param publicPaths paths that permit anonymous but authenticate if credentials present
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
}
