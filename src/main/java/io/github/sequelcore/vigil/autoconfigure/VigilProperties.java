package io.github.sequelcore.vigil.autoconfigure;

import jakarta.validation.constraints.NotBlank;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
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
    Filter filter) {

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
   */
  public VigilProperties {
    if (jwt == null) {
      jwt = new Jwt(null, Duration.ofMinutes(15), Duration.ofDays(7), null, null);
    }
    if (cookie == null) {
      cookie = new Cookie("access_token", "refresh_token", true, "Lax", true);
    }
    if (password == null) {
      password = new Password(12);
    }
    if (blacklist == null) {
      blacklist = new Blacklist(10000, Duration.ofHours(24));
    }
    if (tenant == null) {
      tenant = new Tenant(false, "X-Tenant-ID");
    }
    if (protection == null) {
      protection = new Protection(5, Duration.ofMinutes(15), 10000);
    }
    if (filter == null) {
      filter = new Filter(Collections.emptyList());
    }
  }

  /**
   * JWT token configuration.
   *
   * @param secret the signing secret (minimum 32 characters)
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
     * Applies defaults when TTL values are not provided.
     *
     * @param secret the signing secret
     * @param accessTtl access token time-to-live
     * @param refreshTtl refresh token time-to-live
     * @param issuer optional token issuer claim
     * @param audience optional token audience claim
     */
    public Jwt {
      if (accessTtl == null) {
        accessTtl = Duration.ofMinutes(15);
      }
      if (refreshTtl == null) {
        refreshTtl = Duration.ofDays(7);
      }
    }
  }

  /**
   * Cookie configuration.
   *
   * @param accessTokenName cookie name for access tokens
   * @param refreshTokenName cookie name for refresh tokens
   * @param secure whether to mark cookies as Secure
   * @param sameSite SameSite policy
   * @param httpOnly whether to mark cookies as HttpOnly
   */
  public record Cookie(
      String accessTokenName,
      String refreshTokenName,
      boolean secure,
      String sameSite,
      boolean httpOnly) {
    /**
     * Applies defaults when cookie values are not provided.
     *
     * @param accessTokenName cookie name for access tokens
     * @param refreshTokenName cookie name for refresh tokens
     * @param secure whether to mark cookies as Secure
     * @param sameSite SameSite policy
     * @param httpOnly whether to mark cookies as HttpOnly
     */
    public Cookie {
      if (accessTokenName == null) {
        accessTokenName = "access_token";
      }
      if (refreshTokenName == null) {
        refreshTokenName = "refresh_token";
      }
      if (sameSite == null) {
        sameSite = "Lax";
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
   */
  public record Blacklist(int maxSize, Duration ttl) {
    /**
     * Validates and normalizes blacklist settings.
     *
     * @param maxSize maximum number of tokens to keep
     * @param ttl time-to-live for blacklisted tokens
     */
    public Blacklist {
      if (maxSize <= 0) {
        maxSize = 10000;
      }
      if (ttl == null) {
        ttl = Duration.ofHours(24);
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
   * @param publicPaths list of paths that bypass authentication
   */
  public record Filter(List<String> publicPaths) {
    /**
     * Applies defaults when no public paths are provided.
     *
     * @param publicPaths list of paths that bypass authentication
     */
    public Filter {
      if (publicPaths == null) {
        publicPaths = Collections.emptyList();
      }
    }
  }
}
