package io.github.sequelcore.vigil.autoconfigure;

import jakarta.validation.constraints.NotBlank;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/** Configuration properties for Vigil authentication starter. */
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
      blacklist = new Blacklist(false, 10000, Duration.ofHours(24));
    }
    if (tenant == null) {
      tenant = new Tenant(false, "X-Tenant-ID");
    }
    if (protection == null) {
      protection = new Protection(false, 5, Duration.ofMinutes(15), 10000);
    }
    if (filter == null) {
      filter = new Filter(false, Collections.emptyList());
    }
  }

  /** JWT token configuration. */
  public record Jwt(
      @NotBlank String secret,
      Duration accessTtl,
      Duration refreshTtl,
      String issuer,
      String audience) {
    public Jwt {
      if (accessTtl == null) {
        accessTtl = Duration.ofMinutes(15);
      }
      if (refreshTtl == null) {
        refreshTtl = Duration.ofDays(7);
      }
    }
  }

  /** Cookie configuration. */
  public record Cookie(
      String accessTokenName,
      String refreshTokenName,
      boolean secure,
      String sameSite,
      boolean httpOnly) {
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

  /** Password hashing configuration. */
  public record Password(int strength) {
    public Password {
      if (strength < 4 || strength > 31) {
        strength = 12;
      }
    }
  }

  /** Token blacklist configuration. */
  public record Blacklist(boolean enabled, int maxSize, Duration ttl) {
    public Blacklist {
      if (maxSize <= 0) {
        maxSize = 10000;
      }
      if (ttl == null) {
        ttl = Duration.ofHours(24);
      }
    }
  }

  /** Multi-tenant configuration. */
  public record Tenant(boolean enabled, String headerName) {
    public Tenant {
      if (headerName == null) {
        headerName = "X-Tenant-ID";
      }
    }
  }

  /** Login protection configuration. */
  public record Protection(boolean enabled, int maxAttempts, Duration lockDuration, int maxSize) {
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

  /** Authentication filter configuration. */
  public record Filter(boolean enabled, List<String> publicPaths) {
    public Filter {
      if (publicPaths == null) {
        publicPaths = Collections.emptyList();
      }
    }
  }
}
