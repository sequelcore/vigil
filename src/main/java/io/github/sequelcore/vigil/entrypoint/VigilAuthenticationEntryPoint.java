package io.github.sequelcore.vigil.entrypoint;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.lang.Nullable;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

/**
 * RFC 6750 compliant authentication entry point for bearer token errors.
 *
 * <p>Handles authentication failures by returning HTTP 401 with the {@code WWW-Authenticate} header
 * as specified in RFC 6750 Section 3.
 *
 * <p>The filter sets request attributes to communicate error details:
 *
 * <ul>
 *   <li>{@code vigil.error.code} - Error code (e.g., "invalid_token")
 *   <li>{@code vigil.error.description} - Human-readable error description
 * </ul>
 *
 * <p>Header format examples:
 *
 * <pre>
 * # No token present
 * WWW-Authenticate: Bearer realm="quesoro"
 *
 * # Expired token
 * WWW-Authenticate: Bearer realm="quesoro", error="invalid_token", error_description="The access token has expired"
 *
 * # Invalid signature
 * WWW-Authenticate: Bearer realm="quesoro", error="invalid_token", error_description="Invalid token signature"
 * </pre>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc6750.html#section-3">RFC 6750 Section 3</a>
 */
public class VigilAuthenticationEntryPoint implements AuthenticationEntryPoint {

  /** Request attribute key for error code. */
  public static final String ERROR_CODE_ATTRIBUTE = "vigil.error.code";

  /** Request attribute key for error description. */
  public static final String ERROR_DESCRIPTION_ATTRIBUTE = "vigil.error.description";

  private final String realm;
  private final ObjectMapper objectMapper;

  /**
   * Creates an entry point with the specified realm.
   *
   * @param realm the realm name for the WWW-Authenticate header
   * @param objectMapper JSON mapper for response body
   */
  public VigilAuthenticationEntryPoint(String realm, ObjectMapper objectMapper) {
    this.realm = realm;
    this.objectMapper = objectMapper;
  }

  @Override
  public void commence(
      HttpServletRequest request,
      HttpServletResponse response,
      AuthenticationException authException)
      throws IOException {

    // Extract error details from request attributes (set by filter)
    String errorCode = (String) request.getAttribute(ERROR_CODE_ATTRIBUTE);
    String errorDescription = (String) request.getAttribute(ERROR_DESCRIPTION_ATTRIBUTE);

    // Build WWW-Authenticate header per RFC 6750
    String wwwAuthenticate = buildWwwAuthenticateHeader(errorCode, errorDescription);
    response.setHeader(HttpHeaders.WWW_AUTHENTICATE, wwwAuthenticate);

    // Set HTTP 401 status
    response.setStatus(HttpStatus.UNAUTHORIZED.value());
    response.setContentType("application/json");

    // Write JSON response body
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("status", HttpStatus.UNAUTHORIZED.value());
    body.put("error", "Unauthorized");

    if (errorCode != null) {
      body.put("code", errorCode);
    }
    if (errorDescription != null) {
      body.put("message", errorDescription);
    } else {
      body.put("message", "Full authentication is required to access this resource");
    }

    objectMapper.writeValue(response.getWriter(), body);
  }

  /**
   * Builds the WWW-Authenticate header value according to RFC 6750 Section 3.
   *
   * <p>Format: {@code Bearer realm="...", error="...", error_description="..."}
   *
   * <p>Per RFC 6750: If the request lacks authentication information, the error code SHOULD NOT be
   * included.
   *
   * @param errorCode the error code (nullable - omitted if no token present)
   * @param errorDescription the error description (nullable)
   * @return the WWW-Authenticate header value
   */
  private String buildWwwAuthenticateHeader(
      @Nullable String errorCode, @Nullable String errorDescription) {

    StringBuilder header = new StringBuilder("Bearer");

    // Always include realm if configured
    if (realm != null && !realm.isEmpty()) {
      header.append(" realm=\"").append(escapeQuotes(realm)).append("\"");
    }

    // Only include error if token was present but invalid
    // RFC 6750: "If the request lacks any authentication information...
    // the resource server SHOULD NOT include an error code"
    if (errorCode != null) {
      if (realm != null && !realm.isEmpty()) {
        header.append(",");
      }
      header.append(" error=\"").append(escapeQuotes(errorCode)).append("\"");

      if (errorDescription != null) {
        header.append(", error_description=\"").append(escapeQuotes(errorDescription)).append("\"");
      }
    }

    return header.toString();
  }

  /** Escapes double quotes in header values. */
  private String escapeQuotes(String value) {
    return value.replace("\"", "\\\"");
  }
}
