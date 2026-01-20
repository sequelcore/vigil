package io.github.sequelcore.vigil.entrypoint;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.AuthenticationException;

/** Tests for {@link VigilAuthenticationEntryPoint} - RFC 6750 compliance. */
class VigilAuthenticationEntryPointTest {

  private VigilAuthenticationEntryPoint entryPoint;
  private HttpServletRequest request;
  private HttpServletResponse response;
  private StringWriter responseBody;
  private AuthenticationException authException;

  @BeforeEach
  void setUp() throws Exception {
    ObjectMapper objectMapper = new ObjectMapper();
    entryPoint = new VigilAuthenticationEntryPoint("quesoro", objectMapper);

    request = Mockito.mock(HttpServletRequest.class);
    response = Mockito.mock(HttpServletResponse.class);
    authException = Mockito.mock(AuthenticationException.class);

    responseBody = new StringWriter();
    PrintWriter writer = new PrintWriter(responseBody);
    Mockito.when(response.getWriter()).thenReturn(writer);
  }

  @Test
  void shouldReturnWwwAuthenticateHeaderWithRealmOnlyWhenNoToken() throws Exception {
    // RFC 6750: No error code when request lacks authentication information

    entryPoint.commence(request, response, authException);

    Mockito.verify(response).setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer realm=\"quesoro\"");
    Mockito.verify(response).setStatus(401);
  }

  @Test
  void shouldReturnWwwAuthenticateWithInvalidTokenWhenExpired() throws Exception {
    // RFC 6750: error="invalid_token" for expired tokens
    Mockito.when(request.getAttribute("vigil.error.code")).thenReturn("invalid_token");
    Mockito.when(request.getAttribute("vigil.error.description"))
        .thenReturn("The access token has expired");

    entryPoint.commence(request, response, authException);

    Mockito.verify(response)
        .setHeader(
            HttpHeaders.WWW_AUTHENTICATE,
            "Bearer realm=\"quesoro\", error=\"invalid_token\", error_description=\"The access"
                + " token has expired\"");
    Mockito.verify(response).setStatus(401);
  }

  @Test
  void shouldReturnWwwAuthenticateWithInvalidTokenWhenMalformed() throws Exception {
    Mockito.when(request.getAttribute("vigil.error.code")).thenReturn("invalid_token");
    Mockito.when(request.getAttribute("vigil.error.description"))
        .thenReturn("Invalid token signature");

    entryPoint.commence(request, response, authException);

    Mockito.verify(response)
        .setHeader(
            HttpHeaders.WWW_AUTHENTICATE,
            "Bearer realm=\"quesoro\", error=\"invalid_token\", error_description=\"Invalid token"
                + " signature\"");
    Mockito.verify(response).setStatus(401);
  }

  @Test
  void shouldReturnWwwAuthenticateWithInvalidTokenWhenBlacklisted() throws Exception {
    Mockito.when(request.getAttribute("vigil.error.code")).thenReturn("invalid_token");
    Mockito.when(request.getAttribute("vigil.error.description"))
        .thenReturn("Token has been revoked");

    entryPoint.commence(request, response, authException);

    Mockito.verify(response)
        .setHeader(
            HttpHeaders.WWW_AUTHENTICATE,
            "Bearer realm=\"quesoro\", error=\"invalid_token\", error_description=\"Token has been"
                + " revoked\"");
    Mockito.verify(response).setStatus(401);
  }

  @Test
  void shouldEscapeQuotesInErrorDescription() throws Exception {
    Mockito.when(request.getAttribute("vigil.error.code")).thenReturn("invalid_token");
    Mockito.when(request.getAttribute("vigil.error.description"))
        .thenReturn("Token \"abc\" is invalid");

    entryPoint.commence(request, response, authException);

    Mockito.verify(response)
        .setHeader(
            HttpHeaders.WWW_AUTHENTICATE,
            "Bearer realm=\"quesoro\", error=\"invalid_token\", error_description=\"Token"
                + " \\\"abc\\\" is invalid\"");
  }

  @Test
  void shouldReturnJsonResponseBody() throws Exception {
    Mockito.when(request.getAttribute("vigil.error.code")).thenReturn("invalid_token");
    Mockito.when(request.getAttribute("vigil.error.description"))
        .thenReturn("The access token has expired");

    entryPoint.commence(request, response, authException);

    Mockito.verify(response).setContentType("application/json");

    String json = responseBody.toString();
    assertThat(json).contains("\"status\":401");
    assertThat(json).contains("\"error\":\"Unauthorized\"");
    assertThat(json).contains("\"code\":\"invalid_token\"");
    assertThat(json).contains("\"message\":\"The access token has expired\"");
  }

  @Test
  void shouldUseDefaultMessageWhenNoDescription() throws Exception {
    entryPoint.commence(request, response, authException);

    String json = responseBody.toString();
    assertThat(json)
        .contains("\"message\":\"Full authentication is required to access this resource\"");
  }
}
