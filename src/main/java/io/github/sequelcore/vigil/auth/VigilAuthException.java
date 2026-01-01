package io.github.sequelcore.vigil.auth;

/**
 * Exception thrown when authentication operations fail.
 *
 * <p>Contains an error code for programmatic handling and a descriptive message.
 */
public class VigilAuthException extends RuntimeException {

  private final AuthErrorCode code;

  /**
   * Creates a new authentication exception.
   *
   * @param code the error code
   * @param message descriptive message
   */
  public VigilAuthException(AuthErrorCode code, String message) {
    super(message);
    this.code = code;
  }

  /**
   * Creates a new authentication exception with a cause.
   *
   * @param code the error code
   * @param message descriptive message
   * @param cause the underlying cause
   */
  public VigilAuthException(AuthErrorCode code, String message, Throwable cause) {
    super(message, cause);
    this.code = code;
  }

  /**
   * Returns the error code for programmatic handling.
   *
   * @return the error code
   */
  public AuthErrorCode getCode() {
    return code;
  }

  /** Error codes for authentication failures. */
  public enum AuthErrorCode {
    /** Token was not found in request. */
    TOKEN_NOT_FOUND,

    /** Token has expired. */
    TOKEN_EXPIRED,

    /** Token is in the blacklist. */
    TOKEN_BLACKLISTED,

    /** Token signature or format is invalid. */
    TOKEN_INVALID,

    /** Tenant ID in token does not match request context. */
    TENANT_MISMATCH,

    /** Session has expired. */
    SESSION_EXPIRED,

    /** Session was not found in storage. */
    SESSION_NOT_FOUND,

    /** Reset token has expired. */
    RESET_TOKEN_EXPIRED,

    /** Reset token signature or format is invalid. */
    RESET_TOKEN_INVALID,

    /** Reset token has already been used. */
    RESET_TOKEN_USED
  }
}
