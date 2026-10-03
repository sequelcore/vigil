/**
 * Vigil - Opinionated JWT authentication starter for Spring Boot.
 *
 * <p>This package provides core authentication utilities including JWT token management, password
 * hashing, cookie handling, and optional modules for token blacklisting, multi-tenancy, step-up
 * authorization, and failed-attempt protection.
 *
 * <p>Failed-attempt protection has a single owner, {@link
 * io.github.sequelcore.vigil.login.PasswordLoginGuard}, configured under {@code vigil.login.*}.
 * Password login and step-up PIN verification share one mechanism: {@link
 * io.github.sequelcore.vigil.login.LoginPolicy} defines the lockout, {@link
 * io.github.sequelcore.vigil.login.LoginAttemptStore} holds the counters, and each credential uses
 * its own key namespace so a lock on one never affects the other.
 *
 * @see io.github.sequelcore.vigil.autoconfigure.VigilAutoConfiguration
 * @see io.github.sequelcore.vigil.login.PasswordLoginGuard
 */
package io.github.sequelcore.vigil;
