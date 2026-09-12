package io.github.sequelcore.vigil.enrollment;

/**
 * Application-owned canonicalization of an enrollment email address.
 *
 * <p>The returned value is a storage key and is never logged or returned by Vigil.
 */
@FunctionalInterface
public interface EmailCanonicalizer {
  String canonicalize(String email);
}
