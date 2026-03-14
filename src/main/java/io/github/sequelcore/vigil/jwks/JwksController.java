package io.github.sequelcore.vigil.jwks;

import io.github.sequelcore.vigil.core.jwt.RsaTokenSigner;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Serves the JSON Web Key Set (JWKS) for RS256 token verification.
 *
 * <p>Published at {@code /.well-known/jwks.json} per RFC 7517. Consumers (e.g., the Kiln gateway)
 * fetch this endpoint to obtain the RSA public key needed to verify JWTs without holding the
 * private key.
 *
 * <p>Registered as a bean by {@link
 * io.github.sequelcore.vigil.autoconfigure.VigilAutoConfiguration} only when {@code
 * vigil.jwt.algorithm=RS256}. The path is automatically added to Vigil's ignored paths — no
 * authentication required to access it.
 *
 * <p>Response is cached for 1 hour ({@code Cache-Control: public, max-age=3600}).
 */
@RestController
public class JwksController {

  private final ResponseEntity<Map<String, Object>> cachedResponse;

  /**
   * Creates the JWKS controller with the RSA signer as the key source.
   *
   * @param signer the RS256 signer whose public key is published
   */
  public JwksController(RsaTokenSigner signer) {
    Map<String, Object> body = Map.of("keys", List.of(signer.getJwk()));
    this.cachedResponse =
        ResponseEntity.ok()
            .cacheControl(CacheControl.maxAge(1, TimeUnit.HOURS).cachePublic())
            .body(body);
  }

  /**
   * Returns the JWKS containing the active RSA public key.
   *
   * @return the JWK Set with {@code Cache-Control: public, max-age=3600}
   */
  @GetMapping("/.well-known/jwks.json")
  public ResponseEntity<Map<String, Object>> jwks() {
    return cachedResponse;
  }
}
