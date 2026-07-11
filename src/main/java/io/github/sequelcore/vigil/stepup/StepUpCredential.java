package io.github.sequelcore.vigil.stepup;

/**
 * A credential submitted during a challenge. Implementations must clear secret material promptly.
 */
public interface StepUpCredential extends AutoCloseable {
  StepUpMethod method();

  @Override
  void close();
}
