package io.github.sequelcore.vigil.stepup.pin;

import io.github.sequelcore.vigil.stepup.StepUpCredential;
import io.github.sequelcore.vigil.stepup.StepUpMethod;
import java.util.Arrays;

/** Numeric PIN credential whose mutable character buffer is wiped after verification. */
public final class PinCredential implements StepUpCredential {
  private char[] value;

  public PinCredential(char[] value) {
    if (value == null || value.length == 0) {
      throw new IllegalArgumentException("PIN is required");
    }
    this.value = value.clone();
  }

  @Override
  public StepUpMethod method() {
    return StepUpMethod.PIN;
  }

  char[] value() {
    if (value == null) {
      throw new IllegalStateException("PIN has already been cleared");
    }
    return value;
  }

  @Override
  public void close() {
    if (value != null) {
      Arrays.fill(value, '\0');
      value = null;
    }
  }
}
