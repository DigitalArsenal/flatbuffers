/**
 * Multiply Plugin
 *
 * Multiplies input value by 10
 */

#include "plugin_interface.h"

int multiply_process(const Input* input, Output* output) {
  output->value = static_cast<uint32_t>(input->value) * 10;
  return 0;  // Success
}

DECLARE_PLUGIN(multiply_process)
