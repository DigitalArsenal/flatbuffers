/**
 * Addition Plugin
 *
 * Adds 10 to input value
 */

#include "plugin_interface.h"

int addition_process(const Input* input, Output* output) {
  output->value = static_cast<uint32_t>(input->value) + 10;
  return 0;  // Success
}

DECLARE_PLUGIN(addition_process)
