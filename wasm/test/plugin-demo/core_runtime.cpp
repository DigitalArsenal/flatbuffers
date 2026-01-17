/**
 * Core Runtime
 *
 * Contains the event loop that calls plugins.
 * The runtime is itself a WASM module that:
 * 1. Has function pointers to plugin methods (set by JS host)
 * 2. Runs an event loop calling the active plugin
 * 3. Uses aligned buffers for zero-copy data exchange
 */

#include "plugin_api_aligned.h"
#include <emscripten.h>

using namespace PluginAPI::Aligned;

// Plugin function pointer type
typedef int (*PluginProcessFn)();

// Current active plugin's process function
static PluginProcessFn g_active_plugin = nullptr;

// Shared I/O buffers (plugins read/write to these)
static Input g_input;
static Output g_output;

// Event loop state
static bool g_running = false;
static uint32_t g_tick_count = 0;

extern "C" {

// Get pointers to shared buffers (for JS to create views)
EMSCRIPTEN_KEEPALIVE
Input* get_input_ptr() {
  return &g_input;
}

EMSCRIPTEN_KEEPALIVE
Output* get_output_ptr() {
  return &g_output;
}

EMSCRIPTEN_KEEPALIVE
size_t get_input_size() {
  return sizeof(Input);
}

EMSCRIPTEN_KEEPALIVE
size_t get_output_size() {
  return sizeof(Output);
}

// Register a plugin by its process function pointer
// In real use, this would be a table index for indirect calls
EMSCRIPTEN_KEEPALIVE
void register_plugin(PluginProcessFn process_fn) {
  g_active_plugin = process_fn;
}

// Set input value (convenience for testing)
EMSCRIPTEN_KEEPALIVE
void set_input(uint16_t value) {
  g_input.value = value;
}

// Get output value (convenience for testing)
EMSCRIPTEN_KEEPALIVE
uint32_t get_output() {
  return g_output.value;
}

// Single tick of the event loop
// Returns 0 on success, -1 if no plugin, plugin error code otherwise
EMSCRIPTEN_KEEPALIVE
int tick() {
  if (!g_active_plugin) {
    return -1;  // No plugin registered
  }

  g_tick_count++;

  // Call the active plugin's process function
  // The plugin reads from g_input and writes to g_output
  return g_active_plugin();
}

// Run event loop for N iterations
// Returns number of successful ticks
EMSCRIPTEN_KEEPALIVE
uint32_t run_loop(uint32_t iterations) {
  uint32_t success_count = 0;

  for (uint32_t i = 0; i < iterations; i++) {
    if (tick() == 0) {
      success_count++;
    }
  }

  return success_count;
}

// Get tick count
EMSCRIPTEN_KEEPALIVE
uint32_t get_tick_count() {
  return g_tick_count;
}

// Reset tick count
EMSCRIPTEN_KEEPALIVE
void reset_tick_count() {
  g_tick_count = 0;
}

}  // extern "C"
