#pragma once

/**
 * Plugin Interface
 *
 * Plugins implement this interface to be loaded by the core runtime.
 * The core runtime calls plugins through function pointers stored in
 * a well-known memory location (the plugin table).
 */

#include "plugin_api_aligned.h"

using namespace PluginAPI::Aligned;

// Plugin function signature
// Takes pointer to Input buffer, pointer to Output buffer
// Returns 0 on success, non-zero on error
typedef int (*PluginProcessFn)(const Input* input, Output* output);

// Plugin table entry - stored at well-known offset in each plugin's memory
struct PluginTableEntry {
  uint32_t magic;           // Magic number to verify valid plugin: 0x504C5547 ("PLUG")
  uint32_t version;         // Plugin API version
  PluginProcessFn process;  // Function pointer to process()

  static constexpr uint32_t MAGIC = 0x504C5547;  // "PLUG"
  static constexpr uint32_t API_VERSION = 1;
};

// Well-known offset where plugin table is stored
// Plugins must place their PluginTableEntry at this address
constexpr size_t PLUGIN_TABLE_OFFSET = 1024;

// Shared buffer offsets (in plugin's linear memory)
constexpr size_t INPUT_BUFFER_OFFSET = 2048;
constexpr size_t OUTPUT_BUFFER_OFFSET = 2048 + INPUT_SIZE;

// Macro to declare plugin entry point
#define DECLARE_PLUGIN(process_fn) \
  extern "C" { \
    __attribute__((export_name("get_plugin_table"))) \
    PluginTableEntry* get_plugin_table() { \
      static PluginTableEntry entry = { \
        PluginTableEntry::MAGIC, \
        PluginTableEntry::API_VERSION, \
        process_fn \
      }; \
      return &entry; \
    } \
    \
    __attribute__((export_name("get_input_buffer"))) \
    Input* get_input_buffer() { \
      static Input input; \
      return &input; \
    } \
    \
    __attribute__((export_name("get_output_buffer"))) \
    Output* get_output_buffer() { \
      static Output output; \
      return &output; \
    } \
    \
    __attribute__((export_name("process"))) \
    int process() { \
      return process_fn(get_input_buffer(), get_output_buffer()); \
    } \
  }
