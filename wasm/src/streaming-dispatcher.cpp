/**
 * WASM exports for the Streaming Message Dispatcher
 *
 * Compile with emcc:
 *   emcc streaming-dispatcher.cpp -o streaming-dispatcher.mjs \
 *     -s EXPORTED_FUNCTIONS=[...] -s MODULARIZE=1 -s EXPORT_ES6=1
 */

#include "streaming-dispatcher.h"

using namespace flatbuffers::streaming;

// Global dispatcher instance
static MessageDispatcher g_dispatcher;

// Pre-allocated buffers (can be customized per-type)
// These are in WASM linear memory and accessible from JS
static constexpr size_t INPUT_BUFFER_SIZE = 64 * 1024;  // 64KB input buffer
static uint8_t g_input_buffer[INPUT_BUFFER_SIZE];

extern "C" {

// ============================================================================
// Dispatcher lifecycle
// ============================================================================

/**
 * Initialize the dispatcher with the input buffer
 */
__attribute__((export_name("dispatcher_init")))
void dispatcher_init() {
  g_dispatcher.set_input_buffer(g_input_buffer, INPUT_BUFFER_SIZE);
}

/**
 * Reset all dispatcher state
 */
__attribute__((export_name("dispatcher_reset")))
void dispatcher_reset() {
  g_dispatcher.reset();
}

/**
 * Get the number of registered types
 */
__attribute__((export_name("dispatcher_get_type_count")))
int dispatcher_get_type_count() {
  return g_dispatcher.get_type_count();
}

// ============================================================================
// Type registration
// ============================================================================

/**
 * Register a message type
 *
 * @param file_id_ptr Pointer to 4-byte file identifier
 * @param buffer_ptr Pointer to pre-allocated storage buffer
 * @param buffer_size Size of buffer in bytes
 * @param message_size Size of each message (fixed)
 * @return Type index (0-31) or -1 on error
 */
__attribute__((export_name("dispatcher_register_type")))
int dispatcher_register_type(const char* file_id_ptr, uint8_t* buffer_ptr,
                             size_t buffer_size, size_t message_size) {
  return g_dispatcher.register_type(file_id_ptr, buffer_ptr, buffer_size,
                                    message_size);
}

/**
 * Find a type index by file identifier
 */
__attribute__((export_name("dispatcher_find_type")))
int dispatcher_find_type(const char* file_id_ptr) {
  return g_dispatcher.find_type(file_id_ptr);
}

// ============================================================================
// Message ingestion
// ============================================================================

/**
 * Get pointer to input buffer for direct writes
 */
__attribute__((export_name("dispatcher_get_input_buffer")))
uint8_t* dispatcher_get_input_buffer() {
  return g_input_buffer;
}

/**
 * Get input buffer capacity
 */
__attribute__((export_name("dispatcher_get_input_buffer_size")))
size_t dispatcher_get_input_buffer_size() {
  return INPUT_BUFFER_SIZE;
}

/**
 * Push bytes into the dispatcher and parse messages
 *
 * @param data_ptr Pointer to incoming bytes
 * @param size Number of bytes
 * @return Number of messages parsed, or -1 on error
 */
__attribute__((export_name("dispatcher_push_bytes")))
int dispatcher_push_bytes(const uint8_t* data_ptr, size_t size) {
  return g_dispatcher.push_bytes(data_ptr, size);
}

// ============================================================================
// Message access
// ============================================================================

/**
 * Get the number of messages stored for a type
 */
__attribute__((export_name("dispatcher_get_message_count")))
size_t dispatcher_get_message_count(int type_index) {
  return g_dispatcher.get_message_count(type_index);
}

/**
 * Get total messages received for a type (monotonic counter)
 */
__attribute__((export_name("dispatcher_get_total_received")))
size_t dispatcher_get_total_received(int type_index) {
  return g_dispatcher.get_total_received(type_index);
}

/**
 * Get pointer to a stored message
 *
 * @param type_index Type index from register
 * @param index Message index (0 = oldest)
 * @return Pointer to message or 0 (null)
 */
__attribute__((export_name("dispatcher_get_message")))
const uint8_t* dispatcher_get_message(int type_index, size_t index) {
  return g_dispatcher.get_message(type_index, index);
}

/**
 * Get pointer to the most recent message
 */
__attribute__((export_name("dispatcher_get_latest_message")))
const uint8_t* dispatcher_get_latest_message(int type_index) {
  return g_dispatcher.get_latest_message(type_index);
}

/**
 * Clear all messages for a type
 */
__attribute__((export_name("dispatcher_clear_messages")))
void dispatcher_clear_messages(int type_index) {
  g_dispatcher.clear_messages(type_index);
}

// ============================================================================
// Type info accessors
// ============================================================================

/**
 * Get the file identifier for a registered type
 */
__attribute__((export_name("dispatcher_get_type_file_id")))
const char* dispatcher_get_type_file_id(int type_index) {
  const MessageTypeEntry* entry = g_dispatcher.get_type_entry(type_index);
  return entry ? entry->file_id : nullptr;
}

/**
 * Get the buffer pointer for a type
 */
__attribute__((export_name("dispatcher_get_type_buffer")))
const uint8_t* dispatcher_get_type_buffer(int type_index) {
  const MessageTypeEntry* entry = g_dispatcher.get_type_entry(type_index);
  return entry ? entry->buffer : nullptr;
}

/**
 * Get the message size for a type
 */
__attribute__((export_name("dispatcher_get_type_message_size")))
size_t dispatcher_get_type_message_size(int type_index) {
  const MessageTypeEntry* entry = g_dispatcher.get_type_entry(type_index);
  return entry ? entry->message_size : 0;
}

/**
 * Get the capacity for a type
 */
__attribute__((export_name("dispatcher_get_type_capacity")))
size_t dispatcher_get_type_capacity(int type_index) {
  const MessageTypeEntry* entry = g_dispatcher.get_type_entry(type_index);
  return entry ? entry->capacity : 0;
}

}  // extern "C"
