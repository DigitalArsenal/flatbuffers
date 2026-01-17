#pragma once
/**
 * Streaming Message Dispatcher for FlatBuffers
 *
 * Parses size-prefixed FlatBuffers from a byte stream and routes them
 * to typed storage based on the 4-byte file identifier.
 *
 * Wire format (per message):
 *   [size:4][file_id:4][flatbuffer_data:size-4]
 *
 * The dispatcher maintains separate ring buffers for each registered
 * message type, enabling zero-copy access to the most recent messages.
 */

#include <cstdint>
#include <cstddef>
#include <cstring>

namespace flatbuffers {
namespace streaming {

// File identifier is always 4 bytes
constexpr size_t FILE_ID_LENGTH = 4;

// Maximum number of message types that can be registered
constexpr size_t MAX_MESSAGE_TYPES = 32;

// Default ring buffer capacity per message type
constexpr size_t DEFAULT_RING_CAPACITY = 64;

/**
 * Message type registration entry
 */
struct MessageTypeEntry {
  char file_id[FILE_ID_LENGTH + 1];  // null-terminated file identifier
  uint8_t* buffer;                    // ring buffer for this type
  size_t buffer_size;                 // total buffer size in bytes
  size_t message_size;                // size of each message (0 = variable)
  size_t capacity;                    // max messages in ring buffer
  size_t head;                        // next write position
  size_t count;                       // number of messages stored
  size_t total_received;              // total messages received (monotonic)
};

/**
 * Parse result codes
 */
enum class ParseResult : int32_t {
  OK = 0,
  NEED_MORE_DATA = 1,      // Incomplete message, need more bytes
  UNKNOWN_TYPE = 2,        // File ID not registered
  BUFFER_FULL = 3,         // Ring buffer is full (shouldn't happen with ring)
  INVALID_SIZE = 4,        // Size field is invalid
  MESSAGE_TOO_LARGE = 5,   // Message exceeds max size
};

/**
 * Streaming Message Dispatcher
 *
 * Usage:
 *   1. Register message types with register_type()
 *   2. Feed bytes with push_bytes()
 *   3. Access messages with get_message() or iterate with get_message_count()
 */
class MessageDispatcher {
public:
  MessageDispatcher() : type_count_(0), input_buffer_(nullptr),
                        input_size_(0), input_capacity_(0) {
    memset(types_, 0, sizeof(types_));
  }

  /**
   * Register a message type for routing
   *
   * @param file_id 4-character file identifier
   * @param buffer Pre-allocated buffer for storing messages
   * @param buffer_size Size of the buffer in bytes
   * @param message_size Fixed size per message (0 for variable-length)
   * @return Type index (0-31) or -1 on error
   */
  int register_type(const char* file_id, uint8_t* buffer, size_t buffer_size,
                    size_t message_size) {
    if (type_count_ >= MAX_MESSAGE_TYPES) return -1;
    if (strlen(file_id) != FILE_ID_LENGTH) return -1;

    MessageTypeEntry& entry = types_[type_count_];
    memcpy(entry.file_id, file_id, FILE_ID_LENGTH);
    entry.file_id[FILE_ID_LENGTH] = '\0';
    entry.buffer = buffer;
    entry.buffer_size = buffer_size;
    entry.message_size = message_size;
    entry.capacity = message_size > 0 ? buffer_size / message_size : 0;
    entry.head = 0;
    entry.count = 0;
    entry.total_received = 0;

    return type_count_++;
  }

  /**
   * Set the input buffer for streaming data
   * This buffer is used to accumulate partial messages
   */
  void set_input_buffer(uint8_t* buffer, size_t capacity) {
    input_buffer_ = buffer;
    input_capacity_ = capacity;
    input_size_ = 0;
  }

  /**
   * Push bytes into the dispatcher and parse any complete messages
   *
   * @param data Incoming bytes
   * @param size Number of bytes
   * @return Number of complete messages parsed
   */
  int push_bytes(const uint8_t* data, size_t size) {
    if (!input_buffer_) return -1;

    // Append to input buffer
    size_t to_copy = size;
    if (input_size_ + size > input_capacity_) {
      to_copy = input_capacity_ - input_size_;
    }
    memcpy(input_buffer_ + input_size_, data, to_copy);
    input_size_ += to_copy;

    // Parse complete messages
    int messages_parsed = 0;
    size_t offset = 0;

    while (offset + 8 <= input_size_) {  // Need at least size + file_id
      // Read size prefix (little-endian)
      uint32_t msg_size = read_u32_le(input_buffer_ + offset);

      // Validate size
      if (msg_size < FILE_ID_LENGTH) {
        // Invalid size - skip this byte and try to resync
        offset++;
        continue;
      }

      // Check if we have the complete message
      if (offset + 4 + msg_size > input_size_) {
        break;  // Need more data
      }

      // Extract file identifier
      const char* file_id = reinterpret_cast<const char*>(
          input_buffer_ + offset + 4);

      // Find registered type
      int type_index = find_type(file_id);
      if (type_index >= 0) {
        // Store the message (including file_id and data, excluding size prefix)
        store_message(type_index, input_buffer_ + offset + 4, msg_size);
        messages_parsed++;
      }

      offset += 4 + msg_size;
    }

    // Compact input buffer
    if (offset > 0) {
      memmove(input_buffer_, input_buffer_ + offset, input_size_ - offset);
      input_size_ -= offset;
    }

    return messages_parsed;
  }

  /**
   * Get the number of stored messages for a type
   */
  size_t get_message_count(int type_index) const {
    if (type_index < 0 || type_index >= type_count_) return 0;
    return types_[type_index].count;
  }

  /**
   * Get total messages received for a type (monotonic counter)
   */
  size_t get_total_received(int type_index) const {
    if (type_index < 0 || type_index >= type_count_) return 0;
    return types_[type_index].total_received;
  }

  /**
   * Get a pointer to a stored message
   *
   * @param type_index Type index from register_type()
   * @param index Message index (0 = oldest, count-1 = newest)
   * @return Pointer to message data or nullptr
   */
  const uint8_t* get_message(int type_index, size_t index) const {
    if (type_index < 0 || type_index >= type_count_) return nullptr;
    const MessageTypeEntry& entry = types_[type_index];
    if (index >= entry.count) return nullptr;

    // Ring buffer index calculation
    size_t ring_index;
    if (entry.count < entry.capacity) {
      ring_index = index;
    } else {
      ring_index = (entry.head + index) % entry.capacity;
    }

    return entry.buffer + ring_index * entry.message_size;
  }

  /**
   * Get the most recent message for a type
   */
  const uint8_t* get_latest_message(int type_index) const {
    if (type_index < 0 || type_index >= type_count_) return nullptr;
    const MessageTypeEntry& entry = types_[type_index];
    if (entry.count == 0) return nullptr;

    size_t latest_index = (entry.head + entry.capacity - 1) % entry.capacity;
    return entry.buffer + latest_index * entry.message_size;
  }

  /**
   * Clear all stored messages for a type
   */
  void clear_messages(int type_index) {
    if (type_index < 0 || type_index >= type_count_) return;
    MessageTypeEntry& entry = types_[type_index];
    entry.head = 0;
    entry.count = 0;
  }

  /**
   * Get type entry for inspection
   */
  const MessageTypeEntry* get_type_entry(int type_index) const {
    if (type_index < 0 || type_index >= type_count_) return nullptr;
    return &types_[type_index];
  }

  /**
   * Find type index by file identifier
   */
  int find_type(const char* file_id) const {
    for (int i = 0; i < type_count_; i++) {
      if (memcmp(types_[i].file_id, file_id, FILE_ID_LENGTH) == 0) {
        return i;
      }
    }
    return -1;
  }

  /**
   * Get number of registered types
   */
  int get_type_count() const { return type_count_; }

  /**
   * Reset the dispatcher (clear all state)
   */
  void reset() {
    for (int i = 0; i < type_count_; i++) {
      types_[i].head = 0;
      types_[i].count = 0;
      types_[i].total_received = 0;
    }
    input_size_ = 0;
  }

private:
  static uint32_t read_u32_le(const uint8_t* data) {
    return static_cast<uint32_t>(data[0]) |
           (static_cast<uint32_t>(data[1]) << 8) |
           (static_cast<uint32_t>(data[2]) << 16) |
           (static_cast<uint32_t>(data[3]) << 24);
  }

  void store_message(int type_index, const uint8_t* data, size_t size) {
    MessageTypeEntry& entry = types_[type_index];

    // For fixed-size messages, store at ring buffer position
    if (entry.message_size > 0 && entry.capacity > 0) {
      size_t store_size = entry.message_size;
      if (size < store_size) {
        // Zero-pad if message is smaller
        memset(entry.buffer + entry.head * store_size, 0, store_size);
      }
      memcpy(entry.buffer + entry.head * store_size, data,
             size < store_size ? size : store_size);

      entry.head = (entry.head + 1) % entry.capacity;
      if (entry.count < entry.capacity) {
        entry.count++;
      }
    }

    entry.total_received++;
  }

  MessageTypeEntry types_[MAX_MESSAGE_TYPES];
  int type_count_;

  uint8_t* input_buffer_;
  size_t input_size_;
  size_t input_capacity_;
};

}  // namespace streaming
}  // namespace flatbuffers
