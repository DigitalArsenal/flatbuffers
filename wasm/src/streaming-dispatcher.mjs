/**
 * Streaming Message Dispatcher for FlatBuffers
 *
 * Parses size-prefixed FlatBuffers from a byte stream and routes them
 * to typed storage based on the 4-byte file identifier.
 *
 * @module streaming-dispatcher
 */

/**
 * Message type registration info
 * @typedef {Object} MessageTypeInfo
 * @property {string} fileId - 4-character file identifier
 * @property {number} typeIndex - Index returned from registration
 * @property {number} messageSize - Fixed size per message in bytes
 * @property {number} capacity - Max messages in ring buffer
 * @property {number} bufferPtr - Pointer to storage buffer in WASM memory
 */

/**
 * Dispatcher statistics
 * @typedef {Object} DispatcherStats
 * @property {number} count - Current number of stored messages
 * @property {number} totalReceived - Total messages received (monotonic)
 */

/**
 * High-level wrapper for the streaming message dispatcher.
 * Manages WASM module lifecycle and provides typed access to messages.
 */
export class StreamingDispatcher {
  /**
   * @param {Object} wasmModule - Initialized WASM module with dispatcher exports
   */
  constructor(wasmModule) {
    this._wasm = wasmModule;
    this._types = new Map(); // fileId -> MessageTypeInfo
    this._typesByIndex = new Map(); // typeIndex -> MessageTypeInfo
    this._encryptionContexts = new Map(); // fileId -> EncryptionContext (Task 45)
    this._sequenceCounter = 0n; // Monotonic counter for replay protection (Task 38)
    this._textEncoder = new TextEncoder();
    this._textDecoder = new TextDecoder();

    // Initialize dispatcher
    this._wasm._dispatcher_init();
  }

  /**
   * Register a message type for routing
   *
   * @param {string} fileId - 4-character file identifier (e.g., "MON1")
   * @param {number} messageSize - Fixed size of each message in bytes
   * @param {number} [capacity=64] - Number of messages to store in ring buffer
   * @returns {MessageTypeInfo} Registration info
   * @throws {Error} If fileId is not 4 characters or registration fails
   */
  registerType(fileId, messageSize, capacity = 64) {
    if (fileId.length !== 4) {
      throw new Error(`File identifier must be exactly 4 characters: "${fileId}"`);
    }

    if (this._types.has(fileId)) {
      return this._types.get(fileId);
    }

    // Allocate buffer in WASM memory
    const bufferSize = messageSize * capacity;
    const bufferPtr = this._wasm._malloc(bufferSize);
    if (!bufferPtr) {
      throw new Error('Failed to allocate message buffer');
    }

    // Write file ID to temporary WASM memory
    const fileIdPtr = this._wasm._malloc(5);
    const fileIdBytes = this._textEncoder.encode(fileId);
    this._wasm.HEAPU8.set(fileIdBytes, fileIdPtr);
    this._wasm.HEAPU8[fileIdPtr + 4] = 0; // null terminator

    // Register with dispatcher
    const typeIndex = this._wasm._dispatcher_register_type(
      fileIdPtr, bufferPtr, bufferSize, messageSize
    );

    this._wasm._free(fileIdPtr);

    if (typeIndex < 0) {
      this._wasm._free(bufferPtr);
      throw new Error(`Failed to register type "${fileId}"`);
    }

    const info = {
      fileId,
      typeIndex,
      messageSize,
      capacity,
      bufferPtr,
    };

    this._types.set(fileId, info);
    this._typesByIndex.set(typeIndex, info);

    return info;
  }

  /**
   * Set an EncryptionContext for a specific message type (Task 45).
   * Enables per-type encryption keys for stream multiplexing.
   * @param {string} fileId - 4-character file identifier
   * @param {Object} ctx - EncryptionContext instance
   */
  setEncryptionContext(fileId, ctx) {
    this._encryptionContexts.set(fileId, ctx);
  }

  /**
   * Get the EncryptionContext for a specific message type.
   * @param {string} fileId
   * @returns {Object|undefined}
   */
  getEncryptionContext(fileId) {
    return this._encryptionContexts.get(fileId);
  }

  /**
   * Get and increment the monotonic sequence counter (Task 38).
   * @returns {bigint}
   */
  nextSequenceNumber() {
    return ++this._sequenceCounter;
  }

  /**
   * Push bytes into the dispatcher for parsing
   *
   * @param {Uint8Array} data - Incoming bytes (size-prefixed FlatBuffers)
   * @returns {number} Number of complete messages parsed
   */
  pushBytes(data) {
    // Copy data to WASM memory
    const ptr = this._wasm._malloc(data.length);
    if (!ptr) {
      throw new Error('Failed to allocate memory for input data');
    }

    this._wasm.HEAPU8.set(data, ptr);
    const result = this._wasm._dispatcher_push_bytes(ptr, data.length);
    this._wasm._free(ptr);

    return result;
  }

  /**
   * Push bytes directly using the input buffer (zero-copy for large streams)
   *
   * @param {number} size - Number of bytes written to input buffer
   * @returns {number} Number of complete messages parsed
   */
  pushBytesFromInputBuffer(size) {
    const inputBuffer = this._wasm._dispatcher_get_input_buffer();
    return this._wasm._dispatcher_push_bytes(inputBuffer, size);
  }

  /**
   * Get the input buffer for direct writes
   *
   * @returns {{ ptr: number, size: number, view: Uint8Array }}
   */
  getInputBuffer() {
    const ptr = this._wasm._dispatcher_get_input_buffer();
    const size = this._wasm._dispatcher_get_input_buffer_size();
    return {
      ptr,
      size,
      view: new Uint8Array(this._wasm.HEAPU8.buffer, ptr, size),
    };
  }

  /**
   * Get statistics for a message type
   *
   * @param {string} fileId - File identifier
   * @returns {DispatcherStats|null}
   */
  getStats(fileId) {
    const info = this._types.get(fileId);
    if (!info) return null;

    return {
      count: this._wasm._dispatcher_get_message_count(info.typeIndex),
      totalReceived: this._wasm._dispatcher_get_total_received(info.typeIndex),
    };
  }

  /**
   * Get the number of stored messages for a type
   *
   * @param {string} fileId - File identifier
   * @returns {number}
   */
  getMessageCount(fileId) {
    const info = this._types.get(fileId);
    if (!info) return 0;
    return this._wasm._dispatcher_get_message_count(info.typeIndex);
  }

  /**
   * Get a stored message as a Uint8Array view
   *
   * @param {string} fileId - File identifier
   * @param {number} index - Message index (0 = oldest)
   * @returns {Uint8Array|null} View into WASM memory (valid until next push)
   */
  getMessage(fileId, index) {
    const info = this._types.get(fileId);
    if (!info) return null;

    const ptr = this._wasm._dispatcher_get_message(info.typeIndex, index);
    if (!ptr) return null;

    // Return a view into WASM memory (zero-copy)
    return new Uint8Array(this._wasm.HEAPU8.buffer, ptr, info.messageSize);
  }

  /**
   * Get the most recent message
   *
   * @param {string} fileId - File identifier
   * @returns {Uint8Array|null}
   */
  getLatestMessage(fileId) {
    const info = this._types.get(fileId);
    if (!info) return null;

    const ptr = this._wasm._dispatcher_get_latest_message(info.typeIndex);
    if (!ptr) return null;

    return new Uint8Array(this._wasm.HEAPU8.buffer, ptr, info.messageSize);
  }

  /**
   * Get a DataView for a stored message (for reading FlatBuffer fields)
   *
   * @param {string} fileId - File identifier
   * @param {number} index - Message index
   * @returns {DataView|null}
   */
  getMessageView(fileId, index) {
    const info = this._types.get(fileId);
    if (!info) return null;

    const ptr = this._wasm._dispatcher_get_message(info.typeIndex, index);
    if (!ptr) return null;

    return new DataView(this._wasm.HEAPU8.buffer, ptr, info.messageSize);
  }

  /**
   * Clear all stored messages for a type
   *
   * @param {string} fileId - File identifier
   */
  clearMessages(fileId) {
    const info = this._types.get(fileId);
    if (info) {
      this._wasm._dispatcher_clear_messages(info.typeIndex);
    }
  }

  /**
   * Get all registered type info
   *
   * @returns {MessageTypeInfo[]}
   */
  getRegisteredTypes() {
    return Array.from(this._types.values());
  }

  /**
   * Reset the dispatcher (clear all messages but keep registrations)
   */
  reset() {
    this._wasm._dispatcher_reset();
  }

  /**
   * Iterate over all messages of a type
   *
   * @param {string} fileId - File identifier
   * @yields {Uint8Array} Message data
   */
  *iterMessages(fileId) {
    const count = this.getMessageCount(fileId);
    for (let i = 0; i < count; i++) {
      yield this.getMessage(fileId, i);
    }
  }

  // =========================================================================
  // Batch Operations
  // =========================================================================

  /**
   * Get a range of messages
   *
   * @param {string} fileId - File identifier
   * @param {number} startIndex - Start index (inclusive)
   * @param {number} endIndex - End index (exclusive)
   * @returns {Uint8Array[]} Array of message views
   */
  getMessageRange(fileId, startIndex, endIndex) {
    const count = this.getMessageCount(fileId);
    const start = Math.max(0, startIndex);
    const end = Math.min(count, endIndex);
    const result = [];
    for (let i = start; i < end; i++) {
      const msg = this.getMessage(fileId, i);
      if (msg) result.push(msg);
    }
    return result;
  }

  /**
   * Get the N most recent messages
   *
   * @param {string} fileId - File identifier
   * @param {number} n - Number of messages to retrieve
   * @returns {Uint8Array[]} Array of message views (newest last)
   */
  getLastN(fileId, n) {
    const count = this.getMessageCount(fileId);
    const start = Math.max(0, count - n);
    return this.getMessageRange(fileId, start, count);
  }

  /**
   * Get all stored messages as an array
   *
   * @param {string} fileId - File identifier
   * @returns {Uint8Array[]} Array of all message views
   */
  getAllMessages(fileId) {
    return Array.from(this.iterMessages(fileId));
  }

  // =========================================================================
  // Statistics
  // =========================================================================

  /**
   * Get statistics for all registered types
   *
   * @returns {Object.<string, DispatcherStats>} Stats keyed by fileId
   */
  getAllStats() {
    const stats = {};
    for (const [fileId] of this._types) {
      stats[fileId] = this.getStats(fileId);
    }
    return stats;
  }

  /**
   * Get the number of messages dropped due to ring buffer overflow
   *
   * @param {string} fileId - File identifier
   * @returns {number} Number of dropped messages
   */
  getDroppedCount(fileId) {
    const info = this._types.get(fileId);
    if (!info) return 0;

    const stats = this.getStats(fileId);
    if (!stats) return 0;

    // Dropped = total received - capacity (if overflowed)
    return Math.max(0, stats.totalReceived - info.capacity);
  }

  /**
   * Get buffer utilization for a type
   *
   * @param {string} fileId - File identifier
   * @returns {{ used: number, capacity: number, percent: number }|null}
   */
  getBufferUtilization(fileId) {
    const info = this._types.get(fileId);
    if (!info) return null;

    const count = this.getMessageCount(fileId);
    return {
      used: count,
      capacity: info.capacity,
      percent: info.capacity > 0 ? (count / info.capacity) * 100 : 0,
    };
  }

  // =========================================================================
  // Encryption
  // =========================================================================

  /**
   * Set encryption configuration for the dispatcher.
   * When active, (encrypted) fields in stored messages are encrypted/decrypted.
   *
   * @param {Uint8Array} publicKey - 32-byte encryption key
   * @param {Object} [config={}] - Additional config (schema, direction, etc.)
   * @returns {boolean} true on success
   */
  setEncryption(publicKey, config = {}) {
    if (!publicKey || publicKey.length < 32) {
      throw new Error('Encryption key must be at least 32 bytes');
    }

    // Copy key to WASM memory
    const keyPtr = this._wasm._malloc(publicKey.length);
    if (!keyPtr) throw new Error('Failed to allocate memory for encryption key');
    this._wasm.HEAPU8.set(publicKey, keyPtr);

    // Copy schema data if provided
    let schemaPtr = 0;
    let schemaSize = 0;
    if (config.schema) {
      schemaSize = config.schema.length;
      schemaPtr = this._wasm._malloc(schemaSize);
      if (schemaPtr) {
        this._wasm.HEAPU8.set(config.schema, schemaPtr);
      }
    }

    const result = this._wasm._dispatcher_set_encryption(
      keyPtr, publicKey.length, schemaPtr, schemaSize
    );

    this._wasm._free(keyPtr);
    if (schemaPtr) this._wasm._free(schemaPtr);

    this._encryptionActive = result === 0;
    this._encryptionConfig = config;
    return result === 0;
  }

  /**
   * Clear encryption state, securely zeroing key material.
   * Subsequent messages will be processed in plaintext.
   */
  clearEncryption() {
    this._wasm._dispatcher_clear_encryption();
    this._encryptionActive = false;
    this._encryptionConfig = null;
  }

  /**
   * Check if encryption is currently active.
   * @returns {boolean}
   */
  isEncryptionActive() {
    return this._wasm._dispatcher_is_encryption_active() === 1;
  }

  // =========================================================================
  // Convenience Methods
  // =========================================================================

  /**
   * Check if a type is registered
   *
   * @param {string} fileId - File identifier
   * @returns {boolean}
   */
  isTypeRegistered(fileId) {
    return this._types.has(fileId);
  }

  /**
   * Get full type information
   *
   * @param {string} fileId - File identifier
   * @returns {MessageTypeInfo|null}
   */
  getTypeInfo(fileId) {
    return this._types.get(fileId) || null;
  }

  /**
   * Iterate over messages with a callback
   *
   * @param {string} fileId - File identifier
   * @param {function(Uint8Array, number): void} callback - Called for each message with (data, index)
   */
  forEachMessage(fileId, callback) {
    const count = this.getMessageCount(fileId);
    for (let i = 0; i < count; i++) {
      const msg = this.getMessage(fileId, i);
      if (msg) callback(msg, i);
    }
  }
}

/**
 * Create a size-prefixed FlatBuffer message for testing
 *
 * @param {string} fileId - 4-character file identifier
 * @param {Uint8Array} data - FlatBuffer data (root offset + payload)
 * @returns {Uint8Array} Size-prefixed message
 */
export function createSizePrefixedMessage(fileId, data) {
  if (fileId.length !== 4) {
    throw new Error('File identifier must be 4 characters');
  }

  // Size includes file_id + data
  const size = 4 + data.length;
  const result = new Uint8Array(4 + size);

  // Write size (little-endian)
  result[0] = size & 0xff;
  result[1] = (size >> 8) & 0xff;
  result[2] = (size >> 16) & 0xff;
  result[3] = (size >> 24) & 0xff;

  // Write file identifier
  const encoder = new TextEncoder();
  const fileIdBytes = encoder.encode(fileId);
  result.set(fileIdBytes, 4);

  // Write data
  result.set(data, 8);

  return result;
}

/**
 * Concatenate multiple size-prefixed messages into a stream
 *
 * @param  {...Uint8Array} messages - Size-prefixed messages
 * @returns {Uint8Array}
 */
export function concatMessages(...messages) {
  const totalSize = messages.reduce((sum, m) => sum + m.length, 0);
  const result = new Uint8Array(totalSize);
  let offset = 0;
  for (const msg of messages) {
    result.set(msg, offset);
    offset += msg.length;
  }
  return result;
}

export default StreamingDispatcher;
