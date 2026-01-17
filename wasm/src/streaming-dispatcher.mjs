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
