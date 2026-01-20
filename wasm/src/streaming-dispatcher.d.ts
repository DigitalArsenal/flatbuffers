/**
 * Streaming Message Dispatcher for FlatBuffers
 *
 * Parses size-prefixed FlatBuffers from a byte stream and routes them
 * to typed storage based on the 4-byte file identifier.
 */

/**
 * Message type registration info
 */
export interface MessageTypeInfo {
  /** 4-character file identifier */
  fileId: string;
  /** Index returned from registration */
  typeIndex: number;
  /** Fixed size per message in bytes */
  messageSize: number;
  /** Max messages in ring buffer */
  capacity: number;
  /** Pointer to storage buffer in WASM memory */
  bufferPtr: number;
}

/**
 * Dispatcher statistics for a message type
 */
export interface DispatcherStats {
  /** Current number of stored messages */
  count: number;
  /** Total messages received (monotonic counter) */
  totalReceived: number;
}

/**
 * Input buffer info for direct writes
 */
export interface InputBufferInfo {
  /** Pointer in WASM memory */
  ptr: number;
  /** Buffer capacity in bytes */
  size: number;
  /** Uint8Array view for writing */
  view: Uint8Array;
}

/**
 * WASM module interface expected by StreamingDispatcher
 */
export interface DispatcherWasmModule {
  HEAPU8: Uint8Array;
  _malloc(size: number): number;
  _free(ptr: number): void;
  _dispatcher_init(): void;
  _dispatcher_reset(): void;
  _dispatcher_get_type_count(): number;
  _dispatcher_register_type(
    fileIdPtr: number,
    bufferPtr: number,
    bufferSize: number,
    messageSize: number
  ): number;
  _dispatcher_find_type(fileIdPtr: number): number;
  _dispatcher_get_input_buffer(): number;
  _dispatcher_get_input_buffer_size(): number;
  _dispatcher_push_bytes(dataPtr: number, size: number): number;
  _dispatcher_get_message_count(typeIndex: number): number;
  _dispatcher_get_total_received(typeIndex: number): number;
  _dispatcher_get_message(typeIndex: number, index: number): number;
  _dispatcher_get_latest_message(typeIndex: number): number;
  _dispatcher_clear_messages(typeIndex: number): void;
  _dispatcher_get_type_file_id(typeIndex: number): number;
  _dispatcher_get_type_buffer(typeIndex: number): number;
  _dispatcher_get_type_message_size(typeIndex: number): number;
  _dispatcher_get_type_capacity(typeIndex: number): number;
}

/**
 * High-level wrapper for the streaming message dispatcher.
 * Manages WASM module lifecycle and provides typed access to messages.
 */
export declare class StreamingDispatcher {
  /**
   * Create a new dispatcher wrapping a WASM module
   * @param wasmModule - Initialized WASM module with dispatcher exports
   */
  constructor(wasmModule: DispatcherWasmModule);

  /**
   * Register a message type for routing
   *
   * @param fileId - 4-character file identifier (e.g., "MON1")
   * @param messageSize - Fixed size of each message in bytes
   * @param capacity - Number of messages to store in ring buffer (default: 64)
   * @returns Registration info
   * @throws Error if fileId is not 4 characters or registration fails
   */
  registerType(
    fileId: string,
    messageSize: number,
    capacity?: number
  ): MessageTypeInfo;

  /**
   * Push bytes into the dispatcher for parsing
   *
   * @param data - Incoming bytes (size-prefixed FlatBuffers)
   * @returns Number of complete messages parsed
   */
  pushBytes(data: Uint8Array): number;

  /**
   * Push bytes directly using the input buffer (zero-copy for large streams)
   *
   * @param size - Number of bytes written to input buffer
   * @returns Number of complete messages parsed
   */
  pushBytesFromInputBuffer(size: number): number;

  /**
   * Get the input buffer for direct writes
   */
  getInputBuffer(): InputBufferInfo;

  /**
   * Get statistics for a message type
   */
  getStats(fileId: string): DispatcherStats | null;

  /**
   * Get the number of stored messages for a type
   */
  getMessageCount(fileId: string): number;

  /**
   * Get a stored message as a Uint8Array view
   *
   * @param fileId - File identifier
   * @param index - Message index (0 = oldest)
   * @returns View into WASM memory (valid until next push)
   */
  getMessage(fileId: string, index: number): Uint8Array | null;

  /**
   * Get the most recent message
   */
  getLatestMessage(fileId: string): Uint8Array | null;

  /**
   * Get a DataView for a stored message (for reading FlatBuffer fields)
   */
  getMessageView(fileId: string, index: number): DataView | null;

  /**
   * Clear all stored messages for a type
   */
  clearMessages(fileId: string): void;

  /**
   * Get all registered type info
   */
  getRegisteredTypes(): MessageTypeInfo[];

  /**
   * Reset the dispatcher (clear all messages but keep registrations)
   */
  reset(): void;

  /**
   * Iterate over all messages of a type
   */
  iterMessages(fileId: string): IterableIterator<Uint8Array>;
}

/**
 * Create a size-prefixed FlatBuffer message for testing
 *
 * @param fileId - 4-character file identifier
 * @param data - FlatBuffer data (root offset + payload)
 * @returns Size-prefixed message
 */
export declare function createSizePrefixedMessage(
  fileId: string,
  data: Uint8Array
): Uint8Array;

/**
 * Concatenate multiple size-prefixed messages into a stream
 */
export declare function concatMessages(...messages: Uint8Array[]): Uint8Array;

export default StreamingDispatcher;
