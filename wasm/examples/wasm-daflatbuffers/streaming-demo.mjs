/**
 * Streaming Dispatcher Demo
 *
 * Demonstrates real-time message routing using the StreamingDispatcher.
 * Generates mixed message streams and sorts them into linear arrays by type.
 */

import { StreamingDispatcher, createSizePrefixedMessage, concatMessages } from '../../src/streaming-dispatcher.mjs';

/**
 * Message type configuration for the demo
 */
export const MessageTypes = {
  MONS: {
    fileId: 'MONS',
    name: 'Monster',
    color: '#ef4444', // red
    messageSize: 64,
    defaultCapacity: 1000,
  },
  WEAP: {
    fileId: 'WEAP',
    name: 'Weapon',
    color: '#3b82f6', // blue
    messageSize: 32,
    defaultCapacity: 500,
  },
  GALX: {
    fileId: 'GALX',
    name: 'Galaxy',
    color: '#8b5cf6', // purple
    messageSize: 16,
    defaultCapacity: 200,
  },
};

/**
 * Streaming demo controller
 */
export class StreamingDemo {
  /**
   * @param {Object} wasmModule - Initialized WASM module with dispatcher exports
   */
  constructor(wasmModule) {
    this.wasm = wasmModule;
    this.dispatcher = null;
    this.isStreaming = false;
    this.abortController = null;

    // Callbacks
    this.onStatsUpdate = null;
    this.onMessageReceived = null;
    this.onStreamComplete = null;
    this.onError = null;
  }

  /**
   * Initialize the dispatcher with message types
   * @param {Object} capacities - Capacity overrides { MONS: 1000, WEAP: 500, GALX: 200 }
   */
  init(capacities = {}) {
    if (!this.wasm) {
      throw new Error('WASM module not available');
    }

    this.dispatcher = new StreamingDispatcher(this.wasm);

    // Register message types
    for (const [fileId, config] of Object.entries(MessageTypes)) {
      const capacity = capacities[fileId] || config.defaultCapacity;
      this.dispatcher.registerType(fileId, config.messageSize, capacity);
    }
  }

  /**
   * Generate a mock FlatBuffer message for a type
   * @param {string} fileId - Message type identifier
   * @param {number} index - Message index (for varying content)
   * @returns {Uint8Array}
   */
  generateMockMessage(fileId, index) {
    const config = MessageTypes[fileId];
    if (!config) {
      throw new Error(`Unknown message type: ${fileId}`);
    }

    // Create a mock FlatBuffer-like structure
    // [4 bytes: root offset][data...]
    const data = new Uint8Array(config.messageSize);
    const view = new DataView(data.buffer);

    // Root offset (points to start of table data)
    view.setUint32(0, 4, true);

    // Fill with identifiable pattern based on type and index
    const typeCode = fileId.charCodeAt(0);
    for (let i = 4; i < config.messageSize; i++) {
      data[i] = (typeCode + index + i) % 256;
    }

    // Store index in first field area for verification
    view.setUint32(8, index, true);

    return data;
  }

  /**
   * Generate a mixed stream of messages
   * @param {Object} counts - Message counts per type { MONS: 1000, WEAP: 500, GALX: 200 }
   * @param {boolean} shuffle - Whether to shuffle the stream
   * @returns {{ messages: Uint8Array[], totalSize: number, distribution: Object }}
   */
  generateMixedStream(counts, shuffle = true) {
    const messages = [];
    const distribution = {};

    for (const [fileId, count] of Object.entries(counts)) {
      if (!MessageTypes[fileId]) continue;

      distribution[fileId] = count;

      for (let i = 0; i < count; i++) {
        const data = this.generateMockMessage(fileId, i);
        const msg = createSizePrefixedMessage(fileId, data);
        messages.push({ fileId, index: i, bytes: msg });
      }
    }

    // Shuffle for realistic mixed stream
    if (shuffle) {
      this.shuffleArray(messages);
    }

    const totalSize = messages.reduce((sum, m) => sum + m.bytes.length, 0);

    return {
      messages,
      totalSize,
      distribution,
    };
  }

  /**
   * Fisher-Yates shuffle
   * @param {Array} array
   */
  shuffleArray(array) {
    for (let i = array.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [array[i], array[j]] = [array[j], array[i]];
    }
  }

  /**
   * Stream messages with visualization pacing
   * @param {Object} options - Streaming options
   * @param {Object} options.counts - Message counts { MONS: 1000, WEAP: 500, GALX: 200 }
   * @param {number} [options.batchSize=100] - Messages per batch
   * @param {number} [options.delayMs=10] - Delay between batches
   * @param {boolean} [options.shuffle=true] - Shuffle the stream
   */
  async startStreaming(options) {
    if (this.isStreaming) {
      throw new Error('Already streaming');
    }

    if (!this.dispatcher) {
      throw new Error('Dispatcher not initialized. Call init() first.');
    }

    const {
      counts,
      batchSize = 100,
      delayMs = 10,
      shuffle = true,
    } = options;

    this.isStreaming = true;
    this.abortController = new AbortController();

    // Reset dispatcher state
    this.dispatcher.reset();

    // Generate the stream
    const { messages, totalSize, distribution } = this.generateMixedStream(counts, shuffle);

    const startTime = performance.now();
    let processedCount = 0;
    let processedBytes = 0;

    try {
      // Process in batches
      for (let i = 0; i < messages.length; i += batchSize) {
        // Check for abort
        if (this.abortController.signal.aborted) {
          break;
        }

        const batch = messages.slice(i, i + batchSize);
        const combined = concatMessages(...batch.map(m => m.bytes));

        // Push to dispatcher
        const parsed = this.dispatcher.pushBytes(combined);
        processedCount += batch.length;
        processedBytes += combined.length;

        // Notify stats update
        if (this.onStatsUpdate) {
          this.onStatsUpdate({
            processed: processedCount,
            total: messages.length,
            bytes: processedBytes,
            totalBytes: totalSize,
            elapsed: performance.now() - startTime,
            stats: this.getStats(),
          });
        }

        // Notify per message (for last batch item)
        if (this.onMessageReceived) {
          this.onMessageReceived({
            fileId: batch[batch.length - 1].fileId,
            index: batch[batch.length - 1].index,
            batchIndex: Math.floor(i / batchSize),
          });
        }

        // Delay for visualization
        if (delayMs > 0 && i + batchSize < messages.length) {
          await this.delay(delayMs);
        }
      }

      const elapsed = performance.now() - startTime;

      if (this.onStreamComplete) {
        this.onStreamComplete({
          totalMessages: processedCount,
          totalBytes: processedBytes,
          elapsed,
          throughput: (processedBytes / 1024 / 1024) / (elapsed / 1000), // MB/s
          stats: this.getStats(),
        });
      }

    } catch (err) {
      if (this.onError) {
        this.onError(err);
      }
      throw err;
    } finally {
      this.isStreaming = false;
      this.abortController = null;
    }
  }

  /**
   * Stop streaming
   */
  stopStreaming() {
    if (this.abortController) {
      this.abortController.abort();
    }
  }

  /**
   * Get current stats for all types
   * @returns {Object}
   */
  getStats() {
    if (!this.dispatcher) return {};

    const stats = {};
    for (const [fileId, config] of Object.entries(MessageTypes)) {
      const typeStats = this.dispatcher.getStats(fileId);
      if (typeStats) {
        stats[fileId] = {
          ...config,
          ...typeStats,
          capacity: this.dispatcher._types.get(fileId)?.capacity || config.defaultCapacity,
        };
      }
    }
    return stats;
  }

  /**
   * Get messages for a type
   * @param {string} fileId - Message type
   * @returns {Uint8Array[]}
   */
  getMessages(fileId) {
    if (!this.dispatcher) return [];
    return Array.from(this.dispatcher.iterMessages(fileId));
  }

  /**
   * Get latest message for a type
   * @param {string} fileId - Message type
   * @returns {Uint8Array|null}
   */
  getLatestMessage(fileId) {
    if (!this.dispatcher) return null;
    return this.dispatcher.getLatestMessage(fileId);
  }

  /**
   * Clear all messages
   */
  clearAll() {
    if (!this.dispatcher) return;
    for (const fileId of Object.keys(MessageTypes)) {
      this.dispatcher.clearMessages(fileId);
    }
  }

  /**
   * Delay helper
   * @param {number} ms
   * @returns {Promise<void>}
   */
  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Destroy the demo
   */
  destroy() {
    this.stopStreaming();
    this.dispatcher = null;
  }
}

/**
 * Format bytes to human readable
 * @param {number} bytes
 * @returns {string}
 */
export function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

/**
 * Format throughput
 * @param {number} mbPerSec
 * @returns {string}
 */
export function formatThroughput(mbPerSec) {
  if (mbPerSec < 1) return `${(mbPerSec * 1024).toFixed(1)} KB/s`;
  return `${mbPerSec.toFixed(2)} MB/s`;
}

export default StreamingDemo;
