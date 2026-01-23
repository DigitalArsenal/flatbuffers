/**
 * Streaming Dispatcher Demo
 *
 * Demonstrates real-time message routing using the StreamingDispatcher.
 * Generates mixed message streams and sorts them into linear arrays by type.
 */

import { StreamingDispatcher, createSizePrefixedMessage, concatMessages } from '../src/streaming-dispatcher.mjs';

// =============================================================================
// Lord of the Rings themed data
// =============================================================================

const LOTR_MONSTERS = [
  'Balrog', 'Shelob', 'Smaug', 'Nazgul', 'Warg', 'Cave Troll', 'Uruk-hai',
  'Morgul Lord', 'Fell Beast', 'Watcher', 'Barrow-wight', 'Great Goblin',
  'Mumakil', 'Werewolf', 'Vampire', 'Dragon', 'Giant Spider', 'Orc Captain',
  'Ringwraith', 'Witch-king', 'Gothmog', 'Lurtz', 'Grishnakh', 'Ugluk',
];

const LOTR_WEAPONS = [
  'Anduril', 'Sting', 'Glamdring', 'Orcrist', 'Morgul Blade', 'Grond',
  'Aiglos', 'Narsil', 'Gurthang', 'Anglachel', 'Ringil', 'Herugrim',
  'Guthwine', 'Hadhafang', 'Aeglos', 'Black Arrow', 'Belthronding',
  'Dramborleg', 'Aranruth', 'Bow of Galadriel', 'Mithril Coat', 'Axe of Gimli',
];

const LOTR_GALAXIES = [
  'Valinor', 'Arda', 'Aman', 'Numenor', 'Beleriand', 'Gondolin',
  'Doriath', 'Lothlorien', 'Rivendell', 'Mirkwood', 'Mordor', 'Isengard',
  'Rohan', 'Gondor', 'Shire', 'Bree', 'Erebor', 'Moria', 'Angband', 'Utumno',
];

/**
 * Message type configuration for the demo
 * Each type has a fixed-size binary layout with typed fields
 */
export const MessageTypes = {
  MONS: {
    fileId: 'MONS',
    name: 'Monster',
    color: '#ef4444', // red
    messageSize: 64,
    defaultCapacity: 1000,
    // Layout: [root:4][vtable:4][name:16][hp:2][mana:2][level:1][pad:3][x:4][y:4][z:4][id:4][pad:16]
    fields: ['name', 'hp', 'mana', 'level', 'x', 'y', 'z', 'id'],
  },
  WEAP: {
    fileId: 'WEAP',
    name: 'Weapon',
    color: '#3b82f6', // blue
    messageSize: 32,
    defaultCapacity: 500,
    // Layout: [root:4][vtable:4][name:12][damage:2][weight:4][durability:2][enchant:4]
    fields: ['name', 'damage', 'weight', 'durability', 'enchantment'],
  },
  GALX: {
    fileId: 'GALX',
    name: 'Galaxy',
    color: '#8b5cf6', // purple
    messageSize: 16,
    defaultCapacity: 200,
    // Layout: [root:4][stars:4][age:4][type:4]
    fields: ['stars', 'age', 'type'],
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

    // Reuse existing dispatcher if already initialized, just reset it
    if (this.dispatcher) {
      this.dispatcher.reset();
      return;
    }

    this.dispatcher = new StreamingDispatcher(this.wasm);

    // Register message types
    for (const [fileId, config] of Object.entries(MessageTypes)) {
      const capacity = capacities[fileId] || config.defaultCapacity;
      this.dispatcher.registerType(fileId, config.messageSize, capacity);
    }
  }

  /**
   * Write a fixed-length string to a buffer
   * @param {Uint8Array} data - Target buffer
   * @param {number} offset - Start offset
   * @param {string} str - String to write
   * @param {number} maxLen - Maximum length
   */
  writeFixedString(data, offset, str, maxLen) {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(str.slice(0, maxLen));
    data.set(bytes, offset);
    // Zero-fill remainder
    for (let i = bytes.length; i < maxLen; i++) {
      data[offset + i] = 0;
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

    const data = new Uint8Array(config.messageSize);
    const view = new DataView(data.buffer);

    // Root offset (points to table data at offset 4)
    view.setUint32(0, 4, true);

    switch (fileId) {
      case 'MONS': {
        // Monster: name(16), hp(2), mana(2), level(1), pad(3), x(4), y(4), z(4), id(4)
        const name = LOTR_MONSTERS[index % LOTR_MONSTERS.length];
        this.writeFixedString(data, 4, name, 16);
        view.setInt16(20, 100 + (index % 900), true);           // hp: 100-999
        view.setInt16(22, 50 + (index % 450), true);            // mana: 50-499
        view.setUint8(24, 1 + (index % 99));                    // level: 1-99
        // padding at 25-27
        view.setFloat32(28, (index * 1.5) % 1000, true);        // x position
        view.setFloat32(32, (index * 2.3) % 1000, true);        // y position
        view.setFloat32(36, (index * 0.7) % 100, true);         // z position
        view.setUint32(40, index, true);                        // id
        break;
      }
      case 'WEAP': {
        // Weapon: name(12), damage(2), weight(4), durability(2), enchant(4)
        const name = LOTR_WEAPONS[index % LOTR_WEAPONS.length];
        this.writeFixedString(data, 4, name, 12);
        view.setInt16(16, 10 + (index % 490), true);            // damage: 10-499
        view.setFloat32(18, 0.5 + (index % 50) * 0.2, true);    // weight: 0.5-10.5
        view.setUint16(22, 100 - (index % 100), true);          // durability: 1-100
        view.setUint32(24, (index * 7) % 0xFFFFFF, true);       // enchantment id
        view.setUint32(28, index, true);                        // id
        break;
      }
      case 'GALX': {
        // Galaxy: stars(4), age(4), type(4), id(4)
        view.setUint32(4, 1000000 + (index * 12345) % 999000000, true);  // stars: 1M-1B
        view.setFloat32(8, (index * 0.13) % 14.0, true);                 // age in billions
        view.setUint32(12, index % 4, true);                             // type: 0-3 (spiral, elliptical, etc)
        break;
      }
    }

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
