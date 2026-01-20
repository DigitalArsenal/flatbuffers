/**
 * Session-Based Header Store
 *
 * For IPFS and streaming scenarios, encrypted FlatBuffers are stored/transmitted
 * without modification. Headers are managed per-session:
 *
 * Session-Based Model (Preferred for Streaming):
 * - One header applies to all messages in a session
 * - New header replaces the old one (no per-message lookup)
 * - Sessions identified by ID or recipient key
 *
 * The header store can be:
 * - A JSON file alongside the data (e.g., session.json in IPFS folder)
 * - A FlatBuffer binary file (e.g., session.bin in IPFS folder)
 * - A REST API endpoint
 * - An IPNS record pointing to the current session
 * - A smart contract (for blockchain use cases)
 *
 * This module demonstrates BOTH JSON and FlatBuffer binary formats for headers.
 */

import {
  sha256,
  encryptionHeaderToJSON,
  encryptionHeaderFromJSON,
} from "flatc-wasm/encryption";

/**
 * Session descriptor - can be serialized to JSON or FlatBuffer
 */
export function createSession(header, options = {}) {
  // Accept header as object, JSON string, or keep as-is
  const headerObj = typeof header === "string" ? JSON.parse(header) : header;
  return {
    version: 1,
    sessionId: options.sessionId || generateSessionId(),
    created: new Date().toISOString(),
    header: headerObj,
    files: options.files || [],
    description: options.description,
  };
}

function generateSessionId() {
  return Math.random().toString(36).substring(2, 10) + Date.now().toString(36);
}

/**
 * In-memory header store with support for both JSON and binary formats
 */
class HeaderStore {
  constructor() {
    // Map of content hash -> header object
    this.byContentHash = new Map();
    // Map of message ID -> header object
    this.byMessageId = new Map();
    // Map of recipient key ID -> [headers] (multiple messages per recipient)
    this.byRecipientKeyId = new Map();
  }

  /**
   * Compute content hash of encrypted data
   * @param {Uint8Array} encryptedData
   * @returns {string} - Hex-encoded SHA-256 hash
   */
  computeContentHash(encryptedData) {
    const hash = sha256(encryptedData);
    return Array.from(hash)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  /**
   * Store a header with multiple lookup keys
   * @param {Object} options
   * @param {Object} options.header - The encryption header object
   * @param {Uint8Array} [options.encryptedData] - For content-hash lookup
   * @param {string} [options.messageId] - For message-ID lookup
   */
  store(options) {
    const { header, encryptedData, messageId } = options;

    // Always store by content hash if data provided
    if (encryptedData) {
      const contentHash = this.computeContentHash(encryptedData);
      this.byContentHash.set(contentHash, header);
    }

    // Store by message ID if provided
    if (messageId) {
      this.byMessageId.set(messageId, header);
    }

    // Store by recipient key ID (from header)
    const recipientKeyId = header.recipient_key_id || header.recipientKeyId;
    if (recipientKeyId) {
      const keyIdHex = Array.isArray(recipientKeyId)
        ? recipientKeyId.map((b) => b.toString(16).padStart(2, "0")).join("")
        : recipientKeyId instanceof Uint8Array
          ? Array.from(recipientKeyId)
              .map((b) => b.toString(16).padStart(2, "0"))
              .join("")
          : recipientKeyId;

      if (!this.byRecipientKeyId.has(keyIdHex)) {
        this.byRecipientKeyId.set(keyIdHex, []);
      }
      this.byRecipientKeyId.get(keyIdHex).push({
        header,
        timestamp: header.timestamp || Date.now(),
        messageId,
      });
    }

    return {
      contentHash: encryptedData ? this.computeContentHash(encryptedData) : null,
      messageId,
    };
  }

  /**
   * Get header by content hash
   * @param {string|Uint8Array} hashOrData - Hex hash or encrypted data
   * @returns {Object|null} - Header object or null
   */
  getByContentHash(hashOrData) {
    let hash;
    if (typeof hashOrData === "string") {
      hash = hashOrData;
    } else {
      hash = this.computeContentHash(hashOrData);
    }
    return this.byContentHash.get(hash) || null;
  }

  /**
   * Get header by message ID
   * @param {string} messageId
   * @returns {Object|null} - Header object or null
   */
  getByMessageId(messageId) {
    return this.byMessageId.get(messageId) || null;
  }

  /**
   * Get all headers for a recipient (by key ID)
   * @param {Uint8Array|string} keyId - Key ID (8 bytes or hex)
   * @returns {Array} - Array of {header, timestamp, messageId}
   */
  getByRecipientKeyId(keyId) {
    let keyIdHex;
    if (typeof keyId === "string") {
      keyIdHex = keyId;
    } else {
      keyIdHex = Array.from(keyId)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    }
    return this.byRecipientKeyId.get(keyIdHex) || [];
  }

  /**
   * Export all headers as JSON (for storage)
   * @returns {Object}
   */
  toJSON() {
    return {
      version: 1,
      byContentHash: Object.fromEntries(this.byContentHash),
      byMessageId: Object.fromEntries(this.byMessageId),
      byRecipientKeyId: Object.fromEntries(this.byRecipientKeyId),
    };
  }

  /**
   * Import headers from JSON
   * @param {Object} json
   */
  fromJSON(json) {
    if (json.byContentHash) {
      this.byContentHash = new Map(Object.entries(json.byContentHash));
    }
    if (json.byMessageId) {
      this.byMessageId = new Map(Object.entries(json.byMessageId));
    }
    if (json.byRecipientKeyId) {
      this.byRecipientKeyId = new Map(Object.entries(json.byRecipientKeyId));
    }
  }
}

export { HeaderStore };

// =============================================================================
// Session File I/O - Both JSON and FlatBuffer Binary Formats
// =============================================================================

/**
 * Save session to JSON format
 * @param {Object} session - Session object from createSession()
 * @returns {string} - JSON string
 */
export function sessionToJSON(session) {
  return JSON.stringify(session, null, 2);
}

/**
 * Load session from JSON format
 * @param {string} json - JSON string
 * @returns {Object} - Session object with header as parsed object
 */
export function sessionFromJSON(json) {
  const session = JSON.parse(json);
  // Ensure header has Uint8Array fields converted
  if (session.header && typeof session.header === "object") {
    session.header = normalizeHeader(session.header);
  }
  return session;
}

/**
 * Save session to binary format
 * Uses JSON encoding for the full session (simple and portable)
 * @param {Object} session - Session object from createSession()
 * @returns {Uint8Array} - Binary encoded session
 */
export function sessionToBinary(session) {
  const json = sessionToJSON(session);
  return new TextEncoder().encode(json);
}

/**
 * Load session from binary format
 * @param {Uint8Array} binary - Binary data from sessionToBinary()
 * @returns {Object} - Session object with header as parsed object
 */
export function sessionFromBinary(binary) {
  const json = new TextDecoder().decode(binary);
  return sessionFromJSON(json);
}

/**
 * Save header only to binary (JSON encoded)
 * @param {Object} header - Header object
 * @returns {Uint8Array} - Binary encoded header
 */
export function headerToBinary(header) {
  const json = headerToJSON(header);
  return new TextEncoder().encode(json);
}

/**
 * Load header only from binary (JSON encoded)
 * @param {Uint8Array} binary - Binary encoded header
 * @returns {Object} - Header object
 */
export function headerFromBinary(binary) {
  const json = new TextDecoder().decode(binary);
  return headerFromJSON(json);
}

/**
 * Save header only to JSON
 * @param {Object} header - Header object
 * @returns {string} - JSON string
 */
export function headerToJSON(header) {
  return encryptionHeaderToJSON(header);
}

/**
 * Load header only from JSON
 * @param {string} json - JSON string
 * @returns {Object} - Header object
 */
export function headerFromJSON(json) {
  return encryptionHeaderFromJSON(json);
}

/**
 * Normalize header object (convert arrays to Uint8Array)
 * @param {Object} header
 * @returns {Object}
 */
function normalizeHeader(header) {
  const result = { ...header };
  if (Array.isArray(result.ephemeral_public_key)) {
    result.ephemeralPublicKey = new Uint8Array(result.ephemeral_public_key);
  }
  if (Array.isArray(result.recipient_key_id)) {
    result.recipientKeyId = new Uint8Array(result.recipient_key_id);
  }
  if (Array.isArray(result.schema_hash)) {
    result.schemaHash = new Uint8Array(result.schema_hash);
  }
  return result;
}

/**
 * IPFS Session-Based Storage (Recommended)
 *
 * Option 1: JSON format
 * /ipfs/Qm.../
 *   session.json        <- { sessionId, header: {...}, files: [...] }
 *   001.bin             <- Encrypted FlatBuffer (unmodified)
 *   002.bin             <- Encrypted FlatBuffer (unmodified)
 *
 * Option 2: Binary format (more compact)
 * /ipfs/Qm.../
 *   session.bin         <- [metadata length][metadata JSON][header FlatBuffer]
 *   001.bin             <- Encrypted FlatBuffer (unmodified)
 *   002.bin             <- Encrypted FlatBuffer (unmodified)
 *
 * Option 3: Header-only binary (minimal)
 * /ipfs/Qm.../
 *   header.bin          <- Header as FlatBuffer only
 *   001.bin             <- Encrypted FlatBuffer (unmodified)
 *   002.bin             <- Encrypted FlatBuffer (unmodified)
 *
 * To decrypt:
 * 1. Fetch session.json, session.bin, or header.bin
 * 2. Parse header using appropriate function
 * 3. Create decryption context from header
 * 4. Stream and decrypt each .bin file using same context
 *
 * Example session.json:
 * {
 *   "version": 1,
 *   "sessionId": "abc123xyz",
 *   "created": "2024-01-15T10:30:00Z",
 *   "header": {
 *     "version": 1,
 *     "key_exchange": 0,
 *     "ephemeral_public_key": [...],
 *     "context": "my-app-v1",
 *     ...
 *   },
 *   "files": ["001.bin", "002.bin", "003.bin"]
 * }
 */
