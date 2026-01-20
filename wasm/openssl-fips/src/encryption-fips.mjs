/**
 * @module encryption-fips
 *
 * FlatBuffers field-level encryption using OpenSSL FIPS Provider.
 * This module provides a FIPS 140-3 compatible encryption API that mirrors
 * the main encryption.mjs API but uses OpenSSL instead of Crypto++.
 *
 * IMPORTANT: The OpenSSL FIPS Provider is validated under certificate #4282.
 * However, FIPS validation is platform-specific. WebAssembly compilation
 * creates a new operational environment NOT covered by the NIST certificate.
 *
 * This module provides FIPS-COMPATIBLE algorithms (AES-256, SHA-256, ECDH P-256,
 * HKDF), but NOT FIPS-VALIDATED execution in the browser context.
 *
 * Key Differences from encryption.mjs:
 * - Uses P-256 (NIST curve) instead of X25519 for ECDH by default
 * - Uses AES-256-GCM with authentication instead of AES-256-CTR
 * - X25519 and Ed25519 are NOT available (not FIPS approved)
 * - secp256k1 is NOT available (not FIPS approved)
 *
 * Features:
 * - AES-256-CTR symmetric encryption (FIPS approved)
 * - AES-256-GCM authenticated encryption (FIPS approved)
 * - ECDH P-256 key exchange (NIST curve, FIPS approved)
 * - HKDF-SHA256 key derivation (FIPS approved)
 * - SHA-256 hashing (FIPS approved)
 */

// Import the OpenSSL crypto wrapper
import crypto from '../dist/crypto.mjs';

// Cached encoder/decoder instances for performance
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

// Track initialization state
let initialized = false;

// =============================================================================
// Error Types
// =============================================================================

/**
 * Error codes for cryptographic operations
 */
export const CryptoErrorCode = {
  NOT_INITIALIZED: 'NOT_INITIALIZED',
  INVALID_KEY_SIZE: 'INVALID_KEY_SIZE',
  INVALID_IV_SIZE: 'INVALID_IV_SIZE',
  INVALID_NONCE_SIZE: 'INVALID_NONCE_SIZE',
  INVALID_SIGNATURE: 'INVALID_SIGNATURE',
  INVALID_PUBLIC_KEY: 'INVALID_PUBLIC_KEY',
  INVALID_PRIVATE_KEY: 'INVALID_PRIVATE_KEY',
  ENCRYPTION_FAILED: 'ENCRYPTION_FAILED',
  DECRYPTION_FAILED: 'DECRYPTION_FAILED',
  KEY_GENERATION_FAILED: 'KEY_GENERATION_FAILED',
  ECDH_FAILED: 'ECDH_FAILED',
  SIGNING_FAILED: 'SIGNING_FAILED',
  VERIFICATION_FAILED: 'VERIFICATION_FAILED',
  AUTHENTICATION_FAILED: 'AUTHENTICATION_FAILED',
  MEMORY_ERROR: 'MEMORY_ERROR',
  INVALID_INPUT: 'INVALID_INPUT',
  NOT_FIPS_APPROVED: 'NOT_FIPS_APPROVED',
};

/**
 * Custom error class for cryptographic operations
 */
export class CryptoError extends Error {
  constructor(code, message, cause) {
    super(message);
    this.name = 'CryptoError';
    this.code = code;
    this.cause = cause;
  }
}

// =============================================================================
// Constants
// =============================================================================

// Key sizes
export const KEY_SIZE = 32;
export const IV_SIZE = 16;
export const GCM_IV_SIZE = 12;
export const GCM_TAG_SIZE = 16;
export const SHA256_SIZE = 32;
export const HMAC_SIZE = 32;

// P-256 key sizes (FIPS approved)
export const P256_PRIVATE_KEY_SIZE = 32;
export const P256_PUBLIC_KEY_SIZE = 65; // Uncompressed point (0x04 || x || y)

// Algorithms supported in FIPS mode
export const KeyExchangeAlgorithm = {
  P256: 'p256',  // NIST P-256, FIPS approved
  // X25519 and secp256k1 are NOT FIPS approved
};

export const SymmetricAlgorithm = {
  AES_256_CTR: 'aes-256-ctr',  // FIPS approved
  AES_256_GCM: 'aes-256-gcm',  // FIPS approved (default for authenticated encryption)
};

export const KeyDerivationFunction = {
  HKDF_SHA256: 'hkdf-sha256',  // FIPS approved
};

// =============================================================================
// Initialization
// =============================================================================

/**
 * Initialize the FIPS encryption module
 * @param {Object} [options] - Options
 * @param {boolean} [options.fips=true] - Enable FIPS mode (default true)
 * @returns {Promise<void>}
 */
export async function initEncryption(options = {}) {
  if (initialized) return;

  const fipsMode = options.fips !== false;
  await crypto.init({ fips: fipsMode });
  initialized = true;
}

/**
 * Check if the module is initialized
 */
export function isInitialized() {
  return initialized;
}

/**
 * Check if running in FIPS mode
 */
export function isFIPSMode() {
  return crypto.isFIPSMode();
}

/**
 * Helper to ensure initialization
 */
function ensureInitialized() {
  if (!initialized) {
    throw new CryptoError(
      CryptoErrorCode.NOT_INITIALIZED,
      'Encryption module not initialized. Call initEncryption() first.'
    );
  }
}

// =============================================================================
// Core Cryptographic Functions
// =============================================================================

/**
 * Generate cryptographically secure random bytes
 */
export function getRandomBytes(length) {
  ensureInitialized();
  return crypto.randomBytes(length);
}

/**
 * SHA-256 hash
 */
export function sha256(data) {
  ensureInitialized();
  if (typeof data === 'string') {
    data = textEncoder.encode(data);
  }
  return crypto.sha256(data);
}

/**
 * HKDF-SHA256 key derivation
 * @param {Uint8Array} ikm - Input key material
 * @param {Uint8Array|null} salt - Salt (optional)
 * @param {Uint8Array|null} info - Context info (optional)
 * @param {number} length - Output length
 * @returns {Uint8Array} Derived key
 */
export function hkdf(ikm, salt, info, length) {
  ensureInitialized();
  return crypto.hkdf(
    ikm,
    salt || new Uint8Array(0),
    info || new Uint8Array(0),
    length
  );
}

/**
 * AES-256-CTR encryption/decryption (in-place, same operation)
 * @param {Uint8Array} data - Data to encrypt/decrypt (modified in place)
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} iv - 16-byte IV
 * @returns {Uint8Array} The modified data buffer
 */
export function encryptBytes(data, key, iv) {
  ensureInitialized();
  if (key.length !== KEY_SIZE) {
    throw new CryptoError(
      CryptoErrorCode.INVALID_KEY_SIZE,
      `Invalid key length: expected ${KEY_SIZE} bytes, got ${key.length}`
    );
  }
  if (iv.length !== IV_SIZE) {
    throw new CryptoError(
      CryptoErrorCode.INVALID_IV_SIZE,
      `Invalid IV length: expected ${IV_SIZE} bytes, got ${iv.length}`
    );
  }
  return crypto.aes256ctr(data, key, iv);
}

/**
 * Decrypt bytes (alias for encryptBytes since CTR mode is symmetric)
 */
export const decryptBytes = encryptBytes;

/**
 * AES-256-GCM authenticated encryption
 * @param {Uint8Array} plaintext - Data to encrypt
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} [aad] - Additional authenticated data
 * @returns {{ ciphertext: Uint8Array, iv: Uint8Array, tag: Uint8Array }}
 */
export function encryptAuthenticated(plaintext, key, aad) {
  ensureInitialized();
  if (key.length !== KEY_SIZE) {
    throw new CryptoError(
      CryptoErrorCode.INVALID_KEY_SIZE,
      `Invalid key length: expected ${KEY_SIZE} bytes, got ${key.length}`
    );
  }

  const iv = getRandomBytes(GCM_IV_SIZE);
  const result = crypto.aes256gcmEncrypt(plaintext, key, iv, aad);

  return {
    ciphertext: result.ciphertext,
    iv: iv,
    tag: result.tag,
  };
}

/**
 * AES-256-GCM authenticated decryption
 * @param {Uint8Array} ciphertext - Encrypted data
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} iv - 12-byte IV
 * @param {Uint8Array} tag - 16-byte authentication tag
 * @param {Uint8Array} [aad] - Additional authenticated data
 * @returns {Uint8Array} Decrypted plaintext
 * @throws {CryptoError} If authentication fails
 */
export function decryptAuthenticated(ciphertext, key, iv, tag, aad) {
  ensureInitialized();
  if (key.length !== KEY_SIZE) {
    throw new CryptoError(
      CryptoErrorCode.INVALID_KEY_SIZE,
      `Invalid key length: expected ${KEY_SIZE} bytes, got ${key.length}`
    );
  }

  try {
    return crypto.aes256gcmDecrypt(ciphertext, tag, key, iv, aad);
  } catch (e) {
    throw new CryptoError(
      CryptoErrorCode.AUTHENTICATION_FAILED,
      'Decryption failed: authentication error',
      e
    );
  }
}

// =============================================================================
// ECDH P-256 Key Exchange (FIPS Approved)
// =============================================================================

/**
 * Generate ECDH P-256 key pair
 * @returns {{ privateKey: Uint8Array, publicKey: Uint8Array }}
 */
export function p256GenerateKeyPair() {
  ensureInitialized();
  return crypto.ecdhP256Keygen();
}

/**
 * Compute ECDH P-256 shared secret
 * @param {Uint8Array} privateKey - 32-byte private key
 * @param {Uint8Array} publicKey - 65-byte public key (uncompressed)
 * @returns {Uint8Array} 32-byte shared secret
 */
export function p256SharedSecret(privateKey, publicKey) {
  ensureInitialized();
  if (privateKey.length !== P256_PRIVATE_KEY_SIZE) {
    throw new CryptoError(
      CryptoErrorCode.INVALID_PRIVATE_KEY,
      `Invalid private key length: expected ${P256_PRIVATE_KEY_SIZE} bytes, got ${privateKey.length}`
    );
  }
  if (publicKey.length !== P256_PUBLIC_KEY_SIZE) {
    throw new CryptoError(
      CryptoErrorCode.INVALID_PUBLIC_KEY,
      `Invalid public key length: expected ${P256_PUBLIC_KEY_SIZE} bytes, got ${publicKey.length}`
    );
  }
  return crypto.ecdhP256Compute(privateKey, publicKey);
}

/**
 * Derive key from shared secret
 * @param {Uint8Array} sharedSecret - Shared secret from ECDH
 * @param {string} [context] - Context string for HKDF
 * @returns {Uint8Array} 32-byte derived key
 */
export function p256DeriveKey(sharedSecret, context = '') {
  const info = context ? textEncoder.encode(context) : new Uint8Array(0);
  return hkdf(sharedSecret, null, info, KEY_SIZE);
}

// =============================================================================
// Non-FIPS algorithms - Throw helpful errors
// =============================================================================

function notFIPSApproved(algorithm) {
  throw new CryptoError(
    CryptoErrorCode.NOT_FIPS_APPROVED,
    `${algorithm} is not FIPS 140-3 approved. Use P-256 for key exchange in FIPS mode.`
  );
}

export function x25519GenerateKeyPair() {
  notFIPSApproved('X25519');
}

export function x25519SharedSecret() {
  notFIPSApproved('X25519');
}

export function x25519DeriveKey() {
  notFIPSApproved('X25519');
}

export function secp256k1GenerateKeyPair() {
  notFIPSApproved('secp256k1');
}

export function secp256k1SharedSecret() {
  notFIPSApproved('secp256k1');
}

export function secp256k1DeriveKey() {
  notFIPSApproved('secp256k1');
}

export function secp256k1Sign() {
  notFIPSApproved('secp256k1');
}

export function secp256k1Verify() {
  notFIPSApproved('secp256k1');
}

export function ed25519GenerateKeyPair() {
  notFIPSApproved('Ed25519');
}

export function ed25519Sign() {
  notFIPSApproved('Ed25519');
}

export function ed25519Verify() {
  notFIPSApproved('Ed25519');
}

// =============================================================================
// EncryptionContext (FIPS Compatible)
// =============================================================================

/**
 * Encryption context for field-level encryption with FIPS support.
 *
 * Factory methods:
 * - `forEncryption(recipientPublicKey, options)` - Sender side (uses P-256)
 * - `forDecryption(privateKey, header)` - Recipient side
 *
 * WARNING: Methods that encrypt data modify the buffer in-place.
 */
export class EncryptionContext {
  #key;
  #nonce;
  #ephemeralPublicKey;
  #recipientKeyId;
  #algorithm;
  #context;
  #fieldKeyCache;

  /**
   * Create encryption context
   * @param {Uint8Array|string} key - 32-byte master key
   * @param {Uint8Array} [nonce] - Optional 16-byte nonce
   */
  constructor(key, nonce) {
    if (typeof key === 'string') {
      // Parse hex string
      if (!/^[0-9a-fA-F]*$/.test(key)) {
        throw new Error('Invalid hex string');
      }
      if (key.length !== 64) {
        throw new Error(`Invalid hex key length: expected 64 characters, got ${key.length}`);
      }
      const bytes = new Uint8Array(32);
      for (let i = 0; i < 64; i += 2) {
        bytes[i / 2] = parseInt(key.substring(i, i + 2), 16);
      }
      this.#key = bytes;
    } else if (key instanceof Uint8Array) {
      if (key.length !== KEY_SIZE) {
        throw new Error(`Invalid key length: expected ${KEY_SIZE} bytes, got ${key.length}`);
      }
      this.#key = new Uint8Array(key);
    } else {
      throw new Error('Key must be a Uint8Array or 64-character hex string');
    }

    if (nonce !== undefined) {
      if (!(nonce instanceof Uint8Array)) {
        throw new Error('Nonce must be a Uint8Array');
      }
      if (nonce.length !== IV_SIZE) {
        throw new Error(`Invalid nonce length: expected ${IV_SIZE} bytes, got ${nonce.length}`);
      }
      this.#nonce = new Uint8Array(nonce);
    } else {
      this.#nonce = getRandomBytes(IV_SIZE);
    }

    this.#ephemeralPublicKey = null;
    this.#recipientKeyId = null;
    this.#algorithm = null;
    this.#context = null;
    this.#fieldKeyCache = new Map();
  }

  /**
   * Create an encryption context for hybrid (ECIES) encryption.
   * Uses P-256 (NIST curve) for FIPS compliance.
   *
   * @param {Uint8Array} recipientPublicKey - Recipient's P-256 public key (65 bytes)
   * @param {Object} [options] - Encryption options
   * @param {string} [options.algorithm='p256'] - Only 'p256' is supported in FIPS mode
   * @param {string} [options.context=''] - Application context for key derivation
   * @returns {EncryptionContext} Configured encryption context
   */
  static forEncryption(recipientPublicKey, options = {}) {
    ensureInitialized();

    const algorithm = options.algorithm || KeyExchangeAlgorithm.P256;
    const contextStr = options.context || '';

    // Only P-256 is FIPS approved
    if (algorithm !== KeyExchangeAlgorithm.P256 && algorithm !== 'p256') {
      throw new CryptoError(
        CryptoErrorCode.NOT_FIPS_APPROVED,
        `Algorithm '${algorithm}' is not FIPS approved. Use 'p256' for FIPS-compliant key exchange.`
      );
    }

    // Generate ephemeral key pair
    const ephemeralKeys = p256GenerateKeyPair();

    // Compute shared secret via ECDH
    const sharedSecret = p256SharedSecret(ephemeralKeys.privateKey, recipientPublicKey);

    // Derive symmetric key from shared secret using HKDF
    const info = contextStr ? textEncoder.encode(contextStr) : null;
    const symmetricKey = hkdf(sharedSecret, null, info, KEY_SIZE);

    // Create context with derived key
    const ctx = new EncryptionContext(symmetricKey);
    ctx.#ephemeralPublicKey = ephemeralKeys.publicKey;
    ctx.#recipientKeyId = computeKeyId(recipientPublicKey);
    ctx.#algorithm = algorithm;
    ctx.#context = contextStr;

    return ctx;
  }

  /**
   * Create an encryption context for hybrid (ECIES) decryption.
   *
   * @param {Uint8Array} privateKey - Recipient's P-256 private key
   * @param {Object} header - Encryption header from sender
   * @param {string} [context] - Application context
   * @returns {EncryptionContext} Configured decryption context
   */
  static forDecryption(privateKey, header, context = '') {
    ensureInitialized();

    const algorithm = header.algorithm || KeyExchangeAlgorithm.P256;
    const ephemeralPublicKey = header.senderPublicKey;
    const nonce = header.iv;

    if (!ephemeralPublicKey) {
      throw new CryptoError(
        CryptoErrorCode.INVALID_INPUT,
        'Header must contain senderPublicKey'
      );
    }

    if (!nonce) {
      throw new CryptoError(
        CryptoErrorCode.INVALID_IV_SIZE,
        'Header must contain iv (nonce) for decryption'
      );
    }

    // Only P-256 is FIPS approved
    if (algorithm !== KeyExchangeAlgorithm.P256 && algorithm !== 'p256') {
      throw new CryptoError(
        CryptoErrorCode.NOT_FIPS_APPROVED,
        `Algorithm '${algorithm}' is not FIPS approved. Cannot decrypt non-FIPS data in FIPS mode.`
      );
    }

    // Compute shared secret via ECDH
    const sharedSecret = p256SharedSecret(privateKey, ephemeralPublicKey);

    // Derive symmetric key from shared secret using HKDF
    const info = context ? textEncoder.encode(context) : null;
    const symmetricKey = hkdf(sharedSecret, null, info, KEY_SIZE);

    // Create context with derived key and nonce from header
    const ctx = new EncryptionContext(symmetricKey, nonce);
    ctx.#ephemeralPublicKey = ephemeralPublicKey;
    ctx.#algorithm = algorithm;
    ctx.#context = context;

    return ctx;
  }

  /**
   * Get the ephemeral public key
   */
  getEphemeralPublicKey() {
    return this.#ephemeralPublicKey ? new Uint8Array(this.#ephemeralPublicKey) : null;
  }

  /**
   * Get the encryption header for transmission
   */
  getHeader() {
    if (!this.#ephemeralPublicKey) {
      throw new CryptoError(
        CryptoErrorCode.INVALID_INPUT,
        'No ephemeral key available. Use EncryptionContext.forEncryption() for ECIES.'
      );
    }
    return {
      version: 2,  // Version 2 indicates FIPS mode
      algorithm: this.#algorithm || KeyExchangeAlgorithm.P256,
      senderPublicKey: new Uint8Array(this.#ephemeralPublicKey),
      recipientKeyId: this.#recipientKeyId ? new Uint8Array(this.#recipientKeyId) : new Uint8Array(8),
      iv: this.getNonce(),
      context: this.#context || '',
      fips: true,  // Indicates FIPS-compatible encryption
    };
  }

  /**
   * Get the encryption header as JSON string
   */
  getHeaderJSON() {
    const header = this.getHeader();
    return JSON.stringify(encryptionHeaderToJSON(header));
  }

  /**
   * Get the algorithm
   */
  getAlgorithm() {
    return this.#algorithm;
  }

  /**
   * Get the context string
   */
  getContext() {
    return this.#context;
  }

  /**
   * Get the nonce
   */
  getNonce() {
    return new Uint8Array(this.#nonce);
  }

  /**
   * Check if context is valid
   */
  isValid() {
    return this.#key !== null && this.#key.length === KEY_SIZE;
  }

  /**
   * Create from hex string
   */
  static fromHex(hexKey, nonce) {
    return new EncryptionContext(hexKey, nonce);
  }

  /**
   * Derive field-specific key
   */
  deriveFieldKey(fieldId) {
    const info = new Uint8Array(19);
    textEncoder.encodeInto('flatbuffers-field', info);
    info[17] = (fieldId >> 8) & 0xff;
    info[18] = fieldId & 0xff;
    return hkdf(this.#key, null, info, KEY_SIZE);
  }

  /**
   * Derive field-specific IV
   */
  deriveFieldIV(fieldId) {
    const info = new Uint8Array(18);
    textEncoder.encodeInto('flatbuffers-iv', info);
    info[14] = (fieldId >> 8) & 0xff;
    info[15] = fieldId & 0xff;
    return hkdf(this.#key, this.#nonce, info, IV_SIZE);
  }

  /**
   * Encrypt scalar value
   */
  encryptScalar(buffer, offset, size, fieldId) {
    const key = this.deriveFieldKey(fieldId);
    const iv = this.deriveFieldIV(fieldId);
    const data = buffer.subarray(offset, offset + size);
    encryptBytes(data, key, iv);
  }

  /**
   * Encrypt string value
   */
  encryptString(buffer, offset, length, fieldId) {
    const key = this.deriveFieldKey(fieldId);
    const iv = this.deriveFieldIV(fieldId);
    const data = buffer.subarray(offset, offset + length);
    encryptBytes(data, key, iv);
  }

  /**
   * Encrypt vector data
   */
  encryptVector(buffer, offset, elementSize, count, fieldId) {
    const key = this.deriveFieldKey(fieldId);
    const iv = this.deriveFieldIV(fieldId);
    const data = buffer.subarray(offset, offset + elementSize * count);
    encryptBytes(data, key, iv);
  }

  // =========================================================================
  // High-Performance Streaming Methods
  // =========================================================================

  /**
   * Get a cached field key
   */
  getFieldKey(fieldId) {
    if (!this.#fieldKeyCache.has(fieldId)) {
      this.#fieldKeyCache.set(fieldId, this.deriveFieldKey(fieldId));
    }
    return this.#fieldKeyCache.get(fieldId);
  }

  /**
   * Compute a unique IV for a (fieldId, recordCounter) pair using XOR
   */
  computeFieldIV(fieldId, recordCounter) {
    const iv = new Uint8Array(this.#nonce);

    // XOR in fieldId (bytes 0-1, big-endian)
    iv[0] ^= (fieldId >> 8) & 0xff;
    iv[1] ^= fieldId & 0xff;

    // XOR in recordCounter (bytes 2-9, big-endian 64-bit)
    // JavaScript safely handles integers up to 2^53-1
    for (let i = 7; i >= 0; i--) {
      iv[2 + (7 - i)] ^= (recordCounter / Math.pow(256, i)) & 0xff;
    }

    return iv;
  }

  /**
   * High-performance field encryption for streaming
   */
  encryptField(buffer, offset, size, fieldId, recordCounter) {
    const key = this.getFieldKey(fieldId);
    const iv = this.computeFieldIV(fieldId, recordCounter);
    const data = buffer.subarray(offset, offset + size);
    encryptBytes(data, key, iv);
  }

  /**
   * Encrypt entire buffer for streaming (single field)
   */
  encryptBuffer(buffer, recordCounter, fieldId = 0) {
    this.encryptField(buffer, 0, buffer.length, fieldId, recordCounter);
  }

  /**
   * Decrypt buffer (same as encrypt for CTR mode)
   */
  decryptBuffer(buffer, recordCounter, fieldId = 0) {
    this.encryptField(buffer, 0, buffer.length, fieldId, recordCounter);
  }

  /**
   * Clear the field key cache
   */
  clearCache() {
    this.#fieldKeyCache.clear();
  }
}

// =============================================================================
// Header Utilities
// =============================================================================

/**
 * Compute a key ID from a public key
 */
export function computeKeyId(publicKey) {
  const hash = sha256(publicKey);
  return hash.subarray(0, 8);
}

/**
 * Convert header to JSON-serializable format
 */
export function encryptionHeaderToJSON(header) {
  return {
    version: header.version,
    algorithm: header.algorithm,
    senderPublicKey: uint8ArrayToHex(header.senderPublicKey),
    recipientKeyId: uint8ArrayToHex(header.recipientKeyId),
    iv: uint8ArrayToHex(header.iv),
    context: header.context,
    fips: header.fips,
  };
}

/**
 * Parse header from JSON
 */
export function encryptionHeaderFromJSON(json) {
  const data = typeof json === 'string' ? JSON.parse(json) : json;
  return {
    version: data.version,
    algorithm: data.algorithm,
    senderPublicKey: hexToUint8Array(data.senderPublicKey),
    recipientKeyId: hexToUint8Array(data.recipientKeyId),
    iv: hexToUint8Array(data.iv),
    context: data.context || '',
    fips: data.fips,
  };
}

// =============================================================================
// Utility Functions
// =============================================================================

function uint8ArrayToHex(arr) {
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToUint8Array(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

// =============================================================================
// Default Export
// =============================================================================

export default {
  // Initialization
  initEncryption,
  isInitialized,
  isFIPSMode,

  // Core functions
  getRandomBytes,
  sha256,
  hkdf,
  encryptBytes,
  decryptBytes,
  encryptAuthenticated,
  decryptAuthenticated,

  // P-256 ECDH (FIPS approved)
  p256GenerateKeyPair,
  p256SharedSecret,
  p256DeriveKey,

  // Classes
  EncryptionContext,
  CryptoError,
  CryptoErrorCode,

  // Constants
  KEY_SIZE,
  IV_SIZE,
  GCM_IV_SIZE,
  GCM_TAG_SIZE,
  SHA256_SIZE,
  P256_PRIVATE_KEY_SIZE,
  P256_PUBLIC_KEY_SIZE,
  KeyExchangeAlgorithm,
  SymmetricAlgorithm,
  KeyDerivationFunction,

  // Utilities
  computeKeyId,
  encryptionHeaderToJSON,
  encryptionHeaderFromJSON,
};
