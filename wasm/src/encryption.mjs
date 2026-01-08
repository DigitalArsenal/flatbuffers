/**
 * @module encryption
 *
 * FlatBuffers field-level encryption using Crypto++ via WASM.
 * All cryptographic operations are performed by the flatc-encryption.wasm module
 * compiled from C++ with Crypto++.
 *
 * Features:
 * - AES-256-CTR symmetric encryption
 * - X25519 ECDH key exchange
 * - secp256k1 ECDH and ECDSA (Bitcoin/Ethereum compatible)
 * - P-256 ECDH and ECDSA (NIST)
 * - Ed25519 signatures
 * - HKDF-SHA256 key derivation
 */

// WASM module instance (set by initEncryption)
let wasmModule = null;
let wasmMemory = null;

// Key sizes
export const KEY_SIZE = 32;
export const IV_SIZE = 16;
export const SHA256_SIZE = 32;
export const X25519_PRIVATE_KEY_SIZE = 32;
export const X25519_PUBLIC_KEY_SIZE = 32;
export const SECP256K1_PRIVATE_KEY_SIZE = 32;
export const SECP256K1_PUBLIC_KEY_SIZE = 33;
export const P256_PRIVATE_KEY_SIZE = 32;
export const P256_PUBLIC_KEY_SIZE = 33;
export const ED25519_PRIVATE_KEY_SIZE = 64;
export const ED25519_PUBLIC_KEY_SIZE = 32;
export const ED25519_SIGNATURE_SIZE = 64;

/**
 * Initialize the encryption module with WASM
 * @param {WebAssembly.Instance} instance - The flatc-encryption.wasm instance
 */
export function initEncryption(instance) {
  wasmModule = instance.exports;
  wasmMemory = wasmModule.memory;
}

/**
 * Check if encryption module is initialized
 * @returns {boolean}
 */
export function isInitialized() {
  return wasmModule !== null;
}

/**
 * Check if Crypto++ is available in the WASM module
 * @returns {boolean}
 */
export function hasCryptopp() {
  if (!wasmModule || !wasmModule.wasi_has_cryptopp) return false;
  return wasmModule.wasi_has_cryptopp() === 1;
}

/**
 * Get the WASM module version
 * @returns {string}
 */
export function getVersion() {
  if (!wasmModule || !wasmModule.wasi_get_version) return 'unknown';
  const ptr = wasmModule.wasi_get_version();
  return readString(ptr);
}

// =============================================================================
// Memory helpers
// =============================================================================

function readString(ptr, maxLen = 32) {
  const view = new Uint8Array(wasmMemory.buffer, ptr, maxLen);
  let end = view.indexOf(0);
  if (end === -1) end = maxLen;
  return new TextDecoder().decode(view.subarray(0, end));
}

function allocate(size) {
  const ptr = wasmModule.malloc(size);
  if (ptr === 0) throw new Error('malloc failed');
  return ptr;
}

function deallocate(ptr) {
  if (ptr !== 0) wasmModule.free(ptr);
}

function writeBytes(ptr, data) {
  new Uint8Array(wasmMemory.buffer, ptr, data.length).set(data);
}

function readBytes(ptr, size) {
  return new Uint8Array(wasmMemory.buffer, ptr, size).slice();
}

// =============================================================================
// SHA-256
// =============================================================================

/**
 * Compute SHA-256 hash
 * @param {Uint8Array} data - Data to hash
 * @returns {Uint8Array} - 32-byte hash
 */
export function sha256(data) {
  if (!wasmModule) throw new Error('Encryption module not initialized');

  const dataPtr = allocate(data.length);
  const hashPtr = allocate(SHA256_SIZE);

  try {
    writeBytes(dataPtr, data);
    wasmModule.wasi_sha256(dataPtr, data.length, hashPtr);
    return readBytes(hashPtr, SHA256_SIZE);
  } finally {
    deallocate(dataPtr);
    deallocate(hashPtr);
  }
}

// =============================================================================
// AES-256-CTR Encryption
// =============================================================================

/**
 * Encrypt data in-place using AES-256-CTR
 * @param {Uint8Array} data - Data to encrypt (modified in-place)
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} iv - 16-byte IV
 */
export function encryptBytes(data, key, iv) {
  if (!wasmModule) throw new Error('Encryption module not initialized');
  if (key.length !== KEY_SIZE) throw new Error('Key must be 32 bytes');
  if (iv.length !== IV_SIZE) throw new Error('IV must be 16 bytes');
  if (data.length === 0) return;

  const keyPtr = allocate(KEY_SIZE);
  const ivPtr = allocate(IV_SIZE);
  const dataPtr = allocate(data.length);

  try {
    writeBytes(keyPtr, key);
    writeBytes(ivPtr, iv);
    writeBytes(dataPtr, data);

    const result = wasmModule.wasi_encrypt_bytes(keyPtr, ivPtr, dataPtr, data.length);
    if (result !== 0) throw new Error('Encryption failed');

    data.set(readBytes(dataPtr, data.length));
  } finally {
    deallocate(keyPtr);
    deallocate(ivPtr);
    deallocate(dataPtr);
  }
}

/**
 * Decrypt data in-place using AES-256-CTR
 * Same as encryptBytes (CTR mode is symmetric)
 */
export const decryptBytes = encryptBytes;

// =============================================================================
// HKDF Key Derivation
// =============================================================================

/**
 * Derive key using HKDF-SHA256
 * @param {Uint8Array} ikm - Input key material
 * @param {Uint8Array|null} salt - Optional salt
 * @param {Uint8Array|null} info - Optional context info
 * @param {number} length - Output length
 * @returns {Uint8Array}
 */
export function hkdf(ikm, salt, info, length) {
  if (!wasmModule) throw new Error('Encryption module not initialized');

  const ikmPtr = allocate(ikm.length);
  const saltPtr = salt ? allocate(salt.length) : 0;
  const infoPtr = info ? allocate(info.length) : 0;
  const okmPtr = allocate(length);

  try {
    writeBytes(ikmPtr, ikm);
    if (salt) writeBytes(saltPtr, salt);
    if (info) writeBytes(infoPtr, info);

    wasmModule.wasi_hkdf(
      ikmPtr, ikm.length,
      saltPtr, salt ? salt.length : 0,
      infoPtr, info ? info.length : 0,
      okmPtr, length
    );

    return readBytes(okmPtr, length);
  } finally {
    deallocate(ikmPtr);
    if (saltPtr) deallocate(saltPtr);
    if (infoPtr) deallocate(infoPtr);
    deallocate(okmPtr);
  }
}

// =============================================================================
// X25519 Key Exchange
// =============================================================================

/**
 * Generate X25519 key pair
 * @param {Uint8Array} [privateKey] - Optional 32-byte private key (generates random if not provided)
 * @returns {{privateKey: Uint8Array, publicKey: Uint8Array}}
 */
export function x25519GenerateKeyPair(privateKey) {
  if (!wasmModule) throw new Error('Encryption module not initialized');

  const privPtr = allocate(X25519_PRIVATE_KEY_SIZE);
  const pubPtr = allocate(X25519_PUBLIC_KEY_SIZE);

  try {
    if (privateKey) {
      writeBytes(privPtr, privateKey);
    }

    const result = wasmModule.wasi_x25519_generate_keypair(privPtr, pubPtr);
    if (result !== 0) throw new Error('X25519 key generation failed');

    return {
      privateKey: readBytes(privPtr, X25519_PRIVATE_KEY_SIZE),
      publicKey: readBytes(pubPtr, X25519_PUBLIC_KEY_SIZE),
    };
  } finally {
    deallocate(privPtr);
    deallocate(pubPtr);
  }
}

/**
 * Compute X25519 shared secret
 * @param {Uint8Array} privateKey - Our private key (32 bytes)
 * @param {Uint8Array} publicKey - Their public key (32 bytes)
 * @returns {Uint8Array} - 32-byte shared secret
 */
export function x25519SharedSecret(privateKey, publicKey) {
  if (!wasmModule) throw new Error('Encryption module not initialized');

  const privPtr = allocate(X25519_PRIVATE_KEY_SIZE);
  const pubPtr = allocate(X25519_PUBLIC_KEY_SIZE);
  const secretPtr = allocate(KEY_SIZE);

  try {
    writeBytes(privPtr, privateKey);
    writeBytes(pubPtr, publicKey);

    const result = wasmModule.wasi_x25519_shared_secret(privPtr, pubPtr, secretPtr);
    if (result !== 0) throw new Error('X25519 ECDH failed');

    return readBytes(secretPtr, KEY_SIZE);
  } finally {
    deallocate(privPtr);
    deallocate(pubPtr);
    deallocate(secretPtr);
  }
}

/**
 * Derive symmetric key from X25519 shared secret
 * @param {Uint8Array} sharedSecret - ECDH shared secret
 * @param {Uint8Array|string} context - Context for key derivation
 * @returns {Uint8Array} - 32-byte symmetric key
 */
export function x25519DeriveKey(sharedSecret, context) {
  const info = typeof context === 'string'
    ? new TextEncoder().encode(context)
    : context;
  return hkdf(sharedSecret, null, info, KEY_SIZE);
}

// =============================================================================
// secp256k1 Key Exchange and Signatures (Bitcoin/Ethereum)
// =============================================================================

/**
 * Generate secp256k1 key pair
 * @param {Uint8Array} [privateKey] - Optional 32-byte private key
 * @returns {{privateKey: Uint8Array, publicKey: Uint8Array}}
 */
export function secp256k1GenerateKeyPair(privateKey) {
  if (!wasmModule) throw new Error('Encryption module not initialized');

  const privPtr = allocate(SECP256K1_PRIVATE_KEY_SIZE);
  const pubPtr = allocate(SECP256K1_PUBLIC_KEY_SIZE);

  try {
    if (privateKey) {
      writeBytes(privPtr, privateKey);
    }

    const result = wasmModule.wasi_secp256k1_generate_keypair(privPtr, pubPtr);
    if (result !== 0) throw new Error('secp256k1 key generation failed');

    return {
      privateKey: readBytes(privPtr, SECP256K1_PRIVATE_KEY_SIZE),
      publicKey: readBytes(pubPtr, SECP256K1_PUBLIC_KEY_SIZE),
    };
  } finally {
    deallocate(privPtr);
    deallocate(pubPtr);
  }
}

/**
 * Compute secp256k1 ECDH shared secret
 * @param {Uint8Array} privateKey - Our private key (32 bytes)
 * @param {Uint8Array} publicKey - Their public key (33 bytes compressed)
 * @returns {Uint8Array} - 32-byte shared secret
 */
export function secp256k1SharedSecret(privateKey, publicKey) {
  if (!wasmModule) throw new Error('Encryption module not initialized');

  const privPtr = allocate(SECP256K1_PRIVATE_KEY_SIZE);
  const pubPtr = allocate(publicKey.length);
  const secretPtr = allocate(KEY_SIZE);

  try {
    writeBytes(privPtr, privateKey);
    writeBytes(pubPtr, publicKey);

    const result = wasmModule.wasi_secp256k1_shared_secret(
      privPtr, pubPtr, publicKey.length, secretPtr
    );
    if (result !== 0) throw new Error('secp256k1 ECDH failed');

    return readBytes(secretPtr, KEY_SIZE);
  } finally {
    deallocate(privPtr);
    deallocate(pubPtr);
    deallocate(secretPtr);
  }
}

/**
 * Derive symmetric key from secp256k1 shared secret
 */
export function secp256k1DeriveKey(sharedSecret, context) {
  const info = typeof context === 'string'
    ? new TextEncoder().encode(context)
    : context;
  return hkdf(sharedSecret, null, info, KEY_SIZE);
}

/**
 * Sign data with secp256k1 ECDSA
 * @param {Uint8Array} privateKey - Signing private key (32 bytes)
 * @param {Uint8Array} data - Data to sign
 * @returns {Uint8Array} - Signature (DER encoded)
 */
export function secp256k1Sign(privateKey, data) {
  if (!wasmModule) throw new Error('Encryption module not initialized');

  const privPtr = allocate(SECP256K1_PRIVATE_KEY_SIZE);
  const dataPtr = allocate(data.length);
  const sigPtr = allocate(72); // Max DER signature size
  const sigSizePtr = allocate(4);

  try {
    writeBytes(privPtr, privateKey);
    writeBytes(dataPtr, data);

    const result = wasmModule.wasi_secp256k1_sign(
      privPtr, dataPtr, data.length, sigPtr, sigSizePtr
    );
    if (result !== 0) throw new Error('secp256k1 signing failed');

    const sigSize = new DataView(wasmMemory.buffer).getUint32(sigSizePtr, true);
    return readBytes(sigPtr, sigSize);
  } finally {
    deallocate(privPtr);
    deallocate(dataPtr);
    deallocate(sigPtr);
    deallocate(sigSizePtr);
  }
}

/**
 * Verify secp256k1 ECDSA signature
 * @param {Uint8Array} publicKey - Verification public key (33 bytes)
 * @param {Uint8Array} data - Original data
 * @param {Uint8Array} signature - Signature to verify
 * @returns {boolean} - True if valid
 */
export function secp256k1Verify(publicKey, data, signature) {
  if (!wasmModule) throw new Error('Encryption module not initialized');

  const pubPtr = allocate(publicKey.length);
  const dataPtr = allocate(data.length);
  const sigPtr = allocate(signature.length);

  try {
    writeBytes(pubPtr, publicKey);
    writeBytes(dataPtr, data);
    writeBytes(sigPtr, signature);

    const result = wasmModule.wasi_secp256k1_verify(
      pubPtr, publicKey.length,
      dataPtr, data.length,
      sigPtr, signature.length
    );
    return result === 0;
  } finally {
    deallocate(pubPtr);
    deallocate(dataPtr);
    deallocate(sigPtr);
  }
}

// =============================================================================
// P-256 Key Exchange and Signatures (NIST)
// =============================================================================

/**
 * Generate P-256 key pair
 * @param {Uint8Array} [privateKey] - Optional 32-byte private key
 * @returns {{privateKey: Uint8Array, publicKey: Uint8Array}}
 */
export function p256GenerateKeyPair(privateKey) {
  if (!wasmModule) throw new Error('Encryption module not initialized');

  const privPtr = allocate(P256_PRIVATE_KEY_SIZE);
  const pubPtr = allocate(P256_PUBLIC_KEY_SIZE);

  try {
    if (privateKey) {
      writeBytes(privPtr, privateKey);
    }

    const result = wasmModule.wasi_p256_generate_keypair(privPtr, pubPtr);
    if (result !== 0) throw new Error('P-256 key generation failed');

    return {
      privateKey: readBytes(privPtr, P256_PRIVATE_KEY_SIZE),
      publicKey: readBytes(pubPtr, P256_PUBLIC_KEY_SIZE),
    };
  } finally {
    deallocate(privPtr);
    deallocate(pubPtr);
  }
}

/**
 * Compute P-256 ECDH shared secret
 * @param {Uint8Array} privateKey - Our private key (32 bytes)
 * @param {Uint8Array} publicKey - Their public key (33 bytes compressed)
 * @returns {Uint8Array} - 32-byte shared secret
 */
export function p256SharedSecret(privateKey, publicKey) {
  if (!wasmModule) throw new Error('Encryption module not initialized');

  const privPtr = allocate(P256_PRIVATE_KEY_SIZE);
  const pubPtr = allocate(publicKey.length);
  const secretPtr = allocate(KEY_SIZE);

  try {
    writeBytes(privPtr, privateKey);
    writeBytes(pubPtr, publicKey);

    const result = wasmModule.wasi_p256_shared_secret(
      privPtr, pubPtr, publicKey.length, secretPtr
    );
    if (result !== 0) throw new Error('P-256 ECDH failed');

    return readBytes(secretPtr, KEY_SIZE);
  } finally {
    deallocate(privPtr);
    deallocate(pubPtr);
    deallocate(secretPtr);
  }
}

/**
 * Derive symmetric key from P-256 shared secret
 */
export function p256DeriveKey(sharedSecret, context) {
  const info = typeof context === 'string'
    ? new TextEncoder().encode(context)
    : context;
  return hkdf(sharedSecret, null, info, KEY_SIZE);
}

/**
 * Sign data with P-256 ECDSA
 * @param {Uint8Array} privateKey - Signing private key (32 bytes)
 * @param {Uint8Array} data - Data to sign
 * @returns {Uint8Array} - Signature (DER encoded)
 */
export function p256Sign(privateKey, data) {
  if (!wasmModule) throw new Error('Encryption module not initialized');

  const privPtr = allocate(P256_PRIVATE_KEY_SIZE);
  const dataPtr = allocate(data.length);
  const sigPtr = allocate(72); // Max DER signature size
  const sigSizePtr = allocate(4);

  try {
    writeBytes(privPtr, privateKey);
    writeBytes(dataPtr, data);

    const result = wasmModule.wasi_p256_sign(
      privPtr, dataPtr, data.length, sigPtr, sigSizePtr
    );
    if (result !== 0) throw new Error('P-256 signing failed');

    const sigSize = new DataView(wasmMemory.buffer).getUint32(sigSizePtr, true);
    return readBytes(sigPtr, sigSize);
  } finally {
    deallocate(privPtr);
    deallocate(dataPtr);
    deallocate(sigPtr);
    deallocate(sigSizePtr);
  }
}

/**
 * Verify P-256 ECDSA signature
 * @param {Uint8Array} publicKey - Verification public key (33 bytes)
 * @param {Uint8Array} data - Original data
 * @param {Uint8Array} signature - Signature to verify
 * @returns {boolean} - True if valid
 */
export function p256Verify(publicKey, data, signature) {
  if (!wasmModule) throw new Error('Encryption module not initialized');

  const pubPtr = allocate(publicKey.length);
  const dataPtr = allocate(data.length);
  const sigPtr = allocate(signature.length);

  try {
    writeBytes(pubPtr, publicKey);
    writeBytes(dataPtr, data);
    writeBytes(sigPtr, signature);

    const result = wasmModule.wasi_p256_verify(
      pubPtr, publicKey.length,
      dataPtr, data.length,
      sigPtr, signature.length
    );
    return result === 0;
  } finally {
    deallocate(pubPtr);
    deallocate(dataPtr);
    deallocate(sigPtr);
  }
}

// =============================================================================
// Ed25519 Signatures
// =============================================================================

/**
 * Generate Ed25519 signing key pair
 * @returns {{privateKey: Uint8Array, publicKey: Uint8Array}}
 */
export function ed25519GenerateKeyPair() {
  if (!wasmModule) throw new Error('Encryption module not initialized');

  const privPtr = allocate(ED25519_PRIVATE_KEY_SIZE);
  const pubPtr = allocate(ED25519_PUBLIC_KEY_SIZE);

  try {
    const result = wasmModule.wasi_ed25519_generate_keypair(privPtr, pubPtr);
    if (result !== 0) throw new Error('Ed25519 key generation failed');

    return {
      privateKey: readBytes(privPtr, ED25519_PRIVATE_KEY_SIZE),
      publicKey: readBytes(pubPtr, ED25519_PUBLIC_KEY_SIZE),
    };
  } finally {
    deallocate(privPtr);
    deallocate(pubPtr);
  }
}

/**
 * Sign data with Ed25519
 * @param {Uint8Array} privateKey - Signing private key (64 bytes)
 * @param {Uint8Array} data - Data to sign
 * @returns {Uint8Array} - 64-byte signature
 */
export function ed25519Sign(privateKey, data) {
  if (!wasmModule) throw new Error('Encryption module not initialized');

  const privPtr = allocate(ED25519_PRIVATE_KEY_SIZE);
  const dataPtr = allocate(data.length);
  const sigPtr = allocate(ED25519_SIGNATURE_SIZE);

  try {
    writeBytes(privPtr, privateKey);
    writeBytes(dataPtr, data);

    const result = wasmModule.wasi_ed25519_sign(
      privPtr, dataPtr, data.length, sigPtr
    );
    if (result !== 0) throw new Error('Ed25519 signing failed');

    return readBytes(sigPtr, ED25519_SIGNATURE_SIZE);
  } finally {
    deallocate(privPtr);
    deallocate(dataPtr);
    deallocate(sigPtr);
  }
}

/**
 * Verify Ed25519 signature
 * @param {Uint8Array} publicKey - Verification public key (32 bytes)
 * @param {Uint8Array} data - Original data
 * @param {Uint8Array} signature - 64-byte signature
 * @returns {boolean} - True if valid
 */
export function ed25519Verify(publicKey, data, signature) {
  if (!wasmModule) throw new Error('Encryption module not initialized');

  const pubPtr = allocate(ED25519_PUBLIC_KEY_SIZE);
  const dataPtr = allocate(data.length);
  const sigPtr = allocate(ED25519_SIGNATURE_SIZE);

  try {
    writeBytes(pubPtr, publicKey);
    writeBytes(dataPtr, data);
    writeBytes(sigPtr, signature);

    const result = wasmModule.wasi_ed25519_verify(
      pubPtr, dataPtr, data.length, sigPtr
    );
    return result === 0;
  } finally {
    deallocate(pubPtr);
    deallocate(dataPtr);
    deallocate(sigPtr);
  }
}

// =============================================================================
// Algorithm Constants (for backward compatibility)
// =============================================================================

export const KeyExchangeAlgorithm = {
  X25519: 'x25519',
  SECP256K1: 'secp256k1',
  P256: 'p256',
};

export const SignatureAlgorithm = {
  ED25519: 'ed25519',
  SECP256K1_ECDSA: 'secp256k1-ecdsa',
  P256_ECDSA: 'p256-ecdsa',
};

export const SymmetricAlgorithm = {
  AES_256_CTR: 'aes-256-ctr',
};

export const KeyDerivationFunction = {
  HKDF_SHA256: 'hkdf-sha256',
};

// =============================================================================
// Encryption Context (field-level key derivation)
// =============================================================================

/**
 * Encryption context for field-level key derivation
 */
export class EncryptionContext {
  #key;

  /**
   * Create encryption context
   * @param {Uint8Array} key - 32-byte master key
   */
  constructor(key) {
    if (key.length !== KEY_SIZE) {
      throw new Error('Key must be 32 bytes');
    }
    this.#key = new Uint8Array(key);
  }

  /**
   * Create from hex string
   * @param {string} hexKey
   * @returns {EncryptionContext}
   */
  static fromHex(hexKey) {
    const key = new Uint8Array(hexKey.match(/.{1,2}/g).map(b => parseInt(b, 16)));
    return new EncryptionContext(key);
  }

  /**
   * Derive field-specific key
   * @param {number} fieldId
   * @returns {Uint8Array}
   */
  deriveFieldKey(fieldId) {
    const info = new Uint8Array(19);
    new TextEncoder().encodeInto('flatbuffers-field', info);
    info[17] = (fieldId >> 8) & 0xff;
    info[18] = fieldId & 0xff;
    return hkdf(this.#key, null, info, KEY_SIZE);
  }

  /**
   * Derive field-specific IV
   * @param {number} fieldId
   * @returns {Uint8Array}
   */
  deriveFieldIV(fieldId) {
    const info = new Uint8Array(16);
    new TextEncoder().encodeInto('flatbuffers-iv', info);
    info[14] = (fieldId >> 8) & 0xff;
    info[15] = fieldId & 0xff;
    return hkdf(this.#key, null, info, IV_SIZE);
  }

  /**
   * Encrypt scalar value
   * @param {Uint8Array} buffer
   * @param {number} offset
   * @param {number} size
   * @param {number} fieldId
   */
  encryptScalar(buffer, offset, size, fieldId) {
    const key = this.deriveFieldKey(fieldId);
    const iv = this.deriveFieldIV(fieldId);
    const data = buffer.subarray(offset, offset + size);
    encryptBytes(data, key, iv);
  }

  /**
   * Encrypt string value
   * @param {Uint8Array} buffer
   * @param {number} offset
   * @param {number} length
   * @param {number} fieldId
   */
  encryptString(buffer, offset, length, fieldId) {
    const key = this.deriveFieldKey(fieldId);
    const iv = this.deriveFieldIV(fieldId);
    const data = buffer.subarray(offset, offset + length);
    encryptBytes(data, key, iv);
  }

  /**
   * Encrypt vector data
   * @param {Uint8Array} buffer
   * @param {number} offset
   * @param {number} elementSize
   * @param {number} count
   * @param {number} fieldId
   */
  encryptVector(buffer, offset, elementSize, count, fieldId) {
    const key = this.deriveFieldKey(fieldId);
    const iv = this.deriveFieldIV(fieldId);
    const data = buffer.subarray(offset, offset + elementSize * count);
    encryptBytes(data, key, iv);
  }
}

// =============================================================================
// Encryption Header (for hybrid encryption)
// =============================================================================

/**
 * Create encryption header for hybrid encryption
 * @param {Object} options
 * @param {string} options.algorithm - Key exchange algorithm
 * @param {Uint8Array} options.senderPublicKey - Sender's public key
 * @param {Uint8Array} options.recipientKeyId - Recipient key identifier
 * @param {Uint8Array} [options.iv] - Optional IV (generated if not provided)
 * @returns {Object}
 */
export function createEncryptionHeader(options) {
  const iv = options.iv || crypto.getRandomValues(new Uint8Array(IV_SIZE));
  return {
    version: 1,
    algorithm: options.algorithm,
    senderPublicKey: options.senderPublicKey,
    recipientKeyId: options.recipientKeyId,
    iv,
  };
}

/**
 * Compute key ID from public key (first 8 bytes of SHA-256)
 * @param {Uint8Array} publicKey
 * @returns {Uint8Array} - 8-byte key ID
 */
export function computeKeyId(publicKey) {
  return sha256(publicKey).subarray(0, 8);
}

/**
 * Convert encryption header to JSON
 * @param {Object} header
 * @returns {Object}
 */
export function encryptionHeaderToJSON(header) {
  return {
    version: header.version,
    algorithm: header.algorithm,
    senderPublicKey: Array.from(header.senderPublicKey),
    recipientKeyId: Array.from(header.recipientKeyId),
    iv: Array.from(header.iv),
  };
}

/**
 * Parse encryption header from JSON
 * @param {Object} json
 * @returns {Object}
 */
export function encryptionHeaderFromJSON(json) {
  return {
    version: json.version,
    algorithm: json.algorithm,
    senderPublicKey: new Uint8Array(json.senderPublicKey),
    recipientKeyId: new Uint8Array(json.recipientKeyId),
    iv: new Uint8Array(json.iv),
  };
}

// =============================================================================
// Field-level encryption helpers
// =============================================================================

/**
 * Encrypt scalar in buffer
 * @param {Uint8Array} buffer
 * @param {number} offset
 * @param {number} size
 * @param {EncryptionContext} ctx
 * @param {number} fieldId
 */
export function encryptScalar(buffer, offset, size, ctx, fieldId) {
  ctx.encryptScalar(buffer, offset, size, fieldId);
}

// =============================================================================
// Default export
// =============================================================================

export default {
  // Initialization
  initEncryption,
  isInitialized,
  hasCryptopp,
  getVersion,

  // Hash
  sha256,

  // Symmetric encryption
  encryptBytes,
  decryptBytes,
  hkdf,

  // X25519
  x25519GenerateKeyPair,
  x25519SharedSecret,
  x25519DeriveKey,

  // secp256k1
  secp256k1GenerateKeyPair,
  secp256k1SharedSecret,
  secp256k1DeriveKey,
  secp256k1Sign,
  secp256k1Verify,

  // P-256
  p256GenerateKeyPair,
  p256SharedSecret,
  p256DeriveKey,
  p256Sign,
  p256Verify,

  // Ed25519
  ed25519GenerateKeyPair,
  ed25519Sign,
  ed25519Verify,

  // Constants
  KeyExchangeAlgorithm,
  SignatureAlgorithm,
  SymmetricAlgorithm,
  KeyDerivationFunction,

  // Classes
  EncryptionContext,

  // Header utilities
  createEncryptionHeader,
  computeKeyId,
  encryptionHeaderToJSON,
  encryptionHeaderFromJSON,
  encryptScalar,
};
