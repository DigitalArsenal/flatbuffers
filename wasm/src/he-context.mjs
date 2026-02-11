/**
 * Homomorphic Encryption Context for FlatBuffers WASM
 *
 * Provides a JavaScript wrapper around the WASM HE functions,
 * enabling homomorphic encryption operations on FlatBuffer data.
 *
 * Requires the HE-enabled WASM build (flatc-wasm-he.js).
 *
 * @example
 * ```js
 * import { HEContext, initHEModule } from './he-context.mjs';
 *
 * // Initialize with WASM module
 * initHEModule(wasmModule);
 *
 * // Create client context (has secret key)
 * const client = HEContext.createClient();
 * const publicKey = client.getPublicKey();
 * const relinKeys = client.getRelinKeys();
 *
 * // Create server context (public key only, cannot decrypt)
 * const server = HEContext.createServer(publicKey);
 * server.setRelinKeys(relinKeys);
 *
 * // Client encrypts values
 * const ct1 = client.encryptInt64(42n);
 * const ct2 = client.encryptInt64(10n);
 *
 * // Server performs homomorphic operations
 * const sum = server.add(ct1, ct2);      // Encrypted 52
 * const prod = server.multiply(ct1, ct2); // Encrypted 420
 *
 * // Client decrypts results
 * console.log(client.decryptInt64(sum));  // 52n
 * console.log(client.decryptInt64(prod)); // 420n
 * ```
 */

let wasmModule = null;

/**
 * Initialize the HE module with a WASM instance.
 * Must be called before using HEContext.
 * @param {object} module - The Emscripten WASM module with HE exports
 */
export function initHEModule(module) {
  wasmModule = module;
}

/**
 * Get the current WASM module (for internal use).
 * @returns {object|null}
 */
export function getHEModule() {
  return wasmModule;
}

/**
 * Get the last error message from WASM.
 * @returns {string}
 */
export function getLastError() {
  if (!wasmModule) return 'WASM module not initialized';
  const errPtr = wasmModule._wasm_get_last_error();
  return errPtr ? wasmModule.UTF8ToString(errPtr) : '';
}

/** Default polynomial modulus degree (4096 = ~128-bit security) */
export const DEFAULT_POLY_MODULUS_DEGREE = 4096;

/**
 * HEContext provides homomorphic encryption operations.
 *
 * Two modes:
 * - Client mode (created with createClient): Has secret key, can encrypt/decrypt
 * - Server mode (created with createServer): Public key only, can compute but not decrypt
 */
export class HEContext {
  #contextId;
  #hasSecretKey;

  /**
   * @param {number} contextId - WASM context ID
   * @param {boolean} hasSecretKey - Whether this is a client context
   */
  constructor(contextId, hasSecretKey) {
    this.#contextId = contextId;
    this.#hasSecretKey = hasSecretKey;
  }

  /**
   * Get the underlying WASM context ID (for internal/advanced use).
   * @returns {number}
   */
  getContextId() {
    return this.#contextId;
  }

  /**
   * Create a client context with full key pair.
   * Client can encrypt, decrypt, and perform HE operations.
   *
   * @param {number} [polyModulusDegree=4096] - Power of 2, typically 4096, 8192, or 16384.
   *   Higher = more security but slower and larger ciphertexts.
   * @returns {HEContext}
   */
  static createClient(polyModulusDegree = DEFAULT_POLY_MODULUS_DEGREE) {
    if (!wasmModule) throw new Error('WASM module not initialized. Call initHEModule first.');

    const ctxId = wasmModule._wasm_he_context_create_client(polyModulusDegree);
    if (ctxId < 0) {
      throw new Error(`Failed to create HE client context: ${getLastError()}`);
    }
    return new HEContext(ctxId, true);
  }

  /**
   * Create a client context from a deterministic seed.
   * The seed is used to initialize the PRNG for key generation,
   * producing deterministic keys from the same seed.
   *
   * @param {Uint8Array} seed - 64-byte seed for deterministic key generation
   * @param {number} [polyModulusDegree=4096] - Polynomial modulus degree
   * @returns {HEContext}
   */
  static createClientFromSeed(seed, polyModulusDegree = DEFAULT_POLY_MODULUS_DEGREE) {
    if (!wasmModule) throw new Error('WASM module not initialized. Call initHEModule first.');

    if (!(seed instanceof Uint8Array) || seed.length < 32) {
      throw new Error('Seed must be a Uint8Array of at least 32 bytes');
    }

    // Check if seeded creation is available
    if (typeof wasmModule._wasm_he_context_create_client_seeded !== 'function') {
      throw new Error('Seeded HE context creation not available. Requires HE-enabled WASM build with seeded support.');
    }

    const seedPtr = wasmModule._malloc(seed.length);
    try {
      wasmModule.HEAPU8.set(seed, seedPtr);
      const ctxId = wasmModule._wasm_he_context_create_client_seeded(
        polyModulusDegree, seedPtr, seed.length
      );
      if (ctxId < 0) {
        throw new Error(`Failed to create seeded HE client context: ${getLastError()}`);
      }
      return new HEContext(ctxId, true);
    } finally {
      wasmModule._free(seedPtr);
    }
  }

  /**
   * Create a server context from a public key.
   * Server can perform HE operations but cannot decrypt.
   *
   * @param {Uint8Array} publicKey - Serialized public key from a client context
   * @returns {HEContext}
   */
  static createServer(publicKey) {
    if (!wasmModule) throw new Error('WASM module not initialized. Call initHEModule first.');

    const pkPtr = wasmModule._malloc(publicKey.length);
    try {
      wasmModule.HEAPU8.set(publicKey, pkPtr);
      const ctxId = wasmModule._wasm_he_context_create_server(pkPtr, publicKey.length);
      if (ctxId < 0) {
        throw new Error(`Failed to create HE server context: ${getLastError()}`);
      }
      return new HEContext(ctxId, false);
    } finally {
      wasmModule._free(pkPtr);
    }
  }

  /**
   * Destroy the context and free resources.
   */
  destroy() {
    if (!wasmModule || this.#contextId < 0) return;
    wasmModule._wasm_he_context_destroy(this.#contextId);
    this.#contextId = -1;
  }

  /**
   * Check if this is a client context (has secret key).
   * @returns {boolean}
   */
  canDecrypt() {
    return this.#hasSecretKey;
  }

  /**
   * Get the serialized public key.
   * @returns {Uint8Array}
   */
  getPublicKey() {
    return this.#getKeyData(wasmModule._wasm_he_get_public_key);
  }

  /**
   * Get the serialized relinearization keys.
   * These are needed by server contexts for multiplication.
   * @returns {Uint8Array}
   */
  getRelinKeys() {
    return this.#getKeyData(wasmModule._wasm_he_get_relin_keys);
  }

  /**
   * Get the serialized secret key (client only).
   * @throws {Error} if this is a server context
   * @returns {Uint8Array}
   */
  getSecretKey() {
    if (!this.#hasSecretKey) {
      throw new Error('Cannot get secret key from server context');
    }
    return this.#getKeyData(wasmModule._wasm_he_get_secret_key);
  }

  /**
   * Set relinearization keys (for server context).
   * Required before performing multiplication operations.
   * @param {Uint8Array} relinKeys
   */
  setRelinKeys(relinKeys) {
    if (!wasmModule) throw new Error('WASM module not initialized');

    const rkPtr = wasmModule._malloc(relinKeys.length);
    try {
      wasmModule.HEAPU8.set(relinKeys, rkPtr);
      const result = wasmModule._wasm_he_set_relin_keys(this.#contextId, rkPtr, relinKeys.length);
      if (result < 0) {
        throw new Error(`Failed to set relin keys: ${getLastError()}`);
      }
    } finally {
      wasmModule._free(rkPtr);
    }
  }

  // =========================================================================
  // Encryption
  // =========================================================================

  /**
   * Encrypt a 64-bit integer.
   * @param {bigint} value
   * @returns {Uint8Array} Serialized ciphertext
   */
  encryptInt64(value) {
    if (!wasmModule) throw new Error('WASM module not initialized');

    const outLenPtr = wasmModule._malloc(4);
    try {
      const resultPtr = wasmModule._wasm_he_encrypt_int64(this.#contextId, value, outLenPtr);
      if (resultPtr === 0) {
        throw new Error(`Encryption failed: ${getLastError()}`);
      }
      const outLen = wasmModule.getValue(outLenPtr, 'i32');
      return new Uint8Array(wasmModule.HEAPU8.buffer, resultPtr, outLen).slice();
    } finally {
      wasmModule._free(outLenPtr);
    }
  }

  /**
   * Encrypt a double (using fixed-point encoding).
   * @param {number} value
   * @returns {Uint8Array} Serialized ciphertext
   */
  encryptDouble(value) {
    if (!wasmModule) throw new Error('WASM module not initialized');

    const outLenPtr = wasmModule._malloc(4);
    try {
      const resultPtr = wasmModule._wasm_he_encrypt_double(this.#contextId, value, outLenPtr);
      if (resultPtr === 0) {
        throw new Error(`Encryption failed: ${getLastError()}`);
      }
      const outLen = wasmModule.getValue(outLenPtr, 'i32');
      return new Uint8Array(wasmModule.HEAPU8.buffer, resultPtr, outLen).slice();
    } finally {
      wasmModule._free(outLenPtr);
    }
  }

  // =========================================================================
  // Decryption (client only)
  // =========================================================================

  /**
   * Decrypt a ciphertext to a 64-bit integer.
   * @param {Uint8Array} ciphertext
   * @returns {bigint}
   * @throws {Error} if this is a server context
   */
  decryptInt64(ciphertext) {
    if (!this.#hasSecretKey) {
      throw new Error('Cannot decrypt: server context has no secret key');
    }
    if (!wasmModule) throw new Error('WASM module not initialized');

    const ctPtr = wasmModule._malloc(ciphertext.length);
    try {
      wasmModule.HEAPU8.set(ciphertext, ctPtr);
      return wasmModule._wasm_he_decrypt_int64(this.#contextId, ctPtr, ciphertext.length);
    } finally {
      wasmModule._free(ctPtr);
    }
  }

  /**
   * Decrypt a ciphertext to a double.
   * @param {Uint8Array} ciphertext
   * @returns {number}
   * @throws {Error} if this is a server context
   */
  decryptDouble(ciphertext) {
    if (!this.#hasSecretKey) {
      throw new Error('Cannot decrypt: server context has no secret key');
    }
    if (!wasmModule) throw new Error('WASM module not initialized');

    const ctPtr = wasmModule._malloc(ciphertext.length);
    try {
      wasmModule.HEAPU8.set(ciphertext, ctPtr);
      return wasmModule._wasm_he_decrypt_double(this.#contextId, ctPtr, ciphertext.length);
    } finally {
      wasmModule._free(ctPtr);
    }
  }

  // =========================================================================
  // Homomorphic operations
  // =========================================================================

  /**
   * Add two ciphertexts homomorphically.
   * @param {Uint8Array} ct1
   * @param {Uint8Array} ct2
   * @returns {Uint8Array}
   */
  add(ct1, ct2) {
    return this.#binaryOp(ct1, ct2, wasmModule._wasm_he_add);
  }

  /**
   * Subtract two ciphertexts homomorphically.
   * @param {Uint8Array} ct1
   * @param {Uint8Array} ct2
   * @returns {Uint8Array}
   */
  sub(ct1, ct2) {
    return this.#binaryOp(ct1, ct2, wasmModule._wasm_he_sub);
  }

  /**
   * Multiply two ciphertexts homomorphically.
   * Requires relinearization keys to be set.
   * @param {Uint8Array} ct1
   * @param {Uint8Array} ct2
   * @returns {Uint8Array}
   */
  multiply(ct1, ct2) {
    return this.#binaryOp(ct1, ct2, wasmModule._wasm_he_multiply);
  }

  /**
   * Negate a ciphertext homomorphically.
   * @param {Uint8Array} ct
   * @returns {Uint8Array}
   */
  negate(ct) {
    if (!wasmModule) throw new Error('WASM module not initialized');

    const ctPtr = wasmModule._malloc(ct.length);
    const outLenPtr = wasmModule._malloc(4);
    try {
      wasmModule.HEAPU8.set(ct, ctPtr);
      const resultPtr = wasmModule._wasm_he_negate(this.#contextId, ctPtr, ct.length, outLenPtr);
      if (resultPtr === 0) {
        throw new Error(`HE negate failed: ${getLastError()}`);
      }
      const outLen = wasmModule.getValue(outLenPtr, 'i32');
      return new Uint8Array(wasmModule.HEAPU8.buffer, resultPtr, outLen).slice();
    } finally {
      wasmModule._free(ctPtr);
      wasmModule._free(outLenPtr);
    }
  }

  /**
   * Add a plaintext value to a ciphertext.
   * @param {Uint8Array} ct
   * @param {bigint} plain
   * @returns {Uint8Array}
   */
  addPlain(ct, plain) {
    return this.#plainOp(ct, plain, wasmModule._wasm_he_add_plain);
  }

  /**
   * Multiply a ciphertext by a plaintext value.
   * @param {Uint8Array} ct
   * @param {bigint} plain
   * @returns {Uint8Array}
   */
  multiplyPlain(ct, plain) {
    return this.#plainOp(ct, plain, wasmModule._wasm_he_multiply_plain);
  }

  // =========================================================================
  // Private helpers
  // =========================================================================

  #getKeyData(fn) {
    if (!wasmModule) throw new Error('WASM module not initialized');

    const outLenPtr = wasmModule._malloc(4);
    try {
      const resultPtr = fn.call(wasmModule, this.#contextId, outLenPtr);
      if (resultPtr === 0) {
        throw new Error(`Failed to get key: ${getLastError()}`);
      }
      const outLen = wasmModule.getValue(outLenPtr, 'i32');
      return new Uint8Array(wasmModule.HEAPU8.buffer, resultPtr, outLen).slice();
    } finally {
      wasmModule._free(outLenPtr);
    }
  }

  #binaryOp(ct1, ct2, fn) {
    if (!wasmModule) throw new Error('WASM module not initialized');

    const ct1Ptr = wasmModule._malloc(ct1.length);
    const ct2Ptr = wasmModule._malloc(ct2.length);
    const outLenPtr = wasmModule._malloc(4);
    try {
      wasmModule.HEAPU8.set(ct1, ct1Ptr);
      wasmModule.HEAPU8.set(ct2, ct2Ptr);
      const resultPtr = fn.call(wasmModule, this.#contextId, ct1Ptr, ct1.length, ct2Ptr, ct2.length, outLenPtr);
      if (resultPtr === 0) {
        throw new Error(`HE operation failed: ${getLastError()}`);
      }
      const outLen = wasmModule.getValue(outLenPtr, 'i32');
      return new Uint8Array(wasmModule.HEAPU8.buffer, resultPtr, outLen).slice();
    } finally {
      wasmModule._free(ct1Ptr);
      wasmModule._free(ct2Ptr);
      wasmModule._free(outLenPtr);
    }
  }

  #plainOp(ct, plain, fn) {
    if (!wasmModule) throw new Error('WASM module not initialized');

    const ctPtr = wasmModule._malloc(ct.length);
    const outLenPtr = wasmModule._malloc(4);
    try {
      wasmModule.HEAPU8.set(ct, ctPtr);
      const resultPtr = fn.call(wasmModule, this.#contextId, ctPtr, ct.length, plain, outLenPtr);
      if (resultPtr === 0) {
        throw new Error(`HE operation failed: ${getLastError()}`);
      }
      const outLen = wasmModule.getValue(outLenPtr, 'i32');
      return new Uint8Array(wasmModule.HEAPU8.buffer, resultPtr, outLen).slice();
    } finally {
      wasmModule._free(ctPtr);
      wasmModule._free(outLenPtr);
    }
  }
}
