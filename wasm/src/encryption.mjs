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
 * - P-384 ECDH and ECDSA (NIST, higher security)
 * - Ed25519 signatures
 * - HKDF-SHA256 key derivation
 *
 * SECURITY THREAT MODEL:
 * ----------------------
 * This module provides cryptographic operations in JavaScript/WASM environments.
 * Users should understand the following security boundaries:
 *
 * 1. MEMORY PROTECTION LIMITATIONS:
 *    - JavaScript does not provide secure memory that can be locked or protected
 *    - Keys and plaintext may remain in memory after use until garbage collected
 *    - The zeroBytes() function attempts best-effort memory clearing but cannot
 *      guarantee immediate zeroing due to JS engine optimizations
 *    - Browser extensions, debugging tools, or memory dumps may expose secrets
 *    - For high-security applications, consider using WebCrypto API with
 *      non-extractable keys where possible
 *
 * 2. SIDE-CHANNEL CONSIDERATIONS:
 *    - WASM execution may be vulnerable to timing attacks
 *    - Cache-timing attacks are possible in shared environments
 *    - Do not use in multi-tenant environments where attackers control co-located code
 *
 * 3. RANDOM NUMBER GENERATION:
 *    - Requires crypto.getRandomValues() (browser) or Node.js crypto module
 *    - Will throw an error if no secure random source is available
 *    - Never use in environments without proper entropy sources
 *
 * 4. AUTHENTICATION:
 *    - encryptBuffer() computes HMAC-SHA256 for integrity protection by default
 *    - The MAC must be stored with encrypted data and passed to decryptBuffer()
 *    - To disable authentication (not recommended), pass { authenticate: false }
 *    - Low-level encryptBytes()/decryptBytes() are deprecated; use encryptAuthenticated()
 *
 * 5. KEY MANAGEMENT:
 *    - This module does not persist or protect keys at rest
 *    - Users are responsible for secure key storage and rotation
 *    - Use destroyKey() and destroy() methods when done with sensitive material
 */

// WASM module instance (set by initEncryption)
let wasmModule = null;
let wasmMemory = null;

// Cached encoder/decoder instances for performance
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

// =============================================================================
// IV Tracking for AES-CTR Security (VULN-001 fix)
// =============================================================================

/**
 * Tracks used IVs per key to prevent catastrophic IV reuse in AES-CTR mode.
 * Key: hex string of key hash, Value: Set of hex IV strings
 * @type {Map<string, Set<string>>}
 */
const usedIVsByKey = new Map();

/**
 * Maximum number of IVs to track per key before forcing key rotation.
 * With 128-bit IVs, birthday paradox collision risk is negligible below 2^64,
 * but we limit to 1M to bound memory usage.
 */
const MAX_IVS_PER_KEY = 1_000_000;

/**
 * Convert bytes to hex string for Map keys
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function bytesToHex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Get a hash of the key for IV tracking (we don't store the full key)
 * SECURITY FIX (VULN-NEW-005): Use 64-bit hash instead of 32-bit to reduce
 * collision probability from ~1/2^16 (birthday bound) to ~1/2^32
 * @param {Uint8Array} key
 * @returns {string}
 */
function getKeyId(key) {
  // Use two independent FNV-1a hashes to create a 64-bit key identifier
  // This significantly reduces collision probability vs. single 32-bit hash
  let hashLow = 0x811c9dc5;  // FNV-1a offset basis
  let hashHigh = 0xcbf29ce4; // Different offset for second hash

  for (let i = 0; i < key.length; i++) {
    // First hash (low 32 bits)
    hashLow ^= key[i];
    hashLow = Math.imul(hashLow, 0x01000193); // FNV-1a prime

    // Second hash (high 32 bits) with different initial state
    hashHigh ^= key[i];
    hashHigh = Math.imul(hashHigh, 0x01000193);
    hashHigh ^= (i & 0xff); // Mix in position for additional entropy
  }

  // Combine into 64-bit hex string
  const lowHex = (hashLow >>> 0).toString(16).padStart(8, '0');
  const highHex = (hashHigh >>> 0).toString(16).padStart(8, '0');
  return highHex + lowHex;
}

/**
 * Check and record IV usage for a key. Throws if IV was already used.
 * @param {Uint8Array} key - Encryption key
 * @param {Uint8Array} iv - IV to check
 * @param {boolean} [trackUsage=true] - Whether to track this IV (false for decryption)
 * @throws {CryptoError} If IV was already used with this key
 */
function checkAndRecordIV(key, iv, trackUsage = true) {
  const keyId = getKeyId(key);
  const ivHex = bytesToHex(iv);

  if (!usedIVsByKey.has(keyId)) {
    usedIVsByKey.set(keyId, new Set());
  }

  const usedIVs = usedIVsByKey.get(keyId);

  if (usedIVs.has(ivHex)) {
    throw new CryptoError(
      CryptoErrorCode.IV_REUSE,
      'IV has already been used with this key. AES-CTR requires unique IVs per key to maintain security. ' +
      'Generate a new random IV for each encryption operation.'
    );
  }

  if (trackUsage) {
    if (usedIVs.size >= MAX_IVS_PER_KEY) {
      throw new CryptoError(
        CryptoErrorCode.IV_REUSE,
        `Maximum IV count (${MAX_IVS_PER_KEY}) reached for this key. ` +
        'Rotate to a new key to maintain security.'
      );
    }
    usedIVs.add(ivHex);
  }
}

/**
 * Clear IV tracking for a specific key (call when key is rotated/destroyed)
 * @param {Uint8Array} key
 */
export function clearIVTracking(key) {
  if (key) {
    const keyId = getKeyId(key);
    usedIVsByKey.delete(keyId);
  }
}

/**
 * Clear all IV tracking (use with caution - only for testing or full reset)
 */
export function clearAllIVTracking() {
  usedIVsByKey.clear();
}

/**
 * Generate a cryptographically random IV
 * @returns {Uint8Array} 16-byte random IV
 */
export function generateIV() {
  return getRandomBytes(IV_SIZE);
}

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
  IV_REUSE: 'IV_REUSE',
};

/**
 * Custom error class for cryptographic operations
 */
export class CryptoError extends Error {
  /**
   * @param {string} code - Error code from CryptoErrorCode
   * @param {string} message - Human-readable error message
   * @param {Error} [cause] - Original error that caused this one
   */
  constructor(code, message, cause) {
    super(message);
    this.name = 'CryptoError';
    this.code = code;
    this.cause = cause;
  }

  /**
   * Create a CryptoError from a WASM error code
   * @param {number} wasmCode - Error code returned by WASM function
   * @param {string} operation - Name of the operation that failed
   * @returns {CryptoError}
   */
  static fromWasmCode(wasmCode, operation) {
    const codeMap = {
      1: CryptoErrorCode.INVALID_INPUT,
      2: CryptoErrorCode.INVALID_KEY_SIZE,
      3: CryptoErrorCode.MEMORY_ERROR,
      4: CryptoErrorCode.ENCRYPTION_FAILED,
      5: CryptoErrorCode.DECRYPTION_FAILED,
      6: CryptoErrorCode.KEY_GENERATION_FAILED,
      7: CryptoErrorCode.ECDH_FAILED,
      8: CryptoErrorCode.SIGNING_FAILED,
      9: CryptoErrorCode.VERIFICATION_FAILED,
    };

    const code = codeMap[wasmCode] || CryptoErrorCode.ENCRYPTION_FAILED;
    return new CryptoError(code, `${operation} failed with code ${wasmCode}`);
  }
}

// Key sizes
export const KEY_SIZE = 32;
export const IV_SIZE = 16;
export const SHA256_SIZE = 32;
export const HMAC_SIZE = 32;
export const X25519_PRIVATE_KEY_SIZE = 32;
export const X25519_PUBLIC_KEY_SIZE = 32;
export const SECP256K1_PRIVATE_KEY_SIZE = 32;
export const SECP256K1_PUBLIC_KEY_SIZE = 33;
export const P256_PRIVATE_KEY_SIZE = 32;
export const P256_PUBLIC_KEY_SIZE = 33;
export const P384_PRIVATE_KEY_SIZE = 48;
export const P384_PUBLIC_KEY_SIZE = 49;
export const ED25519_PRIVATE_KEY_SIZE = 64;
export const ED25519_PUBLIC_KEY_SIZE = 32;
export const ED25519_SIGNATURE_SIZE = 64;
export const MAX_DER_SIGNATURE_SIZE = 72;

/**
 * Initialize the encryption module with WASM
 * @param {WebAssembly.Instance} instance - The flatc-encryption.wasm instance
 */
export function initEncryption(instance) {
  wasmModule = instance.exports;
  wasmMemory = wasmModule.memory;
  // Call _initialize if it exists (WASI startup)
  if (wasmModule._initialize) {
    wasmModule._initialize();
  }
}

/**
 * Load and initialize the encryption WASM module
 * @param {string|URL|Uint8Array|ArrayBuffer} wasmSource - Path to WASM file, URL, or binary data
 * @returns {Promise<void>}
 */
export async function loadEncryptionWasm(wasmSource) {
  let wasmBytes;

  if (wasmSource instanceof Uint8Array || wasmSource instanceof ArrayBuffer) {
    wasmBytes = wasmSource;
  } else if (typeof wasmSource === 'string' || wasmSource instanceof URL) {
    const urlStr = wasmSource instanceof URL ? wasmSource.href : wasmSource;

    // Check if it's an HTTP(S) URL or file URL
    if (urlStr.startsWith('http://') || urlStr.startsWith('https://')) {
      // Use fetch for HTTP URLs (works in both Node.js 18+ and browser)
      const response = await fetch(urlStr);
      if (!response.ok) {
        throw new Error(`Failed to fetch WASM: ${response.status} ${response.statusText}`);
      }
      wasmBytes = await response.arrayBuffer();
    } else if (urlStr.startsWith('file://')) {
      // File URL - Node.js only
      if (typeof process !== 'undefined' && process.versions?.node) {
        const { readFileSync } = await import('fs');
        const { fileURLToPath } = await import('url');
        const path = fileURLToPath(urlStr);
        wasmBytes = readFileSync(path);
      } else {
        throw new Error('file:// URLs are only supported in Node.js');
      }
    } else if (typeof process !== 'undefined' && process.versions?.node) {
      // Local file path - Node.js only
      const { readFileSync } = await import('fs');
      wasmBytes = readFileSync(urlStr);
    } else {
      // In browser, use fetch for relative/absolute paths
      const response = await fetch(urlStr);
      if (!response.ok) {
        throw new Error(`Failed to fetch WASM: ${response.status} ${response.statusText}`);
      }
      wasmBytes = await response.arrayBuffer();
    }
  } else {
    throw new Error('Invalid WASM source: must be a path, URL, or binary data');
  }

  // Exception handling state
  let exceptionPtr = 0;

  // Temporary memory reference - will be set after instantiation
  let tempMemory = null;

  // Helper to get memory view safely
  function getMemoryView() {
    const mem = tempMemory || wasmMemory;
    if (!mem) {
      throw new Error('WASM memory not yet initialized');
    }
    return new DataView(mem.buffer);
  }

  // Helper to call a WASM function with exception handling
  function invoke(fn, ...args) {
    try {
      return fn(...args);
    } catch (e) {
      // Set exception state
      return 0;
    }
  }

  // WASI and env imports required by the encryption module
  const imports = {
    wasi_snapshot_preview1: {
      // Clock
      clock_time_get: (clockId, precision, resultPtr) => {
        const now = BigInt(Date.now()) * 1000000n;
        const view = getMemoryView();
        view.setBigUint64(resultPtr, now, true);
        return 0;
      },
      // Environment
      environ_sizes_get: (countPtr, sizePtr) => {
        const view = getMemoryView();
        view.setUint32(countPtr, 0, true);
        view.setUint32(sizePtr, 0, true);
        return 0;
      },
      environ_get: () => 0,
      // Random - required for cryptographic operations
      random_get: (bufPtr, bufLen) => {
        const mem = tempMemory || wasmMemory;
        if (!mem) return 1; // ERRNO_BADF
        const buf = new Uint8Array(mem.buffer, bufPtr, bufLen);
        // Use crypto.getRandomValues (available in browser and Node.js 18+)
        if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.getRandomValues) {
          globalThis.crypto.getRandomValues(buf);
        } else if (typeof process !== 'undefined' && process.versions?.node) {
          // Fallback for older Node.js
          try {
            // eslint-disable-next-line no-new-func
            const nodeCrypto = new Function('return require("crypto")')();
            const randomBytes = nodeCrypto.randomBytes(bufLen);
            buf.set(randomBytes);
          } catch {
            return 1; // ERRNO_BADF
          }
        } else {
          return 1; // ERRNO_BADF - no random source available
        }
        return 0;
      },
      // File descriptors
      fd_write: () => 0,
      fd_read: () => 0,
      fd_close: () => 0,
      fd_seek: () => 0,
    },
    env: {
      // Exception handling for Emscripten
      __cxa_throw: (ptr, type, destructor) => {
        exceptionPtr = ptr;
        throw new Error('C++ exception');
      },
      __cxa_begin_catch: (ptr) => ptr,
      __cxa_end_catch: () => {},
      __cxa_find_matching_catch_2: () => {
        return exceptionPtr;
      },
      __cxa_find_matching_catch_3: () => {
        return exceptionPtr;
      },
      __cxa_uncaught_exceptions: () => 0,
      __resumeException: (ptr) => {
        throw new Error('Resumed C++ exception');
      },
      llvm_eh_typeid_for: (type) => type,

      // Invoke wrappers for exception-safe calls
      // These are generated by Emscripten to wrap function calls that might throw
      invoke_v: (fn) => invoke(() => wasmModule.__indirect_function_table.get(fn)()),
      invoke_i: (fn) => invoke(() => wasmModule.__indirect_function_table.get(fn)()),
      invoke_ii: (fn, a) => invoke(() => wasmModule.__indirect_function_table.get(fn)(a)),
      invoke_iii: (fn, a, b) => invoke(() => wasmModule.__indirect_function_table.get(fn)(a, b)),
      invoke_iiii: (fn, a, b, c) => invoke(() => wasmModule.__indirect_function_table.get(fn)(a, b, c)),
      invoke_iiiii: (fn, a, b, c, d) => invoke(() => wasmModule.__indirect_function_table.get(fn)(a, b, c, d)),
      invoke_iiiiii: (fn, a, b, c, d, e) => invoke(() => wasmModule.__indirect_function_table.get(fn)(a, b, c, d, e)),
      invoke_iiiiiii: (fn, a, b, c, d, e, f) => invoke(() => wasmModule.__indirect_function_table.get(fn)(a, b, c, d, e, f)),
      invoke_iiiiiiii: (fn, a, b, c, d, e, f, g) => invoke(() => wasmModule.__indirect_function_table.get(fn)(a, b, c, d, e, f, g)),
      invoke_iiiiiiiiii: (fn, a, b, c, d, e, f, g, h, i) => invoke(() => wasmModule.__indirect_function_table.get(fn)(a, b, c, d, e, f, g, h, i)),
      invoke_vi: (fn, a) => invoke(() => wasmModule.__indirect_function_table.get(fn)(a)),
      invoke_vii: (fn, a, b) => invoke(() => wasmModule.__indirect_function_table.get(fn)(a, b)),
      invoke_viii: (fn, a, b, c) => invoke(() => wasmModule.__indirect_function_table.get(fn)(a, b, c)),
      invoke_viiii: (fn, a, b, c, d) => invoke(() => wasmModule.__indirect_function_table.get(fn)(a, b, c, d)),
      invoke_viiiii: (fn, a, b, c, d, e) => invoke(() => wasmModule.__indirect_function_table.get(fn)(a, b, c, d, e)),
      invoke_viiiiii: (fn, a, b, c, d, e, f) => invoke(() => wasmModule.__indirect_function_table.get(fn)(a, b, c, d, e, f)),
      invoke_viiiiiii: (fn, a, b, c, d, e, f, g) => invoke(() => wasmModule.__indirect_function_table.get(fn)(a, b, c, d, e, f, g)),
      invoke_viiiiiiiii: (fn, a, b, c, d, e, f, g, h, i) => invoke(() => wasmModule.__indirect_function_table.get(fn)(a, b, c, d, e, f, g, h, i)),
    }
  };

  // Compile and instantiate
  const { instance } = await WebAssembly.instantiate(wasmBytes, imports);

  // Store memory reference before initializing
  tempMemory = instance.exports.memory;
  wasmMemory = instance.exports.memory;

  // Initialize
  initEncryption(instance);
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
  if (!wasmMemory) throw new Error('WASM memory not initialized');
  if (ptr < 0 || ptr >= wasmMemory.buffer.byteLength) {
    throw new Error(`Invalid pointer: ${ptr} (memory size: ${wasmMemory.buffer.byteLength})`);
  }
  const safeLen = Math.min(maxLen, wasmMemory.buffer.byteLength - ptr);
  const view = new Uint8Array(wasmMemory.buffer, ptr, safeLen);
  let end = view.indexOf(0);
  if (end === -1) end = safeLen;
  return textDecoder.decode(view.subarray(0, end));
}

// Cached Node.js crypto module (lazy-loaded)
let nodeCryptoModule = null;

// Flag to track if we've already warned about RNG issues
let rngWarningShown = false;

/**
 * Get cryptographically secure random bytes (works in Node.js and browser)
 *
 * This function provides defense-in-depth by:
 * 1. Using the most secure available source (crypto.getRandomValues or Node.js crypto)
 * 2. Validating the output is not all zeros (catastrophic RNG failure detection)
 * 3. Throwing clear errors when no secure source is available
 *
 * @param {number} size - Number of random bytes
 * @returns {Uint8Array}
 * @throws {CryptoError} If no cryptographic random source is available or RNG fails
 */
function getRandomBytes(size) {
  if (size <= 0) {
    throw new CryptoError(
      CryptoErrorCode.INVALID_INPUT,
      'Size must be a positive integer'
    );
  }

  let bytes;

  // Browser environment - check for SecureContext
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.getRandomValues) {
    try {
      bytes = globalThis.crypto.getRandomValues(new Uint8Array(size));
    } catch (e) {
      // getRandomValues may fail if not in a secure context
      throw new CryptoError(
        CryptoErrorCode.KEY_GENERATION_FAILED,
        `crypto.getRandomValues failed: ${e.message}. Ensure you are in a secure context (HTTPS or localhost).`,
        e
      );
    }
  } else if (typeof process !== 'undefined' && process.versions?.node) {
    // Node.js environment - use cached module
    if (!nodeCryptoModule) {
      // Node.js has crypto as a built-in, access via globalThis or lazy import
      // In Node.js 18+, crypto is available on globalThis
      if (globalThis.crypto?.randomBytes) {
        nodeCryptoModule = globalThis.crypto;
      } else {
        // Fallback: use dynamic import for ESM compatibility
        try {
          // eslint-disable-next-line no-new-func
          nodeCryptoModule = new Function('return require("crypto")')();
        } catch (e) {
          throw new CryptoError(
            CryptoErrorCode.KEY_GENERATION_FAILED,
            'Node.js crypto module not available. Ensure you are running Node.js 14+ with crypto support.',
            e
          );
        }
      }
    }

    try {
      bytes = new Uint8Array(nodeCryptoModule.randomBytes(size));
    } catch (e) {
      throw new CryptoError(
        CryptoErrorCode.KEY_GENERATION_FAILED,
        `Node.js randomBytes failed: ${e.message}`,
        e
      );
    }
  } else {
    throw new CryptoError(
      CryptoErrorCode.KEY_GENERATION_FAILED,
      'No cryptographic random source available. Use a modern browser with HTTPS or Node.js 14+. ' +
      'Do NOT use this library with insecure random sources - cryptographic security depends on proper entropy.'
    );
  }

  // Defense-in-depth: verify we didn't get all zeros (catastrophic RNG failure)
  // This catches scenarios like:
  // - Broken PRNG implementations
  // - VM snapshot issues where entropy pool wasn't reseeded
  // - Hardware RNG failures
  if (size >= 16) {
    let allZeros = true;
    for (let i = 0; i < bytes.length; i++) {
      if (bytes[i] !== 0) {
        allZeros = false;
        break;
      }
    }
    if (allZeros) {
      throw new CryptoError(
        CryptoErrorCode.KEY_GENERATION_FAILED,
        'CRITICAL: Random number generator returned all zeros. This indicates a catastrophic RNG failure. ' +
        'Do NOT proceed with cryptographic operations. Check your system entropy source.'
      );
    }
  }

  return bytes;
}

/**
 * Inject external entropy into the WASM RNG pool.
 * This is called automatically before key generation to ensure the WASM module
 * has access to high-quality entropy from the browser/Node.js crypto APIs.
 * @param {number} [entropyBytes=64] - Number of entropy bytes to inject
 */
function injectEntropy(entropyBytes = 64) {
  if (!wasmModule) return;
  if (!wasmModule.wasi_inject_entropy) return; // Old WASM without entropy support

  const entropy = getRandomBytes(entropyBytes);
  const ptr = wasmModule.malloc(entropyBytes);
  if (ptr === 0) return;

  try {
    const view = new Uint8Array(wasmMemory.buffer, ptr, entropyBytes);
    view.set(entropy);
    wasmModule.wasi_inject_entropy(ptr, entropyBytes);
  } finally {
    wasmModule.free(ptr);
  }
}

/**
 * Allocate memory in WASM heap
 * @param {number} size - Number of bytes to allocate
 * @returns {number} Pointer to allocated memory
 * @throws {Error} If allocation fails or module not initialized
 */
function allocate(size) {
  if (!wasmModule) throw new Error('Encryption module not initialized. Call loadEncryptionWasm() first.');
  if (size <= 0) throw new Error(`Invalid allocation size: ${size}`);
  const ptr = wasmModule.malloc(size);
  if (ptr === 0) throw new Error(`Memory allocation failed for ${size} bytes`);
  return ptr;
}

/**
 * Securely deallocate memory by zeroing it first.
 * This prevents sensitive data (keys, plaintext) from remaining in freed memory.
 * @param {number} ptr - Pointer to memory
 * @param {number} size - Size of memory to clear before freeing
 */
function secureDeallocate(ptr, size) {
  if (ptr !== 0 && wasmMemory) {
    // Zero-fill the memory before freeing to prevent data leakage
    try {
      const view = new Uint8Array(wasmMemory.buffer, ptr, size);
      view.fill(0);
    } catch {
      // Memory may already be invalid, continue with free
    }
    wasmModule.free(ptr);
  }
}

/**
 * Deallocate memory (non-secure, for non-sensitive data)
 * @param {number} ptr - Pointer to memory
 */
function deallocate(ptr) {
  if (ptr !== 0) wasmModule.free(ptr);
}

/**
 * Best-effort zeroing of a Uint8Array.
 *
 * SECURITY NOTE: JavaScript does not guarantee that this actually clears memory.
 * The JIT compiler may optimize away the fill operation, or the original data
 * may remain in other memory locations (copies, V8 internal structures, etc.).
 * This is a best-effort mitigation, not a security guarantee.
 *
 * For truly secure key handling, consider:
 * - Using WebCrypto API with non-extractable keys
 * - Using native modules in Node.js with secure memory
 * - Keeping keys in WASM linear memory (use secureDeallocate)
 *
 * @param {Uint8Array} arr - Array to zero
 */
export function zeroBytes(arr) {
  if (!(arr instanceof Uint8Array)) return;

  // Use crypto.getRandomValues first to make optimization harder,
  // then fill with zeros. This two-step process makes it harder for
  // the optimizer to detect and eliminate the zeroing operation.
  try {
    if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.getRandomValues) {
      globalThis.crypto.getRandomValues(arr);
    }
  } catch {
    // Ignore errors, continue to zero
  }

  // Now zero the array
  arr.fill(0);

  // Volatile read to prevent dead-store elimination (best effort)
  // Access the first and last elements to force materialization
  if (arr.length > 0) {
    // eslint-disable-next-line no-unused-expressions
    arr[0] | arr[arr.length - 1];
  }
}

/**
 * Securely destroy a key by zeroing its contents.
 * This is a convenience wrapper around zeroBytes for semantic clarity.
 *
 * @param {Uint8Array} key - Key to destroy
 * @example
 * const key = hkdf(ikm, salt, info, 32);
 * try {
 *   // use key for encryption
 * } finally {
 *   destroyKey(key);
 * }
 */
export function destroyKey(key) {
  zeroBytes(key);
}

/**
 * Write bytes to WASM memory with bounds checking
 * @param {number} ptr - Destination pointer
 * @param {Uint8Array} data - Data to write
 * @throws {Error} If write would exceed memory bounds
 */
function writeBytes(ptr, data) {
  if (!wasmMemory) throw new Error('WASM memory not initialized');
  if (ptr < 0) throw new Error(`Invalid pointer: ${ptr}`);

  const memSize = wasmMemory.buffer.byteLength;
  if (ptr + data.length > memSize) {
    throw new Error(`Memory write overflow: ptr=${ptr}, size=${data.length}, memSize=${memSize}`);
  }

  new Uint8Array(wasmMemory.buffer, ptr, data.length).set(data);
}

/**
 * Read bytes from WASM memory with bounds checking
 * @param {number} ptr - Source pointer
 * @param {number} size - Number of bytes to read
 * @returns {Uint8Array} Copy of the data
 * @throws {Error} If read would exceed memory bounds
 */
function readBytes(ptr, size) {
  if (!wasmMemory) throw new Error('WASM memory not initialized');
  if (ptr < 0) throw new Error(`Invalid pointer: ${ptr}`);
  if (size < 0) throw new Error(`Invalid size: ${size}`);

  const memSize = wasmMemory.buffer.byteLength;
  if (ptr + size > memSize) {
    throw new Error(`Memory read overflow: ptr=${ptr}, size=${size}, memSize=${memSize}`);
  }

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

  // Handle empty input specially - SHA-256 of empty input is a well-defined constant
  // We still need to call the WASM function, but with a dummy 1-byte allocation
  const dataLen = data.length;
  const dataPtr = allocate(dataLen > 0 ? dataLen : 1);
  const hashPtr = allocate(SHA256_SIZE);

  try {
    if (dataLen > 0) {
      writeBytes(dataPtr, data);
    }
    wasmModule.wasi_sha256(dataPtr, dataLen, hashPtr);
    return readBytes(hashPtr, SHA256_SIZE);
  } finally {
    if (dataLen > 0) {
      secureDeallocate(dataPtr, dataLen);
    } else {
      deallocate(dataPtr);
    }
    deallocate(hashPtr);
  }
}

// =============================================================================
// HMAC-SHA256
// =============================================================================

/**
 * Compute HMAC-SHA256
 * @param {Uint8Array} key - HMAC key
 * @param {Uint8Array} data - Data to authenticate
 * @returns {Uint8Array} - 32-byte HMAC tag
 */
export function hmacSha256(key, data) {
  if (!wasmModule) throw new Error('Encryption module not initialized');
  if (!(key instanceof Uint8Array)) throw new Error('Key must be a Uint8Array');
  if (!(data instanceof Uint8Array)) throw new Error('Data must be a Uint8Array');

  // Check if WASM module has HMAC function
  if (wasmModule.wasi_hmac_sha256) {
    const keyPtr = allocate(key.length);
    const dataPtr = allocate(data.length);
    const macPtr = allocate(HMAC_SIZE);

    try {
      writeBytes(keyPtr, key);
      writeBytes(dataPtr, data);
      wasmModule.wasi_hmac_sha256(keyPtr, key.length, dataPtr, data.length, macPtr);
      return readBytes(macPtr, HMAC_SIZE);
    } finally {
      secureDeallocate(keyPtr, key.length);
      deallocate(dataPtr);
      deallocate(macPtr);
    }
  }

  // Fallback: implement HMAC-SHA256 using sha256
  // HMAC(K, m) = H((K' ^ opad) || H((K' ^ ipad) || m))
  const BLOCK_SIZE = 64;
  let keyPrime;

  if (key.length > BLOCK_SIZE) {
    keyPrime = sha256(key);
  } else {
    keyPrime = new Uint8Array(BLOCK_SIZE);
    keyPrime.set(key);
  }

  // Pad key to block size
  if (keyPrime.length < BLOCK_SIZE) {
    const padded = new Uint8Array(BLOCK_SIZE);
    padded.set(keyPrime);
    keyPrime = padded;
  }

  const ipad = new Uint8Array(BLOCK_SIZE);
  const opad = new Uint8Array(BLOCK_SIZE);

  for (let i = 0; i < BLOCK_SIZE; i++) {
    ipad[i] = keyPrime[i] ^ 0x36;
    opad[i] = keyPrime[i] ^ 0x5c;
  }

  // Inner hash: H((K' ^ ipad) || m)
  const innerData = new Uint8Array(BLOCK_SIZE + data.length);
  innerData.set(ipad);
  innerData.set(data, BLOCK_SIZE);
  const innerHash = sha256(innerData);

  // Outer hash: H((K' ^ opad) || innerHash)
  const outerData = new Uint8Array(BLOCK_SIZE + HMAC_SIZE);
  outerData.set(opad);
  outerData.set(innerHash, BLOCK_SIZE);

  return sha256(outerData);
}

/**
 * Verify HMAC-SHA256 in constant time
 * @param {Uint8Array} key - HMAC key
 * @param {Uint8Array} data - Data to verify
 * @param {Uint8Array} expectedMac - Expected HMAC tag
 * @returns {boolean} - True if MAC is valid
 */
export function hmacSha256Verify(key, data, expectedMac) {
  if (expectedMac.length !== HMAC_SIZE) {
    return false;
  }

  const computedMac = hmacSha256(key, data);

  // Constant-time comparison to prevent timing attacks
  let diff = 0;
  for (let i = 0; i < HMAC_SIZE; i++) {
    diff |= computedMac[i] ^ expectedMac[i];
  }
  return diff === 0;
}

// =============================================================================
// AES-256-CTR Encryption
// =============================================================================

/**
 * Internal encryption implementation
 * @param {Uint8Array} data - Data to encrypt (modified in-place)
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} iv - 16-byte IV
 * @param {boolean} isEncrypt - true for encryption (tracks IV), false for decryption
 */
function _encryptBytesInternal(data, key, iv, isEncrypt) {
  if (!wasmModule) {
    throw new CryptoError(CryptoErrorCode.NOT_INITIALIZED, 'Encryption module not initialized. Call loadEncryptionWasm() first.');
  }
  if (!(data instanceof Uint8Array)) {
    throw new CryptoError(CryptoErrorCode.INVALID_INPUT, 'Data must be a Uint8Array');
  }
  if (!(key instanceof Uint8Array)) {
    throw new CryptoError(CryptoErrorCode.INVALID_INPUT, 'Key must be a Uint8Array');
  }
  if (!(iv instanceof Uint8Array)) {
    throw new CryptoError(CryptoErrorCode.INVALID_INPUT, 'IV must be a Uint8Array');
  }
  if (key.length !== KEY_SIZE) {
    throw new CryptoError(CryptoErrorCode.INVALID_KEY_SIZE, `Key must be ${KEY_SIZE} bytes, got ${key.length}`);
  }
  if (iv.length !== IV_SIZE) {
    throw new CryptoError(CryptoErrorCode.INVALID_IV_SIZE, `IV must be ${IV_SIZE} bytes, got ${iv.length}`);
  }
  if (data.length === 0) return; // Nothing to encrypt - data is unchanged

  // VULN-001 FIX: Check for IV reuse (only for encryption, not decryption)
  // Reusing an IV with the same key in CTR mode completely breaks security
  if (isEncrypt) {
    checkAndRecordIV(key, iv, true);
  }

  const keyPtr = allocate(KEY_SIZE);
  const ivPtr = allocate(IV_SIZE);
  const dataPtr = allocate(data.length);

  try {
    writeBytes(keyPtr, key);
    writeBytes(ivPtr, iv);
    writeBytes(dataPtr, data);

    const result = wasmModule.wasi_encrypt_bytes(keyPtr, ivPtr, dataPtr, data.length);
    if (result !== 0) {
      throw CryptoError.fromWasmCode(result, 'AES-256-CTR encryption');
    }

    data.set(readBytes(dataPtr, data.length));
  } finally {
    // Securely clear sensitive data (key, IV, plaintext/ciphertext)
    secureDeallocate(keyPtr, KEY_SIZE);
    secureDeallocate(ivPtr, IV_SIZE);
    secureDeallocate(dataPtr, data.length);
  }
}

// Track deprecation warnings to avoid spamming console
let encryptBytesWarningShown = false;
let decryptBytesWarningShown = false;

/**
 * Encrypt data in-place using AES-256-CTR
 *
 * @deprecated Use encryptAuthenticated() for integrity protection, or encryptBytesCopy()
 * if you need raw CTR mode. This function provides NO authentication - data can be
 * tampered with via bit-flipping attacks without detection.
 *
 * SECURITY: This function tracks IV usage per key to prevent catastrophic IV reuse.
 * Each (key, IV) pair can only be used once. Attempting to reuse an IV will throw.
 *
 * WARNING: This function modifies the data array in-place. If you need to preserve
 * the original plaintext, use encryptBytesCopy() instead.
 *
 * @param {Uint8Array} data - Data to encrypt (modified in-place)
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} iv - 16-byte IV (must be unique per encryption with this key)
 * @throws {CryptoError} If IV has been used before with this key (IV_REUSE)
 */
export function encryptBytes(data, key, iv) {
  if (!encryptBytesWarningShown) {
    encryptBytesWarningShown = true;
    console.warn(
      '[flatc-wasm] encryptBytes() is deprecated and provides NO integrity protection. ' +
      'Use encryptAuthenticated() instead, or pass { authenticate: false } to encryptBuffer() ' +
      'if you explicitly need unauthenticated encryption.'
    );
  }
  _encryptBytesInternal(data, key, iv, true);
}

/**
 * Encrypt data and return a copy (non-destructive)
 *
 * SECURITY: This function tracks IV usage per key to prevent catastrophic IV reuse.
 * Each (key, IV) pair can only be used once. Attempting to reuse an IV will throw.
 *
 * This is the recommended function for most use cases as it preserves the original data.
 *
 * @param {Uint8Array} data - Data to encrypt (not modified)
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} [iv] - 16-byte IV (auto-generated if not provided)
 * @returns {{ciphertext: Uint8Array, iv: Uint8Array}} Ciphertext and IV used
 * @throws {CryptoError} If IV has been used before with this key (IV_REUSE)
 */
export function encryptBytesCopy(data, key, iv = null) {
  // VULN-004 FIX: Non-destructive encryption that returns a copy
  const actualIV = iv || generateIV();
  const ciphertext = new Uint8Array(data);
  _encryptBytesInternal(ciphertext, key, actualIV, true);
  return { ciphertext, iv: actualIV };
}

/**
 * Decrypt data in-place using AES-256-CTR
 *
 * @deprecated Use decryptAuthenticated() for integrity verification, or decryptBytesCopy()
 * if you need raw CTR mode. This function provides NO authentication - tampered data
 * will be decrypted without detection.
 *
 * Note: Decryption does not check IV reuse since the IV comes from the ciphertext.
 *
 * @param {Uint8Array} data - Data to decrypt (modified in-place)
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} iv - 16-byte IV
 */
export function decryptBytes(data, key, iv) {
  if (!decryptBytesWarningShown) {
    decryptBytesWarningShown = true;
    console.warn(
      '[flatc-wasm] decryptBytes() is deprecated and provides NO integrity verification. ' +
      'Use decryptAuthenticated() instead, or pass { mac } to decryptBuffer() ' +
      'for integrity verification.'
    );
  }
  _encryptBytesInternal(data, key, iv, false);
}

/**
 * Decrypt data and return a copy (non-destructive)
 *
 * This is the recommended function for most use cases as it preserves the original data.
 *
 * @param {Uint8Array} data - Data to decrypt (not modified)
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} iv - 16-byte IV
 * @returns {Uint8Array} Decrypted plaintext
 */
export function decryptBytesCopy(data, key, iv) {
  // VULN-004 FIX: Non-destructive decryption that returns a copy
  const plaintext = new Uint8Array(data);
  _encryptBytesInternal(plaintext, key, iv, false);
  return plaintext;
}

// =============================================================================
// Authenticated Encryption (Encrypt-then-MAC)
// =============================================================================

/**
 * Encrypt data with authentication using AES-256-CTR + HMAC-SHA256 (Encrypt-then-MAC).
 * Returns a new buffer containing: IV (16 bytes) + ciphertext + HMAC (32 bytes).
 *
 * @param {Uint8Array} plaintext - Data to encrypt
 * @param {Uint8Array} key - 32-byte encryption key
 * @param {Uint8Array} [associatedData] - Optional additional data to authenticate (not encrypted)
 * @returns {Uint8Array} - Authenticated ciphertext (IV + ciphertext + HMAC)
 */
export function encryptAuthenticated(plaintext, key, associatedData) {
  if (!wasmModule) throw new Error('Encryption module not initialized');
  if (!(plaintext instanceof Uint8Array)) throw new Error('Plaintext must be a Uint8Array');
  if (!(key instanceof Uint8Array)) throw new Error('Key must be a Uint8Array');
  if (key.length !== KEY_SIZE) throw new Error(`Key must be ${KEY_SIZE} bytes`);

  // Derive separate keys for encryption and MAC (using HKDF)
  const encKey = hkdf(key, null, textEncoder.encode('aes-key'), KEY_SIZE);
  const macKey = hkdf(key, null, textEncoder.encode('mac-key'), KEY_SIZE);

  // Generate random IV
  const iv = getRandomBytes(IV_SIZE);

  // Encrypt (copy plaintext to avoid modifying input)
  const ciphertext = new Uint8Array(plaintext);
  _encryptBytesInternal(ciphertext, encKey, iv, true);

  // Compute HMAC over: IV || ciphertext || associatedData
  const aadLen = associatedData ? associatedData.length : 0;
  const macInput = new Uint8Array(IV_SIZE + ciphertext.length + aadLen);
  macInput.set(iv, 0);
  macInput.set(ciphertext, IV_SIZE);
  if (associatedData) {
    macInput.set(associatedData, IV_SIZE + ciphertext.length);
  }
  const mac = hmacSha256(macKey, macInput);

  // Assemble output: IV + ciphertext + MAC
  const output = new Uint8Array(IV_SIZE + ciphertext.length + HMAC_SIZE);
  output.set(iv, 0);
  output.set(ciphertext, IV_SIZE);
  output.set(mac, IV_SIZE + ciphertext.length);

  return output;
}

/**
 * Decrypt and verify authenticated ciphertext.
 * Input format: IV (16 bytes) + ciphertext + HMAC (32 bytes).
 *
 * @param {Uint8Array} authenticatedCiphertext - Output from encryptAuthenticated
 * @param {Uint8Array} key - 32-byte encryption key
 * @param {Uint8Array} [associatedData] - Optional additional authenticated data
 * @returns {Uint8Array} - Decrypted plaintext
 * @throws {Error} If authentication fails
 */
export function decryptAuthenticated(authenticatedCiphertext, key, associatedData) {
  if (!wasmModule) throw new Error('Encryption module not initialized');
  if (!(authenticatedCiphertext instanceof Uint8Array)) throw new Error('Ciphertext must be a Uint8Array');
  if (!(key instanceof Uint8Array)) throw new Error('Key must be a Uint8Array');
  if (key.length !== KEY_SIZE) throw new Error(`Key must be ${KEY_SIZE} bytes`);

  const minLen = IV_SIZE + HMAC_SIZE;
  if (authenticatedCiphertext.length < minLen) {
    throw new Error(`Authenticated ciphertext too short: expected at least ${minLen} bytes`);
  }

  // Derive keys
  const encKey = hkdf(key, null, textEncoder.encode('aes-key'), KEY_SIZE);
  const macKey = hkdf(key, null, textEncoder.encode('mac-key'), KEY_SIZE);

  // Parse input
  const iv = authenticatedCiphertext.subarray(0, IV_SIZE);
  const ciphertext = authenticatedCiphertext.subarray(IV_SIZE, authenticatedCiphertext.length - HMAC_SIZE);
  const receivedMac = authenticatedCiphertext.subarray(authenticatedCiphertext.length - HMAC_SIZE);

  // Verify HMAC first (before decryption)
  const aadLen = associatedData ? associatedData.length : 0;
  const macInput = new Uint8Array(IV_SIZE + ciphertext.length + aadLen);
  macInput.set(iv, 0);
  macInput.set(ciphertext, IV_SIZE);
  if (associatedData) {
    macInput.set(associatedData, IV_SIZE + ciphertext.length);
  }

  if (!hmacSha256Verify(macKey, macInput, receivedMac)) {
    throw new CryptoError(CryptoErrorCode.AUTHENTICATION_FAILED, 'Authentication failed: HMAC verification failed');
  }

  // Decrypt
  const plaintext = new Uint8Array(ciphertext);
  _encryptBytesInternal(plaintext, encKey, iv, false);

  return plaintext;
}

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

  // Handle empty arrays as null (HKDF allows empty salt/info)
  const hasSalt = salt && salt.length > 0;
  const hasInfo = info && info.length > 0;

  const ikmPtr = allocate(ikm.length);
  const saltPtr = hasSalt ? allocate(salt.length) : 0;
  const infoPtr = hasInfo ? allocate(info.length) : 0;
  const okmPtr = allocate(length);

  try {
    writeBytes(ikmPtr, ikm);
    if (hasSalt) writeBytes(saltPtr, salt);
    if (hasInfo) writeBytes(infoPtr, info);

    wasmModule.wasi_hkdf(
      ikmPtr, ikm.length,
      saltPtr, hasSalt ? salt.length : 0,
      infoPtr, hasInfo ? info.length : 0,
      okmPtr, length
    );

    return readBytes(okmPtr, length);
  } finally {
    // Securely clear input key material and derived key
    secureDeallocate(ikmPtr, ikm.length);
    if (saltPtr) secureDeallocate(saltPtr, salt.length);
    if (infoPtr) deallocate(infoPtr); // info is not sensitive
    secureDeallocate(okmPtr, length);
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
  if (privateKey && privateKey.length !== X25519_PRIVATE_KEY_SIZE) {
    throw new Error(`Private key must be ${X25519_PRIVATE_KEY_SIZE} bytes`);
  }

  // Inject entropy before key generation to ensure high-quality randomness
  injectEntropy();

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
    secureDeallocate(privPtr, X25519_PRIVATE_KEY_SIZE);
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
  if (privateKey.length !== X25519_PRIVATE_KEY_SIZE) {
    throw new Error(`Private key must be ${X25519_PRIVATE_KEY_SIZE} bytes`);
  }
  if (publicKey.length !== X25519_PUBLIC_KEY_SIZE) {
    throw new Error(`Public key must be ${X25519_PUBLIC_KEY_SIZE} bytes`);
  }

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
    secureDeallocate(privPtr, X25519_PRIVATE_KEY_SIZE);
    deallocate(pubPtr);
    secureDeallocate(secretPtr, KEY_SIZE);
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
    ? textEncoder.encode(context)
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
  if (privateKey && privateKey.length !== SECP256K1_PRIVATE_KEY_SIZE) {
    throw new Error(`Private key must be ${SECP256K1_PRIVATE_KEY_SIZE} bytes`);
  }

  // Inject entropy before key generation to ensure high-quality randomness
  injectEntropy();

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
    secureDeallocate(privPtr, SECP256K1_PRIVATE_KEY_SIZE);
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
  if (privateKey.length !== SECP256K1_PRIVATE_KEY_SIZE) {
    throw new Error(`Private key must be ${SECP256K1_PRIVATE_KEY_SIZE} bytes`);
  }
  if (publicKey.length !== SECP256K1_PUBLIC_KEY_SIZE) {
    throw new Error(`Public key must be ${SECP256K1_PUBLIC_KEY_SIZE} bytes (compressed)`);
  }

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
    secureDeallocate(privPtr, SECP256K1_PRIVATE_KEY_SIZE);
    deallocate(pubPtr);
    secureDeallocate(secretPtr, KEY_SIZE);
  }
}

/**
 * Derive symmetric key from secp256k1 shared secret
 */
export function secp256k1DeriveKey(sharedSecret, context) {
  const info = typeof context === 'string'
    ? textEncoder.encode(context)
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
  if (privateKey.length !== SECP256K1_PRIVATE_KEY_SIZE) {
    throw new Error(`Private key must be ${SECP256K1_PRIVATE_KEY_SIZE} bytes`);
  }

  const privPtr = allocate(SECP256K1_PRIVATE_KEY_SIZE);
  const dataPtr = allocate(data.length);
  const sigPtr = allocate(MAX_DER_SIGNATURE_SIZE);
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
    secureDeallocate(privPtr, SECP256K1_PRIVATE_KEY_SIZE);
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
  if (privateKey && privateKey.length !== P256_PRIVATE_KEY_SIZE) {
    throw new Error(`Private key must be ${P256_PRIVATE_KEY_SIZE} bytes`);
  }

  // Inject entropy before key generation to ensure high-quality randomness
  injectEntropy();

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
    secureDeallocate(privPtr, P256_PRIVATE_KEY_SIZE);
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
  if (privateKey.length !== P256_PRIVATE_KEY_SIZE) {
    throw new Error(`Private key must be ${P256_PRIVATE_KEY_SIZE} bytes`);
  }
  if (publicKey.length !== P256_PUBLIC_KEY_SIZE) {
    throw new Error(`Public key must be ${P256_PUBLIC_KEY_SIZE} bytes (compressed)`);
  }

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
    secureDeallocate(privPtr, P256_PRIVATE_KEY_SIZE);
    deallocate(pubPtr);
    secureDeallocate(secretPtr, KEY_SIZE);
  }
}

/**
 * Derive symmetric key from P-256 shared secret
 */
export function p256DeriveKey(sharedSecret, context) {
  const info = typeof context === 'string'
    ? textEncoder.encode(context)
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
  if (privateKey.length !== P256_PRIVATE_KEY_SIZE) {
    throw new Error(`Private key must be ${P256_PRIVATE_KEY_SIZE} bytes`);
  }

  const privPtr = allocate(P256_PRIVATE_KEY_SIZE);
  const dataPtr = allocate(data.length);
  const sigPtr = allocate(MAX_DER_SIGNATURE_SIZE);
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
    secureDeallocate(privPtr, P256_PRIVATE_KEY_SIZE);
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
// P-384 Key Exchange and Signatures (NIST)
// =============================================================================

/**
 * Generate P-384 key pair
 * @param {Uint8Array} [privateKey] - Optional 48-byte private key
 * @returns {{privateKey: Uint8Array, publicKey: Uint8Array}}
 */
export function p384GenerateKeyPair(privateKey) {
  if (!wasmModule) throw new Error('Encryption module not initialized');
  if (privateKey && privateKey.length !== P384_PRIVATE_KEY_SIZE) {
    throw new Error(`Private key must be ${P384_PRIVATE_KEY_SIZE} bytes`);
  }

  // Inject entropy before key generation to ensure high-quality randomness
  injectEntropy();

  const privPtr = allocate(P384_PRIVATE_KEY_SIZE);
  const pubPtr = allocate(P384_PUBLIC_KEY_SIZE);

  try {
    if (privateKey) {
      writeBytes(privPtr, privateKey);
    }

    const result = wasmModule.wasi_p384_generate_keypair(privPtr, pubPtr);
    if (result !== 0) throw new Error('P-384 key generation failed');

    return {
      privateKey: readBytes(privPtr, P384_PRIVATE_KEY_SIZE),
      publicKey: readBytes(pubPtr, P384_PUBLIC_KEY_SIZE),
    };
  } finally {
    secureDeallocate(privPtr, P384_PRIVATE_KEY_SIZE);
    deallocate(pubPtr);
  }
}

/**
 * Compute P-384 ECDH shared secret
 * @param {Uint8Array} privateKey - Our private key (48 bytes)
 * @param {Uint8Array} publicKey - Their public key (49 bytes compressed)
 * @returns {Uint8Array} - 32-byte shared secret (hashed from 48-byte raw secret)
 */
export function p384SharedSecret(privateKey, publicKey) {
  if (!wasmModule) throw new Error('Encryption module not initialized');
  if (privateKey.length !== P384_PRIVATE_KEY_SIZE) {
    throw new Error(`Private key must be ${P384_PRIVATE_KEY_SIZE} bytes`);
  }
  if (publicKey.length !== P384_PUBLIC_KEY_SIZE) {
    throw new Error(`Public key must be ${P384_PUBLIC_KEY_SIZE} bytes (compressed)`);
  }

  const privPtr = allocate(P384_PRIVATE_KEY_SIZE);
  const pubPtr = allocate(publicKey.length);
  const secretPtr = allocate(KEY_SIZE);

  try {
    writeBytes(privPtr, privateKey);
    writeBytes(pubPtr, publicKey);

    const result = wasmModule.wasi_p384_shared_secret(
      privPtr, pubPtr, publicKey.length, secretPtr
    );
    if (result !== 0) throw new Error('P-384 ECDH failed');

    return readBytes(secretPtr, KEY_SIZE);
  } finally {
    secureDeallocate(privPtr, P384_PRIVATE_KEY_SIZE);
    deallocate(pubPtr);
    secureDeallocate(secretPtr, KEY_SIZE);
  }
}

/**
 * Derive symmetric key from P-384 shared secret
 */
export function p384DeriveKey(sharedSecret, context) {
  const info = typeof context === 'string'
    ? textEncoder.encode(context)
    : context;
  return hkdf(sharedSecret, null, info, KEY_SIZE);
}

/**
 * Sign data with P-384 ECDSA
 * @param {Uint8Array} privateKey - Signing private key (48 bytes)
 * @param {Uint8Array} data - Data to sign
 * @returns {Uint8Array} - Signature (DER encoded)
 */
export function p384Sign(privateKey, data) {
  if (!wasmModule) throw new Error('Encryption module not initialized');
  if (privateKey.length !== P384_PRIVATE_KEY_SIZE) {
    throw new Error(`Private key must be ${P384_PRIVATE_KEY_SIZE} bytes`);
  }

  const privPtr = allocate(P384_PRIVATE_KEY_SIZE);
  const dataPtr = allocate(data.length);
  const sigPtr = allocate(MAX_DER_SIGNATURE_SIZE + 32); // P-384 signatures can be larger
  const sigSizePtr = allocate(4);

  try {
    writeBytes(privPtr, privateKey);
    writeBytes(dataPtr, data);

    const result = wasmModule.wasi_p384_sign(
      privPtr, dataPtr, data.length, sigPtr, sigSizePtr
    );
    if (result !== 0) throw new Error('P-384 signing failed');

    const sigSize = new DataView(wasmMemory.buffer).getUint32(sigSizePtr, true);
    return readBytes(sigPtr, sigSize);
  } finally {
    secureDeallocate(privPtr, P384_PRIVATE_KEY_SIZE);
    deallocate(dataPtr);
    deallocate(sigPtr);
    deallocate(sigSizePtr);
  }
}

/**
 * Verify P-384 ECDSA signature
 * @param {Uint8Array} publicKey - Verification public key (49 bytes)
 * @param {Uint8Array} data - Original data
 * @param {Uint8Array} signature - Signature to verify
 * @returns {boolean} - True if valid
 */
export function p384Verify(publicKey, data, signature) {
  if (!wasmModule) throw new Error('Encryption module not initialized');

  const pubPtr = allocate(publicKey.length);
  const dataPtr = allocate(data.length);
  const sigPtr = allocate(signature.length);

  try {
    writeBytes(pubPtr, publicKey);
    writeBytes(dataPtr, data);
    writeBytes(sigPtr, signature);

    const result = wasmModule.wasi_p384_verify(
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

  // Inject entropy before key generation to ensure high-quality randomness
  injectEntropy();

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
    secureDeallocate(privPtr, ED25519_PRIVATE_KEY_SIZE);
    deallocate(pubPtr);
  }
}

/**
 * Sign data with Ed25519
 * @param {Uint8Array} privateKey - Signing private key (64 bytes)
 * @param {Uint8Array} data - Data to sign
 * @returns {Uint8Array} - 64-byte signature
 * @throws {Error} If privateKey is not 64 bytes or inputs are not Uint8Array
 */
export function ed25519Sign(privateKey, data) {
  if (!wasmModule) throw new Error('Encryption module not initialized');

  // Validate inputs before allocation
  if (!(privateKey instanceof Uint8Array)) {
    throw new Error('privateKey must be a Uint8Array');
  }
  if (privateKey.length !== ED25519_PRIVATE_KEY_SIZE) {
    throw new Error(`Invalid private key length: expected ${ED25519_PRIVATE_KEY_SIZE} bytes, got ${privateKey.length}`);
  }
  if (!(data instanceof Uint8Array)) {
    throw new Error('data must be a Uint8Array');
  }

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
    secureDeallocate(privPtr, ED25519_PRIVATE_KEY_SIZE);
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
 * @throws {Error} If publicKey is not 32 bytes or signature is not 64 bytes
 */
export function ed25519Verify(publicKey, data, signature) {
  if (!wasmModule) throw new Error('Encryption module not initialized');

  // Validate input lengths before allocation to prevent buffer issues
  if (!(publicKey instanceof Uint8Array)) {
    throw new Error('publicKey must be a Uint8Array');
  }
  if (publicKey.length !== ED25519_PUBLIC_KEY_SIZE) {
    throw new Error(`Invalid public key length: expected ${ED25519_PUBLIC_KEY_SIZE} bytes, got ${publicKey.length}`);
  }
  if (!(signature instanceof Uint8Array)) {
    throw new Error('signature must be a Uint8Array');
  }
  if (signature.length !== ED25519_SIGNATURE_SIZE) {
    throw new Error(`Invalid signature length: expected ${ED25519_SIGNATURE_SIZE} bytes, got ${signature.length}`);
  }
  if (!(data instanceof Uint8Array)) {
    throw new Error('data must be a Uint8Array');
  }

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
  P384: 'p384',
};

export const SignatureAlgorithm = {
  ED25519: 'ed25519',
  SECP256K1_ECDSA: 'secp256k1-ecdsa',
  P256_ECDSA: 'p256-ecdsa',
  P384_ECDSA: 'p384-ecdsa',
};

export const SymmetricAlgorithm = {
  AES_256_CTR: 'aes-256-ctr',
};

export const KeyDerivationFunction = {
  HKDF_SHA256: 'hkdf-sha256',
};

// =============================================================================
// Encryption Context (field-level key derivation + ECIES hybrid encryption)
// =============================================================================

/**
 * Encryption context for field-level key derivation and hybrid (ECIES) encryption.
 *
 * IMPORTANT: Each encryption operation requires a unique nonce to prevent IV reuse.
 * The nonce is combined with the field ID to derive unique IVs for each field.
 *
 * For hybrid encryption (ECIES), use the static factory methods:
 * - `forEncryption(recipientPublicKey, options)` - Sender side
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
  #fieldKeyCache;  // Map<fieldId, Uint8Array> for cached derived keys

  /**
   * Create encryption context
   * @param {Uint8Array|string} key - 32-byte master key as Uint8Array or 64-char hex string
   * @param {Uint8Array} [nonce] - Optional 16-byte nonce for IV derivation.
   *   CRITICAL: A new random nonce MUST be used for each encryption operation.
   *   If not provided, a random nonce is generated.
   */
  constructor(key, nonce) {
    if (typeof key === 'string') {
      // Validate hex string
      if (!/^[0-9a-fA-F]*$/.test(key)) {
        throw new Error('Invalid hex string: must contain only hex characters (0-9, a-f, A-F)');
      }
      if (key.length !== 64) {
        throw new Error(`Invalid hex key length: expected 64 characters (32 bytes), got ${key.length}`);
      }
      // Parse hex string
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

    // Handle nonce - generate random if not provided
    if (nonce !== undefined) {
      if (!(nonce instanceof Uint8Array)) {
        throw new Error('Nonce must be a Uint8Array');
      }
      if (nonce.length !== IV_SIZE) {
        throw new Error(`Invalid nonce length: expected ${IV_SIZE} bytes, got ${nonce.length}`);
      }
      this.#nonce = new Uint8Array(nonce);
    } else {
      // Generate random nonce for safety
      this.#nonce = getRandomBytes(IV_SIZE);
    }

    // Initialize ECIES-specific fields (set by factory methods)
    this.#ephemeralPublicKey = null;
    this.#recipientKeyId = null;
    this.#algorithm = null;
    this.#context = null;

    // Initialize field key cache for streaming performance
    // Keys are derived lazily and cached for reuse across records
    this.#fieldKeyCache = new Map();
  }

  /**
   * Create an encryption context for hybrid (ECIES) encryption.
   *
   * This performs the sender-side ECIES setup:
   * 1. Generates an ephemeral key pair for the specified algorithm
   * 2. Computes a shared secret via ECDH with the recipient's public key
   * 3. Derives a symmetric key from the shared secret using HKDF
   *
   * The ephemeral public key and other metadata must be sent to the recipient
   * along with the encrypted data (via getHeader() or getHeaderJSON()).
   *
   * @param {Uint8Array} recipientPublicKey - Recipient's public key
   * @param {Object} [options] - Encryption options
   * @param {string} [options.algorithm='secp256k1'] - Key exchange algorithm ('x25519', 'secp256k1', 'p256', 'p384')
   * @param {string} [options.context=''] - Application context for key derivation
   * @param {string} [options.rootType] - Root type name (for documentation/debugging)
   * @returns {EncryptionContext} Configured encryption context
   *
   * @example
   * const ctx = EncryptionContext.forEncryption(recipientPublicKey, {
   *   algorithm: 'secp256k1',
   *   context: 'my-app-v1',
   * });
   * const header = ctx.getHeaderJSON();
   * encryptBuffer(buffer, schema, ctx, 'MyTable');
   * // Send header + encrypted buffer to recipient
   */
  static forEncryption(recipientPublicKey, options = {}) {
    const algorithm = options.algorithm || KeyExchangeAlgorithm.SECP256K1;
    const contextStr = options.context || '';

    let ephemeralKeys;
    let sharedSecret;

    // Generate ephemeral key pair and compute shared secret based on algorithm
    switch (algorithm) {
      case KeyExchangeAlgorithm.X25519:
      case 'x25519':
        ephemeralKeys = x25519GenerateKeyPair();
        sharedSecret = x25519SharedSecret(ephemeralKeys.privateKey, recipientPublicKey);
        break;
      case KeyExchangeAlgorithm.SECP256K1:
      case 'secp256k1':
        ephemeralKeys = secp256k1GenerateKeyPair();
        sharedSecret = secp256k1SharedSecret(ephemeralKeys.privateKey, recipientPublicKey);
        break;
      case KeyExchangeAlgorithm.P256:
      case 'p256':
        ephemeralKeys = p256GenerateKeyPair();
        sharedSecret = p256SharedSecret(ephemeralKeys.privateKey, recipientPublicKey);
        break;
      case KeyExchangeAlgorithm.P384:
      case 'p384':
        ephemeralKeys = p384GenerateKeyPair();
        sharedSecret = p384SharedSecret(ephemeralKeys.privateKey, recipientPublicKey);
        break;
      default:
        throw new CryptoError(
          CryptoErrorCode.INVALID_INPUT,
          `Unsupported key exchange algorithm: ${algorithm}`
        );
    }

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
   * This performs the recipient-side ECIES setup:
   * 1. Extracts the ephemeral public key from the header
   * 2. Computes the shared secret via ECDH with our private key
   * 3. Derives the same symmetric key using HKDF
   *
   * @param {Uint8Array} privateKey - Recipient's private key
   * @param {Object} header - Encryption header from sender (from getHeader() or parsed JSON)
   * @param {string} [header.algorithm] - Key exchange algorithm
   * @param {Uint8Array} header.senderPublicKey - Sender's ephemeral public key
   * @param {Uint8Array} [header.iv] - IV/nonce from header
   * @param {string} [context] - Application context (must match sender's context)
   * @returns {EncryptionContext} Configured decryption context
   *
   * @example
   * const header = encryptionHeaderFromJSON(receivedHeaderJSON);
   * const ctx = EncryptionContext.forDecryption(myPrivateKey, header, 'my-app-v1');
   * decryptBuffer(buffer, schema, ctx, 'MyTable');
   */
  static forDecryption(privateKey, header, context = '') {
    const algorithm = header.algorithm || KeyExchangeAlgorithm.SECP256K1;
    const ephemeralPublicKey = header.senderPublicKey;
    const nonce = header.iv;

    if (!ephemeralPublicKey) {
      throw new CryptoError(
        CryptoErrorCode.INVALID_INPUT,
        'Header must contain senderPublicKey (ephemeral public key)'
      );
    }

    // IV/nonce is required for decryption - without it, decryption produces garbage
    if (!nonce) {
      throw new CryptoError(
        CryptoErrorCode.INVALID_IV_SIZE,
        'Header must contain iv (nonce) for decryption - cannot decrypt without the original nonce'
      );
    }

    let sharedSecret;

    // Compute shared secret based on algorithm
    switch (algorithm) {
      case KeyExchangeAlgorithm.X25519:
      case 'x25519':
        sharedSecret = x25519SharedSecret(privateKey, ephemeralPublicKey);
        break;
      case KeyExchangeAlgorithm.SECP256K1:
      case 'secp256k1':
        sharedSecret = secp256k1SharedSecret(privateKey, ephemeralPublicKey);
        break;
      case KeyExchangeAlgorithm.P256:
      case 'p256':
        sharedSecret = p256SharedSecret(privateKey, ephemeralPublicKey);
        break;
      case KeyExchangeAlgorithm.P384:
      case 'p384':
        sharedSecret = p384SharedSecret(privateKey, ephemeralPublicKey);
        break;
      default:
        throw new CryptoError(
          CryptoErrorCode.INVALID_INPUT,
          `Unsupported key exchange algorithm: ${algorithm}`
        );
    }

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
   * Get the ephemeral public key (for ECIES encryption).
   * This key must be sent to the recipient along with the encrypted data.
   * @returns {Uint8Array|null} The ephemeral public key, or null if not using ECIES
   */
  getEphemeralPublicKey() {
    return this.#ephemeralPublicKey ? new Uint8Array(this.#ephemeralPublicKey) : null;
  }

  /**
   * Get the encryption header for transmission to recipient.
   * Contains all information needed for the recipient to decrypt.
   * @returns {Object} Encryption header
   */
  getHeader() {
    if (!this.#ephemeralPublicKey) {
      throw new CryptoError(
        CryptoErrorCode.INVALID_INPUT,
        'No ephemeral key available. Use EncryptionContext.forEncryption() for ECIES.'
      );
    }
    return {
      version: 1,
      algorithm: this.#algorithm || KeyExchangeAlgorithm.SECP256K1,
      senderPublicKey: new Uint8Array(this.#ephemeralPublicKey),
      recipientKeyId: this.#recipientKeyId ? new Uint8Array(this.#recipientKeyId) : new Uint8Array(8),
      iv: this.getNonce(),
      context: this.#context || '',
    };
  }

  /**
   * Get the encryption header as a JSON string for transmission.
   * @returns {string} JSON-encoded encryption header
   */
  getHeaderJSON() {
    const header = this.getHeader();
    return JSON.stringify(encryptionHeaderToJSON(header));
  }

  /**
   * Get the algorithm used for key exchange (for ECIES contexts).
   * @returns {string|null} The algorithm name, or null if not using ECIES
   */
  getAlgorithm() {
    return this.#algorithm;
  }

  /**
   * Get the context string used for key derivation.
   * @returns {string|null} The context string, or null if not set
   */
  getContext() {
    return this.#context;
  }

  /**
   * Get the nonce used by this context.
   * This nonce must be stored/transmitted with the encrypted data for decryption.
   * @returns {Uint8Array} The 16-byte nonce
   */
  getNonce() {
    return new Uint8Array(this.#nonce);
  }

  /**
   * Get a copy of the master key.
   * WARNING: Handle with care - this returns the actual encryption key.
   * Use only when necessary (e.g., for MAC computation).
   * @returns {Uint8Array} Copy of the 32-byte master key
   */
  getKey() {
    return new Uint8Array(this.#key);
  }

  /**
   * Check if context is valid
   * @returns {boolean}
   */
  isValid() {
    return this.#key !== null && this.#key.length === KEY_SIZE;
  }

  /**
   * Create from hex string
   * @param {string} hexKey - 64-character hex string
   * @param {Uint8Array} [nonce] - Optional 16-byte nonce for IV derivation
   * @returns {EncryptionContext}
   */
  static fromHex(hexKey, nonce) {
    if (typeof hexKey !== 'string') {
      throw new Error('hexKey must be a string');
    }
    if (!/^[0-9a-fA-F]*$/.test(hexKey)) {
      throw new Error('Invalid hex string: must contain only hex characters (0-9, a-f, A-F)');
    }
    if (hexKey.length !== 64) {
      throw new Error(`Invalid hex key length: expected 64 characters (32 bytes), got ${hexKey.length}`);
    }
    return new EncryptionContext(hexKey, nonce);
  }

  /**
   * Derive field-specific key
   * @param {number} fieldId
   * @returns {Uint8Array}
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
   * The IV is derived from the key, nonce, and field ID to ensure uniqueness.
   * @param {number} fieldId
   * @returns {Uint8Array}
   */
  deriveFieldIV(fieldId) {
    // Combine nonce with field ID info for HKDF
    // This ensures different IVs even when encrypting the same buffer multiple times
    const info = new Uint8Array(18); // 'flatbuffers-iv' (14) + fieldId (2) + padding (2)
    textEncoder.encodeInto('flatbuffers-iv', info);
    info[14] = (fieldId >> 8) & 0xff;
    info[15] = fieldId & 0xff;
    // Use nonce as salt to ensure IV uniqueness across encryption operations
    return hkdf(this.#key, this.#nonce, info, IV_SIZE);
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
    _encryptBytesInternal(data, key, iv, true);
  }

  /**
   * Decrypt scalar value (CTR mode - same operation as encrypt but no IV tracking)
   * @param {Uint8Array} buffer
   * @param {number} offset
   * @param {number} size
   * @param {number} fieldId
   */
  decryptScalar(buffer, offset, size, fieldId) {
    const key = this.deriveFieldKey(fieldId);
    const iv = this.deriveFieldIV(fieldId);
    const data = buffer.subarray(offset, offset + size);
    _encryptBytesInternal(data, key, iv, false);
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
    _encryptBytesInternal(data, key, iv, true);
  }

  /**
   * Decrypt string value (CTR mode - same operation as encrypt but no IV tracking)
   * @param {Uint8Array} buffer
   * @param {number} offset
   * @param {number} length
   * @param {number} fieldId
   */
  decryptString(buffer, offset, length, fieldId) {
    const key = this.deriveFieldKey(fieldId);
    const iv = this.deriveFieldIV(fieldId);
    const data = buffer.subarray(offset, offset + length);
    _encryptBytesInternal(data, key, iv, false);
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
    _encryptBytesInternal(data, key, iv, true);
  }

  /**
   * Decrypt vector data (CTR mode - same operation as encrypt but no IV tracking)
   * @param {Uint8Array} buffer
   * @param {number} offset
   * @param {number} elementSize
   * @param {number} count
   * @param {number} fieldId
   */
  decryptVector(buffer, offset, elementSize, count, fieldId) {
    const key = this.deriveFieldKey(fieldId);
    const iv = this.deriveFieldIV(fieldId);
    const data = buffer.subarray(offset, offset + elementSize * count);
    _encryptBytesInternal(data, key, iv, false);
  }

  // ===========================================================================
  // High-Performance Streaming Encryption Methods
  // ===========================================================================
  // These methods follow the patterns established by:
  // - Google Tink Streaming AEAD (key derived once, IV varies per segment)
  // - RFC 9180 HPKE (nonce XOR sequence number)
  // - Libsodium SecretStream (nonce chaining)
  //
  // Key insight: Derive field keys ONCE (via HKDF), then compute IVs using
  // fast XOR operations with (fieldId || recordCounter). This eliminates
  // the ~2 HKDF calls per field that were causing performance issues.
  // ===========================================================================

  /**
   * Get a cached field key, deriving it via HKDF only on first access.
   *
   * This is the core optimization: HKDF is expensive (~100μs per call in WASM),
   * but for streaming encryption we use the same key for each field across
   * all records. By caching derived keys, we pay the HKDF cost only once
   * per field ID rather than once per record.
   *
   * @param {number} fieldId - Field identifier (0-65535)
   * @returns {Uint8Array} 32-byte derived key for this field
   */
  getFieldKey(fieldId) {
    if (!this.#fieldKeyCache.has(fieldId)) {
      this.#fieldKeyCache.set(fieldId, this.deriveFieldKey(fieldId));
    }
    return this.#fieldKeyCache.get(fieldId);
  }

  /**
   * Compute a unique IV for a (fieldId, recordCounter) pair using XOR.
   *
   * This follows RFC 9180 HPKE nonce management:
   *   nonce_i = base_nonce XOR encode(sequence_number)
   *
   * We extend this to include the fieldId to ensure uniqueness across fields:
   *   IV = baseNonce XOR (fieldId_high || fieldId_low || counter_bytes)
   *
   * Layout of 16-byte IV:
   *   Bytes 0-1:  XOR with fieldId (16-bit)
   *   Bytes 2-9:  XOR with recordCounter (64-bit big-endian)
   *   Bytes 10-15: Unchanged from baseNonce
   *
   * Security properties:
   * - Same field, different records → different IV (counter differs)
   * - Different fields, same record → different IV (fieldId differs)
   * - Same (field, record) with same context → same IV (deterministic, required for decryption)
   * - Same (field, record) with different context → different IV (baseNonce differs)
   *
   * @param {number} fieldId - Field identifier (0-65535)
   * @param {number} recordCounter - Record sequence number (0 to 2^53-1 safely in JS)
   * @returns {Uint8Array} 16-byte IV unique to this (fieldId, recordCounter) pair
   */
  computeFieldIV(fieldId, recordCounter) {
    // SECURITY FIX (VULN-NEW-008): Validate counter is within safe integer range
    if (!Number.isInteger(recordCounter) || recordCounter < 0) {
      throw new CryptoError(
        CryptoErrorCode.INVALID_INPUT,
        'recordCounter must be a non-negative integer'
      );
    }
    if (recordCounter > Number.MAX_SAFE_INTEGER) {
      throw new CryptoError(
        CryptoErrorCode.INVALID_INPUT,
        `recordCounter exceeds MAX_SAFE_INTEGER (${Number.MAX_SAFE_INTEGER}). ` +
        'Counter overflow would cause IV collisions. Use a new encryption context.'
      );
    }

    // Copy base nonce to avoid mutating the original
    const iv = new Uint8Array(this.#nonce);

    // XOR in fieldId (bytes 0-1, big-endian)
    iv[0] ^= (fieldId >> 8) & 0xff;
    iv[1] ^= fieldId & 0xff;

    // XOR in recordCounter (bytes 2-9, big-endian)
    // JavaScript safely handles integers up to 2^53-1 (validated above)
    // For counters larger than 32 bits, we need to handle high/low parts
    const counterHigh = Math.floor(recordCounter / 0x100000000);
    const counterLow = recordCounter >>> 0;

    iv[2] ^= (counterHigh >> 24) & 0xff;
    iv[3] ^= (counterHigh >> 16) & 0xff;
    iv[4] ^= (counterHigh >> 8) & 0xff;
    iv[5] ^= counterHigh & 0xff;
    iv[6] ^= (counterLow >> 24) & 0xff;
    iv[7] ^= (counterLow >> 16) & 0xff;
    iv[8] ^= (counterLow >> 8) & 0xff;
    iv[9] ^= counterLow & 0xff;

    return iv;
  }

  /**
   * High-performance field encryption for streaming/bulk operations.
   *
   * Unlike encryptScalar() which derives key and IV via HKDF on every call,
   * this method:
   * 1. Uses cached field keys (HKDF only on first access per fieldId)
   * 2. Computes IVs via fast XOR operations
   *
   * Performance: ~100x faster than encryptScalar() for bulk operations
   * because HKDF (~100μs) is replaced with XOR (~0.1μs) for IV computation.
   *
   * @param {Uint8Array} buffer - Buffer containing data to encrypt (modified in-place)
   * @param {number} offset - Start offset in buffer
   * @param {number} size - Number of bytes to encrypt
   * @param {number} fieldId - Field identifier for key derivation
   * @param {number} recordCounter - Record sequence number for IV uniqueness
   */
  encryptField(buffer, offset, size, fieldId, recordCounter) {
    const key = this.getFieldKey(fieldId);
    const iv = this.computeFieldIV(fieldId, recordCounter);
    const data = buffer.subarray(offset, offset + size);
    _encryptBytesInternal(data, key, iv, true);
  }

  /**
   * High-performance buffer encryption for streaming/bulk operations.
   *
   * Encrypts an entire buffer as a single field. This is the fastest option
   * when you don't need per-field encryption granularity.
   *
   * @param {Uint8Array} buffer - Buffer to encrypt (modified in-place)
   * @param {number} recordCounter - Record sequence number for IV uniqueness
   * @param {number} [fieldId=0] - Optional field ID (defaults to 0)
   */
  encryptBuffer(buffer, recordCounter, fieldId = 0) {
    this.encryptField(buffer, 0, buffer.length, fieldId, recordCounter);
  }

  /**
   * Decrypt a buffer encrypted with encryptBuffer().
   * AES-CTR is symmetric, so encryption and decryption are the same operation.
   *
   * @param {Uint8Array} buffer - Buffer to decrypt (modified in-place)
   * @param {number} recordCounter - Record sequence number (must match encryption)
   * @param {number} [fieldId=0] - Optional field ID (must match encryption)
   */
  decryptBuffer(buffer, recordCounter, fieldId = 0) {
    // AES-CTR is symmetric, but we must NOT track IV for decryption
    // (only encryption should track to prevent IV reuse)
    const key = this.getFieldKey(fieldId);
    const iv = this.computeFieldIV(fieldId, recordCounter);
    _encryptBytesInternal(buffer, key, iv, false); // false = don't track IV
  }

  /**
   * Clear the field key cache with secure zeroing.
   *
   * Call this when you're done with a batch of records and want to free memory.
   * The keys will be re-derived on next use if needed.
   *
   * This method attempts to zero all cached keys before clearing the Map.
   * See zeroBytes() documentation for security limitations.
   *
   * @param {boolean} [secureZero=true] - Whether to zero keys before clearing
   */
  clearKeyCache(secureZero = true) {
    if (secureZero) {
      for (const key of this.#fieldKeyCache.values()) {
        zeroBytes(key);
      }
    }
    this.#fieldKeyCache.clear();
  }

  /**
   * Get the number of cached field keys.
   * Useful for debugging and memory monitoring.
   *
   * @returns {number} Number of cached keys
   */
  getCacheSize() {
    return this.#fieldKeyCache.size;
  }

  /**
   * Securely destroy this encryption context.
   *
   * This method:
   * 1. Zeros all cached field keys
   * 2. Zeros the master key
   * 3. Zeros the nonce
   * 4. Clears IV tracking for this key
   *
   * After calling destroy(), this context cannot be used for encryption/decryption.
   * Any attempt to use it will result in errors or undefined behavior.
   *
   * IMPORTANT: Call this method when you're done with the context to minimize
   * the window during which key material is exposed in memory.
   *
   * @example
   * const ctx = new EncryptionContext(key);
   * try {
   *   encryptBuffer(buffer, schema, ctx, 'MyTable');
   * } finally {
   *   ctx.destroy();
   * }
   */
  destroy() {
    // Clear cached field keys with secure zeroing
    this.clearKeyCache(true);

    // Clear IV tracking for this key before zeroing it
    if (this.#key) {
      clearIVTracking(this.#key);
      zeroBytes(this.#key);
      this.#key = null;
    }

    // Zero the nonce
    if (this.#nonce) {
      zeroBytes(this.#nonce);
      this.#nonce = null;
    }

    // Zero ephemeral keys if present (ECIES)
    if (this.#ephemeralPublicKey) {
      zeroBytes(this.#ephemeralPublicKey);
      this.#ephemeralPublicKey = null;
    }

    if (this.#recipientKeyId) {
      zeroBytes(this.#recipientKeyId);
      this.#recipientKeyId = null;
    }

    // Clear string references
    this.#algorithm = null;
    this.#context = null;
  }

  /**
   * Check if this context has been destroyed.
   * @returns {boolean} True if destroy() has been called
   */
  isDestroyed() {
    return this.#key === null;
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
  const iv = options.iv || getRandomBytes(IV_SIZE);
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
  const json = {
    version: header.version,
    algorithm: header.algorithm,
    senderPublicKey: Array.from(header.senderPublicKey),
    recipientKeyId: Array.from(header.recipientKeyId),
    iv: Array.from(header.iv),
  };
  // Include context if present
  if (header.context !== undefined && header.context !== '') {
    json.context = header.context;
  }
  return json;
}

/**
 * Parse encryption header from JSON
 * @param {Object|string} json - JSON object or JSON string
 * @returns {Object}
 */
export function encryptionHeaderFromJSON(json) {
  // Handle JSON string input
  const parsed = typeof json === 'string' ? JSON.parse(json) : json;
  return {
    version: parsed.version,
    algorithm: parsed.algorithm,
    senderPublicKey: new Uint8Array(parsed.senderPublicKey),
    recipientKeyId: new Uint8Array(parsed.recipientKeyId),
    iv: new Uint8Array(parsed.iv),
    context: parsed.context || '',
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
// Schema Parsing and Buffer Encryption
// =============================================================================

/**
 * Type sizes for FlatBuffer scalar types
 */
const TYPE_SIZES = {
  bool: 1, byte: 1, ubyte: 1,
  short: 2, ushort: 2,
  int: 4, uint: 4, float: 4,
  long: 8, ulong: 8, double: 8,
};

const SCALAR_TYPES = new Set(Object.keys(TYPE_SIZES));

/**
 * Parse a FlatBuffers schema to extract field encryption info.
 *
 * Handles edge cases:
 * - Comments (// and /* ... *\/)
 * - Nested braces in default values
 * - Multi-line table definitions
 * - String default values containing special characters
 *
 * @param {string} schemaContent - FlatBuffers schema content (.fbs)
 * @param {string} rootType - Name of the root type
 * @returns {Object} Parsed schema with encryption metadata
 */
export function parseSchemaForEncryption(schemaContent, rootType) {
  const schema = { fields: [] };

  // Remove comments first
  let cleanContent = schemaContent
    // Remove single-line comments
    .replace(/\/\/[^\n]*/g, '')
    // Remove multi-line comments
    .replace(/\/\*[\s\S]*?\*\//g, '');

  // Find the table definition using a more robust approach
  // Match 'table Name {' and then find the balanced closing brace
  const tableStartRegex = new RegExp(`table\\s+${escapeRegex(rootType)}\\s*\\{`, 's');
  const startMatch = cleanContent.match(tableStartRegex);
  if (!startMatch) return schema;

  const startIndex = startMatch.index + startMatch[0].length;

  // Find matching closing brace (handle nested braces)
  let braceCount = 1;
  let endIndex = startIndex;
  while (braceCount > 0 && endIndex < cleanContent.length) {
    const char = cleanContent[endIndex];
    if (char === '{') braceCount++;
    else if (char === '}') braceCount--;
    endIndex++;
  }

  if (braceCount !== 0) {
    // Unbalanced braces - return empty schema
    return schema;
  }

  const tableBody = cleanContent.substring(startIndex, endIndex - 1);

  // Parse fields more carefully
  // Field format: name : type [= default] [(attributes)] ;
  // We need to handle string defaults that might contain special chars
  const lines = tableBody.split(';').map(l => l.trim()).filter(l => l.length > 0);

  // First pass: collect all fields with their explicit IDs (if any)
  const fieldsWithIds = [];
  let implicitId = 0;

  for (const line of lines) {
    // Skip empty lines or lines that are just whitespace
    if (!line || /^\s*$/.test(line)) continue;

    // Match: name : type ...
    const fieldMatch = line.match(/^(\w+)\s*:\s*(\[?\w+(?:\.\w+)*\]?)/);
    if (!fieldMatch) continue;

    const name = fieldMatch[1];
    const typeStr = fieldMatch[2];

    // Extract all attributes from parentheses at the end
    // Match any parenthesized group at the end of the line
    const attrMatch = line.match(/\(\s*([^)]+)\s*\)\s*$/);
    const attributesStr = attrMatch ? attrMatch[1] : '';

    // Parse individual attributes
    const isEncrypted = /\bencrypted\b/.test(attributesStr);

    // Look for explicit id: attribute
    // Format: id: N or id:N
    const idMatch = attributesStr.match(/\bid\s*:\s*(\d+)\b/);
    const explicitId = idMatch ? parseInt(idMatch[1], 10) : null;

    const isVector = typeStr.startsWith('[') && typeStr.endsWith(']');
    const baseType = isVector ? typeStr.slice(1, -1) : typeStr;
    // Handle namespaced types (e.g., MyGame.Sample.Monster)
    const simpleBaseType = baseType.includes('.') ? baseType.split('.').pop() : baseType;

    let fieldType;
    if (isVector) {
      fieldType = 'vector';
    } else if (SCALAR_TYPES.has(simpleBaseType)) {
      fieldType = simpleBaseType;
    } else if (simpleBaseType === 'string') {
      fieldType = 'string';
    } else {
      fieldType = 'struct';
    }

    fieldsWithIds.push({
      name,
      explicitId,
      implicitOrder: implicitId++,
      type: fieldType,
      encrypted: isEncrypted,
      elementType: isVector ? (SCALAR_TYPES.has(simpleBaseType) ? simpleBaseType : 'struct') : undefined,
      elementSize: TYPE_SIZES[simpleBaseType] || 1,
    });
  }

  // Second pass: assign IDs
  // Fields with explicit IDs get those IDs
  // Fields without explicit IDs get sequential IDs starting from 0,
  // skipping any IDs that are explicitly assigned
  const usedIds = new Set(
    fieldsWithIds.filter(f => f.explicitId !== null).map(f => f.explicitId)
  );

  let nextImplicitId = 0;
  for (const field of fieldsWithIds) {
    let finalId;
    if (field.explicitId !== null) {
      finalId = field.explicitId;
    } else {
      // Find next available ID
      while (usedIds.has(nextImplicitId)) {
        nextImplicitId++;
      }
      finalId = nextImplicitId++;
      usedIds.add(finalId);
    }

    schema.fields.push({
      name: field.name,
      id: finalId,
      type: field.type,
      encrypted: field.encrypted,
      elementType: field.elementType,
      elementSize: field.elementSize,
    });
  }

  return schema;
}

/**
 * Escape special regex characters in a string
 * @param {string} str
 * @returns {string}
 */
function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Read uint32 from buffer (little-endian)
 */
function readUint32(buffer, offset) {
  return buffer[offset] | (buffer[offset + 1] << 8) | (buffer[offset + 2] << 16) | (buffer[offset + 3] << 24) >>> 0;
}

/**
 * Read int32 from buffer (little-endian)
 */
function readInt32(buffer, offset) {
  return buffer[offset] | (buffer[offset + 1] << 8) | (buffer[offset + 2] << 16) | (buffer[offset + 3] << 24);
}

/**
 * Read uint16 from buffer (little-endian)
 */
function readUint16(buffer, offset) {
  return buffer[offset] | (buffer[offset + 1] << 8);
}

/**
 * Process a FlatBuffer table and encrypt/decrypt marked fields
 * @param {Uint8Array} buffer - The FlatBuffer
 * @param {number} tableOffset - Offset to the table
 * @param {Object} schema - Parsed schema
 * @param {EncryptionContext} ctx - Encryption context
 */
function processTable(buffer, tableOffset, schema, ctx) {
  const bufLen = buffer.length;

  // Bounds check: table offset must be within buffer
  if (tableOffset < 0 || tableOffset + 4 > bufLen) {
    throw new CryptoError(
      CryptoErrorCode.INVALID_INPUT,
      `Invalid table offset: ${tableOffset} (buffer size: ${bufLen})`
    );
  }

  // Read vtable offset (soffset_t at table start)
  const vtableOffsetDelta = readInt32(buffer, tableOffset);
  const vtableOffset = tableOffset - vtableOffsetDelta;

  // Bounds check: vtable must be within buffer
  if (vtableOffset < 0 || vtableOffset + 4 > bufLen) {
    throw new CryptoError(
      CryptoErrorCode.INVALID_INPUT,
      `Invalid vtable offset: ${vtableOffset} (buffer size: ${bufLen})`
    );
  }

  // Read vtable size
  const vtableSize = readUint16(buffer, vtableOffset);

  // Bounds check: vtable must fit within buffer
  if (vtableOffset + vtableSize > bufLen) {
    throw new CryptoError(
      CryptoErrorCode.INVALID_INPUT,
      `VTable extends beyond buffer: offset=${vtableOffset}, size=${vtableSize}, bufLen=${bufLen}`
    );
  }

  for (const field of schema.fields) {
    // Field offset is at vtable + (field.id + 2) * 2
    const fieldVtableIdx = (field.id + 2) * 2;
    if (fieldVtableIdx >= vtableSize) continue;

    const fieldOffset = readUint16(buffer, vtableOffset + fieldVtableIdx);
    if (fieldOffset === 0) continue; // Field not present

    const fieldLoc = tableOffset + fieldOffset;

    // Bounds check: field location must be within buffer
    if (fieldLoc < 0 || fieldLoc >= bufLen) {
      throw new CryptoError(
        CryptoErrorCode.INVALID_INPUT,
        `Field '${field.name}' offset ${fieldLoc} is out of bounds (buffer size: ${bufLen})`
      );
    }

    if (!field.encrypted) continue;

    const key = ctx.deriveFieldKey(field.id);
    const iv = ctx.deriveFieldIV(field.id);

    // Handle different field types
    const size = TYPE_SIZES[field.type];
    if (size) {
      // Bounds check for scalar
      if (fieldLoc + size > bufLen) {
        throw new CryptoError(
          CryptoErrorCode.INVALID_INPUT,
          `Field '${field.name}' data extends beyond buffer: offset=${fieldLoc}, size=${size}, bufLen=${bufLen}`
        );
      }
      // Scalar type - encrypt in place
      const data = buffer.subarray(fieldLoc, fieldLoc + size);
      _encryptBytesInternal(data, key, iv, true);
    } else if (field.type === 'string') {
      // String: offset to string, then length-prefixed data
      if (fieldLoc + 4 > bufLen) {
        throw new CryptoError(
          CryptoErrorCode.INVALID_INPUT,
          `Field '${field.name}' string offset extends beyond buffer`
        );
      }
      const strOffset = readUint32(buffer, fieldLoc);
      const strLoc = fieldLoc + strOffset;
      if (strLoc + 4 > bufLen) {
        throw new CryptoError(
          CryptoErrorCode.INVALID_INPUT,
          `Field '${field.name}' string length extends beyond buffer`
        );
      }
      const strLen = readUint32(buffer, strLoc);
      if (strLoc + 4 + strLen > bufLen) {
        throw new CryptoError(
          CryptoErrorCode.INVALID_INPUT,
          `Field '${field.name}' string data extends beyond buffer: strLoc=${strLoc}, strLen=${strLen}, bufLen=${bufLen}`
        );
      }
      const strData = buffer.subarray(strLoc + 4, strLoc + 4 + strLen);
      encryptBytes(strData, key, iv);
    } else if (field.type === 'vector') {
      // Vector: offset to vector, then length-prefixed elements
      // Only scalar vectors are supported - vectors of strings/tables/structs contain
      // offsets, not inline data, and encrypting offsets would corrupt the buffer
      if (field.elementType === 'struct' || field.elementType === 'string') {
        throw new CryptoError(
          CryptoErrorCode.INVALID_INPUT,
          `Field '${field.name}': encryption of vector<${field.elementType}> is not supported. ` +
          `Only vectors of scalar types (int, float, byte, etc.) can be encrypted. ` +
          `For vectors of strings/tables, encrypt each element individually before adding to the buffer.`
        );
      }
      if (fieldLoc + 4 > bufLen) {
        throw new CryptoError(
          CryptoErrorCode.INVALID_INPUT,
          `Field '${field.name}' vector offset extends beyond buffer`
        );
      }
      const vecOffset = readUint32(buffer, fieldLoc);
      const vecLoc = fieldLoc + vecOffset;
      if (vecLoc + 4 > bufLen) {
        throw new CryptoError(
          CryptoErrorCode.INVALID_INPUT,
          `Field '${field.name}' vector length extends beyond buffer`
        );
      }
      const vecLen = readUint32(buffer, vecLoc);
      const elemSize = field.elementSize;
      if (!elemSize || elemSize < 1) {
        throw new CryptoError(
          CryptoErrorCode.INVALID_INPUT,
          `Field '${field.name}': cannot determine element size for vector encryption`
        );
      }
      const vecDataLen = vecLen * elemSize;
      if (vecLoc + 4 + vecDataLen > bufLen) {
        throw new CryptoError(
          CryptoErrorCode.INVALID_INPUT,
          `Field '${field.name}' vector data extends beyond buffer: vecLoc=${vecLoc}, vecDataLen=${vecDataLen}, bufLen=${bufLen}`
        );
      }
      const vecData = buffer.subarray(vecLoc + 4, vecLoc + 4 + vecDataLen);
      encryptBytes(vecData, key, iv);
    } else if (field.type === 'struct') {
      // Struct encryption requires knowing the struct size, which isn't available
      // from schema parsing alone. Skip with a descriptive error in the field info.
      // Users should use explicit field-level encryption for struct fields.
      throw new CryptoError(
        CryptoErrorCode.INVALID_INPUT,
        `Cannot encrypt struct field '${field.name}': struct size is unknown. Use explicit field-level encryption instead.`
      );
    }
  }
}

/**
 * Result of encrypting a FlatBuffer
 */
/**
 * @typedef {Object} EncryptBufferResult
 * @property {Uint8Array} buffer - The encrypted buffer (same reference as input)
 * @property {Uint8Array} nonce - The 16-byte nonce used for encryption (must be stored for decryption)
 * @property {Uint8Array} [mac] - 32-byte HMAC-SHA256 authentication tag (when authenticate: true)
 */

/**
 * Options for buffer encryption
 * @typedef {Object} EncryptBufferOptions
 * @property {boolean} [authenticate=true] - Whether to compute HMAC for integrity protection.
 *   When true (default), a 32-byte MAC is computed over nonce||buffer and included in the result.
 *   This protects against bit-flipping attacks and tampering.
 */

/**
 * Encrypt a FlatBuffer in-place with integrity protection.
 *
 * Fields marked with the (encrypted) attribute will be encrypted.
 * The buffer structure remains valid - only field values change.
 *
 * **SECURITY**: By default (authenticate: true), this function computes an HMAC-SHA256
 * over (nonce || encrypted_buffer) to provide integrity protection against tampering
 * and bit-flipping attacks. The MAC must be stored alongside the encrypted data and
 * passed to decryptBuffer() for verification.
 *
 * WARNING: This function modifies the buffer in-place.
 *
 * IMPORTANT: When passing a raw key (Uint8Array or hex string), a random nonce is generated.
 * You MUST save the returned nonce (and mac if authenticate: true) and pass them to
 * decryptBuffer for decryption.
 *
 * LIMITATION: This function only encrypts fields in the ROOT table. Encrypted fields in
 * nested tables (tables referenced by the root table) are NOT processed. If you need to
 * encrypt fields in nested structures, you must either:
 * 1. Flatten your schema to avoid nesting
 * 2. Encrypt nested data before building the FlatBuffer
 * 3. Use encryptAuthenticated() directly on the nested table's buffer region
 *
 * SUPPORTED TYPES for encryption:
 * - Scalar types (int, float, bool, byte, etc.): fully supported
 * - Strings: fully supported
 * - Vectors of scalars (e.g., [int], [float]): fully supported
 * - Vectors of strings/tables: NOT supported (will throw an error)
 * - Structs: NOT supported (will throw an error)
 * - Nested tables: NOT traversed (see LIMITATION above)
 *
 * @param {Uint8Array} buffer - FlatBuffer to encrypt (modified in-place)
 * @param {Object|string} schema - Parsed schema or schema content string
 * @param {Uint8Array|string|EncryptionContext} key - Encryption key or context
 * @param {string} [rootType] - Root type name (required if schema is string)
 * @param {EncryptBufferOptions} [options] - Encryption options
 * @param {boolean} [options.authenticate=true] - Compute HMAC for integrity (default: true)
 * @returns {EncryptBufferResult} Object with encrypted buffer, nonce, and mac (if authenticated)
 *
 * @example
 * // Default: authenticated encryption (recommended)
 * const { buffer, nonce, mac } = encryptBuffer(buf, schema, key, 'MyTable');
 * // Store: buffer + nonce + mac
 * // Decrypt: decryptBuffer(buffer, schema, key, 'MyTable', nonce, { mac });
 *
 * @example
 * // Legacy: unauthenticated encryption (NOT recommended)
 * const { buffer, nonce } = encryptBuffer(buf, schema, key, 'MyTable', { authenticate: false });
 * // WARNING: No integrity protection - vulnerable to bit-flipping attacks
 *
 * @example
 * // Using EncryptionContext with authentication
 * const ctx = new EncryptionContext(key);
 * const { buffer, nonce, mac } = encryptBuffer(buf, schema, ctx, 'MyTable');
 */
export function encryptBuffer(buffer, schema, key, rootType, options = {}) {
  // Default to authenticated encryption
  const authenticate = options.authenticate !== false;

  // Get or create encryption context
  let ctx;
  let masterKey;
  if (key instanceof EncryptionContext) {
    ctx = key;
    masterKey = ctx.getKey();
  } else {
    ctx = new EncryptionContext(key);
    // Store the original key for MAC computation
    masterKey = typeof key === 'string' ? hexToBytes(key) : key;
  }

  if (!ctx.isValid()) {
    throw new Error('Invalid encryption key');
  }

  // Parse schema if needed
  const parsedSchema = typeof schema === 'string'
    ? parseSchemaForEncryption(schema, rootType)
    : schema;

  if (!parsedSchema.fields || parsedSchema.fields.length === 0) {
    throw new Error('No fields found in schema. Check that rootType matches the table name.');
  }

  // Read root table offset
  const rootOffset = readUint32(buffer, 0);

  // Process the root table
  processTable(buffer, rootOffset, parsedSchema, ctx);

  const nonce = ctx.getNonce();

  // Compute MAC if authentication is enabled
  if (authenticate) {
    // Derive a separate MAC key from master key using HKDF
    const macKey = hkdf(masterKey, null, textEncoder.encode('flatbuffer-mac-key'), KEY_SIZE);

    // MAC covers: nonce || encrypted_buffer
    const macInput = new Uint8Array(IV_SIZE + buffer.length);
    macInput.set(nonce, 0);
    macInput.set(buffer, IV_SIZE);
    const mac = hmacSha256(macKey, macInput);

    return { buffer, nonce, mac };
  }

  // Return buffer and nonce - nonce is critical for decryption
  return { buffer, nonce };
}

/**
 * Convert hex string to bytes
 * @param {string} hex
 * @returns {Uint8Array}
 */
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Options for buffer decryption
 * @typedef {Object} DecryptBufferOptions
 * @property {Uint8Array} [mac] - 32-byte HMAC to verify before decryption.
 *   If provided, the MAC is verified first and decryption only proceeds if valid.
 *   This protects against tampering and bit-flipping attacks.
 */

/**
 * Decrypt a FlatBuffer in-place with optional integrity verification.
 *
 * AES-CTR is symmetric, so decryption uses the same operation as encryption.
 * You MUST provide the same nonce that was used during encryption.
 *
 * **SECURITY**: If a MAC was returned from encryptBuffer(), you should pass it
 * in options.mac for verification. This ensures the encrypted data has not been
 * tampered with. Verification is performed BEFORE decryption - if the MAC is
 * invalid, the buffer is left unchanged and an error is thrown.
 *
 * WARNING: This function modifies the buffer in-place (only after MAC verification passes).
 *
 * @param {Uint8Array} buffer - FlatBuffer to decrypt (modified in-place)
 * @param {Object|string} schema - Parsed schema or schema content string
 * @param {Uint8Array|string|EncryptionContext} key - Encryption key or context
 * @param {string} [rootType] - Root type name (required if schema is string)
 * @param {Uint8Array} [nonce] - The 16-byte nonce from encryption (required if key is not EncryptionContext)
 * @param {DecryptBufferOptions} [options] - Decryption options
 * @param {Uint8Array} [options.mac] - MAC from encryptBuffer() for integrity verification
 * @returns {Uint8Array} The decrypted buffer (same reference)
 * @throws {CryptoError} If MAC verification fails (AUTHENTICATION_FAILED)
 *
 * @example
 * // With MAC verification (recommended)
 * const { buffer: encrypted, nonce, mac } = encryptBuffer(buf, schema, key, 'MyTable');
 * // ... later ...
 * decryptBuffer(encrypted, schema, key, 'MyTable', nonce, { mac });
 *
 * @example
 * // Legacy: without MAC verification (NOT recommended)
 * const { buffer: encrypted, nonce } = encryptBuffer(buf, schema, key, 'MyTable', { authenticate: false });
 * decryptBuffer(encrypted, schema, key, 'MyTable', nonce);
 *
 * @example
 * // Using EncryptionContext with saved nonce and MAC
 * const ctx = new EncryptionContext(key, savedNonce);
 * decryptBuffer(encrypted, schema, ctx, 'MyTable', null, { mac: savedMac });
 */
export function decryptBuffer(buffer, schema, key, rootType, nonce, options = {}) {
  // Get or create encryption context
  let ctx;
  let masterKey;
  if (key instanceof EncryptionContext) {
    ctx = key;
    masterKey = ctx.getKey();
  } else {
    // For raw keys, nonce is required for decryption
    if (!nonce) {
      throw new CryptoError(
        CryptoErrorCode.INVALID_NONCE_SIZE,
        'Nonce is required for decryption when using a raw key. Pass the nonce returned from encryptBuffer.'
      );
    }
    ctx = new EncryptionContext(key, nonce);
    masterKey = typeof key === 'string' ? hexToBytes(key) : key;
  }

  if (!ctx.isValid()) {
    throw new Error('Invalid encryption key');
  }

  // Verify MAC if provided (BEFORE decryption)
  if (options.mac) {
    if (!(options.mac instanceof Uint8Array) || options.mac.length !== HMAC_SIZE) {
      throw new CryptoError(
        CryptoErrorCode.INVALID_INPUT,
        `Invalid MAC: expected ${HMAC_SIZE}-byte Uint8Array`
      );
    }

    // Derive MAC key
    const macKey = hkdf(masterKey, null, textEncoder.encode('flatbuffer-mac-key'), KEY_SIZE);

    // Recompute expected MAC
    const actualNonce = ctx.getNonce();
    const macInput = new Uint8Array(IV_SIZE + buffer.length);
    macInput.set(actualNonce, 0);
    macInput.set(buffer, IV_SIZE);

    if (!hmacSha256Verify(macKey, macInput, options.mac)) {
      throw new CryptoError(
        CryptoErrorCode.AUTHENTICATION_FAILED,
        'MAC verification failed: encrypted data may have been tampered with'
      );
    }
  }

  // Parse schema if needed
  const parsedSchema = typeof schema === 'string'
    ? parseSchemaForEncryption(schema, rootType)
    : schema;

  if (!parsedSchema.fields || parsedSchema.fields.length === 0) {
    throw new Error('No fields found in schema. Check that rootType matches the table name.');
  }

  // Read root table offset
  const rootOffset = readUint32(buffer, 0);

  // Process the root table (CTR mode: encryption = decryption)
  processTable(buffer, rootOffset, parsedSchema, ctx);

  return buffer;
}

// =============================================================================
// Default export
// =============================================================================

export default {
  // Error types
  CryptoError,
  CryptoErrorCode,

  // Initialization
  initEncryption,
  loadEncryptionWasm,
  isInitialized,
  hasCryptopp,
  getVersion,

  // Hash
  sha256,

  // HMAC
  hmacSha256,
  hmacSha256Verify,

  // Symmetric encryption
  encryptBytes,
  decryptBytes,
  encryptAuthenticated,
  decryptAuthenticated,
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

  // P-384
  p384GenerateKeyPair,
  p384SharedSecret,
  p384DeriveKey,
  p384Sign,
  p384Verify,

  // Ed25519
  ed25519GenerateKeyPair,
  ed25519Sign,
  ed25519Verify,

  // Constants
  KeyExchangeAlgorithm,
  SignatureAlgorithm,
  SymmetricAlgorithm,
  KeyDerivationFunction,
  KEY_SIZE,
  IV_SIZE,
  HMAC_SIZE,
  SHA256_SIZE,

  // Classes
  EncryptionContext,

  // Security utilities
  zeroBytes,
  destroyKey,

  // IV management
  generateIV,
  clearIVTracking,
  clearAllIVTracking,

  // Non-destructive encryption
  encryptBytesCopy,
  decryptBytesCopy,

  // Header utilities
  createEncryptionHeader,
  computeKeyId,
  encryptionHeaderToJSON,
  encryptionHeaderFromJSON,
  encryptScalar,

  // Buffer encryption
  parseSchemaForEncryption,
  encryptBuffer,
  decryptBuffer,
};
