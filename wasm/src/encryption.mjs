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

// Cached encoder/decoder instances for performance
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

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

/**
 * Get cryptographically secure random bytes (works in Node.js and browser)
 * @param {number} size - Number of random bytes
 * @returns {Uint8Array}
 * @throws {Error} If no cryptographic random source is available
 */
function getRandomBytes(size) {
  if (size <= 0) {
    throw new Error('Size must be a positive integer');
  }

  // Browser environment - check for SecureContext
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.getRandomValues) {
    try {
      return globalThis.crypto.getRandomValues(new Uint8Array(size));
    } catch (e) {
      // getRandomValues may fail if not in a secure context
      throw new Error(`crypto.getRandomValues failed: ${e.message}. Ensure you are in a secure context (HTTPS).`);
    }
  }

  // Node.js environment - use cached module
  if (typeof process !== 'undefined' && process.versions?.node) {
    if (!nodeCryptoModule) {
      // Node.js has crypto as a built-in, access via globalThis or lazy import
      // In Node.js 18+, crypto is available on globalThis
      if (globalThis.crypto?.randomBytes) {
        nodeCryptoModule = globalThis.crypto;
      } else {
        // Fallback: use Function constructor to avoid static analysis of require
        // This is necessary because we're in an ESM module
        try {
          // eslint-disable-next-line no-new-func
          nodeCryptoModule = new Function('return require("crypto")')();
        } catch {
          throw new Error('Node.js crypto module not available');
        }
      }
    }
    return new Uint8Array(nodeCryptoModule.randomBytes(size));
  }

  throw new Error('No cryptographic random source available. Use a modern browser with HTTPS or Node.js 18+.');
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

  const dataPtr = allocate(data.length);
  const hashPtr = allocate(SHA256_SIZE);

  try {
    writeBytes(dataPtr, data);
    wasmModule.wasi_sha256(dataPtr, data.length, hashPtr);
    return readBytes(hashPtr, SHA256_SIZE);
  } finally {
    secureDeallocate(dataPtr, data.length);
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
 * Encrypt data in-place using AES-256-CTR
 * @param {Uint8Array} data - Data to encrypt (modified in-place)
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} iv - 16-byte IV
 */
export function encryptBytes(data, key, iv) {
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

/**
 * Decrypt data in-place using AES-256-CTR
 * Same as encryptBytes (CTR mode is symmetric)
 */
export const decryptBytes = encryptBytes;

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
  encryptBytes(ciphertext, encKey, iv);

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
  decryptBytes(plaintext, encKey, iv);

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
    secureDeallocate(privPtr, ED25519_PRIVATE_KEY_SIZE);
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
  if (privateKey.length !== ED25519_PRIVATE_KEY_SIZE) {
    throw new Error(`Private key must be ${ED25519_PRIVATE_KEY_SIZE} bytes`);
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
 * Encryption context for field-level key derivation.
 *
 * IMPORTANT: Each encryption operation requires a unique nonce to prevent IV reuse.
 * The nonce is combined with the field ID to derive unique IVs for each field.
 *
 * WARNING: Methods that encrypt data modify the buffer in-place.
 */
export class EncryptionContext {
  #key;
  #nonce;

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
      encryptBytes(data, key, iv);
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
      const elemSize = field.elementSize || 1;
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
 */

/**
 * Encrypt a FlatBuffer in-place.
 *
 * Fields marked with the (encrypted) attribute will be encrypted.
 * The buffer structure remains valid - only field values change.
 *
 * WARNING: This function modifies the buffer in-place.
 *
 * IMPORTANT: When passing a raw key (Uint8Array or hex string), a random nonce is generated.
 * You MUST save the returned nonce and pass it to decryptBuffer for decryption.
 * For better control, use an EncryptionContext directly.
 *
 * SECURITY NOTE: This function uses AES-CTR without authentication (no HMAC).
 * This preserves the FlatBuffer binary layout but does not detect tampering.
 * For tamper detection, either:
 * 1. Use encryptAuthenticated() to encrypt the entire buffer (changes format)
 * 2. Add an HMAC of the encrypted buffer at the transport layer
 * 3. Use a transport that provides integrity (TLS, authenticated channels)
 *
 * @param {Uint8Array} buffer - FlatBuffer to encrypt (modified in-place)
 * @param {Object|string} schema - Parsed schema or schema content string
 * @param {Uint8Array|string|EncryptionContext} key - Encryption key or context
 * @param {string} [rootType] - Root type name (required if schema is string)
 * @returns {EncryptBufferResult} Object with encrypted buffer and nonce
 *
 * @example
 * // Using raw key - MUST save the nonce
 * const { buffer, nonce } = encryptBuffer(buf, schema, key, 'MyTable');
 * // Store nonce alongside encrypted data for decryption
 *
 * @example
 * // Using EncryptionContext - manage nonce yourself
 * const ctx = new EncryptionContext(key, nonce);
 * const { buffer } = encryptBuffer(buf, schema, ctx, 'MyTable');
 */
export function encryptBuffer(buffer, schema, key, rootType) {
  // Get or create encryption context
  let ctx;
  if (key instanceof EncryptionContext) {
    ctx = key;
  } else {
    ctx = new EncryptionContext(key);
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

  // Return buffer and nonce - nonce is critical for decryption
  return {
    buffer,
    nonce: ctx.getNonce(),
  };
}

/**
 * Decrypt a FlatBuffer in-place.
 *
 * AES-CTR is symmetric, so decryption uses the same operation as encryption.
 * You MUST provide the same nonce that was used during encryption.
 *
 * WARNING: This function modifies the buffer in-place.
 *
 * @param {Uint8Array} buffer - FlatBuffer to decrypt (modified in-place)
 * @param {Object|string} schema - Parsed schema or schema content string
 * @param {Uint8Array|string|EncryptionContext} key - Encryption key or context
 * @param {string} [rootType] - Root type name (required if schema is string)
 * @param {Uint8Array} [nonce] - The 16-byte nonce from encryption (required if key is not EncryptionContext)
 * @returns {Uint8Array} The decrypted buffer (same reference)
 *
 * @example
 * // Using raw key with nonce from encryptBuffer
 * const { buffer: encrypted, nonce } = encryptBuffer(buf, schema, key, 'MyTable');
 * // ... later ...
 * decryptBuffer(encrypted, schema, key, 'MyTable', nonce);
 *
 * @example
 * // Using EncryptionContext with saved nonce
 * const ctx = new EncryptionContext(key, savedNonce);
 * decryptBuffer(encrypted, schema, ctx, 'MyTable');
 */
export function decryptBuffer(buffer, schema, key, rootType, nonce) {
  // Get or create encryption context
  let ctx;
  if (key instanceof EncryptionContext) {
    ctx = key;
  } else {
    // For raw keys, nonce is required for decryption
    if (!nonce) {
      throw new CryptoError(
        CryptoErrorCode.INVALID_NONCE_SIZE,
        'Nonce is required for decryption when using a raw key. Pass the nonce returned from encryptBuffer.'
      );
    }
    ctx = new EncryptionContext(key, nonce);
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
