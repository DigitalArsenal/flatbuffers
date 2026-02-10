/**
 * Homomorphic Encryption Context for FlatBuffers WASM
 *
 * This module provides a TypeScript wrapper around the WASM HE functions,
 * enabling homomorphic encryption operations on FlatBuffer data.
 *
 * Requires the HE-enabled WASM build (flatc-wasm-he.js).
 *
 * @example
 * ```typescript
 * import { HEContext } from './he-context.mjs';
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

export interface WasmHEModule {
  _wasm_he_context_create_client(polyDegree: number): number;
  _wasm_he_context_create_server(pkPtr: number, pkLen: number): number;
  _wasm_he_context_destroy(ctxId: number): void;
  _wasm_he_get_public_key(ctxId: number, outLenPtr: number): number;
  _wasm_he_get_relin_keys(ctxId: number, outLenPtr: number): number;
  _wasm_he_get_secret_key(ctxId: number, outLenPtr: number): number;
  _wasm_he_set_relin_keys(ctxId: number, rkPtr: number, rkLen: number): number;
  _wasm_he_encrypt_int64(ctxId: number, value: bigint, outLenPtr: number): number;
  _wasm_he_decrypt_int64(ctxId: number, ctPtr: number, ctLen: number): bigint;
  _wasm_he_encrypt_double(ctxId: number, value: number, outLenPtr: number): number;
  _wasm_he_decrypt_double(ctxId: number, ctPtr: number, ctLen: number): number;
  _wasm_he_add(ctxId: number, ct1Ptr: number, ct1Len: number, ct2Ptr: number, ct2Len: number, outLenPtr: number): number;
  _wasm_he_sub(ctxId: number, ct1Ptr: number, ct1Len: number, ct2Ptr: number, ct2Len: number, outLenPtr: number): number;
  _wasm_he_multiply(ctxId: number, ct1Ptr: number, ct1Len: number, ct2Ptr: number, ct2Len: number, outLenPtr: number): number;
  _wasm_he_negate(ctxId: number, ctPtr: number, ctLen: number, outLenPtr: number): number;
  _wasm_he_add_plain(ctxId: number, ctPtr: number, ctLen: number, plain: bigint, outLenPtr: number): number;
  _wasm_he_multiply_plain(ctxId: number, ctPtr: number, ctLen: number, plain: bigint, outLenPtr: number): number;
  _wasm_get_last_error(): number;
  _malloc(size: number): number;
  _free(ptr: number): void;
  HEAPU8: Uint8Array;
  getValue(ptr: number, type: string): number;
  UTF8ToString(ptr: number): string;
}

let wasmModule: WasmHEModule | null = null;

/**
 * Initialize the HE module with a WASM instance.
 * Must be called before using HEContext.
 */
export function initHEModule(module: WasmHEModule): void {
  wasmModule = module;
}

/**
 * Get the last error message from WASM.
 */
export function getLastError(): string {
  if (!wasmModule) return 'WASM module not initialized';
  const errPtr = wasmModule._wasm_get_last_error();
  return errPtr ? wasmModule.UTF8ToString(errPtr) : '';
}

/**
 * Default polynomial modulus degree (4096 = ~128-bit security)
 */
export const DEFAULT_POLY_MODULUS_DEGREE = 4096;

/**
 * HEContext provides homomorphic encryption operations.
 *
 * Two modes:
 * - Client mode (created with createClient): Has secret key, can encrypt/decrypt
 * - Server mode (created with createServer): Public key only, can compute but not decrypt
 */
export class HEContext {
  private contextId: number;
  private hasSecretKey: boolean;

  private constructor(contextId: number, hasSecretKey: boolean) {
    this.contextId = contextId;
    this.hasSecretKey = hasSecretKey;
  }

  /**
   * Create a client context with full key pair.
   * Client can encrypt, decrypt, and perform HE operations.
   *
   * @param polyModulusDegree Power of 2, typically 4096, 8192, or 16384.
   *                          Higher = more security but slower and larger ciphertexts.
   */
  static createClient(polyModulusDegree: number = DEFAULT_POLY_MODULUS_DEGREE): HEContext {
    if (!wasmModule) throw new Error('WASM module not initialized. Call initHEModule first.');

    const ctxId = wasmModule._wasm_he_context_create_client(polyModulusDegree);
    if (ctxId < 0) {
      throw new Error(`Failed to create HE client context: ${getLastError()}`);
    }
    return new HEContext(ctxId, true);
  }

  /**
   * Create a server context from a public key.
   * Server can perform HE operations but cannot decrypt.
   *
   * @param publicKey Serialized public key from a client context
   */
  static createServer(publicKey: Uint8Array): HEContext {
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
  destroy(): void {
    if (!wasmModule || this.contextId < 0) return;
    wasmModule._wasm_he_context_destroy(this.contextId);
    this.contextId = -1;
  }

  /**
   * Check if this is a client context (has secret key).
   */
  canDecrypt(): boolean {
    return this.hasSecretKey;
  }

  /**
   * Get the serialized public key.
   */
  getPublicKey(): Uint8Array {
    return this.getKeyData(wasmModule!._wasm_he_get_public_key);
  }

  /**
   * Get the serialized relinearization keys.
   * These are needed by server contexts for multiplication.
   */
  getRelinKeys(): Uint8Array {
    return this.getKeyData(wasmModule!._wasm_he_get_relin_keys);
  }

  /**
   * Get the serialized secret key (client only).
   * @throws Error if this is a server context
   */
  getSecretKey(): Uint8Array {
    if (!this.hasSecretKey) {
      throw new Error('Cannot get secret key from server context');
    }
    return this.getKeyData(wasmModule!._wasm_he_get_secret_key);
  }

  /**
   * Set relinearization keys (for server context).
   * Required before performing multiplication operations.
   */
  setRelinKeys(relinKeys: Uint8Array): void {
    if (!wasmModule) throw new Error('WASM module not initialized');

    const rkPtr = wasmModule._malloc(relinKeys.length);
    try {
      wasmModule.HEAPU8.set(relinKeys, rkPtr);
      const result = wasmModule._wasm_he_set_relin_keys(this.contextId, rkPtr, relinKeys.length);
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
   */
  encryptInt64(value: bigint): Uint8Array {
    if (!wasmModule) throw new Error('WASM module not initialized');

    const outLenPtr = wasmModule._malloc(4);
    try {
      const resultPtr = wasmModule._wasm_he_encrypt_int64(this.contextId, value, outLenPtr);
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
   */
  encryptDouble(value: number): Uint8Array {
    if (!wasmModule) throw new Error('WASM module not initialized');

    const outLenPtr = wasmModule._malloc(4);
    try {
      const resultPtr = wasmModule._wasm_he_encrypt_double(this.contextId, value, outLenPtr);
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
   * @throws Error if this is a server context
   */
  decryptInt64(ciphertext: Uint8Array): bigint {
    if (!this.hasSecretKey) {
      throw new Error('Cannot decrypt: server context has no secret key');
    }
    if (!wasmModule) throw new Error('WASM module not initialized');

    const ctPtr = wasmModule._malloc(ciphertext.length);
    try {
      wasmModule.HEAPU8.set(ciphertext, ctPtr);
      return wasmModule._wasm_he_decrypt_int64(this.contextId, ctPtr, ciphertext.length);
    } finally {
      wasmModule._free(ctPtr);
    }
  }

  /**
   * Decrypt a ciphertext to a double.
   * @throws Error if this is a server context
   */
  decryptDouble(ciphertext: Uint8Array): number {
    if (!this.hasSecretKey) {
      throw new Error('Cannot decrypt: server context has no secret key');
    }
    if (!wasmModule) throw new Error('WASM module not initialized');

    const ctPtr = wasmModule._malloc(ciphertext.length);
    try {
      wasmModule.HEAPU8.set(ciphertext, ctPtr);
      return wasmModule._wasm_he_decrypt_double(this.contextId, ctPtr, ciphertext.length);
    } finally {
      wasmModule._free(ctPtr);
    }
  }

  // =========================================================================
  // Homomorphic operations
  // =========================================================================

  /**
   * Add two ciphertexts homomorphically.
   */
  add(ct1: Uint8Array, ct2: Uint8Array): Uint8Array {
    return this.binaryOp(ct1, ct2, wasmModule!._wasm_he_add);
  }

  /**
   * Subtract two ciphertexts homomorphically.
   */
  sub(ct1: Uint8Array, ct2: Uint8Array): Uint8Array {
    return this.binaryOp(ct1, ct2, wasmModule!._wasm_he_sub);
  }

  /**
   * Multiply two ciphertexts homomorphically.
   * Requires relinearization keys to be set.
   */
  multiply(ct1: Uint8Array, ct2: Uint8Array): Uint8Array {
    return this.binaryOp(ct1, ct2, wasmModule!._wasm_he_multiply);
  }

  /**
   * Negate a ciphertext homomorphically.
   */
  negate(ct: Uint8Array): Uint8Array {
    if (!wasmModule) throw new Error('WASM module not initialized');

    const ctPtr = wasmModule._malloc(ct.length);
    const outLenPtr = wasmModule._malloc(4);
    try {
      wasmModule.HEAPU8.set(ct, ctPtr);
      const resultPtr = wasmModule._wasm_he_negate(this.contextId, ctPtr, ct.length, outLenPtr);
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
   */
  addPlain(ct: Uint8Array, plain: bigint): Uint8Array {
    return this.plainOp(ct, plain, wasmModule!._wasm_he_add_plain);
  }

  /**
   * Multiply a ciphertext by a plaintext value.
   */
  multiplyPlain(ct: Uint8Array, plain: bigint): Uint8Array {
    return this.plainOp(ct, plain, wasmModule!._wasm_he_multiply_plain);
  }

  // =========================================================================
  // Private helpers
  // =========================================================================

  private getKeyData(fn: (ctxId: number, outLenPtr: number) => number): Uint8Array {
    if (!wasmModule) throw new Error('WASM module not initialized');

    const outLenPtr = wasmModule._malloc(4);
    try {
      const resultPtr = fn.call(wasmModule, this.contextId, outLenPtr);
      if (resultPtr === 0) {
        throw new Error(`Failed to get key: ${getLastError()}`);
      }
      const outLen = wasmModule.getValue(outLenPtr, 'i32');
      return new Uint8Array(wasmModule.HEAPU8.buffer, resultPtr, outLen).slice();
    } finally {
      wasmModule._free(outLenPtr);
    }
  }

  private binaryOp(
    ct1: Uint8Array,
    ct2: Uint8Array,
    fn: (ctxId: number, ct1Ptr: number, ct1Len: number, ct2Ptr: number, ct2Len: number, outLenPtr: number) => number
  ): Uint8Array {
    if (!wasmModule) throw new Error('WASM module not initialized');

    const ct1Ptr = wasmModule._malloc(ct1.length);
    const ct2Ptr = wasmModule._malloc(ct2.length);
    const outLenPtr = wasmModule._malloc(4);
    try {
      wasmModule.HEAPU8.set(ct1, ct1Ptr);
      wasmModule.HEAPU8.set(ct2, ct2Ptr);
      const resultPtr = fn.call(wasmModule, this.contextId, ct1Ptr, ct1.length, ct2Ptr, ct2.length, outLenPtr);
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

  private plainOp(
    ct: Uint8Array,
    plain: bigint,
    fn: (ctxId: number, ctPtr: number, ctLen: number, plain: bigint, outLenPtr: number) => number
  ): Uint8Array {
    if (!wasmModule) throw new Error('WASM module not initialized');

    const ctPtr = wasmModule._malloc(ct.length);
    const outLenPtr = wasmModule._malloc(4);
    try {
      wasmModule.HEAPU8.set(ct, ctPtr);
      const resultPtr = fn.call(wasmModule, this.contextId, ctPtr, ct.length, plain, outLenPtr);
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
