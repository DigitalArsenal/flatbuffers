/**
 * Homomorphic Encryption Context for FlatBuffers WASM
 */

/** WASM module interface required for HE operations */
export interface WasmHEModule {
  _wasm_he_context_create_client(polyDegree: number): number;
  _wasm_he_context_create_client_seeded(polyDegree: number, seedPtr: number, seedLen: number): number;
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

/**
 * Initialize the HE module with a WASM instance.
 * Must be called before using HEContext.
 */
export function initHEModule(module: WasmHEModule): void;

/** Get the current WASM module (for internal use). */
export function getHEModule(): WasmHEModule | null;

/** Get the last error message from WASM. */
export function getLastError(): string;

/** Default polynomial modulus degree (4096 = ~128-bit security) */
export const DEFAULT_POLY_MODULUS_DEGREE: number;

/**
 * HEContext provides homomorphic encryption operations.
 *
 * Two modes:
 * - Client mode (created with createClient): Has secret key, can encrypt/decrypt
 * - Server mode (created with createServer): Public key only, can compute but not decrypt
 */
export class HEContext {
  constructor(contextId: number, hasSecretKey: boolean);

  /** Get the underlying WASM context ID. */
  getContextId(): number;

  /**
   * Create a client context with full key pair.
   * @param polyModulusDegree Power of 2, typically 4096, 8192, or 16384
   */
  static createClient(polyModulusDegree?: number): HEContext;

  /**
   * Create a client context from a deterministic seed.
   * @param seed 64-byte seed for deterministic key generation
   * @param polyModulusDegree Polynomial modulus degree
   */
  static createClientFromSeed(seed: Uint8Array, polyModulusDegree?: number): HEContext;

  /**
   * Create a server context from a public key.
   * @param publicKey Serialized public key from a client context
   */
  static createServer(publicKey: Uint8Array): HEContext;

  /** Destroy the context and free resources. */
  destroy(): void;

  /** Check if this is a client context (has secret key). */
  canDecrypt(): boolean;

  /** Get the serialized public key. */
  getPublicKey(): Uint8Array;

  /** Get the serialized relinearization keys. */
  getRelinKeys(): Uint8Array;

  /** Get the serialized secret key (client only). */
  getSecretKey(): Uint8Array;

  /** Set relinearization keys (for server context). */
  setRelinKeys(relinKeys: Uint8Array): void;

  /** Encrypt a 64-bit integer. */
  encryptInt64(value: bigint): Uint8Array;

  /** Encrypt a double (using fixed-point encoding). */
  encryptDouble(value: number): Uint8Array;

  /** Decrypt a ciphertext to a 64-bit integer (client only). */
  decryptInt64(ciphertext: Uint8Array): bigint;

  /** Decrypt a ciphertext to a double (client only). */
  decryptDouble(ciphertext: Uint8Array): number;

  /** Add two ciphertexts homomorphically. */
  add(ct1: Uint8Array, ct2: Uint8Array): Uint8Array;

  /** Subtract two ciphertexts homomorphically. */
  sub(ct1: Uint8Array, ct2: Uint8Array): Uint8Array;

  /** Multiply two ciphertexts (requires relin keys). */
  multiply(ct1: Uint8Array, ct2: Uint8Array): Uint8Array;

  /** Negate a ciphertext homomorphically. */
  negate(ct: Uint8Array): Uint8Array;

  /** Add a plaintext value to a ciphertext. */
  addPlain(ct: Uint8Array, plain: bigint): Uint8Array;

  /** Multiply a ciphertext by a plaintext value. */
  multiplyPlain(ct: Uint8Array, plain: bigint): Uint8Array;
}
