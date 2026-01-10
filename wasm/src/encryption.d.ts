/**
 * Type definitions for FlatBuffers field-level encryption
 *
 * All cryptographic operations use the Crypto++ WASM module.
 */

// =============================================================================
// Error Types
// =============================================================================

/**
 * Error codes for cryptographic operations
 */
export declare const CryptoErrorCode: {
  NOT_INITIALIZED: 'NOT_INITIALIZED';
  INVALID_KEY_SIZE: 'INVALID_KEY_SIZE';
  INVALID_IV_SIZE: 'INVALID_IV_SIZE';
  INVALID_NONCE_SIZE: 'INVALID_NONCE_SIZE';
  INVALID_SIGNATURE: 'INVALID_SIGNATURE';
  INVALID_PUBLIC_KEY: 'INVALID_PUBLIC_KEY';
  INVALID_PRIVATE_KEY: 'INVALID_PRIVATE_KEY';
  ENCRYPTION_FAILED: 'ENCRYPTION_FAILED';
  DECRYPTION_FAILED: 'DECRYPTION_FAILED';
  KEY_GENERATION_FAILED: 'KEY_GENERATION_FAILED';
  ECDH_FAILED: 'ECDH_FAILED';
  SIGNING_FAILED: 'SIGNING_FAILED';
  VERIFICATION_FAILED: 'VERIFICATION_FAILED';
  AUTHENTICATION_FAILED: 'AUTHENTICATION_FAILED';
  MEMORY_ERROR: 'MEMORY_ERROR';
  INVALID_INPUT: 'INVALID_INPUT';
};

export type CryptoErrorCodeType = typeof CryptoErrorCode[keyof typeof CryptoErrorCode];

/**
 * Custom error class for cryptographic operations
 */
export declare class CryptoError extends Error {
  readonly code: CryptoErrorCodeType;
  readonly cause?: Error;

  constructor(code: CryptoErrorCodeType, message: string, cause?: Error);

  static fromWasmCode(wasmCode: number, operation: string): CryptoError;
}

// =============================================================================
// Constants
// =============================================================================

export declare const KEY_SIZE: 32;
export declare const IV_SIZE: 16;
export declare const SHA256_SIZE: 32;
export declare const HMAC_SIZE: 32;
export declare const X25519_PRIVATE_KEY_SIZE: 32;
export declare const X25519_PUBLIC_KEY_SIZE: 32;
export declare const SECP256K1_PRIVATE_KEY_SIZE: 32;
export declare const SECP256K1_PUBLIC_KEY_SIZE: 33;
export declare const P256_PRIVATE_KEY_SIZE: 32;
export declare const P256_PUBLIC_KEY_SIZE: 33;
export declare const ED25519_PRIVATE_KEY_SIZE: 64;
export declare const ED25519_PUBLIC_KEY_SIZE: 32;
export declare const ED25519_SIGNATURE_SIZE: 64;
export declare const MAX_DER_SIGNATURE_SIZE: 72;

export declare const KeyExchangeAlgorithm: {
  X25519: 'x25519';
  SECP256K1: 'secp256k1';
  P256: 'p256';
};

export declare const SignatureAlgorithm: {
  ED25519: 'ed25519';
  SECP256K1_ECDSA: 'secp256k1-ecdsa';
  P256_ECDSA: 'p256-ecdsa';
};

export declare const SymmetricAlgorithm: {
  AES_256_CTR: 'aes-256-ctr';
};

export declare const KeyDerivationFunction: {
  HKDF_SHA256: 'hkdf-sha256';
};

// =============================================================================
// Initialization
// =============================================================================

/**
 * Initialize the encryption module with a pre-loaded WASM instance
 */
export declare function initEncryption(instance: WebAssembly.Instance): void;

/**
 * Load and initialize the encryption WASM module
 * @param wasmSource - Path to WASM file, URL, or binary data
 */
export declare function loadEncryptionWasm(
  wasmSource: string | URL | Uint8Array | ArrayBuffer
): Promise<void>;

/**
 * Check if encryption module is initialized
 */
export declare function isInitialized(): boolean;

/**
 * Check if Crypto++ is available in the WASM module
 */
export declare function hasCryptopp(): boolean;

/**
 * Get the WASM module version
 */
export declare function getVersion(): string;

// =============================================================================
// Hash Functions
// =============================================================================

/**
 * Compute SHA-256 hash
 * @param data - Data to hash
 * @returns 32-byte hash
 */
export declare function sha256(data: Uint8Array): Uint8Array;

// =============================================================================
// HMAC-SHA256
// =============================================================================

/**
 * Compute HMAC-SHA256
 * @param key - HMAC key
 * @param data - Data to authenticate
 * @returns 32-byte HMAC tag
 */
export declare function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array;

/**
 * Verify HMAC-SHA256 in constant time
 * @param key - HMAC key
 * @param data - Data to verify
 * @param expectedMac - Expected HMAC tag
 * @returns true if MAC is valid
 */
export declare function hmacSha256Verify(
  key: Uint8Array,
  data: Uint8Array,
  expectedMac: Uint8Array
): boolean;

// =============================================================================
// Symmetric Encryption (AES-256-CTR)
// =============================================================================

/**
 * Encrypt data in-place using AES-256-CTR
 *
 * WARNING: This function modifies the data array in-place.
 * CTR mode is a stream cipher - each (key, IV) pair must be unique.
 *
 * @param data - Data to encrypt (modified in-place)
 * @param key - 32-byte key
 * @param iv - 16-byte IV (must be unique per encryption)
 */
export declare function encryptBytes(
  data: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array
): void;

/**
 * Decrypt data in-place using AES-256-CTR
 * Same as encryptBytes (CTR mode is symmetric)
 */
export declare function decryptBytes(
  data: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array
): void;

// =============================================================================
// Authenticated Encryption (Encrypt-then-MAC)
// =============================================================================

/**
 * Encrypt data with authentication using AES-256-CTR + HMAC-SHA256 (Encrypt-then-MAC).
 * Returns a new buffer containing: IV (16 bytes) + ciphertext + HMAC (32 bytes).
 *
 * @param plaintext - Data to encrypt
 * @param key - 32-byte encryption key
 * @param associatedData - Optional additional data to authenticate (not encrypted)
 * @returns Authenticated ciphertext (IV + ciphertext + HMAC)
 */
export declare function encryptAuthenticated(
  plaintext: Uint8Array,
  key: Uint8Array,
  associatedData?: Uint8Array
): Uint8Array;

/**
 * Decrypt and verify authenticated ciphertext.
 * Input format: IV (16 bytes) + ciphertext + HMAC (32 bytes).
 *
 * @param authenticatedCiphertext - Output from encryptAuthenticated
 * @param key - 32-byte encryption key
 * @param associatedData - Optional additional authenticated data
 * @returns Decrypted plaintext
 * @throws CryptoError with code AUTHENTICATION_FAILED if MAC verification fails
 */
export declare function decryptAuthenticated(
  authenticatedCiphertext: Uint8Array,
  key: Uint8Array,
  associatedData?: Uint8Array
): Uint8Array;

// =============================================================================
// HKDF Key Derivation
// =============================================================================

/**
 * Derive key using HKDF-SHA256
 * @param ikm - Input key material
 * @param salt - Optional salt (can be null)
 * @param info - Optional context info (can be null)
 * @param length - Output length in bytes
 * @returns Derived key material
 */
export declare function hkdf(
  ikm: Uint8Array,
  salt: Uint8Array | null,
  info: Uint8Array | null,
  length: number
): Uint8Array;

// =============================================================================
// X25519 Key Exchange
// =============================================================================

export interface KeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

/**
 * Generate X25519 key pair
 * @param privateKey - Optional 32-byte private key (generates random if not provided)
 */
export declare function x25519GenerateKeyPair(privateKey?: Uint8Array): KeyPair;

/**
 * Compute X25519 shared secret (ECDH)
 * @param privateKey - Our private key (32 bytes)
 * @param publicKey - Their public key (32 bytes)
 * @returns 32-byte shared secret
 */
export declare function x25519SharedSecret(
  privateKey: Uint8Array,
  publicKey: Uint8Array
): Uint8Array;

/**
 * Derive symmetric key from X25519 shared secret
 */
export declare function x25519DeriveKey(
  sharedSecret: Uint8Array,
  context: Uint8Array | string
): Uint8Array;

// =============================================================================
// secp256k1 Key Exchange and Signatures (Bitcoin/Ethereum)
// =============================================================================

/**
 * Generate secp256k1 key pair
 * @param privateKey - Optional 32-byte private key
 */
export declare function secp256k1GenerateKeyPair(privateKey?: Uint8Array): KeyPair;

/**
 * Compute secp256k1 ECDH shared secret
 * @param privateKey - Our private key (32 bytes)
 * @param publicKey - Their public key (33 bytes compressed)
 */
export declare function secp256k1SharedSecret(
  privateKey: Uint8Array,
  publicKey: Uint8Array
): Uint8Array;

/**
 * Derive symmetric key from secp256k1 shared secret
 */
export declare function secp256k1DeriveKey(
  sharedSecret: Uint8Array,
  context: Uint8Array | string
): Uint8Array;

/**
 * Sign data with secp256k1 ECDSA
 * @param privateKey - Signing private key (32 bytes)
 * @param data - Data to sign
 * @returns DER-encoded signature
 */
export declare function secp256k1Sign(
  privateKey: Uint8Array,
  data: Uint8Array
): Uint8Array;

/**
 * Verify secp256k1 ECDSA signature
 * @param publicKey - Verification public key (33 bytes)
 * @param data - Original data
 * @param signature - DER-encoded signature
 * @returns true if signature is valid, false otherwise
 */
export declare function secp256k1Verify(
  publicKey: Uint8Array,
  data: Uint8Array,
  signature: Uint8Array
): boolean;

// =============================================================================
// P-256 Key Exchange and Signatures (NIST)
// =============================================================================

/**
 * Generate P-256 key pair
 * @param privateKey - Optional 32-byte private key
 */
export declare function p256GenerateKeyPair(privateKey?: Uint8Array): KeyPair;

/**
 * Compute P-256 ECDH shared secret
 */
export declare function p256SharedSecret(
  privateKey: Uint8Array,
  publicKey: Uint8Array
): Uint8Array;

/**
 * Derive symmetric key from P-256 shared secret
 */
export declare function p256DeriveKey(
  sharedSecret: Uint8Array,
  context: Uint8Array | string
): Uint8Array;

/**
 * Sign data with P-256 ECDSA
 */
export declare function p256Sign(
  privateKey: Uint8Array,
  data: Uint8Array
): Uint8Array;

/**
 * Verify P-256 ECDSA signature
 */
export declare function p256Verify(
  publicKey: Uint8Array,
  data: Uint8Array,
  signature: Uint8Array
): boolean;

// =============================================================================
// Ed25519 Signatures
// =============================================================================

/**
 * Generate Ed25519 signing key pair
 */
export declare function ed25519GenerateKeyPair(): KeyPair;

/**
 * Sign data with Ed25519
 * @param privateKey - Signing private key (64 bytes)
 * @param data - Data to sign
 * @returns 64-byte signature
 */
export declare function ed25519Sign(
  privateKey: Uint8Array,
  data: Uint8Array
): Uint8Array;

/**
 * Verify Ed25519 signature
 * @param publicKey - Verification public key (32 bytes)
 * @param data - Original data
 * @param signature - 64-byte signature
 * @returns true if signature is valid, false otherwise
 */
export declare function ed25519Verify(
  publicKey: Uint8Array,
  data: Uint8Array,
  signature: Uint8Array
): boolean;

// =============================================================================
// Encryption Context
// =============================================================================

/**
 * Encryption context for FlatBuffer field encryption.
 *
 * IMPORTANT: Each encryption operation requires a unique nonce to prevent IV reuse.
 * The nonce is combined with the field ID to derive unique IVs for each field.
 *
 * WARNING: Methods that encrypt data modify the buffer in-place.
 */
export declare class EncryptionContext {
  /**
   * Create an encryption context
   * @param key - 32-byte key as Uint8Array or 64-character hex string
   * @param nonce - Optional 16-byte nonce for IV derivation.
   *   CRITICAL: A new random nonce MUST be used for each encryption operation.
   *   If not provided, a random nonce is generated.
   */
  constructor(key: Uint8Array | string, nonce?: Uint8Array);

  /**
   * Create from hex string
   * @param hexKey - 64-character hex string
   * @param nonce - Optional 16-byte nonce for IV derivation
   */
  static fromHex(hexKey: string, nonce?: Uint8Array): EncryptionContext;

  /**
   * Get the nonce used by this context.
   * This nonce must be stored/transmitted with the encrypted data for decryption.
   * @returns The 16-byte nonce
   */
  getNonce(): Uint8Array;

  /**
   * Check if context is valid
   */
  isValid(): boolean;

  /**
   * Derive a field-specific key using HKDF
   * @param fieldId - Field ID
   * @returns 32-byte derived key
   */
  deriveFieldKey(fieldId: number): Uint8Array;

  /**
   * Derive a field-specific IV using HKDF
   * @param fieldId - Field ID
   * @returns 16-byte derived IV
   */
  deriveFieldIV(fieldId: number): Uint8Array;

  /**
   * Encrypt scalar value in buffer (modifies buffer in-place)
   */
  encryptScalar(buffer: Uint8Array, offset: number, size: number, fieldId: number): void;

  /**
   * Encrypt string value in buffer (modifies buffer in-place)
   */
  encryptString(buffer: Uint8Array, offset: number, length: number, fieldId: number): void;

  /**
   * Encrypt vector data in buffer (modifies buffer in-place)
   */
  encryptVector(buffer: Uint8Array, offset: number, elementSize: number, count: number, fieldId: number): void;
}

// =============================================================================
// Schema Parsing
// =============================================================================

/**
 * Parsed field information for encryption
 */
export interface EncryptionFieldInfo {
  /** Field name */
  name: string;
  /** Field ID (position in table) */
  id: number;
  /** Field type (bool, int, string, vector, struct, etc.) */
  type: string;
  /** Whether field is marked encrypted */
  encrypted: boolean;
  /** Element type for vectors */
  elementType?: string;
  /** Element size for vectors/scalars */
  elementSize?: number;
}

/**
 * Parsed schema for encryption operations
 */
export interface EncryptionSchema {
  /** Fields in the table */
  fields: EncryptionFieldInfo[];
}

/**
 * Parse a FlatBuffers schema to extract field encryption info
 * @param schemaContent - FlatBuffers schema content (.fbs)
 * @param rootType - Name of the root type
 * @returns Parsed schema with encryption metadata
 */
export declare function parseSchemaForEncryption(
  schemaContent: string,
  rootType: string
): EncryptionSchema;

// =============================================================================
// Buffer Encryption
// =============================================================================

/**
 * Result of encrypting a FlatBuffer
 */
export interface EncryptBufferResult {
  /** The encrypted buffer (same reference as input) */
  buffer: Uint8Array;
  /** The 16-byte nonce used for encryption (must be stored for decryption) */
  nonce: Uint8Array;
}

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
 * @param buffer - FlatBuffer to encrypt (modified in-place)
 * @param schema - Parsed schema or schema content string
 * @param key - 32-byte encryption key, 64-char hex string, or EncryptionContext
 * @param rootType - Root type name (required if schema is string)
 * @returns Object with encrypted buffer and nonce
 *
 * @example
 * ```javascript
 * import { encryptBuffer, EncryptionContext } from 'flatc-wasm/encryption';
 *
 * // Using raw key - MUST save the nonce
 * const key = crypto.getRandomValues(new Uint8Array(32));
 * const { buffer, nonce } = encryptBuffer(buf, schemaContent, key, 'MyTable');
 * // Store nonce alongside encrypted data for decryption
 *
 * // Using EncryptionContext - manage nonce yourself
 * const ctx = new EncryptionContext(key, nonce);
 * const { buffer } = encryptBuffer(buf, schemaContent, ctx, 'MyTable');
 * ```
 */
export declare function encryptBuffer(
  buffer: Uint8Array,
  schema: EncryptionSchema | string,
  key: Uint8Array | string | EncryptionContext,
  rootType?: string
): EncryptBufferResult;

/**
 * Decrypt a FlatBuffer in-place.
 *
 * AES-CTR is symmetric, so decryption uses the same operation as encryption.
 * You MUST provide the same nonce that was used during encryption.
 *
 * WARNING: This function modifies the buffer in-place.
 *
 * @param buffer - FlatBuffer to decrypt (modified in-place)
 * @param schema - Parsed schema or schema content string
 * @param key - 32-byte encryption key, 64-char hex string, or EncryptionContext
 * @param rootType - Root type name (required if schema is string)
 * @param nonce - The 16-byte nonce from encryption (required if key is not EncryptionContext)
 * @returns The decrypted buffer (same reference)
 *
 * @example
 * ```javascript
 * // Using raw key with nonce from encryptBuffer
 * const { buffer: encrypted, nonce } = encryptBuffer(buf, schema, key, 'MyTable');
 * // ... later ...
 * decryptBuffer(encrypted, schema, key, 'MyTable', nonce);
 *
 * // Using EncryptionContext with saved nonce
 * const ctx = new EncryptionContext(key, savedNonce);
 * decryptBuffer(encrypted, schema, ctx, 'MyTable');
 * ```
 */
export declare function decryptBuffer(
  buffer: Uint8Array,
  schema: EncryptionSchema | string,
  key: Uint8Array | string | EncryptionContext,
  rootType?: string,
  nonce?: Uint8Array
): Uint8Array;

/**
 * Encrypt scalar in buffer (convenience function)
 */
export declare function encryptScalar(
  buffer: Uint8Array,
  offset: number,
  size: number,
  ctx: EncryptionContext,
  fieldId: number
): void;

// =============================================================================
// Encryption Header (for hybrid encryption)
// =============================================================================

export interface EncryptionHeader {
  version: number;
  algorithm: string;
  senderPublicKey: Uint8Array;
  recipientKeyId: Uint8Array;
  iv: Uint8Array;
}

export interface EncryptionHeaderJSON {
  version: number;
  algorithm: string;
  senderPublicKey: number[];
  recipientKeyId: number[];
  iv: number[];
}

/**
 * Create encryption header for hybrid encryption
 */
export declare function createEncryptionHeader(options: {
  algorithm: string;
  senderPublicKey: Uint8Array;
  recipientKeyId: Uint8Array;
  iv?: Uint8Array;
}): EncryptionHeader;

/**
 * Compute key ID from public key (first 8 bytes of SHA-256)
 */
export declare function computeKeyId(publicKey: Uint8Array): Uint8Array;

/**
 * Convert encryption header to JSON-serializable object
 */
export declare function encryptionHeaderToJSON(header: EncryptionHeader): EncryptionHeaderJSON;

/**
 * Parse encryption header from JSON
 */
export declare function encryptionHeaderFromJSON(json: EncryptionHeaderJSON): EncryptionHeader;

// =============================================================================
// Default Export
// =============================================================================

declare const encryption: {
  // Error types
  CryptoError: typeof CryptoError;
  CryptoErrorCode: typeof CryptoErrorCode;

  // Initialization
  initEncryption: typeof initEncryption;
  loadEncryptionWasm: typeof loadEncryptionWasm;
  isInitialized: typeof isInitialized;
  hasCryptopp: typeof hasCryptopp;
  getVersion: typeof getVersion;

  // Hash
  sha256: typeof sha256;
  hmacSha256: typeof hmacSha256;
  hmacSha256Verify: typeof hmacSha256Verify;

  // Symmetric encryption
  encryptBytes: typeof encryptBytes;
  decryptBytes: typeof decryptBytes;
  encryptAuthenticated: typeof encryptAuthenticated;
  decryptAuthenticated: typeof decryptAuthenticated;
  hkdf: typeof hkdf;

  // X25519
  x25519GenerateKeyPair: typeof x25519GenerateKeyPair;
  x25519SharedSecret: typeof x25519SharedSecret;
  x25519DeriveKey: typeof x25519DeriveKey;

  // secp256k1
  secp256k1GenerateKeyPair: typeof secp256k1GenerateKeyPair;
  secp256k1SharedSecret: typeof secp256k1SharedSecret;
  secp256k1DeriveKey: typeof secp256k1DeriveKey;
  secp256k1Sign: typeof secp256k1Sign;
  secp256k1Verify: typeof secp256k1Verify;

  // P-256
  p256GenerateKeyPair: typeof p256GenerateKeyPair;
  p256SharedSecret: typeof p256SharedSecret;
  p256DeriveKey: typeof p256DeriveKey;
  p256Sign: typeof p256Sign;
  p256Verify: typeof p256Verify;

  // Ed25519
  ed25519GenerateKeyPair: typeof ed25519GenerateKeyPair;
  ed25519Sign: typeof ed25519Sign;
  ed25519Verify: typeof ed25519Verify;

  // Constants
  KeyExchangeAlgorithm: typeof KeyExchangeAlgorithm;
  SignatureAlgorithm: typeof SignatureAlgorithm;
  SymmetricAlgorithm: typeof SymmetricAlgorithm;
  KeyDerivationFunction: typeof KeyDerivationFunction;

  // Classes
  EncryptionContext: typeof EncryptionContext;

  // Header utilities
  createEncryptionHeader: typeof createEncryptionHeader;
  computeKeyId: typeof computeKeyId;
  encryptionHeaderToJSON: typeof encryptionHeaderToJSON;
  encryptionHeaderFromJSON: typeof encryptionHeaderFromJSON;
  encryptScalar: typeof encryptScalar;

  // Buffer encryption
  parseSchemaForEncryption: typeof parseSchemaForEncryption;
  encryptBuffer: typeof encryptBuffer;
  decryptBuffer: typeof decryptBuffer;
};

export default encryption;
