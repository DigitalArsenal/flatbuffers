/**
 * flatc-wasm - FlatBuffers compiler as a WebAssembly module
 *
 * This module exports:
 * - FlatcRunner: High-level wrapper with typed methods for schema operations
 * - createFlatcModule: Low-level factory for direct WASM module access
 * - Aligned codegen for zero-copy WASM interop
 */

export {
  FlatcRunner,
  SchemaInput,
  BinaryInput,
  CommandResult,
  GenerateBinaryOptions,
  GenerateJSONOptions,
  GenerateCodeOptions,
  TargetLanguage,
  FlatcRunnerOptions,
  EmscriptenModule,
  EmscriptenFS,
} from "./runner.js";

// Aligned codegen exports
export {
  parseSchema,
  computeLayout,
  generateCppHeader,
  generateTypeScript,
  generateJavaScript,
  generateAlignedCode,
} from "./aligned-codegen.js";

// Streaming dispatcher exports
export {
  StreamingDispatcher,
  createSizePrefixedMessage,
  concatMessages,
  MessageTypeInfo,
  DispatcherStats,
  InputBufferInfo,
  DispatcherWasmModule,
} from "./streaming-dispatcher.js";

// HD Key derivation exports (BIP-32/BIP-44)
export {
  // Constants
  BIP44_PURPOSE,
  Chain,
  CoinType,
  Curve,
  CoinTypeToCurve,
  DefaultCoinType,
  CoinTypeName,
  KeyPurpose,
  // Path utilities
  buildPath,
  buildSigningPath,
  buildEncryptionPath,
  parsePath,
  // Manager class
  HDKeyManager,
  // Factory functions
  createFromMnemonic,
  createFromSeed,
  // Validation
  validateSigningKey,
  validateEncryptionKey,
  // Types
  PathOptions,
  DeriveOptions,
  DeriveForPurposeOptions,
  DerivedKey,
  DerivedKeyPair,
  ParsedPath,
  CoinTypeInfo,
} from "./hd-keys.js";

// Encryption types
export interface EncryptionOptions {
  /** Recipient's public key (32 bytes for X25519, 33 for secp256k1) */
  publicKey: Uint8Array;
  /** Key exchange algorithm (default: "x25519"). p256/p384 require async forEncryptionAsync. */
  algorithm?: "x25519" | "secp256k1";
  /** Field names to encrypt (if empty, uses (encrypted) attribute from schema) */
  fields?: string[];
  /** HKDF context string for domain separation */
  context?: string;
  /** Use FIPS mode (OpenSSL path) */
  fips?: boolean;
}

export interface DecryptionOptions {
  /** Private key for decryption */
  privateKey: Uint8Array;
  /** Encryption header (if separate from data) */
  header?: Uint8Array;
}

export interface EncryptedBinaryResult {
  /** Encryption header (EncryptionHeader FlatBuffer) */
  header: Uint8Array;
  /** Encrypted FlatBuffer data */
  data: Uint8Array;
}

export interface GenerateBinaryEncryptedOptions {
  /** Same as GenerateBinaryOptions */
  unknownJson?: boolean;
  strictJson?: boolean;
  fileIdentifier?: boolean;
  sizePrefix?: boolean;
}

export interface GenerateJSONDecryptedOptions {
  /** Same as GenerateJSONOptions */
  strictJson?: boolean;
  rawBinary?: boolean;
  defaultsJson?: boolean;
  encoding?: "utf8" | null;
  skipValidation?: boolean;
}

/**
 * Options for creating the WASM module.
 */
export interface CreateModuleOptions {
  /** Don't exit the runtime when main() returns */
  noExitRuntime?: boolean;
  /** Don't run main() on module load */
  noInitialRun?: boolean;
  /** Custom function for stdout output */
  print?: (text: string) => void;
  /** Custom function for stderr output */
  printErr?: (text: string) => void;
  /** Additional module options */
  [key: string]: unknown;
}

/**
 * The instantiated Emscripten WASM module.
 */
export interface FlatcModule {
  /** Call the main() function with arguments */
  callMain(args: string[]): number;
  /** The virtual filesystem */
  FS: {
    mkdir(path: string): void;
    mkdirTree(path: string): void;
    writeFile(path: string, data: string | Uint8Array): void;
    readFile(path: string, options?: { encoding?: string | null }): string | Uint8Array;
    readdir(path: string): string[];
    unlink(path: string): void;
    rmdir(path: string): void;
    stat(path: string): { mode: number };
    isDir(mode: number): boolean;
  };
  /** Path utilities */
  PATH: {
    dirname(path: string): string;
    basename(path: string): string;
    join(...paths: string[]): string;
  };
  /** Read a UTF-8 string from memory */
  UTF8ToString(ptr: number): string;
  /** Write a UTF-8 string to memory */
  stringToUTF8(str: string, ptr: number, maxBytes: number): void;
  /** Get length of UTF-8 string in bytes */
  lengthBytesUTF8(str: string): number;
  /** Get a value from memory */
  getValue(ptr: number, type: string): number;
  /** Set a value in memory */
  setValue(ptr: number, value: number, type: string): void;
  /** Call a C function */
  ccall(name: string, returnType: string | null, argTypes: string[], args: unknown[]): unknown;
  /** Wrap a C function */
  cwrap(name: string, returnType: string | null, argTypes: string[]): (...args: unknown[]) => unknown;
}

/**
 * Create a new flatc WASM module instance.
 * @param options - Module initialization options.
 * @returns Promise resolving to the module instance.
 */
export declare function createFlatcModule(options?: CreateModuleOptions): Promise<FlatcModule>;

export default createFlatcModule;

// =============================================================================
// Encryption — Constants
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
export declare const P256_PUBLIC_KEY_SIZE: 65;
export declare const P384_PRIVATE_KEY_SIZE: 48;
export declare const P384_PUBLIC_KEY_SIZE: 97;
export declare const ED25519_PRIVATE_KEY_SIZE: 64;
export declare const ED25519_PUBLIC_KEY_SIZE: 32;
export declare const ED25519_SIGNATURE_SIZE: 64;

// =============================================================================
// Encryption — Error Types
// =============================================================================

export declare const CryptoErrorCode: Readonly<{
  IV_REUSE: 'IV_REUSE';
  INVALID_KEY: 'INVALID_KEY';
  INVALID_IV: 'INVALID_IV';
  INVALID_INPUT: 'INVALID_INPUT';
  NOT_INITIALIZED: 'NOT_INITIALIZED';
  WASM_ERROR: 'WASM_ERROR';
  AUTHENTICATION_FAILED: 'AUTHENTICATION_FAILED';
}>;

export declare class CryptoError extends Error {
  code: string;
  constructor(message: string, code: string);
}

// =============================================================================
// Encryption — Key Exchange Algorithm Enum
// =============================================================================

export declare const KeyExchangeAlgorithm: Readonly<{
  X25519: 'x25519';
  SECP256K1: 'secp256k1';
  P256: 'p256';
  P384: 'p384';
}>;

// =============================================================================
// Encryption — Module Loading & Info
// =============================================================================

/**
 * Load the encryption WASM module. Called automatically on first use,
 * but can be called explicitly to pre-warm the module.
 * @returns Promise that resolves when the module is loaded.
 */
export declare function loadEncryptionWasm(): Promise<void>;

/**
 * Check if the encryption WASM module is initialized.
 * @returns true if the module is ready for use.
 */
export declare function isInitialized(): boolean;

/**
 * Get any initialization error that occurred during module loading.
 * @returns The error, or null if initialization succeeded.
 */
export declare function getInitError(): Error | null;

/**
 * Check if Crypto++ is available (WASM encryption module).
 * @returns true if Crypto++ WASM is loaded.
 */
export declare function hasCryptopp(): boolean;

/**
 * Get the version string of the encryption module.
 * @returns Version string.
 */
export declare function getVersion(): string;

// =============================================================================
// Encryption — IV Tracking
// =============================================================================

export declare function clearIVTracking(key: Uint8Array): void;
export declare function clearAllIVTracking(): void;

// =============================================================================
// Encryption — Hashing & KDF
// =============================================================================

/**
 * Compute SHA-256 hash of data.
 * @param data - Input data to hash.
 * @returns 32-byte hash.
 */
export declare function sha256(data: Uint8Array): Uint8Array;

/**
 * Derive a key using HKDF-SHA256 (RFC 5869).
 * @param ikm - Input key material.
 * @param salt - Optional salt (null for no salt).
 * @param info - Optional context info (null for no info).
 * @param length - Desired output length in bytes.
 * @returns Derived key of the specified length.
 */
export declare function hkdf(ikm: Uint8Array, salt: Uint8Array | null, info: Uint8Array | null, length: number): Uint8Array;

/**
 * Compute HMAC-SHA256 message authentication code.
 * @param key - HMAC key.
 * @param data - Data to authenticate.
 * @returns 32-byte MAC.
 */
export declare function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array;

/**
 * Verify HMAC-SHA256 in constant time.
 * @param key - HMAC key.
 * @param data - Data that was authenticated.
 * @param mac - MAC to verify.
 * @returns true if MAC is valid.
 */
export declare function hmacSha256Verify(key: Uint8Array, data: Uint8Array, mac: Uint8Array): boolean;

// =============================================================================
// Encryption — AES-256-CTR
// =============================================================================

export declare function encryptBytes(data: Uint8Array, key: Uint8Array, iv: Uint8Array): void;
export declare function decryptBytes(data: Uint8Array, key: Uint8Array, iv: Uint8Array): void;
export declare function generateIV(): Uint8Array;
export declare function encryptBytesCopy(plaintext: Uint8Array, key: Uint8Array, iv?: Uint8Array): { ciphertext: Uint8Array; iv: Uint8Array };
export declare function decryptBytesCopy(ciphertext: Uint8Array, key: Uint8Array, iv: Uint8Array): Uint8Array;

// =============================================================================
// Encryption — X25519
// =============================================================================

/** Key pair with private and public keys. */
export interface KeyPair {
  /** Private key bytes. */
  privateKey: Uint8Array;
  /** Public key bytes. */
  publicKey: Uint8Array;
}

/**
 * Generate an X25519 key pair for ECDH key exchange.
 * @param existingPrivateKey - Optional existing private key (32 bytes).
 * @returns Key pair with 32-byte private and public keys.
 */
export declare function x25519GenerateKeyPair(existingPrivateKey?: Uint8Array): KeyPair;

/**
 * Compute X25519 shared secret for ECDH key agreement.
 * @param privateKey - Own private key (32 bytes).
 * @param publicKey - Peer's public key (32 bytes).
 * @returns 32-byte shared secret.
 */
export declare function x25519SharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array;

/**
 * Derive an encryption key from X25519 shared secret using HKDF.
 * @param sharedSecret - Shared secret from x25519SharedSecret.
 * @param context - Optional context string for domain separation.
 * @returns 32-byte derived key suitable for AES-256.
 */
export declare function x25519DeriveKey(sharedSecret: Uint8Array, context?: string | Uint8Array): Uint8Array;

// =============================================================================
// Encryption — secp256k1
// =============================================================================

export declare function secp256k1GenerateKeyPair(): KeyPair;
export declare function secp256k1SharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array;
export declare function secp256k1DeriveKey(sharedSecret: Uint8Array, context?: string | Uint8Array): Uint8Array;
export declare function secp256k1Sign(privateKey: Uint8Array, data: Uint8Array): Uint8Array;
export declare function secp256k1Verify(publicKey: Uint8Array, data: Uint8Array, signature: Uint8Array): boolean;

// =============================================================================
// Encryption — P-256 (NIST secp256r1) — Async via Web Crypto API
// =============================================================================

/**
 * Generate a P-256 key pair for ECDH/ECDSA. Uses Web Crypto API (async).
 * @returns Promise resolving to key pair (privateKey: PKCS8, publicKey: raw 65 bytes).
 */
export declare function p256GenerateKeyPairAsync(): Promise<KeyPair>;

/**
 * Compute P-256 shared secret. Uses Web Crypto API (async).
 * @param privateKeyPkcs8 - Private key in PKCS8 format.
 * @param publicKeyRaw - Public key in raw format (65 bytes uncompressed).
 * @returns Promise resolving to 32-byte shared secret.
 */
export declare function p256SharedSecretAsync(privateKeyPkcs8: Uint8Array, publicKeyRaw: Uint8Array): Promise<Uint8Array>;

/**
 * Derive encryption key from P-256 shared secret using HKDF. Synchronous.
 * @param sharedSecret - Shared secret from p256SharedSecretAsync.
 * @param context - Optional context string for domain separation.
 * @returns 32-byte derived key.
 */
export declare function p256DeriveKey(sharedSecret: Uint8Array, context?: string | Uint8Array): Uint8Array;

/**
 * Sign data with P-256 ECDSA (SHA-256). Uses Web Crypto API (async).
 * @param privateKeyPkcs8 - Private key in PKCS8 format.
 * @param data - Data to sign.
 * @returns Promise resolving to signature bytes.
 */
export declare function p256SignAsync(privateKeyPkcs8: Uint8Array, data: Uint8Array): Promise<Uint8Array>;

/**
 * Verify P-256 ECDSA signature. Uses Web Crypto API (async).
 * @param publicKeyRaw - Public key in raw format (65 bytes).
 * @param data - Original data that was signed.
 * @param signature - Signature to verify.
 * @returns Promise resolving to true if valid.
 */
export declare function p256VerifyAsync(publicKeyRaw: Uint8Array, data: Uint8Array, signature: Uint8Array): Promise<boolean>;

// =============================================================================
// Encryption — P-384 (NIST secp384r1) — Async via Web Crypto API
// =============================================================================

/**
 * Generate a P-384 key pair for ECDH/ECDSA. Uses Web Crypto API (async).
 * Provides 192-bit security level.
 * @returns Promise resolving to key pair (privateKey: PKCS8, publicKey: raw 97 bytes).
 */
export declare function p384GenerateKeyPairAsync(): Promise<KeyPair>;

/**
 * Compute P-384 shared secret. Uses Web Crypto API (async).
 * @param privateKeyPkcs8 - Private key in PKCS8 format.
 * @param publicKeyRaw - Public key in raw format (97 bytes uncompressed).
 * @returns Promise resolving to 48-byte shared secret.
 */
export declare function p384SharedSecretAsync(privateKeyPkcs8: Uint8Array, publicKeyRaw: Uint8Array): Promise<Uint8Array>;

/**
 * Derive encryption key from P-384 shared secret using HKDF. Synchronous.
 * @param sharedSecret - Shared secret from p384SharedSecretAsync.
 * @param context - Optional context string for domain separation.
 * @returns 32-byte derived key.
 */
export declare function p384DeriveKey(sharedSecret: Uint8Array, context?: string | Uint8Array): Uint8Array;

/**
 * Sign data with P-384 ECDSA (SHA-384). Uses Web Crypto API (async).
 * @param privateKeyPkcs8 - Private key in PKCS8 format.
 * @param data - Data to sign.
 * @returns Promise resolving to signature bytes.
 */
export declare function p384SignAsync(privateKeyPkcs8: Uint8Array, data: Uint8Array): Promise<Uint8Array>;

/**
 * Verify P-384 ECDSA signature. Uses Web Crypto API (async).
 * @param publicKeyRaw - Public key in raw format (97 bytes).
 * @param data - Original data that was signed.
 * @param signature - Signature to verify.
 * @returns Promise resolving to true if valid.
 */
export declare function p384VerifyAsync(publicKeyRaw: Uint8Array, data: Uint8Array, signature: Uint8Array): Promise<boolean>;

// =============================================================================
// Encryption — Ed25519
// =============================================================================

export declare function ed25519GenerateKeyPair(): KeyPair;
export declare function ed25519Sign(privateKey: Uint8Array, data: Uint8Array): Uint8Array;
export declare function ed25519Verify(publicKey: Uint8Array, data: Uint8Array, signature: Uint8Array): boolean;

// =============================================================================
// Encryption — Encryption Header
// =============================================================================

export interface EncryptionHeader {
  version: number;
  algorithm: string;
  senderPublicKey: Uint8Array;
  recipientKeyId: Uint8Array;
  iv: Uint8Array;
  context: string;
  sequenceNumber?: bigint;
  sessionId?: Uint8Array;
}

export interface CreateEncryptionHeaderOptions {
  algorithm: string;
  senderPublicKey: Uint8Array;
  recipientKeyId: Uint8Array;
  iv?: Uint8Array;
  context?: string;
}

export declare function computeKeyId(publicKey: Uint8Array): Uint8Array;
export declare function createEncryptionHeader(options: CreateEncryptionHeaderOptions): EncryptionHeader;
export declare function encryptionHeaderToJSON(header: EncryptionHeader): string;
export declare function encryptionHeaderFromJSON(input: string | object): EncryptionHeader;

// =============================================================================
// Encryption — Authenticated Encryption
// =============================================================================

export declare function encryptAuthenticated(plaintext: Uint8Array, key: Uint8Array, aad?: Uint8Array): Uint8Array;
export declare function decryptAuthenticated(data: Uint8Array, key: Uint8Array, aad?: Uint8Array): Uint8Array;

// =============================================================================
// Encryption — Buffer Encryption
// =============================================================================

export interface EncryptedFieldInfo {
  id: number;
  name: string;
  offset: number;
  size: number;
  type: string;
}

export interface ParsedEncryptionSchema {
  rootType: string;
  fields: EncryptedFieldInfo[];
  enums: Record<string, any>;
}

export declare function encryptBuffer(buffer: Uint8Array, schema: ParsedEncryptionSchema, ctx: EncryptionContext, recordIndex?: number): Uint8Array;
export declare function decryptBuffer(buffer: Uint8Array, schema: ParsedEncryptionSchema, ctx: EncryptionContext, recordIndex?: number): Uint8Array;
export declare function parseSchemaForEncryption(schema: Uint8Array, rootType?: string): ParsedEncryptionSchema;

// =============================================================================
// Encryption — EncryptionContext
// =============================================================================

export interface EncryptionContextOptions {
  algorithm?: 'x25519' | 'secp256k1';
  context?: string;
}

export declare class EncryptionContext {
  constructor(key: Uint8Array | string);

  static fromHex(hexKey: string): EncryptionContext;
  static forEncryption(recipientPublicKey: Uint8Array, options?: EncryptionContextOptions): EncryptionContext;
  static forDecryption(privateKey: Uint8Array, header: EncryptionHeader, contextStr?: string): EncryptionContext;

  isValid(): boolean;
  getKey(): Uint8Array;
  getEphemeralPublicKey(): Uint8Array | null;
  getAlgorithm(): string | null;
  getContext(): string | null;
  getHeader(): EncryptionHeader;
  getHeaderJSON(): string;

  deriveFieldKey(fieldId: number, recordIndex?: number): Uint8Array;
  deriveFieldIV(fieldId: number, recordIndex?: number): Uint8Array;

  encryptScalar(buffer: Uint8Array, offset: number, length: number, fieldId: number, recordIndex?: number): void;
  decryptScalar(buffer: Uint8Array, offset: number, length: number, fieldId: number, recordIndex?: number): void;
  encryptBuffer(buffer: Uint8Array, recordIndex: number): void;
  decryptBuffer(buffer: Uint8Array, recordIndex: number): void;

  computeBufferMAC(buffer: Uint8Array, fieldIds?: number[]): Uint8Array;
  verifyBufferMAC(buffer: Uint8Array, mac: Uint8Array, fieldIds?: number[]): boolean;
  destroy(): void;
  ratchetKey(): EncryptionContext;
}

// =============================================================================
// Encryption — Wire Format
// =============================================================================

export declare const WIRE_FORMAT_MAGIC: Uint8Array;
export declare function serializeEncryptionHeader(header: EncryptionHeader, payload: Uint8Array): Uint8Array;
export declare function deserializeEncryptionHeader(data: Uint8Array): { header: EncryptionHeader; payload: Uint8Array };

// =============================================================================
// Encryption — Replay Protection
// =============================================================================

export declare class SequenceValidator {
  validate(sequenceNumber: bigint | number): boolean;
  getHighest(): bigint;
  reset(): void;
}

// =============================================================================
// Encryption — Observability
// =============================================================================

export interface CryptoEvent {
  operation: string;
  fieldId?: number;
  timestamp: number;
  keyId?: string;
  size?: number;
}

export declare function onCryptoEvent(callback: ((event: CryptoEvent) => void) | null): void;

// =============================================================================
// Encryption — Key Management
// =============================================================================

export interface KeyLookupOptions extends EncryptionContextOptions {
  lookupRecipientKey: (keyId: Uint8Array) => Uint8Array | Promise<Uint8Array>;
}

export declare function createContextWithKeyLookup(recipientKeyId: Uint8Array, options: KeyLookupOptions): Promise<EncryptionContext>;
