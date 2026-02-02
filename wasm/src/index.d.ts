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

export declare function loadEncryptionWasm(): Promise<void>;
export declare function isInitialized(): boolean;
export declare function getInitError(): Error | null;
export declare function hasCryptopp(): boolean;
export declare function getVersion(): string;

// =============================================================================
// Encryption — IV Tracking
// =============================================================================

export declare function clearIVTracking(key: Uint8Array): void;
export declare function clearAllIVTracking(): void;

// =============================================================================
// Encryption — Hashing & KDF
// =============================================================================

export declare function sha256(data: Uint8Array): Uint8Array;
export declare function hkdf(ikm: Uint8Array, salt: Uint8Array | null, info: Uint8Array | null, length: number): Uint8Array;
export declare function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array;
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

export interface KeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

export declare function x25519GenerateKeyPair(existingPrivateKey?: Uint8Array): KeyPair;
export declare function x25519SharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array;
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
// Encryption — P-256
// =============================================================================

export declare function p256GenerateKeyPairAsync(): Promise<KeyPair>;
export declare function p256SharedSecretAsync(privateKeyPkcs8: Uint8Array, publicKeyRaw: Uint8Array): Promise<Uint8Array>;
export declare function p256DeriveKey(sharedSecret: Uint8Array, context?: string | Uint8Array): Uint8Array;
export declare function p256SignAsync(privateKeyPkcs8: Uint8Array, data: Uint8Array): Promise<Uint8Array>;
export declare function p256VerifyAsync(publicKeyRaw: Uint8Array, data: Uint8Array, signature: Uint8Array): Promise<boolean>;

// =============================================================================
// Encryption — P-384
// =============================================================================

export declare function p384GenerateKeyPairAsync(): Promise<KeyPair>;
export declare function p384SharedSecretAsync(privateKeyPkcs8: Uint8Array, publicKeyRaw: Uint8Array): Promise<Uint8Array>;
export declare function p384DeriveKey(sharedSecret: Uint8Array, context?: string | Uint8Array): Uint8Array;
export declare function p384SignAsync(privateKeyPkcs8: Uint8Array, data: Uint8Array): Promise<Uint8Array>;
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
