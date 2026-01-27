/**
 * flatc-wasm - FlatBuffers compiler as a WebAssembly module
 *
 * This module exports:
 * - FlatcRunner: High-level wrapper with typed methods for schema operations
 * - createFlatcModule: Low-level factory for direct WASM module access
 * - Encryption utilities for field-level encryption
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

// Encryption exports
export {
  // Error types
  CryptoError,
  CryptoErrorCode,
  CryptoErrorCodeType,
  // Context and initialization
  EncryptionContext,
  initEncryption,
  loadEncryptionWasm,
  isInitialized,
  hasCryptopp,
  getVersion,
  // Hashing
  sha256,
  hmacSha256,
  hmacSha256Verify,
  // Symmetric encryption
  encryptBytes,
  decryptBytes,
  encryptAuthenticated,
  decryptAuthenticated,
  encryptScalar,
  // Key derivation
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
  // Header utilities
  createEncryptionHeader,
  computeKeyId,
  encryptionHeaderToJSON,
  encryptionHeaderFromJSON,
  // Buffer encryption
  parseSchemaForEncryption,
  encryptBuffer,
  decryptBuffer,
  EncryptBufferResult,
  EncryptionSchema,
  EncryptionFieldInfo,
  EncryptionHeader,
  EncryptionHeaderJSON,
  KeyPair,
  // Constants
  KEY_SIZE,
  IV_SIZE,
  HMAC_SIZE,
  SHA256_SIZE,
} from "./encryption.js";

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
