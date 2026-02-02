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
  /** Recipient's public key (32 bytes for X25519, 33 for secp256k1/P-256/P-384) */
  publicKey: Uint8Array;
  /** Key exchange algorithm (default: "x25519") */
  algorithm?: "x25519" | "secp256k1" | "p256" | "p384";
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
