/**
 * FlatBufferPipeline - Unified API for FlatBuffers operations
 */

import { FlatcRunner, SchemaInput, GenerateBinaryOptions, GenerateJSONOptions, GenerateCodeOptions, TargetLanguage } from './runner.js';
import { StreamingDispatcher } from './streaming-dispatcher.js';
import { HEContext } from './he-context.js';
import { HDKeyManager } from './hd-keys.js';
import { HEFieldInfo } from './he-field-encryptor.js';

/** Options for creating a FlatBufferPipeline */
export interface PipelineOptions {
  /** Options for FlatcRunner.init() */
  runnerOptions?: Record<string, unknown>;
  /** Enable streaming dispatcher */
  streaming?: boolean;
  /** Options for StreamingDispatcher */
  streamingOptions?: Record<string, unknown>;
  /** Schema to set immediately */
  schema?: SchemaInput;
}

/** Options for HE context derivation from HD wallet */
export interface PipelineKeyOptions {
  /** BIP-44 coin type */
  coinType?: number;
  /** Account index */
  account?: number;
  /** Key index */
  index?: number;
}

/** Options for HE operations */
export interface PipelineHEOptions {
  /** Polynomial modulus degree */
  polyDegree?: number;
  /** Custom HKDF function */
  hkdfFn?: (ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number) => Promise<Uint8Array>;
}

/** Options for stream push */
export interface PushStreamOptions {
  /** 4-char file identifier */
  fileId?: string;
  /** Fixed message size for type registration */
  messageSize?: number;
  /** Ring buffer capacity */
  capacity?: number;
}

/** Options for HE encryption */
export interface EncryptHEOptions {
  /** Field names to encrypt */
  fields?: string[];
  /** Override HE context */
  heContext?: HEContext;
  /** Options for generateBinary */
  binaryOptions?: GenerateBinaryOptions;
}

/** Options for HE decryption */
export interface DecryptHEOptions {
  /** Field names that are encrypted */
  fields?: string[];
  /** Override HE context (must be client) */
  heContext?: HEContext;
}

/** Options for processForRecipient */
export interface RecipientOptions {
  /** Field names to encrypt */
  fields?: string[];
  /** Recipient's relinearization keys */
  relinKeys?: Uint8Array;
}

/** AES encryption config */
export interface AESEncryption {
  publicKey: Uint8Array;
  config?: Record<string, unknown>;
}

/** AES decryption config */
export interface AESDecryption {
  privateKey: Uint8Array;
  config?: Record<string, unknown>;
}

/**
 * Unified FlatBufferPipeline orchestrating all subsystems.
 */
export class FlatBufferPipeline {
  constructor(runner: FlatcRunner);

  /**
   * Create and initialize a new FlatBufferPipeline.
   */
  static create(options?: PipelineOptions): Promise<FlatBufferPipeline>;

  // Schema management
  setSchema(schemaInput: SchemaInput): FlatBufferPipeline;
  getSchemaSource(): string | null;

  // Key management
  setKeyManager(hdKeyManager: HDKeyManager): FlatBufferPipeline;
  setHEContext(heContext: HEContext): FlatBufferPipeline;
  deriveHEContext(keyOptions?: PipelineKeyOptions, heOptions?: PipelineHEOptions): Promise<HEContext>;

  // Format conversion
  toBinary(input: Uint8Array | string | Record<string, unknown>, opts?: GenerateBinaryOptions): Uint8Array;
  toJSON(input: Uint8Array | string, opts?: GenerateJSONOptions): string;

  // Streaming
  pushStream(input: Uint8Array | string | Record<string, unknown>, opts?: PushStreamOptions): { count: number };
  getDispatcher(): StreamingDispatcher | null;

  // HE encryption
  encryptHE(input: string | Record<string, unknown>, opts?: EncryptHEOptions): Uint8Array;
  decryptHE(input: Uint8Array, opts?: DecryptHEOptions): string;
  getCompanionSchema(opts?: { fields?: string[] }): string;
  processForRecipient(input: string | Record<string, unknown>, recipientHEPubKey: Uint8Array, opts?: RecipientOptions): Uint8Array;

  // AES encryption
  encryptAES(input: string | Record<string, unknown>, encryption: AESEncryption): Uint8Array;
  decryptAES(data: Uint8Array, decryption: AESDecryption): string;

  // Code generation
  generateCode(language: TargetLanguage, opts?: GenerateCodeOptions): Record<string, string>;

  // Cleanup
  destroy(): void;

  // Accessors
  getRunner(): FlatcRunner;
  getHEContext(): HEContext | null;
  getKeyManager(): HDKeyManager | null;
}
