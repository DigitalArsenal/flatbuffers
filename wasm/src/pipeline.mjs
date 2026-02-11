/**
 * FlatBufferPipeline - Unified API for FlatBuffers operations
 *
 * Single entrypoint to: load a schema, stream in JSON or FlatBuffers,
 * convert between formats, generate code, and produce HE-encrypted output
 * for a recipient whose keys are managed by hd-wallet-wasm.
 *
 * ```
 * User Input (JSON / FlatBuffer binary)
 *       │
 *       ▼
 * ┌─────────────────────────────────────────────────┐
 * │              FlatBufferPipeline                  │
 * │                                                 │
 * │  setSchema() → toBinary() / toJSON()            │
 * │  pushStream() → streaming dispatcher            │
 * │  encryptHE() / decryptHE() → HE per-field       │
 * │  encryptAES() / decryptAES() → existing AES     │
 * │  generateCode() → flatc codegen                 │
 * │  deriveHEContext() → HD wallet → HE keys        │
 * │  processForRecipient(recipientHEPubKey)          │
 * └──────────┬──────────┬──────────┬────────────────┘
 *            │          │          │
 *      FlatcRunner  StreamingDisp  HDKeyManager + HEContext
 * ```
 *
 * @example
 * ```js
 * const pipeline = await FlatBufferPipeline.create();
 * pipeline.setSchema({ contents: monsterSchema });
 *
 * // Convert JSON → binary
 * const binary = pipeline.toBinary('{"name":"Orc","hp":100}');
 *
 * // Convert binary → JSON
 * const json = pipeline.toJSON(binary);
 *
 * // Stream binary messages
 * pipeline.pushStream(binary, { fileId: 'MONS', messageSize: 64 });
 *
 * // HE encrypt specific fields
 * const encrypted = pipeline.encryptHE('{"name":"Orc","hp":100}', { fields: ['hp'] });
 *
 * pipeline.destroy();
 * ```
 */

import { FlatcRunner } from './runner.mjs';
import { StreamingDispatcher, createSizePrefixedMessage } from './streaming-dispatcher.mjs';
import { detectFormat, detectStringFormat } from './format-detector.mjs';
import { HEContext, initHEModule, getHEModule } from './he-context.mjs';
import { deriveHEContext as bridgeDeriveHEContext, getHEPublicBundle } from './he-key-bridge.mjs';
import {
  identifyHEFields,
  generateCompanionSchema,
  encryptFields,
  decryptFields,
  buildEncryptedBinary,
} from './he-field-encryptor.mjs';

/**
 * Normalize schema input to the { entry, files } format FlatcRunner expects.
 * Accepts:
 *   - { contents: string } → normalized to { entry, files }
 *   - { entry: string, files: Record<string, string> } → passed through
 *
 * @param {object} schemaInput
 * @returns {{ entry: string, files: Record<string, string>, _source: string }}
 */
function normalizeSchema(schemaInput) {
  if (schemaInput.entry && schemaInput.files) {
    // Already in FlatcRunner format
    const source = typeof schemaInput.files[schemaInput.entry] === 'string'
      ? schemaInput.files[schemaInput.entry]
      : null;
    return { ...schemaInput, _source: source };
  }

  if (schemaInput.contents) {
    const entry = '/pipeline_schema.fbs';
    return {
      entry,
      files: { [entry]: schemaInput.contents },
      _source: schemaInput.contents,
    };
  }

  throw new Error('Schema input must have either { contents } or { entry, files }');
}

/**
 * Unified FlatBufferPipeline orchestrating all subsystems.
 */
export class FlatBufferPipeline {
  #runner = null;
  #dispatcher = null;
  #schema = null;
  #schemaSource = null;
  #keyManager = null;
  #heContext = null;
  #companionSchema = null;
  #heFields = null;

  /**
   * Create a new pipeline instance.
   * Use the static `create()` factory instead of calling the constructor directly.
   *
   * @param {object} runner - Initialized FlatcRunner
   */
  constructor(runner) {
    this.#runner = runner;
  }

  /**
   * Create and initialize a new FlatBufferPipeline.
   *
   * @param {object} [options] - Initialization options
   * @param {object} [options.runnerOptions] - Options for FlatcRunner.init()
   * @param {boolean} [options.streaming=false] - Enable streaming dispatcher
   * @param {object} [options.streamingOptions] - Options for StreamingDispatcher
   * @param {object} [options.schema] - Schema to set immediately (SchemaInput)
   * @returns {Promise<FlatBufferPipeline>}
   */
  static async create(options = {}) {
    const runner = await FlatcRunner.init(options.runnerOptions);
    const pipeline = new FlatBufferPipeline(runner);

    if (options.streaming) {
      // StreamingDispatcher requires the WASM module for dispatcher exports
      const wasmModule = options.streamingOptions?.wasmModule || runner.Module;
      if (wasmModule && typeof wasmModule._dispatcher_init === 'function') {
        pipeline.#dispatcher = new StreamingDispatcher(wasmModule);
      }
      // If WASM dispatcher not available, dispatcher is created lazily on pushStream
    }

    if (options.schema) {
      pipeline.setSchema(options.schema);
    }

    return pipeline;
  }

  // =========================================================================
  // Schema management
  // =========================================================================

  /**
   * Set the schema for all operations.
   *
   * @param {object} schemaInput - Schema input ({ contents: string } or { path: string, contents: string })
   * @returns {FlatBufferPipeline} this (for chaining)
   */
  setSchema(schemaInput) {
    if (!schemaInput) {
      throw new Error('schemaInput is required');
    }

    const normalized = normalizeSchema(schemaInput);
    this.#schema = normalized;
    this.#schemaSource = normalized._source;

    // Reset cached companion schema and fields
    this.#companionSchema = null;
    this.#heFields = null;

    return this;
  }

  /**
   * Get the current schema source.
   * @returns {string|null}
   */
  getSchemaSource() {
    return this.#schemaSource;
  }

  // =========================================================================
  // Key management
  // =========================================================================

  /**
   * Attach an HD wallet key manager.
   *
   * @param {object} hdKeyManager - HDKeyManager instance
   * @returns {FlatBufferPipeline} this (for chaining)
   */
  setKeyManager(hdKeyManager) {
    this.#keyManager = hdKeyManager;
    return this;
  }

  /**
   * Set an HE context manually.
   *
   * @param {HEContext} heContext - HEContext instance
   * @returns {FlatBufferPipeline} this (for chaining)
   */
  setHEContext(heContext) {
    this.#heContext = heContext;
    return this;
  }

  /**
   * Derive an HE context from the attached HD wallet key manager.
   *
   * @param {object} [keyOptions] - Key derivation options (coinType, account, index)
   * @param {object} [heOptions] - HE options (polyDegree, hkdfFn)
   * @returns {Promise<HEContext>} The derived HE context (also stored internally)
   */
  async deriveHEContext(keyOptions = {}, heOptions = {}) {
    if (!this.#keyManager) {
      throw new Error('No key manager set. Call setKeyManager() first.');
    }

    const encryptionKey = this.#keyManager.deriveEncryptionKey(keyOptions);
    const ctx = await bridgeDeriveHEContext(encryptionKey, heOptions);
    this.#heContext = ctx;
    return ctx;
  }

  // =========================================================================
  // Format conversion
  // =========================================================================

  /**
   * Convert input to FlatBuffer binary. Auto-detects input format.
   *
   * @param {Uint8Array|string|object} input - JSON string, JSON object, or FlatBuffer binary
   * @param {object} [opts] - Options for generateBinary
   * @returns {Uint8Array} FlatBuffer binary
   */
  toBinary(input, opts = {}) {
    this.#requireSchema('toBinary');

    if (input instanceof Uint8Array) {
      const format = detectFormat(input);
      if (format === 'flatbuffer') {
        return input; // Already binary
      }
      // Assume JSON bytes
      const jsonStr = new TextDecoder().decode(input);
      return this.#runner.generateBinary(this.#schema, jsonStr, opts);
    }

    if (typeof input === 'object' && input !== null) {
      input = JSON.stringify(input);
    }

    if (typeof input === 'string') {
      return this.#runner.generateBinary(this.#schema, input, opts);
    }

    throw new Error('Input must be Uint8Array, string, or object');
  }

  /**
   * Convert input to JSON string. Auto-detects input format.
   *
   * @param {Uint8Array|string} input - FlatBuffer binary or JSON string
   * @param {object} [opts] - Options for generateJSON
   * @returns {string} JSON string
   */
  toJSON(input, opts = {}) {
    this.#requireSchema('toJSON');

    if (input instanceof Uint8Array) {
      const format = detectFormat(input);
      if (format === 'json') {
        return new TextDecoder().decode(input);
      }
      // Treat as FlatBuffer binary
      return this.#runner.generateJSON(
        this.#schema,
        { path: '/pipeline_input.bin', data: input },
        opts
      );
    }

    if (typeof input === 'string') {
      const format = detectStringFormat(input);
      if (format === 'json') {
        return input; // Already JSON
      }
    }

    throw new Error('Input must be Uint8Array or JSON string');
  }

  // =========================================================================
  // Streaming
  // =========================================================================

  /**
   * Push data into the streaming dispatcher.
   * JSON input is auto-converted to binary first.
   *
   * @param {Uint8Array|string|object} input - Input data
   * @param {object} [opts] - Streaming options
   * @param {string} [opts.fileId] - 4-char file identifier for type registration
   * @param {number} [opts.messageSize] - Fixed message size for type registration
   * @param {number} [opts.capacity] - Ring buffer capacity
   * @returns {{ count: number }} Push result with number of messages dispatched
   */
  pushStream(input, opts = {}) {
    if (!this.#dispatcher) {
      const wasmModule = this.#runner.Module;
      if (!wasmModule || typeof wasmModule._dispatcher_init !== 'function') {
        throw new Error('Streaming dispatcher requires WASM module with dispatcher exports');
      }
      this.#dispatcher = new StreamingDispatcher(wasmModule);
    }

    // Register type if fileId and messageSize provided
    if (opts.fileId && opts.messageSize) {
      try {
        this.#dispatcher.registerType(opts.fileId, opts.messageSize, opts.capacity);
      } catch (e) {
        // Type may already be registered, ignore
      }
    }

    // Convert to binary if needed
    let binary;
    if (input instanceof Uint8Array) {
      const format = detectFormat(input);
      if (format === 'json') {
        this.#requireSchema('pushStream (JSON auto-conversion)');
        const jsonStr = new TextDecoder().decode(input);
        binary = this.#runner.generateBinary(this.#schema, jsonStr);
      } else {
        binary = input;
      }
    } else if (typeof input === 'string' || (typeof input === 'object' && input !== null)) {
      this.#requireSchema('pushStream (JSON auto-conversion)');
      const jsonStr = typeof input === 'string' ? input : JSON.stringify(input);
      binary = this.#runner.generateBinary(this.#schema, jsonStr);
    } else {
      throw new Error('Input must be Uint8Array, string, or object');
    }

    // Create size-prefixed message if fileId is provided
    if (opts.fileId) {
      const msg = createSizePrefixedMessage(opts.fileId, binary);
      return this.#dispatcher.pushBytes(msg);
    }

    return this.#dispatcher.pushBytes(binary);
  }

  /**
   * Get the streaming dispatcher (for direct access to messages, stats, etc.).
   * @returns {StreamingDispatcher|null}
   */
  getDispatcher() {
    return this.#dispatcher;
  }

  // =========================================================================
  // HE encryption
  // =========================================================================

  /**
   * Encrypt input with per-field HE encryption, producing a FlatBuffer binary
   * conforming to the auto-generated companion schema.
   *
   * @param {string|object} input - JSON input data
   * @param {object} [opts] - Options
   * @param {string[]} [opts.fields] - Field names to encrypt (or use schema metadata)
   * @param {HEContext} [opts.heContext] - Override HE context
   * @param {object} [opts.binaryOptions] - Options for generateBinary
   * @returns {Uint8Array} FlatBuffer binary with encrypted ciphertext vectors
   */
  encryptHE(input, opts = {}) {
    this.#requireSchema('encryptHE');
    const heCtx = opts.heContext || this.#heContext;
    if (!heCtx) {
      throw new Error('No HE context available. Call setHEContext() or deriveHEContext() first.');
    }

    const data = typeof input === 'string' ? JSON.parse(input) : input;
    const fields = this.#getHEFields(opts.fields);
    const companion = this.#getCompanionSchema(fields);

    return buildEncryptedBinary(
      this.#runner, this.#schemaSource, companion, data, heCtx, fields, opts.binaryOptions
    );
  }

  /**
   * Decrypt an HE-encrypted FlatBuffer back to plaintext JSON.
   *
   * @param {Uint8Array} input - FlatBuffer binary with encrypted fields
   * @param {object} [opts] - Options
   * @param {string[]} [opts.fields] - Field names that are encrypted
   * @param {HEContext} [opts.heContext] - Override HE context (must be client context)
   * @returns {string} Decrypted JSON string
   */
  decryptHE(input, opts = {}) {
    this.#requireSchema('decryptHE');
    const heCtx = opts.heContext || this.#heContext;
    if (!heCtx || !heCtx.canDecrypt()) {
      throw new Error('Decryption requires a client HE context with secret key.');
    }

    const fields = this.#getHEFields(opts.fields);
    const companion = this.#getCompanionSchema(fields);

    // Convert binary to JSON using companion schema
    const companionSchema = normalizeSchema({ contents: companion });
    const encryptedJson = this.#runner.generateJSON(
      companionSchema,
      { path: '/pipeline_encrypted.bin', data: input }
    );
    const encryptedData = JSON.parse(encryptedJson);

    // Decrypt the fields
    const decryptedData = decryptFields(encryptedData, heCtx, fields);

    return JSON.stringify(decryptedData);
  }

  /**
   * Get the auto-generated companion schema for the current schema and fields.
   *
   * @param {object} [opts] - Options
   * @param {string[]} [opts.fields] - Field names to encrypt
   * @returns {string} Companion schema source
   */
  getCompanionSchema(opts = {}) {
    this.#requireSchema('getCompanionSchema');
    const fields = this.#getHEFields(opts.fields);
    return this.#getCompanionSchema(fields);
  }

  /**
   * Encrypt and package data for a specific recipient's HE public key.
   * Creates a server context from the recipient's public key and encrypts.
   *
   * @param {string|object} input - JSON input data
   * @param {Uint8Array} recipientHEPubKey - Recipient's HE public key
   * @param {object} [opts] - Options
   * @param {string[]} [opts.fields] - Field names to encrypt
   * @param {Uint8Array} [opts.relinKeys] - Recipient's relinearization keys
   * @returns {Uint8Array} FlatBuffer binary encrypted for recipient
   */
  processForRecipient(input, recipientHEPubKey, opts = {}) {
    this.#requireSchema('processForRecipient');

    const serverCtx = HEContext.createServer(recipientHEPubKey);
    try {
      if (opts.relinKeys) {
        serverCtx.setRelinKeys(opts.relinKeys);
      }

      return this.encryptHE(input, {
        ...opts,
        heContext: serverCtx,
      });
    } finally {
      serverCtx.destroy();
    }
  }

  // =========================================================================
  // AES encryption (delegates to FlatcRunner)
  // =========================================================================

  /**
   * Encrypt input using AES-256-CTR (existing FlatcRunner path).
   *
   * @param {string|object} input - JSON input data
   * @param {object} encryption - Encryption config { publicKey, config? }
   * @returns {Uint8Array} Encrypted FlatBuffer binary
   */
  encryptAES(input, encryption) {
    this.#requireSchema('encryptAES');

    const jsonStr = typeof input === 'string' ? input : JSON.stringify(input);

    return this.#runner.generateBinaryEncrypted(
      this.#schema,
      jsonStr,
      encryption
    );
  }

  /**
   * Decrypt AES-encrypted FlatBuffer binary.
   *
   * @param {Uint8Array} data - Encrypted FlatBuffer binary
   * @param {object} decryption - Decryption config { privateKey, config? }
   * @returns {string} Decrypted JSON string
   */
  decryptAES(data, decryption) {
    this.#requireSchema('decryptAES');

    return this.#runner.generateJSONDecrypted(
      this.#schema,
      { path: '/pipeline_encrypted.bin', data },
      decryption
    );
  }

  // =========================================================================
  // Code generation
  // =========================================================================

  /**
   * Generate code from the current schema.
   *
   * @param {string} language - Target language (cpp, ts, python, go, rust, java, csharp)
   * @param {object} [opts] - Code generation options
   * @returns {object} Generated code files
   */
  generateCode(language, opts = {}) {
    this.#requireSchema('generateCode');
    return this.#runner.generateCode(this.#schema, language, opts);
  }

  // =========================================================================
  // Cleanup
  // =========================================================================

  /**
   * Destroy the pipeline and clean up resources.
   * Destroys the HE context if one was created.
   */
  destroy() {
    if (this.#heContext) {
      this.#heContext.destroy();
      this.#heContext = null;
    }
    this.#dispatcher = null;
    this.#keyManager = null;
    this.#schema = null;
    this.#schemaSource = null;
    this.#companionSchema = null;
    this.#heFields = null;
  }

  // =========================================================================
  // Accessors
  // =========================================================================

  /** Get the underlying FlatcRunner. */
  getRunner() { return this.#runner; }

  /** Get the current HE context. */
  getHEContext() { return this.#heContext; }

  /** Get the current HD key manager. */
  getKeyManager() { return this.#keyManager; }

  // =========================================================================
  // Private helpers
  // =========================================================================

  #requireSchema(method) {
    if (!this.#schema) {
      throw new Error(`Schema required for ${method}. Call setSchema() first.`);
    }
  }

  #getHEFields(fieldNames) {
    if (!this.#heFields || fieldNames) {
      this.#heFields = identifyHEFields(this.#schemaSource, fieldNames);
    }
    return this.#heFields;
  }

  #getCompanionSchema(fields) {
    if (!this.#companionSchema) {
      this.#companionSchema = generateCompanionSchema(this.#schemaSource, fields);
    }
    return this.#companionSchema;
  }
}
