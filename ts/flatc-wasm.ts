/**
 * flatc-wasm.ts - TypeScript wrapper for the FlatBuffers WASM compiler
 *
 * Provides a high-level API for:
 * - Schema management (add, remove, list, export)
 * - Two-way conversion (JSON ↔ FlatBuffer binary)
 * - Format auto-detection
 *
 * Uses direct memory access for performance and streaming support.
 */

// Emscripten module interface
interface EmscriptenModule {
  // Memory views
  HEAP8: Int8Array;
  HEAPU8: Uint8Array;
  HEAP16: Int16Array;
  HEAPU16: Uint16Array;
  HEAP32: Int32Array;
  HEAPU32: Uint32Array;
  HEAPF32: Float32Array;
  HEAPF64: Float64Array;

  // Memory management
  _malloc(size: number): number;
  _free(ptr: number): void;

  // Runtime methods
  ccall<R>(
    name: string,
    returnType: string | null,
    argTypes: string[],
    args: any[]
  ): R;
  cwrap<R>(
    name: string,
    returnType: string | null,
    argTypes: string[]
  ): (...args: any[]) => R;
  getValue(ptr: number, type: string): number;
  setValue(ptr: number, value: number, type: string): void;
  UTF8ToString(ptr: number, maxLength?: number): string;
  stringToUTF8(str: string, outPtr: number, maxLength: number): void;
  lengthBytesUTF8(str: string): number;

  // Embind exports
  getVersion(): string;
  getLastError(): string;
  createSchema(name: string, source: string): SchemaHandleEmbind;
  getAllSchemas(): VectorSchemaHandle;
  SchemaHandle: SchemaHandleConstructor;
}

interface SchemaHandleEmbind {
  id(): number;
  valid(): boolean;
  name(): string;
  release(): void;
  delete(): void;
}

interface VectorSchemaHandle {
  size(): number;
  get(index: number): SchemaHandleEmbind;
  delete(): void;
}

interface SchemaHandleConstructor {
  new (): SchemaHandleEmbind;
}

/** Schema export format */
export enum SchemaFormat {
  /** FlatBuffers IDL (.fbs) */
  FBS = 0,
  /** JSON Schema (.schema.json) */
  JSONSchema = 1,
}

/** Code generation target language */
export enum Language {
  CPP = 0,
  CSharp = 1,
  Dart = 2,
  Go = 3,
  Java = 4,
  Kotlin = 5,
  Python = 6,
  Rust = 7,
  Swift = 8,
  TypeScript = 9,
  PHP = 10,
  JSONSchema = 11,
  FBS = 12,
}

/** Data format detected or converted */
export enum DataFormat {
  /** JSON text */
  JSON = 0,
  /** FlatBuffer binary */
  Binary = 1,
  /** Unknown format */
  Unknown = -1,
}

/** Result of auto-detection conversion */
export interface ConversionResult {
  /** Format of the input data */
  inputFormat: DataFormat;
  /** Converted output data */
  data: Uint8Array;
}

/** Schema information */
export interface SchemaInfo {
  /** Schema ID */
  id: number;
  /** Schema name */
  name: string;
}

/**
 * FlatcWasm - Main class for interacting with the WASM flatc module
 *
 * Provides both high-level methods and low-level memory access for streaming.
 */
export class FlatcWasm {
  private module: EmscriptenModule;
  private textEncoder = new TextEncoder();
  private textDecoder = new TextDecoder();

  // Cached cwrap functions for performance
  private _wasm_schema_add!: (
    namePtr: number,
    nameLen: number,
    sourcePtr: number,
    sourceLen: number
  ) => number;
  private _wasm_schema_remove!: (id: number) => number;
  private _wasm_schema_count!: () => number;
  private _wasm_schema_get_name!: (id: number) => number;
  private _wasm_schema_export!: (
    id: number,
    format: number,
    outLenPtr: number
  ) => number;
  private _wasm_json_to_binary!: (
    schemaId: number,
    jsonPtr: number,
    jsonLen: number,
    outLenPtr: number
  ) => number;
  private _wasm_binary_to_json!: (
    schemaId: number,
    binaryPtr: number,
    binaryLen: number,
    outLenPtr: number
  ) => number;
  private _wasm_detect_format!: (dataPtr: number, dataLen: number) => number;
  private _wasm_get_last_error!: () => number;
  private _wasm_generate_code!: (
    schemaId: number,
    language: number,
    outLenPtr: number
  ) => number;
  private _wasm_get_supported_languages!: () => number;
  private _wasm_get_language_id!: (namePtr: number) => number;
  private _wasm_stream_reset!: () => void;
  private _wasm_stream_prepare!: (additionalBytes: number) => number;
  private _wasm_stream_commit!: (bytesWritten: number) => void;
  private _wasm_stream_size!: () => number;
  private _wasm_stream_convert!: (
    schemaId: number,
    outPtrPtr: number,
    outLenPtr: number
  ) => number;

  private constructor(module: EmscriptenModule) {
    this.module = module;
    this.initCwrapFunctions();
  }

  private initCwrapFunctions(): void {
    const m = this.module;

    this._wasm_schema_add = m.cwrap("wasm_schema_add", "number", [
      "number",
      "number",
      "number",
      "number",
    ]);
    this._wasm_schema_remove = m.cwrap("wasm_schema_remove", "number", [
      "number",
    ]);
    this._wasm_schema_count = m.cwrap("wasm_schema_count", "number", []);
    this._wasm_schema_get_name = m.cwrap("wasm_schema_get_name", "number", [
      "number",
    ]);
    this._wasm_schema_export = m.cwrap("wasm_schema_export", "number", [
      "number",
      "number",
      "number",
    ]);
    this._wasm_json_to_binary = m.cwrap("wasm_json_to_binary", "number", [
      "number",
      "number",
      "number",
      "number",
    ]);
    this._wasm_binary_to_json = m.cwrap("wasm_binary_to_json", "number", [
      "number",
      "number",
      "number",
      "number",
    ]);
    this._wasm_detect_format = m.cwrap("wasm_detect_format", "number", [
      "number",
      "number",
    ]);
    this._wasm_get_last_error = m.cwrap("wasm_get_last_error", "number", []);
    this._wasm_generate_code = m.cwrap("wasm_generate_code", "number", [
      "number",
      "number",
      "number",
    ]);
    this._wasm_get_supported_languages = m.cwrap(
      "wasm_get_supported_languages",
      "number",
      []
    );
    this._wasm_get_language_id = m.cwrap("wasm_get_language_id", "number", [
      "number",
    ]);
    this._wasm_stream_reset = m.cwrap("wasm_stream_reset", null, []);
    this._wasm_stream_prepare = m.cwrap("wasm_stream_prepare", "number", [
      "number",
    ]);
    this._wasm_stream_commit = m.cwrap("wasm_stream_commit", null, ["number"]);
    this._wasm_stream_size = m.cwrap("wasm_stream_size", "number", []);
    this._wasm_stream_convert = m.cwrap("wasm_stream_convert", "number", [
      "number",
      "number",
      "number",
    ]);
  }

  /**
   * Create a FlatcWasm instance from the loaded module
   */
  static async create(moduleFactory: () => Promise<EmscriptenModule>): Promise<FlatcWasm> {
    const module = await moduleFactory();
    return new FlatcWasm(module);
  }

  // ===========================================================================
  // Memory Helpers
  // ===========================================================================

  /**
   * Allocate memory on the WASM heap
   * @param size Number of bytes to allocate
   * @returns Pointer to allocated memory
   */
  malloc(size: number): number {
    return this.module._malloc(size);
  }

  /**
   * Free memory on the WASM heap
   * @param ptr Pointer to free
   */
  free(ptr: number): void {
    this.module._free(ptr);
  }

  /**
   * Get a view into WASM memory (zero-copy)
   * WARNING: This view becomes invalid after any WASM call that may reallocate
   * @param ptr Pointer to start of data
   * @param length Number of bytes
   */
  getMemoryView(ptr: number, length: number): Uint8Array {
    return new Uint8Array(this.module.HEAPU8.buffer, ptr, length);
  }

  /**
   * Copy data from WASM memory (safe to keep after WASM calls)
   * @param ptr Pointer to start of data
   * @param length Number of bytes
   */
  copyFromMemory(ptr: number, length: number): Uint8Array {
    return this.module.HEAPU8.slice(ptr, ptr + length);
  }

  /**
   * Write data to WASM heap
   * @param data Data to write
   * @returns Pointer to the data in WASM memory (caller must free)
   */
  writeToMemory(data: Uint8Array): number {
    const ptr = this.module._malloc(data.length);
    this.module.HEAPU8.set(data, ptr);
    return ptr;
  }

  /**
   * Write string to WASM heap as UTF-8
   * @param str String to write
   * @returns [pointer, byteLength] (caller must free pointer)
   */
  writeStringToMemory(str: string): [number, number] {
    const bytes = this.textEncoder.encode(str);
    const ptr = this.writeToMemory(bytes);
    return [ptr, bytes.length];
  }

  /**
   * Read null-terminated string from WASM memory
   * @param ptr Pointer to string
   */
  readString(ptr: number): string {
    return this.module.UTF8ToString(ptr);
  }

  // ===========================================================================
  // Utility Methods
  // ===========================================================================

  /** Get FlatBuffers version string */
  getVersion(): string {
    return this.module.getVersion();
  }

  /** Get last error message */
  getLastError(): string {
    const ptr = this._wasm_get_last_error();
    return ptr ? this.readString(ptr) : "";
  }

  // ===========================================================================
  // Schema Management
  // ===========================================================================

  /**
   * Add a schema from source
   * @param name Schema name (used for identification and format detection)
   * @param source Schema source (.fbs or .schema.json content)
   * @returns Schema ID on success
   * @throws Error if parsing fails
   */
  addSchema(name: string, source: string): number {
    const [namePtr, nameLen] = this.writeStringToMemory(name);
    const [sourcePtr, sourceLen] = this.writeStringToMemory(source);

    try {
      const id = this._wasm_schema_add(namePtr, nameLen, sourcePtr, sourceLen);
      if (id < 0) {
        throw new Error(this.getLastError() || "Failed to add schema");
      }
      return id;
    } finally {
      this.free(namePtr);
      this.free(sourcePtr);
    }
  }

  /**
   * Remove a schema by ID
   * @param schemaId Schema ID to remove
   */
  removeSchema(schemaId: number): void {
    const result = this._wasm_schema_remove(schemaId);
    if (result < 0) {
      throw new Error(this.getLastError() || "Schema not found");
    }
  }

  /**
   * Get count of loaded schemas
   */
  getSchemaCount(): number {
    return this._wasm_schema_count();
  }

  /**
   * Get schema name by ID
   * @param schemaId Schema ID
   * @returns Schema name or null if not found
   */
  getSchemaName(schemaId: number): string | null {
    const ptr = this._wasm_schema_get_name(schemaId);
    return ptr ? this.readString(ptr) : null;
  }

  /**
   * List all loaded schemas
   * @returns Array of schema info objects
   */
  listSchemas(): SchemaInfo[] {
    const count = this._wasm_schema_count();
    if (count === 0) return [];

    // Allocate buffer for IDs
    const idsPtr = this.malloc(count * 4);
    try {
      const actualCount = this.module.ccall(
        "wasm_schema_list",
        "number",
        ["number", "number"],
        [idsPtr, count]
      ) as number;

      const schemas: SchemaInfo[] = [];
      for (let i = 0; i < actualCount; i++) {
        const id = this.module.getValue(idsPtr + i * 4, "i32");
        const name = this.getSchemaName(id);
        if (name !== null) {
          schemas.push({ id, name });
        }
      }
      return schemas;
    } finally {
      this.free(idsPtr);
    }
  }

  /**
   * Export schema in specified format
   * @param schemaId Schema ID
   * @param format Export format
   * @returns Schema content as string
   */
  exportSchema(schemaId: number, format: SchemaFormat): string {
    const outLenPtr = this.malloc(4);
    try {
      const resultPtr = this._wasm_schema_export(schemaId, format, outLenPtr);
      if (!resultPtr) {
        throw new Error(this.getLastError() || "Failed to export schema");
      }

      const len = this.module.getValue(outLenPtr, "i32");
      const data = this.copyFromMemory(resultPtr, len);
      return this.textDecoder.decode(data);
    } finally {
      this.free(outLenPtr);
    }
  }

  // ===========================================================================
  // Conversion Methods
  // ===========================================================================

  /**
   * Convert JSON to FlatBuffer binary
   * @param schemaId Schema ID to use for conversion
   * @param json JSON string
   * @returns FlatBuffer binary data
   */
  jsonToBinary(schemaId: number, json: string): Uint8Array {
    const [jsonPtr, jsonLen] = this.writeStringToMemory(json);
    const outLenPtr = this.malloc(4);

    try {
      const resultPtr = this._wasm_json_to_binary(
        schemaId,
        jsonPtr,
        jsonLen,
        outLenPtr
      );
      if (!resultPtr) {
        throw new Error(this.getLastError() || "JSON to binary conversion failed");
      }

      const len = this.module.getValue(outLenPtr, "i32");
      return this.copyFromMemory(resultPtr, len);
    } finally {
      this.free(jsonPtr);
      this.free(outLenPtr);
    }
  }

  /**
   * Convert FlatBuffer binary to JSON
   * @param schemaId Schema ID to use for conversion
   * @param binary FlatBuffer binary data
   * @returns JSON string
   */
  binaryToJson(schemaId: number, binary: Uint8Array): string {
    const binaryPtr = this.writeToMemory(binary);
    const outLenPtr = this.malloc(4);

    try {
      const resultPtr = this._wasm_binary_to_json(
        schemaId,
        binaryPtr,
        binary.length,
        outLenPtr
      );
      if (!resultPtr) {
        throw new Error(this.getLastError() || "Binary to JSON conversion failed");
      }

      const len = this.module.getValue(outLenPtr, "i32");
      const data = this.copyFromMemory(resultPtr, len);
      return this.textDecoder.decode(data);
    } finally {
      this.free(binaryPtr);
      this.free(outLenPtr);
    }
  }

  /**
   * Detect the format of data
   * @param data Data to analyze
   * @returns Detected format
   */
  detectFormat(data: Uint8Array): DataFormat {
    const dataPtr = this.writeToMemory(data);
    try {
      return this._wasm_detect_format(dataPtr, data.length) as DataFormat;
    } finally {
      this.free(dataPtr);
    }
  }

  /**
   * Auto-detect format and convert
   * @param schemaId Schema ID to use
   * @param data Input data (JSON string as bytes, or FlatBuffer binary)
   * @returns Conversion result with input format and converted data
   */
  convert(schemaId: number, data: Uint8Array): ConversionResult {
    const dataPtr = this.writeToMemory(data);
    const outPtrPtr = this.malloc(4);
    const outLenPtr = this.malloc(4);

    try {
      const inputFormat = this.module.ccall<number>(
        "wasm_convert_auto",
        "number",
        ["number", "number", "number", "number", "number"],
        [schemaId, dataPtr, data.length, outPtrPtr, outLenPtr]
      );

      if (inputFormat < 0) {
        throw new Error(this.getLastError() || "Conversion failed");
      }

      const outPtr = this.module.getValue(outPtrPtr, "i32");
      const outLen = this.module.getValue(outLenPtr, "i32");

      return {
        inputFormat: inputFormat as DataFormat,
        data: this.copyFromMemory(outPtr, outLen),
      };
    } finally {
      this.free(dataPtr);
      this.free(outPtrPtr);
      this.free(outLenPtr);
    }
  }

  // ===========================================================================
  // Code Generation
  // ===========================================================================

  /**
   * Generate code for a schema in the specified language
   * @param schemaId Schema ID
   * @param language Target language
   * @returns Generated code as string
   */
  generateCode(schemaId: number, language: Language): string {
    const outLenPtr = this.malloc(4);
    try {
      const resultPtr = this._wasm_generate_code(schemaId, language, outLenPtr);
      if (!resultPtr) {
        throw new Error(this.getLastError() || "Code generation failed");
      }

      const len = this.module.getValue(outLenPtr, "i32");
      const data = this.copyFromMemory(resultPtr, len);
      return this.textDecoder.decode(data);
    } finally {
      this.free(outLenPtr);
    }
  }

  /**
   * Get list of supported languages as comma-separated string
   */
  getSupportedLanguages(): string {
    const ptr = this._wasm_get_supported_languages();
    return this.readString(ptr);
  }

  /**
   * Get language ID from name
   * @param name Language name (e.g., "cpp", "typescript", "python")
   * @returns Language ID or -1 if unknown
   */
  getLanguageId(name: string): number {
    const [namePtr] = this.writeStringToMemory(name + "\0"); // Null terminate
    try {
      return this._wasm_get_language_id(namePtr);
    } finally {
      this.free(namePtr);
    }
  }

  // ===========================================================================
  // Streaming Support
  // ===========================================================================

  /**
   * Create a streaming converter for processing large data
   * @param schemaId Schema ID to use
   * @returns StreamConverter instance
   */
  createStreamConverter(schemaId: number): StreamConverter {
    return new StreamConverter(this, schemaId);
  }

  /**
   * Create a native streaming converter (uses WASM-side buffer)
   * More efficient for very large data as it avoids JS-side accumulation
   * @param schemaId Schema ID to use
   * @returns NativeStreamConverter instance
   */
  createNativeStreamConverter(schemaId: number): NativeStreamConverter {
    return new NativeStreamConverter(this, schemaId);
  }

  // ===========================================================================
  // Embind Object API (alternative higher-level API)
  // ===========================================================================

  /**
   * Create a schema using Embind (returns a handle object)
   * This is an alternative to addSchema() that returns a handle
   * which can be used for automatic cleanup with release()
   */
  createSchemaHandle(name: string, source: string): SchemaHandleEmbind {
    return this.module.createSchema(name, source);
  }

  /**
   * Get all schemas as Embind handles
   */
  getAllSchemaHandles(): SchemaHandleEmbind[] {
    const vec = this.module.getAllSchemas();
    const handles: SchemaHandleEmbind[] = [];
    for (let i = 0; i < vec.size(); i++) {
      handles.push(vec.get(i));
    }
    vec.delete();
    return handles;
  }
}

/**
 * StreamConverter - Accumulates data for streaming conversion
 *
 * Usage:
 *   const stream = flatc.createStreamConverter(schemaId);
 *   stream.write(chunk1);
 *   stream.write(chunk2);
 *   const result = stream.finish();
 */
export class StreamConverter {
  private flatc: FlatcWasm;
  private schemaId: number;
  private chunks: Uint8Array[] = [];
  private totalSize = 0;

  constructor(flatc: FlatcWasm, schemaId: number) {
    this.flatc = flatc;
    this.schemaId = schemaId;
  }

  /**
   * Write a chunk of data
   * @param chunk Data chunk to accumulate
   */
  write(chunk: Uint8Array): void {
    this.chunks.push(chunk);
    this.totalSize += chunk.length;
  }

  /**
   * Finish streaming and convert accumulated data
   * @returns Conversion result
   */
  finish(): ConversionResult {
    // Combine all chunks
    const combined = new Uint8Array(this.totalSize);
    let offset = 0;
    for (const chunk of this.chunks) {
      combined.set(chunk, offset);
      offset += chunk.length;
    }

    // Reset state
    this.chunks = [];
    this.totalSize = 0;

    // Convert
    return this.flatc.convert(this.schemaId, combined);
  }

  /**
   * Reset the stream without converting
   */
  reset(): void {
    this.chunks = [];
    this.totalSize = 0;
  }

  /**
   * Get current accumulated size
   */
  get size(): number {
    return this.totalSize;
  }
}

/**
 * NativeStreamConverter - Uses WASM-side buffer for streaming
 *
 * More efficient for very large data as it writes directly to WASM memory
 * and avoids accumulating in JS. Uses the WASM module's internal stream buffer.
 *
 * Note: Only one NativeStreamConverter can be active at a time per module,
 * as they share the same internal buffer.
 *
 * Usage:
 *   const stream = flatc.createNativeStreamConverter(schemaId);
 *   stream.write(chunk1);
 *   stream.write(chunk2);
 *   const result = stream.finish();
 */
export class NativeStreamConverter {
  private flatc: FlatcWasm;
  private schemaId: number;
  private _wasm_stream_reset: () => void;
  private _wasm_stream_prepare: (additionalBytes: number) => number;
  private _wasm_stream_commit: (bytesWritten: number) => void;
  private _wasm_stream_size: () => number;
  private _wasm_stream_convert: (
    schemaId: number,
    outPtrPtr: number,
    outLenPtr: number
  ) => number;

  constructor(flatc: FlatcWasm, schemaId: number) {
    this.flatc = flatc;
    this.schemaId = schemaId;

    // Get the wrapped functions from the module
    const m = (flatc as any).module;
    this._wasm_stream_reset = m.cwrap("wasm_stream_reset", null, []);
    this._wasm_stream_prepare = m.cwrap("wasm_stream_prepare", "number", [
      "number",
    ]);
    this._wasm_stream_commit = m.cwrap("wasm_stream_commit", null, ["number"]);
    this._wasm_stream_size = m.cwrap("wasm_stream_size", "number", []);
    this._wasm_stream_convert = m.cwrap("wasm_stream_convert", "number", [
      "number",
      "number",
      "number",
    ]);

    // Reset the stream buffer
    this._wasm_stream_reset();
  }

  /**
   * Write a chunk of data directly to WASM memory
   * @param chunk Data chunk to write
   */
  write(chunk: Uint8Array): void {
    // Get pointer to write position
    const writePtr = this._wasm_stream_prepare(chunk.length);

    // Write directly to WASM heap
    const m = (this.flatc as any).module;
    m.HEAPU8.set(chunk, writePtr);

    // Confirm the write
    this._wasm_stream_commit(chunk.length);
  }

  /**
   * Finish streaming and convert accumulated data
   * @returns Conversion result
   */
  finish(): ConversionResult {
    const outPtrPtr = this.flatc.malloc(4);
    const outLenPtr = this.flatc.malloc(4);

    try {
      const inputFormat = this._wasm_stream_convert(
        this.schemaId,
        outPtrPtr,
        outLenPtr
      );

      if (inputFormat < 0) {
        throw new Error(
          this.flatc.getLastError() || "Stream conversion failed"
        );
      }

      const m = (this.flatc as any).module;
      const outPtr = m.getValue(outPtrPtr, "i32");
      const outLen = m.getValue(outLenPtr, "i32");

      return {
        inputFormat: inputFormat as DataFormat,
        data: this.flatc.copyFromMemory(outPtr, outLen),
      };
    } finally {
      this.flatc.free(outPtrPtr);
      this.flatc.free(outLenPtr);
      // Reset for next use
      this._wasm_stream_reset();
    }
  }

  /**
   * Reset the stream without converting
   */
  reset(): void {
    this._wasm_stream_reset();
  }

  /**
   * Get current accumulated size
   */
  get size(): number {
    return this._wasm_stream_size();
  }
}

// Default export for convenient importing
export default FlatcWasm;
