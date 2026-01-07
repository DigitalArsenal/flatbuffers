/**
 * flatc-wasm.d.ts - Type definitions for FlatBuffers WASM compiler
 */

/** Schema export format */
export declare enum SchemaFormat {
  /** FlatBuffers IDL (.fbs) */
  FBS = 0,
  /** JSON Schema (.schema.json) */
  JSONSchema = 1
}

/** Code generation target language */
export declare enum Language {
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
  FBS = 12
}

/** Data format detected or converted */
export declare enum DataFormat {
  /** JSON text */
  JSON = 0,
  /** FlatBuffer binary */
  Binary = 1,
  /** Unknown format */
  Unknown = -1
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
 */
export declare class FlatcWasm {
  /**
   * Create a FlatcWasm instance from the loaded module
   */
  static create(moduleFactory: () => Promise<any>): Promise<FlatcWasm>;

  // Memory Helpers

  /** Allocate memory on the WASM heap */
  malloc(size: number): number;

  /** Free memory on the WASM heap */
  free(ptr: number): void;

  /** Get a view into WASM memory (zero-copy, becomes invalid after WASM calls) */
  getMemoryView(ptr: number, length: number): Uint8Array;

  /** Copy data from WASM memory (safe to keep) */
  copyFromMemory(ptr: number, length: number): Uint8Array;

  /** Write data to WASM heap, returns pointer (caller must free) */
  writeToMemory(data: Uint8Array): number;

  /** Write string to WASM heap as UTF-8, returns [pointer, byteLength] */
  writeStringToMemory(str: string): [number, number];

  /** Read null-terminated string from WASM memory */
  readString(ptr: number): string;

  // Utility Methods

  /** Get FlatBuffers version string */
  getVersion(): string;

  /** Get last error message */
  getLastError(): string;

  // Schema Management

  /** Add a schema from source (.fbs or .schema.json) */
  addSchema(name: string, source: string): number;

  /** Remove a schema by ID */
  removeSchema(schemaId: number): void;

  /** Get count of loaded schemas */
  getSchemaCount(): number;

  /** Get schema name by ID */
  getSchemaName(schemaId: number): string | null;

  /** List all loaded schemas */
  listSchemas(): SchemaInfo[];

  /** Export schema in specified format */
  exportSchema(schemaId: number, format: SchemaFormat): string;

  // Conversion Methods

  /** Convert JSON to FlatBuffer binary */
  jsonToBinary(schemaId: number, json: string): Uint8Array;

  /** Convert FlatBuffer binary to JSON */
  binaryToJson(schemaId: number, binary: Uint8Array): string;

  /** Detect the format of data */
  detectFormat(data: Uint8Array): DataFormat;

  /** Auto-detect format and convert */
  convert(schemaId: number, data: Uint8Array): ConversionResult;

  // Code Generation

  /** Generate code for a schema in the specified language */
  generateCode(schemaId: number, language: Language): string;

  /** Get list of supported languages as comma-separated string */
  getSupportedLanguages(): string;

  /** Get language ID from name */
  getLanguageId(name: string): number;

  // Streaming Support

  /** Create a streaming converter for processing large data */
  createStreamConverter(schemaId: number): StreamConverter;

  /** Create a native streaming converter (uses WASM-side buffer) */
  createNativeStreamConverter(schemaId: number): NativeStreamConverter;
}

/**
 * StreamConverter - Accumulates data for streaming conversion
 */
export declare class StreamConverter {
  constructor(flatc: FlatcWasm, schemaId: number);

  /** Write a chunk of data */
  write(chunk: Uint8Array): void;

  /** Finish streaming and convert accumulated data */
  finish(): ConversionResult;

  /** Reset the stream without converting */
  reset(): void;

  /** Get current accumulated size */
  readonly size: number;
}

/**
 * NativeStreamConverter - Uses WASM-side buffer for streaming
 */
export declare class NativeStreamConverter {
  constructor(flatc: FlatcWasm, schemaId: number);

  /** Write a chunk of data directly to WASM memory */
  write(chunk: Uint8Array): void;

  /** Finish streaming and convert accumulated data */
  finish(): ConversionResult;

  /** Reset the stream without converting */
  reset(): void;

  /** Get current accumulated size */
  readonly size: number;
}

export default FlatcWasm;
