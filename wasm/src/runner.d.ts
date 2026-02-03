/**
 * Type definitions for FlatcRunner - the flatc WebAssembly CLI wrapper
 */

/**
 * Schema input tree for flatc operations.
 * Files are provided as a map from virtual paths to contents.
 */
export interface SchemaInput {
  /** Entry point schema file path (must exist in files) */
  entry: string;
  /** Map of virtual file paths to their contents */
  files: Record<string, string | Uint8Array>;
}

/**
 * Binary input for conversion operations.
 */
export interface BinaryInput {
  /** Virtual path for the binary file */
  path: string;
  /** Binary data */
  data: Uint8Array;
}

/**
 * Result of running a flatc command.
 */
export interface CommandResult {
  /** Exit code (0 = success) */
  code: number;
  /** Standard output */
  stdout: string;
  /** Standard error */
  stderr: string;
}

/**
 * Options for binary generation.
 */
export interface GenerateBinaryOptions {
  /** Allow unknown fields in JSON (default: true) */
  unknownJson?: boolean;
  /** Require strict JSON conformance (default: false) */
  strictJson?: boolean;
  /** Include 4-byte size prefix before the buffer (default: true) */
  sizePrefix?: boolean;
  /** Include file identifier in the buffer (default: true, uses schema's file_identifier) */
  fileIdentifier?: boolean;
}

/**
 * Options for JSON generation.
 */
export interface GenerateJSONOptions {
  /** Output strict JSON (default: true) */
  strictJson?: boolean;
  /** Allow raw binary input (default: true) */
  rawBinary?: boolean;
  /** Include default values in output (default: false) */
  defaultsJson?: boolean;
  /** Output encoding (default: "utf8") */
  encoding?: "utf8" | null;
  /** Skip FlatBuffer format validation (default: false) - use with caution */
  skipValidation?: boolean;
}

// =============================================================================
// Security Limits
// =============================================================================

/**
 * Maximum total size of all schema files combined (10 MB)
 */
export declare const MAX_SCHEMA_TOTAL_SIZE: number;

/**
 * Maximum number of files in a schema input
 */
export declare const MAX_SCHEMA_FILES: number;

/**
 * Maximum depth of include directives
 */
export declare const MAX_INCLUDE_DEPTH: number;

/**
 * Maximum size of a single binary input (100 MB)
 */
export declare const MAX_BINARY_SIZE: number;

/**
 * Options for code generation.
 */
export interface GenerateCodeOptions {
  // General options
  /** Generate object-based API in addition to struct/table API */
  genObjectApi?: boolean;
  /** Generate all code in a single file */
  genOnefile?: boolean;
  /** Generate mutable accessors */
  genMutable?: boolean;
  /** Generate comparison operators */
  genCompare?: boolean;
  /** Generate name strings for enums */
  genNameStrings?: boolean;
  /** Add reflection data for names */
  reflectNames?: boolean;
  /** Add reflection data for types */
  reflectTypes?: boolean;
  /** Generate JSON emit helpers */
  genJsonEmit?: boolean;
  /** Don't generate include statements */
  noIncludes?: boolean;
  /** Keep original prefix from schema */
  keepPrefix?: boolean;
  /** Suppress warnings */
  noWarnings?: boolean;
  /** Generate code for all schemas, not just the entry point */
  genAll?: boolean;
  /** Preserve field name casing from schema (don't convert to language convention) */
  preserveCase?: boolean;
  /** Don't prefix enum values with enum type name */
  noPrefix?: boolean;
  /** Use C++11 scoped enums (enum class) instead of plain enums */
  scopedEnums?: boolean;
  /** Add Clang _Nullable/_Nonnull annotations (C++/ObjC) */
  genNullable?: boolean;

  // Language-specific options
  /** Python: Generate type hints */
  pythonTyping?: boolean;
  /** TypeScript: Include FlexBuffers support */
  tsFlexBuffers?: boolean;
  /** TypeScript: Don't add .js extension to imports */
  tsNoImportExt?: boolean;
  /** TypeScript: Omit namespace entrypoint file */
  tsOmitEntrypoint?: boolean;
  /** Go: Module path for generated code */
  goModule?: string;
  /** Go: Package prefix */
  goPackagePrefix?: string;
  /** Rust: Implement serde::Serialize trait */
  rustSerialize?: boolean;
  /** Rust: Generate mod.rs module root file */
  rustModuleRootFile?: boolean;
  /** Java: Add package prefix to generated code */
  javaPackagePrefix?: string;
  /** C#: Add global:: prefix to type references */
  csGlobalAlias?: boolean;
  /** Kotlin: Add @JvmStatic annotation to companion object methods */
  genJvmStatic?: boolean;
}

/**
 * Supported target languages for code generation.
 */
export type TargetLanguage =
  | "cpp"
  | "csharp"
  | "dart"
  | "go"
  | "java"
  | "json"
  | "jsonschema"
  | "kotlin"
  | "kotlin-kmp"
  | "lobster"
  | "lua"
  | "nim"
  | "php"
  | "python"
  | "rust"
  | "swift"
  | "ts";

/**
 * Options for FlatcRunner initialization.
 */
export interface FlatcRunnerOptions {
  /** Custom print function for stdout */
  print?: (text: string) => void;
  /** Custom print function for stderr */
  printErr?: (text: string) => void;
  /** Additional options passed to the WASM module */
  [key: string]: unknown;
}

/**
 * FlatcRunner - High-level wrapper for the flatc WebAssembly module.
 * Provides CLI-style access to all flatc functionality.
 */
export declare class FlatcRunner {
  /** The underlying Emscripten module */
  Module: EmscriptenModule | null;

  /**
   * Create a FlatcRunner with an existing module.
   * @param Module - The instantiated WebAssembly module.
   */
  constructor(Module: EmscriptenModule | null);

  /**
   * Initialize a new FlatcRunner with a fresh WASM module.
   * @param options - Options passed to the module.
   */
  static init(options?: FlatcRunnerOptions): Promise<FlatcRunner>;

  /**
   * Run flatc with the given command-line arguments.
   * This is the low-level CLI interface - prefer the typed methods below.
   * @param args - Arguments to pass to flatc.
   */
  runCommand(args: string[]): CommandResult;

  /**
   * Mount a single file into the virtual filesystem.
   * @param path - The target path.
   * @param data - File contents.
   */
  mountFile(path: string, data: string | Uint8Array): void;

  /**
   * Mount multiple files into the virtual filesystem.
   * @param files - Array of files to mount.
   */
  mountFiles(files: Array<{ path: string; data: string | Uint8Array }>): void;

  /**
   * Read a file from the virtual filesystem.
   * @param path - File path.
   * @param options - Read options.
   */
  readFile(path: string, options?: { encoding?: "utf8" | "binary" | null }): string | Uint8Array;

  /**
   * List files in a directory.
   * @param path - Directory path.
   */
  readdir(path: string): string[];

  /**
   * Recursively list all files from a directory.
   * @param path - Directory path.
   */
  listAllFiles(path: string): string[];

  /**
   * Delete a file from the virtual filesystem.
   * @param path - File path.
   */
  unlink(path: string): void;

  /**
   * Remove a directory from the virtual filesystem.
   * @param path - Directory path.
   */
  rmdir(path: string): void;

  /**
   * Generate FlatBuffer binary from JSON using a schema.
   * @param schemaInput - Schema files with entry point.
   * @param jsonInput - JSON data to convert.
   * @param options - Generation options.
   */
  generateBinary(
    schemaInput: SchemaInput,
    jsonInput: string | Uint8Array,
    options?: GenerateBinaryOptions
  ): Uint8Array;

  /**
   * Generate JSON from FlatBuffer binary using a schema.
   * @param schemaInput - Schema files with entry point.
   * @param binaryInput - Binary data with path.
   * @param options - Generation options.
   */
  generateJSON(
    schemaInput: SchemaInput,
    binaryInput: BinaryInput,
    options?: GenerateJSONOptions
  ): string;

  /**
   * Generate JSON from FlatBuffer binary (returns Uint8Array).
   * @param schemaInput - Schema files with entry point.
   * @param binaryInput - Binary data with path.
   * @param options - Generation options with encoding: null.
   */
  generateJSON(
    schemaInput: SchemaInput,
    binaryInput: BinaryInput,
    options: GenerateJSONOptions & { encoding: null }
  ): Uint8Array;

  /**
   * Generate source code from a schema.
   * @param schemaInput - Schema files with entry point.
   * @param language - Target language.
   * @param options - Code generation options.
   * @returns Map of filename to content.
   */
  generateCode(
    schemaInput: SchemaInput,
    language: TargetLanguage,
    options?: GenerateCodeOptions
  ): Record<string, string>;

  /**
   * Export a schema to JSON Schema format.
   * @param schemaInput - Schema files with entry point.
   */
  generateJsonSchema(schemaInput: SchemaInput): string;

  /**
   * Get flatc help text.
   */
  help(): string;

  /**
   * Get flatc version.
   */
  version(): string;
}

/**
 * Emscripten module interface (subset used by FlatcRunner).
 */
export interface EmscriptenModule {
  callMain(args: string[]): number;
  FS: EmscriptenFS;
  [key: string]: unknown;
}

/**
 * Emscripten filesystem interface (subset used by FlatcRunner).
 */
export interface EmscriptenFS {
  mkdir(path: string): void;
  mkdirTree(path: string): void;
  writeFile(path: string, data: string | Uint8Array): void;
  readFile(path: string, options?: { encoding?: string | null }): string | Uint8Array;
  readdir(path: string): string[];
  unlink(path: string): void;
  rmdir(path: string): void;
  stat(path: string): { mode: number };
  isDir(mode: number): boolean;
}

export default FlatcRunner;
