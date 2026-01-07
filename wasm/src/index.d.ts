/**
 * flatc-wasm - FlatBuffers compiler as a WebAssembly module
 *
 * This module exports:
 * - FlatcRunner: High-level wrapper with typed methods for schema operations
 * - createFlatcModule: Low-level factory for direct WASM module access
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
