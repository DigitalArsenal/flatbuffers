/**
 * @module FlatcRunner
 *
 * Provides a high-level interface to run the FlatBuffers compiler (flatc) through WebAssembly.
 * Offers functionality for mounting files, generating binaries, JSON, and code from schemas.
 */

import createFlatcModule from "../dist/flatc-wasm.js";
import { generateAlignedCode as generateAligned } from "./aligned-codegen.mjs";

// =============================================================================
// Security Limits (VULN-002 fix)
// =============================================================================

/**
 * Maximum total size of all schema files combined (10 MB)
 * Prevents memory exhaustion attacks via large schemas
 */
const MAX_SCHEMA_TOTAL_SIZE = 10 * 1024 * 1024;

/**
 * Maximum number of files in a schema input
 * Prevents DoS via excessive file count
 */
const MAX_SCHEMA_FILES = 1000;

/**
 * Maximum depth of include directives
 * Prevents stack overflow and DoS via deeply nested includes
 */
const MAX_INCLUDE_DEPTH = 50;

/**
 * Maximum size of a single binary input (100 MB)
 * Prevents memory exhaustion via large binary files
 */
const MAX_BINARY_SIZE = 100 * 1024 * 1024;

/**
 * Minimum valid FlatBuffer size (must have at least root offset)
 */
const MIN_FLATBUFFER_SIZE = 4;

/**
 * Validates that a path is safe and doesn't contain path traversal attempts.
 * @param {string} path - The path to validate
 * @param {string} [context] - Context for error messages
 * @throws {Error} If the path contains traversal sequences or is invalid
 */
function validatePath(path, context = 'path') {
  if (typeof path !== 'string') {
    throw new Error(`Invalid ${context}: must be a string`);
  }
  if (path.length === 0) {
    throw new Error(`Invalid ${context}: cannot be empty`);
  }
  // Check for path traversal attempts
  const normalized = path.replace(/\\/g, '/');
  if (normalized.includes('/../') || normalized.startsWith('../') ||
      normalized.endsWith('/..') || normalized === '..' ||
      normalized.includes('/./') || normalized.startsWith('./')) {
    throw new Error(`Invalid ${context}: path traversal detected in "${path}"`);
  }
  // Check for null bytes (could be used to truncate paths)
  if (path.includes('\0')) {
    throw new Error(`Invalid ${context}: null byte detected`);
  }
  return path;
}

/**
 * Validates schema input structure with security limits.
 * @param {{ entry: string, files: Record<string, string|Uint8Array> }} schemaInput
 * @throws {Error} If the schema input is invalid or exceeds security limits
 */
function validateSchemaInput(schemaInput) {
  if (!schemaInput || typeof schemaInput !== 'object') {
    throw new Error('Schema input must be an object with entry and files properties');
  }
  if (typeof schemaInput.entry !== 'string' || schemaInput.entry.length === 0) {
    throw new Error('Schema input must have a non-empty entry path');
  }
  if (!schemaInput.files || typeof schemaInput.files !== 'object') {
    throw new Error('Schema input must have a files object');
  }

  validatePath(schemaInput.entry, 'schema entry');

  // Validate that entry exists in files
  if (!(schemaInput.entry in schemaInput.files)) {
    throw new Error(`Schema entry "${schemaInput.entry}" not found in files. Available: ${Object.keys(schemaInput.files).join(', ')}`);
  }

  const fileKeys = Object.keys(schemaInput.files);

  // VULN-002 FIX: Check file count limit
  if (fileKeys.length > MAX_SCHEMA_FILES) {
    throw new Error(`Schema input exceeds maximum file count (${MAX_SCHEMA_FILES})`);
  }

  // Validate all file paths and calculate total size
  let totalSize = 0;
  for (const filePath of fileKeys) {
    validatePath(filePath, 'schema file path');

    const content = schemaInput.files[filePath];
    const contentSize = typeof content === 'string' ? content.length : content.byteLength;
    totalSize += contentSize;

    // VULN-002 FIX: Check cumulative size limit
    if (totalSize > MAX_SCHEMA_TOTAL_SIZE) {
      throw new Error(`Schema input exceeds maximum total size (${MAX_SCHEMA_TOTAL_SIZE} bytes)`);
    }
  }

  // VULN-002 FIX: Check for circular includes and include depth
  validateIncludeDepth(schemaInput);
}

/**
 * Validates that schema includes don't exceed max depth and aren't circular.
 * @param {{ entry: string, files: Record<string, string|Uint8Array> }} schemaInput
 * @throws {Error} If includes are circular or too deep
 */
function validateIncludeDepth(schemaInput) {
  const { entry, files } = schemaInput;

  // Extract includes from a schema file
  function extractIncludes(content) {
    const includes = [];
    // Match: include "path"; or include 'path';
    const regex = /include\s+["']([^"']+)["']\s*;/g;
    let match;
    const contentStr = typeof content === 'string' ? content : new TextDecoder().decode(content);
    while ((match = regex.exec(contentStr)) !== null) {
      includes.push(match[1]);
    }
    return includes;
  }

  // Resolve include path relative to current file
  function resolveIncludePath(currentFile, includePath) {
    // If include is absolute (starts with /), use as-is
    if (includePath.startsWith('/')) {
      return includePath;
    }
    // Otherwise, resolve relative to current file's directory
    const lastSlash = currentFile.lastIndexOf('/');
    const dir = lastSlash > 0 ? currentFile.slice(0, lastSlash) : '';
    const resolved = dir ? `${dir}/${includePath}` : includePath;
    // Normalize path (remove ./ and resolve ../)
    return resolved.replace(/\/\.\//g, '/').replace(/[^/]+\/\.\.\//g, '');
  }

  // DFS to check include depth and cycles
  function checkIncludes(file, visited, depth) {
    if (depth > MAX_INCLUDE_DEPTH) {
      throw new Error(`Schema include depth exceeds maximum (${MAX_INCLUDE_DEPTH}). This may indicate circular includes or overly complex schema structure.`);
    }

    if (visited.has(file)) {
      throw new Error(`Circular include detected: "${file}" is included in a cycle. Circular includes are not allowed.`);
    }

    const content = files[file];
    if (!content) {
      // File not in provided files - might be resolved by flatc's include paths
      return;
    }

    visited.add(file);

    const includes = extractIncludes(content);
    for (const includePath of includes) {
      const resolvedPath = resolveIncludePath(file, includePath);
      checkIncludes(resolvedPath, new Set(visited), depth + 1);
    }
  }

  checkIncludes(entry, new Set(), 0);
}

/**
 * Validates a FlatBuffer binary for basic structural integrity.
 * This is a security check to prevent crashes from malformed input.
 *
 * VULN-003 FIX: Basic FlatBuffer format validation
 *
 * @param {Uint8Array} buffer - The binary data to validate
 * @throws {Error} If the binary is malformed or exceeds size limits
 */
function validateFlatBufferBinary(buffer) {
  if (!(buffer instanceof Uint8Array)) {
    throw new Error('Binary input must be a Uint8Array');
  }

  // Check size limits
  if (buffer.length > MAX_BINARY_SIZE) {
    throw new Error(`Binary input exceeds maximum size (${MAX_BINARY_SIZE} bytes)`);
  }

  if (buffer.length < MIN_FLATBUFFER_SIZE) {
    throw new Error(`Binary input too small: must be at least ${MIN_FLATBUFFER_SIZE} bytes`);
  }

  // Read root table offset (little-endian u32 at offset 0)
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  const rootOffset = view.getUint32(0, true);

  // Validate root offset points within the buffer
  // The root offset is the offset from the start of the buffer to the root table
  if (rootOffset >= buffer.length) {
    throw new Error(`Invalid FlatBuffer: root offset (${rootOffset}) points outside buffer (size: ${buffer.length})`);
  }

  // If buffer has a file identifier (bytes 4-7), it should be printable ASCII or null
  // File identifiers are optional but if present should be valid
  if (buffer.length >= 8) {
    const hasFileId = rootOffset >= 8; // File ID is stored at offset 4-7 if root is at 8+
    if (hasFileId) {
      for (let i = 4; i < 8; i++) {
        const byte = buffer[i];
        // Allow printable ASCII (32-126) or null (0)
        if (byte !== 0 && (byte < 32 || byte > 126)) {
          // Not a valid file identifier - this might be a size-prefixed buffer
          // or just data at this location, so we don't fail, just skip validation
          break;
        }
      }
    }
  }

  // Additional sanity check: if we can read the vtable offset from the root table,
  // verify it's within bounds
  if (rootOffset + 4 <= buffer.length) {
    const vtableOffsetSigned = view.getInt32(rootOffset, true);
    const vtablePos = rootOffset - vtableOffsetSigned;

    // vtable should be within buffer and before the root table
    if (vtablePos < 0 || vtablePos >= buffer.length) {
      throw new Error(`Invalid FlatBuffer: vtable position (${vtablePos}) is out of bounds`);
    }

    // Read vtable size (first 2 bytes of vtable)
    if (vtablePos + 2 <= buffer.length) {
      const vtableSize = view.getUint16(vtablePos, true);

      // vtable size should be reasonable (at least 4 bytes for size + table size fields)
      if (vtableSize < 4) {
        throw new Error(`Invalid FlatBuffer: vtable size (${vtableSize}) is too small`);
      }

      // vtable shouldn't extend past buffer
      if (vtablePos + vtableSize > buffer.length) {
        throw new Error(`Invalid FlatBuffer: vtable extends past buffer end`);
      }
    }
  }
}

/**
 * Computes include directories from a schema input tree.
 * @param {{ files: Record<string, string|Uint8Array> }} schemaInput
 * @returns {string[]}
 */
function getIncludeDirs(schemaInput) {
  const dirs = new Set();
  for (const filePath of Object.keys(schemaInput.files)) {
    const lastSlash = filePath.lastIndexOf("/");
    const dir = lastSlash > 0 ? filePath.slice(0, lastSlash) : "/";
    dirs.add(dir);
  }
  return Array.from(dirs);
}

/**
 * FlatcRunner - High-level wrapper for the flatc WebAssembly module.
 * Provides CLI-style access to all flatc functionality.
 */
/**
 * @typedef {Object} EmscriptenFS
 * @property {function(string): void} mkdir
 * @property {function(string): void} mkdirTree
 * @property {function(string, Uint8Array|string): void} writeFile
 * @property {function(string, {encoding?: string}=): string|Uint8Array} readFile
 * @property {function(string): string[]} readdir
 * @property {function(string): {mode: number}} stat
 * @property {function(number): boolean} isDir
 * @property {function(string): void} unlink
 * @property {function(string): void} rmdir
 */

/**
 * @typedef {Object} EmscriptenModule
 * @property {function(string[]): void} callMain
 * @property {EmscriptenFS} FS
 */

export class FlatcRunner {
  /** @type {EmscriptenModule | null} */
  Module = null;

  /** @type {string} */
  _stdout = "";

  /** @type {string} */
  _stderr = "";

  /** @type {{ entry: string, files: Record<string, string|Uint8Array> } | null} */
  _cachedSchema = null;

  /** @type {string[]} */
  _cachedIncludeDirs = [];

  /**
   * Create a FlatcRunner instance.
   * @param {EmscriptenModule | null} Module - The instantiated WebAssembly module.
   */
  constructor(Module) {
    this.Module = Module;
  }

  /**
   * Initialize a new FlatcRunner with a fresh WASM module.
   * @param {Object} [options={}] - Options passed to the module.
   * @returns {Promise<FlatcRunner>}
   */
  static async init(options = {}) {
    const runner = new FlatcRunner(null);
    const Module = await createFlatcModule({
      noExitRuntime: true,
      noInitialRun: true,
      print: (text) => (runner._stdout += text + "\n"),
      printErr: (text) => (runner._stderr += text + "\n"),
      ...options,
    });
    runner.Module = Module;
    return runner;
  }

  /**
   * Run flatc with the given command-line arguments.
   * @param {string[]} args - Arguments to pass to flatc.
   * @returns {{ code: number, stdout: string, stderr: string }}
   */
  runCommand(args) {
    this._stdout = "";
    this._stderr = "";
    let code = 0;
    try {
      // callMain may return an exit code directly or throw it depending on
      // Emscripten build settings. Capture both cases.
      const returnValue = this.Module.callMain(args);
      if (typeof returnValue === "number" && returnValue !== 0) {
        code = returnValue;
      }
    } catch (e) {
      if (typeof e === "number") {
        code = e;
      } else if (e && typeof e === "object" && "status" in e) {
        // Emscripten ExitStatus object
        code = e.status;
      } else {
        throw e;
      }
    }
    return {
      code,
      stdout: this._stdout.trim(),
      stderr: this._stderr.trim(),
    };
  }

  /**
   * Mount a single file into the virtual filesystem.
   * @param {string} path - The target path.
   * @param {string|Uint8Array} data - File contents.
   */
  mountFile(path, data) {
    const { FS } = this.Module;
    const dir = path.substring(0, path.lastIndexOf("/")) || "/";
    const parts = dir.split("/").filter(Boolean);
    let cur = "";
    for (const part of parts) {
      cur += "/" + part;
      try {
        FS.mkdir(cur);
      } catch (e) {
        // EEXIST (error code 20 in Emscripten) means directory already exists - that's OK
        if (e.errno !== 20) {
          throw e;
        }
      }
    }
    FS.writeFile(
      path,
      typeof data === "string" ? new TextEncoder().encode(data) : data
    );
  }

  /**
   * Mount multiple files into the virtual filesystem.
   * @param {{ path: string, data: string|Uint8Array }[]} files
   */
  mountFiles(files) {
    for (const f of files) {
      this.mountFile(f.path, f.data);
    }
  }

  /**
   * Read a file from the virtual filesystem.
   * @param {string} path - File path.
   * @param {{ encoding?: "utf8"|"binary"|null }} [options]
   * @returns {string|Uint8Array}
   */
  readFile(path, options = {}) {
    return this.Module.FS.readFile(path, options);
  }

  /**
   * List files in a directory.
   * @param {string} path - Directory path.
   * @returns {string[]}
   */
  readdir(path) {
    return this.Module.FS.readdir(path).filter((f) => f !== "." && f !== "..");
  }

  /**
   * Recursively list all files from a directory.
   * @param {string} path - Directory path.
   * @returns {string[]}
   */
  listAllFiles(path) {
    const result = [];
    const walk = (dir) => {
      const entries = this.Module.FS.readdir(dir).filter(
        (e) => e !== "." && e !== ".."
      );
      for (const entry of entries) {
        const fullPath = `${dir}/${entry}`;
        const stat = this.Module.FS.stat(fullPath);
        if (this.Module.FS.isDir(stat.mode)) {
          walk(fullPath);
        } else {
          result.push(fullPath);
        }
      }
    };
    walk(path);
    return result;
  }

  /**
   * Delete a file from the virtual filesystem.
   * @param {string} path - File path.
   * @param {boolean} [ignoreNotFound=true] - If true, don't throw if file doesn't exist
   */
  unlink(path, ignoreNotFound = true) {
    try {
      this.Module.FS.unlink(path);
    } catch (e) {
      // ENOENT (error code 44 in Emscripten) means file doesn't exist
      if (ignoreNotFound && e.errno === 44) {
        return;
      }
      throw e;
    }
  }

  /**
   * Remove a directory from the virtual filesystem.
   * @param {string} path - Directory path.
   * @param {boolean} [ignoreNotFound=true] - If true, don't throw if directory doesn't exist
   */
  rmdir(path, ignoreNotFound = true) {
    try {
      this.Module.FS.rmdir(path);
    } catch (e) {
      // ENOENT (error code 44 in Emscripten) means directory doesn't exist
      if (ignoreNotFound && e.errno === 44) {
        return;
      }
      throw e;
    }
  }

  /**
   * Generate FlatBuffer binary from JSON using a schema.
   * @param {{ entry: string, files: Record<string, string|Uint8Array> }} schemaInput
   * @param {string|Uint8Array} jsonInput - JSON data to convert.
   * @param {Object} [options={}]
   * @param {boolean} [options.unknownJson=true] - Allow unknown fields in JSON.
   * @param {boolean} [options.strictJson=false] - Require strict JSON conformance.
   * @returns {Uint8Array}
   */
  generateBinary(schemaInput, jsonInput, options = {}) {
    const outDir = `/out_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    const jsonPath = `/input_${Date.now()}.json`;

    this.Module.FS.mkdirTree(outDir);
    this._mountSchemaIfNeeded(schemaInput);

    this.mountFile(
      jsonPath,
      typeof jsonInput === "string"
        ? new TextEncoder().encode(jsonInput)
        : jsonInput
    );

    const args = [
      "--binary",
      ...(options.unknownJson !== false ? ["--unknown-json"] : []),
      ...(options.strictJson ? ["--strict-json"] : []),
      "-o",
      outDir,
      ...this._cachedIncludeDirs.flatMap((d) => ["-I", d]),
      schemaInput.entry,
      jsonPath,
    ];

    const result = this.runCommand(args);

    const cleanup = () => {
      this.unlink(jsonPath);
      try {
        const files = this.Module.FS.readdir(outDir);
        for (const f of files) {
          if (f !== "." && f !== "..") {
            this.unlink(`${outDir}/${f}`);
          }
        }
        this.rmdir(outDir);
      } catch {
        // ignore
      }
    };

    // Check for errors - flatc sometimes exits 0 but writes errors to stderr
    if (result.code !== 0 || result.stderr.includes("error:")) {
      cleanup();
      throw new Error(
        `flatc binary generation failed (exit ${result.code}):\n${result.stderr || result.stdout}`
      );
    }

    const files = this.Module.FS.readdir(outDir).filter(
      (f) => f !== "." && f !== ".."
    );

    if (files.length === 0) {
      cleanup();
      throw new Error(
        `flatc succeeded but no binary output found in ${outDir}`
      );
    }

    // flatc names output after input JSON file with .bin extension
    const binFile = files[0];
    const output = this.Module.FS.readFile(`${outDir}/${binFile}`);
    cleanup();
    return new Uint8Array(output);
  }

  /**
   * Generate JSON from FlatBuffer binary using a schema.
   * @param {{ entry: string, files: Record<string, string|Uint8Array> }} schemaInput
   * @param {{ path: string, data: Uint8Array }} binaryInput
   * @param {Object} [options={}]
   * @param {boolean} [options.strictJson=true] - Output strict JSON.
   * @param {boolean} [options.rawBinary=true] - Allow raw binary.
   * @param {boolean} [options.defaultsJson=false] - Include default values.
   * @param {"utf8"|null} [options.encoding="utf8"] - Output encoding.
   * @param {boolean} [options.skipValidation=false] - Skip FlatBuffer format validation.
   * @returns {string|Uint8Array}
   */
  generateJSON(schemaInput, binaryInput, options = {}) {
    // VULN-003 FIX: Validate binary input before processing
    if (!options.skipValidation) {
      validateFlatBufferBinary(binaryInput.data);
    }
    // Handle binary path - ensure it has an extension flatc recognizes
    const binaryPath = binaryInput.path.includes(".")
      ? binaryInput.path
      : binaryInput.path + ".bin";
    const outDir = `/out_${Date.now()}_${Math.random().toString(36).slice(2)}`;

    this.Module.FS.mkdirTree(outDir);
    this._mountSchemaIfNeeded(schemaInput);
    this.mountFile(binaryPath, binaryInput.data);

    const args = [
      "--json",
      ...(options.strictJson !== false ? ["--strict-json"] : []),
      ...(options.rawBinary !== false ? ["--raw-binary"] : []),
      ...(options.defaultsJson ? ["--defaults-json"] : []),
      "-o",
      outDir,
      ...this._cachedIncludeDirs.flatMap((d) => ["-I", d]),
      schemaInput.entry,
      "--",
      binaryPath,
    ];

    const result = this.runCommand(args);

    const cleanup = () => {
      this.unlink(binaryPath);
      try {
        const files = this.Module.FS.readdir(outDir);
        for (const f of files) {
          if (f !== "." && f !== "..") {
            this.unlink(`${outDir}/${f}`);
          }
        }
        this.rmdir(outDir);
      } catch {
        // ignore
      }
    };

    // Check for errors - flatc sometimes exits 0 but writes errors to stderr
    if (result.code !== 0 || result.stderr.includes("error:")) {
      cleanup();
      throw new Error(
        `flatc JSON generation failed (exit ${result.code}):\n${result.stderr || result.stdout}`
      );
    }

    // Find the output JSON file
    const files = this.Module.FS.readdir(outDir).filter(
      (f) => f !== "." && f !== ".."
    );

    if (files.length === 0) {
      cleanup();
      throw new Error(`flatc succeeded but no JSON output found in ${outDir}`);
    }

    const jsonFile = files[0];
    const encoding = options.encoding !== undefined ? options.encoding : "utf8";
    const output = this.Module.FS.readFile(`${outDir}/${jsonFile}`, { encoding });
    cleanup();
    return output;
  }

  /**
   * Generate source code from a schema.
   * @param {{ entry: string, files: Record<string, string|Uint8Array> }} schemaInput
   * @param {string} language - Target language (cpp, ts, python, etc.)
   * @param {Object} [options={}]
   * @returns {Record<string, string>} Map of filename to content.
   */
  generateCode(schemaInput, language, options = {}) {
    const outDir = `/out_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    this.Module.FS.mkdirTree(outDir);

    // Cleanup helper - defined early so it can be used in finally block
    const cleanupDir = (dir) => {
      try {
        const entries = this.Module.FS.readdir(dir).filter(
          (e) => e !== "." && e !== ".."
        );
        for (const entry of entries) {
          const fullPath = `${dir}/${entry}`;
          const stat = this.Module.FS.stat(fullPath);
          if (this.Module.FS.isDir(stat.mode)) {
            cleanupDir(fullPath);
          } else {
            this.unlink(fullPath);
          }
        }
        this.rmdir(dir);
      } catch {
        // ignore cleanup errors
      }
    };

    try {
      this._mountSchemaIfNeeded(schemaInput);

      const args = [`--${language}`, "-o", outDir];

      for (const dir of this._cachedIncludeDirs) {
        args.push("-I", dir);
      }

      // Code generation options
      if (options.genObjectApi) args.push("--gen-object-api");
      if (options.genOnefile) args.push("--gen-onefile");
      if (options.genMutable) args.push("--gen-mutable");
      if (options.genCompare) args.push("--gen-compare");
      if (options.genNameStrings) args.push("--gen-name-strings");
      if (options.reflectNames) args.push("--reflect-names");
      if (options.reflectTypes) args.push("--reflect-types");
      if (options.genJsonEmit) args.push("--gen-json-emit");
      if (options.noIncludes) args.push("--no-includes");
      if (options.keepPrefix) args.push("--keep-prefix");
      if (options.noWarnings) args.push("--no-warnings");
      if (options.genAll) args.push("--gen-all");

      // Language-specific options
      if (options.pythonTyping) args.push("--python-typing");
      if (options.tsFlexBuffers) args.push("--ts-flexbuffers");
      if (options.tsNoImportExt) args.push("--ts-no-import-ext");
      if (options.goModule) args.push("--go-module", options.goModule);
      if (options.goPackagePrefix) args.push("--go-package-prefix", options.goPackagePrefix);

      args.push(schemaInput.entry);

      const result = this.runCommand(args);

      // Check for errors - flatc sometimes exits 0 but writes errors to stderr
      if (result.code !== 0 || result.stderr.includes("error:")) {
        throw new Error(
          `flatc code generation failed (exit ${result.code}):\n${result.stderr || result.stdout}`
        );
      }

      // Collect output files
      const output = {};
      const walk = (dir, base = "") => {
        const entries = this.Module.FS.readdir(dir).filter(
          (e) => e !== "." && e !== ".."
        );
        for (const entry of entries) {
          const fullPath = `${dir}/${entry}`;
          const relPath = base ? `${base}/${entry}` : entry;
          const stat = this.Module.FS.stat(fullPath);
          if (this.Module.FS.isDir(stat.mode)) {
            walk(fullPath, relPath);
          } else {
            output[relPath] = this.Module.FS.readFile(fullPath, {
              encoding: "utf8",
            });
          }
        }
      };
      walk(outDir);

      return output;
    } finally {
      // Always cleanup outDir, even on error
      cleanupDir(outDir);
    }
  }

  /**
   * Export a schema to JSON Schema format.
   * @param {{ entry: string, files: Record<string, string|Uint8Array> }} schemaInput
   * @param {Object} [options={}]
   * @param {boolean} [options.includeXFlatbuffers=false] - Include x-flatbuffers metadata for lossless round-tripping.
   * @returns {string}
   */
  generateJsonSchema(schemaInput, options = {}) {
    const outDir = `/out_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    this.Module.FS.mkdirTree(outDir);

    const cleanupDir = (dir) => {
      try {
        const entries = this.Module.FS.readdir(dir).filter(
          (e) => e !== "." && e !== ".."
        );
        for (const entry of entries) {
          const fullPath = `${dir}/${entry}`;
          const stat = this.Module.FS.stat(fullPath);
          if (this.Module.FS.isDir(stat.mode)) {
            cleanupDir(fullPath);
          } else {
            this.unlink(fullPath);
          }
        }
        this.rmdir(dir);
      } catch {
        // ignore cleanup errors
      }
    };

    try {
      this._mountSchemaIfNeeded(schemaInput);

      const args = ["--jsonschema", "-o", outDir];

      if (options.includeXFlatbuffers) {
        args.push("--jsonschema-xflatbuffers");
      }

      for (const dir of this._cachedIncludeDirs) {
        args.push("-I", dir);
      }

      args.push(schemaInput.entry);

      const result = this.runCommand(args);

      if (result.code !== 0 || result.stderr.includes("error:")) {
        throw new Error(
          `flatc JSON Schema generation failed (exit ${result.code}):\n${result.stderr || result.stdout}`
        );
      }

      // Collect output files
      const files = this.Module.FS.readdir(outDir).filter(
        (f) => f !== "." && f !== ".."
      );

      if (files.length === 0) {
        throw new Error("No JSON Schema output generated");
      }

      return this.Module.FS.readFile(`${outDir}/${files[0]}`, {
        encoding: "utf8",
      });
    } finally {
      cleanupDir(outDir);
    }
  }

  /**
   * Generate aligned C++ header and TypeScript view classes for zero-copy WASM interop.
   *
   * This generates a simpler, fixed-size binary format from FlatBuffers schemas,
   * optimized for direct TypedArray views into WASM linear memory. Unlike standard
   * FlatBuffers, this format has no vtables or pointer offsets - just aligned structs.
   *
   * @param {{ entry: string, files: Record<string, string|Uint8Array> }} schemaInput - Schema files
   * @param {Object} [options={}] - Generation options
   * @param {boolean} [options.pragmaOnce=true] - Use #pragma once in C++ header
   * @param {boolean} [options.includeGuard=true] - Include traditional #ifndef guard
   * @returns {{ cpp: string, ts: string, layouts: Object }} Generated code and layout info
   *
   * @example
   * const flatc = await FlatcRunner.init();
   * const schema = {
   *   entry: 'game.fbs',
   *   files: {
   *     'game.fbs': `
   *       namespace Game;
   *       struct Vec3 { x:float; y:float; z:float; }
   *       table Player { id:uint; pos:Vec3; health:ushort; }
   *     `
   *   }
   * };
   * const { cpp, ts, layouts } = flatc.generateAlignedCode(schema);
   * // cpp: C++ header with aligned structs
   * // ts: TypeScript with DataView-based accessors
   * // layouts: computed sizes/offsets for each struct
   */
  generateAlignedCode(schemaInput, options = {}) {
    validateSchemaInput(schemaInput);

    // Get the schema content from the entry file
    const schemaContent = schemaInput.files[schemaInput.entry];
    if (typeof schemaContent !== 'string') {
      throw new Error('Schema content must be a string for aligned code generation');
    }

    return generateAligned(schemaContent, options);
  }

  /**
   * Get flatc help text.
   * @returns {string}
   */
  help() {
    return this.runCommand(["--help"]).stdout;
  }

  /**
   * Get flatc version.
   * @returns {string}
   */
  version() {
    return this.runCommand(["--version"]).stdout;
  }

  /**
   * Internal: Mount schema files if they've changed.
   * @param {{ entry: string, files: Record<string, string|Uint8Array> }} schemaInput
   * @throws {Error} If schema input is invalid or contains path traversal
   * @private
   */
  _mountSchemaIfNeeded(schemaInput) {
    validateSchemaInput(schemaInput);

    const schemaUnchanged =
      this._cachedSchema &&
      this._cachedSchema.entry === schemaInput.entry &&
      Object.keys(this._cachedSchema.files).length ===
        Object.keys(schemaInput.files).length &&
      Object.keys(this._cachedSchema.files).every(
        (key) =>
          schemaInput.files[key] &&
          this._cachedSchema.files[key] === schemaInput.files[key]
      );

    if (!schemaUnchanged) {
      this.mountFiles(
        Object.entries(schemaInput.files).map(([path, data]) => ({
          path,
          data: typeof data === "string" ? data : new Uint8Array(data),
        }))
      );
      this._cachedSchema = schemaInput;
      this._cachedIncludeDirs = getIncludeDirs(schemaInput);
    }
  }
}

export default FlatcRunner;
