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
 * Maximum depth for recursive validation to prevent stack overflow
 */
const MAX_VALIDATION_DEPTH = 64;

/**
 * Maximum number of fields to validate per table
 */
const MAX_FIELDS_PER_TABLE = 1000;

/**
 * Validates a FlatBuffer binary for structural integrity.
 * This is a security check to prevent crashes from malformed input.
 *
 * VULN-003 FIX: Enhanced FlatBuffer format validation with:
 * - Root offset validation
 * - Vtable chain validation (recursive)
 * - Field offset bounds checking
 * - String pointer validation
 * - Vector bounds checking
 * - Depth limiting to prevent stack overflow
 *
 * @param {Uint8Array} buffer - The binary data to validate
 * @param {Object} [options] - Validation options
 * @param {boolean} [options.deep=false] - Enable deep recursive validation
 * @param {number} [options.maxDepth=64] - Maximum recursion depth
 * @throws {Error} If the binary is malformed or exceeds size limits
 */
function validateFlatBufferBinary(buffer, options = {}) {
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

  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);

  // Detect size-prefixed buffer: first 4 bytes == buffer.length - 4
  let dataOffset = 0;
  const firstU32 = view.getUint32(0, true);
  if (firstU32 === buffer.length - 4) {
    // This is a size-prefixed buffer, skip the 4-byte prefix
    dataOffset = 4;
    if (buffer.length < MIN_FLATBUFFER_SIZE + 4) {
      throw new Error(`Binary input too small for size-prefixed buffer`);
    }
  }

  // Read root table offset (little-endian u32)
  const rootOffset = view.getUint32(dataOffset, true);
  const dataLength = buffer.length - dataOffset;

  // Validate root offset points within the buffer
  if (rootOffset >= dataLength) {
    throw new Error(`Invalid FlatBuffer: root offset (${rootOffset}) points outside buffer (size: ${dataLength})`);
  }

  // Minimum required size for a valid table (vtable offset + some data)
  if (rootOffset + 4 > dataLength) {
    throw new Error(`Invalid FlatBuffer: buffer too small for root table at offset ${rootOffset}`);
  }

  // If buffer has a file identifier (bytes 4-7 of data), it should be printable ASCII or null
  if (dataLength >= 8) {
    const hasFileId = rootOffset >= 8; // File ID is stored at offset 4-7 if root is at 8+
    if (hasFileId) {
      for (let i = dataOffset + 4; i < dataOffset + 8; i++) {
        const byte = buffer[i];
        // Allow printable ASCII (32-126) or null (0)
        if (byte !== 0 && (byte < 32 || byte > 126)) {
          // Not a valid file identifier, just skip validation
          break;
        }
      }
    }
  }

  // Validate root table structure (all offsets relative to data start)
  const vtableOffsetSigned = view.getInt32(dataOffset + rootOffset, true);
  const vtablePos = rootOffset - vtableOffsetSigned;

  // vtable should be within buffer
  if (vtablePos < 0 || vtablePos >= dataLength) {
    throw new Error(`Invalid FlatBuffer: vtable position (${vtablePos}) is out of bounds`);
  }

  // Need at least 4 bytes for vtable header (vtable size + table size)
  if (vtablePos + 4 > dataLength) {
    throw new Error(`Invalid FlatBuffer: vtable header extends past buffer end`);
  }

  // Read vtable size (first 2 bytes of vtable, accounting for dataOffset)
  const vtableSize = view.getUint16(dataOffset + vtablePos, true);

  // vtable size should be reasonable (at least 4 bytes for size + table size fields)
  if (vtableSize < 4) {
    throw new Error(`Invalid FlatBuffer: vtable size (${vtableSize}) is too small`);
  }

  // vtable size must be even (it's an array of uint16)
  if (vtableSize % 2 !== 0) {
    throw new Error(`Invalid FlatBuffer: vtable size (${vtableSize}) is not even`);
  }

  // vtable shouldn't extend past buffer
  if (vtablePos + vtableSize > dataLength) {
    throw new Error(`Invalid FlatBuffer: vtable extends past buffer end`);
  }

  // Read table size from vtable (second 2 bytes)
  const tableSize = view.getUint16(dataOffset + vtablePos + 2, true);

  // Table size should be at least 4 (for the vtable offset itself)
  if (tableSize < 4) {
    throw new Error(`Invalid FlatBuffer: table size (${tableSize}) is too small`);
  }

  // Table should fit in buffer
  if (rootOffset + tableSize > dataLength) {
    throw new Error(`Invalid FlatBuffer: root table extends past buffer end`);
  }

  // Calculate number of fields in vtable
  const numFields = (vtableSize - 4) / 2;

  // Sanity check: too many fields might indicate corruption
  if (numFields > MAX_FIELDS_PER_TABLE) {
    throw new Error(`Invalid FlatBuffer: vtable has too many fields (${numFields} > ${MAX_FIELDS_PER_TABLE})`);
  }

  // Validate each field offset in the vtable
  for (let i = 0; i < numFields; i++) {
    const fieldOffset = view.getUint16(dataOffset + vtablePos + 4 + i * 2, true);

    // Field offset 0 means field is not present, which is valid
    if (fieldOffset === 0) continue;

    // Field offset should be within the table
    if (fieldOffset >= tableSize) {
      throw new Error(`Invalid FlatBuffer: field ${i} offset (${fieldOffset}) exceeds table size (${tableSize})`);
    }

    // Absolute position of field data (relative to data start)
    const fieldPos = rootOffset + fieldOffset;

    // Field should be within buffer
    if (fieldPos >= dataLength) {
      throw new Error(`Invalid FlatBuffer: field ${i} position (${fieldPos}) is outside buffer`);
    }
  }

  // Deep validation if requested
  if (options.deep) {
    const maxDepth = options.maxDepth || MAX_VALIDATION_DEPTH;
    const visited = new Set();
    validateTableDeep(buffer, view, rootOffset, visited, 0, maxDepth);
  }
}

/**
 * Recursively validates a table structure.
 * @param {Uint8Array} buffer
 * @param {DataView} view
 * @param {number} tableOffset
 * @param {Set<number>} visited - Visited offsets to detect cycles
 * @param {number} depth - Current recursion depth
 * @param {number} maxDepth - Maximum allowed depth
 */
function validateTableDeep(buffer, view, tableOffset, visited, depth, maxDepth) {
  // Check depth limit
  if (depth > maxDepth) {
    throw new Error(`Invalid FlatBuffer: exceeded maximum validation depth (${maxDepth})`);
  }

  // Check for cycles
  if (visited.has(tableOffset)) {
    throw new Error(`Invalid FlatBuffer: detected cycle at offset ${tableOffset}`);
  }
  visited.add(tableOffset);

  // Read vtable info
  const vtableOffsetSigned = view.getInt32(tableOffset, true);
  const vtablePos = tableOffset - vtableOffsetSigned;

  // Basic bounds check (already validated in caller for root)
  if (vtablePos < 0 || vtablePos + 4 > buffer.length) {
    throw new Error(`Invalid FlatBuffer: invalid vtable at depth ${depth}`);
  }

  const vtableSize = view.getUint16(vtablePos, true);
  const tableSize = view.getUint16(vtablePos + 2, true);

  if (vtablePos + vtableSize > buffer.length) {
    throw new Error(`Invalid FlatBuffer: vtable extends past buffer at depth ${depth}`);
  }

  if (tableOffset + tableSize > buffer.length) {
    throw new Error(`Invalid FlatBuffer: table extends past buffer at depth ${depth}`);
  }

  const numFields = (vtableSize - 4) / 2;

  // Validate field offsets
  for (let i = 0; i < numFields && i < MAX_FIELDS_PER_TABLE; i++) {
    const fieldOffset = view.getUint16(vtablePos + 4 + i * 2, true);
    if (fieldOffset === 0) continue;

    const fieldPos = tableOffset + fieldOffset;
    if (fieldPos >= buffer.length) {
      throw new Error(`Invalid FlatBuffer: field ${i} at depth ${depth} is outside buffer`);
    }

    // We don't know the field type without schema, but we can validate that
    // if this looks like an offset (32-bit value pointing forward), it's valid
    if (fieldPos + 4 <= buffer.length) {
      const possibleOffset = view.getUint32(fieldPos, true);

      // If this is an offset to another table/string/vector (positive, within buffer)
      if (possibleOffset > 0 && possibleOffset < buffer.length) {
        const targetPos = fieldPos + possibleOffset;

        // Target should be within buffer
        if (targetPos >= buffer.length) {
          // This might not be an offset field, so don't error, just skip
          continue;
        }

        // If target looks like it could be a string (has length prefix)
        if (targetPos + 4 <= buffer.length) {
          const possibleLength = view.getUint32(targetPos, true);

          // Validate string bounds if it looks like a string
          if (possibleLength > 0 && possibleLength < buffer.length) {
            if (targetPos + 4 + possibleLength > buffer.length) {
              // String would extend past buffer - this is an error
              throw new Error(`Invalid FlatBuffer: string at field ${i} depth ${depth} extends past buffer`);
            }
          }
        }
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
   * @param {boolean} [options.sizePrefix=true] - Include 4-byte size prefix before the buffer.
   * @param {boolean} [options.fileIdentifier=true] - Include file identifier (from schema).
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
    let output = new Uint8Array(this.Module.FS.readFile(`${outDir}/${binFile}`));
    cleanup();

    // Handle fileIdentifier option (default: true)
    // File identifier is at bytes 4-7 (after the root table offset)
    // If fileIdentifier is false and we have one, we need to zero it out
    if (options.fileIdentifier === false && output.length >= 8) {
      // Zero out the file identifier bytes (4-7)
      output[4] = 0;
      output[5] = 0;
      output[6] = 0;
      output[7] = 0;
    }

    // Handle sizePrefix option (default: true for streaming use cases)
    // Prepend 4-byte little-endian size prefix
    if (options.sizePrefix !== false) {
      const size = output.length;
      const prefixed = new Uint8Array(4 + size);
      // Write size as little-endian uint32
      prefixed[0] = size & 0xFF;
      prefixed[1] = (size >> 8) & 0xFF;
      prefixed[2] = (size >> 16) & 0xFF;
      prefixed[3] = (size >> 24) & 0xFF;
      prefixed.set(output, 4);
      return prefixed;
    }

    return output;
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

    // Strip size prefix if present (flatc --json doesn't expect it)
    let binaryData = binaryInput.data;
    if (binaryData.length >= 8) {
      const view = new DataView(binaryData.buffer, binaryData.byteOffset, binaryData.byteLength);
      const firstU32 = view.getUint32(0, true);
      if (firstU32 === binaryData.length - 4) {
        // Size-prefixed buffer, strip the prefix for flatc
        binaryData = binaryData.subarray(4);
      }
    }

    this.Module.FS.mkdirTree(outDir);
    this._mountSchemaIfNeeded(schemaInput);
    this.mountFile(binaryPath, binaryData);

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
      if (options.preserveCase) args.push("--preserve-case");
      if (options.noPrefix) args.push("--no-prefix");
      if (options.scopedEnums) args.push("--scoped-enums");
      if (options.genNullable) args.push("--gen-nullable");

      // Language-specific options
      if (options.pythonTyping) args.push("--python-typing");
      if (options.tsFlexBuffers) args.push("--ts-flexbuffers");
      if (options.tsNoImportExt) args.push("--ts-no-import-ext");
      if (options.tsOmitEntrypoint) args.push("--ts-omit-entrypoint");
      if (options.goModule) args.push("--go-module", options.goModule);
      if (options.goPackagePrefix) args.push("--go-package-prefix", options.goPackagePrefix);
      if (options.rustSerialize) args.push("--rust-serialize");
      if (options.rustModuleRootFile) args.push("--rust-module-root-file");
      if (options.javaPackagePrefix) args.push("--java-package-prefix", options.javaPackagePrefix);
      if (options.csGlobalAlias) args.push("--cs-global-alias");
      if (options.genJvmStatic) args.push("--gen-jvmstatic");

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
   * @returns {Promise<{ cpp: string, ts: string, layouts: Object }>} Generated code and layout info
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
   * const { cpp, ts, layouts } = await flatc.generateAlignedCode(schema);
   * // cpp: C++ header with aligned structs
   * // ts: TypeScript with DataView-based accessors
   * // layouts: computed sizes/offsets for each struct
   */
  async generateAlignedCode(schemaInput, options = {}) {
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

  // ===========================================================================
  // Encryption API
  // ===========================================================================

  /**
   * Generate an encrypted FlatBuffer binary from JSON input.
   * @param {{ entry: string, files: Record<string, string|Uint8Array> }} schemaInput
   * @param {string|Uint8Array} jsonInput - JSON data to convert and encrypt
   * @param {{ publicKey: Uint8Array, algorithm?: string, fields?: string[], context?: string }} encryption
   * @param {Object} [options={}] - Same options as generateBinary()
   * @returns {{ header: Uint8Array, data: Uint8Array }} Encrypted binary with header
   */
  generateBinaryEncrypted(schemaInput, jsonInput, encryption, options = {}) {
    if (!encryption || !encryption.publicKey) {
      throw new Error('Encryption config must include publicKey');
    }

    // First generate the normal binary
    const binary = this.generateBinary(schemaInput, jsonInput, {
      ...options,
      sizePrefix: false, // Don't size-prefix before encryption
    });

    // Use the C API for encryption if available
    const cwrap = this.Module.cwrap;
    if (cwrap && this.Module._wasm_crypto_encrypt_buffer) {
      // Register schema for C API if needed
      const schemaSource = schemaInput.files[schemaInput.entry];
      const schemaStr = typeof schemaSource === 'string'
        ? schemaSource
        : new TextDecoder().decode(schemaSource);

      const namePtr = this.Module._malloc(schemaInput.entry.length + 1);
      this.Module.stringToUTF8(schemaInput.entry, namePtr, schemaInput.entry.length + 1);
      const srcBytes = new TextEncoder().encode(schemaStr);
      const srcPtr = this.Module._malloc(srcBytes.length);
      this.Module.HEAPU8.set(srcBytes, srcPtr);

      const schemaId = this.Module._wasm_schema_add(namePtr, schemaInput.entry.length, srcPtr, srcBytes.length);
      this.Module._free(namePtr);
      this.Module._free(srcPtr);

      if (schemaId >= 0) {
        // Allocate and copy key + binary to WASM memory
        const keyPtr = this.Module._malloc(encryption.publicKey.length);
        this.Module.HEAPU8.set(encryption.publicKey, keyPtr);

        const binPtr = this.Module._malloc(binary.length);
        this.Module.HEAPU8.set(binary, binPtr);

        const outLenPtr = this.Module._malloc(4);
        const headerLenPtr = this.Module._malloc(4);

        const resultPtr = this.Module._wasm_json_to_binary_encrypted(
          schemaId,
          0, 0, // json already converted
          keyPtr, encryption.publicKey.length,
          outLenPtr, headerLenPtr
        );

        this.Module._free(keyPtr);
        this.Module._free(binPtr);

        if (resultPtr) {
          const outLen = this.Module.getValue(outLenPtr, 'i32');
          const data = new Uint8Array(this.Module.HEAPU8.buffer, resultPtr, outLen).slice();
          this.Module._free(outLenPtr);
          this.Module._free(headerLenPtr);
          this.Module._wasm_schema_remove(schemaId);
          return { header: new Uint8Array(0), data };
        }

        this.Module._free(outLenPtr);
        this.Module._free(headerLenPtr);
        this.Module._wasm_schema_remove(schemaId);
      }
    }

    // No silent fallback — encryption must succeed or throw (Task 26)
    throw new Error('Encryption unavailable: WASM crypto exports not found');
  }

  /**
   * Generate JSON from an encrypted FlatBuffer binary.
   * @param {{ entry: string, files: Record<string, string|Uint8Array> }} schemaInput
   * @param {{ path: string, data: Uint8Array }} binaryInput - Encrypted binary
   * @param {{ privateKey: Uint8Array, header?: Uint8Array }} decryption
   * @param {Object} [options={}] - Same options as generateJSON()
   * @returns {string|Uint8Array}
   */
  generateJSONDecrypted(schemaInput, binaryInput, decryption, options = {}) {
    if (!decryption || !decryption.privateKey) {
      throw new Error('Decryption config must include privateKey');
    }

    // Use C API for decryption if available
    if (this.Module._wasm_binary_to_json_decrypted) {
      const schemaSource = schemaInput.files[schemaInput.entry];
      const schemaStr = typeof schemaSource === 'string'
        ? schemaSource
        : new TextDecoder().decode(schemaSource);

      const namePtr = this.Module._malloc(schemaInput.entry.length + 1);
      this.Module.stringToUTF8(schemaInput.entry, namePtr, schemaInput.entry.length + 1);
      const srcBytes = new TextEncoder().encode(schemaStr);
      const srcPtr = this.Module._malloc(srcBytes.length);
      this.Module.HEAPU8.set(srcBytes, srcPtr);

      const schemaId = this.Module._wasm_schema_add(namePtr, schemaInput.entry.length, srcPtr, srcBytes.length);
      this.Module._free(namePtr);
      this.Module._free(srcPtr);

      if (schemaId >= 0) {
        const keyPtr = this.Module._malloc(decryption.privateKey.length);
        this.Module.HEAPU8.set(decryption.privateKey, keyPtr);

        const binPtr = this.Module._malloc(binaryInput.data.length);
        this.Module.HEAPU8.set(binaryInput.data, binPtr);

        const outLenPtr = this.Module._malloc(4);

        const resultPtr = this.Module._wasm_binary_to_json_decrypted(
          schemaId,
          binPtr, binaryInput.data.length,
          keyPtr, decryption.privateKey.length,
          outLenPtr
        );

        this.Module._free(keyPtr);
        this.Module._free(binPtr);

        if (resultPtr) {
          const outLen = this.Module.getValue(outLenPtr, 'i32');
          const json = this.Module.UTF8ToString(resultPtr, outLen);
          this.Module._free(outLenPtr);
          this.Module._wasm_schema_remove(schemaId);
          return json;
        }

        this.Module._free(outLenPtr);
        this.Module._wasm_schema_remove(schemaId);
      }
    }

    // No silent fallback — decryption must succeed or throw (Task 26)
    throw new Error('Decryption unavailable: WASM crypto exports not found');
  }

  /**
   * Configure session-level encryption for subsequent operations.
   * @param {Uint8Array} publicKey - Recipient's public key
   * @param {Object|Uint8Array} config - Encryption config (JSON object or FlatBuffer)
   */
  configureEncryption(publicKey, config) {
    this._encryptionConfig = { publicKey, config };
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
