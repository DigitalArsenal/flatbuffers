/**
 * @module aligned-codegen
 *
 * Generates aligned, fixed-size structs from FlatBuffers schemas for zero-copy
 * WASM interop. Outputs C++ headers and TypeScript view classes that share the
 * same memory layout.
 *
 * This module wraps the C++ aligned code generator compiled to WASM.
 */

import createFlatcModule from "../dist/flatc-wasm.js";

// Module-level WASM instance (lazily loaded)
let _wasmModule = null;
let _loadingPromise = null;

/**
 * Initialize the WASM module for aligned code generation.
 * Called automatically by generateAlignedCode, but can be called
 * explicitly to warm up the module.
 * @returns {Promise<void>}
 */
export async function initAlignedCodegen() {
  if (_wasmModule) return;
  if (_loadingPromise) {
    await _loadingPromise;
    return;
  }

  _loadingPromise = createFlatcModule({
    noExitRuntime: true,
    noInitialRun: true,
    print: () => {},
    printErr: () => {},
  });

  _wasmModule = await _loadingPromise;
  _loadingPromise = null;
}

// Language ID for aligned code generation in WASM
const ALIGNED_LANGUAGE_ID = 13;

/**
 * Parse a FlatBuffers schema and extract struct/table/enum definitions.
 * This is a JavaScript-based parser for extracting schema structure info.
 * @param {string} schemaContent - The .fbs schema content
 * @param {Object} [options={}] - Parse options (reserved for future use)
 * @returns {{ namespace: string|null, structs: Array, tables: Array, enums: Array }}
 */
export function parseSchema(schemaContent, options = {}) {
  const result = {
    namespace: null,
    structs: [],
    tables: [],
    enums: [],
  };

  // Extract namespace
  const namespaceMatch = schemaContent.match(/namespace\s+([\w.]+)\s*;/);
  if (namespaceMatch) {
    result.namespace = namespaceMatch[1];
  }

  // Extract enums
  const enumRegex = /enum\s+(\w+)\s*:\s*(\w+)\s*\{([^}]*)\}/g;
  let match;
  while ((match = enumRegex.exec(schemaContent)) !== null) {
    const [, name, baseType, body] = match;
    const values = [];
    const valueMatches = body.matchAll(/(\w+)(?:\s*=\s*(-?\d+|0x[0-9a-fA-F]+))?/g);
    for (const vm of valueMatches) {
      values.push({
        name: vm[1],
        value: vm[2] ? parseInt(vm[2], vm[2].startsWith('0x') ? 16 : 10) : null,
      });
    }
    result.enums.push({ name, baseType, values });
  }

  // Extract structs
  const structRegex = /struct\s+(\w+)\s*\{([^}]*)\}/g;
  while ((match = structRegex.exec(schemaContent)) !== null) {
    const [, name, body] = match;
    const fields = parseFields(body, result.enums);
    result.structs.push({ name, fields, isStruct: true });
  }

  // Extract tables (for info purposes - aligned codegen focuses on structs)
  const tableRegex = /table\s+(\w+)\s*\{([^}]*)\}/g;
  while ((match = tableRegex.exec(schemaContent)) !== null) {
    const [, name, body] = match;
    const fields = parseFields(body, result.enums);
    result.tables.push({ name, fields, isStruct: false });
  }

  return result;
}

/**
 * Parse field definitions from a struct/table body
 * @param {string} body - The body content inside braces
 * @param {Array} enums - Known enum definitions for type resolution
 * @returns {Array} Array of field definitions
 */
function parseFields(body, enums) {
  const fields = [];
  const lines = body.split(/[;\n]/).map(l => l.trim()).filter(l => l && !l.startsWith('//'));

  for (const line of lines) {
    // Match: fieldName:type or fieldName:[type:N] (fixed array)
    const fieldMatch = line.match(/^(\w+)\s*:\s*(.+?)(?:\s*=\s*[^;]+)?$/);
    if (!fieldMatch) continue;

    const [, name, typeStr] = fieldMatch;
    let type = typeStr.trim();
    let isArray = false;
    let arraySize = 0;

    // Check for fixed-length array: [type:N]
    const arrayMatch = type.match(/^\[(\w+):(\d+)\]$/);
    if (arrayMatch) {
      type = arrayMatch[1];
      isArray = true;
      arraySize = parseInt(arrayMatch[2], 10);
    }

    // Check if this is an enum type
    const enumDef = enums.find(e => e.name === type);

    fields.push({
      name,
      type,
      isArray,
      arraySize,
      isEnum: !!enumDef,
      enumDef: enumDef || undefined,
    });
  }

  return fields;
}

/**
 * Generate aligned code from a FlatBuffers schema using the C++ code generator.
 * @param {string} schemaContent - The .fbs schema content
 * @param {Object} options - Generation options (currently unused, reserved for future use)
 * @returns {Promise<{ cpp: string, ts: string, js: string, layouts: Object }>}
 */
export async function generateAlignedCode(schemaContent, options = {}) {
  // Initialize WASM module if needed
  await initAlignedCodegen();

  // Helper functions for WASM memory
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  function writeString(str) {
    const bytes = encoder.encode(str);
    const ptr = _wasmModule._malloc(bytes.length);
    _wasmModule.HEAPU8.set(bytes, ptr);
    return [ptr, bytes.length];
  }

  // Add schema to WASM
  const [namePtr, nameLen] = writeString('schema.fbs');
  const [srcPtr, srcLen] = writeString(schemaContent);
  const schemaId = _wasmModule._wasm_schema_add(namePtr, nameLen, srcPtr, srcLen);
  _wasmModule._free(namePtr);
  _wasmModule._free(srcPtr);

  if (schemaId < 0) {
    const errorPtr = _wasmModule._wasm_get_last_error();
    const error = errorPtr ? _wasmModule.UTF8ToString(errorPtr) : 'Failed to parse schema';
    throw new Error(`Schema parsing failed: ${error}`);
  }

  try {
    // Generate aligned code using C++ generator
    const outLenPtr = _wasmModule._malloc(4);
    const resultPtr = _wasmModule._wasm_generate_code(schemaId, ALIGNED_LANGUAGE_ID, outLenPtr);

    if (resultPtr === 0) {
      _wasmModule._free(outLenPtr);
      const errorPtr = _wasmModule._wasm_get_last_error();
      const error = errorPtr ? _wasmModule.UTF8ToString(errorPtr) : 'Code generation failed';
      throw new Error(`Aligned code generation failed: ${error}`);
    }

    const len = _wasmModule.getValue(outLenPtr, 'i32');
    _wasmModule._free(outLenPtr);

    const codeBytes = _wasmModule.HEAPU8.slice(resultPtr, resultPtr + len);
    const jsonOutput = decoder.decode(codeBytes);

    // Parse the single JSON object containing all outputs
    const result = JSON.parse(jsonOutput);
    return {
      cpp: result.cpp || '',
      ts: result.ts || '',
      js: result.js || '',
      layouts: result.layouts || {}
    };
  } finally {
    // Cleanup: remove schema from WASM
    _wasmModule._wasm_schema_remove(schemaId);
  }
}

export default {
  initAlignedCodegen,
  generateAlignedCode,
  parseSchema,
};
