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
};
