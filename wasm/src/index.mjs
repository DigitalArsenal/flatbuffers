/**
 * flatc-wasm - FlatBuffers compiler as a WebAssembly module
 *
 * This module exports:
 * - FlatcRunner: High-level wrapper with typed methods for schema operations
 * - createFlatcModule: Low-level factory for direct WASM module access
 */

export { FlatcRunner } from "./runner.mjs";
import createFlatcModule from "../dist/flatc-wasm.js";

export { createFlatcModule };
export default createFlatcModule;
