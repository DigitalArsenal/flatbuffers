/**
 * flatc-wasm - FlatBuffers compiler as a WebAssembly module
 *
 * This module exports:
 * - FlatcRunner: High-level wrapper with typed methods for schema operations
 * - createFlatcModule: Low-level factory for direct WASM module access
 * - Encryption utilities for field-level encryption
 */

export { FlatcRunner } from "./runner.mjs";
import createFlatcModule from "../dist/flatc-wasm.js";

// Encryption exports
export {
  EncryptionContext,
  encryptBytes,
  decryptBytes,
  encryptScalar,
  encryptBuffer,
  decryptBuffer,
  parseSchemaForEncryption,
} from "./encryption.mjs";

export { createFlatcModule };
export default createFlatcModule;
