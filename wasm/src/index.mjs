/**
 * flatc-wasm - FlatBuffers compiler as a WebAssembly module
 *
 * This module exports:
 * - FlatcRunner: High-level wrapper with typed methods for schema operations
 * - createFlatcModule: Low-level factory for direct WASM module access
 * - Aligned codegen for zero-copy WASM interop
 *
 * All crypto operations live in the compiled WASM binary.
 * Use Module._wasm_crypto_* exports from the Emscripten module directly.
 */

// Encryption context stubs for runner.mjs fallback encryption path.
// These provide the imports that runner.mjs expects. The WASM C API is
// the primary encryption path; these are only used as JS fallback.
class EncryptionContext {
  static forEncryption() { throw new Error('JS encryption fallback not available'); }
  static forDecryption() { throw new Error('JS decryption fallback not available'); }
}
function serializeEncryptionHeader() { return new Uint8Array(0); }
function deserializeEncryptionHeader() { return {}; }
export { EncryptionContext, serializeEncryptionHeader, deserializeEncryptionHeader };

export { FlatcRunner } from "./runner.mjs";
import createFlatcModule from "../dist/flatc-wasm.js";

// Aligned codegen exports (zero-copy WASM interop)
export {
  initAlignedCodegen,
  generateAlignedCode,
} from "./aligned-codegen.mjs";

// Streaming dispatcher exports
export {
  StreamingDispatcher,
  createSizePrefixedMessage,
  concatMessages,
} from "./streaming-dispatcher.mjs";

// HD Key derivation exports (BIP-32/BIP-44)
export {
  // Constants
  BIP44_PURPOSE,
  Chain,
  CoinType,
  Curve,
  CoinTypeToCurve,
  DefaultCoinType,
  CoinTypeName,
  KeyPurpose,
  // Path utilities
  buildPath,
  buildSigningPath,
  buildEncryptionPath,
  parsePath,
  // Manager class
  HDKeyManager,
  // Factory functions
  createFromMnemonic,
  createFromSeed,
  // Validation
  validateSigningKey,
  validateEncryptionKey,
} from "./hd-keys.mjs";

// Format detection
export {
  detectFormat,
  detectStringFormat,
} from "./format-detector.mjs";

// HE Context (promoted from examples)
export {
  HEContext,
  initHEModule,
  getHEModule,
  getLastError as getHELastError,
  DEFAULT_POLY_MODULUS_DEGREE,
} from "./he-context.mjs";

// HE Key Bridge (HD wallet → HE keys)
export {
  deriveHEContext,
  getHEPublicBundle,
  deriveHEContextFromManager,
} from "./he-key-bridge.mjs";

// HE Field Encryptor (per-field encryption + companion schema)
export {
  identifyHEFields,
  generateCompanionSchema,
  encryptFields,
  decryptFields,
  buildEncryptedBinary,
} from "./he-field-encryptor.mjs";

// Unified Pipeline
export { FlatBufferPipeline } from "./pipeline.mjs";

export { createFlatcModule };
export default createFlatcModule;
