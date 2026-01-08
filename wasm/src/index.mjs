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
  initEncryption,
  loadEncryptionWasm,
  isInitialized,
  hasCryptopp,
  getVersion,
  sha256,
  hkdf,
  x25519GenerateKeyPair,
  x25519SharedSecret,
  x25519DeriveKey,
  secp256k1GenerateKeyPair,
  secp256k1SharedSecret,
  secp256k1DeriveKey,
  secp256k1Sign,
  secp256k1Verify,
  p256GenerateKeyPair,
  p256SharedSecret,
  p256DeriveKey,
  p256Sign,
  p256Verify,
  ed25519GenerateKeyPair,
  ed25519Sign,
  ed25519Verify,
  createEncryptionHeader,
  computeKeyId,
  encryptionHeaderToJSON,
  encryptionHeaderFromJSON,
} from "./encryption.mjs";

export { createFlatcModule };
export default createFlatcModule;
