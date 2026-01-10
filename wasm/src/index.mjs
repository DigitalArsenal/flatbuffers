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
  // Error types
  CryptoError,
  CryptoErrorCode,
  // Context and initialization
  EncryptionContext,
  initEncryption,
  loadEncryptionWasm,
  isInitialized,
  hasCryptopp,
  getVersion,
  // Hashing
  sha256,
  hmacSha256,
  hmacSha256Verify,
  // Symmetric encryption
  encryptBytes,
  decryptBytes,
  encryptAuthenticated,
  decryptAuthenticated,
  encryptScalar,
  // Key derivation
  hkdf,
  // X25519
  x25519GenerateKeyPair,
  x25519SharedSecret,
  x25519DeriveKey,
  // secp256k1
  secp256k1GenerateKeyPair,
  secp256k1SharedSecret,
  secp256k1DeriveKey,
  secp256k1Sign,
  secp256k1Verify,
  // P-256
  p256GenerateKeyPair,
  p256SharedSecret,
  p256DeriveKey,
  p256Sign,
  p256Verify,
  // Ed25519
  ed25519GenerateKeyPair,
  ed25519Sign,
  ed25519Verify,
  // Header utilities
  createEncryptionHeader,
  computeKeyId,
  encryptionHeaderToJSON,
  encryptionHeaderFromJSON,
  // Buffer encryption
  parseSchemaForEncryption,
  encryptBuffer,
  decryptBuffer,
  // Constants
  KEY_SIZE,
  IV_SIZE,
  HMAC_SIZE,
  SHA256_SIZE,
} from "./encryption.mjs";

export { createFlatcModule };
export default createFlatcModule;
