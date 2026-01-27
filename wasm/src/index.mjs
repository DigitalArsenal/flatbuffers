/**
 * flatc-wasm - FlatBuffers compiler as a WebAssembly module
 *
 * This module exports:
 * - FlatcRunner: High-level wrapper with typed methods for schema operations
 * - createFlatcModule: Low-level factory for direct WASM module access
 * - Encryption utilities for field-level encryption
 * - Aligned codegen for zero-copy WASM interop
 */

export { FlatcRunner } from "./runner.mjs";
import createFlatcModule from "../dist/flatc-wasm.js";

// Aligned codegen exports (zero-copy WASM interop)
export {
  parseSchema,
  computeLayout,
  generateCppHeader,
  generateTypeScript,
  generateJavaScript,
  generateAlignedCode,
} from "./aligned-codegen.mjs";

// Streaming dispatcher exports
export {
  StreamingDispatcher,
  createSizePrefixedMessage,
  concatMessages,
} from "./streaming-dispatcher.mjs";

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
  // P-384
  p384GenerateKeyPair,
  p384SharedSecret,
  p384DeriveKey,
  p384Sign,
  p384Verify,
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

export { createFlatcModule };
export default createFlatcModule;
