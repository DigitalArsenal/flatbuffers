/**
 * flatc-wasm - FlatBuffers compiler as a WebAssembly module
 *
 * This module exports:
 * - FlatcRunner: High-level wrapper with typed methods for schema operations
 * - createFlatcModule: Low-level factory for direct WASM module access
 * - Aligned codegen for zero-copy WASM interop
 * - Full encryption API (AES-CTR, ECIES, ECDH, signatures, HKDF)
 */

// Encryption module (wraps WASM crypto functions)
export {
  // Module management
  loadEncryptionWasm,
  isInitialized,
  hasCryptopp,
  getVersion,
  // Constants
  KEY_SIZE,
  IV_SIZE,
  NONCE_SIZE,
  SHA256_SIZE,
  HMAC_SIZE,
  X25519_PRIVATE_KEY_SIZE,
  X25519_PUBLIC_KEY_SIZE,
  SECP256K1_PRIVATE_KEY_SIZE,
  SECP256K1_PUBLIC_KEY_SIZE,
  P384_PRIVATE_KEY_SIZE,
  P384_PUBLIC_KEY_SIZE,
  ED25519_PRIVATE_KEY_SIZE,
  ED25519_PUBLIC_KEY_SIZE,
  ED25519_SIGNATURE_SIZE,
  // Error types
  CryptoError,
  CryptoErrorCode,
  // SHA-256
  sha256,
  // HMAC
  hmacSha256,
  hmacSha256Verify,
  // HKDF
  hkdf,
  // IV tracking
  clearIVTracking,
  clearAllIVTracking,
  // Nonce
  generateNonceStart,
  deriveNonce,
  // AES-256-CTR
  encryptBytes,
  decryptBytes,
  encryptBytesCopy,
  decryptBytesCopy,
  // Authenticated encryption
  encryptAuthenticated,
  decryptAuthenticated,
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
  // P-256 (Web Crypto)
  p256GenerateKeyPairAsync,
  p256SharedSecretAsync,
  p256DeriveKey,
  p256SignAsync,
  p256VerifyAsync,
  // P-384 (Web Crypto)
  p384GenerateKeyPairAsync,
  p384SharedSecretAsync,
  p384DeriveKey,
  p384SignAsync,
  p384VerifyAsync,
  // Ed25519
  ed25519GenerateKeyPair,
  ed25519Sign,
  ed25519Verify,
  // EncryptionContext
  EncryptionContext,
  // Header utilities
  computeKeyId,
  createEncryptionHeader,
  encryptionHeaderToJSON,
  encryptionHeaderFromJSON,
  // Schema parsing
  parseSchemaForEncryption,
  // Buffer encryption
  encryptBuffer,
  decryptBuffer,
} from "./encryption.mjs";

// Legacy aliases for backward compatibility
export { encryptionHeaderToJSON as serializeEncryptionHeader } from "./encryption.mjs";
export { encryptionHeaderFromJSON as deserializeEncryptionHeader } from "./encryption.mjs";

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
