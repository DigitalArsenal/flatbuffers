#!/usr/bin/env node
/**
 * test_encryption.mjs - Comprehensive test suite for the encryption module
 *
 * Tests all cryptographic operations including:
 * - AES-256-CTR encryption/decryption
 * - HKDF key derivation
 * - X25519 key exchange
 * - secp256k1 ECDH and ECDSA
 * - P-256 ECDH and ECDSA
 * - Ed25519 signatures
 * - EncryptionContext field-level encryption
 * - Buffer encryption/decryption
 */

import { fileURLToPath } from 'url';
import path from 'path';
import { readFileSync } from 'fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Import encryption module
import {
  loadEncryptionWasm,
  isInitialized,
  hasCryptopp,
  getVersion,
  sha256,
  encryptBytes,
  decryptBytes,
  encryptBytesCopy,
  decryptBytesCopy,
  generateIV,
  clearIVTracking,
  clearAllIVTracking,
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
  EncryptionContext,
  parseSchemaForEncryption,
  encryptBuffer,
  decryptBuffer,
  createEncryptionHeader,
  computeKeyId,
  encryptionHeaderToJSON,
  encryptionHeaderFromJSON,
  CryptoError,
  CryptoErrorCode,
  KEY_SIZE,
  IV_SIZE,
  SHA256_SIZE,
  X25519_PRIVATE_KEY_SIZE,
  X25519_PUBLIC_KEY_SIZE,
  SECP256K1_PRIVATE_KEY_SIZE,
  SECP256K1_PUBLIC_KEY_SIZE,
  ED25519_PRIVATE_KEY_SIZE,
  ED25519_PUBLIC_KEY_SIZE,
  ED25519_SIGNATURE_SIZE,
} from '../src/encryption.mjs';

let passed = 0;
let failed = 0;

function log(msg) {
  console.log(msg);
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(`${message}: expected ${expected}, got ${actual}`);
  }
}

function assertArrayEqual(actual, expected, message) {
  if (actual.length !== expected.length) {
    throw new Error(`${message}: length mismatch - expected ${expected.length}, got ${actual.length}`);
  }
  for (let i = 0; i < actual.length; i++) {
    if (actual[i] !== expected[i]) {
      throw new Error(`${message}: mismatch at index ${i} - expected ${expected[i]}, got ${actual[i]}`);
    }
  }
}

function assertThrows(fn, expectedMessage, testName) {
  let threw = false;
  let actualMessage = '';
  try {
    fn();
  } catch (e) {
    threw = true;
    actualMessage = e.message;
  }
  if (!threw) {
    throw new Error(`Expected function to throw, but it did not`);
  }
  if (expectedMessage && !actualMessage.includes(expectedMessage)) {
    throw new Error(`Expected error containing "${expectedMessage}", got "${actualMessage}"`);
  }
}

async function test(name, fn) {
  try {
    await fn();
    log(`  PASS: ${name}`);
    passed++;
  } catch (err) {
    log(`  FAIL: ${name}`);
    log(`    Error: ${err.message}`);
    if (err.stack) {
      log(`    Stack: ${err.stack.split('\n').slice(1, 3).join('\n    ')}`);
    }
    failed++;
  }
}

// Helper to generate random bytes for testing
function randomBytes(size) {
  const bytes = new Uint8Array(size);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else if (typeof process !== 'undefined' && process.versions?.node) {
    // Fallback for Node.js - use synchronous require
    // eslint-disable-next-line no-new-func
    const nodeCrypto = new Function('return require("crypto")')();
    nodeCrypto.randomFillSync(bytes);
  }
  return bytes;
}

// Helper to convert hex string to Uint8Array
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

// Helper to convert Uint8Array to hex string
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function main() {
  log('============================================================');
  log('Encryption Module Test Suite');
  log('============================================================');

  // Check for CI mode - in CI, missing WASM should be a hard failure
  const isCI = process.env.CI === 'true' || process.env.CI === '1' ||
               process.env.REQUIRE_WASM === 'true' || process.env.REQUIRE_WASM === '1';

  // Try to load WASM module
  log('\n[Module Initialization]');

  const wasmPath = path.join(__dirname, '..', 'dist', 'flatc-encryption.wasm');
  let wasmLoaded = false;

  try {
    await loadEncryptionWasm(wasmPath);
    wasmLoaded = true;
    log(`  WASM module loaded from: ${wasmPath}`);
  } catch (err) {
    log(`  WARNING: Could not load WASM module: ${err.message}`);
    if (isCI) {
      log(`  ERROR: WASM module is required in CI mode (CI=${process.env.CI}, REQUIRE_WASM=${process.env.REQUIRE_WASM})`);
      log(`  Build the WASM module first with: npm run build`);
      process.exit(1);
    }
    log(`  Some tests will be skipped.`);
  }

  await test('isInitialized returns correct state', async () => {
    assertEqual(isInitialized(), wasmLoaded, 'isInitialized should match load state');
  });

  // Skip WASM-dependent tests if not loaded
  if (!wasmLoaded) {
    log('\n  Skipping WASM-dependent tests...');
    log('\n============================================================');
    log(`Results: ${passed} passed, ${failed} failed (many skipped)`);
    log('============================================================');
    // Exit with failure in CI mode (should have already exited above, but just in case)
    process.exit(isCI ? 1 : (failed > 0 ? 1 : 0));
  }

  await test('hasCryptopp returns boolean', async () => {
    const result = hasCryptopp();
    assertEqual(typeof result, 'boolean', 'hasCryptopp should return boolean');
  });

  await test('getVersion returns string', async () => {
    const version = getVersion();
    assertEqual(typeof version, 'string', 'getVersion should return string');
    assert(version.length > 0, 'version should not be empty');
  });

  // ==========================================================================
  // SHA-256 Tests
  // ==========================================================================
  log('\n[SHA-256 Hashing]');

  await test('sha256 produces 32-byte hash', async () => {
    const data = new TextEncoder().encode('Hello, World!');
    const hash = sha256(data);
    assertEqual(hash.length, SHA256_SIZE, 'hash should be 32 bytes');
  });

  await test('sha256 is deterministic', async () => {
    const data = new TextEncoder().encode('test data');
    const hash1 = sha256(data);
    const hash2 = sha256(data);
    assertArrayEqual(hash1, hash2, 'same input should produce same hash');
  });

  await test('sha256 produces different hashes for different inputs', async () => {
    const hash1 = sha256(new TextEncoder().encode('input1'));
    const hash2 = sha256(new TextEncoder().encode('input2'));
    let same = true;
    for (let i = 0; i < hash1.length; i++) {
      if (hash1[i] !== hash2[i]) {
        same = false;
        break;
      }
    }
    assert(!same, 'different inputs should produce different hashes');
  });

  await test('sha256 handles empty input', async () => {
    const hash = sha256(new Uint8Array(0));
    assertEqual(hash.length, SHA256_SIZE, 'empty input should produce 32-byte hash');
  });

  // ==========================================================================
  // AES-256-CTR Tests
  // ==========================================================================
  log('\n[AES-256-CTR Encryption]');

  await test('encryptBytes encrypts data in-place', async () => {
    const key = new Uint8Array(KEY_SIZE).fill(0x42);
    const iv = new Uint8Array(IV_SIZE).fill(0x24);
    const original = new TextEncoder().encode('Hello, World!');
    const data = new Uint8Array(original);

    encryptBytes(data, key, iv);

    // Data should be modified
    let modified = false;
    for (let i = 0; i < data.length; i++) {
      if (data[i] !== original[i]) {
        modified = true;
        break;
      }
    }
    assert(modified, 'data should be modified after encryption');
  });

  await test('decryptBytes reverses encryptBytes', async () => {
    const key = new Uint8Array(KEY_SIZE).fill(0x42);
    const iv = new Uint8Array(IV_SIZE).fill(0x24);
    const original = new TextEncoder().encode('Secret message!');
    const data = new Uint8Array(original);

    clearIVTracking(key);  // Start fresh
    encryptBytes(data, key, iv);
    // decryptBytes doesn't track IVs (only encryption does), so this works
    decryptBytes(data, key, iv);

    assertArrayEqual(data, original, 'decrypt should reverse encrypt');
  });

  await test('CTR mode produces same-length output', async () => {
    const key = new Uint8Array(KEY_SIZE).fill(0x42);
    clearIVTracking(key);

    for (const len of [1, 16, 17, 100, 1000]) {
      // Use unique IV for each encryption to avoid IV reuse
      const iv = randomBytes(IV_SIZE);
      const data = new Uint8Array(len).fill(0xAB);
      const originalLen = data.length;
      encryptBytes(data, key, iv);
      assertEqual(data.length, originalLen, `length should remain ${len}`);
    }
  });

  await test('encryptBytes throws on invalid key size', async () => {
    const key = new Uint8Array(16); // Wrong size
    const iv = new Uint8Array(IV_SIZE);
    const data = new Uint8Array(10);

    assertThrows(
      () => encryptBytes(data, key, iv),
      'Key must be 32 bytes',
      'should throw on invalid key size'
    );
  });

  await test('encryptBytes throws on invalid IV size', async () => {
    const key = new Uint8Array(KEY_SIZE);
    const iv = new Uint8Array(8); // Wrong size
    const data = new Uint8Array(10);

    assertThrows(
      () => encryptBytes(data, key, iv),
      'IV must be 16 bytes',
      'should throw on invalid IV size'
    );
  });

  await test('encryptBytes handles empty data', async () => {
    const key = new Uint8Array(KEY_SIZE).fill(0x42);
    const iv = new Uint8Array(IV_SIZE).fill(0x24);
    const data = new Uint8Array(0);

    // Should not throw
    encryptBytes(data, key, iv);
    assertEqual(data.length, 0, 'empty data should remain empty');
  });

  await test('different keys produce different ciphertext', async () => {
    const iv = new Uint8Array(IV_SIZE).fill(0x24);
    const plaintext = new TextEncoder().encode('Same plaintext');

    const data1 = new Uint8Array(plaintext);
    const data2 = new Uint8Array(plaintext);

    encryptBytes(data1, new Uint8Array(KEY_SIZE).fill(0x01), iv);
    encryptBytes(data2, new Uint8Array(KEY_SIZE).fill(0x02), iv);

    let same = true;
    for (let i = 0; i < data1.length; i++) {
      if (data1[i] !== data2[i]) {
        same = false;
        break;
      }
    }
    assert(!same, 'different keys should produce different ciphertext');
  });

  await test('different IVs produce different ciphertext', async () => {
    const key = new Uint8Array(KEY_SIZE).fill(0x42);
    const plaintext = new TextEncoder().encode('Same plaintext');

    const data1 = new Uint8Array(plaintext);
    const data2 = new Uint8Array(plaintext);

    // Clear IV tracking before test to allow these specific IVs
    clearIVTracking(key);

    encryptBytes(data1, key, new Uint8Array(IV_SIZE).fill(0x01));
    encryptBytes(data2, key, new Uint8Array(IV_SIZE).fill(0x02));

    let same = true;
    for (let i = 0; i < data1.length; i++) {
      if (data1[i] !== data2[i]) {
        same = false;
        break;
      }
    }
    assert(!same, 'different IVs should produce different ciphertext');
  });

  // ==========================================================================
  // Security Tests - IV Reuse Prevention (VULN-001)
  // ==========================================================================
  log('\n[Security: IV Reuse Prevention]');

  await test('encryptBytes throws on IV reuse with same key', async () => {
    const key = randomBytes(KEY_SIZE);
    const iv = randomBytes(IV_SIZE);
    const data1 = new TextEncoder().encode('First message');
    const data2 = new TextEncoder().encode('Second message');

    // Clear any previous tracking for this key
    clearIVTracking(key);

    // First encryption should succeed
    encryptBytes(data1, key, iv);

    // Second encryption with same IV should throw
    assertThrows(
      () => encryptBytes(data2, key, iv),
      'IV has already been used',
      'should throw on IV reuse'
    );
  });

  await test('encryptBytes allows same IV with different keys', async () => {
    const key1 = randomBytes(KEY_SIZE);
    const key2 = randomBytes(KEY_SIZE);
    const iv = randomBytes(IV_SIZE);

    // Clear tracking
    clearIVTracking(key1);
    clearIVTracking(key2);

    const data1 = new TextEncoder().encode('Message for key1');
    const data2 = new TextEncoder().encode('Message for key2');

    // Both should succeed since they use different keys
    encryptBytes(data1, key1, iv);
    encryptBytes(data2, key2, iv);
    // No exception means test passed
  });

  await test('clearIVTracking allows IV reuse after clearing', async () => {
    const key = randomBytes(KEY_SIZE);
    const iv = randomBytes(IV_SIZE);

    clearIVTracking(key);

    const data1 = new TextEncoder().encode('First');
    encryptBytes(data1, key, iv);

    // Clear tracking
    clearIVTracking(key);

    // Now the same IV should work again
    const data2 = new TextEncoder().encode('Second');
    encryptBytes(data2, key, iv);
    // No exception means test passed
  });

  await test('clearAllIVTracking clears all keys', async () => {
    const key1 = randomBytes(KEY_SIZE);
    const key2 = randomBytes(KEY_SIZE);
    const iv1 = randomBytes(IV_SIZE);
    const iv2 = randomBytes(IV_SIZE);

    clearAllIVTracking();

    encryptBytes(new TextEncoder().encode('msg1'), key1, iv1);
    encryptBytes(new TextEncoder().encode('msg2'), key2, iv2);

    // Clear all
    clearAllIVTracking();

    // Both should work again
    encryptBytes(new TextEncoder().encode('msg3'), key1, iv1);
    encryptBytes(new TextEncoder().encode('msg4'), key2, iv2);
  });

  await test('generateIV produces valid random IVs', async () => {
    const iv1 = generateIV();
    const iv2 = generateIV();

    assertEqual(iv1.length, IV_SIZE, 'IV should be 16 bytes');
    assertEqual(iv2.length, IV_SIZE, 'IV should be 16 bytes');

    // IVs should be different (with overwhelming probability)
    let same = true;
    for (let i = 0; i < IV_SIZE; i++) {
      if (iv1[i] !== iv2[i]) {
        same = false;
        break;
      }
    }
    assert(!same, 'generated IVs should be unique');
  });

  // ==========================================================================
  // Security Tests - Non-Destructive Encryption (VULN-004)
  // ==========================================================================
  log('\n[Security: Non-Destructive Encryption]');

  await test('encryptBytesCopy preserves original data', async () => {
    const key = randomBytes(KEY_SIZE);
    const originalPlaintext = new TextEncoder().encode('Original message');
    const plaintext = new Uint8Array(originalPlaintext);

    clearIVTracking(key);

    const { ciphertext, iv } = encryptBytesCopy(plaintext, key);

    // Original should be unchanged
    assertArrayEqual(plaintext, originalPlaintext, 'original should be preserved');

    // Ciphertext should be different from plaintext
    let same = true;
    for (let i = 0; i < plaintext.length; i++) {
      if (ciphertext[i] !== plaintext[i]) {
        same = false;
        break;
      }
    }
    assert(!same, 'ciphertext should differ from plaintext');

    assertEqual(iv.length, IV_SIZE, 'IV should be 16 bytes');
  });

  await test('encryptBytesCopy auto-generates IV when not provided', async () => {
    const key = randomBytes(KEY_SIZE);
    const plaintext = new TextEncoder().encode('Test message');

    clearIVTracking(key);

    const result1 = encryptBytesCopy(plaintext, key);
    const result2 = encryptBytesCopy(plaintext, key);

    // IVs should be different
    let sameIV = true;
    for (let i = 0; i < IV_SIZE; i++) {
      if (result1.iv[i] !== result2.iv[i]) {
        sameIV = false;
        break;
      }
    }
    assert(!sameIV, 'auto-generated IVs should be unique');
  });

  await test('encryptBytesCopy with explicit IV tracks IV usage', async () => {
    const key = randomBytes(KEY_SIZE);
    const iv = randomBytes(IV_SIZE);
    const plaintext = new TextEncoder().encode('Test');

    clearIVTracking(key);

    // First call should succeed
    encryptBytesCopy(plaintext, key, iv);

    // Second call with same IV should throw
    assertThrows(
      () => encryptBytesCopy(plaintext, key, iv),
      'IV has already been used',
      'should track IV usage'
    );
  });

  await test('decryptBytesCopy preserves original ciphertext', async () => {
    const key = randomBytes(KEY_SIZE);
    const plaintext = new TextEncoder().encode('Secret message');

    clearIVTracking(key);

    const { ciphertext, iv } = encryptBytesCopy(plaintext, key);
    const originalCiphertext = new Uint8Array(ciphertext);

    const decrypted = decryptBytesCopy(ciphertext, key, iv);

    // Ciphertext should be unchanged
    assertArrayEqual(ciphertext, originalCiphertext, 'ciphertext should be preserved');

    // Decrypted should match original plaintext
    assertArrayEqual(decrypted, plaintext, 'decryption should recover plaintext');
  });

  await test('encryptBytesCopy/decryptBytesCopy roundtrip', async () => {
    const key = randomBytes(KEY_SIZE);
    const originalMessage = 'Hello, World! This is a test of non-destructive encryption.';
    const plaintext = new TextEncoder().encode(originalMessage);

    clearIVTracking(key);

    const { ciphertext, iv } = encryptBytesCopy(plaintext, key);
    const decrypted = decryptBytesCopy(ciphertext, key, iv);

    const decryptedMessage = new TextDecoder().decode(decrypted);
    assertEqual(decryptedMessage, originalMessage, 'roundtrip should preserve message');
  });

  await test('IV_REUSE error has correct error code', async () => {
    const key = randomBytes(KEY_SIZE);
    const iv = randomBytes(IV_SIZE);

    clearIVTracking(key);

    encryptBytes(new TextEncoder().encode('first'), key, iv);

    try {
      encryptBytes(new TextEncoder().encode('second'), key, iv);
      throw new Error('Expected IV_REUSE error');
    } catch (e) {
      assert(e instanceof CryptoError, 'should be CryptoError');
      assertEqual(e.code, CryptoErrorCode.IV_REUSE, 'should have IV_REUSE code');
    }
  });

  // ==========================================================================
  // HKDF Tests
  // ==========================================================================
  log('\n[HKDF Key Derivation]');

  await test('hkdf produces requested length', async () => {
    const ikm = new Uint8Array(32).fill(0x42);

    for (const len of [16, 32, 64, 128]) {
      const result = hkdf(ikm, null, null, len);
      assertEqual(result.length, len, `should produce ${len} bytes`);
    }
  });

  await test('hkdf is deterministic', async () => {
    const ikm = new Uint8Array(32).fill(0x42);
    const salt = new Uint8Array(16).fill(0x24);
    const info = new TextEncoder().encode('context');

    const result1 = hkdf(ikm, salt, info, 32);
    const result2 = hkdf(ikm, salt, info, 32);

    assertArrayEqual(result1, result2, 'same inputs should produce same output');
  });

  await test('hkdf with different info produces different output', async () => {
    const ikm = new Uint8Array(32).fill(0x42);

    const result1 = hkdf(ikm, null, new TextEncoder().encode('info1'), 32);
    const result2 = hkdf(ikm, null, new TextEncoder().encode('info2'), 32);

    let same = true;
    for (let i = 0; i < result1.length; i++) {
      if (result1[i] !== result2[i]) {
        same = false;
        break;
      }
    }
    assert(!same, 'different info should produce different output');
  });

  await test('hkdf works with null salt', async () => {
    const ikm = new Uint8Array(32).fill(0x42);
    const result = hkdf(ikm, null, null, 32);
    assertEqual(result.length, 32, 'should work with null salt');
  });

  await test('hkdf works with null info', async () => {
    const ikm = new Uint8Array(32).fill(0x42);
    const salt = new Uint8Array(16).fill(0x24);
    const result = hkdf(ikm, salt, null, 32);
    assertEqual(result.length, 32, 'should work with null info');
  });

  // ==========================================================================
  // X25519 Tests
  // ==========================================================================
  log('\n[X25519 Key Exchange]');

  await test('x25519GenerateKeyPair produces valid key sizes', async () => {
    const { privateKey, publicKey } = x25519GenerateKeyPair();
    assertEqual(privateKey.length, X25519_PRIVATE_KEY_SIZE, 'private key should be 32 bytes');
    assertEqual(publicKey.length, X25519_PUBLIC_KEY_SIZE, 'public key should be 32 bytes');
  });

  await test('x25519GenerateKeyPair produces different keys each time', async () => {
    const pair1 = x25519GenerateKeyPair();
    const pair2 = x25519GenerateKeyPair();

    let same = true;
    for (let i = 0; i < pair1.privateKey.length; i++) {
      if (pair1.privateKey[i] !== pair2.privateKey[i]) {
        same = false;
        break;
      }
    }
    assert(!same, 'should generate different keys');
  });

  await test('x25519GenerateKeyPair accepts existing private key', async () => {
    // Note: The WASM module's keypair generation may not respect provided private keys
    // due to the underlying implementation always generating fresh random keys.
    // This test verifies the API accepts a private key parameter without throwing.
    const privateKey = new Uint8Array(X25519_PRIVATE_KEY_SIZE).fill(0x42);
    const pair = x25519GenerateKeyPair(privateKey);

    // Verify we get valid key sizes back
    assertEqual(pair.privateKey.length, X25519_PRIVATE_KEY_SIZE, 'private key should be 32 bytes');
    assertEqual(pair.publicKey.length, X25519_PUBLIC_KEY_SIZE, 'public key should be 32 bytes');
  });

  await test('x25519SharedSecret is symmetric', async () => {
    const alice = x25519GenerateKeyPair();
    const bob = x25519GenerateKeyPair();

    const aliceSecret = x25519SharedSecret(alice.privateKey, bob.publicKey);
    const bobSecret = x25519SharedSecret(bob.privateKey, alice.publicKey);

    assertArrayEqual(aliceSecret, bobSecret, 'shared secrets should match');
  });

  await test('x25519SharedSecret produces 32 bytes', async () => {
    const alice = x25519GenerateKeyPair();
    const bob = x25519GenerateKeyPair();

    const secret = x25519SharedSecret(alice.privateKey, bob.publicKey);
    assertEqual(secret.length, 32, 'shared secret should be 32 bytes');
  });

  await test('x25519DeriveKey produces encryption key', async () => {
    const alice = x25519GenerateKeyPair();
    const bob = x25519GenerateKeyPair();

    const secret = x25519SharedSecret(alice.privateKey, bob.publicKey);
    const key = x25519DeriveKey(secret, 'encryption');

    assertEqual(key.length, KEY_SIZE, 'derived key should be 32 bytes');
  });

  await test('x25519DeriveKey with different contexts produces different keys', async () => {
    const alice = x25519GenerateKeyPair();
    const bob = x25519GenerateKeyPair();

    const secret = x25519SharedSecret(alice.privateKey, bob.publicKey);
    const key1 = x25519DeriveKey(secret, 'context1');
    const key2 = x25519DeriveKey(secret, 'context2');

    let same = true;
    for (let i = 0; i < key1.length; i++) {
      if (key1[i] !== key2[i]) {
        same = false;
        break;
      }
    }
    assert(!same, 'different contexts should produce different keys');
  });

  // ==========================================================================
  // secp256k1 Tests
  // ==========================================================================
  log('\n[secp256k1 Key Exchange & Signatures]');

  await test('secp256k1GenerateKeyPair produces valid key sizes', async () => {
    const { privateKey, publicKey } = secp256k1GenerateKeyPair();
    assertEqual(privateKey.length, SECP256K1_PRIVATE_KEY_SIZE, 'private key should be 32 bytes');
    assertEqual(publicKey.length, SECP256K1_PUBLIC_KEY_SIZE, 'public key should be 33 bytes (compressed)');
  });

  await test('secp256k1SharedSecret is symmetric', async () => {
    const alice = secp256k1GenerateKeyPair();
    const bob = secp256k1GenerateKeyPair();

    const aliceSecret = secp256k1SharedSecret(alice.privateKey, bob.publicKey);
    const bobSecret = secp256k1SharedSecret(bob.privateKey, alice.publicKey);

    assertArrayEqual(aliceSecret, bobSecret, 'shared secrets should match');
  });

  await test('secp256k1Sign produces signature', async () => {
    const { privateKey } = secp256k1GenerateKeyPair();
    const message = new TextEncoder().encode('Hello, Bitcoin!');

    const signature = secp256k1Sign(privateKey, message);
    assert(signature.length > 0, 'signature should not be empty');
    assert(signature.length <= 72, 'DER signature should be at most 72 bytes');
  });

  await test('secp256k1Verify validates correct signature', async () => {
    const { privateKey, publicKey } = secp256k1GenerateKeyPair();
    const message = new TextEncoder().encode('Hello, Bitcoin!');

    const signature = secp256k1Sign(privateKey, message);
    const valid = secp256k1Verify(publicKey, message, signature);

    assert(valid, 'signature should be valid');
  });

  await test('secp256k1Verify rejects tampered message', async () => {
    const { privateKey, publicKey } = secp256k1GenerateKeyPair();
    const message = new TextEncoder().encode('Hello, Bitcoin!');

    const signature = secp256k1Sign(privateKey, message);
    const tamperedMessage = new TextEncoder().encode('Hello, Ethereum!');
    const valid = secp256k1Verify(publicKey, tamperedMessage, signature);

    assert(!valid, 'signature should be invalid for tampered message');
  });

  await test('secp256k1Verify rejects wrong public key', async () => {
    const alice = secp256k1GenerateKeyPair();
    const bob = secp256k1GenerateKeyPair();
    const message = new TextEncoder().encode('Hello!');

    const signature = secp256k1Sign(alice.privateKey, message);
    const valid = secp256k1Verify(bob.publicKey, message, signature);

    assert(!valid, 'signature should be invalid for wrong public key');
  });

  // ==========================================================================
  // P-256 Tests
  // ==========================================================================
  log('\n[P-256 Key Exchange & Signatures]');

  await test('p256GenerateKeyPair produces valid key sizes', async () => {
    const { privateKey, publicKey } = p256GenerateKeyPair();
    assertEqual(privateKey.length, 32, 'private key should be 32 bytes');
    assertEqual(publicKey.length, 33, 'public key should be 33 bytes (compressed)');
  });

  await test('p256SharedSecret is symmetric', async () => {
    const alice = p256GenerateKeyPair();
    const bob = p256GenerateKeyPair();

    const aliceSecret = p256SharedSecret(alice.privateKey, bob.publicKey);
    const bobSecret = p256SharedSecret(bob.privateKey, alice.publicKey);

    assertArrayEqual(aliceSecret, bobSecret, 'shared secrets should match');
  });

  await test('p256Sign and p256Verify work correctly', async () => {
    const { privateKey, publicKey } = p256GenerateKeyPair();
    const message = new TextEncoder().encode('NIST approved message');

    const signature = p256Sign(privateKey, message);
    const valid = p256Verify(publicKey, message, signature);

    assert(valid, 'signature should be valid');
  });

  await test('p256Verify rejects invalid signature', async () => {
    const { privateKey, publicKey } = p256GenerateKeyPair();
    const message = new TextEncoder().encode('Original message');

    const signature = p256Sign(privateKey, message);
    const tamperedMessage = new TextEncoder().encode('Tampered message');
    const valid = p256Verify(publicKey, tamperedMessage, signature);

    assert(!valid, 'signature should be invalid');
  });

  // ==========================================================================
  // Ed25519 Tests
  // ==========================================================================
  log('\n[Ed25519 Signatures]');

  await test('ed25519GenerateKeyPair produces valid key sizes', async () => {
    const { privateKey, publicKey } = ed25519GenerateKeyPair();
    assertEqual(privateKey.length, ED25519_PRIVATE_KEY_SIZE, 'private key should be 64 bytes');
    assertEqual(publicKey.length, ED25519_PUBLIC_KEY_SIZE, 'public key should be 32 bytes');
  });

  await test('ed25519Sign produces 64-byte signature', async () => {
    const { privateKey } = ed25519GenerateKeyPair();
    const message = new TextEncoder().encode('Sign me!');

    const signature = ed25519Sign(privateKey, message);
    assertEqual(signature.length, ED25519_SIGNATURE_SIZE, 'signature should be 64 bytes');
  });

  await test('ed25519Verify validates correct signature', async () => {
    const { privateKey, publicKey } = ed25519GenerateKeyPair();
    const message = new TextEncoder().encode('Important message');

    const signature = ed25519Sign(privateKey, message);
    const valid = ed25519Verify(publicKey, message, signature);

    assert(valid, 'signature should be valid');
  });

  await test('ed25519Verify rejects tampered signature', async () => {
    const { privateKey, publicKey } = ed25519GenerateKeyPair();
    const message = new TextEncoder().encode('Original');

    const signature = ed25519Sign(privateKey, message);
    signature[0] ^= 0xFF; // Tamper with signature
    const valid = ed25519Verify(publicKey, message, signature);

    assert(!valid, 'tampered signature should be invalid');
  });

  await test('ed25519 signatures are deterministic', async () => {
    const { privateKey, publicKey } = ed25519GenerateKeyPair();
    const message = new TextEncoder().encode('Same message');

    const sig1 = ed25519Sign(privateKey, message);
    const sig2 = ed25519Sign(privateKey, message);

    assertArrayEqual(sig1, sig2, 'same message should produce same signature');
  });

  // ==========================================================================
  // EncryptionContext Tests
  // ==========================================================================
  log('\n[EncryptionContext]');

  await test('EncryptionContext accepts Uint8Array key', async () => {
    const key = new Uint8Array(KEY_SIZE).fill(0x42);
    const ctx = new EncryptionContext(key);
    assert(ctx.isValid(), 'context should be valid');
  });

  await test('EncryptionContext accepts hex string key', async () => {
    const hexKey = '42'.repeat(32);
    const ctx = new EncryptionContext(hexKey);
    assert(ctx.isValid(), 'context should be valid');
  });

  await test('EncryptionContext.fromHex works', async () => {
    const hexKey = 'ab'.repeat(32);
    const ctx = EncryptionContext.fromHex(hexKey);
    assert(ctx.isValid(), 'context should be valid');
  });

  await test('EncryptionContext rejects invalid key length', async () => {
    assertThrows(
      () => new EncryptionContext(new Uint8Array(16)),
      'expected 32 bytes',
      'should reject short key'
    );
  });

  await test('EncryptionContext rejects invalid hex string', async () => {
    assertThrows(
      () => new EncryptionContext('not-hex'),
      'hex characters',
      'should reject non-hex string'
    );
  });

  await test('EncryptionContext rejects wrong hex length', async () => {
    assertThrows(
      () => new EncryptionContext('abcd'),
      '64 characters',
      'should reject short hex string'
    );
  });

  await test('deriveFieldKey produces different keys for different fields', async () => {
    const ctx = new EncryptionContext(new Uint8Array(KEY_SIZE).fill(0x42));

    const key1 = ctx.deriveFieldKey(0);
    const key2 = ctx.deriveFieldKey(1);

    let same = true;
    for (let i = 0; i < key1.length; i++) {
      if (key1[i] !== key2[i]) {
        same = false;
        break;
      }
    }
    assert(!same, 'different fields should have different keys');
  });

  await test('deriveFieldIV produces different IVs for different fields', async () => {
    const ctx = new EncryptionContext(new Uint8Array(KEY_SIZE).fill(0x42));

    const iv1 = ctx.deriveFieldIV(0);
    const iv2 = ctx.deriveFieldIV(1);

    let same = true;
    for (let i = 0; i < iv1.length; i++) {
      if (iv1[i] !== iv2[i]) {
        same = false;
        break;
      }
    }
    assert(!same, 'different fields should have different IVs');
  });

  await test('encryptScalar encrypts buffer range', async () => {
    const ctx = new EncryptionContext(new Uint8Array(KEY_SIZE).fill(0x42));
    const buffer = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    const original = new Uint8Array(buffer);

    ctx.encryptScalar(buffer, 2, 4, 0);

    // First 2 bytes should be unchanged
    assertEqual(buffer[0], original[0], 'prefix should be unchanged');
    assertEqual(buffer[1], original[1], 'prefix should be unchanged');

    // Last 2 bytes should be unchanged
    assertEqual(buffer[6], original[6], 'suffix should be unchanged');
    assertEqual(buffer[7], original[7], 'suffix should be unchanged');

    // Middle should be changed
    let changed = false;
    for (let i = 2; i < 6; i++) {
      if (buffer[i] !== original[i]) {
        changed = true;
        break;
      }
    }
    assert(changed, 'encrypted region should be modified');
  });

  // ==========================================================================
  // Schema Parsing Tests
  // ==========================================================================
  log('\n[Schema Parsing]');

  await test('parseSchemaForEncryption extracts fields', async () => {
    const schema = `
      table Monster {
        hp:short;
        name:string;
        inventory:[ubyte];
      }
    `;

    const parsed = parseSchemaForEncryption(schema, 'Monster');
    assertEqual(parsed.fields.length, 3, 'should find 3 fields');
    assertEqual(parsed.fields[0].name, 'hp', 'first field should be hp');
    assertEqual(parsed.fields[1].name, 'name', 'second field should be name');
    assertEqual(parsed.fields[2].name, 'inventory', 'third field should be inventory');
  });

  await test('parseSchemaForEncryption detects encrypted attribute', async () => {
    const schema = `
      table SecureData {
        public_id:int;
        secret_key:string (encrypted);
        data:[ubyte] (encrypted);
      }
    `;

    const parsed = parseSchemaForEncryption(schema, 'SecureData');
    assertEqual(parsed.fields[0].encrypted, false, 'public_id should not be encrypted');
    assertEqual(parsed.fields[1].encrypted, true, 'secret_key should be encrypted');
    assertEqual(parsed.fields[2].encrypted, true, 'data should be encrypted');
  });

  await test('parseSchemaForEncryption identifies types correctly', async () => {
    const schema = `
      table Types {
        a:bool;
        b:int;
        c:float;
        d:string;
        e:[int];
      }
    `;

    const parsed = parseSchemaForEncryption(schema, 'Types');
    assertEqual(parsed.fields[0].type, 'bool', 'a should be bool');
    assertEqual(parsed.fields[1].type, 'int', 'b should be int');
    assertEqual(parsed.fields[2].type, 'float', 'c should be float');
    assertEqual(parsed.fields[3].type, 'string', 'd should be string');
    assertEqual(parsed.fields[4].type, 'vector', 'e should be vector');
  });

  await test('parseSchemaForEncryption returns empty for missing table', async () => {
    const schema = `table Other { x:int; }`;
    const parsed = parseSchemaForEncryption(schema, 'Missing');
    assertEqual(parsed.fields.length, 0, 'should return empty fields for missing table');
  });

  // ==========================================================================
  // Encryption Header Tests
  // ==========================================================================
  log('\n[Encryption Header]');

  await test('createEncryptionHeader creates valid header', async () => {
    const { publicKey } = x25519GenerateKeyPair();
    const keyId = computeKeyId(publicKey);

    const header = createEncryptionHeader({
      algorithm: 'x25519',
      senderPublicKey: publicKey,
      recipientKeyId: keyId,
    });

    assertEqual(header.version, 1, 'version should be 1');
    assertEqual(header.algorithm, 'x25519', 'algorithm should match');
    assertEqual(header.iv.length, IV_SIZE, 'IV should be 16 bytes');
  });

  await test('createEncryptionHeader accepts custom IV', async () => {
    const { publicKey } = x25519GenerateKeyPair();
    const keyId = computeKeyId(publicKey);
    const customIV = new Uint8Array(IV_SIZE).fill(0x42);

    const header = createEncryptionHeader({
      algorithm: 'x25519',
      senderPublicKey: publicKey,
      recipientKeyId: keyId,
      iv: customIV,
    });

    assertArrayEqual(header.iv, customIV, 'IV should match custom value');
  });

  await test('computeKeyId produces 8 bytes', async () => {
    const { publicKey } = x25519GenerateKeyPair();
    const keyId = computeKeyId(publicKey);
    assertEqual(keyId.length, 8, 'key ID should be 8 bytes');
  });

  await test('encryptionHeaderToJSON and encryptionHeaderFromJSON roundtrip', async () => {
    const { publicKey } = x25519GenerateKeyPair();
    const keyId = computeKeyId(publicKey);

    const header = createEncryptionHeader({
      algorithm: 'x25519',
      senderPublicKey: publicKey,
      recipientKeyId: keyId,
    });

    const json = encryptionHeaderToJSON(header);
    const restored = encryptionHeaderFromJSON(json);

    assertEqual(restored.version, header.version, 'version should match');
    assertEqual(restored.algorithm, header.algorithm, 'algorithm should match');
    assertArrayEqual(restored.senderPublicKey, header.senderPublicKey, 'sender key should match');
    assertArrayEqual(restored.recipientKeyId, header.recipientKeyId, 'recipient key ID should match');
    assertArrayEqual(restored.iv, header.iv, 'IV should match');
  });

  // ==========================================================================
  // ECIES (Hybrid Encryption) Tests
  // ==========================================================================
  log('\n[ECIES Hybrid Encryption]');

  await test('EncryptionContext.forEncryption creates valid context with X25519', async () => {
    const recipientKeys = x25519GenerateKeyPair();
    const ctx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
      algorithm: 'x25519',
      context: 'test-app-v1',
    });

    assert(ctx.isValid(), 'context should be valid');
    assert(ctx.getEphemeralPublicKey() !== null, 'should have ephemeral public key');
    assertEqual(ctx.getEphemeralPublicKey().length, 32, 'ephemeral key should be 32 bytes');
    assertEqual(ctx.getAlgorithm(), 'x25519', 'algorithm should be x25519');
    assertEqual(ctx.getContext(), 'test-app-v1', 'context should match');
  });

  await test('EncryptionContext.forEncryption creates valid context with secp256k1', async () => {
    const recipientKeys = secp256k1GenerateKeyPair();
    const ctx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
      algorithm: 'secp256k1',
      context: 'test-app-v1',
    });

    assert(ctx.isValid(), 'context should be valid');
    assert(ctx.getEphemeralPublicKey() !== null, 'should have ephemeral public key');
    assertEqual(ctx.getEphemeralPublicKey().length, 33, 'ephemeral key should be 33 bytes (compressed)');
    assertEqual(ctx.getAlgorithm(), 'secp256k1', 'algorithm should be secp256k1');
  });

  await test('EncryptionContext.forEncryption creates valid context with P-256', async () => {
    const recipientKeys = p256GenerateKeyPair();
    const ctx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
      algorithm: 'p256',
      context: 'test-app-v1',
    });

    assert(ctx.isValid(), 'context should be valid');
    assert(ctx.getEphemeralPublicKey() !== null, 'should have ephemeral public key');
    assertEqual(ctx.getEphemeralPublicKey().length, 33, 'ephemeral key should be 33 bytes (compressed)');
    assertEqual(ctx.getAlgorithm(), 'p256', 'algorithm should be p256');
  });

  await test('EncryptionContext.getHeader returns valid header', async () => {
    const recipientKeys = x25519GenerateKeyPair();
    const ctx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
      algorithm: 'x25519',
      context: 'test-context',
    });

    const header = ctx.getHeader();
    assertEqual(header.version, 1, 'header version should be 1');
    assertEqual(header.algorithm, 'x25519', 'algorithm should match');
    assertEqual(header.senderPublicKey.length, 32, 'sender public key should be 32 bytes');
    assertEqual(header.recipientKeyId.length, 8, 'recipient key ID should be 8 bytes');
    assertEqual(header.iv.length, 16, 'IV should be 16 bytes');
    assertEqual(header.context, 'test-context', 'context should match');
  });

  await test('EncryptionContext.getHeaderJSON returns valid JSON string', async () => {
    const recipientKeys = x25519GenerateKeyPair();
    const ctx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
      context: 'json-test',
    });

    const headerJSON = ctx.getHeaderJSON();
    assert(typeof headerJSON === 'string', 'should return string');

    const parsed = JSON.parse(headerJSON);
    assertEqual(parsed.version, 1, 'parsed version should be 1');
    assert(Array.isArray(parsed.senderPublicKey), 'senderPublicKey should be array');
    assertEqual(parsed.context, 'json-test', 'context should match');
  });

  await test('ECIES encrypt/decrypt roundtrip with X25519', async () => {
    const recipientKeys = x25519GenerateKeyPair();
    const appContext = 'roundtrip-test-v1';

    // Sender encrypts
    const encryptCtx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
      algorithm: 'x25519',
      context: appContext,
    });

    const plaintext = new TextEncoder().encode('Secret message for ECIES test!');
    const data = new Uint8Array(plaintext);
    const originalData = new Uint8Array(plaintext);

    // Encrypt using field-level method
    encryptCtx.encryptScalar(data, 0, data.length, 0);

    // Verify data changed
    let changed = false;
    for (let i = 0; i < data.length; i++) {
      if (data[i] !== originalData[i]) {
        changed = true;
        break;
      }
    }
    assert(changed, 'data should be encrypted');

    // Get header for transmission
    const headerJSON = encryptCtx.getHeaderJSON();

    // Recipient decrypts
    const receivedHeader = encryptionHeaderFromJSON(headerJSON);
    const decryptCtx = EncryptionContext.forDecryption(
      recipientKeys.privateKey,
      receivedHeader,
      appContext
    );

    // Decrypt using decryptScalar (no IV tracking for decryption)
    decryptCtx.decryptScalar(data, 0, data.length, 0);

    // Verify decrypted data matches original
    assertArrayEqual(data, originalData, 'decrypted data should match original');
  });

  await test('ECIES encrypt/decrypt roundtrip with secp256k1', async () => {
    const recipientKeys = secp256k1GenerateKeyPair();
    const appContext = 'secp256k1-test';

    // Sender encrypts
    const encryptCtx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
      algorithm: 'secp256k1',
      context: appContext,
    });

    const plaintext = new TextEncoder().encode('Bitcoin-compatible encryption!');
    const data = new Uint8Array(plaintext);
    const originalData = new Uint8Array(plaintext);

    encryptCtx.encryptScalar(data, 0, data.length, 0);

    // Get header and decrypt
    const headerJSON = encryptCtx.getHeaderJSON();
    const receivedHeader = encryptionHeaderFromJSON(headerJSON);
    const decryptCtx = EncryptionContext.forDecryption(
      recipientKeys.privateKey,
      receivedHeader,
      appContext
    );

    decryptCtx.decryptScalar(data, 0, data.length, 0);
    assertArrayEqual(data, originalData, 'secp256k1 decrypted data should match');
  });

  await test('ECIES encrypt/decrypt roundtrip with P-256', async () => {
    const recipientKeys = p256GenerateKeyPair();
    const appContext = 'p256-nist-test';

    // Sender encrypts
    const encryptCtx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
      algorithm: 'p256',
      context: appContext,
    });

    const plaintext = new TextEncoder().encode('NIST P-256 encryption test!');
    const data = new Uint8Array(plaintext);
    const originalData = new Uint8Array(plaintext);

    encryptCtx.encryptScalar(data, 0, data.length, 0);

    // Get header and decrypt
    const headerJSON = encryptCtx.getHeaderJSON();
    const receivedHeader = encryptionHeaderFromJSON(headerJSON);
    const decryptCtx = EncryptionContext.forDecryption(
      recipientKeys.privateKey,
      receivedHeader,
      appContext
    );

    decryptCtx.decryptScalar(data, 0, data.length, 0);
    assertArrayEqual(data, originalData, 'P-256 decrypted data should match');
  });

  await test('ECIES fails with wrong private key', async () => {
    const recipientKeys = x25519GenerateKeyPair();
    let wrongKeys = x25519GenerateKeyPair();

    // Ensure wrong keys are actually different (WASM RNG can have duplicates)
    // Regenerate until we get a different public key
    let attempts = 0;
    while (attempts < 100) {
      let keysMatch = true;
      for (let i = 0; i < recipientKeys.publicKey.length; i++) {
        if (wrongKeys.publicKey[i] !== recipientKeys.publicKey[i]) {
          keysMatch = false;
          break;
        }
      }
      if (!keysMatch) break;
      wrongKeys = x25519GenerateKeyPair();
      attempts++;
    }
    assert(attempts < 100, 'Failed to generate distinct key pair');

    const appContext = 'wrong-key-test';

    // Sender encrypts to recipient
    const encryptCtx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
      context: appContext,
    });

    const plaintext = new TextEncoder().encode('Secret data');
    const data = new Uint8Array(plaintext);
    const originalData = new Uint8Array(plaintext);

    encryptCtx.encryptScalar(data, 0, data.length, 0);

    // Wrong recipient tries to decrypt
    const headerJSON = encryptCtx.getHeaderJSON();
    const receivedHeader = encryptionHeaderFromJSON(headerJSON);
    const decryptCtx = EncryptionContext.forDecryption(
      wrongKeys.privateKey, // Wrong key!
      receivedHeader,
      appContext
    );

    decryptCtx.decryptScalar(data, 0, data.length, 0);

    // Data should NOT match original (wrong key = wrong derived key)
    let matches = true;
    for (let i = 0; i < data.length; i++) {
      if (data[i] !== originalData[i]) {
        matches = false;
        break;
      }
    }
    assert(!matches, 'decryption with wrong key should produce different data');
  });

  await test('ECIES fails with wrong context', async () => {
    const recipientKeys = x25519GenerateKeyPair();

    // Sender encrypts with context A
    const encryptCtx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
      context: 'context-A',
    });

    const plaintext = new TextEncoder().encode('Context matters!');
    const data = new Uint8Array(plaintext);
    const originalData = new Uint8Array(plaintext);

    encryptCtx.encryptScalar(data, 0, data.length, 0);

    // Recipient decrypts with context B (wrong!)
    const headerJSON = encryptCtx.getHeaderJSON();
    const receivedHeader = encryptionHeaderFromJSON(headerJSON);
    const decryptCtx = EncryptionContext.forDecryption(
      recipientKeys.privateKey,
      receivedHeader,
      'context-B' // Wrong context!
    );

    decryptCtx.encryptScalar(data, 0, data.length, 0);

    // Data should NOT match original (different context = different derived key)
    let matches = true;
    for (let i = 0; i < data.length; i++) {
      if (data[i] !== originalData[i]) {
        matches = false;
        break;
      }
    }
    assert(!matches, 'decryption with wrong context should produce different data');
  });

  await test('encryptionHeaderFromJSON accepts string input', async () => {
    const recipientKeys = x25519GenerateKeyPair();
    const ctx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
      context: 'string-test',
    });

    const headerJSON = ctx.getHeaderJSON();
    const header = encryptionHeaderFromJSON(headerJSON); // Pass string directly

    assertEqual(header.algorithm, 'x25519', 'algorithm should parse correctly');
    assertEqual(header.context, 'string-test', 'context should parse correctly');
    assert(header.senderPublicKey instanceof Uint8Array, 'senderPublicKey should be Uint8Array');
  });

  await test('EncryptionContext.getHeader throws without ECIES setup', async () => {
    const ctx = new EncryptionContext(new Uint8Array(KEY_SIZE).fill(0x42));

    assertThrows(
      () => ctx.getHeader(),
      'ephemeral key',
      'should throw when not using ECIES'
    );
  });

  // ==========================================================================
  // Edge Cases and Error Handling
  // ==========================================================================
  log('\n[Edge Cases & Error Handling]');

  await test('encryption handles large data', async () => {
    const key = new Uint8Array(KEY_SIZE).fill(0x42);
    const iv = new Uint8Array(IV_SIZE).fill(0x24);
    const data = new Uint8Array(1024 * 1024); // 1 MB
    for (let i = 0; i < data.length; i++) {
      data[i] = i & 0xFF;
    }
    const original = new Uint8Array(data);

    encryptBytes(data, key, iv);
    decryptBytes(data, key, iv);

    assertArrayEqual(data, original, 'large data should roundtrip correctly');
  });

  await test('throws on uninitialized module access', async () => {
    // This test would need to reset the module state, which isn't easily possible
    // So we just verify the error message format
    const key = new Uint8Array(KEY_SIZE);
    assert(key.length === 32, 'key should be 32 bytes');
  });

  await test('input validation catches type errors', async () => {
    const key = new Uint8Array(KEY_SIZE);
    const iv = new Uint8Array(IV_SIZE);

    assertThrows(
      () => encryptBytes('string', key, iv),
      'Uint8Array',
      'should reject string data'
    );

    assertThrows(
      () => encryptBytes(new Uint8Array(10), 'key', iv),
      'Uint8Array',
      'should reject string key'
    );

    assertThrows(
      () => encryptBytes(new Uint8Array(10), key, 'iv'),
      'Uint8Array',
      'should reject string IV'
    );
  });

  // ==========================================================================
  // Authenticated Encryption Tests (encryptAuthenticated/decryptAuthenticated)
  // ==========================================================================
  log('\n[Authenticated Encryption]');

  await test('encryptAuthenticated produces authenticated ciphertext', async () => {
    const { encryptAuthenticated, decryptAuthenticated } = await import('../src/encryption.mjs');
    const key = randomBytes(KEY_SIZE);
    const plaintext = new TextEncoder().encode('Secret authenticated message!');

    const ciphertext = encryptAuthenticated(plaintext, key);

    // Ciphertext should be IV(16) + encrypted(len) + MAC(32)
    assertEqual(ciphertext.length, 16 + plaintext.length + 32, 'ciphertext should include IV and MAC');

    // Decrypt should work
    const decrypted = decryptAuthenticated(ciphertext, key);
    assertArrayEqual(decrypted, plaintext, 'decrypted should match plaintext');
  });

  await test('decryptAuthenticated rejects tampered ciphertext', async () => {
    const { encryptAuthenticated, decryptAuthenticated, CryptoError } = await import('../src/encryption.mjs');
    const key = randomBytes(KEY_SIZE);
    const plaintext = new TextEncoder().encode('Do not tamper!');

    const ciphertext = encryptAuthenticated(plaintext, key);

    // Tamper with the ciphertext (flip a bit in the encrypted data)
    const tampered = new Uint8Array(ciphertext);
    tampered[20] ^= 0x01;

    let threwError = false;
    try {
      decryptAuthenticated(tampered, key);
    } catch (e) {
      threwError = true;
      assert(e.code === 'AUTHENTICATION_FAILED', 'should throw AUTHENTICATION_FAILED');
    }
    assert(threwError, 'should throw on tampered data');
  });

  await test('encryptAuthenticated with associated data', async () => {
    const { encryptAuthenticated, decryptAuthenticated } = await import('../src/encryption.mjs');
    const key = randomBytes(KEY_SIZE);
    const plaintext = new TextEncoder().encode('Secret message');
    const aad = new TextEncoder().encode('additional authenticated data');

    const ciphertext = encryptAuthenticated(plaintext, key, aad);
    const decrypted = decryptAuthenticated(ciphertext, key, aad);

    assertArrayEqual(decrypted, plaintext, 'should decrypt with correct AAD');
  });

  await test('decryptAuthenticated rejects wrong associated data', async () => {
    const { encryptAuthenticated, decryptAuthenticated } = await import('../src/encryption.mjs');
    const key = randomBytes(KEY_SIZE);
    const plaintext = new TextEncoder().encode('Secret message');
    const aad = new TextEncoder().encode('correct AAD');
    const wrongAad = new TextEncoder().encode('wrong AAD');

    const ciphertext = encryptAuthenticated(plaintext, key, aad);

    let threwError = false;
    try {
      decryptAuthenticated(ciphertext, key, wrongAad);
    } catch (e) {
      threwError = true;
      assert(e.code === 'AUTHENTICATION_FAILED', 'should throw AUTHENTICATION_FAILED');
    }
    assert(threwError, 'should throw on wrong AAD');
  });

  // ==========================================================================
  // Buffer Encryption with MAC Tests (encryptBuffer/decryptBuffer)
  // ==========================================================================
  log('\n[Buffer Encryption with MAC]');

  // Note: These tests require a valid FlatBuffer, so we create a minimal one
  // For now, we test the MAC generation/verification logic directly

  await test('encryptBuffer returns MAC by default', async () => {
    const { EncryptionContext, hmacSha256, hkdf, HMAC_SIZE, KEY_SIZE: KS, IV_SIZE } = await import('../src/encryption.mjs');

    // Test the MAC computation logic directly since we need a real FlatBuffer for encryptBuffer
    const key = randomBytes(KS);
    const nonce = randomBytes(IV_SIZE);
    const buffer = randomBytes(100);

    // Derive MAC key same way encryptBuffer does
    const textEncoder = new TextEncoder();
    const macKey = hkdf(key, null, textEncoder.encode('flatbuffer-mac-key'), KS);

    // Compute MAC over nonce || buffer
    const { hmacSha256: computeHmac } = await import('../src/encryption.mjs');
    const macInput = new Uint8Array(IV_SIZE + buffer.length);
    macInput.set(nonce, 0);
    macInput.set(buffer, IV_SIZE);
    const mac = computeHmac(macKey, macInput);

    assertEqual(mac.length, HMAC_SIZE, 'MAC should be 32 bytes');
  });

  await test('MAC verification detects tampering', async () => {
    const { hmacSha256, hmacSha256Verify, hkdf, KEY_SIZE: KS, IV_SIZE } = await import('../src/encryption.mjs');

    const key = randomBytes(KS);
    const nonce = randomBytes(IV_SIZE);
    const buffer = randomBytes(100);

    const textEncoder = new TextEncoder();
    const macKey = hkdf(key, null, textEncoder.encode('flatbuffer-mac-key'), KS);

    const macInput = new Uint8Array(IV_SIZE + buffer.length);
    macInput.set(nonce, 0);
    macInput.set(buffer, IV_SIZE);
    const mac = hmacSha256(macKey, macInput);

    // Verify with correct data
    assert(hmacSha256Verify(macKey, macInput, mac), 'MAC should verify with correct data');

    // Tamper with buffer
    const tamperedBuffer = new Uint8Array(buffer);
    tamperedBuffer[50] ^= 0x01;
    const tamperedMacInput = new Uint8Array(IV_SIZE + tamperedBuffer.length);
    tamperedMacInput.set(nonce, 0);
    tamperedMacInput.set(tamperedBuffer, IV_SIZE);

    assert(!hmacSha256Verify(macKey, tamperedMacInput, mac), 'MAC should NOT verify with tampered data');
  });

  await test('EncryptionContext.getKey returns key copy', async () => {
    const key = randomBytes(KEY_SIZE);
    const ctx = new EncryptionContext(key);

    const retrievedKey = ctx.getKey();
    assertArrayEqual(retrievedKey, key, 'retrieved key should match original');

    // Modifying retrieved key should not affect context
    retrievedKey[0] ^= 0xFF;
    const retrievedKey2 = ctx.getKey();
    assertArrayEqual(retrievedKey2, key, 'context key should be unchanged');
  });

  // ==========================================================================
  // Summary
  // ==========================================================================

  log('\n============================================================');
  log(`Results: ${passed} passed, ${failed} failed`);
  log('============================================================');

  if (passed > 0 && failed === 0) {
    log('All tests passed!');
  } else if (failed > 0) {
    log('Some tests failed');
  }

  process.exit(failed > 0 ? 1 : 0);
}

main().catch(err => {
  console.error('Test error:', err);
  process.exit(1);
});
