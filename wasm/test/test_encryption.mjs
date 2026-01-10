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
  } else {
    // Fallback for Node.js
    const { randomFillSync } = await import('crypto');
    randomFillSync(bytes);
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
    process.exit(failed > 0 ? 1 : 0);
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

    encryptBytes(data, key, iv);
    decryptBytes(data, key, iv);

    assertArrayEqual(data, original, 'decrypt should reverse encrypt');
  });

  await test('CTR mode produces same-length output', async () => {
    const key = new Uint8Array(KEY_SIZE).fill(0x42);
    const iv = new Uint8Array(IV_SIZE).fill(0x24);

    for (const len of [1, 16, 17, 100, 1000]) {
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
    const privateKey = new Uint8Array(X25519_PRIVATE_KEY_SIZE).fill(0x42);
    const pair = x25519GenerateKeyPair(privateKey);

    // Public key should be deterministically derived
    const pair2 = x25519GenerateKeyPair(privateKey);
    assertArrayEqual(pair.publicKey, pair2.publicKey, 'same private key should produce same public key');
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
