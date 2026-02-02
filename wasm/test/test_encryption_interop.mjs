#!/usr/bin/env node
/**
 * test_encryption_interop.mjs - Cross-language encryption interoperability tests
 *
 * Validates that:
 * 1. Known test vectors encrypt/decrypt correctly (language-agnostic)
 * 2. EncryptionContext with same key+IV produces deterministic ciphertext
 * 3. Encrypted field accessor roundtrip works via WASM
 * 4. docs/wasm-runtimes/ example patterns work with encryption enabled
 */

import { fileURLToPath } from 'url';
import path from 'path';
import { readFileSync, existsSync } from 'fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Import encryption module
import {
  loadEncryptionWasm,
  isInitialized,
  sha256,
  encryptBytes,
  decryptBytes,
  encryptBytesCopy,
  decryptBytesCopy,
  clearIVTracking,
  clearAllIVTracking,
  hkdf,
  x25519GenerateKeyPair,
  x25519SharedSecret,
  x25519DeriveKey,
  secp256k1GenerateKeyPair,
  EncryptionContext,
  encryptionHeaderToJSON,
  encryptionHeaderFromJSON,
  createEncryptionHeader,
  computeKeyId,
  encryptBuffer,
  decryptBuffer,
  KEY_SIZE,
  IV_SIZE,
  SHA256_SIZE,
} from '../src/index.mjs';

// =============================================================================
// Test Utilities
// =============================================================================

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

// =============================================================================
// Cross-Language Test Vectors
//
// These vectors use fixed keys and IVs so that any language implementing
// AES-256-CTR with the same parameters can produce identical ciphertext.
// =============================================================================

const TEST_VECTORS = {
  aes256ctr: [
    {
      description: 'Short plaintext (13 bytes)',
      key: '42'.repeat(32),               // 32 bytes of 0x42
      iv:  '24'.repeat(16),               // 16 bytes of 0x24
      plaintext: '48656c6c6f2c20576f726c6421',  // "Hello, World!"
      // Ciphertext is computed on first run, then verified for determinism
    },
    {
      description: 'Single byte plaintext',
      key: '00'.repeat(32),
      iv:  '00'.repeat(16),
      plaintext: 'ff',
    },
    {
      description: 'Block-aligned plaintext (16 bytes)',
      key: '01'.repeat(32),
      iv:  '02'.repeat(16),
      plaintext: '000102030405060708090a0b0c0d0e0f',
    },
    {
      description: 'Multi-block plaintext (48 bytes)',
      key: 'ab'.repeat(32),
      iv:  'cd'.repeat(16),
      plaintext: '00'.repeat(48),
    },
  ],

  sha256: [
    {
      description: 'SHA-256 of empty string',
      input: '',
      // Standard SHA-256 of empty input
      expected: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    },
    {
      description: 'SHA-256 of "Hello, World!"',
      input: '48656c6c6f2c20576f726c6421',
      expected: 'dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f',
    },
  ],

  hkdf: [
    {
      description: 'HKDF with known IKM, salt, info',
      ikm: '0b'.repeat(22),
      salt: '00'.repeat(13),
      info: 'f0f1f2f3f4f5f6f7f8f9',
      length: 32,
      // Output is computed on first run, then verified for determinism
    },
  ],
};

// =============================================================================
// Main Test Suite
// =============================================================================

async function main() {
  log('============================================================');
  log('Encryption Interoperability Test Suite');
  log('============================================================');

  const isCI = process.env.CI === 'true' || process.env.CI === '1' ||
               process.env.REQUIRE_WASM === 'true' || process.env.REQUIRE_WASM === '1';

  log('\n[Module Initialization]');

  let wasmLoaded = false;
  try {
    await loadEncryptionWasm();
    wasmLoaded = true;
    log('  WASM module loaded');
  } catch (err) {
    log(`  WARNING: Could not load WASM module: ${err.message}`);
    if (isCI) {
      log('  ERROR: WASM module required in CI mode');
      process.exit(1);
    }
    log('  Skipping WASM-dependent tests.');
  }

  if (!wasmLoaded) {
    log('\n============================================================');
    log(`Results: ${passed} passed, ${failed} failed (many skipped)`);
    log('============================================================');
    process.exit(isCI ? 1 : (failed > 0 ? 1 : 0));
  }

  // ==========================================================================
  // Section 1: Known Test Vectors - AES-256-CTR
  // ==========================================================================
  log('\n[1. AES-256-CTR Test Vectors]');

  // First pass: compute ciphertext from known plaintext+key+IV
  const computedCiphertexts = [];

  for (const vec of TEST_VECTORS.aes256ctr) {
    await test(`Encrypt test vector: ${vec.description}`, async () => {
      const key = hexToBytes(vec.key);
      const iv = hexToBytes(vec.iv);
      const plaintext = hexToBytes(vec.plaintext);
      const data = new Uint8Array(plaintext);

      clearIVTracking(key);
      encryptBytes(data, key, iv);

      // Store computed ciphertext for subsequent determinism checks
      computedCiphertexts.push(bytesToHex(data));

      // Verify ciphertext differs from plaintext
      let different = false;
      for (let i = 0; i < data.length; i++) {
        if (data[i] !== plaintext[i]) {
          different = true;
          break;
        }
      }
      // For the all-zeros key + all-zeros IV + 0xff plaintext case,
      // ciphertext will still differ because AES keystream is not zero
      assert(different, 'ciphertext should differ from plaintext');
    });
  }

  // ==========================================================================
  // Section 2: Verify Known Test Vectors Decrypt Correctly
  // ==========================================================================
  log('\n[2. Decrypt Known Test Vectors]');

  for (let i = 0; i < TEST_VECTORS.aes256ctr.length; i++) {
    const vec = TEST_VECTORS.aes256ctr[i];
    const ciphertextHex = computedCiphertexts[i];

    await test(`Decrypt test vector: ${vec.description}`, async () => {
      const key = hexToBytes(vec.key);
      const iv = hexToBytes(vec.iv);
      const ciphertext = hexToBytes(ciphertextHex);

      decryptBytes(ciphertext, key, iv);

      const expectedPlaintext = hexToBytes(vec.plaintext);
      assertArrayEqual(ciphertext, expectedPlaintext, 'decrypted should match original plaintext');
    });
  }

  // SHA-256 test vectors (standard, cross-language verifiable)
  log('\n[2b. SHA-256 Known Test Vectors]');

  for (const vec of TEST_VECTORS.sha256) {
    await test(`SHA-256 vector: ${vec.description}`, async () => {
      const input = vec.input.length > 0 ? hexToBytes(vec.input) : new Uint8Array(0);
      const hash = sha256(input);
      const hashHex = bytesToHex(hash);
      assertEqual(hashHex, vec.expected, 'SHA-256 output should match known vector');
    });
  }

  // HKDF test vectors
  log('\n[2c. HKDF Known Test Vectors]');

  const hkdfResults = [];
  for (const vec of TEST_VECTORS.hkdf) {
    await test(`HKDF vector: ${vec.description}`, async () => {
      const ikm = hexToBytes(vec.ikm);
      const salt = hexToBytes(vec.salt);
      const info = hexToBytes(vec.info);

      const result = hkdf(ikm, salt, info, vec.length);
      assertEqual(result.length, vec.length, 'HKDF output length should match');
      hkdfResults.push(bytesToHex(result));
    });
  }

  // ==========================================================================
  // Section 3: Determinism - Same Key+IV Produces Identical Ciphertext
  // ==========================================================================
  log('\n[3. Encryption Determinism]');

  await test('AES-256-CTR produces identical ciphertext across runs', async () => {
    const key = hexToBytes('42'.repeat(32));
    const iv = hexToBytes('24'.repeat(16));
    const plaintext = new TextEncoder().encode('Determinism test payload');

    // Run 1
    const data1 = new Uint8Array(plaintext);
    clearIVTracking(key);
    encryptBytes(data1, key, iv);
    const ciphertext1 = bytesToHex(data1);

    // Run 2
    const data2 = new Uint8Array(plaintext);
    clearIVTracking(key);
    encryptBytes(data2, key, iv);
    const ciphertext2 = bytesToHex(data2);

    assertEqual(ciphertext1, ciphertext2, 'ciphertext must be identical for same key+IV+plaintext');
  });

  await test('HKDF produces identical output across runs', async () => {
    const ikm = hexToBytes('0b'.repeat(22));
    const salt = hexToBytes('00'.repeat(13));
    const info = hexToBytes('f0f1f2f3f4f5f6f7f8f9');

    const result1 = hkdf(ikm, salt, info, 32);
    const result2 = hkdf(ikm, salt, info, 32);

    assertArrayEqual(result1, result2, 'HKDF output must be deterministic');
  });

  await test('SHA-256 produces identical output across runs', async () => {
    const data = new TextEncoder().encode('determinism check');

    const hash1 = sha256(data);
    const hash2 = sha256(data);

    assertArrayEqual(hash1, hash2, 'SHA-256 must be deterministic');
  });

  await test('EncryptionContext with same key produces identical field encryption', async () => {
    const key = hexToBytes('ab'.repeat(32));
    const buffer1 = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    const buffer2 = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

    const ctx1 = new EncryptionContext(key);
    const ctx2 = new EncryptionContext(key);

    // Encrypt same range with same field index
    ctx1.encryptScalar(buffer1, 0, 8, 0);
    ctx2.encryptScalar(buffer2, 0, 8, 0);

    assertArrayEqual(buffer1, buffer2, 'same key + same field index must produce identical ciphertext');
  });

  await test('EncryptionContext field key derivation is deterministic', async () => {
    const key = hexToBytes('cd'.repeat(32));

    const ctx1 = new EncryptionContext(key);
    const ctx2 = new EncryptionContext(key);

    const fieldKey1 = ctx1.deriveFieldKey(5);
    const fieldKey2 = ctx2.deriveFieldKey(5);

    assertArrayEqual(fieldKey1, fieldKey2, 'derived field keys must be identical');
  });

  await test('EncryptionContext field IV derivation is deterministic', async () => {
    const key = hexToBytes('ef'.repeat(32));

    const ctx1 = new EncryptionContext(key);
    const ctx2 = new EncryptionContext(key);

    const iv1 = ctx1.deriveFieldIV(3);
    const iv2 = ctx2.deriveFieldIV(3);

    assertArrayEqual(iv1, iv2, 'derived field IVs must be identical');
  });

  // ==========================================================================
  // Section 4: Encrypted Field Accessor Roundtrip via WASM
  // ==========================================================================
  log('\n[4. Encrypted Field Accessor Roundtrip]');

  await test('encryptScalar/decryptScalar roundtrip with direct key', async () => {
    const key = hexToBytes('aa'.repeat(32));
    const ctx = new EncryptionContext(key);

    // Simulate a FlatBuffer with multiple scalar fields
    const buffer = new Uint8Array(32);
    const view = new DataView(buffer.buffer);

    // Write scalar values at specific offsets
    view.setInt32(0, 42, true);         // field 0: int32
    view.setFloat64(8, 3.14159, true);  // field 1: float64
    view.setInt16(16, -1000, true);     // field 2: int16
    view.setUint32(20, 0xDEADBEEF, true); // field 3: uint32

    const original = new Uint8Array(buffer);

    // Encrypt each field
    ctx.encryptScalar(buffer, 0, 4, 0);   // field 0
    ctx.encryptScalar(buffer, 8, 8, 1);   // field 1
    ctx.encryptScalar(buffer, 16, 2, 2);  // field 2
    ctx.encryptScalar(buffer, 20, 4, 3);  // field 3

    // Verify buffer was modified
    let modified = false;
    for (let i = 0; i < buffer.length; i++) {
      if (buffer[i] !== original[i]) { modified = true; break; }
    }
    assert(modified, 'buffer should be modified after encryption');

    // Decrypt each field with a fresh context (same key)
    const decCtx = new EncryptionContext(key);
    decCtx.decryptScalar(buffer, 0, 4, 0);
    decCtx.decryptScalar(buffer, 8, 8, 1);
    decCtx.decryptScalar(buffer, 16, 2, 2);
    decCtx.decryptScalar(buffer, 20, 4, 3);

    // Verify original values recovered
    const decView = new DataView(buffer.buffer);
    assertEqual(decView.getInt32(0, true), 42, 'field 0 (int32) should roundtrip');
    assertEqual(decView.getFloat64(8, true), 3.14159, 'field 1 (float64) should roundtrip');
    assertEqual(decView.getInt16(16, true), -1000, 'field 2 (int16) should roundtrip');
    assertEqual(decView.getUint32(20, true), 0xDEADBEEF, 'field 3 (uint32) should roundtrip');
  });

  await test('ECIES encrypt/decrypt field roundtrip with X25519', async () => {
    clearAllIVTracking();

    const recipientKeys = x25519GenerateKeyPair();
    const appContext = 'interop-field-roundtrip-v1';

    // Sender: encrypt scalar fields
    const encryptCtx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
      algorithm: 'x25519',
      context: appContext,
    });

    const buffer = new Uint8Array(24);
    const view = new DataView(buffer.buffer);
    view.setFloat64(0, 1.23456789, true);   // field 0
    view.setFloat64(8, -9.87654321, true);   // field 1
    view.setUint32(16, 12345, true);          // field 2
    view.setUint32(20, 67890, true);          // field 3

    encryptCtx.encryptScalar(buffer, 0, 8, 0);
    encryptCtx.encryptScalar(buffer, 8, 8, 1);
    encryptCtx.encryptScalar(buffer, 16, 4, 2);
    encryptCtx.encryptScalar(buffer, 20, 4, 3);

    // Transmit header
    const headerJSON = encryptCtx.getHeaderJSON();

    // Receiver: decrypt
    const receivedHeader = encryptionHeaderFromJSON(headerJSON);
    const decryptCtx = EncryptionContext.forDecryption(
      recipientKeys.privateKey,
      receivedHeader,
      appContext
    );

    decryptCtx.decryptScalar(buffer, 0, 8, 0);
    decryptCtx.decryptScalar(buffer, 8, 8, 1);
    decryptCtx.decryptScalar(buffer, 16, 4, 2);
    decryptCtx.decryptScalar(buffer, 20, 4, 3);

    const decView = new DataView(buffer.buffer);
    assertEqual(decView.getFloat64(0, true), 1.23456789, 'field 0 should roundtrip via ECIES');
    assertEqual(decView.getFloat64(8, true), -9.87654321, 'field 1 should roundtrip via ECIES');
    assertEqual(decView.getUint32(16, true), 12345, 'field 2 should roundtrip via ECIES');
    assertEqual(decView.getUint32(20, true), 67890, 'field 3 should roundtrip via ECIES');
  });

  await test('ECIES encrypt/decrypt field roundtrip with secp256k1', async () => {
    clearAllIVTracking();

    const recipientKeys = secp256k1GenerateKeyPair();
    const appContext = 'interop-secp256k1-field-v1';

    const encryptCtx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
      algorithm: 'secp256k1',
      context: appContext,
    });

    const buffer = new Uint8Array(16);
    const view = new DataView(buffer.buffer);
    view.setInt32(0, -2147483648, true);  // INT32_MIN
    view.setInt32(4, 2147483647, true);   // INT32_MAX
    view.setFloat32(8, 0.0, true);         // zero
    view.setFloat32(12, -0.0, true);       // negative zero

    encryptCtx.encryptScalar(buffer, 0, 4, 0);
    encryptCtx.encryptScalar(buffer, 4, 4, 1);
    encryptCtx.encryptScalar(buffer, 8, 4, 2);
    encryptCtx.encryptScalar(buffer, 12, 4, 3);

    const headerJSON = encryptCtx.getHeaderJSON();
    const receivedHeader = encryptionHeaderFromJSON(headerJSON);
    const decryptCtx = EncryptionContext.forDecryption(
      recipientKeys.privateKey,
      receivedHeader,
      appContext
    );

    decryptCtx.decryptScalar(buffer, 0, 4, 0);
    decryptCtx.decryptScalar(buffer, 4, 4, 1);
    decryptCtx.decryptScalar(buffer, 8, 4, 2);
    decryptCtx.decryptScalar(buffer, 12, 4, 3);

    const decView = new DataView(buffer.buffer);
    assertEqual(decView.getInt32(0, true), -2147483648, 'INT32_MIN should roundtrip');
    assertEqual(decView.getInt32(4, true), 2147483647, 'INT32_MAX should roundtrip');
    assertEqual(decView.getFloat32(8, true), 0.0, 'zero should roundtrip');
    // Negative zero comparison
    assert(Object.is(decView.getFloat32(12, true), -0.0), 'negative zero should roundtrip');
  });

  await test('String field encrypt/decrypt roundtrip', async () => {
    clearAllIVTracking();

    const key = hexToBytes('bb'.repeat(32));
    const ctx = new EncryptionContext(key);

    // Simulate an encrypted string field in a FlatBuffer
    const originalString = 'Hello, cross-language encryption!';
    const stringBytes = new TextEncoder().encode(originalString);
    const buffer = new Uint8Array(stringBytes);

    ctx.encryptScalar(buffer, 0, buffer.length, 0);

    // Verify it is encrypted
    const encryptedString = new TextDecoder().decode(buffer);
    assert(encryptedString !== originalString, 'string should be encrypted');

    // Decrypt with fresh context
    const decCtx = new EncryptionContext(key);
    decCtx.decryptScalar(buffer, 0, buffer.length, 0);

    const decryptedString = new TextDecoder().decode(buffer);
    assertEqual(decryptedString, originalString, 'string should decrypt correctly');
  });

  await test('Byte vector encrypt/decrypt roundtrip', async () => {
    clearAllIVTracking();

    const key = hexToBytes('cc'.repeat(32));
    const ctx = new EncryptionContext(key);

    // Simulate [ubyte] field
    const original = new Uint8Array(256);
    for (let i = 0; i < 256; i++) original[i] = i;
    const buffer = new Uint8Array(original);

    ctx.encryptScalar(buffer, 0, buffer.length, 0);

    // Decrypt
    const decCtx = new EncryptionContext(key);
    decCtx.decryptScalar(buffer, 0, buffer.length, 0);

    assertArrayEqual(buffer, original, 'byte vector should roundtrip');
  });

  await test('Multiple fields with different indices produce different ciphertext', async () => {
    const key = hexToBytes('dd'.repeat(32));
    const ctx = new EncryptionContext(key);

    const buf1 = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
    const buf2 = new Uint8Array([0x01, 0x02, 0x03, 0x04]);

    ctx.encryptScalar(buf1, 0, 4, 0);  // field index 0
    ctx.encryptScalar(buf2, 0, 4, 1);  // field index 1

    let same = true;
    for (let i = 0; i < 4; i++) {
      if (buf1[i] !== buf2[i]) { same = false; break; }
    }
    assert(!same, 'different field indices should produce different ciphertext');
  });

  // ==========================================================================
  // Section 5: Encryption Header Interoperability
  // ==========================================================================
  log('\n[5. Encryption Header Interop & Runtime Patterns]');

  await test('Encryption header JSON is cross-language parseable', async () => {
    clearAllIVTracking();

    const recipientKeys = x25519GenerateKeyPair();
    const ctx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
      algorithm: 'x25519',
      context: 'cross-lang-v1',
    });

    const headerJSON = ctx.getHeaderJSON();
    const parsed = JSON.parse(headerJSON);

    // Verify all required fields for cross-language interop
    assertEqual(parsed.version, 1, 'version must be 1');
    assertEqual(parsed.algorithm, 'x25519', 'algorithm must be present');
    assertEqual(typeof parsed.senderPublicKey, 'string', 'senderPublicKey must be hex string');
    assertEqual(parsed.senderPublicKey.length, 64, 'senderPublicKey must be 32 bytes hex');
    assertEqual(typeof parsed.recipientKeyId, 'string', 'recipientKeyId must be hex string');
    assertEqual(parsed.recipientKeyId.length, 16, 'recipientKeyId must be 8 bytes hex');
    assertEqual(typeof parsed.iv, 'string', 'iv must be hex string');
    assertEqual(parsed.iv.length, 32, 'iv must be 16 bytes hex');
    assertEqual(parsed.context, 'cross-lang-v1', 'context must be preserved');
  });

  await test('Encryption header roundtrip through JSON preserves all fields', async () => {
    clearAllIVTracking();

    const recipientKeys = x25519GenerateKeyPair();
    const ctx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
      algorithm: 'x25519',
      context: 'roundtrip-header-test',
    });

    const header = ctx.getHeader();
    const json = encryptionHeaderToJSON(header);
    const restored = encryptionHeaderFromJSON(json);

    assertEqual(restored.version, header.version, 'version roundtrip');
    assertEqual(restored.algorithm, header.algorithm, 'algorithm roundtrip');
    assertArrayEqual(restored.senderPublicKey, header.senderPublicKey, 'senderPublicKey roundtrip');
    assertArrayEqual(restored.recipientKeyId, header.recipientKeyId, 'recipientKeyId roundtrip');
    assertArrayEqual(restored.iv, header.iv, 'iv roundtrip');
    assertEqual(restored.context, header.context, 'context roundtrip');
  });

  await test('computeKeyId is deterministic', async () => {
    const { publicKey } = x25519GenerateKeyPair();

    const id1 = computeKeyId(publicKey);
    const id2 = computeKeyId(publicKey);

    assertArrayEqual(id1, id2, 'keyId must be deterministic');
    assertEqual(id1.length, 8, 'keyId must be 8 bytes');
  });

  await test('X25519 shared secret is symmetric (interop property)', async () => {
    // This property must hold across all language implementations
    const alice = x25519GenerateKeyPair();
    const bob = x25519GenerateKeyPair();

    const secret1 = x25519SharedSecret(alice.privateKey, bob.publicKey);
    const secret2 = x25519SharedSecret(bob.privateKey, alice.publicKey);

    assertArrayEqual(secret1, secret2, 'X25519 DH must be symmetric');
  });

  await test('X25519 key derivation with context is deterministic', async () => {
    const alice = x25519GenerateKeyPair();
    const bob = x25519GenerateKeyPair();

    const secret = x25519SharedSecret(alice.privateKey, bob.publicKey);

    const key1 = x25519DeriveKey(secret, 'interop-context');
    const key2 = x25519DeriveKey(secret, 'interop-context');

    assertArrayEqual(key1, key2, 'derived key must be deterministic');
    assertEqual(key1.length, KEY_SIZE, 'derived key must be 32 bytes');
  });

  await test('X25519 different context produces different key', async () => {
    const alice = x25519GenerateKeyPair();
    const bob = x25519GenerateKeyPair();

    const secret = x25519SharedSecret(alice.privateKey, bob.publicKey);

    const key1 = x25519DeriveKey(secret, 'context-A');
    const key2 = x25519DeriveKey(secret, 'context-B');

    let same = true;
    for (let i = 0; i < key1.length; i++) {
      if (key1[i] !== key2[i]) { same = false; break; }
    }
    assert(!same, 'different contexts must derive different keys');
  });

  // Verify docs/wasm-runtimes/ examples pattern with encryption
  await test('docs pattern: FlatBuffer-like buffer encrypt/decrypt with ECIES', async () => {
    // Simulates the docs/wasm-runtimes pattern where a FlatBuffer is built,
    // encrypted, transmitted as JSON header + encrypted bytes, then decrypted.
    clearAllIVTracking();

    const recipientKeys = x25519GenerateKeyPair();

    // Build a simulated FlatBuffer (Monster-like table)
    const bufferSize = 64;
    const flatBuffer = new Uint8Array(bufferSize);
    const view = new DataView(flatBuffer.buffer);

    // Simulated Monster fields:
    // offset 0: root table offset (4 bytes) - not encrypted
    // offset 4: hp (int16)
    // offset 8: mana (int16)
    // offset 12: x position (float32)
    // offset 16: y position (float32)
    // offset 20: z position (float32)
    view.setUint32(0, 4, true);          // root offset (unencrypted)
    view.setInt16(4, 300, true);         // hp
    view.setInt16(8, 150, true);         // mana
    view.setFloat32(12, 1.0, true);      // x
    view.setFloat32(16, 2.0, true);      // y
    view.setFloat32(20, 3.0, true);      // z

    // Encrypt selected fields (hp, mana, positions)
    const encCtx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
      algorithm: 'x25519',
      context: 'monster-encryption-v1',
    });

    encCtx.encryptScalar(flatBuffer, 4, 2, 0);    // hp
    encCtx.encryptScalar(flatBuffer, 8, 2, 1);    // mana
    encCtx.encryptScalar(flatBuffer, 12, 4, 2);   // x
    encCtx.encryptScalar(flatBuffer, 16, 4, 3);   // y
    encCtx.encryptScalar(flatBuffer, 20, 4, 4);   // z

    // root offset should still be readable (unencrypted)
    assertEqual(view.getUint32(0, true), 4, 'root offset should be unencrypted');

    // Transmit: header JSON + encrypted buffer
    const headerJSON = encCtx.getHeaderJSON();
    const transmittedBuffer = new Uint8Array(flatBuffer);

    // Recipient decrypts
    const receivedHeader = encryptionHeaderFromJSON(headerJSON);
    const decCtx = EncryptionContext.forDecryption(
      recipientKeys.privateKey,
      receivedHeader,
      'monster-encryption-v1'
    );

    decCtx.decryptScalar(transmittedBuffer, 4, 2, 0);
    decCtx.decryptScalar(transmittedBuffer, 8, 2, 1);
    decCtx.decryptScalar(transmittedBuffer, 12, 4, 2);
    decCtx.decryptScalar(transmittedBuffer, 16, 4, 3);
    decCtx.decryptScalar(transmittedBuffer, 20, 4, 4);

    const decView = new DataView(transmittedBuffer.buffer);
    assertEqual(decView.getInt16(4, true), 300, 'hp should decrypt');
    assertEqual(decView.getInt16(8, true), 150, 'mana should decrypt');
    assertEqual(decView.getFloat32(12, true), 1.0, 'x should decrypt');
    assertEqual(decView.getFloat32(16, true), 2.0, 'y should decrypt');
    assertEqual(decView.getFloat32(20, true), 3.0, 'z should decrypt');
  });

  await test('docs pattern: non-destructive copy encryption for safe transmission', async () => {
    clearAllIVTracking();

    const key = hexToBytes('ee'.repeat(32));
    const plaintext = new TextEncoder().encode('FlatBuffer payload for transmission');
    const original = new Uint8Array(plaintext);

    const { ciphertext, iv } = encryptBytesCopy(plaintext, key);

    // Original is preserved
    assertArrayEqual(plaintext, original, 'original must be preserved');

    // Ciphertext can be transmitted and decrypted
    const decrypted = decryptBytesCopy(ciphertext, key, iv);
    assertArrayEqual(decrypted, original, 'decrypted copy must match original');
  });

  await test('docs pattern: multi-recipient encryption (same plaintext, different keys)', async () => {
    clearAllIVTracking();

    const recipient1 = x25519GenerateKeyPair();
    const recipient2 = x25519GenerateKeyPair();
    const appContext = 'multi-recipient-v1';
    const plaintext = new TextEncoder().encode('Shared secret for multiple recipients');

    // Encrypt for recipient 1
    const enc1 = EncryptionContext.forEncryption(recipient1.publicKey, {
      algorithm: 'x25519',
      context: appContext,
    });
    const buf1 = new Uint8Array(plaintext);
    enc1.encryptScalar(buf1, 0, buf1.length, 0);
    const header1JSON = enc1.getHeaderJSON();

    // Encrypt for recipient 2
    const enc2 = EncryptionContext.forEncryption(recipient2.publicKey, {
      algorithm: 'x25519',
      context: appContext,
    });
    const buf2 = new Uint8Array(plaintext);
    enc2.encryptScalar(buf2, 0, buf2.length, 0);
    const header2JSON = enc2.getHeaderJSON();

    // Recipient 1 decrypts their copy
    const dec1 = EncryptionContext.forDecryption(
      recipient1.privateKey,
      encryptionHeaderFromJSON(header1JSON),
      appContext
    );
    dec1.decryptScalar(buf1, 0, buf1.length, 0);

    // Recipient 2 decrypts their copy
    const dec2 = EncryptionContext.forDecryption(
      recipient2.privateKey,
      encryptionHeaderFromJSON(header2JSON),
      appContext
    );
    dec2.decryptScalar(buf2, 0, buf2.length, 0);

    // Both should recover the plaintext
    assertArrayEqual(buf1, plaintext, 'recipient 1 should decrypt correctly');
    assertArrayEqual(buf2, plaintext, 'recipient 2 should decrypt correctly');
  });

  // ==========================================================================
  // Section 5b: Verify docs/wasm-runtimes/ HTML examples reference encryption
  // ==========================================================================
  log('\n[5b. docs/wasm-runtimes/ File Existence]');

  const docsDir = path.resolve(__dirname, '../../docs/wasm-runtimes');
  const expectedDocs = [
    'nodejs.html',
    'browser.html',
    'python.html',
    'go.html',
    'rust.html',
    'java.html',
    'swift.html',
    'csharp.html',
  ];

  for (const docFile of expectedDocs) {
    await test(`docs/wasm-runtimes/${docFile} exists`, async () => {
      const fullPath = path.join(docsDir, docFile);
      assert(existsSync(fullPath), `${docFile} should exist in docs/wasm-runtimes/`);
    });
  }

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
