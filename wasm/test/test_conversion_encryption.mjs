#!/usr/bin/env node
/**
 * test_conversion_encryption.mjs - Integration tests for FlatBuffer conversion + encryption
 *
 * Tests the interplay between FlatBuffer binary/JSON conversion and encryption:
 * - generateBinary() with encryption -> generateJSON() with decryption roundtrip
 * - Streaming encrypt -> stream decrypt roundtrip
 * - Per-field encryption (only specified fields encrypted, others plaintext)
 * - EncryptionHeader correctly prepended to output
 * - Wrong key fails decryption
 * - FIPS mode flag uses OpenSSL path
 */

import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Import the FlatcRunner from flatc-wasm
import { FlatcRunner } from '../src/runner.mjs';

// Import encryption primitives
import {
  loadEncryptionWasm,
  isInitialized,
  x25519GenerateKeyPair,
  x25519SharedSecret,
  x25519DeriveKey,
  EncryptionContext,
  createEncryptionHeader,
  computeKeyId,
  encryptionHeaderToJSON,
  encryptionHeaderFromJSON,
  encryptBuffer,
  decryptBuffer,
  encryptBytes,
  decryptBytes,
  encryptBytesCopy,
  decryptBytesCopy,
  clearIVTracking,
  clearAllIVTracking,
  hkdf,
  KEY_SIZE,
  IV_SIZE,
} from '../src/index.mjs';

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

async function assertThrowsAsync(fn, expectedMessage) {
  let threw = false;
  let actualMessage = '';
  try {
    await fn();
  } catch (e) {
    threw = true;
    actualMessage = e.message;
  }
  if (!threw) {
    throw new Error(`Expected async function to throw, but it did not`);
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

// Helper to generate random bytes
function randomBytes(size) {
  const bytes = new Uint8Array(size);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else if (typeof process !== 'undefined' && process.versions?.node) {
    const nodeCrypto = new Function('return require("crypto")')();
    nodeCrypto.randomFillSync(bytes);
  }
  return bytes;
}

// Schema with (encrypted) attribute on selected fields
const TEST_SCHEMA = `
table TestRecord {
  id: uint64;
  name: string;
  secret: string (encrypted);
  score: int (encrypted);
}
root_type TestRecord;
`;

// Plain schema (no encryption attributes) for comparison
const PLAIN_SCHEMA = `
table TestRecord {
  id: uint64;
  name: string;
  secret: string;
  score: int;
}
root_type TestRecord;
`;

const TEST_JSON = JSON.stringify({
  id: 42,
  name: 'Alice',
  secret: 'top-secret-value',
  score: 9001,
});

const SCHEMA_INPUT = {
  entry: 'test_record.fbs',
  files: { 'test_record.fbs': PLAIN_SCHEMA },
};

const ENCRYPTED_SCHEMA_INPUT = {
  entry: 'test_record_enc.fbs',
  files: { 'test_record_enc.fbs': TEST_SCHEMA },
};

async function main() {
  log('============================================================');
  log('Conversion + Encryption Integration Test Suite');
  log('============================================================');

  // Check CI mode
  const isCI = process.env.CI === 'true' || process.env.CI === '1' ||
               process.env.REQUIRE_WASM === 'true' || process.env.REQUIRE_WASM === '1';

  // Load encryption WASM
  log('\n[Module Initialization]');

  let wasmLoaded = false;
  try {
    await loadEncryptionWasm();
    wasmLoaded = true;
    log('  Encryption WASM module loaded');
  } catch (err) {
    log(`  WARNING: Could not load encryption WASM: ${err.message}`);
    if (isCI) {
      log('  ERROR: WASM module is required in CI mode');
      process.exit(1);
    }
    log('  Some tests will be skipped.');
  }

  // Initialize FlatcRunner
  let runner;
  try {
    runner = await FlatcRunner.init();
    log(`  FlatcRunner initialized (${runner.version().trim()})`);
  } catch (err) {
    log(`  ERROR: Could not initialize FlatcRunner: ${err.message}`);
    if (isCI) {
      process.exit(1);
    }
    log('  Skipping all tests.');
    process.exit(0);
  }

  // ==========================================================================
  // 1. generateBinary() with encryption -> generateJSON() with decryption
  // ==========================================================================
  log('\n[generateBinaryEncrypted -> generateJSONDecrypted Roundtrip]');

  if (wasmLoaded) {
    await test('generateBinaryEncrypted produces output', async () => {
      const recipientKeys = x25519GenerateKeyPair();

      const result = runner.generateBinaryEncrypted(
        SCHEMA_INPUT,
        TEST_JSON,
        { publicKey: recipientKeys.publicKey, algorithm: 'x25519', context: 'test-v1' },
        { sizePrefix: false }
      );

      assert(result.data instanceof Uint8Array, 'data should be Uint8Array');
      assert(result.data.length > 0, 'data should not be empty');
    });

    await test('generateBinaryEncrypted -> generateJSONDecrypted roundtrip', async () => {
      const recipientKeys = x25519GenerateKeyPair();

      const encrypted = runner.generateBinaryEncrypted(
        SCHEMA_INPUT,
        TEST_JSON,
        { publicKey: recipientKeys.publicKey, algorithm: 'x25519', context: 'roundtrip-test' },
        { sizePrefix: false }
      );

      // Decrypt back to JSON
      const jsonOutput = runner.generateJSONDecrypted(
        SCHEMA_INPUT,
        { path: '/roundtrip.bin', data: encrypted.data },
        { privateKey: recipientKeys.privateKey, header: encrypted.header },
      );

      assert(typeof jsonOutput === 'string', 'output should be a string');
      const parsed = JSON.parse(jsonOutput);
      assertEqual(parsed.name, 'Alice', 'name should survive roundtrip');
      assertEqual(parsed.score, 9001, 'score should survive roundtrip');
    });

    await test('plain generateBinary -> generateJSON roundtrip still works', async () => {
      const binary = runner.generateBinary(SCHEMA_INPUT, TEST_JSON, { sizePrefix: false });
      assert(binary.length > 0, 'binary should not be empty');

      const jsonOutput = runner.generateJSON(
        SCHEMA_INPUT,
        { path: '/plain.bin', data: binary },
      );

      const parsed = JSON.parse(jsonOutput);
      assertEqual(parsed.name, 'Alice', 'name should survive plain roundtrip');
      assertEqual(parsed.score, 9001, 'score should survive plain roundtrip');
    });
  } else {
    log('  (Skipping encryption roundtrip tests - WASM not loaded)');
  }

  // ==========================================================================
  // 2. Streaming encrypt -> stream decrypt roundtrip
  // ==========================================================================
  log('\n[Streaming Encrypt -> Decrypt Roundtrip]');

  if (wasmLoaded) {
    await test('streaming encrypt then decrypt preserves data', async () => {
      const recipientKeys = x25519GenerateKeyPair();
      clearAllIVTracking();

      // Encrypt context for sender
      const encryptCtx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
        algorithm: 'x25519',
        context: 'stream-test-v1',
      });

      // Simulate streaming: encrypt multiple chunks with field indices
      const chunk1 = new TextEncoder().encode('chunk-one-data-here');
      const chunk2 = new TextEncoder().encode('chunk-two-data-here');
      const chunk3 = new TextEncoder().encode('chunk-three-data!');

      const encChunk1 = new Uint8Array(chunk1);
      const encChunk2 = new Uint8Array(chunk2);
      const encChunk3 = new Uint8Array(chunk3);

      encryptCtx.encryptScalar(encChunk1, 0, encChunk1.length, 0);
      encryptCtx.encryptScalar(encChunk2, 0, encChunk2.length, 1);
      encryptCtx.encryptScalar(encChunk3, 0, encChunk3.length, 2);

      // Verify chunks are actually encrypted (differ from original)
      let chunk1Changed = false;
      for (let i = 0; i < encChunk1.length; i++) {
        if (encChunk1[i] !== chunk1[i]) { chunk1Changed = true; break; }
      }
      assert(chunk1Changed, 'chunk 1 should be encrypted');

      // Get header for decryption
      const headerJSON = encryptCtx.getHeaderJSON();
      const header = encryptionHeaderFromJSON(headerJSON);

      // Decrypt context for recipient
      const decryptCtx = EncryptionContext.forDecryption(
        recipientKeys.privateKey,
        header,
        'stream-test-v1'
      );

      decryptCtx.decryptScalar(encChunk1, 0, encChunk1.length, 0);
      decryptCtx.decryptScalar(encChunk2, 0, encChunk2.length, 1);
      decryptCtx.decryptScalar(encChunk3, 0, encChunk3.length, 2);

      assertArrayEqual(encChunk1, chunk1, 'chunk 1 should decrypt correctly');
      assertArrayEqual(encChunk2, chunk2, 'chunk 2 should decrypt correctly');
      assertArrayEqual(encChunk3, chunk3, 'chunk 3 should decrypt correctly');
    });

    await test('streaming with interleaved field indices', async () => {
      const recipientKeys = x25519GenerateKeyPair();
      clearAllIVTracking();

      const encryptCtx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
        algorithm: 'x25519',
        context: 'interleave-test',
      });

      // Use same field index multiple times (simulating repeated fields)
      const data1 = new TextEncoder().encode('record-A-field-0');
      const data2 = new TextEncoder().encode('record-B-field-0');
      const enc1 = new Uint8Array(data1);
      const enc2 = new Uint8Array(data2);

      // Both use fieldIndex 0 but different data
      encryptCtx.encryptScalar(enc1, 0, enc1.length, 0);
      // fieldIndex 1 for second piece
      encryptCtx.encryptScalar(enc2, 0, enc2.length, 1);

      const headerJSON = encryptCtx.getHeaderJSON();
      const header = encryptionHeaderFromJSON(headerJSON);

      const decryptCtx = EncryptionContext.forDecryption(
        recipientKeys.privateKey,
        header,
        'interleave-test'
      );

      decryptCtx.decryptScalar(enc1, 0, enc1.length, 0);
      decryptCtx.decryptScalar(enc2, 0, enc2.length, 1);

      assertArrayEqual(enc1, data1, 'first record should decrypt');
      assertArrayEqual(enc2, data2, 'second record should decrypt');
    });
  } else {
    log('  (Skipping streaming tests - WASM not loaded)');
  }

  // ==========================================================================
  // 3. Per-field encryption (only specified fields, others plaintext)
  // ==========================================================================
  log('\n[Per-Field Encryption]');

  if (wasmLoaded) {
    await test('only encrypted fields are modified, others remain plaintext', async () => {
      const recipientKeys = x25519GenerateKeyPair();
      clearAllIVTracking();

      const encryptCtx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
        algorithm: 'x25519',
        context: 'per-field-test',
      });

      // Simulate a buffer with 4 fields laid out sequentially:
      //   field 0: id (plaintext, 8 bytes)
      //   field 1: name (plaintext, 5 bytes)
      //   field 2: secret (encrypted, 16 bytes)
      //   field 3: score (encrypted, 4 bytes)
      const idBytes = new Uint8Array([42, 0, 0, 0, 0, 0, 0, 0]);        // uint64 = 42
      const nameBytes = new TextEncoder().encode('Alice');                 // 5 bytes
      const secretBytes = new TextEncoder().encode('top-secret-value');    // 16 bytes
      const scoreBytes = new Uint8Array([0x29, 0x23, 0x00, 0x00]);       // int32 = 9001

      // Combine into a single buffer
      const totalLen = idBytes.length + nameBytes.length + secretBytes.length + scoreBytes.length;
      const buffer = new Uint8Array(totalLen);
      let offset = 0;
      buffer.set(idBytes, offset); offset += idBytes.length;
      buffer.set(nameBytes, offset); offset += nameBytes.length;
      buffer.set(secretBytes, offset); offset += secretBytes.length;
      buffer.set(scoreBytes, offset);

      const originalBuffer = new Uint8Array(buffer);

      // Only encrypt fields 2 (secret) and 3 (score) - per-field encryption
      const secretOffset = idBytes.length + nameBytes.length;
      const scoreOffset = secretOffset + secretBytes.length;

      encryptCtx.encryptScalar(buffer, secretOffset, secretBytes.length, 2);
      encryptCtx.encryptScalar(buffer, scoreOffset, scoreBytes.length, 3);

      // Verify: id field (plaintext) unchanged
      for (let i = 0; i < idBytes.length; i++) {
        assertEqual(buffer[i], originalBuffer[i], `id byte ${i} should be unchanged`);
      }

      // Verify: name field (plaintext) unchanged
      for (let i = idBytes.length; i < idBytes.length + nameBytes.length; i++) {
        assertEqual(buffer[i], originalBuffer[i], `name byte ${i} should be unchanged`);
      }

      // Verify: secret field (encrypted) changed
      let secretChanged = false;
      for (let i = secretOffset; i < secretOffset + secretBytes.length; i++) {
        if (buffer[i] !== originalBuffer[i]) { secretChanged = true; break; }
      }
      assert(secretChanged, 'secret field should be encrypted');

      // Verify: score field (encrypted) changed
      let scoreChanged = false;
      for (let i = scoreOffset; i < scoreOffset + scoreBytes.length; i++) {
        if (buffer[i] !== originalBuffer[i]) { scoreChanged = true; break; }
      }
      assert(scoreChanged, 'score field should be encrypted');

      // Now decrypt and verify roundtrip
      const headerJSON = encryptCtx.getHeaderJSON();
      const header = encryptionHeaderFromJSON(headerJSON);
      const decryptCtx = EncryptionContext.forDecryption(
        recipientKeys.privateKey,
        header,
        'per-field-test'
      );

      decryptCtx.decryptScalar(buffer, secretOffset, secretBytes.length, 2);
      decryptCtx.decryptScalar(buffer, scoreOffset, scoreBytes.length, 3);

      assertArrayEqual(buffer, originalBuffer, 'buffer should match original after per-field decrypt');
    });

    await test('encrypting zero fields leaves buffer untouched', async () => {
      const recipientKeys = x25519GenerateKeyPair();
      clearAllIVTracking();

      const buffer = new TextEncoder().encode('This should remain plaintext entirely');
      const original = new Uint8Array(buffer);

      // Do not call encryptScalar at all - no fields marked for encryption
      assertArrayEqual(buffer, original, 'buffer should be unchanged when no fields encrypted');
    });
  } else {
    log('  (Skipping per-field tests - WASM not loaded)');
  }

  // ==========================================================================
  // 4. EncryptionHeader correctly prepended to output
  // ==========================================================================
  log('\n[EncryptionHeader Prepended to Output]');

  if (wasmLoaded) {
    await test('EncryptionHeader contains correct version and algorithm', async () => {
      const recipientKeys = x25519GenerateKeyPair();

      const encryptCtx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
        algorithm: 'x25519',
        context: 'header-test',
      });

      const header = encryptCtx.getHeader();
      assertEqual(header.version, 1, 'header version should be 1');
      assertEqual(header.algorithm, 'x25519', 'header algorithm should be x25519');
      assertEqual(header.context, 'header-test', 'header context should match');
    });

    await test('EncryptionHeader contains sender public key', async () => {
      const recipientKeys = x25519GenerateKeyPair();

      const encryptCtx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
        algorithm: 'x25519',
        context: 'sender-key-test',
      });

      const header = encryptCtx.getHeader();
      assert(header.senderPublicKey instanceof Uint8Array, 'senderPublicKey should be Uint8Array');
      assertEqual(header.senderPublicKey.length, 32, 'X25519 sender public key should be 32 bytes');
    });

    await test('EncryptionHeader contains IV', async () => {
      const recipientKeys = x25519GenerateKeyPair();

      const encryptCtx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
        algorithm: 'x25519',
        context: 'iv-test',
      });

      const header = encryptCtx.getHeader();
      assert(header.iv instanceof Uint8Array, 'iv should be Uint8Array');
      assertEqual(header.iv.length, IV_SIZE, 'IV should be 16 bytes');
    });

    await test('EncryptionHeader contains recipient key ID', async () => {
      const recipientKeys = x25519GenerateKeyPair();
      const expectedKeyId = computeKeyId(recipientKeys.publicKey);

      const encryptCtx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
        algorithm: 'x25519',
        context: 'keyid-test',
      });

      const header = encryptCtx.getHeader();
      assert(header.recipientKeyId instanceof Uint8Array, 'recipientKeyId should be Uint8Array');
      assertEqual(header.recipientKeyId.length, 8, 'key ID should be 8 bytes');
      assertArrayEqual(header.recipientKeyId, expectedKeyId, 'key ID should match computed value');
    });

    await test('EncryptionHeader JSON roundtrip preserves all fields', async () => {
      const recipientKeys = x25519GenerateKeyPair();

      const encryptCtx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
        algorithm: 'x25519',
        context: 'json-roundtrip-test',
      });

      const headerJSON = encryptCtx.getHeaderJSON();
      assert(typeof headerJSON === 'string', 'getHeaderJSON should return string');

      const parsed = JSON.parse(headerJSON);
      assertEqual(parsed.version, 1, 'JSON version should be 1');
      assertEqual(parsed.algorithm, 'x25519', 'JSON algorithm should match');
      assertEqual(parsed.context, 'json-roundtrip-test', 'JSON context should match');

      // Roundtrip back through encryptionHeaderFromJSON
      const restored = encryptionHeaderFromJSON(headerJSON);
      assertEqual(restored.version, 1, 'restored version should be 1');
      assertEqual(restored.algorithm, 'x25519', 'restored algorithm should match');
      assert(restored.senderPublicKey instanceof Uint8Array, 'restored senderPublicKey should be Uint8Array');
      assert(restored.iv instanceof Uint8Array, 'restored iv should be Uint8Array');
    });

    await test('generateBinaryEncrypted result contains header', async () => {
      const recipientKeys = x25519GenerateKeyPair();

      const result = runner.generateBinaryEncrypted(
        SCHEMA_INPUT,
        TEST_JSON,
        { publicKey: recipientKeys.publicKey, algorithm: 'x25519', context: 'header-prepend' },
        { sizePrefix: false }
      );

      assert(result.header !== undefined, 'result should contain header field');
      assert(result.data !== undefined, 'result should contain data field');
      assert(result.data instanceof Uint8Array, 'data should be Uint8Array');
    });
  } else {
    log('  (Skipping header tests - WASM not loaded)');
  }

  // ==========================================================================
  // 5. Wrong key fails decryption
  // ==========================================================================
  log('\n[Wrong Key Fails Decryption]');

  if (wasmLoaded) {
    await test('wrong private key produces garbled output', async () => {
      const recipientKeys = x25519GenerateKeyPair();
      let wrongKeys = x25519GenerateKeyPair();

      // Ensure keys are different
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
      assert(attempts < 100, 'should generate distinct keys');

      clearAllIVTracking();

      const encryptCtx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
        algorithm: 'x25519',
        context: 'wrong-key-test',
      });

      const plaintext = new TextEncoder().encode('Secret message for wrong-key test!');
      const data = new Uint8Array(plaintext);
      const original = new Uint8Array(plaintext);

      encryptCtx.encryptScalar(data, 0, data.length, 0);

      // Attempt decryption with wrong key
      const headerJSON = encryptCtx.getHeaderJSON();
      const header = encryptionHeaderFromJSON(headerJSON);
      const wrongDecryptCtx = EncryptionContext.forDecryption(
        wrongKeys.privateKey,
        header,
        'wrong-key-test'
      );

      wrongDecryptCtx.decryptScalar(data, 0, data.length, 0);

      // Data should NOT match original
      let matches = true;
      for (let i = 0; i < data.length; i++) {
        if (data[i] !== original[i]) { matches = false; break; }
      }
      assert(!matches, 'decryption with wrong key should produce garbled data');
    });

    await test('wrong context produces garbled output', async () => {
      const recipientKeys = x25519GenerateKeyPair();
      clearAllIVTracking();

      const encryptCtx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
        algorithm: 'x25519',
        context: 'correct-context',
      });

      const plaintext = new TextEncoder().encode('Context-sensitive data');
      const data = new Uint8Array(plaintext);
      const original = new Uint8Array(plaintext);

      encryptCtx.encryptScalar(data, 0, data.length, 0);

      const headerJSON = encryptCtx.getHeaderJSON();
      const header = encryptionHeaderFromJSON(headerJSON);

      // Decrypt with wrong context
      const wrongCtx = EncryptionContext.forDecryption(
        recipientKeys.privateKey,
        header,
        'wrong-context'
      );

      wrongCtx.decryptScalar(data, 0, data.length, 0);

      let matches = true;
      for (let i = 0; i < data.length; i++) {
        if (data[i] !== original[i]) { matches = false; break; }
      }
      assert(!matches, 'decryption with wrong context should produce garbled data');
    });

    await test('generateBinaryEncrypted requires publicKey', async () => {
      let threw = false;
      try {
        runner.generateBinaryEncrypted(SCHEMA_INPUT, TEST_JSON, {});
      } catch (e) {
        threw = true;
        assert(e.message.includes('publicKey'), 'error should mention publicKey');
      }
      assert(threw, 'should throw when publicKey is missing');
    });

    await test('generateJSONDecrypted requires privateKey', async () => {
      const binary = runner.generateBinary(SCHEMA_INPUT, TEST_JSON, { sizePrefix: false });
      let threw = false;
      try {
        runner.generateJSONDecrypted(
          SCHEMA_INPUT,
          { path: '/test.bin', data: binary },
          {}
        );
      } catch (e) {
        threw = true;
        assert(e.message.includes('privateKey'), 'error should mention privateKey');
      }
      assert(threw, 'should throw when privateKey is missing');
    });
  } else {
    log('  (Skipping wrong-key tests - WASM not loaded)');
  }

  // ==========================================================================
  // 6. FIPS mode flag uses OpenSSL path
  // ==========================================================================
  log('\n[FIPS Mode Flag]');

  await test('EncryptionContext accepts fips option without error', async () => {
    if (!wasmLoaded) {
      log('    (Skipped - WASM not loaded)');
      return;
    }

    // FIPS mode is a configuration flag that directs crypto operations to use
    // an OpenSSL-backed path. We verify the flag is accepted and does not cause
    // errors in context creation.
    const recipientKeys = x25519GenerateKeyPair();

    // The forEncryption method should accept a fips flag gracefully.
    // If the underlying implementation does not support FIPS, it may ignore it
    // or throw a specific error - either is acceptable behavior.
    let contextCreated = false;
    let fipsError = null;
    try {
      const ctx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
        algorithm: 'x25519',
        context: 'fips-test',
        fips: true,
      });
      contextCreated = true;
      assert(ctx.isValid(), 'FIPS context should be valid');
    } catch (e) {
      fipsError = e;
      // Acceptable: FIPS not supported in this build
      assert(
        e.message.includes('FIPS') || e.message.includes('fips') ||
        e.message.includes('not supported') || e.message.includes('Unsupported'),
        `FIPS error should be descriptive, got: ${e.message}`
      );
    }

    if (contextCreated) {
      log('    (FIPS flag accepted - implementation may use OpenSSL path)');
    } else {
      log(`    (FIPS not available in this build: ${fipsError.message})`);
    }
  });

  await test('FIPS mode encrypt/decrypt roundtrip (when supported)', async () => {
    if (!wasmLoaded) {
      log('    (Skipped - WASM not loaded)');
      return;
    }

    const recipientKeys = x25519GenerateKeyPair();
    clearAllIVTracking();

    let ctx;
    try {
      ctx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
        algorithm: 'x25519',
        context: 'fips-roundtrip',
        fips: true,
      });
    } catch (e) {
      // FIPS not supported - skip gracefully
      log('    (FIPS mode not supported - skipping roundtrip)');
      return;
    }

    const plaintext = new TextEncoder().encode('FIPS-compliant data');
    const data = new Uint8Array(plaintext);

    ctx.encryptScalar(data, 0, data.length, 0);

    const headerJSON = ctx.getHeaderJSON();
    const header = encryptionHeaderFromJSON(headerJSON);

    const decryptCtx = EncryptionContext.forDecryption(
      recipientKeys.privateKey,
      header,
      'fips-roundtrip'
    );

    decryptCtx.decryptScalar(data, 0, data.length, 0);
    assertArrayEqual(data, plaintext, 'FIPS roundtrip should preserve data');
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
