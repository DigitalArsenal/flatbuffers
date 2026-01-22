#!/usr/bin/env node
/**
 * test_webapp_crypto.mjs - Test harness for webapp encryption/decryption flows
 *
 * This test file specifically validates the encryption patterns used in the
 * webapp (wasm/docs/app.mjs) to prevent bugs like:
 * - Using encryptScalar() instead of decryptScalar() for decryption
 * - IV reuse which catastrophically breaks AES-CTR security
 *
 * Run this test pre-commit to catch crypto bugs before deployment.
 */

import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Import encryption module
import {
  loadEncryptionWasm,
  x25519GenerateKeyPair,
  EncryptionContext,
  encryptionHeaderFromJSON,
  clearAllIVTracking,
  CryptoError,
  CryptoErrorCode,
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

async function test(name, fn) {
  try {
    await fn();
    passed++;
    log(`  ✓ ${name}`);
  } catch (err) {
    failed++;
    log(`  ✗ ${name}`);
    log(`    Error: ${err.message}`);
    if (err.stack) {
      log(`    ${err.stack.split('\n').slice(1, 3).join('\n    ')}`);
    }
  }
}

// =============================================================================
// Webapp Flow Simulation Functions
// These simulate the functions in app.mjs
// =============================================================================

/**
 * Simulates encryptFieldBytesWithPKI from app.mjs
 * Encrypts field bytes using recipient's public key (ECIES)
 */
function encryptFieldBytesWithPKI(bytes, recipientPublicKey, fieldId = 0) {
  const encryptCtx = EncryptionContext.forEncryption(recipientPublicKey, {
    context: 'flatbuffers-field-encryption-v1',
  });

  const encrypted = new Uint8Array(bytes);
  encryptCtx.encryptScalar(encrypted, 0, encrypted.length, fieldId);

  return {
    encrypted,
    headerJSON: encryptCtx.getHeaderJSON(),
  };
}

/**
 * Simulates decryptFieldBytesWithPKI from app.mjs (CORRECT version)
 * Decrypts field bytes using recipient's private key
 */
function decryptFieldBytesWithPKI_CORRECT(encrypted, headerJSON, recipientPrivateKey, fieldId = 0) {
  const header = encryptionHeaderFromJSON(headerJSON);
  const decryptCtx = EncryptionContext.forDecryption(
    recipientPrivateKey,
    header,
    'flatbuffers-field-encryption-v1'
  );

  const decrypted = new Uint8Array(encrypted);
  // CORRECT: Use decryptScalar which does NOT track IV
  decryptCtx.decryptScalar(decrypted, 0, decrypted.length, fieldId);
  return decrypted;
}

/**
 * Simulates the BUGGY version that was in app.mjs before the fix
 * Using encryptScalar instead of decryptScalar
 */
function decryptFieldBytesWithPKI_BUGGY(encrypted, headerJSON, recipientPrivateKey, fieldId = 0) {
  const header = encryptionHeaderFromJSON(headerJSON);
  const decryptCtx = EncryptionContext.forDecryption(
    recipientPrivateKey,
    header,
    'flatbuffers-field-encryption-v1'
  );

  const decrypted = new Uint8Array(encrypted);
  // BUGGY: Using encryptScalar which TRACKS IV - causes IV reuse error!
  decryptCtx.encryptScalar(decrypted, 0, decrypted.length, fieldId);
  return decrypted;
}

/**
 * Simulates decryptBulkRecord from app.mjs
 * Uses decryptBuffer for bulk operations
 */
function decryptBulkRecord(encrypted, headerJSON, recipientPrivateKey, recordIndex) {
  const header = encryptionHeaderFromJSON(headerJSON);
  const decryptCtx = EncryptionContext.forDecryption(
    recipientPrivateKey,
    header,
    'flatbuffers-field-encryption-v1'
  );

  const decrypted = new Uint8Array(encrypted);
  decryptCtx.decryptBuffer(decrypted, recordIndex);
  return decrypted;
}

// =============================================================================
// Test Suite
// =============================================================================

async function runTests() {
  log('\n=== Webapp Crypto Test Suite ===\n');
  log('Testing encryption/decryption flows used in the webapp...\n');

  // Initialize WASM
  const wasmPath = path.join(__dirname, '..', 'dist', 'flatc-encryption.wasm');
  await loadEncryptionWasm(wasmPath);

  log('--- IV Reuse Prevention Tests ---');

  await test('CORRECT: decryptScalar does not cause IV reuse error', async () => {
    clearAllIVTracking();

    // Simulate Alice (sender) and Bob (recipient)
    const bobKeys = x25519GenerateKeyPair();
    const plaintext = new TextEncoder().encode('Secret message for Bob');

    // Alice encrypts for Bob
    const { encrypted, headerJSON } = encryptFieldBytesWithPKI(
      plaintext,
      bobKeys.publicKey,
      0
    );

    // Bob decrypts using CORRECT method
    const decrypted = decryptFieldBytesWithPKI_CORRECT(
      encrypted,
      headerJSON,
      bobKeys.privateKey,
      0
    );

    // Verify decryption worked
    const result = new TextDecoder().decode(decrypted);
    assertEqual(result, 'Secret message for Bob', 'decryption should produce original message');
  });

  await test('BUGGY: encryptScalar for decryption DOES cause IV reuse error', async () => {
    clearAllIVTracking();

    const bobKeys = x25519GenerateKeyPair();
    const plaintext = new TextEncoder().encode('Secret message');

    // Alice encrypts for Bob
    const { encrypted, headerJSON } = encryptFieldBytesWithPKI(
      plaintext,
      bobKeys.publicKey,
      0
    );

    // Bob tries to decrypt using BUGGY method (encryptScalar)
    let caughtIVReuse = false;
    try {
      decryptFieldBytesWithPKI_BUGGY(encrypted, headerJSON, bobKeys.privateKey, 0);
    } catch (err) {
      if (err.message && err.message.includes('IV has already been used')) {
        caughtIVReuse = true;
      } else {
        throw err;
      }
    }

    assert(caughtIVReuse,
      'Using encryptScalar for decryption MUST throw IV reuse error - ' +
      'this is the bug we are preventing!'
    );
  });

  await test('Multiple field encryption/decryption cycles work correctly', async () => {
    clearAllIVTracking();

    const bobKeys = x25519GenerateKeyPair();

    // Encrypt multiple fields
    const fields = [
      { data: 'Field 0: Name', fieldId: 0 },
      { data: 'Field 1: Email', fieldId: 1 },
      { data: 'Field 2: SSN', fieldId: 2 },
    ];

    const encryptedFields = fields.map(f => {
      const plaintext = new TextEncoder().encode(f.data);
      return {
        ...encryptFieldBytesWithPKI(plaintext, bobKeys.publicKey, f.fieldId),
        fieldId: f.fieldId,
        original: f.data,
      };
    });

    // Decrypt all fields - should NOT cause IV reuse
    for (const field of encryptedFields) {
      const decrypted = decryptFieldBytesWithPKI_CORRECT(
        field.encrypted,
        field.headerJSON,
        bobKeys.privateKey,
        field.fieldId
      );
      const result = new TextDecoder().decode(decrypted);
      assertEqual(result, field.original, `Field ${field.fieldId} should decrypt correctly`);
    }
  });

  await test('Bulk record decryption works without IV reuse', async () => {
    clearAllIVTracking();

    const bobKeys = x25519GenerateKeyPair();

    // Encrypt a "bulk record"
    const plaintext = new TextEncoder().encode('Bulk record data with multiple fields');
    const encryptCtx = EncryptionContext.forEncryption(bobKeys.publicKey, {
      context: 'flatbuffers-field-encryption-v1',
    });

    const encrypted = new Uint8Array(plaintext);
    encryptCtx.encryptBuffer(encrypted, 0); // recordIndex = 0

    const headerJSON = encryptCtx.getHeaderJSON();

    // Decrypt using bulk method
    const decrypted = decryptBulkRecord(encrypted, headerJSON, bobKeys.privateKey, 0);
    const result = new TextDecoder().decode(decrypted);
    assertEqual(result, 'Bulk record data with multiple fields', 'bulk decryption should work');
  });

  await test('Decrypting same data multiple times works (no IV tracking for decrypt)', async () => {
    clearAllIVTracking();

    const bobKeys = x25519GenerateKeyPair();
    const plaintext = new TextEncoder().encode('Repeat decrypt test');

    const { encrypted, headerJSON } = encryptFieldBytesWithPKI(
      plaintext,
      bobKeys.publicKey,
      0
    );

    // Decrypt the SAME ciphertext 3 times - should all work
    for (let i = 0; i < 3; i++) {
      const copy = new Uint8Array(encrypted);
      const decrypted = decryptFieldBytesWithPKI_CORRECT(
        copy,
        headerJSON,
        bobKeys.privateKey,
        0
      );
      const result = new TextDecoder().decode(decrypted);
      assertEqual(result, 'Repeat decrypt test', `Decryption attempt ${i + 1} should work`);
    }
  });

  await test('Encrypting same plaintext twice produces different ciphertext (fresh IV)', async () => {
    clearAllIVTracking();

    const bobKeys = x25519GenerateKeyPair();
    const plaintext = new TextEncoder().encode('Same message');

    const result1 = encryptFieldBytesWithPKI(plaintext, bobKeys.publicKey, 0);

    clearAllIVTracking(); // Clear to allow "reuse" for test

    const result2 = encryptFieldBytesWithPKI(plaintext, bobKeys.publicKey, 0);

    // The encrypted data should be different due to fresh ephemeral keys
    let isDifferent = false;
    for (let i = 0; i < result1.encrypted.length; i++) {
      if (result1.encrypted[i] !== result2.encrypted[i]) {
        isDifferent = true;
        break;
      }
    }
    assert(isDifferent, 'Two encryptions of same data should produce different ciphertext');
  });

  log('\n--- Security Invariant Tests ---');

  await test('IV reuse with same derived key is detected', async () => {
    clearAllIVTracking();

    const bobKeys = x25519GenerateKeyPair();

    // Create encryption context
    const encryptCtx = EncryptionContext.forEncryption(bobKeys.publicKey, {
      context: 'iv-reuse-security-test',
    });

    // First encryption - should work
    const data1 = new Uint8Array(new TextEncoder().encode('Message 1'));
    encryptCtx.encryptScalar(data1, 0, data1.length, 0);

    // Second encryption with SAME fieldId should fail (same derived key + IV)
    const data2 = new Uint8Array(new TextEncoder().encode('Message 2'));
    let ivReuseDetected = false;
    try {
      encryptCtx.encryptScalar(data2, 0, data2.length, 0); // Same fieldId = same IV
    } catch (err) {
      if (err.message && err.message.includes('IV has already been used')) {
        ivReuseDetected = true;
      } else {
        throw err;
      }
    }

    assert(ivReuseDetected,
      'CRITICAL: IV reuse MUST be detected! AES-CTR with reused IV completely breaks security.'
    );
  });

  await test('Different fieldIds produce different IVs (no collision)', async () => {
    clearAllIVTracking();

    const bobKeys = x25519GenerateKeyPair();
    const encryptCtx = EncryptionContext.forEncryption(bobKeys.publicKey, {
      context: 'field-id-test',
    });

    // Encrypt with different fieldIds - should all work (different IVs)
    for (let fieldId = 0; fieldId < 10; fieldId++) {
      const data = new Uint8Array(new TextEncoder().encode(`Field ${fieldId}`));
      encryptCtx.encryptScalar(data, 0, data.length, fieldId);
    }
    // If we get here without IV reuse error, different fieldIds use different IVs
  });

  // Print summary
  log('\n=== Test Summary ===');
  log(`Passed: ${passed}`);
  log(`Failed: ${failed}`);

  if (failed > 0) {
    log('\n⚠️  CRITICAL: Some tests failed! Fix before committing.');
    process.exit(1);
  } else {
    log('\n✓ All webapp crypto tests passed.');
    process.exit(0);
  }
}

// Run tests
runTests().catch(err => {
  console.error('Test runner error:', err);
  process.exit(1);
});
