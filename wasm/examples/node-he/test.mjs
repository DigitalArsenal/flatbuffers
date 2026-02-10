#!/usr/bin/env node
/**
 * test_he_encryption.mjs - Tests for Homomorphic Encryption in FlatBuffers WASM
 *
 * Tests the HE functionality:
 * - HEContext creation (client and server)
 * - Key generation and serialization
 * - Encrypt/decrypt round-trip
 * - Homomorphic operations (add, multiply, etc.)
 * - Server-side computation without secret key
 *
 * NOTE: These tests require the HE-enabled WASM build (flatc-wasm-he.js)
 * If running with the standard WASM, HE functions won't be available.
 */

import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

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

function assertClose(actual, expected, tolerance, message) {
  if (Math.abs(actual - expected) > tolerance) {
    throw new Error(`${message}: expected ~${expected}, got ${actual}`);
  }
}

async function runTest(name, fn) {
  try {
    await fn();
    log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    log(`  ✗ ${name}`);
    log(`    Error: ${e.message}`);
    failed++;
  }
}

// Check if HE functions are available
function checkHEAvailable(module) {
  return typeof module._wasm_he_context_create_client === 'function';
}

// Helper to allocate and copy data to WASM memory
function allocateBytes(module, data) {
  const ptr = module._malloc(data.length);
  module.HEAPU8.set(data, ptr);
  return ptr;
}

// Helper to read output with length
function readOutput(module, ptr, lenPtr) {
  const len = module.getValue(lenPtr, 'i32');
  if (ptr === 0 || len === 0) return null;
  return new Uint8Array(module.HEAPU8.buffer, ptr, len).slice();
}

async function main() {
  log('');
  log('=== Homomorphic Encryption WASM Tests ===');
  log('');

  // Try to load the HE-enabled WASM module
  let wasmModule;
  try {
    // Try HE module first
    const hePath = path.join(__dirname, '../../dist/flatc-he.js');
    const { default: createModule } = await import(hePath);
    wasmModule = await createModule();
    log('Loaded HE-enabled WASM module');
  } catch (e) {
    // Fall back to standard module
    try {
      const stdPath = path.join(__dirname, '../../dist/flatc-wasm.js');
      const { default: createModule } = await import(stdPath);
      wasmModule = await createModule();
      log('Loaded standard WASM module (HE not available)');
    } catch (e2) {
      log('ERROR: Could not load any WASM module');
      log(`  HE error: ${e.message}`);
      log(`  Std error: ${e2.message}`);
      process.exit(1);
    }
  }

  const heAvailable = checkHEAvailable(wasmModule);
  if (!heAvailable) {
    log('');
    log('HE functions not available in this WASM build.');
    log('To run HE tests, build with:');
    log('  cmake -B build -S . -DFLATBUFFERS_BUILD_WASM=ON -DFLATBUFFERS_WASM_ENABLE_HE=ON');
    log('  cmake --build build --target flatc_wasm_he');
    log('');
    log('Skipping HE tests...');
    process.exit(0);
  }

  log('');
  log('Running HE tests...');
  log('');

  // Allocate a length pointer for output
  const lenPtr = wasmModule._malloc(4);

  // Test: Create client context
  await runTest('Create client context', async () => {
    const ctxId = wasmModule._wasm_he_context_create_client(4096);
    assert(ctxId > 0, 'Context creation should return positive ID');

    // Clean up
    wasmModule._wasm_he_context_destroy(ctxId);
  });

  // Test: Get public key
  let clientCtxId;
  let publicKey;
  let relinKeys;

  await runTest('Get public key from client', async () => {
    clientCtxId = wasmModule._wasm_he_context_create_client(4096);
    assert(clientCtxId > 0, 'Context creation failed');

    const pkPtr = wasmModule._wasm_he_get_public_key(clientCtxId, lenPtr);
    publicKey = readOutput(wasmModule, pkPtr, lenPtr);
    assert(publicKey !== null, 'Public key should not be null');
    assert(publicKey.length > 0, 'Public key should not be empty');
    log(`    (public key size: ${publicKey.length} bytes)`);
  });

  // Test: Get relin keys
  await runTest('Get relinearization keys', async () => {
    const rkPtr = wasmModule._wasm_he_get_relin_keys(clientCtxId, lenPtr);
    relinKeys = readOutput(wasmModule, rkPtr, lenPtr);
    assert(relinKeys !== null, 'Relin keys should not be null');
    assert(relinKeys.length > 0, 'Relin keys should not be empty');
    log(`    (relin keys size: ${relinKeys.length} bytes)`);
  });

  // Test: Get secret key
  await runTest('Get secret key from client', async () => {
    const skPtr = wasmModule._wasm_he_get_secret_key(clientCtxId, lenPtr);
    const secretKey = readOutput(wasmModule, skPtr, lenPtr);
    assert(secretKey !== null, 'Secret key should not be null');
    assert(secretKey.length > 0, 'Secret key should not be empty');
    log(`    (secret key size: ${secretKey.length} bytes)`);
  });

  // Test: Create server context
  let serverCtxId;
  await runTest('Create server context from public key', async () => {
    const pkPtr = allocateBytes(wasmModule, publicKey);
    serverCtxId = wasmModule._wasm_he_context_create_server(pkPtr, publicKey.length);
    wasmModule._free(pkPtr);
    assert(serverCtxId > 0, 'Server context creation failed');

    // Set relin keys
    const rkPtr = allocateBytes(wasmModule, relinKeys);
    const result = wasmModule._wasm_he_set_relin_keys(serverCtxId, rkPtr, relinKeys.length);
    wasmModule._free(rkPtr);
    assertEqual(result, 0, 'Set relin keys should succeed');
  });

  // Test: Encrypt/decrypt int64
  await runTest('Encrypt/decrypt int64 round-trip', async () => {
    const value = 42n;

    // Encrypt
    const ctPtr = wasmModule._wasm_he_encrypt_int64(clientCtxId, value, lenPtr);
    const ciphertext = readOutput(wasmModule, ctPtr, lenPtr);
    assert(ciphertext !== null, 'Encryption failed');
    log(`    (ciphertext size: ${ciphertext.length} bytes)`);

    // Decrypt
    const ctPtrDec = allocateBytes(wasmModule, ciphertext);
    const decrypted = wasmModule._wasm_he_decrypt_int64(clientCtxId, ctPtrDec, ciphertext.length);
    wasmModule._free(ctPtrDec);
    assertEqual(decrypted, value, 'Decrypted value mismatch');
  });

  // Test: Encrypt/decrypt double
  await runTest('Encrypt/decrypt double round-trip', async () => {
    const value = 3.14159;

    // Encrypt
    const ctPtr = wasmModule._wasm_he_encrypt_double(clientCtxId, value, lenPtr);
    const ciphertext = readOutput(wasmModule, ctPtr, lenPtr);
    assert(ciphertext !== null, 'Encryption failed');

    // Decrypt
    const ctPtrDec = allocateBytes(wasmModule, ciphertext);
    const decrypted = wasmModule._wasm_he_decrypt_double(clientCtxId, ctPtrDec, ciphertext.length);
    wasmModule._free(ctPtrDec);
    assertClose(decrypted, value, 0.0001, 'Decrypted value mismatch');
  });

  // Test: Homomorphic addition
  await runTest('Homomorphic addition', async () => {
    const val1 = 42n;
    const val2 = 10n;

    // Encrypt both values
    const ct1Ptr = wasmModule._wasm_he_encrypt_int64(clientCtxId, val1, lenPtr);
    const ct1 = readOutput(wasmModule, ct1Ptr, lenPtr);

    const ct2Ptr = wasmModule._wasm_he_encrypt_int64(clientCtxId, val2, lenPtr);
    const ct2 = readOutput(wasmModule, ct2Ptr, lenPtr);

    // Add on server (doesn't have secret key)
    const ct1PtrAdd = allocateBytes(wasmModule, ct1);
    const ct2PtrAdd = allocateBytes(wasmModule, ct2);
    const sumPtr = wasmModule._wasm_he_add(serverCtxId, ct1PtrAdd, ct1.length, ct2PtrAdd, ct2.length, lenPtr);
    const sumCt = readOutput(wasmModule, sumPtr, lenPtr);
    wasmModule._free(ct1PtrAdd);
    wasmModule._free(ct2PtrAdd);
    assert(sumCt !== null, 'Addition failed');

    // Decrypt on client
    const sumPtrDec = allocateBytes(wasmModule, sumCt);
    const result = wasmModule._wasm_he_decrypt_int64(clientCtxId, sumPtrDec, sumCt.length);
    wasmModule._free(sumPtrDec);
    assertEqual(result, val1 + val2, 'Addition result mismatch');
  });

  // Test: Homomorphic multiplication
  await runTest('Homomorphic multiplication', async () => {
    const val1 = 7n;
    const val2 = 6n;

    // Encrypt both values
    const ct1Ptr = wasmModule._wasm_he_encrypt_int64(clientCtxId, val1, lenPtr);
    const ct1 = readOutput(wasmModule, ct1Ptr, lenPtr);

    const ct2Ptr = wasmModule._wasm_he_encrypt_int64(clientCtxId, val2, lenPtr);
    const ct2 = readOutput(wasmModule, ct2Ptr, lenPtr);

    // Multiply on server
    const ct1PtrMul = allocateBytes(wasmModule, ct1);
    const ct2PtrMul = allocateBytes(wasmModule, ct2);
    const prodPtr = wasmModule._wasm_he_multiply(serverCtxId, ct1PtrMul, ct1.length, ct2PtrMul, ct2.length, lenPtr);
    const prodCt = readOutput(wasmModule, prodPtr, lenPtr);
    wasmModule._free(ct1PtrMul);
    wasmModule._free(ct2PtrMul);
    assert(prodCt !== null, 'Multiplication failed');

    // Decrypt on client
    const prodPtrDec = allocateBytes(wasmModule, prodCt);
    const result = wasmModule._wasm_he_decrypt_int64(clientCtxId, prodPtrDec, prodCt.length);
    wasmModule._free(prodPtrDec);
    assertEqual(result, val1 * val2, 'Multiplication result mismatch');
  });

  // Test: Add plaintext
  await runTest('Add plaintext to ciphertext', async () => {
    const val = 100n;
    const plain = 50n;

    // Encrypt
    const ctPtr = wasmModule._wasm_he_encrypt_int64(clientCtxId, val, lenPtr);
    const ct = readOutput(wasmModule, ctPtr, lenPtr);

    // Add plain on server
    const ctPtrAdd = allocateBytes(wasmModule, ct);
    const sumPtr = wasmModule._wasm_he_add_plain(serverCtxId, ctPtrAdd, ct.length, plain, lenPtr);
    const sumCt = readOutput(wasmModule, sumPtr, lenPtr);
    wasmModule._free(ctPtrAdd);
    assert(sumCt !== null, 'Add plain failed');

    // Decrypt
    const sumPtrDec = allocateBytes(wasmModule, sumCt);
    const result = wasmModule._wasm_he_decrypt_int64(clientCtxId, sumPtrDec, sumCt.length);
    wasmModule._free(sumPtrDec);
    assertEqual(result, val + plain, 'Add plain result mismatch');
  });

  // Test: Multiply by plaintext
  await runTest('Multiply ciphertext by plaintext', async () => {
    const val = 25n;
    const plain = 4n;

    // Encrypt
    const ctPtr = wasmModule._wasm_he_encrypt_int64(clientCtxId, val, lenPtr);
    const ct = readOutput(wasmModule, ctPtr, lenPtr);

    // Multiply plain on server
    const ctPtrMul = allocateBytes(wasmModule, ct);
    const prodPtr = wasmModule._wasm_he_multiply_plain(serverCtxId, ctPtrMul, ct.length, plain, lenPtr);
    const prodCt = readOutput(wasmModule, prodPtr, lenPtr);
    wasmModule._free(ctPtrMul);
    assert(prodCt !== null, 'Multiply plain failed');

    // Decrypt
    const prodPtrDec = allocateBytes(wasmModule, prodCt);
    const result = wasmModule._wasm_he_decrypt_int64(clientCtxId, prodPtrDec, prodCt.length);
    wasmModule._free(prodPtrDec);
    assertEqual(result, val * plain, 'Multiply plain result mismatch');
  });

  // Clean up
  wasmModule._wasm_he_context_destroy(clientCtxId);
  wasmModule._wasm_he_context_destroy(serverCtxId);
  wasmModule._free(lenPtr);

  log('');
  log('=== Test Results ===');
  log(`Passed: ${passed}`);
  log(`Failed: ${failed}`);
  log('');

  process.exit(failed > 0 ? 1 : 0);
}

main().catch(e => {
  console.error('Test runner error:', e);
  process.exit(1);
});
