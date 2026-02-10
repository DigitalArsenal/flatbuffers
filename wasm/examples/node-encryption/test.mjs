/**
 * Node.js Encryption Example
 *
 * Demonstrates field-level encryption using the WASM binary's exported
 * wasm_crypto_* functions. All crypto lives in the compiled binary.
 */

import { randomBytes } from "crypto";
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Load the Emscripten module directly
const wasmPath = path.join(__dirname, '..', '..', 'dist', 'flatc-wasm.js');
const { default: createModule } = await import(wasmPath);
const Module = await createModule({ noExitRuntime: true, noInitialRun: true });

// Test utilities
let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${name}`);
    console.log(`    Error: ${e.message}`);
    failed++;
  }
}

function assertEqual(actual, expected, msg) {
  if (actual !== expected) {
    throw new Error(`${msg}: expected ${expected}, got ${actual}`);
  }
}

function assertArrayEqual(a, b, msg) {
  if (a.length !== b.length) {
    throw new Error(`${msg}: length mismatch ${a.length} vs ${b.length}`);
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      throw new Error(`${msg}: mismatch at index ${i}`);
    }
  }
}

// =============================================================================
// WASM Memory Helpers
// =============================================================================

function allocBytes(data) {
  const ptr = Module._malloc(data.length);
  Module.HEAPU8.set(data, ptr);
  return ptr;
}

function readBytes(ptr, len) {
  return new Uint8Array(Module.HEAPU8.buffer, ptr, len).slice();
}

// =============================================================================
// Tests
// =============================================================================

console.log("\n=== Node.js Encryption Example (WASM Binary) ===\n");

// Test 1: WASM module info
console.log("1. WASM Module Info:");

test("has crypto version", () => {
  const versionPtr = Module._wasm_crypto_get_version();
  const version = Module.UTF8ToString(versionPtr);
  assertEqual(typeof version, "string", "version type");
  console.log(`    Version: ${version}`);
});

test("has Crypto++ available", () => {
  const hasCryptopp = Module._wasm_crypto_has_cryptopp();
  console.log(`    Crypto++: ${hasCryptopp ? "YES" : "NO"}`);
});

// Test 2: AES-256-CTR encrypt/decrypt
console.log("\n2. AES-256-CTR via WASM:");

test("encrypts and decrypts bytes", () => {
  const key = randomBytes(32);
  const iv = randomBytes(16);
  const plaintext = new TextEncoder().encode("Hello, World!");

  const keyPtr = allocBytes(key);
  const ivPtr = allocBytes(iv);
  const dataPtr = allocBytes(plaintext);

  // Encrypt in-place
  const encResult = Module._wasm_crypto_encrypt_bytes(keyPtr, ivPtr, dataPtr, plaintext.length);
  assertEqual(encResult, 0, "encrypt return code");

  const encrypted = readBytes(dataPtr, plaintext.length);

  // Should differ from plaintext
  let changed = false;
  for (let i = 0; i < plaintext.length; i++) {
    if (encrypted[i] !== plaintext[i]) { changed = true; break; }
  }
  assertEqual(changed, true, "data should change after encryption");

  // Decrypt in-place
  const decResult = Module._wasm_crypto_decrypt_bytes(keyPtr, ivPtr, dataPtr, plaintext.length);
  assertEqual(decResult, 0, "decrypt return code");

  const decrypted = readBytes(dataPtr, plaintext.length);
  assertArrayEqual(decrypted, plaintext, "round-trip");

  Module._free(keyPtr);
  Module._free(ivPtr);
  Module._free(dataPtr);
});

// Test 3: X25519 key exchange
console.log("\n3. X25519 Key Exchange via WASM:");

test("generates key pair and computes shared secret", () => {
  const privPtr1 = Module._malloc(32);
  const pubPtr1 = Module._malloc(32);
  const privPtr2 = Module._malloc(32);
  const pubPtr2 = Module._malloc(32);
  const secretPtr1 = Module._malloc(32);
  const secretPtr2 = Module._malloc(32);

  // Generate two key pairs
  assertEqual(Module._wasm_crypto_x25519_generate_keypair(privPtr1, pubPtr1), 0, "keygen1");
  assertEqual(Module._wasm_crypto_x25519_generate_keypair(privPtr2, pubPtr2), 0, "keygen2");

  // Compute shared secrets (should match)
  assertEqual(Module._wasm_crypto_x25519_shared_secret(privPtr1, pubPtr1, pubPtr2, secretPtr1), 0, "ecdh1");
  assertEqual(Module._wasm_crypto_x25519_shared_secret(privPtr2, pubPtr2, pubPtr1, secretPtr2), 0, "ecdh2");

  const secret1 = readBytes(secretPtr1, 32);
  const secret2 = readBytes(secretPtr2, 32);
  assertArrayEqual(secret1, secret2, "shared secrets should match");

  Module._free(privPtr1); Module._free(pubPtr1);
  Module._free(privPtr2); Module._free(pubPtr2);
  Module._free(secretPtr1); Module._free(secretPtr2);
});

// Test 4: SHA-256
console.log("\n4. SHA-256 via WASM:");

test("computes SHA-256 hash", () => {
  const data = new TextEncoder().encode("test");
  const dataPtr = allocBytes(data);
  const hashPtr = Module._malloc(32);

  Module._wasm_crypto_sha256(dataPtr, data.length, hashPtr);
  const hash = readBytes(hashPtr, 32);
  assertEqual(hash.length, 32, "hash length");

  // Known SHA-256 of "test"
  const expected = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
  const actual = Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
  assertEqual(actual, expected, "SHA-256 of 'test'");

  Module._free(dataPtr);
  Module._free(hashPtr);
});

// Test 5: HKDF
console.log("\n5. HKDF via WASM:");

test("derives key material with HKDF", () => {
  const ikm = randomBytes(32);
  const salt = randomBytes(16);
  const info = new TextEncoder().encode("flatbuffers-test");

  const ikmPtr = allocBytes(ikm);
  const saltPtr = allocBytes(salt);
  const infoPtr = allocBytes(info);
  const outPtr = Module._malloc(32);

  Module._wasm_crypto_hkdf(ikmPtr, ikm.length, saltPtr, salt.length, infoPtr, info.length, outPtr, 32);
  const derived = readBytes(outPtr, 32);
  assertEqual(derived.length, 32, "derived key length");

  // Derive again — should be deterministic
  Module._wasm_crypto_hkdf(ikmPtr, ikm.length, saltPtr, salt.length, infoPtr, info.length, outPtr, 32);
  const derived2 = readBytes(outPtr, 32);
  assertArrayEqual(derived, derived2, "HKDF should be deterministic");

  Module._free(ikmPtr); Module._free(saltPtr);
  Module._free(infoPtr); Module._free(outPtr);
});

// Test 6: secp256k1
console.log("\n6. secp256k1 via WASM:");

test("generates key pair and signs/verifies", () => {
  const privPtr = Module._malloc(32);
  const pubPtr = Module._malloc(33);

  assertEqual(Module._wasm_crypto_secp256k1_generate_keypair(privPtr, pubPtr), 0, "keygen");

  const data = new TextEncoder().encode("message to sign");
  const dataPtr = allocBytes(data);
  const sigPtr = Module._malloc(72); // DER-encoded signature, max 72 bytes
  const sigLenPtr = Module._malloc(4);

  const signResult = Module._wasm_crypto_secp256k1_sign(privPtr, data.length, dataPtr, data.length, sigPtr, sigLenPtr);
  assertEqual(signResult, 0, "sign");

  const sigLen = Module.getValue(sigLenPtr, 'i32');
  const verifyResult = Module._wasm_crypto_secp256k1_verify(pubPtr, 33, dataPtr, data.length, sigPtr, sigLen);
  assertEqual(verifyResult, 0, "verify");

  Module._free(privPtr); Module._free(pubPtr);
  Module._free(dataPtr); Module._free(sigPtr); Module._free(sigLenPtr);
});

// Summary
console.log("\n=== Test Summary ===");
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log(`Total:  ${passed + failed}`);

if (failed > 0) {
  process.exit(1);
}

console.log("\nAll Node.js encryption tests passed!\n");
process.exit(0);
