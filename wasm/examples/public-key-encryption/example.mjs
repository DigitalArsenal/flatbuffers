#!/usr/bin/env node
/**
 * Public Key Encryption Example
 *
 * Demonstrates X25519 ECDH + AES-256-CTR encryption using the WASM binary's
 * exported wasm_crypto_* functions. No JS crypto code is used.
 *
 * The workflow:
 * 1. Recipient generates an X25519 key pair (via WASM binary)
 * 2. Sender generates an ephemeral X25519 key pair
 * 3. Sender computes shared secret via ECDH, derives symmetric key via HKDF
 * 4. Sender encrypts data with AES-256-CTR
 * 5. Recipient derives same symmetric key and decrypts
 *
 * Usage: node example.mjs
 */

import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Load the Emscripten module directly
const wasmPath = path.join(__dirname, '..', '..', 'dist', 'flatc-wasm.js');
const { default: createModule } = await import(wasmPath);
const Module = await createModule({ noExitRuntime: true, noInitialRun: true });

// WASM memory helpers
function allocBytes(data) {
  const ptr = Module._malloc(data.length);
  Module.HEAPU8.set(data, ptr);
  return ptr;
}

function readBytes(ptr, len) {
  return new Uint8Array(Module.HEAPU8.buffer, ptr, len).slice();
}

function toHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function main() {
  console.log("=== Public Key Encryption Example (WASM Binary) ===\n");

  const versionPtr = Module._wasm_crypto_get_version();
  console.log(`WASM crypto version: ${Module.UTF8ToString(versionPtr)}\n`);

  // Step 1: Recipient generates their long-term key pair
  console.log("1. Recipient generates X25519 key pair...");
  const recipPrivPtr = Module._malloc(32);
  const recipPubPtr = Module._malloc(32);
  Module._wasm_crypto_x25519_generate_keypair(recipPrivPtr, recipPubPtr);
  const recipientPublicKey = readBytes(recipPubPtr, 32);
  console.log(`   Public key: ${toHex(recipientPublicKey).substring(0, 32)}...\n`);

  // Step 2: Sender generates ephemeral key pair
  console.log("2. Sender generates ephemeral X25519 key pair...");
  const ephPrivPtr = Module._malloc(32);
  const ephPubPtr = Module._malloc(32);
  Module._wasm_crypto_x25519_generate_keypair(ephPrivPtr, ephPubPtr);
  const ephemeralPublicKey = readBytes(ephPubPtr, 32);
  console.log(`   Ephemeral public key: ${toHex(ephemeralPublicKey).substring(0, 32)}...\n`);

  // Step 3: Sender computes shared secret and derives symmetric key
  console.log("3. Sender derives symmetric key via ECDH + HKDF...");
  const senderSecretPtr = Module._malloc(32);
  Module._wasm_crypto_x25519_shared_secret(ephPrivPtr, ephPubPtr, recipPubPtr, senderSecretPtr);
  const senderSecret = readBytes(senderSecretPtr, 32);

  // Derive symmetric key using HKDF
  const info = new TextEncoder().encode("flatbuffers-encryption-v1");
  const infoPtr = allocBytes(info);
  const symKeyPtr = Module._malloc(32);
  // Use ephemeral public key as salt for key separation
  const saltPtr = allocBytes(ephemeralPublicKey);
  Module._wasm_crypto_hkdf(senderSecretPtr, 32, saltPtr, 32, infoPtr, info.length, symKeyPtr, 32);
  const symmetricKey = readBytes(symKeyPtr, 32);
  console.log(`   Symmetric key: ${toHex(symmetricKey).substring(0, 32)}...\n`);

  // Zero ephemeral private key (forward secrecy)
  Module.HEAPU8.fill(0, ephPrivPtr, ephPrivPtr + 32);

  // Step 4: Sender encrypts data
  console.log("4. Sender encrypts data with AES-256-CTR...");
  const plaintext = new TextEncoder().encode("This is a secret message encrypted with X25519 + AES-256-CTR!");
  const original = new Uint8Array(plaintext);
  console.log(`   Plaintext: "${new TextDecoder().decode(plaintext)}"`);

  // Generate a random IV
  const iv = new Uint8Array(16);
  globalThis.crypto.getRandomValues(iv);
  const ivPtr = allocBytes(iv);
  const dataPtr = allocBytes(plaintext);

  Module._wasm_crypto_encrypt_bytes(symKeyPtr, ivPtr, dataPtr, plaintext.length);
  const encrypted = readBytes(dataPtr, plaintext.length);
  console.log(`   Encrypted: ${toHex(encrypted).substring(0, 64)}...\n`);

  // Sender would transmit: ephemeralPublicKey + iv + encrypted data

  // Step 5: Recipient derives same symmetric key
  console.log("5. Recipient derives the same symmetric key...");
  const recipSecretPtr = Module._malloc(32);
  const ephPubPtrRecip = allocBytes(ephemeralPublicKey);
  Module._wasm_crypto_x25519_shared_secret(recipPrivPtr, recipPubPtr, ephPubPtrRecip, recipSecretPtr);

  const recipSymKeyPtr = Module._malloc(32);
  const recipSaltPtr = allocBytes(ephemeralPublicKey);
  Module._wasm_crypto_hkdf(recipSecretPtr, 32, recipSaltPtr, 32, infoPtr, info.length, recipSymKeyPtr, 32);
  const recipSymKey = readBytes(recipSymKeyPtr, 32);
  console.log(`   Symmetric key: ${toHex(recipSymKey).substring(0, 32)}...`);
  console.log(`   Keys match: ${toHex(symmetricKey) === toHex(recipSymKey) ? "YES" : "NO"}\n`);

  // Step 6: Recipient decrypts
  console.log("6. Recipient decrypts data...");
  const ivPtrDec = allocBytes(iv);
  Module._wasm_crypto_decrypt_bytes(recipSymKeyPtr, ivPtrDec, dataPtr, plaintext.length);
  const decrypted = readBytes(dataPtr, plaintext.length);
  const decryptedText = new TextDecoder().decode(decrypted);
  console.log(`   Decrypted: "${decryptedText}"`);

  const success = decryptedText === new TextDecoder().decode(original);
  console.log(`\n=== Test ${success ? "PASSED" : "FAILED"} ===`);

  // Cleanup
  [recipPrivPtr, recipPubPtr, ephPrivPtr, ephPubPtr, senderSecretPtr,
   infoPtr, symKeyPtr, saltPtr, ivPtr, dataPtr, recipSecretPtr,
   ephPubPtrRecip, recipSymKeyPtr, recipSaltPtr, ivPtrDec].forEach(p => Module._free(p));

  if (!success) process.exit(1);
}

main().catch(err => {
  console.error("Error:", err);
  process.exit(1);
});
