#!/usr/bin/env node
/**
 * Multi-Curve Public Key Encryption Test -- WASM binary exports
 *
 * Tests ECDH key exchange, HKDF key derivation, and AES-256-CTR
 * encrypt/decrypt with all three supported curves:
 * - X25519 (Curve25519)
 * - secp256k1 (Bitcoin/Ethereum)
 * - P-256 (NIST secp256r1)
 */

import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function toHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function loadModule() {
  const wasmPath = path.join(__dirname, "..", "..", "dist", "flatc-wasm.js");
  const { default: createModule } = await import(wasmPath);
  const Module = await createModule({
    noInitialRun: true,
    noExitRuntime: true,
  });
  return Module;
}

function allocBytes(Module, data) {
  const ptr = Module._malloc(data.length);
  Module.HEAPU8.set(data, ptr);
  return ptr;
}

function readBytes(Module, ptr, len) {
  return new Uint8Array(Module.HEAPU8.buffer, ptr, len).slice();
}

// --- Curve-specific helpers ---

function x25519GenerateKeyPair(Module) {
  const privPtr = Module._malloc(32);
  const pubPtr = Module._malloc(32);
  Module._wasm_crypto_x25519_generate_keypair(privPtr, pubPtr);
  const privateKey = readBytes(Module, privPtr, 32);
  const publicKey = readBytes(Module, pubPtr, 32);
  Module._free(privPtr);
  Module._free(pubPtr);
  return { privateKey, publicKey };
}

function x25519SharedSecret(Module, priv, pub) {
  const privPtr = allocBytes(Module, priv);
  const pubPtr = allocBytes(Module, pub);
  const outPtr = Module._malloc(32);
  Module._wasm_crypto_x25519_shared_secret(privPtr, pubPtr, outPtr);
  const shared = readBytes(Module, outPtr, 32);
  Module._free(privPtr);
  Module._free(pubPtr);
  Module._free(outPtr);
  return shared;
}

function secp256k1GenerateKeyPair(Module) {
  const privPtr = Module._malloc(32);
  const pubPtr = Module._malloc(33);
  Module._wasm_crypto_secp256k1_generate_keypair(privPtr, pubPtr);
  const privateKey = readBytes(Module, privPtr, 32);
  const publicKey = readBytes(Module, pubPtr, 33);
  Module._free(privPtr);
  Module._free(pubPtr);
  return { privateKey, publicKey };
}

function secp256k1SharedSecret(Module, priv, pub) {
  const privPtr = allocBytes(Module, priv);
  const pubPtr = allocBytes(Module, pub);
  const outPtr = Module._malloc(32);
  Module._wasm_crypto_secp256k1_shared_secret(privPtr, pubPtr, outPtr);
  const shared = readBytes(Module, outPtr, 32);
  Module._free(privPtr);
  Module._free(pubPtr);
  Module._free(outPtr);
  return shared;
}

function p256GenerateKeyPair(Module) {
  const privPtr = Module._malloc(32);
  const pubPtr = Module._malloc(33);
  Module._wasm_crypto_p256_generate_keypair(privPtr, pubPtr);
  const privateKey = readBytes(Module, privPtr, 32);
  const publicKey = readBytes(Module, pubPtr, 33);
  Module._free(privPtr);
  Module._free(pubPtr);
  return { privateKey, publicKey };
}

function p256SharedSecret(Module, priv, pub) {
  const privPtr = allocBytes(Module, priv);
  const pubPtr = allocBytes(Module, pub);
  const outPtr = Module._malloc(32);
  Module._wasm_crypto_p256_shared_secret(privPtr, pubPtr, outPtr);
  const shared = readBytes(Module, outPtr, 32);
  Module._free(privPtr);
  Module._free(pubPtr);
  Module._free(outPtr);
  return shared;
}

// --- Common crypto helpers ---

function hkdf(Module, ikm, salt, info, outLen) {
  const ikmPtr = allocBytes(Module, ikm);
  const saltPtr = salt ? allocBytes(Module, salt) : 0;
  const infoPtr = info ? allocBytes(Module, info) : 0;
  const outPtr = Module._malloc(outLen);
  Module._wasm_crypto_hkdf(
    ikmPtr, ikm.length,
    saltPtr, salt ? salt.length : 0,
    infoPtr, info ? info.length : 0,
    outPtr, outLen,
  );
  const derived = readBytes(Module, outPtr, outLen);
  Module._free(ikmPtr);
  if (saltPtr) Module._free(saltPtr);
  if (infoPtr) Module._free(infoPtr);
  Module._free(outPtr);
  return derived;
}

function encryptBytes(Module, plaintext, key, iv) {
  const dataPtr = allocBytes(Module, plaintext);
  const keyPtr = allocBytes(Module, key);
  const ivPtr = allocBytes(Module, iv);
  Module._wasm_crypto_encrypt_bytes(dataPtr, plaintext.length, keyPtr, ivPtr);
  const ciphertext = readBytes(Module, dataPtr, plaintext.length);
  Module._free(dataPtr);
  Module._free(keyPtr);
  Module._free(ivPtr);
  return ciphertext;
}

function decryptBytes(Module, ciphertext, key, iv) {
  const dataPtr = allocBytes(Module, ciphertext);
  const keyPtr = allocBytes(Module, key);
  const ivPtr = allocBytes(Module, iv);
  Module._wasm_crypto_decrypt_bytes(dataPtr, ciphertext.length, keyPtr, ivPtr);
  const plaintext = readBytes(Module, dataPtr, ciphertext.length);
  Module._free(dataPtr);
  Module._free(keyPtr);
  Module._free(ivPtr);
  return plaintext;
}

// --- Test each curve's full ECDH + HKDF + encrypt/decrypt flow ---

function testCurve(Module, curveName, generateKeyPair, sharedSecret) {
  console.log(`\n=== Testing ${curveName} ===\n`);

  // Generate recipient (long-term) and sender (ephemeral) key pairs
  const recipient = generateKeyPair(Module);
  const ephemeral = generateKeyPair(Module);
  console.log(`Recipient public key: ${toHex(recipient.publicKey).substring(0, 40)}...`);
  console.log(`Ephemeral public key: ${toHex(ephemeral.publicKey).substring(0, 40)}...`);

  // Both sides compute the same shared secret
  const senderShared = sharedSecret(Module, ephemeral.privateKey, recipient.publicKey);
  const recipientShared = sharedSecret(Module, recipient.privateKey, ephemeral.publicKey);

  const sharedMatch = toHex(senderShared) === toHex(recipientShared);
  console.log(`Shared secrets match: ${sharedMatch ? "YES" : "NO"}`);
  if (!sharedMatch) return false;

  // Derive symmetric key via HKDF
  const context = new TextEncoder().encode(`test-${curveName.toLowerCase()}`);
  const symmetricKey = hkdf(Module, senderShared, null, context, 32);
  const recipientKey = hkdf(Module, recipientShared, null, context, 32);

  const keyMatch = toHex(symmetricKey) === toHex(recipientKey);
  console.log(`Derived keys match: ${keyMatch ? "YES" : "NO"}`);
  if (!keyMatch) return false;

  // Encrypt some data with AES-256-CTR
  const plaintext = new TextEncoder().encode("This is a secret message!");
  const iv = new Uint8Array(16); // zero IV for demo
  crypto.getRandomValues(iv);
  console.log(`Plaintext: "${new TextDecoder().decode(plaintext)}"`);

  const ciphertext = encryptBytes(Module, plaintext, symmetricKey, iv);
  console.log(`Ciphertext: ${toHex(ciphertext).substring(0, 40)}...`);

  const changed = toHex(plaintext) !== toHex(ciphertext);
  console.log(`Buffer encrypted: ${changed ? "YES" : "NO"}`);
  if (!changed) return false;

  // Decrypt with recipient's derived key
  const decrypted = decryptBytes(Module, ciphertext, recipientKey, iv);
  const decryptedText = new TextDecoder().decode(decrypted);
  console.log(`Decrypted: "${decryptedText}"`);

  const matches = decryptedText === "This is a secret message!";
  console.log(`Decryption matches original: ${matches ? "YES" : "NO"}`);

  return matches;
}

async function main() {
  console.log("=== Multi-Curve Public Key Encryption Test ===");

  const Module = await loadModule();

  const results = {
    x25519: testCurve(Module, "X25519", x25519GenerateKeyPair, x25519SharedSecret),
    secp256k1: testCurve(Module, "secp256k1", secp256k1GenerateKeyPair, secp256k1SharedSecret),
    p256: testCurve(Module, "P-256", p256GenerateKeyPair, p256SharedSecret),
  };

  console.log("\n=== Summary ===");
  console.log(`X25519:    ${results.x25519 ? "PASS" : "FAIL"}`);
  console.log(`secp256k1: ${results.secp256k1 ? "PASS" : "FAIL"}`);
  console.log(`P-256:     ${results.p256 ? "PASS" : "FAIL"}`);

  const allPassed = results.x25519 && results.secp256k1 && results.p256;
  console.log(`\nOverall: ${allPassed ? "ALL TESTS PASSED" : "SOME TESTS FAILED"}`);

  if (!allPassed) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("Error:", err);
  process.exit(1);
});
