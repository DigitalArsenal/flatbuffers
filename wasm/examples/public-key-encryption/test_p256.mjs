#!/usr/bin/env node
/**
 * P-256 (secp256r1) ECDH Test (NIST curve) -- WASM binary exports
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

function p256GenerateKeyPair(Module, existingPrivate) {
  const privPtr = Module._malloc(32);
  const pubPtr = Module._malloc(33); // compressed public key

  if (existingPrivate) {
    Module.HEAPU8.set(existingPrivate, privPtr);
  }

  Module._wasm_crypto_p256_generate_keypair(privPtr, pubPtr);

  const privateKey = readBytes(Module, privPtr, 32);
  const publicKey = readBytes(Module, pubPtr, 33);
  Module._free(privPtr);
  Module._free(pubPtr);
  return { privateKey, publicKey };
}

function p256SharedSecret(Module, privateKey, publicKey) {
  const privPtr = allocBytes(Module, privateKey);
  const pubPtr = allocBytes(Module, publicKey);
  const outPtr = Module._malloc(32);

  Module._wasm_crypto_p256_shared_secret(privPtr, pubPtr, outPtr);

  const shared = readBytes(Module, outPtr, 32);
  Module._free(privPtr);
  Module._free(pubPtr);
  Module._free(outPtr);
  return shared;
}

function hkdf(Module, inputKey) {
  const ikmPtr = allocBytes(Module, inputKey);
  const outPtr = Module._malloc(32);
  Module._wasm_crypto_hkdf(ikmPtr, inputKey.length, 0, 0, 0, 0, outPtr, 32);
  const derived = readBytes(Module, outPtr, 32);
  Module._free(ikmPtr);
  Module._free(outPtr);
  return derived;
}

function testBasicKeyExchange(Module) {
  console.log("=== Testing P-256 Key Exchange ===\n");

  // Generate Alice's key pair
  const alice = p256GenerateKeyPair(Module);
  console.log("Alice's private key:", toHex(alice.privateKey));
  console.log("Alice's public key: ", toHex(alice.publicKey));
  console.log("  (compressed, 33 bytes)");
  console.log();

  // Generate Bob's key pair
  const bob = p256GenerateKeyPair(Module);
  console.log("Bob's private key:  ", toHex(bob.privateKey));
  console.log("Bob's public key:   ", toHex(bob.publicKey));
  console.log();

  // Alice computes shared secret with Bob's public key
  const aliceShared = p256SharedSecret(Module, alice.privateKey, bob.publicKey);
  console.log("Alice's shared secret:", toHex(aliceShared));

  // Bob computes shared secret with Alice's public key
  const bobShared = p256SharedSecret(Module, bob.privateKey, alice.publicKey);
  console.log("Bob's shared secret:  ", toHex(bobShared));

  // Compare
  const match = toHex(aliceShared) === toHex(bobShared);
  console.log("\nShared secrets match:", match ? "YES" : "NO");

  if (!match) {
    console.log("ERROR: Shared secrets do not match!");
    return false;
  }

  // Test key derivation
  console.log("\n=== Testing Key Derivation ===\n");

  const aliceDerived = hkdf(Module, aliceShared);
  const bobDerived = hkdf(Module, bobShared);

  console.log("Alice's derived key:", toHex(aliceDerived));
  console.log("Bob's derived key:  ", toHex(bobDerived));

  const derivedMatch = toHex(aliceDerived) === toHex(bobDerived);
  console.log("\nDerived keys match:", derivedMatch ? "YES" : "NO");

  return match && derivedMatch;
}

function testKnownVector(Module) {
  console.log("\n=== Testing Known Vector (NIST P-256) ===\n");

  // Private key 1
  const alicePrivate = new Uint8Array([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
  ]);

  // Generator G compressed (03 prefix because G.y is odd)
  const aliceExpectedPublic = new Uint8Array([
    0x03,
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
    0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
    0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
  ]);

  // Private key 2
  const bobPrivate = new Uint8Array([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
  ]);

  // 2G compressed (03 prefix because 2G.y is odd)
  const bobExpectedPublic = new Uint8Array([
    0x03,
    0x7c, 0xf2, 0x7b, 0x18, 0x8d, 0x03, 0x4f, 0x7e,
    0x8a, 0x52, 0x38, 0x03, 0x04, 0xb5, 0x1a, 0xc3,
    0xc0, 0x89, 0x69, 0xe2, 0x77, 0xf2, 0x1b, 0x35,
    0xa6, 0x0b, 0x48, 0xfc, 0x47, 0x66, 0x99, 0x78,
  ]);

  // x-coordinate of 2G
  const expectedShared = new Uint8Array([
    0x7c, 0xf2, 0x7b, 0x18, 0x8d, 0x03, 0x4f, 0x7e,
    0x8a, 0x52, 0x38, 0x03, 0x04, 0xb5, 0x1a, 0xc3,
    0xc0, 0x89, 0x69, 0xe2, 0x77, 0xf2, 0x1b, 0x35,
    0xa6, 0x0b, 0x48, 0xfc, 0x47, 0x66, 0x99, 0x78,
  ]);

  const alice = p256GenerateKeyPair(Module, alicePrivate);
  console.log("Alice's public key (computed): ", toHex(alice.publicKey));
  console.log("Alice's public key (expected): ", toHex(aliceExpectedPublic));
  const aliceMatch = toHex(alice.publicKey) === toHex(aliceExpectedPublic);
  console.log("Match:", aliceMatch ? "YES" : "NO");
  console.log();

  const bob = p256GenerateKeyPair(Module, bobPrivate);
  console.log("Bob's public key (computed): ", toHex(bob.publicKey));
  console.log("Bob's public key (expected): ", toHex(bobExpectedPublic));
  const bobMatch = toHex(bob.publicKey) === toHex(bobExpectedPublic);
  console.log("Match:", bobMatch ? "YES" : "NO");
  console.log();

  const aliceShared = p256SharedSecret(Module, alice.privateKey, bob.publicKey);
  console.log("Alice's shared secret (computed):", toHex(aliceShared));
  console.log("Shared secret (expected):        ", toHex(expectedShared));
  const aliceSharedMatch = toHex(aliceShared) === toHex(expectedShared);
  console.log("Match:", aliceSharedMatch ? "YES" : "NO");
  console.log();

  const bobShared = p256SharedSecret(Module, bob.privateKey, alice.publicKey);
  console.log("Bob's shared secret (computed):  ", toHex(bobShared));
  console.log("Shared secret (expected):        ", toHex(expectedShared));
  const bobSharedMatch = toHex(bobShared) === toHex(expectedShared);
  console.log("Match:", bobSharedMatch ? "YES" : "NO");

  return aliceMatch && bobMatch && aliceSharedMatch && bobSharedMatch;
}

async function main() {
  const Module = await loadModule();

  const basicOk = testBasicKeyExchange(Module);
  const vectorOk = testKnownVector(Module);

  console.log("\n=== Summary ===");
  console.log("Basic key exchange:", basicOk ? "PASS" : "FAIL");
  console.log("Known vectors:", vectorOk ? "PASS" : "FAIL");

  if (!basicOk || !vectorOk) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("Error:", err);
  process.exit(1);
});
