#!/usr/bin/env node
/**
 * X25519 ECDH Test
 */

import {
  x25519GenerateKeyPair,
  x25519SharedSecret,
  x25519DeriveKey,
} from "flatc-wasm/encryption";

function toHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function testBasicKeyExchange() {
  console.log("=== Testing X25519 Key Exchange ===\n");

  // Generate Alice's key pair
  const alice = x25519GenerateKeyPair();
  console.log("Alice's private key:", toHex(alice.privateKey));
  console.log("Alice's public key: ", toHex(alice.publicKey));
  console.log();

  // Generate Bob's key pair
  const bob = x25519GenerateKeyPair();
  console.log("Bob's private key:  ", toHex(bob.privateKey));
  console.log("Bob's public key:   ", toHex(bob.publicKey));
  console.log();

  // Alice computes shared secret with Bob's public key
  const aliceShared = x25519SharedSecret(alice.privateKey, bob.publicKey);
  console.log("Alice's shared secret:", toHex(aliceShared));

  // Bob computes shared secret with Alice's public key
  const bobShared = x25519SharedSecret(bob.privateKey, alice.publicKey);
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

  const aliceDerived = x25519DeriveKey(aliceShared);
  const bobDerived = x25519DeriveKey(bobShared);

  console.log("Alice's derived key:", toHex(aliceDerived));
  console.log("Bob's derived key:  ", toHex(bobDerived));

  const derivedMatch = toHex(aliceDerived) === toHex(bobDerived);
  console.log("\nDerived keys match:", derivedMatch ? "YES" : "NO");

  return match && derivedMatch;
}

function testKnownVector() {
  console.log("\n=== Testing Known Vector (RFC 7748) ===\n");

  // RFC 7748 test vector
  const alicePrivate = new Uint8Array([
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
    0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
    0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
    0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
  ]);

  const bobPrivate = new Uint8Array([
    0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
    0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
    0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
    0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
  ]);

  // Expected public keys from RFC 7748
  const aliceExpectedPublic = new Uint8Array([
    0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
    0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
    0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
    0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
  ]);

  const bobExpectedPublic = new Uint8Array([
    0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
    0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
    0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
    0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
  ]);

  // Expected shared secret
  const expectedShared = new Uint8Array([
    0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
    0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
    0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
    0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42,
  ]);

  // Generate Alice's public key
  const alice = x25519GenerateKeyPair(alicePrivate);
  console.log("Alice's public key (computed): ", toHex(alice.publicKey));
  console.log("Alice's public key (expected): ", toHex(aliceExpectedPublic));
  const aliceMatch = toHex(alice.publicKey) === toHex(aliceExpectedPublic);
  console.log("Match:", aliceMatch ? "YES" : "NO");
  console.log();

  // Generate Bob's public key
  const bob = x25519GenerateKeyPair(bobPrivate);
  console.log("Bob's public key (computed): ", toHex(bob.publicKey));
  console.log("Bob's public key (expected): ", toHex(bobExpectedPublic));
  const bobMatch = toHex(bob.publicKey) === toHex(bobExpectedPublic);
  console.log("Match:", bobMatch ? "YES" : "NO");
  console.log();

  // Compute shared secret
  const shared = x25519SharedSecret(alice.privateKey, bob.publicKey);
  console.log("Shared secret (computed):", toHex(shared));
  console.log("Shared secret (expected):", toHex(expectedShared));
  const sharedMatch = toHex(shared) === toHex(expectedShared);
  console.log("Match:", sharedMatch ? "YES" : "NO");

  return aliceMatch && bobMatch && sharedMatch;
}

const basicOk = testBasicKeyExchange();
const vectorOk = testKnownVector();

console.log("\n=== Summary ===");
console.log("Basic key exchange:", basicOk ? "PASS" : "FAIL");
console.log("RFC 7748 vectors:", vectorOk ? "PASS" : "FAIL");

if (!basicOk || !vectorOk) {
  process.exit(1);
}
