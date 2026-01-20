#!/usr/bin/env node
/**
 * P-256 (secp256r1) ECDH Test (NIST curve)
 */

import {
  p256GenerateKeyPair,
  p256SharedSecret,
  p256DeriveKey,
} from "flatc-wasm/encryption";

function toHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function testBasicKeyExchange() {
  console.log("=== Testing P-256 Key Exchange ===\n");

  // Generate Alice's key pair
  const alice = p256GenerateKeyPair();
  console.log("Alice's private key:", toHex(alice.privateKey));
  console.log("Alice's public key: ", toHex(alice.publicKey));
  console.log("  (compressed, 33 bytes)");
  console.log();

  // Generate Bob's key pair
  const bob = p256GenerateKeyPair();
  console.log("Bob's private key:  ", toHex(bob.privateKey));
  console.log("Bob's public key:   ", toHex(bob.publicKey));
  console.log();

  // Alice computes shared secret with Bob's public key
  const aliceShared = p256SharedSecret(alice.privateKey, bob.publicKey);
  console.log("Alice's shared secret:", toHex(aliceShared));

  // Bob computes shared secret with Alice's public key
  const bobShared = p256SharedSecret(bob.privateKey, alice.publicKey);
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

  const aliceDerived = p256DeriveKey(aliceShared);
  const bobDerived = p256DeriveKey(bobShared);

  console.log("Alice's derived key:", toHex(aliceDerived));
  console.log("Bob's derived key:  ", toHex(bobDerived));

  const derivedMatch = toHex(aliceDerived) === toHex(bobDerived);
  console.log("\nDerived keys match:", derivedMatch ? "YES" : "NO");

  return match && derivedMatch;
}

function testKnownVector() {
  console.log("\n=== Testing Known Vector (NIST P-256) ===\n");

  // NIST P-256 test vectors
  // Using small private keys for predictable results

  // Private key 1
  const alicePrivate = new Uint8Array([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
  ]);

  // Generator point G is the public key for private key = 1
  // G.x = 6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
  // G.y = 4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
  // Compressed: 03 6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
  // (03 prefix because G.y ends in f5 which is odd)
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

  // 2G: x = 7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978
  //     y = 07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1
  // Compressed: 03 7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978
  // (03 prefix because 2G.y ends in d1 which is odd)
  const bobExpectedPublic = new Uint8Array([
    0x03,
    0x7c, 0xf2, 0x7b, 0x18, 0x8d, 0x03, 0x4f, 0x7e,
    0x8a, 0x52, 0x38, 0x03, 0x04, 0xb5, 0x1a, 0xc3,
    0xc0, 0x89, 0x69, 0xe2, 0x77, 0xf2, 0x1b, 0x35,
    0xa6, 0x0b, 0x48, 0xfc, 0x47, 0x66, 0x99, 0x78,
  ]);

  // Shared secret: 1 * 2G = 2 * 1G = 2G
  // The x-coordinate of 2G
  const expectedShared = new Uint8Array([
    0x7c, 0xf2, 0x7b, 0x18, 0x8d, 0x03, 0x4f, 0x7e,
    0x8a, 0x52, 0x38, 0x03, 0x04, 0xb5, 0x1a, 0xc3,
    0xc0, 0x89, 0x69, 0xe2, 0x77, 0xf2, 0x1b, 0x35,
    0xa6, 0x0b, 0x48, 0xfc, 0x47, 0x66, 0x99, 0x78,
  ]);

  // Generate Alice's public key
  const alice = p256GenerateKeyPair(alicePrivate);
  console.log("Alice's public key (computed): ", toHex(alice.publicKey));
  console.log("Alice's public key (expected): ", toHex(aliceExpectedPublic));
  const aliceMatch = toHex(alice.publicKey) === toHex(aliceExpectedPublic);
  console.log("Match:", aliceMatch ? "YES" : "NO");
  console.log();

  // Generate Bob's public key
  const bob = p256GenerateKeyPair(bobPrivate);
  console.log("Bob's public key (computed): ", toHex(bob.publicKey));
  console.log("Bob's public key (expected): ", toHex(bobExpectedPublic));
  const bobMatch = toHex(bob.publicKey) === toHex(bobExpectedPublic);
  console.log("Match:", bobMatch ? "YES" : "NO");
  console.log();

  // Compute shared secret (Alice using Bob's public key)
  const aliceShared = p256SharedSecret(alice.privateKey, bob.publicKey);
  console.log("Alice's shared secret (computed):", toHex(aliceShared));
  console.log("Shared secret (expected):        ", toHex(expectedShared));
  const aliceSharedMatch = toHex(aliceShared) === toHex(expectedShared);
  console.log("Match:", aliceSharedMatch ? "YES" : "NO");
  console.log();

  // Compute shared secret (Bob using Alice's public key)
  const bobShared = p256SharedSecret(bob.privateKey, alice.publicKey);
  console.log("Bob's shared secret (computed):  ", toHex(bobShared));
  console.log("Shared secret (expected):        ", toHex(expectedShared));
  const bobSharedMatch = toHex(bobShared) === toHex(expectedShared);
  console.log("Match:", bobSharedMatch ? "YES" : "NO");

  return aliceMatch && bobMatch && aliceSharedMatch && bobSharedMatch;
}

const basicOk = testBasicKeyExchange();
const vectorOk = testKnownVector();

console.log("\n=== Summary ===");
console.log("Basic key exchange:", basicOk ? "PASS" : "FAIL");
console.log("Known vectors:", vectorOk ? "PASS" : "FAIL");

if (!basicOk || !vectorOk) {
  process.exit(1);
}
