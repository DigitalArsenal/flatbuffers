#!/usr/bin/env node
/**
 * secp256k1 ECDH Test (Bitcoin/Ethereum curve)
 */

import {
  secp256k1GenerateKeyPair,
  secp256k1SharedSecret,
  secp256k1DeriveKey,
} from "flatc-wasm/encryption";

function toHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function testBasicKeyExchange() {
  console.log("=== Testing secp256k1 Key Exchange ===\n");

  // Generate Alice's key pair
  const alice = secp256k1GenerateKeyPair();
  console.log("Alice's private key:", toHex(alice.privateKey));
  console.log("Alice's public key: ", toHex(alice.publicKey));
  console.log("  (compressed, 33 bytes)");
  console.log();

  // Generate Bob's key pair
  const bob = secp256k1GenerateKeyPair();
  console.log("Bob's private key:  ", toHex(bob.privateKey));
  console.log("Bob's public key:   ", toHex(bob.publicKey));
  console.log();

  // Alice computes shared secret with Bob's public key
  const aliceShared = secp256k1SharedSecret(alice.privateKey, bob.publicKey);
  console.log("Alice's shared secret:", toHex(aliceShared));

  // Bob computes shared secret with Alice's public key
  const bobShared = secp256k1SharedSecret(bob.privateKey, alice.publicKey);
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

  const aliceDerived = secp256k1DeriveKey(aliceShared);
  const bobDerived = secp256k1DeriveKey(bobShared);

  console.log("Alice's derived key:", toHex(aliceDerived));
  console.log("Bob's derived key:  ", toHex(bobDerived));

  const derivedMatch = toHex(aliceDerived) === toHex(bobDerived);
  console.log("\nDerived keys match:", derivedMatch ? "YES" : "NO");

  return match && derivedMatch;
}

function testKnownVector() {
  console.log("\n=== Testing Known Vector (secp256k1) ===\n");

  // Test vector from Bitcoin/Ethereum ECDH
  // Private key 1
  const alicePrivate = new Uint8Array([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
  ]);

  // Generator point G is the public key for private key = 1
  // Compressed: 02 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
  const aliceExpectedPublic = new Uint8Array([
    0x02,
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
    0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
    0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
  ]);

  // Private key 2
  const bobPrivate = new Uint8Array([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
  ]);

  // 2G: Compressed 02 C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5
  const bobExpectedPublic = new Uint8Array([
    0x02,
    0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d,
    0x30, 0x45, 0x40, 0x6e, 0x95, 0xc0, 0x7c, 0xd8,
    0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7,
    0xab, 0xac, 0x09, 0xb9, 0x5c, 0x70, 0x9e, 0xe5,
  ]);

  // Shared secret: 1 * 2G = 2 * 1G = 2G
  // The x-coordinate of 2G
  const expectedShared = new Uint8Array([
    0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d,
    0x30, 0x45, 0x40, 0x6e, 0x95, 0xc0, 0x7c, 0xd8,
    0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7,
    0xab, 0xac, 0x09, 0xb9, 0x5c, 0x70, 0x9e, 0xe5,
  ]);

  // Generate Alice's public key
  const alice = secp256k1GenerateKeyPair(alicePrivate);
  console.log("Alice's public key (computed): ", toHex(alice.publicKey));
  console.log("Alice's public key (expected): ", toHex(aliceExpectedPublic));
  const aliceMatch = toHex(alice.publicKey) === toHex(aliceExpectedPublic);
  console.log("Match:", aliceMatch ? "YES" : "NO");
  console.log();

  // Generate Bob's public key
  const bob = secp256k1GenerateKeyPair(bobPrivate);
  console.log("Bob's public key (computed): ", toHex(bob.publicKey));
  console.log("Bob's public key (expected): ", toHex(bobExpectedPublic));
  const bobMatch = toHex(bob.publicKey) === toHex(bobExpectedPublic);
  console.log("Match:", bobMatch ? "YES" : "NO");
  console.log();

  // Compute shared secret (Alice using Bob's public key)
  const aliceShared = secp256k1SharedSecret(alice.privateKey, bob.publicKey);
  console.log("Alice's shared secret (computed):", toHex(aliceShared));
  console.log("Shared secret (expected):        ", toHex(expectedShared));
  const aliceSharedMatch = toHex(aliceShared) === toHex(expectedShared);
  console.log("Match:", aliceSharedMatch ? "YES" : "NO");
  console.log();

  // Compute shared secret (Bob using Alice's public key)
  const bobShared = secp256k1SharedSecret(bob.privateKey, alice.publicKey);
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
