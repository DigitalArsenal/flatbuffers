#!/usr/bin/env node
/**
 * Multi-Curve Public Key Encryption Test
 *
 * Tests EncryptionContext with all three supported key exchange algorithms:
 * - X25519 (Curve25519)
 * - secp256k1 (Bitcoin/Ethereum)
 * - P-256 (NIST secp256r1)
 */

import {
  EncryptionContext,
  KeyExchangeAlgorithm,
  x25519GenerateKeyPair,
  secp256k1GenerateKeyPair,
  p256GenerateKeyPair,
  encryptBuffer,
  decryptBuffer,
  encryptionHeaderFromJSON,
} from "flatc-wasm/encryption";

import { FlatcRunner } from "flatc-wasm";

function toHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

const schemaContent = `
  attribute "encrypted";

  table SecretMessage {
    recipient: string;
    message: string (encrypted);
    secret_code: int (encrypted);
    public_note: string;
  }

  root_type SecretMessage;
`;

const schemaInput = {
  entry: "/schema.fbs",
  files: { "/schema.fbs": schemaContent },
};

const originalData = {
  recipient: "Alice",
  message: "This is a secret message!",
  secret_code: 42,
  public_note: "This note is not encrypted",
};

async function testCurve(curveName, keyExchange, generateKeyPair) {
  console.log(`\n=== Testing ${curveName} ===\n`);

  // Generate recipient key pair
  const recipientKeys = generateKeyPair();
  console.log(`Recipient public key: ${toHex(recipientKeys.publicKey).substring(0, 40)}...`);

  // Create FlatBuffer
  const runner = await FlatcRunner.init();
  const flatbuffer = runner.generateBinary(schemaInput, JSON.stringify(originalData));
  const originalHex = toHex(flatbuffer);

  // Encrypt using EncryptionContext
  const encryptCtx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
    algorithm: keyExchange,
    context: `test-${curveName.toLowerCase()}`,
    rootType: "SecretMessage",
  });

  const headerJSON = encryptCtx.getHeaderJSON();
  console.log(`Ephemeral public key: ${toHex(encryptCtx.getEphemeralPublicKey()).substring(0, 40)}...`);

  // Encrypt the buffer
  encryptBuffer(flatbuffer, schemaContent, encryptCtx, "SecretMessage");
  const encryptedHex = toHex(flatbuffer);

  const changed = originalHex !== encryptedHex;
  console.log(`Buffer encrypted: ${changed ? "YES" : "NO"}`);

  if (!changed) {
    console.log("ERROR: Buffer was not encrypted!");
    return false;
  }

  // Decrypt using recipient's private key
  const receivedHeader = encryptionHeaderFromJSON(headerJSON);
  const decryptCtx = EncryptionContext.forDecryption(
    recipientKeys.privateKey,
    receivedHeader,
    `test-${curveName.toLowerCase()}`
  );

  decryptBuffer(flatbuffer, schemaContent, decryptCtx, "SecretMessage");
  const decryptedHex = toHex(flatbuffer);

  const matches = decryptedHex === originalHex;
  console.log(`Decryption matches original: ${matches ? "YES" : "NO"}`);

  if (!matches) {
    console.log("ERROR: Decrypted buffer does not match original!");
    return false;
  }

  // Verify data
  const decryptedJson = runner.generateJSON(
    schemaInput,
    { path: "/decrypted.bin", data: flatbuffer }
  );
  const decryptedData = JSON.parse(decryptedJson);

  const dataMatches =
    decryptedData.recipient === originalData.recipient &&
    decryptedData.message === originalData.message &&
    decryptedData.secret_code === originalData.secret_code &&
    decryptedData.public_note === originalData.public_note;

  console.log(`Data verification: ${dataMatches ? "PASS" : "FAIL"}`);

  return dataMatches;
}

async function main() {
  console.log("=== Multi-Curve Public Key Encryption Test ===");

  const results = {
    x25519: await testCurve("X25519", KeyExchangeAlgorithm.X25519, x25519GenerateKeyPair),
    secp256k1: await testCurve("secp256k1", KeyExchangeAlgorithm.SECP256K1, secp256k1GenerateKeyPair),
    p256: await testCurve("P-256", KeyExchangeAlgorithm.P256, p256GenerateKeyPair),
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
