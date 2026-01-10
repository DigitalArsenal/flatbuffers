#!/usr/bin/env node
/**
 * Public Key Encryption Example
 *
 * This example demonstrates how to use X25519 (Curve25519) ECDH for
 * hybrid encryption of FlatBuffers.
 *
 * The workflow:
 * 1. Recipient generates a long-term X25519 key pair
 * 2. Sender encrypts a FlatBuffer using recipient's public key
 *    - Generates ephemeral X25519 key pair
 *    - Computes shared secret via ECDH
 *    - Derives symmetric key via HKDF
 *    - Encrypts fields with AES-256-CTR
 * 3. Sender sends encrypted FlatBuffer + EncryptionHeader to recipient
 * 4. Recipient decrypts using their private key + ephemeral public key from header
 *
 * Usage: node example.mjs
 */

import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

import {
  loadEncryptionWasm,
  EncryptionContext,
  x25519GenerateKeyPair,
  encryptBuffer,
  decryptBuffer,
  encryptionHeaderFromJSON,
} from "../../src/encryption.mjs";

import { FlatcRunner } from "flatc-wasm";

function toHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function main() {
  console.log("=== Public Key Encryption Example ===\n");

  // Initialize the encryption WASM module
  const wasmPath = path.join(__dirname, '..', '..', 'dist', 'flatc-encryption.wasm');
  console.log("Loading encryption WASM module...");
  await loadEncryptionWasm(wasmPath);
  console.log("WASM module loaded.\n");

  // Step 1: Recipient generates their long-term key pair
  console.log("1. Recipient generates X25519 key pair...");
  const recipientKeys = x25519GenerateKeyPair();
  console.log(`   Private key: ${toHex(recipientKeys.privateKey).substring(0, 32)}...`);
  console.log(`   Public key:  ${toHex(recipientKeys.publicKey).substring(0, 32)}...\n`);

  // Step 2: Sender prepares a FlatBuffer to encrypt
  console.log("2. Sender creates a FlatBuffer with sensitive data...");

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

  console.log(`   Original data: ${JSON.stringify(originalData)}\n`);

  // Create FlatBuffer using FlatcRunner
  const runner = await FlatcRunner.init();
  const flatbuffer = runner.generateBinary(schemaInput, JSON.stringify(originalData));
  console.log(`   FlatBuffer size: ${flatbuffer.length} bytes`);

  // Make a copy of the original for comparison
  const originalHex = toHex(flatbuffer);

  // Step 3: Sender encrypts using recipient's public key
  console.log("\n3. Sender encrypts using recipient's public key...");
  const appContext = "example-app-v1";
  const encryptCtx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
    algorithm: "x25519",
    context: appContext,
    rootType: "SecretMessage",
  });

  // Get the encryption header (must be sent to recipient along with encrypted data)
  const headerJSON = encryptCtx.getHeaderJSON();
  console.log(`   Ephemeral public key: ${toHex(encryptCtx.getEphemeralPublicKey()).substring(0, 32)}...`);
  console.log(`   Header: ${headerJSON.substring(0, 100)}...\n`);

  // Encrypt the buffer
  encryptBuffer(flatbuffer, schemaContent, encryptCtx, "SecretMessage");
  const encryptedHex = toHex(flatbuffer);
  console.log(`   Original hex:  ${originalHex.substring(0, 60)}...`);
  console.log(`   Encrypted hex: ${encryptedHex.substring(0, 60)}...`);
  console.log(`   Buffer changed: ${originalHex !== encryptedHex ? "YES" : "NO"}\n`);

  // Step 4: Recipient receives encrypted data + header
  console.log("4. Recipient receives encrypted data and header...");

  // Simulate transmission - recipient parses the header
  const receivedHeader = encryptionHeaderFromJSON(headerJSON);
  console.log(`   Received ephemeral key: ${toHex(receivedHeader.senderPublicKey).substring(0, 32)}...`);
  console.log(`   Algorithm: ${receivedHeader.algorithm}`);
  console.log(`   Context: ${receivedHeader.context || appContext}`);

  // Step 5: Recipient decrypts using their private key
  console.log("\n5. Recipient decrypts using their private key...");
  const decryptCtx = EncryptionContext.forDecryption(
    recipientKeys.privateKey,
    receivedHeader,
    appContext  // Pass context explicitly for key derivation
  );

  // Decrypt the buffer
  decryptBuffer(flatbuffer, schemaContent, decryptCtx, "SecretMessage");
  const decryptedHex = toHex(flatbuffer);

  console.log(`   Decrypted hex: ${decryptedHex.substring(0, 60)}...`);
  console.log(`   Matches original: ${decryptedHex === originalHex ? "YES" : "NO"}\n`);

  // Step 6: Verify by reading back the data
  console.log("6. Verifying decrypted data...");
  const decryptedJson = runner.generateJSON(
    schemaInput,
    { path: "/decrypted.bin", data: flatbuffer }
  );
  const decryptedData = JSON.parse(decryptedJson);
  console.log(`   Decrypted: ${JSON.stringify(decryptedData)}`);
  console.log(`   Original:  ${JSON.stringify(originalData)}`);

  const success =
    decryptedData.recipient === originalData.recipient &&
    decryptedData.message === originalData.message &&
    decryptedData.secret_code === originalData.secret_code &&
    decryptedData.public_note === originalData.public_note;

  console.log(`\n=== Test ${success ? "PASSED" : "FAILED"} ===`);

  if (!success) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("Error:", err);
  process.exit(1);
});
