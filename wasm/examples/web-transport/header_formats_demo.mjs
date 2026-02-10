#!/usr/bin/env node
/**
 * Header Formats Demo
 *
 * Demonstrates both JSON and FlatBuffer binary formats for session headers.
 * All crypto operations use WASM binary exports (Module._wasm_crypto_*).
 *
 * Shows how to:
 * - Create an encryption session
 * - Save headers in JSON format
 * - Save headers in FlatBuffer binary format
 * - Load and use headers from both formats
 *
 * Usage: node header_formats_demo.mjs
 */

import { writeFile, readFile, mkdir } from "fs/promises";
import { existsSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import {
  getWasmModule,
  getRunner,
  schemaContent,
  schemaInput,
  toHex,
  fromHex,
} from "./shared.mjs";
import {
  createSession,
  sessionToJSON,
  sessionFromJSON,
  sessionToBinary,
  sessionFromBinary,
  headerToBinary,
  headerFromBinary,
  headerToJSON,
  headerFromJSON,
} from "./header_store.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DEMO_DIR = join(__dirname, "demo_output");

// ---------------------------------------------------------------------------
// WASM memory helpers
// ---------------------------------------------------------------------------

let Module;

function allocBytes(data) {
  const ptr = Module._malloc(data.length);
  Module.HEAPU8.set(data, ptr);
  return ptr;
}

function readBytes(ptr, len) {
  return new Uint8Array(Module.HEAPU8.buffer, ptr, len).slice();
}

function freeBytes(ptr) {
  Module._free(ptr);
}

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

function x25519GenerateKeyPair() {
  const privPtr = Module._malloc(32);
  const pubPtr = Module._malloc(32);
  const rc = Module._wasm_crypto_x25519_generate_keypair(privPtr, pubPtr);
  if (rc !== 0) throw new Error("x25519 keypair generation failed");
  const privateKey = readBytes(privPtr, 32);
  const publicKey = readBytes(pubPtr, 32);
  freeBytes(privPtr);
  freeBytes(pubPtr);
  return { privateKey, publicKey };
}

function x25519SharedSecret(privateKey, myPublicKey, peerPublicKey) {
  const privPtr = allocBytes(privateKey);
  const myPubPtr = allocBytes(myPublicKey);
  const peerPubPtr = allocBytes(peerPublicKey);
  const secretPtr = Module._malloc(32);
  const rc = Module._wasm_crypto_x25519_shared_secret(privPtr, myPubPtr, peerPubPtr, secretPtr);
  if (rc !== 0) throw new Error("x25519 shared secret failed");
  const secret = readBytes(secretPtr, 32);
  freeBytes(privPtr);
  freeBytes(myPubPtr);
  freeBytes(peerPubPtr);
  freeBytes(secretPtr);
  return secret;
}

function deriveSymmetricKey(sharedSecret, context) {
  const ssPtr = allocBytes(sharedSecret);
  const ctxBytes = new TextEncoder().encode(context);
  const ctxPtr = allocBytes(ctxBytes);
  const outLen = 32;
  const outPtr = Module._malloc(outLen);
  Module._wasm_crypto_derive_symmetric_key(
    ssPtr, sharedSecret.length,
    ctxPtr, ctxBytes.length,
    outPtr, outLen
  );
  const key = readBytes(outPtr, outLen);
  freeBytes(ssPtr);
  freeBytes(ctxPtr);
  freeBytes(outPtr);
  return key;
}

function encryptBytes(key, iv, data) {
  const keyPtr = allocBytes(key);
  const ivPtr = allocBytes(iv);
  const dataPtr = allocBytes(data);
  const rc = Module._wasm_crypto_encrypt_bytes(keyPtr, ivPtr, dataPtr, data.length);
  if (rc !== 0) throw new Error("encryption failed");
  const result = readBytes(dataPtr, data.length);
  freeBytes(keyPtr);
  freeBytes(ivPtr);
  freeBytes(dataPtr);
  return result;
}

function decryptBytes(key, iv, data) {
  const keyPtr = allocBytes(key);
  const ivPtr = allocBytes(iv);
  const dataPtr = allocBytes(data);
  const rc = Module._wasm_crypto_decrypt_bytes(keyPtr, ivPtr, dataPtr, data.length);
  if (rc !== 0) throw new Error("decryption failed");
  const result = readBytes(dataPtr, data.length);
  freeBytes(keyPtr);
  freeBytes(ivPtr);
  freeBytes(dataPtr);
  return result;
}

function sha256(data) {
  const dataPtr = allocBytes(data);
  const hashPtr = Module._malloc(32);
  Module._wasm_crypto_sha256(dataPtr, data.length, hashPtr);
  const hash = readBytes(hashPtr, 32);
  freeBytes(dataPtr);
  freeBytes(hashPtr);
  return hash;
}

// ---------------------------------------------------------------------------
// Encrypt / Decrypt helpers
// ---------------------------------------------------------------------------

function encryptFlatBuffer(buffer, peerPublicKey, context) {
  const ephemeral = x25519GenerateKeyPair();
  const shared = x25519SharedSecret(ephemeral.privateKey, ephemeral.publicKey, peerPublicKey);
  const key = deriveSymmetricKey(shared, context);
  const iv = sha256(ephemeral.publicKey).slice(0, 16);
  const enc = encryptBytes(key, iv, buffer);
  return {
    encrypted: enc,
    header: {
      key_exchange: 0, // 0 = X25519
      ephemeral_public_key: Array.from(ephemeral.publicKey),
      iv: Array.from(iv),
      context,
    },
  };
}

function decryptFlatBuffer(buffer, privateKey, myPublicKey, header) {
  const ephPub = header.ephemeral_public_key instanceof Uint8Array
    ? header.ephemeral_public_key
    : new Uint8Array(header.ephemeral_public_key);
  const shared = x25519SharedSecret(privateKey, myPublicKey, ephPub);
  const key = deriveSymmetricKey(shared, header.context);
  const iv = header.iv instanceof Uint8Array
    ? header.iv
    : new Uint8Array(header.iv);
  return decryptBytes(key, iv, buffer);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  Module = await getWasmModule();

  console.log("=== Header Formats Demo ===\n");
  console.log("This demo shows both JSON and FlatBuffer binary formats for headers.\n");

  // Create output directory
  if (!existsSync(DEMO_DIR)) {
    await mkdir(DEMO_DIR);
  }

  const runner = await getRunner();

  // Generate key pairs using WASM crypto
  const recipientKeys = x25519GenerateKeyPair();
  console.log("Recipient public key:", toHex(recipientKeys.publicKey));
  console.log();

  // Create an ephemeral keypair and build a header (simulating EncryptionContext)
  const ephemeral = x25519GenerateKeyPair();
  const shared = x25519SharedSecret(ephemeral.privateKey, ephemeral.publicKey, recipientKeys.publicKey);
  const symKey = deriveSymmetricKey(shared, "demo-session-v1");
  const iv = sha256(ephemeral.publicKey).slice(0, 16);

  const header = {
    key_exchange: 0, // 0 = X25519
    ephemeral_public_key: Array.from(ephemeral.publicKey),
    iv: Array.from(iv),
    context: "demo-session-v1",
  };

  console.log("Created encryption header:");
  console.log(`  Key exchange: ${header.key_exchange} (0 = X25519)`);
  console.log(`  Context: ${header.context}`);
  console.log(`  Ephemeral key: ${toHex(new Uint8Array(header.ephemeral_public_key)).substring(0, 32)}...`);
  console.log();

  // ==========================================================================
  // Demo 1: JSON Format
  // ==========================================================================
  console.log("--- Demo 1: JSON Format ---\n");

  // Create a session
  const session = createSession(header, {
    description: "Demo session showing JSON format",
    files: ["001.bin", "002.bin", "003.bin"],
  });

  // Save as JSON
  const sessionJSON = sessionToJSON(session);
  const jsonPath = join(DEMO_DIR, "session.json");
  await writeFile(jsonPath, sessionJSON);
  console.log(`Saved session.json (${sessionJSON.length} bytes)`);

  // Load from JSON
  const loadedJSON = await readFile(jsonPath, "utf-8");
  const sessionFromJSONFile = sessionFromJSON(loadedJSON);
  console.log(`Loaded session from JSON:`);
  console.log(`  Session ID: ${sessionFromJSONFile.sessionId}`);
  console.log(`  Created: ${sessionFromJSONFile.created}`);
  console.log(`  Files: ${sessionFromJSONFile.files.join(", ")}`);
  console.log();

  // ==========================================================================
  // Demo 2: FlatBuffer Binary Format
  // ==========================================================================
  console.log("--- Demo 2: FlatBuffer Binary Format ---\n");

  // Save as binary
  const sessionBinary = sessionToBinary(session);
  const binPath = join(DEMO_DIR, "session.bin");
  await writeFile(binPath, sessionBinary);
  console.log(`Saved session.bin (${sessionBinary.length} bytes)`);

  // Load from binary
  const loadedBinary = await readFile(binPath);
  const sessionFromBinaryFile = sessionFromBinary(new Uint8Array(loadedBinary));
  console.log(`Loaded session from binary:`);
  console.log(`  Session ID: ${sessionFromBinaryFile.sessionId}`);
  console.log(`  Created: ${sessionFromBinaryFile.created}`);
  console.log(`  Files: ${sessionFromBinaryFile.files.join(", ")}`);
  console.log();

  // ==========================================================================
  // Demo 3: Header-Only Formats
  // ==========================================================================
  console.log("--- Demo 3: Header-Only Formats ---\n");

  // Header as JSON
  const headerJSONStr = headerToJSON(header);
  const headerJsonPath = join(DEMO_DIR, "header.json");
  await writeFile(headerJsonPath, headerJSONStr);
  console.log(`Saved header.json (${headerJSONStr.length} bytes)`);

  // Header as binary
  const headerBinary = headerToBinary(header);
  const headerBinPath = join(DEMO_DIR, "header.bin");
  await writeFile(headerBinPath, headerBinary);
  console.log(`Saved header.bin (${headerBinary.length} bytes)`);

  // Size comparison
  console.log(`\nSize comparison:`);
  console.log(`  session.json:  ${sessionJSON.length} bytes`);
  console.log(`  session.bin:   ${sessionBinary.length} bytes`);
  console.log(`  header.json:   ${headerJSONStr.length} bytes`);
  console.log(`  header.bin:    ${headerBinary.length} bytes`);
  console.log();

  // ==========================================================================
  // Demo 4: Full Encryption/Decryption Roundtrip
  // ==========================================================================
  console.log("--- Demo 4: Full Encryption/Decryption Roundtrip ---\n");

  // Create some test data
  const testMessages = [
    { id: "msg1", sender: "Alice", content: "Hello, World!", timestamp: Date.now(), public_tag: "greeting" },
    { id: "msg2", sender: "Bob", content: "Secret message", timestamp: Date.now(), public_tag: "reply" },
    { id: "msg3", sender: "Alice", content: "Top secret!", timestamp: Date.now(), public_tag: "final" },
  ];

  // Encrypt and save messages using the session's symmetric key
  const encryptedFiles = [];
  for (let i = 0; i < testMessages.length; i++) {
    const msg = testMessages[i];
    const buffer = runner.generateBinary(schemaInput, JSON.stringify(msg));
    const enc = encryptBytes(symKey, iv, buffer);

    const filename = `${String(i + 1).padStart(3, "0")}.bin`;
    await writeFile(join(DEMO_DIR, filename), enc);
    encryptedFiles.push(filename);
    console.log(`Encrypted ${filename} (${enc.length} bytes)`);
  }

  // Update session with actual files and re-save
  session.files = encryptedFiles;
  await writeFile(jsonPath, sessionToJSON(session));
  await writeFile(binPath, sessionToBinary(session));
  console.log(`\nUpdated session files with: ${encryptedFiles.join(", ")}`);
  console.log();

  // Now simulate loading from disk and decrypting
  console.log("--- Simulating Load from Disk ---\n");

  // Load session (using binary format this time)
  const loadedSessionBin = await readFile(binPath);
  const loadedSession = sessionFromBinary(new Uint8Array(loadedSessionBin));

  // Re-derive the symmetric key from loaded header + recipient private key
  const loadedEphPub = new Uint8Array(loadedSession.header.ephemeral_public_key);
  const loadedShared = x25519SharedSecret(
    recipientKeys.privateKey, recipientKeys.publicKey, loadedEphPub
  );
  const loadedKey = deriveSymmetricKey(loadedShared, loadedSession.header.context);
  const loadedIv = new Uint8Array(loadedSession.header.iv);

  // Decrypt each file
  console.log("Decrypting files using header from session.bin:");
  for (const filename of loadedSession.files) {
    const encrypted = await readFile(join(DEMO_DIR, filename));
    const decrypted = decryptBytes(loadedKey, loadedIv, new Uint8Array(encrypted));

    const json = runner.generateJSON(schemaInput, {
      path: `/${filename}`,
      data: decrypted,
    });
    const msg = JSON.parse(json);
    console.log(`  ${filename}: ${msg.sender} says "${msg.content}"`);
  }

  console.log();

  // ==========================================================================
  // Summary
  // ==========================================================================
  console.log("=== Summary ===\n");
  console.log("Files created in demo_output/:");
  console.log("  session.json  - Full session with metadata (JSON)");
  console.log("  session.bin   - Full session with metadata (Binary)");
  console.log("  header.json   - Header only (JSON)");
  console.log("  header.bin    - Header only (FlatBuffer binary)");
  console.log("  001.bin       - Encrypted FlatBuffer message");
  console.log("  002.bin       - Encrypted FlatBuffer message");
  console.log("  003.bin       - Encrypted FlatBuffer message");
  console.log();
  console.log("For IPFS storage, you can choose:");
  console.log("  - session.json + *.bin files (human-readable metadata)");
  console.log("  - session.bin + *.bin files (more compact)");
  console.log("  - header.bin + *.bin files (minimal, header only)");
  console.log();
}

main().catch(console.error);
