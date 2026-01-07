#!/usr/bin/env node
/**
 * Header Formats Demo
 *
 * Demonstrates both JSON and FlatBuffer binary formats for session headers.
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
  x25519GenerateKeyPair,
  EncryptionContext,
  encryptBuffer,
  decryptBuffer,
} from "flatc-wasm/encryption";
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
import { schemaContent, schemaInput, getRunner, toHex } from "./shared.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DEMO_DIR = join(__dirname, "demo_output");

async function main() {
  console.log("=== Header Formats Demo ===\n");
  console.log("This demo shows both JSON and FlatBuffer binary formats for headers.\n");

  // Create output directory
  if (!existsSync(DEMO_DIR)) {
    await mkdir(DEMO_DIR);
  }

  const runner = await getRunner();

  // Generate key pairs
  const recipientKeys = x25519GenerateKeyPair();
  console.log("Recipient public key:", toHex(recipientKeys.publicKey));
  console.log();

  // Create encryption context
  const encryptCtx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
    context: "demo-session-v1",
    rootType: "Message",
  });

  const header = encryptCtx.getHeader();
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
  const sessionBinary = await sessionToBinary(session);
  const binPath = join(DEMO_DIR, "session.bin");
  await writeFile(binPath, sessionBinary);
  console.log(`Saved session.bin (${sessionBinary.length} bytes)`);

  // Load from binary
  const loadedBinary = await readFile(binPath);
  const sessionFromBinaryFile = await sessionFromBinary(new Uint8Array(loadedBinary));
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

  // Header as binary FlatBuffer
  const headerBinary = await headerToBinary(header);
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

  // Encrypt and save messages
  const encryptedFiles = [];
  for (let i = 0; i < testMessages.length; i++) {
    const msg = testMessages[i];
    const buffer = runner.generateBinary(schemaInput, JSON.stringify(msg));
    encryptBuffer(buffer, schemaContent, encryptCtx, "Message");

    const filename = `${String(i + 1).padStart(3, "0")}.bin`;
    await writeFile(join(DEMO_DIR, filename), buffer);
    encryptedFiles.push(filename);
    console.log(`Encrypted ${filename} (${buffer.length} bytes)`);
  }

  // Update session with actual files and re-save
  session.files = encryptedFiles;
  await writeFile(jsonPath, sessionToJSON(session));
  await writeFile(binPath, await sessionToBinary(session));
  console.log(`\nUpdated session files with: ${encryptedFiles.join(", ")}`);
  console.log();

  // Now simulate loading from disk and decrypting
  console.log("--- Simulating Load from Disk ---\n");

  // Load session (using binary format this time)
  const loadedSessionBin = await readFile(binPath);
  const loadedSession = await sessionFromBinary(new Uint8Array(loadedSessionBin));

  // Create decryption context from loaded header
  const decryptCtx = EncryptionContext.forDecryption(
    recipientKeys.privateKey,
    loadedSession.header
  );

  // Decrypt each file
  console.log("Decrypting files using header from session.bin:");
  for (const filename of loadedSession.files) {
    const encrypted = await readFile(join(DEMO_DIR, filename));
    const buffer = new Uint8Array(encrypted);
    decryptBuffer(buffer, schemaContent, decryptCtx, "Message");

    const json = runner.generateJSON(schemaInput, {
      path: `/${filename}`,
      data: buffer,
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
