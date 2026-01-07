#!/usr/bin/env node
/**
 * Cross-language verification test for Node.js/JavaScript encryption implementation.
 *
 * This script loads test vectors and verifies that the JavaScript implementation
 * can correctly decrypt buffers it previously encrypted.
 *
 * Usage: node verify_node.mjs
 */

import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { decryptBuffer, EncryptionContext } from "flatc-wasm/encryption";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function fromHex(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function toHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function main() {
  // Load test vectors
  const vectorsPath = join(__dirname, "test_vectors.json");
  const data = readFileSync(vectorsPath, "utf-8");
  const testData = JSON.parse(data);

  const key = fromHex(testData.key_hex);
  const ctx = new EncryptionContext(key);

  console.log(`Testing against ${testData.flatc_version}`);
  console.log(`Key: ${testData.key_hex.substring(0, 16)}...`);
  console.log();

  let passed = 0;
  let failed = 0;

  for (const vector of testData.vectors) {
    // Skip if no encryption happened
    if (vector.original_hex === vector.encrypted_hex) {
      console.log(`SKIP: ${vector.name} (no encrypted fields present)`);
      continue;
    }

    // Decrypt using our JavaScript implementation
    const encrypted = fromHex(vector.encrypted_hex);
    decryptBuffer(encrypted, vector.schema, ctx, vector.root_type);
    const decryptedHex = toHex(encrypted);

    if (decryptedHex === vector.original_hex) {
      console.log(`PASS: ${vector.name}`);
      passed++;
    } else {
      console.log(`FAIL: ${vector.name}`);
      console.log(`  Expected: ${vector.original_hex.substring(0, 80)}...`);
      console.log(`  Got:      ${decryptedHex.substring(0, 80)}...`);
      failed++;
    }
  }

  console.log();
  console.log(`Results: ${passed} passed, ${failed} failed`);
  if (failed > 0) {
    process.exit(1);
  }
}

main();
