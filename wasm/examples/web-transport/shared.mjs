/**
 * Shared utilities for web transport examples
 */

import { fileURLToPath } from 'url';
import path from 'path';
import { FlatcRunner } from "flatc-wasm";
import { loadEncryptionWasm, isInitialized } from "../../src/encryption.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Schema for messages
export const schemaContent = `
  attribute "encrypted";

  table Message {
    id: string;
    sender: string;
    content: string (encrypted);
    timestamp: long (encrypted);
    public_tag: string;
  }

  root_type Message;
`;

export const schemaInput = {
  entry: "/schema.fbs",
  files: { "/schema.fbs": schemaContent },
};

// Non-encrypted schema (for comparison)
export const plainSchemaContent = `
  table Message {
    id: string;
    sender: string;
    content: string;
    timestamp: long;
    public_tag: string;
  }

  root_type Message;
`;

export const plainSchemaInput = {
  entry: "/schema.fbs",
  files: { "/schema.fbs": plainSchemaContent },
};

let runnerInstance = null;
let encryptionInitialized = false;

/**
 * Initialize the encryption WASM module (call once before using encryption)
 */
export async function initEncryption() {
  if (!encryptionInitialized && !isInitialized()) {
    const wasmPath = path.join(__dirname, '..', '..', 'dist', 'flatc-encryption.wasm');
    await loadEncryptionWasm(wasmPath);
    encryptionInitialized = true;
  }
}

export async function getRunner() {
  if (!runnerInstance) {
    runnerInstance = await FlatcRunner.init();
  }
  // Also init encryption when getting runner
  await initEncryption();
  return runnerInstance;
}

export function toHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function fromHex(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

export function generateId() {
  return Math.random().toString(36).substring(2, 10);
}
