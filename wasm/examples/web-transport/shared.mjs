/**
 * Shared utilities for web transport examples
 *
 * All crypto operations use the WASM binary's exported wasm_crypto_* functions.
 */

import { fileURLToPath } from 'url';
import path from 'path';
import { FlatcRunner } from "flatc-wasm";

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
let wasmModule = null;

/**
 * Get the WASM module with crypto exports.
 * Load the Emscripten module directly — all crypto lives in the binary.
 */
export async function getWasmModule() {
  if (!wasmModule) {
    const wasmPath = path.join(__dirname, '..', '..', 'dist', 'flatc-wasm.js');
    const { default: createModule } = await import(wasmPath);
    wasmModule = await createModule({ noExitRuntime: true, noInitialRun: true });
  }
  return wasmModule;
}

export async function getRunner() {
  if (!runnerInstance) {
    runnerInstance = await FlatcRunner.init();
  }
  // Also ensure WASM module is loaded
  await getWasmModule();
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
