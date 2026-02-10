#!/usr/bin/env node
/**
 * Pipe Receiver Example -- WASM binary exports
 *
 * Reads a framed encrypted message from stdin, reconstructs the shared secret
 * using the recipient's private key and the sender's ephemeral public key,
 * derives the symmetric key via HKDF, and decrypts with AES-256-CTR.
 *
 * Usage:
 *   node pipe_sender.mjs | PRIVATE_KEY=<hex> node pipe_receiver.mjs
 *   node pipe_sender.mjs | node pipe_receiver.mjs <private_key_hex>
 *   node pipe_sender.mjs --generate | node pipe_receiver.mjs --file private_key.txt
 */

import path from "path";
import { fileURLToPath } from "url";
import { readFileSync } from "fs";
import { unframeMessage } from "./framing.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function fromHex(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

async function loadModule() {
  const wasmPath = path.join(__dirname, "..", "..", "dist", "flatc-wasm.js");
  const { default: createModule } = await import(wasmPath);
  const Module = await createModule({
    noInitialRun: true,
    noExitRuntime: true,
  });
  return Module;
}

function allocBytes(Module, data) {
  const ptr = Module._malloc(data.length);
  Module.HEAPU8.set(data, ptr);
  return ptr;
}

function readBytes(Module, ptr, len) {
  return new Uint8Array(Module.HEAPU8.buffer, ptr, len).slice();
}

function x25519SharedSecret(Module, priv, pub) {
  const privPtr = allocBytes(Module, priv);
  const pubPtr = allocBytes(Module, pub);
  const outPtr = Module._malloc(32);
  Module._wasm_crypto_x25519_shared_secret(privPtr, pubPtr, outPtr);
  const shared = readBytes(Module, outPtr, 32);
  Module._free(privPtr);
  Module._free(pubPtr);
  Module._free(outPtr);
  return shared;
}

function hkdf(Module, ikm, info) {
  const ikmPtr = allocBytes(Module, ikm);
  const infoPtr = info ? allocBytes(Module, info) : 0;
  const outPtr = Module._malloc(32);
  Module._wasm_crypto_hkdf(
    ikmPtr, ikm.length,
    0, 0,
    infoPtr, info ? info.length : 0,
    outPtr, 32,
  );
  const derived = readBytes(Module, outPtr, 32);
  Module._free(ikmPtr);
  if (infoPtr) Module._free(infoPtr);
  Module._free(outPtr);
  return derived;
}

function decryptBytes(Module, ciphertext, key, iv) {
  const dataPtr = allocBytes(Module, ciphertext);
  const keyPtr = allocBytes(Module, key);
  const ivPtr = allocBytes(Module, iv);
  Module._wasm_crypto_decrypt_bytes(dataPtr, ciphertext.length, keyPtr, ivPtr);
  const plaintext = readBytes(Module, dataPtr, ciphertext.length);
  Module._free(dataPtr);
  Module._free(keyPtr);
  Module._free(ivPtr);
  return plaintext;
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  const totalLength = chunks.reduce((sum, c) => sum + c.length, 0);
  const buffer = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    buffer.set(chunk, offset);
    offset += chunk.length;
  }
  return buffer;
}

async function main() {
  const Module = await loadModule();

  // Get private key
  let privateKeyHex;
  const arg = process.argv[2];
  const arg2 = process.argv[3];

  if (arg === "--file" && arg2) {
    privateKeyHex = readFileSync(arg2, "utf-8").trim();
  } else if (arg && arg !== "--file") {
    privateKeyHex = arg;
  } else if (process.env.PRIVATE_KEY) {
    privateKeyHex = process.env.PRIVATE_KEY;
  } else {
    try {
      privateKeyHex = readFileSync("private_key.txt", "utf-8").trim();
      console.error("Using private key from private_key.txt");
    } catch {
      console.error("Error: No private key provided.");
      console.error("Usage: node pipe_receiver.mjs <private_key_hex>");
      console.error("   or: PRIVATE_KEY=<hex> node pipe_receiver.mjs");
      console.error("   or: node pipe_receiver.mjs --file <key_file>");
      process.exit(1);
    }
  }

  const privateKey = fromHex(privateKeyHex);

  console.error("Waiting for encrypted message on stdin...");

  // Read from stdin
  const buffer = await readStdin();
  console.error(`Received ${buffer.length} bytes`);

  // Unframe the message
  const { headerJSON, data } = unframeMessage(buffer);
  const header = JSON.parse(headerJSON);

  console.error(`Key exchange: ${header.algorithm}`);
  console.error(`Context: ${header.context || "(none)"}`);

  // Reconstruct the shared secret
  const ephemeralPublicKey = fromHex(header.ephemeralPublicKey);
  const shared = x25519SharedSecret(Module, privateKey, ephemeralPublicKey);

  // Derive symmetric key
  const context = header.context ? new TextEncoder().encode(header.context) : null;
  const symmetricKey = hkdf(Module, shared, context);

  // Decrypt
  const iv = fromHex(header.iv);
  const plaintext = decryptBytes(Module, data, symmetricKey, iv);

  // Parse the decrypted message
  const message = JSON.parse(new TextDecoder().decode(plaintext));

  console.error("\nDecrypted message:");
  console.log(JSON.stringify(message, null, 2));
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});
