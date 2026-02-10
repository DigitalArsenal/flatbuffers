#!/usr/bin/env node
/**
 * Pipe Sender Example -- WASM binary exports
 *
 * Generates an ephemeral X25519 key pair, computes the shared secret with the
 * recipient's public key, derives a symmetric key via HKDF, encrypts a
 * plaintext message with AES-256-CTR, and writes it (with a JSON header
 * containing the ephemeral public key) to stdout using the framing protocol.
 *
 * Usage:
 *   RECIPIENT_KEY=<hex> node pipe_sender.mjs | node pipe_receiver.mjs
 *   node pipe_sender.mjs <recipient_public_key_hex> | node pipe_receiver.mjs
 *   node pipe_sender.mjs --generate | node pipe_receiver.mjs --file private_key.txt
 */

import path from "path";
import { fileURLToPath } from "url";
import { writeFileSync } from "fs";
import { frameMessage } from "./framing.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function toHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

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

function x25519GenerateKeyPair(Module) {
  const privPtr = Module._malloc(32);
  const pubPtr = Module._malloc(32);
  Module._wasm_crypto_x25519_generate_keypair(privPtr, pubPtr);
  const privateKey = readBytes(Module, privPtr, 32);
  const publicKey = readBytes(Module, pubPtr, 32);
  Module._free(privPtr);
  Module._free(pubPtr);
  return { privateKey, publicKey };
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

function encryptBytes(Module, data, key, iv) {
  const dataPtr = allocBytes(Module, data);
  const keyPtr = allocBytes(Module, key);
  const ivPtr = allocBytes(Module, iv);
  Module._wasm_crypto_encrypt_bytes(dataPtr, data.length, keyPtr, ivPtr);
  const ciphertext = readBytes(Module, dataPtr, data.length);
  Module._free(dataPtr);
  Module._free(keyPtr);
  Module._free(ivPtr);
  return ciphertext;
}

async function main() {
  const Module = await loadModule();

  let recipientPublicKey;

  const arg = process.argv[2];

  if (arg === "--generate" || (!arg && !process.env.RECIPIENT_KEY)) {
    // Generate a key pair for testing
    const keys = x25519GenerateKeyPair(Module);
    recipientPublicKey = keys.publicKey;

    // Write private key to file for receiver to use
    writeFileSync("private_key.txt", toHex(keys.privateKey));
    console.error("Generated key pair. Private key written to private_key.txt");
    console.error(`Public key: ${toHex(recipientPublicKey)}`);
  } else {
    const keyHex = arg || process.env.RECIPIENT_KEY;
    recipientPublicKey = fromHex(keyHex);
  }

  // The plaintext message
  const messageData = {
    sender: "PipeSender",
    message: "This secret message was sent through a pipe!",
    secret_number: 12345,
  };

  console.error("Sending message:");
  console.error(`  Sender: ${messageData.sender}`);
  console.error(`  Message: ${messageData.message}`);
  console.error(`  Secret Number: ${messageData.secret_number}`);
  console.error();

  const plaintext = new TextEncoder().encode(JSON.stringify(messageData));

  // Generate ephemeral key pair, compute shared secret, derive symmetric key
  const ephemeral = x25519GenerateKeyPair(Module);
  const shared = x25519SharedSecret(Module, ephemeral.privateKey, recipientPublicKey);
  const context = new TextEncoder().encode("pipe-example-v1");
  const symmetricKey = hkdf(Module, shared, context);

  // Random IV for AES-256-CTR
  const iv = new Uint8Array(16);
  crypto.getRandomValues(iv);

  // Encrypt
  const ciphertext = encryptBytes(Module, plaintext, symmetricKey, iv);

  // Build a JSON header containing everything the receiver needs
  const headerJSON = JSON.stringify({
    algorithm: "X25519",
    ephemeralPublicKey: toHex(ephemeral.publicKey),
    iv: toHex(iv),
    context: "pipe-example-v1",
  });

  // Frame and write to stdout
  const framed = frameMessage(headerJSON, ciphertext);

  console.error(`Encrypted and framed: ${framed.length} bytes`);

  process.stdout.write(Buffer.from(framed));
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});
