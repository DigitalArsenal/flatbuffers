#!/usr/bin/env node
/**
 * Server-Sent Events (SSE) Client Example
 *
 * Demonstrates receiving streaming FlatBuffers over SSE.
 * Supports both plaintext and encrypted streams.
 * All crypto operations use WASM binary exports (Module._wasm_crypto_*).
 *
 * Session-Based Encryption:
 * - Receives header once at connection (or on rotation)
 * - Uses same header to decrypt all subsequent messages
 * - Handles key rotation when server sends "rotate" event
 *
 * Usage:
 *   node sse_client.mjs [--encrypted] [server_url]
 *
 * Examples:
 *   node sse_client.mjs                              # Plaintext
 *   node sse_client.mjs --encrypted                  # Encrypted with X25519
 *   node sse_client.mjs --encrypted http://localhost:8081
 */

import {
  getWasmModule,
  getRunner,
  schemaContent,
  schemaInput,
  plainSchemaInput,
  toHex,
  fromHex,
} from "./shared.mjs";

const args = process.argv.slice(2);
const encrypted = args.includes("--encrypted");
const SERVER_URL = args.find((a) => !a.startsWith("--")) || "http://localhost:8081";

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
// Session key derivation from a received header
// ---------------------------------------------------------------------------

function deriveSessionKeys(privateKey, myPublicKey, header) {
  const ephPub = typeof header.ephemeralPublicKey === "string"
    ? fromHex(header.ephemeralPublicKey) : header.ephemeralPublicKey;
  const shared = x25519SharedSecret(privateKey, myPublicKey, ephPub);
  const key = deriveSymmetricKey(shared, "sse-stream-v1");
  const iv = header.iv
    ? (typeof header.iv === "string" ? fromHex(header.iv) : header.iv)
    : sha256(ephPub).slice(0, 16);
  return { key, iv };
}

// ---------------------------------------------------------------------------
// Base64 helper
// ---------------------------------------------------------------------------

function fromBase64(base64) {
  return new Uint8Array(Buffer.from(base64, "base64"));
}

// ---------------------------------------------------------------------------
// Plaintext client
// ---------------------------------------------------------------------------

async function runPlainClient() {
  const runner = await getRunner();

  console.log("=== SSE Client (Plaintext) ===\n");
  console.log(`Connecting to ${SERVER_URL}/events...\n`);

  const response = await fetch(`${SERVER_URL}/events`);
  const reader = response.body.getReader();
  const decoder = new TextDecoder();

  let buffer = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });

    // Parse SSE events
    const lines = buffer.split("\n");
    buffer = lines.pop(); // Keep incomplete line

    let eventType = null;
    let eventData = null;

    for (const line of lines) {
      if (line.startsWith("event: ")) {
        eventType = line.substring(7);
      } else if (line.startsWith("data: ")) {
        eventData = line.substring(6);
      } else if (line === "" && eventType && eventData) {
        // End of event
        handlePlainEvent(runner, eventType, eventData);
        eventType = null;
        eventData = null;
      }
    }
  }
}

function handlePlainEvent(runner, eventType, eventData) {
  const data = JSON.parse(eventData);

  if (eventType === "connected") {
    console.log("Connected (plaintext mode)\n");
    return;
  }

  if (eventType === "message") {
    const buffer = fromBase64(data.buffer);
    const json = runner.generateJSON(plainSchemaInput, {
      path: "/msg.bin",
      data: buffer,
    });
    const message = JSON.parse(json);

    console.log(`[${message.id}] ${message.sender}: ${message.content}`);
    console.log(`  Tag: ${message.public_tag}, Time: ${new Date(Number(message.timestamp)).toISOString()}\n`);
  }
}

// ---------------------------------------------------------------------------
// Encrypted client
// ---------------------------------------------------------------------------

async function runEncryptedClient() {
  const runner = await getRunner();

  // Generate client's key pair
  const clientKeys = x25519GenerateKeyPair();

  console.log("=== SSE Client (Encrypted) ===\n");
  console.log(`Client public key: ${toHex(clientKeys.publicKey)}`);
  console.log(`Connecting to ${SERVER_URL}/encrypted-events...\n`);

  const url = `${SERVER_URL}/encrypted-events?key=${toHex(clientKeys.publicKey)}&algo=x25519`;
  const response = await fetch(url);
  const reader = response.body.getReader();
  const decoder = new TextDecoder();

  let buffer = "";
  let sessionKey = null;
  let sessionIv = null;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });

    const lines = buffer.split("\n");
    buffer = lines.pop();

    let eventType = null;
    let eventData = null;

    for (const line of lines) {
      if (line.startsWith("event: ")) {
        eventType = line.substring(7);
      } else if (line.startsWith("data: ")) {
        eventData = line.substring(6);
      } else if (line === "" && eventType && eventData) {
        const data = JSON.parse(eventData);

        if (eventType === "connected") {
          console.log(`Connected (encrypted, algo: ${data.algo})`);
          const keys = deriveSessionKeys(
            clientKeys.privateKey, clientKeys.publicKey, data.header
          );
          sessionKey = keys.key;
          sessionIv = keys.iv;
          console.log("Session header received, ready to decrypt\n");
        } else if (eventType === "rotate") {
          console.log(`\n[KEY ROTATION] Reason: ${data.reason}`);
          const keys = deriveSessionKeys(
            clientKeys.privateKey, clientKeys.publicKey, data.header
          );
          sessionKey = keys.key;
          sessionIv = keys.iv;
          console.log("New session header applied\n");
        } else if (eventType === "message") {
          if (!sessionKey) {
            console.log("ERROR: No decryption context (missing header)");
          } else {
            const encryptedBuffer = fromBase64(data.buffer);
            const decryptedBuffer = decryptBytes(sessionKey, sessionIv, encryptedBuffer);

            const json = runner.generateJSON(schemaInput, {
              path: "/msg.bin",
              data: decryptedBuffer,
            });
            const message = JSON.parse(json);

            console.log(`[${message.id}] ${message.sender}: ${message.content}`);
            console.log(`  Tag: ${message.public_tag}, Time: ${new Date(Number(message.timestamp)).toISOString()}\n`);
          }
        }

        eventType = null;
        eventData = null;
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  Module = await getWasmModule();

  try {
    if (encrypted) {
      await runEncryptedClient();
    } else {
      await runPlainClient();
    }
  } catch (err) {
    if (err.code === "ECONNREFUSED") {
      console.error(`Cannot connect to ${SERVER_URL}. Is the server running?`);
      console.error("Start the server with: node sse_server.mjs");
    } else {
      console.error("Error:", err.message);
    }
  }
}

main();
