#!/usr/bin/env node
/**
 * WebSocket Client Example
 *
 * Demonstrates bidirectional FlatBuffer communication over WebSocket.
 * Supports both plaintext and encrypted connections.
 * All crypto operations use WASM binary exports (Module._wasm_crypto_*).
 *
 * Usage:
 *   node ws_client.mjs [--encrypted] [server_url]
 *
 * Examples:
 *   node ws_client.mjs                              # Plaintext
 *   node ws_client.mjs --encrypted                  # Encrypted with X25519
 *   node ws_client.mjs --encrypted ws://localhost:8082
 */

import WebSocket from "ws";
import {
  getWasmModule,
  getRunner,
  schemaContent,
  schemaInput,
  plainSchemaInput,
  toHex,
  fromHex,
  generateId,
} from "./shared.mjs";

const args = process.argv.slice(2);
const encrypted = args.includes("--encrypted");
const SERVER_URL = args.find((a) => !a.startsWith("--")) || "ws://localhost:8082";

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
      ephemeralPublicKey: toHex(ephemeral.publicKey),
      iv: toHex(iv),
      algorithm: "x25519",
      context,
    },
  };
}

function decryptFlatBuffer(buffer, privateKey, myPublicKey, header) {
  const ephPub = typeof header.ephemeralPublicKey === "string"
    ? fromHex(header.ephemeralPublicKey) : header.ephemeralPublicKey;
  const shared = x25519SharedSecret(privateKey, myPublicKey, ephPub);
  const key = deriveSymmetricKey(shared, header.context);
  const iv = header.iv
    ? (typeof header.iv === "string" ? fromHex(header.iv) : header.iv)
    : sha256(ephPub).slice(0, 16);
  return decryptBytes(key, iv, buffer);
}

// ---------------------------------------------------------------------------
// Base64 helpers
// ---------------------------------------------------------------------------

function toBase64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

function fromBase64(base64) {
  return new Uint8Array(Buffer.from(base64, "base64"));
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  Module = await getWasmModule();
  const runner = await getRunner();

  // Generate client key pair for encrypted mode
  const clientKeys = encrypted ? x25519GenerateKeyPair() : null;

  console.log(`=== WebSocket Client (${encrypted ? "Encrypted" : "Plaintext"}) ===\n`);
  if (encrypted) {
    console.log(`Client public key: ${toHex(clientKeys.publicKey)}`);
  }
  console.log(`Connecting to ${SERVER_URL}...\n`);

  const ws = new WebSocket(SERVER_URL);

  // Session state
  let sessionEncryptKey = null;  // Symmetric key for encrypting TO server
  let sessionEncryptIv = null;
  let sessionDecryptKey = null;  // Symmetric key for decrypting FROM server
  let sessionDecryptIv = null;
  let serverPublicKey = null;
  let ready = false;

  ws.on("open", () => {
    console.log("Connected!\n");
  });

  ws.on("message", async (message) => {
    const data = JSON.parse(message.toString());

    switch (data.type) {
      case "welcome":
        console.log(`Server: ${data.message}\n`);

        if (encrypted) {
          // Initiate encrypted session
          console.log("Initiating encrypted session...\n");
          ws.send(JSON.stringify({
            type: "hello",
            publicKey: toHex(clientKeys.publicKey),
            algo: "x25519",
          }));
        } else {
          // Ready to send plaintext
          ready = true;
          sendTestMessage(ws, runner);
        }
        break;

      case "session": {
        // Server sent their session header
        console.log(`Received server session header${data.rotated ? " (rotated)" : ""}`);

        // Derive decryption key from server's ephemeral public key
        const serverEphPub = fromHex(data.header.ephemeralPublicKey);
        const decShared = x25519SharedSecret(
          clientKeys.privateKey, clientKeys.publicKey, serverEphPub
        );
        sessionDecryptKey = deriveSymmetricKey(decShared, "ws-stream-v1");
        sessionDecryptIv = data.header.iv
          ? fromHex(data.header.iv)
          : sha256(serverEphPub).slice(0, 16);

        if (!data.rotated && data.serverPublicKey) {
          // First session - create ephemeral key to encrypt messages TO server
          serverPublicKey = fromHex(data.serverPublicKey);
          const ephemeral = x25519GenerateKeyPair();
          const encShared = x25519SharedSecret(
            ephemeral.privateKey, ephemeral.publicKey, serverPublicKey
          );
          sessionEncryptKey = deriveSymmetricKey(encShared, "ws-stream-v1");
          sessionEncryptIv = sha256(ephemeral.publicKey).slice(0, 16);

          // Send our session header to server
          ws.send(JSON.stringify({
            type: "session",
            header: {
              ephemeralPublicKey: toHex(ephemeral.publicKey),
              iv: toHex(sessionEncryptIv),
              algorithm: "x25519",
              context: "ws-stream-v1",
            },
          }));

          console.log("Sent client session header");
          console.log("Bidirectional encryption established!\n");
        }

        ready = true;
        sendTestMessage(ws, runner);
        break;
      }

      case "message": {
        const buffer = fromBase64(data.buffer);

        if (encrypted && sessionDecryptKey) {
          // Decrypt message from server
          const decrypted = decryptBytes(sessionDecryptKey, sessionDecryptIv, buffer);

          const json = runner.generateJSON(schemaInput, {
            path: "/msg.bin",
            data: decrypted,
          });
          const msg = JSON.parse(json);
          console.log(`[ENCRYPTED] Server: ${msg.content}`);
        } else {
          // Plaintext
          const json = runner.generateJSON(plainSchemaInput, {
            path: "/msg.bin",
            data: buffer,
          });
          const msg = JSON.parse(json);
          console.log(`[PLAIN] Server: ${msg.content}`);
        }
        break;
      }

      case "error":
        console.error(`Server error: ${data.message}`);
        break;
    }
  });

  ws.on("close", () => {
    console.log("\nDisconnected");
    process.exit(0);
  });

  ws.on("error", (err) => {
    if (err.code === "ECONNREFUSED") {
      console.error(`Cannot connect to ${SERVER_URL}. Is the server running?`);
      console.error("Start the server with: node ws_server.mjs");
    } else {
      console.error("Error:", err.message);
    }
    process.exit(1);
  });

  // Send test messages periodically
  function sendTestMessage(ws, runner) {
    const message = {
      id: generateId(),
      sender: "Client",
      content: `Hello from client at ${new Date().toISOString()}`,
      timestamp: Date.now(),
      public_tag: "greeting",
    };

    if (encrypted && sessionEncryptKey) {
      const buffer = runner.generateBinary(schemaInput, JSON.stringify(message));
      const enc = encryptBytes(sessionEncryptKey, sessionEncryptIv, buffer);

      ws.send(JSON.stringify({
        type: "message",
        buffer: toBase64(enc),
      }));
      console.log(`[ENCRYPTED] Sent: ${message.content}`);
    } else if (!encrypted) {
      const buffer = runner.generateBinary(plainSchemaInput, JSON.stringify(message));

      ws.send(JSON.stringify({
        type: "message",
        buffer: toBase64(buffer),
      }));
      console.log(`[PLAIN] Sent: ${message.content}`);
    }
  }

  // Send a message every 5 seconds
  setInterval(() => {
    if (ready && ws.readyState === WebSocket.OPEN) {
      sendTestMessage(ws, runner);
    }
  }, 5000);
}

main().catch(console.error);
