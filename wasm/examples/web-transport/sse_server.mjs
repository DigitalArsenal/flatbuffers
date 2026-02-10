#!/usr/bin/env node
/**
 * Server-Sent Events (SSE) Server Example
 *
 * Demonstrates streaming FlatBuffers over SSE.
 * Supports both encrypted and non-encrypted streams.
 * All crypto operations use WASM binary exports (Module._wasm_crypto_*).
 *
 * Encryption Model (Session-Based):
 * - One header establishes the encryption context for the stream
 * - All subsequent messages use that header until a new one is sent
 * - Header is sent ONCE at connection, then periodically for rotation
 * - This enables efficient streaming without per-message overhead
 *
 * Endpoints:
 *   GET /events                     - Plaintext FlatBuffer event stream
 *   GET /encrypted-events?key=<hex> - Encrypted event stream
 *   GET /keys                       - Get server's public keys
 *
 * Event types:
 *   - "connected": Initial connection + session header
 *   - "message": FlatBuffer data (base64 encoded)
 *   - "rotate": New session header (optional key rotation)
 *
 * Usage: node sse_server.mjs [port]
 */

import { createServer } from "http";
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

const PORT = parseInt(process.argv[2]) || 8081;

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

function secp256k1GenerateKeyPair() {
  const privPtr = Module._malloc(32);
  const pubPtr = Module._malloc(33);
  const rc = Module._wasm_crypto_secp256k1_generate_keypair(privPtr, pubPtr);
  if (rc !== 0) throw new Error("secp256k1 keypair generation failed");
  const privateKey = readBytes(privPtr, 32);
  const publicKey = readBytes(pubPtr, 33);
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
// Session management
// ---------------------------------------------------------------------------

// Server's key pairs (initialised after WASM module loads)
let serverKeys;

// Active SSE connections
const plainClients = new Set();
// Encrypted clients with their session context
const encryptedClients = new Map(); // Map<res, session>

function toBase64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

/**
 * Create a new encryption session for a client.
 * Generates an ephemeral keypair, computes shared secret, derives symmetric key.
 */
function createSession(publicKey, algorithm) {
  const ephemeral = x25519GenerateKeyPair();
  const shared = x25519SharedSecret(ephemeral.privateKey, ephemeral.publicKey, publicKey);
  const encryptKey = deriveSymmetricKey(shared, "sse-stream-v1");
  const encryptIv = sha256(ephemeral.publicKey).slice(0, 16);

  return {
    publicKey,
    algorithm,
    encryptKey,
    encryptIv,
    header: {
      ephemeralPublicKey: toHex(ephemeral.publicKey),
      iv: toHex(encryptIv),
      algorithm: "x25519",
      context: "sse-stream-v1",
    },
    messageCount: 0,
  };
}

// ---------------------------------------------------------------------------
// HTTP handler
// ---------------------------------------------------------------------------

async function handleRequest(req, res) {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const path = url.pathname;

  // CORS headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  try {
    // GET /keys - Return server's public keys
    if (path === "/keys") {
      const keys = {
        x25519: toHex(serverKeys.x25519.publicKey),
        secp256k1: toHex(serverKeys.secp256k1.publicKey),
      };
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(keys, null, 2));
      return;
    }

    // GET /events - Plaintext SSE stream
    if (path === "/events") {
      res.writeHead(200, {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
      });

      plainClients.add(res);
      console.log(`[PLAIN] Client connected (${plainClients.size} total)`);

      req.on("close", () => {
        plainClients.delete(res);
        console.log(`[PLAIN] Client disconnected (${plainClients.size} total)`);
      });

      res.write(`event: connected\ndata: ${JSON.stringify({ type: "plain" })}\n\n`);
      return;
    }

    // GET /encrypted-events?key=<hex>&algo=<x25519>
    if (path === "/encrypted-events") {
      const keyHex = url.searchParams.get("key");
      const algo = url.searchParams.get("algo") || "x25519";

      if (!keyHex) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Missing 'key' parameter" }));
        return;
      }

      if (algo !== "x25519") {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Only x25519 supported via WASM" }));
        return;
      }

      const publicKey = fromHex(keyHex);
      if (publicKey.length !== 32) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: `Invalid key length for ${algo}` }));
        return;
      }

      res.writeHead(200, {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
      });

      // Create session with encryption context
      const session = createSession(publicKey, algo);
      encryptedClients.set(res, session);
      console.log(`[ENCRYPTED] Client connected with ${algo} (${encryptedClients.size} total)`);

      req.on("close", () => {
        encryptedClients.delete(res);
        console.log(`[ENCRYPTED] Client disconnected (${encryptedClients.size} total)`);
      });

      // Send connection event WITH the session header
      // Client uses this header for ALL subsequent messages
      res.write(`event: connected\ndata: ${JSON.stringify({
        type: "encrypted",
        algo,
        header: session.header,
      })}\n\n`);
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found" }));
  } catch (err) {
    console.error("Error:", err);
    res.writeHead(500, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: err.message }));
  }
}

// ---------------------------------------------------------------------------
// Broadcast loop
// ---------------------------------------------------------------------------

async function broadcast() {
  const runner = await getRunner();
  const now = Date.now();

  const message = {
    id: generateId(),
    sender: "Server",
    content: `Server event at ${new Date(now).toISOString()}`,
    timestamp: now,
    public_tag: "broadcast",
  };

  // Broadcast to plaintext clients
  if (plainClients.size > 0) {
    const buffer = runner.generateBinary(plainSchemaInput, JSON.stringify(message));
    const data = { buffer: toBase64(buffer) };

    for (const client of plainClients) {
      try {
        client.write(`event: message\ndata: ${JSON.stringify(data)}\n\n`);
      } catch (err) {
        plainClients.delete(client);
      }
    }
  }

  // Broadcast to encrypted clients using their session context
  for (const [client, session] of encryptedClients) {
    try {
      const buffer = runner.generateBinary(schemaInput, JSON.stringify(message));

      // Encrypt using session's symmetric key
      const enc = encryptBytes(session.encryptKey, session.encryptIv, buffer);
      session.messageCount++;

      // Optional: Rotate keys every N messages (e.g., 100)
      const ROTATION_INTERVAL = 100;
      if (session.messageCount % ROTATION_INTERVAL === 0) {
        // Create new session (key rotation)
        const newSession = createSession(session.publicKey, session.algorithm);
        encryptedClients.set(client, newSession);

        // Send rotation event with new header
        client.write(`event: rotate\ndata: ${JSON.stringify({
          header: newSession.header,
          reason: "periodic",
        })}\n\n`);

        console.log(`[ENCRYPTED] Rotated keys for client after ${ROTATION_INTERVAL} messages`);
      }

      // Send encrypted data (just the buffer, no header)
      client.write(`event: message\ndata: ${JSON.stringify({
        buffer: toBase64(enc),
      })}\n\n`);
    } catch (err) {
      encryptedClients.delete(client);
    }
  }

  if (plainClients.size > 0 || encryptedClients.size > 0) {
    console.log(`Broadcast to ${plainClients.size} plain + ${encryptedClients.size} encrypted`);
  }
}

// ---------------------------------------------------------------------------
// Start server
// ---------------------------------------------------------------------------

async function start() {
  Module = await getWasmModule();

  // Generate server key pairs using WASM crypto
  serverKeys = {
    x25519: x25519GenerateKeyPair(),
    secp256k1: secp256k1GenerateKeyPair(),
  };

  const server = createServer(handleRequest);

  server.listen(PORT, () => {
    console.log("=== SSE Server (Session-Based Encryption) ===\n");
    console.log(`Listening on http://localhost:${PORT}\n`);
    console.log("Endpoints:");
    console.log("  GET /keys                     - Get server public keys");
    console.log("  GET /events                   - Plaintext event stream");
    console.log("  GET /encrypted-events?key=... - Encrypted event stream");
    console.log("\nEncryption model:");
    console.log("  - Header sent once at connection");
    console.log("  - All messages use same header until rotation");
    console.log("  - Optional key rotation every 100 messages");
    console.log("\nServer public keys:");
    console.log(`  X25519: ${toHex(serverKeys.x25519.publicKey)}`);
    console.log();
  });

  setInterval(broadcast, 3000);
  setTimeout(broadcast, 1000);
}

start().catch(console.error);
