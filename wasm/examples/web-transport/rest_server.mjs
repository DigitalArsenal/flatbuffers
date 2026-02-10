#!/usr/bin/env node
/**
 * REST Server Example
 *
 * Demonstrates sending/receiving FlatBuffers over REST API.
 * Supports both encrypted and non-encrypted endpoints.
 * All crypto operations use WASM binary exports (Module._wasm_crypto_*).
 *
 * Endpoints:
 *   POST /message          - Send plaintext FlatBuffer
 *   GET  /message/:id      - Get plaintext FlatBuffer
 *   POST /encrypted        - Send encrypted FlatBuffer (requires X-Encryption-Header)
 *   GET  /encrypted/:id    - Get encrypted FlatBuffer (returns X-Encryption-Header)
 *   GET  /keys             - Get server's public keys for encryption
 *
 * Usage: node rest_server.mjs [port]
 */

import { createServer } from "http";
import {
  getWasmModule,
  getRunner,
  schemaContent,
  schemaInput,
  plainSchemaContent,
  plainSchemaInput,
  toHex,
  fromHex,
  generateId,
} from "./shared.mjs";

const PORT = parseInt(process.argv[2]) || 8080;

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

function secp256k1SharedSecret(privateKey, peerPublicKey) {
  const privPtr = allocBytes(privateKey);
  const pubPtr = allocBytes(peerPublicKey);
  const secretPtr = Module._malloc(32);
  const rc = Module._wasm_crypto_secp256k1_shared_secret(
    privPtr, privateKey.length, pubPtr, peerPublicKey.length, secretPtr
  );
  if (rc !== 0) throw new Error("secp256k1 shared secret failed");
  const secret = readBytes(secretPtr, 32);
  freeBytes(privPtr);
  freeBytes(pubPtr);
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
  const decrypted = readBytes(dataPtr, data.length);
  freeBytes(keyPtr);
  freeBytes(ivPtr);
  freeBytes(dataPtr);
  return decrypted;
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
// Header serialisation helpers
// ---------------------------------------------------------------------------

function headerFromJSONStr(json) {
  const obj = typeof json === "string" ? JSON.parse(json) : json;
  return {
    ephemeralPublicKey: fromHex(obj.ephemeralPublicKey),
    iv: fromHex(obj.iv),
    algorithm: obj.algorithm,
    context: obj.context,
  };
}

// ---------------------------------------------------------------------------
// Decrypt a FlatBuffer given our private key and the header
// ---------------------------------------------------------------------------

function decryptFlatBuffer(buffer, privateKey, myPublicKey, header) {
  let shared;
  if (header.algorithm === "secp256k1") {
    shared = secp256k1SharedSecret(privateKey, header.ephemeralPublicKey);
  } else {
    // Default to x25519
    shared = x25519SharedSecret(privateKey, myPublicKey, header.ephemeralPublicKey);
  }
  const key = deriveSymmetricKey(shared, header.context);
  const iv = header.iv || sha256(header.ephemeralPublicKey).slice(0, 16);
  return decryptBytes(key, iv, buffer);
}

// ---------------------------------------------------------------------------
// Server setup
// ---------------------------------------------------------------------------

// Server's key pairs will be initialised after WASM module loads
let serverKeys;

// In-memory storage
const plainMessages = new Map();
const encryptedMessages = new Map();

async function handleRequest(req, res) {
  const runner = await getRunner();
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const path = url.pathname;

  // CORS headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Encryption-Header");
  res.setHeader("Access-Control-Expose-Headers", "X-Encryption-Header");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  try {
    // GET /keys - Return server's public keys
    if (req.method === "GET" && path === "/keys") {
      const keys = {
        x25519: toHex(serverKeys.x25519.publicKey),
        secp256k1: toHex(serverKeys.secp256k1.publicKey),
      };
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(keys, null, 2));
      return;
    }

    // POST /message - Store plaintext FlatBuffer
    if (req.method === "POST" && path === "/message") {
      const body = await readBody(req);
      const id = generateId();

      // Parse to verify it's valid
      const json = runner.generateJSON(plainSchemaInput, {
        path: "/msg.bin",
        data: body,
      });
      const message = JSON.parse(json);

      plainMessages.set(id, { buffer: body, message });

      console.log(`[PLAIN] Stored message ${id}: ${message.content}`);

      res.writeHead(201, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ id, message }));
      return;
    }

    // GET /message/:id - Retrieve plaintext FlatBuffer
    if (req.method === "GET" && path.startsWith("/message/")) {
      const id = path.substring("/message/".length);
      const stored = plainMessages.get(id);

      if (!stored) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Not found" }));
        return;
      }

      res.writeHead(200, {
        "Content-Type": "application/octet-stream",
        "X-Message-Id": id,
      });
      res.end(Buffer.from(stored.buffer));
      return;
    }

    // POST /encrypted - Store encrypted FlatBuffer
    if (req.method === "POST" && path === "/encrypted") {
      const headerJSON = req.headers["x-encryption-header"];
      if (!headerJSON) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Missing X-Encryption-Header" }));
        return;
      }

      const body = await readBody(req);
      const header = headerFromJSONStr(headerJSON);
      const id = generateId();

      // Select private key based on algorithm
      const algorithm = header.algorithm || "x25519";
      let privateKey, myPublicKey;
      switch (algorithm) {
        case "x25519":
          privateKey = serverKeys.x25519.privateKey;
          myPublicKey = serverKeys.x25519.publicKey;
          break;
        case "secp256k1":
          privateKey = serverKeys.secp256k1.privateKey;
          myPublicKey = serverKeys.secp256k1.publicKey;
          break;
        default:
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: `Unsupported key exchange algorithm: ${algorithm}` }));
          return;
      }

      // Decrypt to verify and log
      const decrypted = decryptFlatBuffer(body, privateKey, myPublicKey, header);

      const json = runner.generateJSON(schemaInput, {
        path: "/msg.bin",
        data: decrypted,
      });
      const message = JSON.parse(json);

      // Store original encrypted buffer and header
      encryptedMessages.set(id, {
        buffer: body,
        headerJSON,
        decryptedMessage: message,
      });

      console.log(`[ENCRYPTED] Stored message ${id}: ${message.content}`);

      res.writeHead(201, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ id, received: true }));
      return;
    }

    // GET /encrypted/:id - Retrieve encrypted FlatBuffer
    if (req.method === "GET" && path.startsWith("/encrypted/")) {
      const id = path.substring("/encrypted/".length);
      const stored = encryptedMessages.get(id);

      if (!stored) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Not found" }));
        return;
      }

      res.writeHead(200, {
        "Content-Type": "application/octet-stream",
        "X-Encryption-Header": stored.headerJSON,
        "X-Message-Id": id,
      });
      res.end(Buffer.from(stored.buffer));
      return;
    }

    // 404 for everything else
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found" }));
  } catch (err) {
    console.error("Error:", err);
    res.writeHead(500, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: err.message }));
  }
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      const buffer = Buffer.concat(chunks);
      resolve(new Uint8Array(buffer));
    });
    req.on("error", reject);
  });
}

async function start() {
  Module = await getWasmModule();

  // Generate server key pairs using WASM crypto
  serverKeys = {
    x25519: x25519GenerateKeyPair(),
    secp256k1: secp256k1GenerateKeyPair(),
  };

  const server = createServer(handleRequest);

  server.listen(PORT, () => {
    console.log("=== REST Server ===\n");
    console.log(`Listening on http://localhost:${PORT}\n`);
    console.log("Endpoints:");
    console.log("  GET  /keys           - Get server public keys");
    console.log("  POST /message        - Send plaintext FlatBuffer");
    console.log("  GET  /message/:id    - Get plaintext FlatBuffer");
    console.log("  POST /encrypted      - Send encrypted FlatBuffer");
    console.log("  GET  /encrypted/:id  - Get encrypted FlatBuffer");
    console.log("\nServer public keys:");
    console.log(`  X25519:    ${toHex(serverKeys.x25519.publicKey)}`);
    console.log(`  secp256k1: ${toHex(serverKeys.secp256k1.publicKey)}`);
    console.log();
  });
}

start().catch(console.error);
