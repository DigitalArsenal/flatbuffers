#!/usr/bin/env node
/**
 * REST Server Example
 *
 * Demonstrates sending/receiving FlatBuffers over REST API.
 * Supports both encrypted and non-encrypted endpoints.
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
  x25519GenerateKeyPair,
  secp256k1GenerateKeyPair,
  p256GenerateKeyPair,
  EncryptionContext,
  KeyExchangeAlgorithm,
  encryptBuffer,
  decryptBuffer,
  encryptionHeaderFromJSON,
} from "flatc-wasm/encryption";
import {
  schemaContent,
  schemaInput,
  plainSchemaContent,
  plainSchemaInput,
  getRunner,
  toHex,
  generateId,
} from "./shared.mjs";

const PORT = parseInt(process.argv[2]) || 8080;

// Server's key pairs (for receiving encrypted messages)
const serverKeys = {
  x25519: x25519GenerateKeyPair(),
  secp256k1: secp256k1GenerateKeyPair(),
  p256: p256GenerateKeyPair(),
};

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
        p256: toHex(serverKeys.p256.publicKey),
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
      const header = encryptionHeaderFromJSON(headerJSON);
      const id = generateId();

      // Select private key based on algorithm
      let privateKey;
      switch (header.keyExchange) {
        case KeyExchangeAlgorithm.X25519:
          privateKey = serverKeys.x25519.privateKey;
          break;
        case KeyExchangeAlgorithm.Secp256k1:
          privateKey = serverKeys.secp256k1.privateKey;
          break;
        case KeyExchangeAlgorithm.P256:
          privateKey = serverKeys.p256.privateKey;
          break;
        default:
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Unsupported key exchange" }));
          return;
      }

      // Decrypt to verify and log
      const decryptCtx = EncryptionContext.forDecryption(privateKey, header);
      const decrypted = new Uint8Array(body);
      decryptBuffer(decrypted, schemaContent, decryptCtx, "Message");

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
  console.log(`  P-256:     ${toHex(serverKeys.p256.publicKey)}`);
  console.log();
});
