#!/usr/bin/env node
/**
 * Server-Sent Events (SSE) Server Example
 *
 * Demonstrates streaming FlatBuffers over SSE.
 * Supports both encrypted and non-encrypted streams.
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
  x25519GenerateKeyPair,
  secp256k1GenerateKeyPair,
  p256GenerateKeyPair,
  EncryptionContext,
  KeyExchangeAlgorithm,
  encryptBuffer,
} from "flatc-wasm/encryption";
import {
  schemaContent,
  schemaInput,
  plainSchemaInput,
  getRunner,
  toHex,
  fromHex,
  generateId,
} from "./shared.mjs";

const PORT = parseInt(process.argv[2]) || 8081;

// Server's key pairs
const serverKeys = {
  x25519: x25519GenerateKeyPair(),
  secp256k1: secp256k1GenerateKeyPair(),
  p256: p256GenerateKeyPair(),
};

// Active SSE connections
const plainClients = new Set();
// Encrypted clients with their session context
const encryptedClients = new Map(); // Map<res, {publicKey, keyExchange, encryptCtx}>

function toBase64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

/**
 * Create a new encryption session for a client
 */
function createSession(publicKey, algorithm) {
  const encryptCtx = EncryptionContext.forEncryption(publicKey, {
    algorithm,
    context: "sse-stream-v1",
    rootType: "Message",
  });
  return {
    publicKey,
    algorithm,
    encryptCtx,
    headerJSON: encryptCtx.getHeaderJSON(),
    messageCount: 0,
  };
}

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
        p256: toHex(serverKeys.p256.publicKey),
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

    // GET /encrypted-events?key=<hex>&algo=<x25519|secp256k1|p256>
    if (path === "/encrypted-events") {
      const keyHex = url.searchParams.get("key");
      const algo = url.searchParams.get("algo") || "x25519";

      if (!keyHex) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Missing 'key' parameter" }));
        return;
      }

      let algorithm;
      let expectedLength;
      switch (algo) {
        case "x25519":
          algorithm = KeyExchangeAlgorithm.X25519;
          expectedLength = 32;
          break;
        case "secp256k1":
          algorithm = KeyExchangeAlgorithm.SECP256K1;
          expectedLength = 33;
          break;
        case "p256":
          algorithm = KeyExchangeAlgorithm.P256;
          expectedLength = 33;
          break;
        default:
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Invalid algo" }));
          return;
      }

      const publicKey = fromHex(keyHex);
      if (publicKey.length !== expectedLength) {
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
      const session = createSession(publicKey, algorithm);
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
        header: JSON.parse(session.headerJSON),
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

      // Use the session's encryption context
      encryptBuffer(buffer, schemaContent, session.encryptCtx, "Message");
      session.messageCount++;

      // Optional: Rotate keys every N messages (e.g., 100)
      const ROTATION_INTERVAL = 100;
      if (session.messageCount % ROTATION_INTERVAL === 0) {
        // Create new session (key rotation)
        const newSession = createSession(session.publicKey, session.algorithm);
        encryptedClients.set(client, newSession);

        // Send rotation event with new header
        client.write(`event: rotate\ndata: ${JSON.stringify({
          header: JSON.parse(newSession.headerJSON),
          reason: "periodic",
        })}\n\n`);

        console.log(`[ENCRYPTED] Rotated keys for client after ${ROTATION_INTERVAL} messages`);
      }

      // Send encrypted data (just the buffer, no header)
      client.write(`event: message\ndata: ${JSON.stringify({
        buffer: toBase64(buffer),
      })}\n\n`);
    } catch (err) {
      encryptedClients.delete(client);
    }
  }

  if (plainClients.size > 0 || encryptedClients.size > 0) {
    console.log(`Broadcast to ${plainClients.size} plain + ${encryptedClients.size} encrypted`);
  }
}

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
