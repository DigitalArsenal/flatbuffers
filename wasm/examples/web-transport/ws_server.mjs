#!/usr/bin/env node
/**
 * WebSocket Server Example
 *
 * Demonstrates bidirectional FlatBuffer communication over WebSocket.
 * Supports both plaintext and encrypted connections.
 *
 * Session-Based Encryption:
 * - Client sends public key in first message
 * - Server responds with session header
 * - All subsequent messages use that header until rotation
 * - Either side can request key rotation
 *
 * Protocol:
 *   { type: "hello", publicKey: "<hex>", algo: "x25519" }  -> Client initiates encryption
 *   { type: "session", header: {...} }                     -> Server sends session header
 *   { type: "message", buffer: "<base64>" }                -> Encrypted or plaintext message
 *   { type: "rotate" }                                     -> Request key rotation
 *
 * Usage: node ws_server.mjs [port]
 */

import { WebSocketServer } from "ws";
import {
  x25519GenerateKeyPair,
  secp256k1GenerateKeyPair,
  p256GenerateKeyPair,
  EncryptionContext,
  KeyExchangeAlgorithm,
  encryptBuffer,
  decryptBuffer,
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

const PORT = parseInt(process.argv[2]) || 8082;

// Server's key pairs
const serverKeys = {
  x25519: x25519GenerateKeyPair(),
  secp256k1: secp256k1GenerateKeyPair(),
  p256: p256GenerateKeyPair(),
};

// Client sessions: Map<ws, { encrypted, encryptCtx, decryptCtx, publicKey, keyExchange }>
const sessions = new Map();

function toBase64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

function fromBase64(base64) {
  return new Uint8Array(Buffer.from(base64, "base64"));
}

/**
 * Create encryption/decryption contexts for a client
 */
function createSession(clientPublicKey, keyExchange) {
  // Context for encrypting TO client
  const encryptCtx = EncryptionContext.forEncryption(clientPublicKey, {
    keyExchange,
    context: "ws-stream-v1",
    rootType: "Message",
  });

  return {
    encrypted: true,
    publicKey: clientPublicKey,
    keyExchange,
    encryptCtx,
    decryptCtx: null, // Will be set when client sends their header
    serverHeader: JSON.parse(encryptCtx.getHeaderJSON()),
    clientHeader: null,
    messageCount: 0,
  };
}

async function handleMessage(ws, message, runner) {
  let session = sessions.get(ws);
  let data;

  try {
    data = JSON.parse(message.toString());
  } catch {
    ws.send(JSON.stringify({ type: "error", message: "Invalid JSON" }));
    return;
  }

  switch (data.type) {
    case "hello": {
      // Client wants encrypted communication
      const algo = data.algo || "x25519";
      let keyExchange;
      let expectedLength;

      switch (algo) {
        case "x25519":
          keyExchange = KeyExchangeAlgorithm.X25519;
          expectedLength = 32;
          break;
        case "secp256k1":
          keyExchange = KeyExchangeAlgorithm.Secp256k1;
          expectedLength = 33;
          break;
        case "p256":
          keyExchange = KeyExchangeAlgorithm.P256;
          expectedLength = 33;
          break;
        default:
          ws.send(JSON.stringify({ type: "error", message: "Invalid algo" }));
          return;
      }

      const clientPublicKey = fromHex(data.publicKey);
      if (clientPublicKey.length !== expectedLength) {
        ws.send(JSON.stringify({ type: "error", message: "Invalid key length" }));
        return;
      }

      session = createSession(clientPublicKey, keyExchange);
      sessions.set(ws, session);

      console.log(`[WS] Client initiated ${algo} encryption`);

      // Send server's session header to client
      ws.send(JSON.stringify({
        type: "session",
        header: session.serverHeader,
        serverPublicKey: toHex(serverKeys[algo].publicKey),
      }));
      break;
    }

    case "session": {
      // Client is sending their session header (for messages TO server)
      if (!session || !session.encrypted) {
        ws.send(JSON.stringify({ type: "error", message: "No encrypted session" }));
        return;
      }

      // Select server private key based on algorithm
      let privateKey;
      switch (session.keyExchange) {
        case KeyExchangeAlgorithm.X25519:
          privateKey = serverKeys.x25519.privateKey;
          break;
        case KeyExchangeAlgorithm.Secp256k1:
          privateKey = serverKeys.secp256k1.privateKey;
          break;
        case KeyExchangeAlgorithm.P256:
          privateKey = serverKeys.p256.privateKey;
          break;
      }

      session.clientHeader = data.header;
      session.decryptCtx = EncryptionContext.forDecryption(privateKey, data.header);

      console.log(`[WS] Received client session header, bidirectional encryption ready`);
      break;
    }

    case "message": {
      const buffer = fromBase64(data.buffer);

      if (session?.encrypted && session.decryptCtx) {
        // Decrypt incoming message
        const decrypted = new Uint8Array(buffer);
        decryptBuffer(decrypted, schemaContent, session.decryptCtx, "Message");

        const json = runner.generateJSON(schemaInput, {
          path: "/msg.bin",
          data: decrypted,
        });
        const msg = JSON.parse(json);
        console.log(`[WS] Received (encrypted): ${msg.sender}: ${msg.content}`);

        // Echo back encrypted
        await sendEncryptedMessage(ws, session, runner, {
          id: generateId(),
          sender: "Server",
          content: `Echo: ${msg.content}`,
          timestamp: Date.now(),
          public_tag: "echo",
        });
      } else {
        // Plaintext
        const json = runner.generateJSON(plainSchemaInput, {
          path: "/msg.bin",
          data: buffer,
        });
        const msg = JSON.parse(json);
        console.log(`[WS] Received (plain): ${msg.sender}: ${msg.content}`);

        // Echo back
        const response = {
          id: generateId(),
          sender: "Server",
          content: `Echo: ${msg.content}`,
          timestamp: Date.now(),
          public_tag: "echo",
        };
        const responseBuffer = runner.generateBinary(plainSchemaInput, JSON.stringify(response));
        ws.send(JSON.stringify({
          type: "message",
          buffer: toBase64(responseBuffer),
        }));
      }
      break;
    }

    case "rotate": {
      // Client requests key rotation
      if (!session?.encrypted) {
        ws.send(JSON.stringify({ type: "error", message: "No encrypted session" }));
        return;
      }

      const newSession = createSession(session.publicKey, session.keyExchange);
      newSession.decryptCtx = session.decryptCtx; // Keep ability to decrypt old messages
      sessions.set(ws, newSession);

      console.log(`[WS] Key rotation requested`);

      ws.send(JSON.stringify({
        type: "session",
        header: newSession.serverHeader,
        rotated: true,
      }));
      break;
    }

    default:
      ws.send(JSON.stringify({ type: "error", message: "Unknown message type" }));
  }
}

async function sendEncryptedMessage(ws, session, runner, message) {
  const buffer = runner.generateBinary(schemaInput, JSON.stringify(message));
  encryptBuffer(buffer, schemaContent, session.encryptCtx, "Message");
  session.messageCount++;

  ws.send(JSON.stringify({
    type: "message",
    buffer: toBase64(buffer),
  }));
}

async function main() {
  const runner = await getRunner();

  const wss = new WebSocketServer({ port: PORT });

  wss.on("connection", (ws) => {
    // Default to plaintext session
    sessions.set(ws, { encrypted: false });
    console.log(`[WS] Client connected (${wss.clients.size} total)`);

    ws.on("message", (message) => handleMessage(ws, message, runner));

    ws.on("close", () => {
      sessions.delete(ws);
      console.log(`[WS] Client disconnected (${wss.clients.size} total)`);
    });

    ws.on("error", (err) => {
      console.error("[WS] Error:", err.message);
    });

    // Send welcome message
    ws.send(JSON.stringify({
      type: "welcome",
      message: "Send { type: 'hello', publicKey: '<hex>', algo: 'x25519' } for encryption",
      serverKeys: {
        x25519: toHex(serverKeys.x25519.publicKey),
        secp256k1: toHex(serverKeys.secp256k1.publicKey),
        p256: toHex(serverKeys.p256.publicKey),
      },
    }));
  });

  console.log("=== WebSocket Server ===\n");
  console.log(`Listening on ws://localhost:${PORT}\n`);
  console.log("Protocol:");
  console.log("  1. Connect to ws://localhost:" + PORT);
  console.log("  2. For encryption, send: { type: 'hello', publicKey: '<hex>', algo: 'x25519' }");
  console.log("  3. Receive session header from server");
  console.log("  4. Send your session header: { type: 'session', header: {...} }");
  console.log("  5. Exchange encrypted messages: { type: 'message', buffer: '<base64>' }");
  console.log("\nServer public keys:");
  console.log(`  X25519: ${toHex(serverKeys.x25519.publicKey)}`);
  console.log();
}

main().catch(console.error);
