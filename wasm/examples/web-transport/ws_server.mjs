#!/usr/bin/env node
/**
 * WebSocket Server Example
 *
 * Demonstrates bidirectional FlatBuffer communication over WebSocket.
 * Supports both plaintext and encrypted connections.
 * All crypto operations use WASM binary exports (Module._wasm_crypto_*).
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
  getWasmModule,
  getRunner,
  schemaContent,
  schemaInput,
  plainSchemaInput,
  toHex,
  fromHex,
  generateId,
} from "./shared.mjs";

const PORT = parseInt(process.argv[2]) || 8082;

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
// Session management
// ---------------------------------------------------------------------------

// Server's key pairs (initialised after WASM module loads)
let serverKeys;

// Client sessions: Map<ws, session>
const sessions = new Map();

function toBase64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

function fromBase64(base64) {
  return new Uint8Array(Buffer.from(base64, "base64"));
}

/**
 * Create encryption session for a client.
 * Generates an ephemeral keypair, computes shared secret, derives symmetric key.
 */
function createSession(clientPublicKey, algorithm) {
  const ephemeral = x25519GenerateKeyPair();
  const shared = x25519SharedSecret(ephemeral.privateKey, ephemeral.publicKey, clientPublicKey);
  const encryptKey = deriveSymmetricKey(shared, "ws-stream-v1");
  const encryptIv = sha256(ephemeral.publicKey).slice(0, 16);

  return {
    encrypted: true,
    publicKey: clientPublicKey,
    algorithm,
    // For encrypting TO client
    encryptKey,
    encryptIv,
    // Header to send to client so they can derive the same key
    serverHeader: {
      ephemeralPublicKey: toHex(ephemeral.publicKey),
      iv: toHex(encryptIv),
      algorithm: "x25519",
      context: "ws-stream-v1",
    },
    // For decrypting FROM client (set when client sends their header)
    decryptKey: null,
    decryptIv: null,
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

      if (algo !== "x25519") {
        ws.send(JSON.stringify({ type: "error", message: "Only x25519 supported via WASM" }));
        return;
      }

      const clientPublicKey = fromHex(data.publicKey);
      if (clientPublicKey.length !== 32) {
        ws.send(JSON.stringify({ type: "error", message: "Invalid key length" }));
        return;
      }

      session = createSession(clientPublicKey, algo);
      sessions.set(ws, session);

      console.log(`[WS] Client initiated ${algo} encryption`);

      // Send server's session header to client
      ws.send(JSON.stringify({
        type: "session",
        header: session.serverHeader,
        serverPublicKey: toHex(serverKeys.x25519.publicKey),
      }));
      break;
    }

    case "session": {
      // Client is sending their session header (for messages TO server)
      if (!session || !session.encrypted) {
        ws.send(JSON.stringify({ type: "error", message: "No encrypted session" }));
        return;
      }

      session.clientHeader = data.header;

      // Derive decryption key from client's ephemeral public key
      const clientEphPub = fromHex(data.header.ephemeralPublicKey);
      const shared = x25519SharedSecret(
        serverKeys.x25519.privateKey, serverKeys.x25519.publicKey, clientEphPub
      );
      session.decryptKey = deriveSymmetricKey(shared, "ws-stream-v1");
      session.decryptIv = data.header.iv
        ? fromHex(data.header.iv)
        : sha256(clientEphPub).slice(0, 16);

      console.log(`[WS] Received client session header, bidirectional encryption ready`);
      break;
    }

    case "message": {
      const buffer = fromBase64(data.buffer);

      if (session?.encrypted && session.decryptKey) {
        // Decrypt incoming message
        const decrypted = decryptBytes(session.decryptKey, session.decryptIv, buffer);

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

      const newSession = createSession(session.publicKey, session.algorithm);
      // Keep ability to decrypt old messages from client
      newSession.decryptKey = session.decryptKey;
      newSession.decryptIv = session.decryptIv;
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
  const enc = encryptBytes(session.encryptKey, session.encryptIv, buffer);
  session.messageCount++;

  ws.send(JSON.stringify({
    type: "message",
    buffer: toBase64(enc),
  }));
}

async function main() {
  Module = await getWasmModule();
  const runner = await getRunner();

  // Generate server key pairs using WASM crypto
  serverKeys = {
    x25519: x25519GenerateKeyPair(),
    secp256k1: secp256k1GenerateKeyPair(),
  };

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
