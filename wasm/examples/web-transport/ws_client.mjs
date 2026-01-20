#!/usr/bin/env node
/**
 * WebSocket Client Example
 *
 * Demonstrates bidirectional FlatBuffer communication over WebSocket.
 * Supports both plaintext and encrypted connections.
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
  x25519GenerateKeyPair,
  EncryptionContext,
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

const args = process.argv.slice(2);
const encrypted = args.includes("--encrypted");
const SERVER_URL = args.find((a) => !a.startsWith("--")) || "ws://localhost:8082";

function toBase64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

function fromBase64(base64) {
  return new Uint8Array(Buffer.from(base64, "base64"));
}

async function main() {
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
  let encryptCtx = null;  // For encrypting TO server
  let decryptCtx = null;  // For decrypting FROM server
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
          sendTestMessage(ws, runner, null);
        }
        break;

      case "session":
        // Server sent their session header
        console.log(`Received server session header${data.rotated ? " (rotated)" : ""}`);

        // Create context to decrypt messages FROM server
        decryptCtx = EncryptionContext.forDecryption(clientKeys.privateKey, data.header, "ws-stream-v1");

        if (!data.rotated && data.serverPublicKey) {
          // First session - create context to encrypt messages TO server
          serverPublicKey = fromHex(data.serverPublicKey);
          encryptCtx = EncryptionContext.forEncryption(serverPublicKey, {
            context: "ws-stream-v1",
            rootType: "Message",
          });

          // Send our session header to server
          ws.send(JSON.stringify({
            type: "session",
            header: JSON.parse(encryptCtx.getHeaderJSON()),
          }));

          console.log("Sent client session header");
          console.log("Bidirectional encryption established!\n");
        }

        ready = true;
        sendTestMessage(ws, runner, encryptCtx);
        break;

      case "message":
        const buffer = fromBase64(data.buffer);

        if (encrypted && decryptCtx) {
          // Decrypt message from server
          const decrypted = new Uint8Array(buffer);
          decryptBuffer(decrypted, schemaContent, decryptCtx, "Message");

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
  async function sendTestMessage(ws, runner, encryptCtx) {
    const message = {
      id: generateId(),
      sender: "Client",
      content: `Hello from client at ${new Date().toISOString()}`,
      timestamp: Date.now(),
      public_tag: "greeting",
    };

    if (encrypted && encryptCtx) {
      const buffer = runner.generateBinary(schemaInput, JSON.stringify(message));
      encryptBuffer(buffer, schemaContent, encryptCtx, "Message");

      ws.send(JSON.stringify({
        type: "message",
        buffer: toBase64(buffer),
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
      sendTestMessage(ws, runner, encryptCtx);
    }
  }, 5000);
}

main().catch(console.error);
