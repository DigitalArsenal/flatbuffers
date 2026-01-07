#!/usr/bin/env node
/**
 * TCP Sender Example
 *
 * Sends an encrypted FlatBuffer message to a receiver via TCP.
 *
 * Usage: node tcp_sender.mjs <recipient_public_key_hex> [host] [port] [curve]
 *
 * Examples:
 *   node tcp_sender.mjs abc123... localhost 9999 x25519
 *   node tcp_sender.mjs abc123... localhost 9999 secp256k1
 *   node tcp_sender.mjs abc123... localhost 9999 p256
 */

import { createConnection } from "net";
import {
  EncryptionContext,
  KeyExchangeAlgorithm,
  encryptBuffer,
} from "flatc-wasm/encryption";
import { FlatcRunner } from "flatc-wasm";
import { frameMessage } from "./framing.mjs";

const args = process.argv.slice(2);

if (args.length < 1) {
  console.log("Usage: node tcp_sender.mjs <recipient_public_key_hex> [host] [port] [curve]");
  console.log("\nCurves: x25519 (default), secp256k1, p256");
  console.log("\nGet the recipient's public key from the receiver output.");
  process.exit(1);
}

const recipientKeyHex = args[0];
const HOST = args[1] || "localhost";
const PORT = parseInt(args[2]) || 9999;
const CURVE = (args[3] || "x25519").toLowerCase();

// Schema for the encrypted message
const schemaContent = `
  attribute "encrypted";

  table SecretMessage {
    sender: string;
    message: string (encrypted);
    timestamp: long (encrypted);
  }

  root_type SecretMessage;
`;

const schemaInput = {
  entry: "/schema.fbs",
  files: { "/schema.fbs": schemaContent },
};

function fromHex(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function toHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function main() {
  console.log("=== TCP Sender ===\n");

  // Parse recipient's public key
  const recipientPublicKey = fromHex(recipientKeyHex);

  // Determine key exchange algorithm
  let keyExchange;
  let expectedKeyLength;
  switch (CURVE) {
    case "x25519":
      keyExchange = KeyExchangeAlgorithm.X25519;
      expectedKeyLength = 32;
      break;
    case "secp256k1":
      keyExchange = KeyExchangeAlgorithm.Secp256k1;
      expectedKeyLength = 33;
      break;
    case "p256":
      keyExchange = KeyExchangeAlgorithm.P256;
      expectedKeyLength = 33;
      break;
    default:
      console.error(`Unknown curve: ${CURVE}`);
      process.exit(1);
  }

  if (recipientPublicKey.length !== expectedKeyLength) {
    console.error(
      `Invalid public key length for ${CURVE}: expected ${expectedKeyLength}, got ${recipientPublicKey.length}`
    );
    process.exit(1);
  }

  console.log(`Curve: ${CURVE}`);
  console.log(`Recipient: ${recipientKeyHex.substring(0, 32)}...`);
  console.log(`Target: ${HOST}:${PORT}\n`);

  // Create the message
  const messageData = {
    sender: "Alice",
    message: "Hello from the TCP sender! This is a secret message.",
    timestamp: Date.now(),
  };

  console.log("Original message:");
  console.log(`  Sender:    ${messageData.sender}`);
  console.log(`  Message:   ${messageData.message}`);
  console.log(`  Timestamp: ${new Date(messageData.timestamp).toISOString()}`);
  console.log();

  // Create FlatBuffer
  const runner = await FlatcRunner.init();
  const flatbuffer = runner.generateBinary(
    schemaInput,
    JSON.stringify(messageData)
  );

  console.log(`FlatBuffer size: ${flatbuffer.length} bytes`);

  // Create encryption context
  const encryptCtx = EncryptionContext.forEncryption(recipientPublicKey, {
    keyExchange,
    context: "tcp-example-v1",
    rootType: "SecretMessage",
  });

  // Encrypt the FlatBuffer
  encryptBuffer(flatbuffer, schemaContent, encryptCtx, "SecretMessage");

  console.log(`Ephemeral key: ${toHex(encryptCtx.getEphemeralPublicKey()).substring(0, 32)}...`);

  // Get the header
  const headerJSON = encryptCtx.getHeaderJSON();

  // Frame the message
  const framed = frameMessage(headerJSON, flatbuffer);

  console.log(`Framed message: ${framed.length} bytes`);
  console.log();

  // Send via TCP
  return new Promise((resolve, reject) => {
    const socket = createConnection(PORT, HOST, () => {
      console.log(`Connected to ${HOST}:${PORT}`);
      socket.write(framed, () => {
        console.log("Message sent!");
        socket.end();
      });
    });

    socket.on("close", () => {
      console.log("Connection closed");
      resolve();
    });

    socket.on("error", (err) => {
      console.error("Connection error:", err.message);
      reject(err);
    });
  });
}

main().catch(console.error);
