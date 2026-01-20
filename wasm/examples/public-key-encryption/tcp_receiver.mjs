#!/usr/bin/env node
/**
 * TCP Receiver Example
 *
 * Starts a TCP server that:
 * 1. Generates a long-term key pair
 * 2. Prints the public key (for sender to use)
 * 3. Listens for encrypted messages
 * 4. Decrypts and displays them
 *
 * Usage: node tcp_receiver.mjs [port]
 */

import { createServer } from "net";
import {
  x25519GenerateKeyPair,
  secp256k1GenerateKeyPair,
  p256GenerateKeyPair,
  EncryptionContext,
  KeyExchangeAlgorithm,
  decryptBuffer,
  encryptionHeaderFromJSON,
} from "flatc-wasm/encryption";
import { FlatcRunner } from "flatc-wasm";
import { unframeMessage } from "./framing.mjs";

const PORT = parseInt(process.argv[2]) || 9999;

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

function toHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function main() {
  // Generate key pairs for all supported curves
  const keys = {
    x25519: x25519GenerateKeyPair(),
    secp256k1: secp256k1GenerateKeyPair(),
    p256: p256GenerateKeyPair(),
  };

  console.log("=== TCP Receiver ===\n");
  console.log("Recipient public keys (share with sender):\n");
  console.log(`X25519:    ${toHex(keys.x25519.publicKey)}`);
  console.log(`secp256k1: ${toHex(keys.secp256k1.publicKey)}`);
  console.log(`P-256:     ${toHex(keys.p256.publicKey)}`);
  console.log();

  const runner = await FlatcRunner.init();

  const server = createServer((socket) => {
    console.log(`\nConnection from ${socket.remoteAddress}:${socket.remotePort}`);

    const chunks = [];

    socket.on("data", (chunk) => {
      chunks.push(chunk);
    });

    socket.on("end", async () => {
      try {
        // Concatenate all chunks
        const totalLength = chunks.reduce((sum, c) => sum + c.length, 0);
        const buffer = new Uint8Array(totalLength);
        let offset = 0;
        for (const chunk of chunks) {
          buffer.set(chunk, offset);
          offset += chunk.length;
        }

        console.log(`Received ${buffer.length} bytes`);

        // Unframe the message
        const { headerJSON, data } = unframeMessage(buffer);
        const header = encryptionHeaderFromJSON(headerJSON);

        console.log(`Key exchange: ${["X25519", "secp256k1", "P-256"][header.algorithm]}`);
        console.log(`Context: ${header.context || "(none)"}`);

        // Select the appropriate private key based on the key exchange algorithm
        let privateKey;
        switch (header.algorithm) {
          case KeyExchangeAlgorithm.X25519:
            privateKey = keys.x25519.privateKey;
            break;
          case KeyExchangeAlgorithm.SECP256K1:
            privateKey = keys.secp256k1.privateKey;
            break;
          case KeyExchangeAlgorithm.P256:
            privateKey = keys.p256.privateKey;
            break;
          default:
            throw new Error(`Unknown key exchange: ${header.algorithm}`);
        }

        // Create decryption context
        const decryptCtx = EncryptionContext.forDecryption(privateKey, header, header.context || "");

        // Decrypt the FlatBuffer
        decryptBuffer(data, schemaContent, decryptCtx, "SecretMessage");

        // Parse the decrypted FlatBuffer
        const json = runner.generateJSON(schemaInput, {
          path: "/message.bin",
          data: data,
        });
        const message = JSON.parse(json);

        console.log("\nDecrypted message:");
        console.log(`  Sender:    ${message.sender}`);
        console.log(`  Message:   ${message.message}`);
        console.log(`  Timestamp: ${new Date(Number(message.timestamp)).toISOString()}`);
        console.log();
      } catch (err) {
        console.error("Error processing message:", err.message);
      }
    });

    socket.on("error", (err) => {
      console.error("Socket error:", err.message);
    });
  });

  server.listen(PORT, () => {
    console.log(`Listening on port ${PORT}...\n`);
  });
}

main().catch(console.error);
