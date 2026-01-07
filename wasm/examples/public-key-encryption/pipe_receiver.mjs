#!/usr/bin/env node
/**
 * Pipe Receiver Example
 *
 * Reads an encrypted FlatBuffer message from stdin and decrypts it.
 * The recipient's private key is read from an environment variable, argument, or file.
 *
 * Usage:
 *   node pipe_sender.mjs | PRIVATE_KEY=<hex> node pipe_receiver.mjs
 *   node pipe_sender.mjs | node pipe_receiver.mjs <private_key_hex>
 *   node pipe_sender.mjs --generate | node pipe_receiver.mjs --file private_key.txt
 */

import {
  EncryptionContext,
  decryptBuffer,
  encryptionHeaderFromJSON,
} from "flatc-wasm/encryption";
import { FlatcRunner } from "flatc-wasm";
import { unframeMessage } from "./framing.mjs";
import { readFileSync } from "fs";

// Schema for the encrypted message
const schemaContent = `
  attribute "encrypted";

  table SecretMessage {
    sender: string;
    message: string (encrypted);
    secret_number: int (encrypted);
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

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  const totalLength = chunks.reduce((sum, c) => sum + c.length, 0);
  const buffer = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    buffer.set(chunk, offset);
    offset += chunk.length;
  }
  return buffer;
}

async function main() {
  // Get private key
  let privateKeyHex;

  const arg = process.argv[2];
  const arg2 = process.argv[3];

  if (arg === "--file" && arg2) {
    privateKeyHex = readFileSync(arg2, "utf-8").trim();
  } else if (arg && arg !== "--file") {
    privateKeyHex = arg;
  } else if (process.env.PRIVATE_KEY) {
    privateKeyHex = process.env.PRIVATE_KEY;
  } else {
    // Try to read from default file
    try {
      privateKeyHex = readFileSync("private_key.txt", "utf-8").trim();
      console.error("Using private key from private_key.txt");
    } catch {
      console.error("Error: No private key provided.");
      console.error("Usage: node pipe_receiver.mjs <private_key_hex>");
      console.error("   or: PRIVATE_KEY=<hex> node pipe_receiver.mjs");
      console.error("   or: node pipe_receiver.mjs --file <key_file>");
      process.exit(1);
    }
  }

  const privateKey = fromHex(privateKeyHex);

  console.error("Waiting for encrypted message on stdin...");

  // Read from stdin
  const buffer = await readStdin();

  console.error(`Received ${buffer.length} bytes`);

  // Unframe the message
  const { headerJSON, data } = unframeMessage(buffer);
  const header = encryptionHeaderFromJSON(headerJSON);

  console.error(`Key exchange: ${["X25519", "secp256k1", "P-256"][header.keyExchange]}`);
  console.error(`Context: ${header.context || "(none)"}`);

  // Create decryption context
  const decryptCtx = EncryptionContext.forDecryption(privateKey, header);

  // Decrypt the FlatBuffer
  decryptBuffer(data, schemaContent, decryptCtx, "SecretMessage");

  // Parse the decrypted FlatBuffer
  const runner = await FlatcRunner.init();
  const json = runner.generateJSON(schemaInput, {
    path: "/message.bin",
    data: data,
  });
  const message = JSON.parse(json);

  console.error("\nDecrypted message:");
  console.log(JSON.stringify(message, null, 2));
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});
