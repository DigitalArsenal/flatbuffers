#!/usr/bin/env node
/**
 * Pipe Sender Example
 *
 * Encrypts a FlatBuffer message and writes it to stdout.
 * The recipient's public key is read from an environment variable or argument.
 *
 * Usage:
 *   RECIPIENT_KEY=<hex> node pipe_sender.mjs | node pipe_receiver.mjs
 *   node pipe_sender.mjs <recipient_public_key_hex> | node pipe_receiver.mjs
 *
 * For testing without a recipient, generates a key pair and prints the private key:
 *   node pipe_sender.mjs --generate | PRIVATE_KEY=$(cat key.txt) node pipe_receiver.mjs
 */

import {
  EncryptionContext,
  KeyExchangeAlgorithm,
  x25519GenerateKeyPair,
  encryptBuffer,
} from "flatc-wasm/encryption";
import { FlatcRunner } from "flatc-wasm";
import { frameMessage } from "./framing.mjs";
import { writeFileSync } from "fs";

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

function toHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function main() {
  let recipientPublicKey;
  let recipientPrivateKey;

  const arg = process.argv[2];

  if (arg === "--generate" || !arg && !process.env.RECIPIENT_KEY) {
    // Generate a key pair for testing
    const keys = x25519GenerateKeyPair();
    recipientPublicKey = keys.publicKey;
    recipientPrivateKey = keys.privateKey;

    // Write private key to file for receiver to use
    writeFileSync("private_key.txt", toHex(recipientPrivateKey));
    console.error("Generated key pair. Private key written to private_key.txt");
    console.error(`Public key: ${toHex(recipientPublicKey)}`);
  } else {
    // Use provided key
    const keyHex = arg || process.env.RECIPIENT_KEY;
    recipientPublicKey = fromHex(keyHex);
  }

  // Create the message
  const messageData = {
    sender: "PipeSender",
    message: "This secret message was sent through a pipe!",
    secret_number: 12345,
  };

  console.error("Sending message:");
  console.error(`  Sender: ${messageData.sender}`);
  console.error(`  Message: ${messageData.message}`);
  console.error(`  Secret Number: ${messageData.secret_number}`);
  console.error();

  // Create FlatBuffer
  const runner = await FlatcRunner.init();
  const flatbuffer = runner.generateBinary(
    schemaInput,
    JSON.stringify(messageData)
  );

  // Create encryption context
  const encryptCtx = EncryptionContext.forEncryption(recipientPublicKey, {
    algorithm: KeyExchangeAlgorithm.X25519,
    context: "pipe-example-v1",
    rootType: "SecretMessage",
  });

  // Encrypt the FlatBuffer
  encryptBuffer(flatbuffer, schemaContent, encryptCtx, "SecretMessage");

  // Get the header
  const headerJSON = encryptCtx.getHeaderJSON();

  // Frame the message
  const framed = frameMessage(headerJSON, flatbuffer);

  console.error(`Encrypted and framed: ${framed.length} bytes`);

  // Write to stdout
  process.stdout.write(Buffer.from(framed));
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});
