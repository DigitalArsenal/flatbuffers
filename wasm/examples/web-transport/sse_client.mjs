#!/usr/bin/env node
/**
 * Server-Sent Events (SSE) Client Example
 *
 * Demonstrates receiving streaming FlatBuffers over SSE.
 * Supports both plaintext and encrypted streams.
 *
 * Session-Based Encryption:
 * - Receives header once at connection (or on rotation)
 * - Uses same header to decrypt all subsequent messages
 * - Handles key rotation when server sends "rotate" event
 *
 * Usage:
 *   node sse_client.mjs [--encrypted] [server_url]
 *
 * Examples:
 *   node sse_client.mjs                              # Plaintext
 *   node sse_client.mjs --encrypted                  # Encrypted with X25519
 *   node sse_client.mjs --encrypted http://localhost:8081
 */

import {
  x25519GenerateKeyPair,
  EncryptionContext,
  decryptBuffer,
} from "flatc-wasm/encryption";
import {
  schemaContent,
  schemaInput,
  plainSchemaInput,
  getRunner,
  toHex,
} from "./shared.mjs";

const args = process.argv.slice(2);
const encrypted = args.includes("--encrypted");
const SERVER_URL = args.find((a) => !a.startsWith("--")) || "http://localhost:8081";

function fromBase64(base64) {
  return new Uint8Array(Buffer.from(base64, "base64"));
}

async function runPlainClient() {
  const runner = await getRunner();

  console.log("=== SSE Client (Plaintext) ===\n");
  console.log(`Connecting to ${SERVER_URL}/events...\n`);

  const response = await fetch(`${SERVER_URL}/events`);
  const reader = response.body.getReader();
  const decoder = new TextDecoder();

  let buffer = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });

    // Parse SSE events
    const lines = buffer.split("\n");
    buffer = lines.pop(); // Keep incomplete line

    let eventType = null;
    let eventData = null;

    for (const line of lines) {
      if (line.startsWith("event: ")) {
        eventType = line.substring(7);
      } else if (line.startsWith("data: ")) {
        eventData = line.substring(6);
      } else if (line === "" && eventType && eventData) {
        // End of event
        handlePlainEvent(runner, eventType, eventData);
        eventType = null;
        eventData = null;
      }
    }
  }
}

function handlePlainEvent(runner, eventType, eventData) {
  const data = JSON.parse(eventData);

  if (eventType === "connected") {
    console.log("Connected (plaintext mode)\n");
    return;
  }

  if (eventType === "message") {
    const buffer = fromBase64(data.buffer);
    const json = runner.generateJSON(plainSchemaInput, {
      path: "/msg.bin",
      data: buffer,
    });
    const message = JSON.parse(json);

    console.log(`[${message.id}] ${message.sender}: ${message.content}`);
    console.log(`  Tag: ${message.public_tag}, Time: ${new Date(Number(message.timestamp)).toISOString()}\n`);
  }
}

async function runEncryptedClient() {
  const runner = await getRunner();

  // Generate client's key pair
  const clientKeys = x25519GenerateKeyPair();

  console.log("=== SSE Client (Encrypted) ===\n");
  console.log(`Client public key: ${toHex(clientKeys.publicKey)}`);
  console.log(`Connecting to ${SERVER_URL}/encrypted-events...\n`);

  const url = `${SERVER_URL}/encrypted-events?key=${toHex(clientKeys.publicKey)}&algo=x25519`;
  const response = await fetch(url);
  const reader = response.body.getReader();
  const decoder = new TextDecoder();

  let buffer = "";
  let decryptCtx = null; // Current session decryption context
  let messageCount = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });

    const lines = buffer.split("\n");
    buffer = lines.pop();

    let eventType = null;
    let eventData = null;

    for (const line of lines) {
      if (line.startsWith("event: ")) {
        eventType = line.substring(7);
      } else if (line.startsWith("data: ")) {
        eventData = line.substring(6);
      } else if (line === "" && eventType && eventData) {
        const result = handleEncryptedEvent(
          runner,
          eventType,
          eventData,
          clientKeys.privateKey,
          decryptCtx
        );
        if (result.decryptCtx) {
          decryptCtx = result.decryptCtx;
        }
        if (result.messageCount !== undefined) {
          messageCount = result.messageCount;
        }
        eventType = null;
        eventData = null;
      }
    }
  }
}

function handleEncryptedEvent(runner, eventType, eventData, privateKey, currentCtx) {
  const data = JSON.parse(eventData);
  let decryptCtx = currentCtx;
  let messageCount;

  if (eventType === "connected") {
    console.log(`Connected (encrypted, algo: ${data.algo})`);

    // Create decryption context from session header
    decryptCtx = EncryptionContext.forDecryption(privateKey, data.header, "sse-stream-v1");
    console.log("Session header received, ready to decrypt\n");

    return { decryptCtx, messageCount: 0 };
  }

  if (eventType === "rotate") {
    console.log(`\n[KEY ROTATION] Reason: ${data.reason}`);

    // Create new decryption context from new header
    decryptCtx = EncryptionContext.forDecryption(privateKey, data.header, "sse-stream-v1");
    console.log("New session header applied\n");

    return { decryptCtx, messageCount: 0 };
  }

  if (eventType === "message") {
    if (!decryptCtx) {
      console.log("ERROR: No decryption context (missing header)");
      return {};
    }

    const encryptedBuffer = fromBase64(data.buffer);

    // Decrypt using session context
    const decryptedBuffer = new Uint8Array(encryptedBuffer);
    decryptBuffer(decryptedBuffer, schemaContent, decryptCtx, "Message");

    const json = runner.generateJSON(schemaInput, {
      path: "/msg.bin",
      data: decryptedBuffer,
    });
    const message = JSON.parse(json);

    console.log(`[${message.id}] ${message.sender}: ${message.content}`);
    console.log(`  Tag: ${message.public_tag}, Time: ${new Date(Number(message.timestamp)).toISOString()}\n`);

    return {};
  }

  return {};
}

async function main() {
  try {
    if (encrypted) {
      await runEncryptedClient();
    } else {
      await runPlainClient();
    }
  } catch (err) {
    if (err.code === "ECONNREFUSED") {
      console.error(`Cannot connect to ${SERVER_URL}. Is the server running?`);
      console.error("Start the server with: node sse_server.mjs");
    } else {
      console.error("Error:", err.message);
    }
  }
}

main();
