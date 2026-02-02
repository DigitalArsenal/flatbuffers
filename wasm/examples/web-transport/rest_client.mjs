#!/usr/bin/env node
/**
 * REST Client Example
 *
 * Demonstrates sending/receiving FlatBuffers over REST API.
 * Shows both encrypted and non-encrypted usage.
 *
 * Usage: node rest_client.mjs [server_url]
 */

import {
  x25519GenerateKeyPair,
  EncryptionContext,
  KeyExchangeAlgorithm,
  encryptBuffer,
  decryptBuffer,
  encryptionHeaderFromJSON,
} from "../../src/index.mjs";
import {
  schemaContent,
  schemaInput,
  plainSchemaContent,
  plainSchemaInput,
  getRunner,
  toHex,
  fromHex,
} from "./shared.mjs";

const SERVER_URL = process.argv[2] || "http://localhost:8080";

async function main() {
  const runner = await getRunner();

  console.log("=== REST Client Example ===\n");
  console.log(`Server: ${SERVER_URL}\n`);

  // =========================================================================
  // Part 1: Non-encrypted (plaintext) FlatBuffer
  // =========================================================================
  console.log("--- Part 1: Plaintext FlatBuffer ---\n");

  const plainMessage = {
    id: "msg-001",
    sender: "Alice",
    content: "Hello, this is a public message!",
    timestamp: Date.now(),
    public_tag: "greeting",
  };

  console.log("Creating plaintext message:");
  console.log(`  ${JSON.stringify(plainMessage)}\n`);

  // Create FlatBuffer
  const plainBuffer = runner.generateBinary(
    plainSchemaInput,
    JSON.stringify(plainMessage)
  );
  console.log(`FlatBuffer size: ${plainBuffer.length} bytes`);

  // POST to server
  console.log("Sending to POST /message...");
  const postPlainRes = await fetch(`${SERVER_URL}/message`, {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream" },
    body: plainBuffer,
  });
  const postPlainJson = await postPlainRes.json();
  console.log(`Response: ${JSON.stringify(postPlainJson)}\n`);

  // GET from server
  const messageId = postPlainJson.id;
  console.log(`Fetching GET /message/${messageId}...`);
  const getPlainRes = await fetch(`${SERVER_URL}/message/${messageId}`);
  const getPlainBuffer = new Uint8Array(await getPlainRes.arrayBuffer());
  console.log(`Received ${getPlainBuffer.length} bytes`);

  // Parse the received FlatBuffer
  const receivedJson = runner.generateJSON(plainSchemaInput, {
    path: "/msg.bin",
    data: getPlainBuffer,
  });
  console.log(`Parsed: ${receivedJson}\n`);

  // =========================================================================
  // Part 2: Encrypted FlatBuffer
  // =========================================================================
  console.log("--- Part 2: Encrypted FlatBuffer ---\n");

  // Step 1: Get server's public keys
  console.log("Fetching server public keys...");
  const keysRes = await fetch(`${SERVER_URL}/keys`);
  const serverKeys = await keysRes.json();
  console.log(`  X25519: ${serverKeys.x25519.substring(0, 32)}...`);

  // Use X25519 for this example
  const serverPublicKey = fromHex(serverKeys.x25519);

  // Step 2: Create encrypted message
  const secretMessage = {
    id: "secret-001",
    sender: "Bob",
    content: "This is a TOP SECRET message!",
    timestamp: Date.now(),
    public_tag: "classified",
  };

  console.log("\nCreating encrypted message:");
  console.log(`  Content: "${secretMessage.content}" (will be encrypted)`);
  console.log(`  Public tag: "${secretMessage.public_tag}" (not encrypted)\n`);

  // Create FlatBuffer
  const encBuffer = runner.generateBinary(schemaInput, JSON.stringify(secretMessage));
  console.log(`Original FlatBuffer: ${encBuffer.length} bytes`);
  console.log(`Original hex: ${toHex(encBuffer).substring(0, 60)}...`);

  // Create encryption context with server's public key
  const appContext = "rest-api-v1";
  const encryptCtx = EncryptionContext.forEncryption(serverPublicKey, {
    algorithm: KeyExchangeAlgorithm.X25519,
    context: appContext,
    rootType: "Message",
  });

  // Encrypt the FlatBuffer
  encryptBuffer(encBuffer, schemaContent, encryptCtx, "Message");
  console.log(`Encrypted hex: ${toHex(encBuffer).substring(0, 60)}...`);

  // Get the encryption header
  const headerJSON = encryptCtx.getHeaderJSON();
  console.log(`Ephemeral key: ${toHex(encryptCtx.getEphemeralPublicKey()).substring(0, 32)}...`);

  // Step 3: POST encrypted message to server
  console.log("\nSending to POST /encrypted...");
  const postEncRes = await fetch(`${SERVER_URL}/encrypted`, {
    method: "POST",
    headers: {
      "Content-Type": "application/octet-stream",
      "X-Encryption-Header": headerJSON,
    },
    body: encBuffer,
  });
  const postEncJson = await postEncRes.json();
  console.log(`Response: ${JSON.stringify(postEncJson)}\n`);

  // Step 4: GET encrypted message back (simulating another client)
  const encryptedId = postEncJson.id;
  console.log(`Fetching GET /encrypted/${encryptedId}...`);
  const getEncRes = await fetch(`${SERVER_URL}/encrypted/${encryptedId}`);
  const receivedEncBuffer = new Uint8Array(await getEncRes.arrayBuffer());
  const receivedHeaderJSON = getEncRes.headers.get("X-Encryption-Header");

  console.log(`Received ${receivedEncBuffer.length} bytes`);
  console.log(`Header received: ${receivedHeaderJSON ? "yes" : "no"}`);

  // Note: In a real scenario, only the recipient with the matching private key
  // can decrypt. Here we just verify the data was received correctly.
  console.log(`Encrypted data matches: ${toHex(receivedEncBuffer) === toHex(encBuffer) ? "yes" : "no"}`);

  // =========================================================================
  // Part 3: End-to-end encrypted messaging (client-to-client via server)
  // =========================================================================
  console.log("\n--- Part 3: Client-to-Client Encryption ---\n");

  // Generate recipient's key pair (in real app, this would be the other client)
  const recipientKeys = x25519GenerateKeyPair();
  console.log(`Recipient public key: ${toHex(recipientKeys.publicKey).substring(0, 32)}...`);

  // Sender creates message for recipient (not for server)
  const privateMessage = {
    id: "private-001",
    sender: "Charlie",
    content: "Only you can read this, not even the server!",
    timestamp: Date.now(),
    public_tag: "private",
  };

  console.log(`\nMessage: "${privateMessage.content}"`);

  // Create and encrypt FlatBuffer for recipient
  const privateBuffer = runner.generateBinary(schemaInput, JSON.stringify(privateMessage));
  const e2eContext = "e2e-messaging-v1";
  const senderCtx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
    algorithm: KeyExchangeAlgorithm.X25519,
    context: e2eContext,
    rootType: "Message",
  });
  encryptBuffer(privateBuffer, schemaContent, senderCtx, "Message");
  const e2eHeaderJSON = senderCtx.getHeaderJSON();

  console.log("Encrypted for recipient, sending via server...");

  // Server just stores/relays - cannot decrypt!
  // (Using a different endpoint that doesn't try to decrypt)
  // For this demo, we'll just simulate the relay

  // Recipient receives and decrypts
  console.log("\nRecipient decrypting...");
  const e2eHeader = encryptionHeaderFromJSON(e2eHeaderJSON);
  const recipientCtx = EncryptionContext.forDecryption(recipientKeys.privateKey, e2eHeader, e2eContext);

  const decryptedBuffer = new Uint8Array(privateBuffer);
  decryptBuffer(decryptedBuffer, schemaContent, recipientCtx, "Message");

  const decryptedJson = runner.generateJSON(schemaInput, {
    path: "/msg.bin",
    data: decryptedBuffer,
  });
  const decryptedMessage = JSON.parse(decryptedJson);

  console.log(`Decrypted: "${decryptedMessage.content}"`);
  console.log(`Match: ${decryptedMessage.content === privateMessage.content ? "yes" : "no"}`);

  console.log("\n=== All tests completed ===");
}

main().catch(console.error);
