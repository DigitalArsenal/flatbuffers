#!/usr/bin/env node
/**
 * REST Client Example
 *
 * Demonstrates sending/receiving FlatBuffers over REST API.
 * Shows both encrypted and non-encrypted usage.
 * All crypto operations use WASM binary exports (Module._wasm_crypto_*).
 *
 * Usage: node rest_client.mjs [server_url]
 */

import {
  getWasmModule,
  getRunner,
  schemaContent,
  schemaInput,
  plainSchemaContent,
  plainSchemaInput,
  toHex,
  fromHex,
  generateId,
} from "./shared.mjs";

const SERVER_URL = process.argv[2] || "http://localhost:8080";

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
// Crypto helpers that wrap Module._wasm_crypto_* functions
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
  const encrypted = readBytes(dataPtr, data.length);
  freeBytes(keyPtr);
  freeBytes(ivPtr);
  freeBytes(dataPtr);
  return encrypted;
}

function decryptBytes(key, iv, data) {
  const keyPtr = allocBytes(key);
  const ivPtr = allocBytes(iv);
  const dataPtr = allocBytes(data);
  const rc = Module._wasm_crypto_decrypt_bytes(keyPtr, ivPtr, dataPtr, data.length);
  if (rc !== 0) throw new Error("decryption failed");
  const decrypted = readBytes(dataPtr, data.length);
  freeBytes(keyPtr);
  freeBytes(ivPtr);
  freeBytes(dataPtr);
  return decrypted;
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
// Encrypt / Decrypt a FlatBuffer using ephemeral X25519 key exchange
// ---------------------------------------------------------------------------

/**
 * Encrypt a FlatBuffer buffer in-place style. Returns { encrypted, header }.
 * header contains the ephemeral public key and IV needed for decryption.
 */
function encryptFlatBuffer(buffer, peerPublicKey, context) {
  const ephemeral = x25519GenerateKeyPair();
  const shared = x25519SharedSecret(ephemeral.privateKey, ephemeral.publicKey, peerPublicKey);
  const key = deriveSymmetricKey(shared, context);
  // Use first 16 bytes of SHA-256(ephemeral public key) as IV
  const iv = sha256(ephemeral.publicKey).slice(0, 16);
  const encrypted = encryptBytes(key, iv, buffer);
  return {
    encrypted,
    header: {
      ephemeralPublicKey: ephemeral.publicKey,
      iv,
      algorithm: "x25519",
      context,
    },
  };
}

/**
 * Decrypt a FlatBuffer buffer using our private key and the header.
 */
function decryptFlatBuffer(buffer, privateKey, myPublicKey, header) {
  const shared = x25519SharedSecret(privateKey, myPublicKey, header.ephemeralPublicKey);
  const key = deriveSymmetricKey(shared, header.context);
  const iv = header.iv || sha256(header.ephemeralPublicKey).slice(0, 16);
  return decryptBytes(key, iv, buffer);
}

// ---------------------------------------------------------------------------
// Serialise / deserialise headers as JSON for transport
// ---------------------------------------------------------------------------

function headerToJSON(header) {
  return JSON.stringify({
    ephemeralPublicKey: toHex(header.ephemeralPublicKey),
    iv: toHex(header.iv),
    algorithm: header.algorithm,
    context: header.context,
  });
}

function headerFromJSONStr(json) {
  const obj = typeof json === "string" ? JSON.parse(json) : json;
  return {
    ephemeralPublicKey: fromHex(obj.ephemeralPublicKey),
    iv: fromHex(obj.iv),
    algorithm: obj.algorithm,
    context: obj.context,
  };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  Module = await getWasmModule();
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

  // Encrypt using WASM crypto
  const appContext = "rest-api-v1";
  const { encrypted: encryptedData, header: encHeader } = encryptFlatBuffer(
    encBuffer, serverPublicKey, appContext
  );
  console.log(`Encrypted hex: ${toHex(encryptedData).substring(0, 60)}...`);

  // Get the encryption header as JSON
  const encHeaderJSON = headerToJSON(encHeader);
  console.log(`Ephemeral key: ${toHex(encHeader.ephemeralPublicKey).substring(0, 32)}...`);

  // Step 3: POST encrypted message to server
  console.log("\nSending to POST /encrypted...");
  const postEncRes = await fetch(`${SERVER_URL}/encrypted`, {
    method: "POST",
    headers: {
      "Content-Type": "application/octet-stream",
      "X-Encryption-Header": encHeaderJSON,
    },
    body: encryptedData,
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
  console.log(`Encrypted data matches: ${toHex(receivedEncBuffer) === toHex(encryptedData) ? "yes" : "no"}`);

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
  const { encrypted: e2eEncrypted, header: e2eHeader } = encryptFlatBuffer(
    privateBuffer, recipientKeys.publicKey, e2eContext
  );
  const e2eHeaderJSON = headerToJSON(e2eHeader);

  console.log("Encrypted for recipient, sending via server...");

  // Server just stores/relays - cannot decrypt!
  // (Using a different endpoint that doesn't try to decrypt)
  // For this demo, we'll just simulate the relay

  // Recipient receives and decrypts
  console.log("\nRecipient decrypting...");
  const parsedE2eHeader = headerFromJSONStr(e2eHeaderJSON);

  // Recipient needs to derive the same shared secret from their private key
  const decryptedBuffer = decryptFlatBuffer(
    e2eEncrypted,
    recipientKeys.privateKey,
    recipientKeys.publicKey,
    parsedE2eHeader
  );

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
