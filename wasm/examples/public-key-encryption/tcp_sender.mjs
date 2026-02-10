#!/usr/bin/env node
/**
 * TCP Sender Example -- WASM binary exports
 *
 * Sends an encrypted message to a receiver via TCP, using the WASM crypto
 * primitives directly: ECDH key exchange, HKDF, AES-256-CTR.
 *
 * Usage: node tcp_sender.mjs <recipient_public_key_hex> [host] [port] [curve]
 *
 * Examples:
 *   node tcp_sender.mjs abc123... localhost 9999 x25519
 *   node tcp_sender.mjs abc123... localhost 9999 secp256k1
 *   node tcp_sender.mjs abc123... localhost 9999 p256
 */

import { createConnection } from "net";
import path from "path";
import { fileURLToPath } from "url";
import { frameMessage } from "./framing.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

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

function toHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function fromHex(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

async function loadModule() {
  const wasmPath = path.join(__dirname, "..", "..", "dist", "flatc-wasm.js");
  const { default: createModule } = await import(wasmPath);
  const Module = await createModule({
    noInitialRun: true,
    noExitRuntime: true,
  });
  return Module;
}

function allocBytes(Module, data) {
  const ptr = Module._malloc(data.length);
  Module.HEAPU8.set(data, ptr);
  return ptr;
}

function readBytes(Module, ptr, len) {
  return new Uint8Array(Module.HEAPU8.buffer, ptr, len).slice();
}

// --- Curve dispatchers ---

const CURVES = {
  x25519: {
    pubLen: 32,
    generateKeyPair(Module) {
      const privPtr = Module._malloc(32);
      const pubPtr = Module._malloc(32);
      Module._wasm_crypto_x25519_generate_keypair(privPtr, pubPtr);
      const priv = readBytes(Module, privPtr, 32);
      const pub = readBytes(Module, pubPtr, 32);
      Module._free(privPtr);
      Module._free(pubPtr);
      return { privateKey: priv, publicKey: pub };
    },
    sharedSecret(Module, priv, pub) {
      const privPtr = allocBytes(Module, priv);
      const pubPtr = allocBytes(Module, pub);
      const outPtr = Module._malloc(32);
      Module._wasm_crypto_x25519_shared_secret(privPtr, pubPtr, outPtr);
      const s = readBytes(Module, outPtr, 32);
      Module._free(privPtr);
      Module._free(pubPtr);
      Module._free(outPtr);
      return s;
    },
  },
  secp256k1: {
    pubLen: 33,
    generateKeyPair(Module) {
      const privPtr = Module._malloc(32);
      const pubPtr = Module._malloc(33);
      Module._wasm_crypto_secp256k1_generate_keypair(privPtr, pubPtr);
      const priv = readBytes(Module, privPtr, 32);
      const pub = readBytes(Module, pubPtr, 33);
      Module._free(privPtr);
      Module._free(pubPtr);
      return { privateKey: priv, publicKey: pub };
    },
    sharedSecret(Module, priv, pub) {
      const privPtr = allocBytes(Module, priv);
      const pubPtr = allocBytes(Module, pub);
      const outPtr = Module._malloc(32);
      Module._wasm_crypto_secp256k1_shared_secret(privPtr, pubPtr, outPtr);
      const s = readBytes(Module, outPtr, 32);
      Module._free(privPtr);
      Module._free(pubPtr);
      Module._free(outPtr);
      return s;
    },
  },
  p256: {
    pubLen: 33,
    generateKeyPair(Module) {
      const privPtr = Module._malloc(32);
      const pubPtr = Module._malloc(33);
      Module._wasm_crypto_p256_generate_keypair(privPtr, pubPtr);
      const priv = readBytes(Module, privPtr, 32);
      const pub = readBytes(Module, pubPtr, 33);
      Module._free(privPtr);
      Module._free(pubPtr);
      return { privateKey: priv, publicKey: pub };
    },
    sharedSecret(Module, priv, pub) {
      const privPtr = allocBytes(Module, priv);
      const pubPtr = allocBytes(Module, pub);
      const outPtr = Module._malloc(32);
      Module._wasm_crypto_p256_shared_secret(privPtr, pubPtr, outPtr);
      const s = readBytes(Module, outPtr, 32);
      Module._free(privPtr);
      Module._free(pubPtr);
      Module._free(outPtr);
      return s;
    },
  },
};

function hkdf(Module, ikm, info) {
  const ikmPtr = allocBytes(Module, ikm);
  const infoPtr = info ? allocBytes(Module, info) : 0;
  const outPtr = Module._malloc(32);
  Module._wasm_crypto_hkdf(
    ikmPtr, ikm.length,
    0, 0,
    infoPtr, info ? info.length : 0,
    outPtr, 32,
  );
  const derived = readBytes(Module, outPtr, 32);
  Module._free(ikmPtr);
  if (infoPtr) Module._free(infoPtr);
  Module._free(outPtr);
  return derived;
}

function encryptBytes(Module, data, key, iv) {
  const dataPtr = allocBytes(Module, data);
  const keyPtr = allocBytes(Module, key);
  const ivPtr = allocBytes(Module, iv);
  Module._wasm_crypto_encrypt_bytes(dataPtr, data.length, keyPtr, ivPtr);
  const ct = readBytes(Module, dataPtr, data.length);
  Module._free(dataPtr);
  Module._free(keyPtr);
  Module._free(ivPtr);
  return ct;
}

async function main() {
  console.log("=== TCP Sender ===\n");

  const curve = CURVES[CURVE];
  if (!curve) {
    console.error(`Unknown curve: ${CURVE}`);
    process.exit(1);
  }

  const recipientPublicKey = fromHex(recipientKeyHex);
  if (recipientPublicKey.length !== curve.pubLen) {
    console.error(
      `Invalid public key length for ${CURVE}: expected ${curve.pubLen}, got ${recipientPublicKey.length}`
    );
    process.exit(1);
  }

  console.log(`Curve: ${CURVE}`);
  console.log(`Recipient: ${recipientKeyHex.substring(0, 32)}...`);
  console.log(`Target: ${HOST}:${PORT}\n`);

  const Module = await loadModule();

  // Build the plaintext message
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

  const plaintext = new TextEncoder().encode(JSON.stringify(messageData));
  console.log(`Plaintext size: ${plaintext.length} bytes`);

  // Generate ephemeral key pair and compute shared secret
  const ephemeral = curve.generateKeyPair(Module);
  const shared = curve.sharedSecret(Module, ephemeral.privateKey, recipientPublicKey);

  // Derive symmetric key
  const context = new TextEncoder().encode("tcp-example-v1");
  const symmetricKey = hkdf(Module, shared, context);

  console.log(`Ephemeral key: ${toHex(ephemeral.publicKey).substring(0, 32)}...`);

  // Random IV
  const iv = new Uint8Array(16);
  crypto.getRandomValues(iv);

  // Encrypt
  const ciphertext = encryptBytes(Module, plaintext, symmetricKey, iv);

  // Build header
  const headerJSON = JSON.stringify({
    algorithm: CURVE,
    ephemeralPublicKey: toHex(ephemeral.publicKey),
    iv: toHex(iv),
    context: "tcp-example-v1",
  });

  // Frame the message
  const framed = frameMessage(headerJSON, ciphertext);
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
