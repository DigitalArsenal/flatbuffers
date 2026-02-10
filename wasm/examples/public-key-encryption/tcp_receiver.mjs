#!/usr/bin/env node
/**
 * TCP Receiver Example -- WASM binary exports
 *
 * Starts a TCP server that:
 * 1. Generates long-term key pairs for all three curves
 * 2. Prints the public keys (for sender to use)
 * 3. Listens for encrypted messages
 * 4. Decrypts and displays them using WASM crypto primitives
 *
 * Usage: node tcp_receiver.mjs [port]
 */

import { createServer } from "net";
import path from "path";
import { fileURLToPath } from "url";
import { unframeMessage } from "./framing.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = parseInt(process.argv[2]) || 9999;

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

// --- Shared secret dispatchers ---

function x25519SharedSecret(Module, priv, pub) {
  const privPtr = allocBytes(Module, priv);
  const pubPtr = allocBytes(Module, pub);
  const outPtr = Module._malloc(32);
  Module._wasm_crypto_x25519_shared_secret(privPtr, pubPtr, outPtr);
  const s = readBytes(Module, outPtr, 32);
  Module._free(privPtr);
  Module._free(pubPtr);
  Module._free(outPtr);
  return s;
}

function secp256k1SharedSecret(Module, priv, pub) {
  const privPtr = allocBytes(Module, priv);
  const pubPtr = allocBytes(Module, pub);
  const outPtr = Module._malloc(32);
  Module._wasm_crypto_secp256k1_shared_secret(privPtr, pubPtr, outPtr);
  const s = readBytes(Module, outPtr, 32);
  Module._free(privPtr);
  Module._free(pubPtr);
  Module._free(outPtr);
  return s;
}

function p256SharedSecret(Module, priv, pub) {
  const privPtr = allocBytes(Module, priv);
  const pubPtr = allocBytes(Module, pub);
  const outPtr = Module._malloc(32);
  Module._wasm_crypto_p256_shared_secret(privPtr, pubPtr, outPtr);
  const s = readBytes(Module, outPtr, 32);
  Module._free(privPtr);
  Module._free(pubPtr);
  Module._free(outPtr);
  return s;
}

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

function decryptBytes(Module, ciphertext, key, iv) {
  const dataPtr = allocBytes(Module, ciphertext);
  const keyPtr = allocBytes(Module, key);
  const ivPtr = allocBytes(Module, iv);
  Module._wasm_crypto_decrypt_bytes(dataPtr, ciphertext.length, keyPtr, ivPtr);
  const plaintext = readBytes(Module, dataPtr, ciphertext.length);
  Module._free(dataPtr);
  Module._free(keyPtr);
  Module._free(ivPtr);
  return plaintext;
}

// --- Key pair generators ---

function x25519GenerateKeyPair(Module) {
  const privPtr = Module._malloc(32);
  const pubPtr = Module._malloc(32);
  Module._wasm_crypto_x25519_generate_keypair(privPtr, pubPtr);
  const priv = readBytes(Module, privPtr, 32);
  const pub = readBytes(Module, pubPtr, 32);
  Module._free(privPtr);
  Module._free(pubPtr);
  return { privateKey: priv, publicKey: pub };
}

function secp256k1GenerateKeyPair(Module) {
  const privPtr = Module._malloc(32);
  const pubPtr = Module._malloc(33);
  Module._wasm_crypto_secp256k1_generate_keypair(privPtr, pubPtr);
  const priv = readBytes(Module, privPtr, 32);
  const pub = readBytes(Module, pubPtr, 33);
  Module._free(privPtr);
  Module._free(pubPtr);
  return { privateKey: priv, publicKey: pub };
}

function p256GenerateKeyPair(Module) {
  const privPtr = Module._malloc(32);
  const pubPtr = Module._malloc(33);
  Module._wasm_crypto_p256_generate_keypair(privPtr, pubPtr);
  const priv = readBytes(Module, privPtr, 32);
  const pub = readBytes(Module, pubPtr, 33);
  Module._free(privPtr);
  Module._free(pubPtr);
  return { privateKey: priv, publicKey: pub };
}

// --- Curve dispatch table ---

const SHARED_SECRET_FNS = {
  x25519: x25519SharedSecret,
  secp256k1: secp256k1SharedSecret,
  p256: p256SharedSecret,
};

async function main() {
  const Module = await loadModule();

  // Generate key pairs for all supported curves
  const keys = {
    x25519: x25519GenerateKeyPair(Module),
    secp256k1: secp256k1GenerateKeyPair(Module),
    p256: p256GenerateKeyPair(Module),
  };

  console.log("=== TCP Receiver ===\n");
  console.log("Recipient public keys (share with sender):\n");
  console.log(`X25519:    ${toHex(keys.x25519.publicKey)}`);
  console.log(`secp256k1: ${toHex(keys.secp256k1.publicKey)}`);
  console.log(`P-256:     ${toHex(keys.p256.publicKey)}`);
  console.log();

  const server = createServer((socket) => {
    console.log(`\nConnection from ${socket.remoteAddress}:${socket.remotePort}`);

    const chunks = [];

    socket.on("data", (chunk) => {
      chunks.push(chunk);
    });

    socket.on("end", () => {
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
        const header = JSON.parse(headerJSON);

        const curveName = header.algorithm.toLowerCase();
        console.log(`Key exchange: ${header.algorithm}`);
        console.log(`Context: ${header.context || "(none)"}`);

        // Select the appropriate private key
        const curveKeys = keys[curveName];
        if (!curveKeys) {
          throw new Error(`Unknown curve: ${curveName}`);
        }

        const sharedSecretFn = SHARED_SECRET_FNS[curveName];
        if (!sharedSecretFn) {
          throw new Error(`No shared-secret function for curve: ${curveName}`);
        }

        // Reconstruct shared secret
        const ephemeralPublicKey = fromHex(header.ephemeralPublicKey);
        const shared = sharedSecretFn(Module, curveKeys.privateKey, ephemeralPublicKey);

        // Derive symmetric key
        const context = header.context
          ? new TextEncoder().encode(header.context)
          : null;
        const symmetricKey = hkdf(Module, shared, context);

        // Decrypt
        const iv = fromHex(header.iv);
        const plaintext = decryptBytes(Module, data, symmetricKey, iv);

        // Parse the decrypted message
        const message = JSON.parse(new TextDecoder().decode(plaintext));

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
