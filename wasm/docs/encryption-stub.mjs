/**
 * Stub encryption module for the docs demo
 * The actual encryption module has been removed from the flatc-wasm package.
 * This stub allows the demo to build but encryption features will not work.
 */

export async function loadEncryptionWasm() {
  console.warn('Encryption module has been removed from flatc-wasm package');
  return false;
}

export async function sha256(data) {
  // Use Web Crypto API as fallback
  const buffer = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(buffer);
}

export async function hkdf(ikm, salt, info, length) {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: salt || new Uint8Array(32), info: info || new Uint8Array(0) },
    key,
    length * 8
  );
  return new Uint8Array(bits);
}

export function x25519GenerateKeyPair() {
  console.warn('x25519GenerateKeyPair: Encryption module removed');
  return { publicKey: new Uint8Array(32), privateKey: new Uint8Array(32) };
}

export function secp256k1GenerateKeyPair() {
  console.warn('secp256k1GenerateKeyPair: Encryption module removed');
  return { publicKey: new Uint8Array(33), privateKey: new Uint8Array(32) };
}

export async function p256GenerateKeyPairAsync() {
  console.warn('p256GenerateKeyPairAsync: Encryption module removed');
  return { publicKey: new Uint8Array(65), privateKey: new Uint8Array(32) };
}

export async function p384GenerateKeyPairAsync() {
  console.warn('p384GenerateKeyPairAsync: Encryption module removed');
  return { publicKey: new Uint8Array(97), privateKey: new Uint8Array(48) };
}

export class EncryptionContext {
  constructor() {
    console.warn('EncryptionContext: Encryption module removed');
  }
  async encrypt() { return new Uint8Array(0); }
  async decrypt() { return new Uint8Array(0); }
}

export function encryptionHeaderFromJSON(json) {
  return json;
}

export async function encryptBuffer(buffer, options) {
  console.warn('encryptBuffer: Encryption module removed');
  return { encryptedBuffer: buffer, header: {} };
}

export async function decryptBuffer(buffer, options) {
  console.warn('decryptBuffer: Encryption module removed');
  return buffer;
}
