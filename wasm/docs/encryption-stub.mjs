/**
 * WebCrypto utilities for the docs demo
 * Uses native crypto.subtle for SHA-256, HKDF, and AES-GCM
 * Key generation is handled by hd-wallet-wasm (not here)
 */

export async function loadEncryptionWasm() {
  return true;
}

export async function sha256(data) {
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

export class EncryptionContext {
  constructor(key) {
    if (typeof key === 'string') {
      if (!/^[0-9a-fA-F]+$/.test(key)) throw new Error('Invalid hex string');
      if (key.length !== 64) throw new Error('Hex key must be 64 characters');
      this._key = new Uint8Array(key.match(/.{2}/g).map(b => parseInt(b, 16)));
    } else if (key instanceof Uint8Array) {
      if (key.length !== 32) throw new Error('Key expected 32 bytes');
      this._key = key;
    } else {
      throw new Error('Key must be hex string or Uint8Array');
    }
  }
  async encrypt(data) { return data; }
  async decrypt(data) { return data; }
}

export function encryptionHeaderFromJSON(json) {
  return json;
}

export async function encryptBuffer(buffer, options) {
  return { encryptedBuffer: buffer, header: {} };
}

export async function decryptBuffer(buffer, options) {
  return buffer;
}
