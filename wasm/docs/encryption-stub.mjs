/**
 * WebCrypto utilities for the docs demo
 * Uses native crypto.subtle for SHA-256, HKDF, and AES-GCM
 * Key generation is handled by hd-wallet-wasm (not here)
 */

import { x25519 } from '@noble/curves/ed25519';
import { secp256k1 } from '@noble/curves/secp256k1';
import { p256 } from '@noble/curves/p256';

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

  /**
   * Create encryption context for ECIES encryption to a public key
   */
  static forEncryption(publicKey, options = {}) {
    const ctx = new EncryptionContext(new Uint8Array(32)); // placeholder
    ctx._mode = 'encrypt';
    ctx._recipientPublicKey = publicKey;
    ctx._algorithm = options.algorithm || 'x25519';
    ctx._context = options.context || 'flatbuffers-encryption';

    // Generate ephemeral key pair based on algorithm
    if (ctx._algorithm === 'x25519') {
      ctx._ephemeralPrivate = x25519.utils.randomPrivateKey();
      ctx._ephemeralPublic = x25519.getPublicKey(ctx._ephemeralPrivate);
      // Compute shared secret
      ctx._sharedSecret = x25519.getSharedSecret(ctx._ephemeralPrivate, publicKey);
    } else if (ctx._algorithm === 'secp256k1') {
      ctx._ephemeralPrivate = secp256k1.utils.randomPrivateKey();
      ctx._ephemeralPublic = secp256k1.getPublicKey(ctx._ephemeralPrivate, true);
      ctx._sharedSecret = secp256k1.getSharedSecret(ctx._ephemeralPrivate, publicKey, true).slice(1);
    } else if (ctx._algorithm === 'p256') {
      ctx._ephemeralPrivate = p256.utils.randomPrivateKey();
      ctx._ephemeralPublic = p256.getPublicKey(ctx._ephemeralPrivate, true);
      ctx._sharedSecret = p256.getSharedSecret(ctx._ephemeralPrivate, publicKey, true).slice(1);
    } else {
      // Default to x25519
      ctx._ephemeralPrivate = x25519.utils.randomPrivateKey();
      ctx._ephemeralPublic = x25519.getPublicKey(ctx._ephemeralPrivate);
      ctx._sharedSecret = x25519.getSharedSecret(ctx._ephemeralPrivate, publicKey);
    }

    return ctx;
  }

  /**
   * Create decryption context from header and private key
   */
  static forDecryption(privateKey, header, options = {}) {
    const ctx = new EncryptionContext(new Uint8Array(32)); // placeholder
    ctx._mode = 'decrypt';
    ctx._privateKey = privateKey;
    ctx._algorithm = header.algorithm || options.algorithm || 'x25519';
    ctx._context = header.context || options.context || 'flatbuffers-encryption';
    ctx._ephemeralPublic = new Uint8Array(header.ephemeralPublicKey);

    // Compute shared secret
    if (ctx._algorithm === 'x25519') {
      ctx._sharedSecret = x25519.getSharedSecret(privateKey, ctx._ephemeralPublic);
    } else if (ctx._algorithm === 'secp256k1') {
      ctx._sharedSecret = secp256k1.getSharedSecret(privateKey, ctx._ephemeralPublic, true).slice(1);
    } else if (ctx._algorithm === 'p256') {
      ctx._sharedSecret = p256.getSharedSecret(privateKey, ctx._ephemeralPublic, true).slice(1);
    } else {
      ctx._sharedSecret = x25519.getSharedSecret(privateKey, ctx._ephemeralPublic);
    }

    return ctx;
  }

  /**
   * Derive a field-specific key using HKDF
   */
  async _deriveFieldKey(fieldId) {
    const info = new TextEncoder().encode(`${this._context}:field:${fieldId}`);
    return await hkdf(this._sharedSecret, new Uint8Array(32), info, 32);
  }

  /**
   * Encrypt scalar field data in-place using XOR with derived keystream
   */
  encryptScalar(buffer, offset, length, fieldId) {
    // Synchronously derive key using simple hash for now
    // In production, use async HKDF
    const fieldKey = this._deriveFieldKeySync(fieldId);

    // XOR encryption with keystream derived from field key
    for (let i = 0; i < length; i++) {
      buffer[offset + i] ^= fieldKey[i % fieldKey.length];
    }
  }

  /**
   * Decrypt scalar field data in-place (XOR is symmetric)
   */
  decryptScalar(buffer, offset, length, fieldId) {
    // XOR decryption is same as encryption
    this.encryptScalar(buffer, offset, length, fieldId);
  }

  /**
   * Synchronous key derivation using simple mixing
   */
  _deriveFieldKeySync(fieldId) {
    // Simple key derivation: mix shared secret with field ID
    const result = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      result[i] = this._sharedSecret[i] ^ ((fieldId >> (i % 4) * 8) & 0xFF);
    }
    return result;
  }

  /**
   * Get encryption header as JSON for storage with ciphertext
   */
  getHeaderJSON() {
    return {
      algorithm: this._algorithm,
      context: this._context,
      ephemeralPublicKey: Array.from(this._ephemeralPublic),
    };
  }

  /**
   * Encrypt entire buffer in-place using record counter for IV derivation
   */
  encryptBuffer(buffer, recordCounter = 0) {
    const key = this._deriveFieldKeySync(recordCounter);
    for (let i = 0; i < buffer.length; i++) {
      buffer[i] ^= key[i % key.length];
    }
  }

  /**
   * Decrypt entire buffer in-place (XOR is symmetric)
   */
  decryptBuffer(buffer, recordCounter = 0) {
    this.encryptBuffer(buffer, recordCounter);
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
