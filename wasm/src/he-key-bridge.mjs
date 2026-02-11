/**
 * HE Key Bridge: HD Wallet → Deterministic Homomorphic Encryption Keys
 *
 * Derives deterministic HE keys from an HD wallet encryption key using HKDF
 * with domain separation. HE keys are fully recoverable from the mnemonic.
 *
 * Flow:
 *   HDKeyManager.deriveEncryptionKey() → HKDF(key, salt, info) → 64-byte seed → HEContext
 *
 * Domain separation prevents key reuse between AES and HE cryptosystems:
 *   - Salt: "flatbuffers-he-v1"
 *   - Info: "seal-bfv-{polyDegree}" (e.g. "seal-bfv-4096")
 */

import { HEContext, DEFAULT_POLY_MODULUS_DEGREE } from './he-context.mjs';

const HE_SALT = 'flatbuffers-he-v1';
const HE_INFO_PREFIX = 'seal-bfv-';
const HE_SEED_LENGTH = 64;

/**
 * Encode a string to Uint8Array (UTF-8).
 * @param {string} str
 * @returns {Uint8Array}
 */
function encodeString(str) {
  return new TextEncoder().encode(str);
}

/**
 * Default HKDF implementation using Web Crypto API.
 * Derives a key of the specified length from input key material.
 *
 * @param {Uint8Array} ikm - Input key material (the HD wallet private key)
 * @param {Uint8Array} salt - Salt for domain separation
 * @param {Uint8Array} info - Context/application-specific info
 * @param {number} length - Desired output length in bytes
 * @returns {Promise<Uint8Array>} Derived key material
 */
async function defaultHkdf(ikm, salt, info, length) {
  const crypto = globalThis.crypto || (await import('node:crypto')).webcrypto;

  const keyMaterial = await crypto.subtle.importKey(
    'raw', ikm, { name: 'HKDF' }, false, ['deriveBits']
  );

  const derived = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    keyMaterial,
    length * 8
  );

  return new Uint8Array(derived);
}

/**
 * Derive a deterministic HE context from an HD wallet encryption key.
 *
 * The derivation path:
 *   1. Extract the private key bytes from the HD-derived encryption key
 *   2. Run HKDF with domain-separated salt and info strings
 *   3. Use the 64-byte output as seed for deterministic SEAL key generation
 *
 * @param {object} hdEncryptionKey - Derived key from HDKeyManager.deriveEncryptionKey()
 *   Must have a `privateKey` property (Uint8Array).
 * @param {object} [options] - Options
 * @param {number} [options.polyDegree=4096] - Polynomial modulus degree (4096, 8192, 16384)
 * @param {function} [options.hkdfFn] - Custom HKDF function (defaults to Web Crypto HKDF)
 *   Signature: (ikm, salt, info, length) => Promise<Uint8Array>
 * @returns {Promise<HEContext>} Deterministic HE client context
 */
export async function deriveHEContext(hdEncryptionKey, options = {}) {
  if (!hdEncryptionKey || !hdEncryptionKey.privateKey) {
    throw new Error('hdEncryptionKey must have a privateKey property (Uint8Array)');
  }

  const polyDegree = options.polyDegree || DEFAULT_POLY_MODULUS_DEGREE;
  const hkdfFn = options.hkdfFn || defaultHkdf;

  const ikm = hdEncryptionKey.privateKey;
  const salt = encodeString(HE_SALT);
  const info = encodeString(`${HE_INFO_PREFIX}${polyDegree}`);

  const seed = await hkdfFn(ikm, salt, info, HE_SEED_LENGTH);

  return HEContext.createClientFromSeed(seed, polyDegree);
}

/**
 * Extract the public bundle from an HE context for sharing with recipients.
 * Recipients use this bundle to create a server context for encrypted computation.
 *
 * @param {HEContext} heContext - Client HE context
 * @returns {{ publicKey: Uint8Array, relinKeys: Uint8Array }} Public bundle
 */
export function getHEPublicBundle(heContext) {
  if (!heContext) {
    throw new Error('heContext is required');
  }

  return {
    publicKey: heContext.getPublicKey(),
    relinKeys: heContext.getRelinKeys(),
  };
}

/**
 * Derive an HE context directly from an HDKeyManager instance.
 * Convenience wrapper that handles key derivation + HKDF in one call.
 *
 * @param {object} hdKeyManager - HDKeyManager instance
 * @param {object} [keyOptions] - Key derivation options
 * @param {number} [keyOptions.coinType] - BIP-44 coin type
 * @param {number} [keyOptions.account=0] - Account index
 * @param {number} [keyOptions.index=0] - Key index
 * @param {object} [heOptions] - HE options
 * @param {number} [heOptions.polyDegree=4096] - Polynomial modulus degree
 * @param {function} [heOptions.hkdfFn] - Custom HKDF function
 * @returns {Promise<HEContext>} Deterministic HE client context
 */
export async function deriveHEContextFromManager(hdKeyManager, keyOptions = {}, heOptions = {}) {
  if (!hdKeyManager || typeof hdKeyManager.deriveEncryptionKey !== 'function') {
    throw new Error('hdKeyManager must be an HDKeyManager instance');
  }

  const encryptionKey = hdKeyManager.deriveEncryptionKey(keyOptions);
  return deriveHEContext(encryptionKey, heOptions);
}
