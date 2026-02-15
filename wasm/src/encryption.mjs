/**
 * encryption.mjs - Encryption module wrapping flatc-wasm crypto functions
 *
 * Provides high-level JS APIs around the WASM cryptographic operations.
 */

import createFlatcModule from '../dist/flatc-wasm.js';

// =============================================================================
// Constants
// =============================================================================

export const KEY_SIZE = 32;
export const IV_SIZE = 16;
export const NONCE_SIZE = 12;
export const SHA256_SIZE = 32;
export const HMAC_SIZE = 32;
export const X25519_PRIVATE_KEY_SIZE = 32;
export const X25519_PUBLIC_KEY_SIZE = 32;
export const SECP256K1_PRIVATE_KEY_SIZE = 32;
export const SECP256K1_PUBLIC_KEY_SIZE = 33;
export const P384_PRIVATE_KEY_SIZE = 48;
export const P384_PUBLIC_KEY_SIZE = 49;
export const ED25519_PRIVATE_KEY_SIZE = 64;
export const ED25519_PUBLIC_KEY_SIZE = 32;
export const ED25519_SIGNATURE_SIZE = 64;

// =============================================================================
// Error Handling
// =============================================================================

export const CryptoErrorCode = {
  UNINITIALIZED: 'UNINITIALIZED',
  INVALID_KEY: 'INVALID_KEY',
  INVALID_IV: 'INVALID_IV',
  INVALID_INPUT: 'INVALID_INPUT',
  WASM_ERROR: 'WASM_ERROR',
  KEY_GENERATION_FAILED: 'KEY_GENERATION_FAILED',
  ECDH_FAILED: 'ECDH_FAILED',
  SIGN_FAILED: 'SIGN_FAILED',
  VERIFY_FAILED: 'VERIFY_FAILED',
  AUTHENTICATION_FAILED: 'AUTHENTICATION_FAILED',
  ALLOCATION_FAILED: 'ALLOCATION_FAILED',
};

export class CryptoError extends Error {
  constructor(message, code = CryptoErrorCode.WASM_ERROR) {
    super(message);
    this.name = 'CryptoError';
    this.code = code;
  }
}

// =============================================================================
// Module State
// =============================================================================

let _module = null;

function ensureInit() {
  if (!_module) {
    throw new CryptoError(
      'Encryption module not initialized. Call loadEncryptionWasm() first.',
      CryptoErrorCode.UNINITIALIZED
    );
  }
}

export async function loadEncryptionWasm() {
  if (_module) return;
  _module = await createFlatcModule();
}

export function isInitialized() {
  return _module !== null;
}

export function hasCryptopp() {
  ensureInit();
  return _module._wasm_crypto_has_cryptopp() === 1;
}

export function getVersion() {
  ensureInit();
  const ptr = _module._wasm_crypto_get_version();
  return _module.UTF8ToString(ptr);
}

// =============================================================================
// WASM Memory Helpers
// =============================================================================

function walloc(size) {
  const ptr = _module._wasm_crypto_alloc(Math.max(size, 1));
  if (!ptr) throw new CryptoError('WASM allocation failed', CryptoErrorCode.ALLOCATION_FAILED);
  return ptr;
}

function wfree(ptr) { _module._wasm_crypto_dealloc(ptr); }
function wfreeSecure(ptr, size) { _module._wasm_crypto_dealloc_secure(ptr, size); }
function wwrite(ptr, data) { _module.HEAPU8.set(data, ptr); }
function wread(ptr, size) { return _module.HEAPU8.slice(ptr, ptr + size); }

// =============================================================================
// Utility Functions
// =============================================================================

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function getRandomBytes(size) {
  const bytes = new Uint8Array(size);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

// =============================================================================
// SHA-256
// =============================================================================

export function sha256(data) {
  ensureInit();
  if (!(data instanceof Uint8Array)) throw new CryptoError('Data must be Uint8Array', CryptoErrorCode.INVALID_INPUT);

  const dataPtr = walloc(data.length);
  const hashPtr = walloc(SHA256_SIZE);
  try {
    if (data.length > 0) wwrite(dataPtr, data);
    _module._wasm_crypto_sha256(dataPtr, data.length, hashPtr);
    return wread(hashPtr, SHA256_SIZE);
  } finally {
    wfree(dataPtr);
    wfree(hashPtr);
  }
}

// =============================================================================
// HMAC-SHA256 (built on WASM SHA-256)
// =============================================================================

export function hmacSha256(key, data) {
  if (!(key instanceof Uint8Array)) throw new CryptoError('Key must be Uint8Array', CryptoErrorCode.INVALID_INPUT);
  if (!(data instanceof Uint8Array)) throw new CryptoError('Data must be Uint8Array', CryptoErrorCode.INVALID_INPUT);

  const BLOCK = 64;
  let k = key.length > BLOCK ? sha256(key) : key;
  const padded = new Uint8Array(BLOCK);
  padded.set(k);

  const ipad = new Uint8Array(BLOCK);
  const opad = new Uint8Array(BLOCK);
  for (let i = 0; i < BLOCK; i++) {
    ipad[i] = padded[i] ^ 0x36;
    opad[i] = padded[i] ^ 0x5c;
  }

  const inner = new Uint8Array(BLOCK + data.length);
  inner.set(ipad, 0);
  inner.set(data, BLOCK);
  const innerHash = sha256(inner);

  const outer = new Uint8Array(BLOCK + SHA256_SIZE);
  outer.set(opad, 0);
  outer.set(innerHash, BLOCK);
  return sha256(outer);
}

export function hmacSha256Verify(key, data, mac) {
  const computed = hmacSha256(key, data);
  if (computed.length !== mac.length) return false;
  let r = 0;
  for (let i = 0; i < computed.length; i++) r |= computed[i] ^ mac[i];
  return r === 0;
}

// =============================================================================
// HKDF
// =============================================================================

export function hkdf(ikm, salt, info, length) {
  ensureInit();
  if (!(ikm instanceof Uint8Array)) throw new CryptoError('IKM must be Uint8Array', CryptoErrorCode.INVALID_INPUT);

  const ikmPtr = walloc(ikm.length);
  const saltPtr = salt ? walloc(salt.length) : 0;
  const infoPtr = info ? walloc(info.length) : 0;
  const okmPtr = walloc(length);

  try {
    wwrite(ikmPtr, ikm);
    if (salt && salt.length > 0) wwrite(saltPtr, salt);
    if (info && info.length > 0) wwrite(infoPtr, info);

    _module._wasm_crypto_hkdf(
      ikmPtr, ikm.length,
      saltPtr, salt ? salt.length : 0,
      infoPtr, info ? info.length : 0,
      okmPtr, length
    );
    return wread(okmPtr, length);
  } finally {
    wfree(ikmPtr);
    if (saltPtr) wfree(saltPtr);
    if (infoPtr) wfree(infoPtr);
    wfree(okmPtr);
  }
}

// =============================================================================
// IV Tracking
// =============================================================================

const _ivTracker = new Map();

function trackIV(key, iv) {
  const kh = bytesToHex(key);
  if (!_ivTracker.has(kh)) _ivTracker.set(kh, new Set());
  const ivSet = _ivTracker.get(kh);
  const ih = bytesToHex(iv);
  if (ivSet.has(ih) && typeof console !== 'undefined' && console.warn) {
    console.warn(`[SECURITY] IV reuse detected for key ${kh.substring(0, 8)}...`);
  }
  ivSet.add(ih);
}

export function clearIVTracking(key) {
  _ivTracker.delete(bytesToHex(key));
}

export function clearAllIVTracking() {
  _ivTracker.clear();
}

// =============================================================================
// Nonce Generation and Derivation
// =============================================================================

export function generateNonceStart() {
  return getRandomBytes(NONCE_SIZE);
}

export function deriveNonce(nonceStart, recordIndex) {
  if (!(nonceStart instanceof Uint8Array) || nonceStart.length !== NONCE_SIZE) {
    throw new CryptoError('nonceStart must be a 12-byte Uint8Array', CryptoErrorCode.INVALID_INPUT);
  }

  const result = new Uint8Array(nonceStart);
  let idx = typeof recordIndex === 'bigint' ? recordIndex : BigInt(recordIndex);

  let carry = 0n;
  for (let i = 11; i >= 0; i--) {
    const sum = BigInt(result[i]) + (idx & 0xFFn) + carry;
    result[i] = Number(sum & 0xFFn);
    carry = sum >> 8n;
    idx >>= 8n;
  }
  return result;
}

// =============================================================================
// AES-256-CTR Encryption (In-Place)
// =============================================================================

function validateInputs(data, key, iv) {
  if (!(data instanceof Uint8Array)) throw new CryptoError('Data must be Uint8Array', CryptoErrorCode.INVALID_INPUT);
  if (!(key instanceof Uint8Array)) throw new CryptoError('Key must be Uint8Array', CryptoErrorCode.INVALID_KEY);
  if (!(iv instanceof Uint8Array)) throw new CryptoError('IV must be Uint8Array', CryptoErrorCode.INVALID_IV);
  if (key.length !== KEY_SIZE) throw new CryptoError(`Key must be ${KEY_SIZE} bytes, got ${key.length}`, CryptoErrorCode.INVALID_KEY);
  if (iv.length !== IV_SIZE) throw new CryptoError(`IV must be ${IV_SIZE} bytes, got ${iv.length}`, CryptoErrorCode.INVALID_IV);
}

export function encryptBytes(data, key, iv) {
  ensureInit();
  validateInputs(data, key, iv);
  if (data.length === 0) return;

  trackIV(key, iv);

  const keyPtr = walloc(KEY_SIZE);
  const ivPtr = walloc(IV_SIZE);
  const dataPtr = walloc(data.length);
  try {
    wwrite(keyPtr, key);
    wwrite(ivPtr, iv);
    wwrite(dataPtr, data);
    const r = _module._wasm_crypto_encrypt_bytes(keyPtr, ivPtr, dataPtr, data.length);
    if (r !== 0) throw new CryptoError('Encryption failed', CryptoErrorCode.WASM_ERROR);
    data.set(wread(dataPtr, data.length));
  } finally {
    wfreeSecure(keyPtr, KEY_SIZE);
    wfree(ivPtr);
    wfree(dataPtr);
  }
}

export function decryptBytes(data, key, iv) {
  ensureInit();
  validateInputs(data, key, iv);
  if (data.length === 0) return;

  const keyPtr = walloc(KEY_SIZE);
  const ivPtr = walloc(IV_SIZE);
  const dataPtr = walloc(data.length);
  try {
    wwrite(keyPtr, key);
    wwrite(ivPtr, iv);
    wwrite(dataPtr, data);
    const r = _module._wasm_crypto_decrypt_bytes(keyPtr, ivPtr, dataPtr, data.length);
    if (r !== 0) throw new CryptoError('Decryption failed', CryptoErrorCode.WASM_ERROR);
    data.set(wread(dataPtr, data.length));
  } finally {
    wfreeSecure(keyPtr, KEY_SIZE);
    wfree(ivPtr);
    wfree(dataPtr);
  }
}

// =============================================================================
// Non-Destructive Encryption
// =============================================================================

export function encryptBytesCopy(plaintext, key, iv) {
  if (!(plaintext instanceof Uint8Array)) throw new CryptoError('Data must be Uint8Array', CryptoErrorCode.INVALID_INPUT);
  if (!iv) iv = getRandomBytes(IV_SIZE);
  const ciphertext = new Uint8Array(plaintext);
  encryptBytes(ciphertext, key, iv);
  return { ciphertext, iv };
}

export function decryptBytesCopy(ciphertext, key, iv) {
  const plaintext = new Uint8Array(ciphertext);
  decryptBytes(plaintext, key, iv);
  return plaintext;
}

// =============================================================================
// Authenticated Encryption (AES-256-CTR + HMAC-SHA256)
// =============================================================================

export function encryptAuthenticated(plaintext, key, aad) {
  const iv = getRandomBytes(IV_SIZE);
  const ct = new Uint8Array(plaintext);
  encryptBytes(ct, key, iv);

  const macLen = IV_SIZE + ct.length + (aad ? aad.length : 0);
  const macInput = new Uint8Array(macLen);
  macInput.set(iv, 0);
  macInput.set(ct, IV_SIZE);
  if (aad) macInput.set(aad, IV_SIZE + ct.length);
  const mac = hmacSha256(key, macInput);

  const out = new Uint8Array(IV_SIZE + ct.length + HMAC_SIZE);
  out.set(iv, 0);
  out.set(ct, IV_SIZE);
  out.set(mac, IV_SIZE + ct.length);
  return out;
}

export function decryptAuthenticated(message, key, aad) {
  if (message.length < IV_SIZE + HMAC_SIZE) {
    throw new CryptoError('Message too short', CryptoErrorCode.INVALID_INPUT);
  }
  const iv = message.slice(0, IV_SIZE);
  const ct = message.slice(IV_SIZE, message.length - HMAC_SIZE);
  const mac = message.slice(message.length - HMAC_SIZE);

  const macLen = IV_SIZE + ct.length + (aad ? aad.length : 0);
  const macInput = new Uint8Array(macLen);
  macInput.set(iv, 0);
  macInput.set(ct, IV_SIZE);
  if (aad) macInput.set(aad, IV_SIZE + ct.length);

  if (!hmacSha256Verify(key, macInput, mac)) {
    throw new CryptoError('MAC verification failed', CryptoErrorCode.AUTHENTICATION_FAILED);
  }

  const pt = new Uint8Array(ct);
  decryptBytes(pt, key, iv);
  return pt;
}

// =============================================================================
// X25519 Key Exchange
// =============================================================================

export function x25519GenerateKeyPair(existingPrivateKey) {
  ensureInit();
  const privPtr = walloc(X25519_PRIVATE_KEY_SIZE);
  const pubPtr = walloc(X25519_PUBLIC_KEY_SIZE);
  try {
    if (existingPrivateKey) wwrite(privPtr, existingPrivateKey);
    const r = _module._wasm_crypto_x25519_generate_keypair(privPtr, pubPtr);
    if (r !== 0) throw new CryptoError('X25519 key generation failed', CryptoErrorCode.KEY_GENERATION_FAILED);
    return {
      privateKey: wread(privPtr, X25519_PRIVATE_KEY_SIZE),
      publicKey: wread(pubPtr, X25519_PUBLIC_KEY_SIZE),
    };
  } finally {
    wfreeSecure(privPtr, X25519_PRIVATE_KEY_SIZE);
    wfree(pubPtr);
  }
}

export function x25519SharedSecret(privateKey, publicKey) {
  ensureInit();
  const privPtr = walloc(X25519_PRIVATE_KEY_SIZE);
  const pubPtr = walloc(X25519_PUBLIC_KEY_SIZE);
  const secPtr = walloc(32);
  try {
    wwrite(privPtr, privateKey);
    wwrite(pubPtr, publicKey);
    const r = _module._wasm_crypto_x25519_shared_secret(privPtr, pubPtr, secPtr);
    if (r !== 0) throw new CryptoError('X25519 ECDH failed', CryptoErrorCode.ECDH_FAILED);
    return wread(secPtr, 32);
  } finally {
    wfreeSecure(privPtr, X25519_PRIVATE_KEY_SIZE);
    wfree(pubPtr);
    wfreeSecure(secPtr, 32);
  }
}

export function x25519DeriveKey(sharedSecret, context) {
  const info = context ? new TextEncoder().encode(context) : null;
  return hkdf(sharedSecret, null, info, KEY_SIZE);
}

// =============================================================================
// secp256k1 Key Exchange & Signatures
// =============================================================================

export function secp256k1GenerateKeyPair() {
  ensureInit();
  const privPtr = walloc(SECP256K1_PRIVATE_KEY_SIZE);
  const pubPtr = walloc(SECP256K1_PUBLIC_KEY_SIZE);
  try {
    const r = _module._wasm_crypto_secp256k1_generate_keypair(privPtr, pubPtr);
    if (r !== 0) throw new CryptoError('secp256k1 key generation failed', CryptoErrorCode.KEY_GENERATION_FAILED);
    return {
      privateKey: wread(privPtr, SECP256K1_PRIVATE_KEY_SIZE),
      publicKey: wread(pubPtr, SECP256K1_PUBLIC_KEY_SIZE),
    };
  } finally {
    wfreeSecure(privPtr, SECP256K1_PRIVATE_KEY_SIZE);
    wfree(pubPtr);
  }
}

export function secp256k1SharedSecret(privateKey, publicKey) {
  ensureInit();
  const privPtr = walloc(SECP256K1_PRIVATE_KEY_SIZE);
  const pubPtr = walloc(publicKey.length);
  const secPtr = walloc(32);
  try {
    wwrite(privPtr, privateKey);
    wwrite(pubPtr, publicKey);
    const r = _module._wasm_crypto_secp256k1_shared_secret(privPtr, pubPtr, publicKey.length, secPtr);
    if (r !== 0) throw new CryptoError('secp256k1 ECDH failed', CryptoErrorCode.ECDH_FAILED);
    return wread(secPtr, 32);
  } finally {
    wfreeSecure(privPtr, SECP256K1_PRIVATE_KEY_SIZE);
    wfree(pubPtr);
    wfreeSecure(secPtr, 32);
  }
}

export function secp256k1DeriveKey(sharedSecret, context) {
  const info = context ? new TextEncoder().encode(context) : null;
  return hkdf(sharedSecret, null, info, KEY_SIZE);
}

export function secp256k1Sign(privateKey, data) {
  ensureInit();
  const privPtr = walloc(SECP256K1_PRIVATE_KEY_SIZE);
  const dataPtr = walloc(data.length);
  const sigPtr = walloc(72);
  const sizePtr = walloc(4);
  try {
    wwrite(privPtr, privateKey);
    wwrite(dataPtr, data);
    _module.setValue(sizePtr, 0, 'i32');
    const r = _module._wasm_crypto_secp256k1_sign(privPtr, dataPtr, data.length, sigPtr, sizePtr);
    if (r !== 0) throw new CryptoError('secp256k1 sign failed', CryptoErrorCode.SIGN_FAILED);
    const sigSize = _module.getValue(sizePtr, 'i32');
    return wread(sigPtr, sigSize);
  } finally {
    wfreeSecure(privPtr, SECP256K1_PRIVATE_KEY_SIZE);
    wfree(dataPtr);
    wfree(sigPtr);
    wfree(sizePtr);
  }
}

export function secp256k1Verify(publicKey, data, signature) {
  ensureInit();
  const pubPtr = walloc(publicKey.length);
  const dataPtr = walloc(data.length);
  const sigPtr = walloc(signature.length);
  try {
    wwrite(pubPtr, publicKey);
    wwrite(dataPtr, data);
    wwrite(sigPtr, signature);
    return _module._wasm_crypto_secp256k1_verify(
      pubPtr, publicKey.length, dataPtr, data.length, sigPtr, signature.length
    ) === 0;
  } finally {
    wfree(pubPtr);
    wfree(dataPtr);
    wfree(sigPtr);
  }
}

// =============================================================================
// P-256 Key Exchange & Signatures (Web Crypto)
// =============================================================================

const subtle = globalThis.crypto?.subtle;

export async function p256GenerateKeyPairAsync() {
  const kp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  return {
    privateKey: new Uint8Array(await subtle.exportKey('pkcs8', kp.privateKey)),
    publicKey: new Uint8Array(await subtle.exportKey('raw', kp.publicKey)),
  };
}

export async function p256SharedSecretAsync(privateKeyPKCS8, publicKeyRaw) {
  const priv = await subtle.importKey('pkcs8', privateKeyPKCS8, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const pub = await subtle.importKey('raw', publicKeyRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  return new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: pub }, priv, 256));
}

export function p256DeriveKey(sharedSecret, context) {
  const info = context ? new TextEncoder().encode(context) : null;
  return hkdf(sharedSecret, null, info, KEY_SIZE);
}

export async function p256SignAsync(privateKeyPKCS8, data) {
  const key = await subtle.importKey('pkcs8', privateKeyPKCS8, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, data));
}

export async function p256VerifyAsync(publicKeyRaw, data, signature) {
  const key = await subtle.importKey('raw', publicKeyRaw, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  return subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, signature, data);
}

// =============================================================================
// P-384 Key Exchange & Signatures (Web Crypto)
// =============================================================================

export async function p384GenerateKeyPairAsync() {
  const kp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-384' }, true, ['deriveBits']);
  return {
    privateKey: new Uint8Array(await subtle.exportKey('pkcs8', kp.privateKey)),
    publicKey: new Uint8Array(await subtle.exportKey('raw', kp.publicKey)),
  };
}

export async function p384SharedSecretAsync(privateKeyPKCS8, publicKeyRaw) {
  const priv = await subtle.importKey('pkcs8', privateKeyPKCS8, { name: 'ECDH', namedCurve: 'P-384' }, false, ['deriveBits']);
  const pub = await subtle.importKey('raw', publicKeyRaw, { name: 'ECDH', namedCurve: 'P-384' }, false, []);
  return new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: pub }, priv, 384));
}

export function p384DeriveKey(sharedSecret, context) {
  const info = context ? new TextEncoder().encode(context) : null;
  return hkdf(sharedSecret, null, info, KEY_SIZE);
}

export async function p384SignAsync(privateKeyPKCS8, data) {
  const key = await subtle.importKey('pkcs8', privateKeyPKCS8, { name: 'ECDSA', namedCurve: 'P-384' }, false, ['sign']);
  return new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: 'SHA-384' }, key, data));
}

export async function p384VerifyAsync(publicKeyRaw, data, signature) {
  const key = await subtle.importKey('raw', publicKeyRaw, { name: 'ECDSA', namedCurve: 'P-384' }, false, ['verify']);
  return subtle.verify({ name: 'ECDSA', hash: 'SHA-384' }, key, signature, data);
}

// =============================================================================
// Ed25519 Signatures
// =============================================================================

export function ed25519GenerateKeyPair() {
  ensureInit();
  const privPtr = walloc(ED25519_PRIVATE_KEY_SIZE);
  const pubPtr = walloc(ED25519_PUBLIC_KEY_SIZE);
  try {
    const r = _module._wasm_crypto_ed25519_generate_keypair(privPtr, pubPtr);
    if (r !== 0) throw new CryptoError('Ed25519 key generation failed', CryptoErrorCode.KEY_GENERATION_FAILED);
    return {
      privateKey: wread(privPtr, ED25519_PRIVATE_KEY_SIZE),
      publicKey: wread(pubPtr, ED25519_PUBLIC_KEY_SIZE),
    };
  } finally {
    wfreeSecure(privPtr, ED25519_PRIVATE_KEY_SIZE);
    wfree(pubPtr);
  }
}

export function ed25519Sign(privateKey, data) {
  ensureInit();
  const privPtr = walloc(ED25519_PRIVATE_KEY_SIZE);
  const dataPtr = walloc(data.length);
  const sigPtr = walloc(ED25519_SIGNATURE_SIZE);
  try {
    wwrite(privPtr, privateKey);
    wwrite(dataPtr, data);
    const r = _module._wasm_crypto_ed25519_sign(privPtr, dataPtr, data.length, sigPtr);
    if (r !== 0) throw new CryptoError('Ed25519 sign failed', CryptoErrorCode.SIGN_FAILED);
    return wread(sigPtr, ED25519_SIGNATURE_SIZE);
  } finally {
    wfreeSecure(privPtr, ED25519_PRIVATE_KEY_SIZE);
    wfree(dataPtr);
    wfree(sigPtr);
  }
}

export function ed25519Verify(publicKey, data, signature) {
  ensureInit();
  const pubPtr = walloc(ED25519_PUBLIC_KEY_SIZE);
  const dataPtr = walloc(data.length);
  const sigPtr = walloc(ED25519_SIGNATURE_SIZE);
  try {
    wwrite(pubPtr, publicKey);
    wwrite(dataPtr, data);
    wwrite(sigPtr, signature);
    return _module._wasm_crypto_ed25519_verify(pubPtr, dataPtr, data.length, sigPtr) === 0;
  } finally {
    wfree(pubPtr);
    wfree(dataPtr);
    wfree(sigPtr);
  }
}

// =============================================================================
// Header Utilities
// =============================================================================

export function computeKeyId(publicKey) {
  return sha256(publicKey).slice(0, 8);
}

export function createEncryptionHeader(opts) {
  return {
    version: 2,
    algorithm: opts.algorithm || 'x25519',
    senderPublicKey: opts.senderPublicKey ? new Uint8Array(opts.senderPublicKey) : null,
    recipientKeyId: opts.recipientKeyId ? new Uint8Array(opts.recipientKeyId) : null,
    nonceStart: opts.nonceStart ? new Uint8Array(opts.nonceStart) : generateNonceStart(),
    context: opts.context || null,
  };
}

export function encryptionHeaderToJSON(header) {
  return JSON.stringify({
    version: header.version,
    algorithm: header.algorithm,
    senderPublicKey: bytesToHex(header.senderPublicKey),
    recipientKeyId: bytesToHex(header.recipientKeyId),
    nonceStart: bytesToHex(header.nonceStart),
    context: header.context,
  });
}

export function encryptionHeaderFromJSON(json) {
  const obj = typeof json === 'string' ? JSON.parse(json) : json;
  return {
    version: obj.version,
    algorithm: obj.algorithm,
    senderPublicKey: hexToBytes(obj.senderPublicKey),
    recipientKeyId: hexToBytes(obj.recipientKeyId),
    nonceStart: hexToBytes(obj.nonceStart),
    context: obj.context || null,
  };
}

// =============================================================================
// Schema Parsing (stub)
// =============================================================================

export function parseSchemaForEncryption(schema, rootType) {
  return { rootType, fields: [], enums: {} };
}

// =============================================================================
// Buffer Encryption (stubs - require compiled FlatBuffer schema)
// =============================================================================

export function encryptBuffer() {
  throw new CryptoError('Buffer encryption requires a compiled schema');
}

export function decryptBuffer() {
  throw new CryptoError('Buffer decryption requires a compiled schema');
}

// =============================================================================
// EncryptionContext
// =============================================================================

function _createWasmCtx(key) {
  const keyPtr = walloc(KEY_SIZE);
  try {
    wwrite(keyPtr, key);
    return _module._wasm_crypto_encryption_create(keyPtr, KEY_SIZE);
  } finally {
    wfreeSecure(keyPtr, KEY_SIZE);
  }
}

export class EncryptionContext {
  constructor(key, nonceStart) {
    // Accept hex string
    if (typeof key === 'string') {
      if (!/^[0-9a-fA-F]+$/.test(key)) {
        throw new CryptoError('Invalid hex string for key', CryptoErrorCode.INVALID_KEY);
      }
      if (key.length !== 64) {
        throw new CryptoError(`Hex key must be 64 characters, got ${key.length}`, CryptoErrorCode.INVALID_KEY);
      }
      key = hexToBytes(key);
    }

    if (!(key instanceof Uint8Array) || key.length !== KEY_SIZE) {
      throw new CryptoError(`Key must be Uint8Array, expected ${KEY_SIZE} bytes, got ${key?.length || 0}`, CryptoErrorCode.INVALID_KEY);
    }

    this._key = new Uint8Array(key);
    this._nonceStart = nonceStart ? new Uint8Array(nonceStart) : null;
    this._wasmCtx = null;
    this._algorithm = null;
    this._context = null;
    this._ephemeralPublicKey = null;
    this._recipientKeyId = null;
    this._recordIndex = 0;

    if (_module) {
      this._wasmCtx = _createWasmCtx(this._key);
    }
  }

  static fromHex(hexKey) {
    return new EncryptionContext(hexKey);
  }

  static forEncryption(recipientPublicKey, options = {}) {
    const algorithm = options.algorithm || 'x25519';
    const context = options.context || null;
    const nonceStart = options.nonceStart || generateNonceStart();

    let ephKP, sharedSecret;

    switch (algorithm) {
      case 'x25519':
        ephKP = x25519GenerateKeyPair();
        sharedSecret = x25519SharedSecret(ephKP.privateKey, recipientPublicKey);
        break;
      case 'secp256k1':
        ephKP = secp256k1GenerateKeyPair();
        sharedSecret = secp256k1SharedSecret(ephKP.privateKey, recipientPublicKey);
        break;
      default:
        throw new CryptoError(`Unsupported algorithm: ${algorithm}. Use x25519 or secp256k1.`, CryptoErrorCode.INVALID_INPUT);
    }

    const info = context ? new TextEncoder().encode(context) : null;
    const symmetricKey = hkdf(sharedSecret, null, info, KEY_SIZE);

    const ctx = new EncryptionContext(symmetricKey, nonceStart);
    ctx._algorithm = algorithm;
    ctx._context = context;
    ctx._ephemeralPublicKey = new Uint8Array(ephKP.publicKey);
    ctx._recipientKeyId = computeKeyId(recipientPublicKey);
    return ctx;
  }

  static forDecryption(recipientPrivateKey, header, context) {
    const algorithm = header.algorithm || 'x25519';
    const senderPublicKey = header.senderPublicKey;
    const nonceStart = header.nonceStart;
    const ctx_str = context || header.context || null;

    let sharedSecret;
    switch (algorithm) {
      case 'x25519':
        sharedSecret = x25519SharedSecret(recipientPrivateKey, senderPublicKey);
        break;
      case 'secp256k1':
        sharedSecret = secp256k1SharedSecret(recipientPrivateKey, senderPublicKey);
        break;
      default:
        throw new CryptoError(`Unsupported algorithm: ${algorithm}`, CryptoErrorCode.INVALID_INPUT);
    }

    const info = ctx_str ? new TextEncoder().encode(ctx_str) : null;
    const symmetricKey = hkdf(sharedSecret, null, info, KEY_SIZE);

    const enc = new EncryptionContext(symmetricKey, nonceStart);
    enc._algorithm = algorithm;
    enc._context = ctx_str;
    return enc;
  }

  isValid() {
    return this._key !== null && this._key.length === KEY_SIZE;
  }

  getKey() { return new Uint8Array(this._key); }
  getNonceStart() { return this._nonceStart ? new Uint8Array(this._nonceStart) : null; }
  getRecordIndex() { return this._recordIndex; }
  setRecordIndex(n) { this._recordIndex = n; }
  nextRecordIndex() { return ++this._recordIndex; }
  getEphemeralPublicKey() { return this._ephemeralPublicKey ? new Uint8Array(this._ephemeralPublicKey) : null; }
  getAlgorithm() { return this._algorithm; }
  getContext() { return this._context; }

  deriveFieldKey(fieldId, recordIndex = 0) {
    ensureInit();
    const keyPtr = walloc(KEY_SIZE);
    try {
      _module._wasm_crypto_derive_field_key(this._wasmCtx, fieldId, keyPtr, recordIndex);
      return wread(keyPtr, KEY_SIZE);
    } finally {
      wfreeSecure(keyPtr, KEY_SIZE);
    }
  }

  deriveFieldNonce(fieldId, recordIndex = 0) {
    if (!this._nonceStart) {
      throw new CryptoError('No nonceStart set');
    }
    const nonce = new Uint8Array(this._nonceStart);
    // XOR fieldId into high bytes for field-level separation
    nonce[0] ^= (fieldId >> 8) & 0xFF;
    nonce[1] ^= fieldId & 0xFF;
    if (recordIndex !== 0) {
      return deriveNonce(nonce, recordIndex);
    }
    return nonce;
  }

  encryptScalar(buffer, offset, length, fieldId, recordIndex = 0) {
    ensureInit();
    if (length === 0) return;

    const keyPtr = walloc(KEY_SIZE);
    const ivPtr = walloc(IV_SIZE);
    const dataPtr = walloc(length);
    try {
      _module._wasm_crypto_derive_field_key(this._wasmCtx, fieldId, keyPtr, recordIndex);
      _module._wasm_crypto_derive_field_iv(this._wasmCtx, fieldId, ivPtr, recordIndex);
      wwrite(dataPtr, buffer.subarray(offset, offset + length));
      _module._wasm_crypto_encrypt_bytes(keyPtr, ivPtr, dataPtr, length);
      buffer.set(wread(dataPtr, length), offset);
    } finally {
      wfreeSecure(keyPtr, KEY_SIZE);
      wfree(ivPtr);
      wfree(dataPtr);
    }
  }

  decryptScalar(buffer, offset, length, fieldId, recordIndex = 0) {
    ensureInit();
    if (length === 0) return;

    const keyPtr = walloc(KEY_SIZE);
    const ivPtr = walloc(IV_SIZE);
    const dataPtr = walloc(length);
    try {
      _module._wasm_crypto_derive_field_key(this._wasmCtx, fieldId, keyPtr, recordIndex);
      _module._wasm_crypto_derive_field_iv(this._wasmCtx, fieldId, ivPtr, recordIndex);
      wwrite(dataPtr, buffer.subarray(offset, offset + length));
      _module._wasm_crypto_decrypt_bytes(keyPtr, ivPtr, dataPtr, length);
      buffer.set(wread(dataPtr, length), offset);
    } finally {
      wfreeSecure(keyPtr, KEY_SIZE);
      wfree(ivPtr);
      wfree(dataPtr);
    }
  }

  getHeader() {
    if (!this._ephemeralPublicKey) {
      throw new CryptoError('No ephemeral key available. Use forEncryption() for ECIES mode.');
    }
    return {
      version: 2,
      algorithm: this._algorithm,
      senderPublicKey: new Uint8Array(this._ephemeralPublicKey),
      recipientKeyId: this._recipientKeyId ? new Uint8Array(this._recipientKeyId) : new Uint8Array(8),
      nonceStart: this._nonceStart ? new Uint8Array(this._nonceStart) : generateNonceStart(),
      context: this._context,
    };
  }

  getHeaderJSON() {
    return encryptionHeaderToJSON(this.getHeader());
  }
}
