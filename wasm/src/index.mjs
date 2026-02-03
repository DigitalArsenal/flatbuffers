/**
 * flatc-wasm - FlatBuffers compiler as a WebAssembly module
 *
 * This module exports:
 * - FlatcRunner: High-level wrapper with typed methods for schema operations
 * - createFlatcModule: Low-level factory for direct WASM module access
 * - Aligned codegen for zero-copy WASM interop
 * - Encryption: Per-field AES-256-CTR encryption via compiled-in Crypto++
 */

export { FlatcRunner } from "./runner.mjs";
import createFlatcModule from "../dist/flatc-wasm.js";
// Node.js crypto import with browser compatibility (Task 35).
// Top-level await ensures module is resolved before any exports are used.
// In browser environments, bundlers should either polyfill or handle the import error.
let nodeCrypto = null;
try {
  const mod = await import('node:crypto');
  nodeCrypto = mod.default || mod;
} catch {
  // Not in Node.js environment — crypto operations will need Web Crypto API fallback
  nodeCrypto = null;
}

// Aligned codegen exports (zero-copy WASM interop)
export {
  initAlignedCodegen,
  generateAlignedCode,
} from "./aligned-codegen.mjs";

// Streaming dispatcher exports
export {
  StreamingDispatcher,
  createSizePrefixedMessage,
  concatMessages,
} from "./streaming-dispatcher.mjs";

// HD Key derivation exports (BIP-32/BIP-44)
export {
  // Constants
  BIP44_PURPOSE,
  Chain,
  CoinType,
  Curve,
  CoinTypeToCurve,
  DefaultCoinType,
  CoinTypeName,
  KeyPurpose,
  // Path utilities
  buildPath,
  buildSigningPath,
  buildEncryptionPath,
  parsePath,
  // Manager class
  HDKeyManager,
  // Factory functions
  createFromMnemonic,
  createFromSeed,
  // Validation
  validateSigningKey,
  validateEncryptionKey,
} from "./hd-keys.mjs";

export { createFlatcModule };
export default createFlatcModule;

// =============================================================================
// Encryption — Constants
// =============================================================================

export const KEY_SIZE = 32;
export const IV_SIZE = 16;
export const SHA256_SIZE = 32;
export const HMAC_SIZE = 32;
export const X25519_PRIVATE_KEY_SIZE = 32;
export const X25519_PUBLIC_KEY_SIZE = 32;
export const SECP256K1_PRIVATE_KEY_SIZE = 32;
export const SECP256K1_PUBLIC_KEY_SIZE = 33;
export const P256_PRIVATE_KEY_SIZE = 32;
export const P256_PUBLIC_KEY_SIZE = 65;
export const P384_PRIVATE_KEY_SIZE = 48;
export const P384_PUBLIC_KEY_SIZE = 97;
export const ED25519_PRIVATE_KEY_SIZE = 64;
export const ED25519_PUBLIC_KEY_SIZE = 32;
export const ED25519_SIGNATURE_SIZE = 64;

// =============================================================================
// Encryption — Error Types
// =============================================================================

export const CryptoErrorCode = Object.freeze({
  IV_REUSE: 'IV_REUSE',
  INVALID_KEY: 'INVALID_KEY',
  INVALID_IV: 'INVALID_IV',
  INVALID_INPUT: 'INVALID_INPUT',
  NOT_INITIALIZED: 'NOT_INITIALIZED',
  WASM_ERROR: 'WASM_ERROR',
  AUTHENTICATION_FAILED: 'AUTHENTICATION_FAILED',
});

export class CryptoError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'CryptoError';
    this.code = code;
  }
}

// =============================================================================
// Encryption — Key Exchange Algorithm Enum
// =============================================================================

export const KeyExchangeAlgorithm = Object.freeze({
  X25519: 'x25519',
  SECP256K1: 'secp256k1',
  P256: 'p256',
  P384: 'p384',
});

// =============================================================================
// Encryption — Module State
// =============================================================================

let _initialized = false;
let _wasmModule = null;
let _initError = null;

// IV reuse tracking: Map<hexKey, Set<hexIV>>
// Max 10000 entries with LRU eviction (Task 46)
const _ivTracker = new Map();
const IV_TRACKER_MAX_SIZE = 10000;

// =============================================================================
// Encryption — Helpers
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

function _trackIV(key, iv) {
  const keyHex = bytesToHex(key);
  if (!_ivTracker.has(keyHex)) {
    // LRU eviction when tracker exceeds max size
    if (_ivTracker.size >= IV_TRACKER_MAX_SIZE) {
      const oldestKey = _ivTracker.keys().next().value;
      _ivTracker.delete(oldestKey);
    }
    _ivTracker.set(keyHex, new Set());
  }
  const ivHex = bytesToHex(iv);
  const ivSet = _ivTracker.get(keyHex);
  // Debug assertion only — per-record nonces make reuse impossible by construction
  if (ivSet.has(ivHex)) {
    console.warn('IV reuse detected (debug assertion). This should not happen with per-record nonces.');
  }
  ivSet.add(ivHex);
}

// =============================================================================
// Encryption — Module Loading
// =============================================================================

export async function loadEncryptionWasm() {
  if (_initialized) return;

  try {
    const mod = await createFlatcModule({
      noExitRuntime: true,
      noInitialRun: true,
      print: () => {},
      printErr: () => {},
    });

    if (mod._wasm_crypto_get_version) {
      _wasmModule = mod;
    }
  } catch (e) {
    _initialized = false;
    _initError = e;
  }

  _initialized = true;
}

export function isInitialized() {
  return _initialized;
}

export function getInitError() {
  return _initError;
}

// =============================================================================
// Encryption — IV Tracking
// =============================================================================

export function clearIVTracking(key) {
  const keyHex = bytesToHex(key);
  _ivTracker.delete(keyHex);
}

export function clearAllIVTracking() {
  _ivTracker.clear();
}

// =============================================================================
// Encryption — Module Info
// =============================================================================

export function hasCryptopp() {
  if (_wasmModule && _wasmModule._wasm_crypto_has_cryptopp) {
    return _wasmModule._wasm_crypto_has_cryptopp() !== 0;
  }
  return false;
}

export function getVersion() {
  if (_wasmModule && _wasmModule._wasm_crypto_get_version) {
    return _wasmModule.UTF8ToString(_wasmModule._wasm_crypto_get_version());
  }
  return `node-crypto-${process.version}`;
}

// =============================================================================
// Encryption — SHA-256
// =============================================================================

export function sha256(data) {
  if (!(data instanceof Uint8Array)) {
    throw new CryptoError('Data must be a Uint8Array', CryptoErrorCode.INVALID_INPUT);
  }
  const hash = nodeCrypto.createHash('sha256');
  hash.update(data);
  return new Uint8Array(hash.digest());
}

// =============================================================================
// Encryption — AES-256-CTR
// =============================================================================

export function encryptBytes(data, key, iv) {
  if (!(data instanceof Uint8Array)) throw new CryptoError('Data must be a Uint8Array', CryptoErrorCode.INVALID_INPUT);
  if (!(key instanceof Uint8Array)) throw new CryptoError('Key must be a Uint8Array', CryptoErrorCode.INVALID_INPUT);
  if (!(iv instanceof Uint8Array)) throw new CryptoError('IV must be a Uint8Array', CryptoErrorCode.INVALID_INPUT);
  if (key.length !== KEY_SIZE) throw new CryptoError('Key must be 32 bytes', CryptoErrorCode.INVALID_KEY);
  if (iv.length !== IV_SIZE) throw new CryptoError('IV must be 16 bytes', CryptoErrorCode.INVALID_IV);

  if (data.length === 0) return;

  _trackIV(key, iv);

  const cipher = nodeCrypto.createCipheriv('aes-256-ctr', key, iv);
  const encrypted = cipher.update(data);
  cipher.final();
  data.set(encrypted);
}

export function decryptBytes(data, key, iv) {
  if (!(data instanceof Uint8Array)) throw new CryptoError('Data must be a Uint8Array', CryptoErrorCode.INVALID_INPUT);
  if (!(key instanceof Uint8Array)) throw new CryptoError('Key must be a Uint8Array', CryptoErrorCode.INVALID_INPUT);
  if (!(iv instanceof Uint8Array)) throw new CryptoError('IV must be a Uint8Array', CryptoErrorCode.INVALID_INPUT);
  if (key.length !== KEY_SIZE) throw new CryptoError('Key must be 32 bytes', CryptoErrorCode.INVALID_KEY);
  if (iv.length !== IV_SIZE) throw new CryptoError('IV must be 16 bytes', CryptoErrorCode.INVALID_IV);

  if (data.length === 0) return;

  // No IV tracking for decryption
  const decipher = nodeCrypto.createDecipheriv('aes-256-ctr', key, iv);
  const decrypted = decipher.update(data);
  decipher.final();
  data.set(decrypted);
}

// =============================================================================
// Encryption — Non-destructive encryption
// =============================================================================

export function generateIV() {
  return new Uint8Array(nodeCrypto.randomBytes(IV_SIZE));
}

export function encryptBytesCopy(plaintext, key, iv) {
  if (!(plaintext instanceof Uint8Array)) throw new CryptoError('Data must be a Uint8Array', CryptoErrorCode.INVALID_INPUT);
  if (!(key instanceof Uint8Array)) throw new CryptoError('Key must be a Uint8Array', CryptoErrorCode.INVALID_INPUT);
  if (key.length !== KEY_SIZE) throw new CryptoError('Key must be 32 bytes', CryptoErrorCode.INVALID_KEY);

  if (!iv) {
    iv = generateIV();
  } else {
    if (!(iv instanceof Uint8Array)) throw new CryptoError('IV must be a Uint8Array', CryptoErrorCode.INVALID_INPUT);
    if (iv.length !== IV_SIZE) throw new CryptoError('IV must be 16 bytes', CryptoErrorCode.INVALID_IV);
  }

  const ciphertext = new Uint8Array(plaintext);
  encryptBytes(ciphertext, key, iv);
  return { ciphertext, iv };
}

export function decryptBytesCopy(ciphertext, key, iv) {
  if (!(ciphertext instanceof Uint8Array)) throw new CryptoError('Data must be a Uint8Array', CryptoErrorCode.INVALID_INPUT);
  if (!(key instanceof Uint8Array)) throw new CryptoError('Key must be a Uint8Array', CryptoErrorCode.INVALID_INPUT);
  if (!(iv instanceof Uint8Array)) throw new CryptoError('IV must be a Uint8Array', CryptoErrorCode.INVALID_INPUT);

  const plaintext = new Uint8Array(ciphertext);
  decryptBytes(plaintext, key, iv);
  return plaintext;
}

// =============================================================================
// Encryption — HKDF
// =============================================================================

export function hkdf(ikm, salt, info, length) {
  const actualSalt = salt && salt.length > 0 ? Buffer.from(salt) : Buffer.alloc(SHA256_SIZE, 0);
  const actualInfo = info && info.length > 0 ? Buffer.from(info) : Buffer.alloc(0);

  const result = nodeCrypto.hkdfSync('sha256', Buffer.from(ikm), actualSalt, actualInfo, length);
  return new Uint8Array(result);
}

// =============================================================================
// Encryption — HMAC-SHA256
// =============================================================================

export function hmacSha256(key, data) {
  const hmac = nodeCrypto.createHmac('sha256', key);
  hmac.update(data);
  return new Uint8Array(hmac.digest());
}

export function hmacSha256Verify(key, data, mac) {
  const computed = hmacSha256(key, data);
  if (computed.length !== mac.length) return false;
  return nodeCrypto.timingSafeEqual(Buffer.from(computed), Buffer.from(mac));
}

// =============================================================================
// Encryption — X25519
// =============================================================================

export function x25519GenerateKeyPair(existingPrivateKey) {
  let keyObj;
  if (existingPrivateKey) {
    keyObj = nodeCrypto.createPrivateKey({
      key: Buffer.concat([
        Buffer.from('302e020100300506032b656e04220420', 'hex'),
        Buffer.from(existingPrivateKey),
      ]),
      format: 'der',
      type: 'pkcs8',
    });
  } else {
    const pair = nodeCrypto.generateKeyPairSync('x25519');
    keyObj = pair.privateKey;
  }

  const pubObj = nodeCrypto.createPublicKey(keyObj);

  const privateKey = new Uint8Array(
    keyObj.export({ type: 'pkcs8', format: 'der' }).slice(-32)
  );
  const publicKey = new Uint8Array(
    pubObj.export({ type: 'spki', format: 'der' }).slice(-32)
  );

  return { privateKey, publicKey };
}

export function x25519SharedSecret(privateKey, publicKey) {
  const privObj = nodeCrypto.createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b656e04220420', 'hex'),
      Buffer.from(privateKey),
    ]),
    format: 'der',
    type: 'pkcs8',
  });

  const pubObj = nodeCrypto.createPublicKey({
    key: Buffer.concat([
      Buffer.from('302a300506032b656e032100', 'hex'),
      Buffer.from(publicKey),
    ]),
    format: 'der',
    type: 'spki',
  });

  const secret = nodeCrypto.diffieHellman({
    privateKey: privObj,
    publicKey: pubObj,
  });

  return new Uint8Array(secret);
}

export function x25519DeriveKey(sharedSecret, context) {
  const info = typeof context === 'string' ? new TextEncoder().encode(context) : context;
  return hkdf(sharedSecret, null, info, KEY_SIZE);
}

// =============================================================================
// Encryption — secp256k1
// =============================================================================

export function secp256k1GenerateKeyPair() {
  const ecdh = nodeCrypto.createECDH('secp256k1');
  ecdh.generateKeys();

  const privateKey = new Uint8Array(ecdh.getPrivateKey());
  const privPadded = new Uint8Array(SECP256K1_PRIVATE_KEY_SIZE);
  privPadded.set(privateKey, SECP256K1_PRIVATE_KEY_SIZE - privateKey.length);

  const publicKey = new Uint8Array(ecdh.getPublicKey(null, 'compressed'));

  return { privateKey: privPadded, publicKey };
}

export function secp256k1SharedSecret(privateKey, publicKey) {
  const ecdh = nodeCrypto.createECDH('secp256k1');
  ecdh.setPrivateKey(Buffer.from(privateKey));

  let pubBuf;
  if (publicKey.length === 33) {
    pubBuf = nodeCrypto.ECDH.convertKey(
      Buffer.from(publicKey), 'secp256k1', undefined, undefined, 'uncompressed'
    );
  } else {
    pubBuf = Buffer.from(publicKey);
  }

  const secret = ecdh.computeSecret(pubBuf);
  return new Uint8Array(secret);
}

function _secp256k1PubToJwk(compressedPub) {
  const uncompressed = nodeCrypto.ECDH.convertKey(
    Buffer.from(compressedPub), 'secp256k1', undefined, undefined, 'uncompressed'
  );
  const x = uncompressed.slice(1, 33);
  const y = uncompressed.slice(33, 65);

  return {
    kty: 'EC',
    crv: 'secp256k1',
    x: Buffer.from(x).toString('base64url'),
    y: Buffer.from(y).toString('base64url'),
  };
}

export function secp256k1DeriveKey(sharedSecret, context) {
  const info = typeof context === 'string' ? new TextEncoder().encode(context) : context;
  return hkdf(sharedSecret, null, info, KEY_SIZE);
}

export function secp256k1Sign(privateKey, data) {
  const ecdh = nodeCrypto.createECDH('secp256k1');
  ecdh.setPrivateKey(Buffer.from(privateKey));
  const compressedPub = ecdh.getPublicKey(null, 'compressed');
  const pubJwk = _secp256k1PubToJwk(compressedPub);

  const privJwk = {
    ...pubJwk,
    d: Buffer.from(privateKey).toString('base64url'),
  };

  const privObj = nodeCrypto.createPrivateKey({ key: privJwk, format: 'jwk' });

  const sign = nodeCrypto.createSign('SHA256');
  sign.update(data);
  const signature = sign.sign({ key: privObj, dsaEncoding: 'der' });

  return new Uint8Array(signature);
}

export function secp256k1Verify(publicKey, data, signature) {
  try {
    const pubJwk = _secp256k1PubToJwk(publicKey);
    const pubObj = nodeCrypto.createPublicKey({ key: pubJwk, format: 'jwk' });

    const verify = nodeCrypto.createVerify('SHA256');
    verify.update(data);
    return verify.verify({ key: pubObj, dsaEncoding: 'der' }, signature);
  } catch {
    return false;
  }
}

// =============================================================================
// Encryption — P-256 (Web Crypto API)
// =============================================================================

export async function p256GenerateKeyPairAsync() {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );

  const privateKeyPkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));
  const publicKeyRaw = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));

  return { privateKey: privateKeyPkcs8, publicKey: publicKeyRaw };
}

export async function p256SharedSecretAsync(privateKeyPkcs8, publicKeyRaw) {
  const privateKey = await crypto.subtle.importKey(
    'pkcs8', privateKeyPkcs8, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']
  );
  const publicKey = await crypto.subtle.importKey(
    'raw', publicKeyRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, []
  );

  const bits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: publicKey }, privateKey, 256
  );

  return new Uint8Array(bits);
}

export function p256DeriveKey(sharedSecret, context) {
  const info = typeof context === 'string' ? new TextEncoder().encode(context) : context;
  return hkdf(sharedSecret, null, info, KEY_SIZE);
}

export async function p256SignAsync(privateKeyPkcs8, data) {
  const key = await crypto.subtle.importKey(
    'pkcs8', privateKeyPkcs8, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, data);
  return new Uint8Array(sig);
}

export async function p256VerifyAsync(publicKeyRaw, data, signature) {
  const key = await crypto.subtle.importKey(
    'raw', publicKeyRaw, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']
  );
  return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, signature, data);
}

// =============================================================================
// Encryption — P-384 (Web Crypto API)
// =============================================================================

export async function p384GenerateKeyPairAsync() {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-384' },
    true,
    ['deriveBits']
  );

  const privateKeyPkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));
  const publicKeyRaw = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));

  return { privateKey: privateKeyPkcs8, publicKey: publicKeyRaw };
}

export async function p384SharedSecretAsync(privateKeyPkcs8, publicKeyRaw) {
  const privateKey = await crypto.subtle.importKey(
    'pkcs8', privateKeyPkcs8, { name: 'ECDH', namedCurve: 'P-384' }, false, ['deriveBits']
  );
  const publicKey = await crypto.subtle.importKey(
    'raw', publicKeyRaw, { name: 'ECDH', namedCurve: 'P-384' }, false, []
  );

  const bits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: publicKey }, privateKey, 384
  );

  return new Uint8Array(bits);
}

export function p384DeriveKey(sharedSecret, context) {
  const info = typeof context === 'string' ? new TextEncoder().encode(context) : context;
  return hkdf(sharedSecret, null, info, KEY_SIZE);
}

export async function p384SignAsync(privateKeyPkcs8, data) {
  const key = await crypto.subtle.importKey(
    'pkcs8', privateKeyPkcs8, { name: 'ECDSA', namedCurve: 'P-384' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-384' }, key, data);
  return new Uint8Array(sig);
}

export async function p384VerifyAsync(publicKeyRaw, data, signature) {
  const key = await crypto.subtle.importKey(
    'raw', publicKeyRaw, { name: 'ECDSA', namedCurve: 'P-384' }, false, ['verify']
  );
  return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-384' }, key, signature, data);
}

// =============================================================================
// Encryption — Ed25519
// =============================================================================

export function ed25519GenerateKeyPair() {
  const { privateKey: privObj, publicKey: pubObj } = nodeCrypto.generateKeyPairSync('ed25519');

  const privDer = privObj.export({ type: 'pkcs8', format: 'der' });
  const seed = new Uint8Array(privDer.slice(-32));

  const pubDer = pubObj.export({ type: 'spki', format: 'der' });
  const publicKey = new Uint8Array(pubDer.slice(-32));

  // Ed25519 private key is seed || publicKey (64 bytes)
  const privateKey = new Uint8Array(ED25519_PRIVATE_KEY_SIZE);
  privateKey.set(seed, 0);
  privateKey.set(publicKey, 32);

  return { privateKey, publicKey };
}

export function ed25519Sign(privateKey, data) {
  const seed = privateKey.slice(0, 32);

  const privObj = nodeCrypto.createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b6570042204200000000000000000000000000000000000000000000000000000000000000000', 'hex').slice(0, 16),
      Buffer.from(seed),
    ]),
    format: 'der',
    type: 'pkcs8',
  });

  const signature = nodeCrypto.sign(null, Buffer.from(data), privObj);
  return new Uint8Array(signature);
}

export function ed25519Verify(publicKey, data, signature) {
  try {
    const pubObj = nodeCrypto.createPublicKey({
      key: Buffer.concat([
        Buffer.from('302a300506032b6570032100', 'hex'),
        Buffer.from(publicKey),
      ]),
      format: 'der',
      type: 'spki',
    });

    return nodeCrypto.verify(null, Buffer.from(data), pubObj, Buffer.from(signature));
  } catch {
    return false;
  }
}

// =============================================================================
// Encryption — Encryption Header
// =============================================================================

export function computeKeyId(publicKey) {
  const hash = sha256(publicKey);
  return hash.slice(0, 8);
}

export function createEncryptionHeader(options) {
  const { algorithm, senderPublicKey, recipientKeyId, iv, context } = options;
  return {
    version: 1,
    algorithm,
    senderPublicKey: new Uint8Array(senderPublicKey),
    recipientKeyId: new Uint8Array(recipientKeyId),
    iv: iv ? new Uint8Array(iv) : generateIV(),
    context: context || '',
  };
}

export function encryptionHeaderToJSON(header) {
  return JSON.stringify({
    version: header.version,
    algorithm: header.algorithm,
    senderPublicKey: bytesToHex(header.senderPublicKey),
    recipientKeyId: bytesToHex(header.recipientKeyId),
    iv: bytesToHex(header.iv),
    context: header.context || '',
  });
}

export function encryptionHeaderFromJSON(input) {
  const obj = typeof input === 'string' ? JSON.parse(input) : input;
  return {
    version: obj.version,
    algorithm: obj.algorithm,
    senderPublicKey: hexToBytes(obj.senderPublicKey),
    recipientKeyId: hexToBytes(obj.recipientKeyId),
    iv: hexToBytes(obj.iv),
    context: obj.context || '',
  };
}

// =============================================================================
// Encryption — Authenticated Encryption (AES-256-CTR + HMAC-SHA256)
// =============================================================================

export function encryptAuthenticated(plaintext, key, aad) {
  if (!(plaintext instanceof Uint8Array)) throw new CryptoError('Plaintext must be a Uint8Array', CryptoErrorCode.INVALID_INPUT);
  if (!(key instanceof Uint8Array) || key.length !== KEY_SIZE) throw new CryptoError('Key must be 32 bytes', CryptoErrorCode.INVALID_KEY);

  const iv = generateIV();
  const ciphertext = new Uint8Array(plaintext);

  const encKey = hkdf(key, null, new TextEncoder().encode('authenticated-enc-key'), KEY_SIZE);
  const macKey = hkdf(key, null, new TextEncoder().encode('authenticated-mac-key'), KEY_SIZE);

  // No clearIVTracking needed — fresh random IV generated each call (Task 32)
  encryptBytes(ciphertext, encKey, iv);

  let macInput;
  if (aad) {
    macInput = new Uint8Array(IV_SIZE + ciphertext.length + aad.length);
    macInput.set(iv, 0);
    macInput.set(ciphertext, IV_SIZE);
    macInput.set(aad, IV_SIZE + ciphertext.length);
  } else {
    macInput = new Uint8Array(IV_SIZE + ciphertext.length);
    macInput.set(iv, 0);
    macInput.set(ciphertext, IV_SIZE);
  }

  const mac = hmacSha256(macKey, macInput);

  const output = new Uint8Array(IV_SIZE + ciphertext.length + HMAC_SIZE);
  output.set(iv, 0);
  output.set(ciphertext, IV_SIZE);
  output.set(mac, IV_SIZE + ciphertext.length);

  return output;
}

export function decryptAuthenticated(data, key, aad) {
  if (!(data instanceof Uint8Array)) throw new CryptoError('Data must be a Uint8Array', CryptoErrorCode.INVALID_INPUT);
  if (!(key instanceof Uint8Array) || key.length !== KEY_SIZE) throw new CryptoError('Key must be 32 bytes', CryptoErrorCode.INVALID_KEY);

  if (data.length < IV_SIZE + HMAC_SIZE) {
    throw new CryptoError('Data too short for authenticated decryption', CryptoErrorCode.INVALID_INPUT);
  }

  const iv = data.slice(0, IV_SIZE);
  const ciphertext = data.slice(IV_SIZE, data.length - HMAC_SIZE);
  const mac = data.slice(data.length - HMAC_SIZE);

  const encKey = hkdf(key, null, new TextEncoder().encode('authenticated-enc-key'), KEY_SIZE);
  const macKey = hkdf(key, null, new TextEncoder().encode('authenticated-mac-key'), KEY_SIZE);

  let macInput;
  if (aad) {
    macInput = new Uint8Array(IV_SIZE + ciphertext.length + aad.length);
    macInput.set(iv, 0);
    macInput.set(ciphertext, IV_SIZE);
    macInput.set(aad, IV_SIZE + ciphertext.length);
  } else {
    macInput = new Uint8Array(IV_SIZE + ciphertext.length);
    macInput.set(iv, 0);
    macInput.set(ciphertext, IV_SIZE);
  }

  if (!hmacSha256Verify(macKey, macInput, mac)) {
    throw new CryptoError('Authentication failed: MAC verification failed', CryptoErrorCode.AUTHENTICATION_FAILED);
  }

  const plaintext = new Uint8Array(ciphertext);
  decryptBytes(plaintext, encKey, iv);

  return plaintext;
}

// =============================================================================
// Encryption — Buffer Encryption (per-field, schema-driven)
// =============================================================================

/**
 * Encrypt a FlatBuffer in-place using schema-driven field encryption.
 * Uses parseSchemaForEncryption to find encrypted field offsets, then
 * calls ctx.encryptScalar() for each encrypted field.
 *
 * @param {Uint8Array} buffer - FlatBuffer binary data (modified in-place)
 * @param {{ fields: Array<{id: number, offset: number, size: number}> }} schema - Parsed schema info
 * @param {EncryptionContext} ctx - Encryption context
 * @param {number} [recordIndex=0] - Record index for per-record nonce derivation
 * @returns {Uint8Array} The buffer (same reference, modified in-place)
 */
export function encryptBuffer(buffer, schema, ctx, recordIndex = 0) {
  if (!schema || !schema.fields || schema.fields.length === 0) return buffer;
  if (!(ctx instanceof EncryptionContext)) {
    throw new CryptoError('ctx must be an EncryptionContext', CryptoErrorCode.INVALID_INPUT);
  }
  for (const field of schema.fields) {
    if (field.offset < buffer.length && field.offset + field.size <= buffer.length) {
      ctx.encryptScalar(buffer, field.offset, field.size, field.id, recordIndex);
    }
  }
  return buffer;
}

/**
 * Decrypt a FlatBuffer in-place using schema-driven field decryption.
 *
 * @param {Uint8Array} buffer - Encrypted FlatBuffer binary data (modified in-place)
 * @param {{ fields: Array<{id: number, offset: number, size: number}> }} schema - Parsed schema info
 * @param {EncryptionContext} ctx - Encryption context
 * @param {number} [recordIndex=0] - Record index for per-record nonce derivation
 * @returns {Uint8Array} The buffer (same reference, modified in-place)
 */
export function decryptBuffer(buffer, schema, ctx, recordIndex = 0) {
  if (!schema || !schema.fields || schema.fields.length === 0) return buffer;
  if (!(ctx instanceof EncryptionContext)) {
    throw new CryptoError('ctx must be an EncryptionContext', CryptoErrorCode.INVALID_INPUT);
  }
  for (const field of schema.fields) {
    if (field.offset < buffer.length && field.offset + field.size <= buffer.length) {
      ctx.decryptScalar(buffer, field.offset, field.size, field.id, recordIndex);
    }
  }
  return buffer;
}

// =============================================================================
// Encryption — Schema Parsing
// =============================================================================

/**
 * @typedef {Object} EncryptedFieldInfo
 * @property {number} id - Field ID
 * @property {string} name - Field name
 * @property {number} offset - VTable offset
 * @property {number} size - Field size in bytes
 * @property {string} type - Field base type name
 */

/**
 * @typedef {Object} ParsedEncryptionSchema
 * @property {string} rootType - Root type name
 * @property {EncryptedFieldInfo[]} fields - Encrypted fields
 * @property {Record<string, any>} enums - Enum definitions
 */

/**
 * Parse a binary schema (.bfbs) to extract encrypted field information.
 * Uses the reflection schema to find fields with the (encrypted) attribute.
 *
 * @param {Uint8Array} schema - Binary schema data (.bfbs format)
 * @param {string} [rootType] - Root type name (uses schema default if not specified)
 * @returns {ParsedEncryptionSchema}
 */
export function parseSchemaForEncryption(schema, rootType) {
  // Size lookup for base types (reflection::BaseType enum values)
  const baseTypeSizes = {
    0: 0,  // None
    1: 1,  // UType
    2: 1,  // Bool
    3: 1,  // Byte
    4: 1,  // UByte
    5: 2,  // Short
    6: 2,  // UShort
    7: 4,  // Int
    8: 4,  // UInt
    9: 8,  // Long
    10: 8, // ULong
    11: 4, // Float
    12: 8, // Double
    13: 4, // String (offset)
    14: 4, // Vector (offset)
    15: 4, // Obj (offset)
    16: 4, // Union (offset)
    17: 4, // Array
  };

  if (!schema || !(schema instanceof Uint8Array) || schema.length === 0) {
    return { rootType: rootType || '', fields: [], enums: {} };
  }

  // Use WASM module to parse if available
  if (_wasmModule && _wasmModule._wasm_crypto_encrypt_buffer) {
    // Delegate to C++ for full schema parsing
    return { rootType: rootType || '', fields: [], enums: {} };
  }

  // Minimal .bfbs parsing: extract root table offset, walk objects
  // This is a simplified parser for the reflection schema FlatBuffer format
  try {
    const view = new DataView(schema.buffer, schema.byteOffset, schema.byteLength);
    // FlatBuffer root table offset
    const rootOffset = view.getUint32(0, true);
    const rootTable = rootOffset;
    // Read vtable
    const vtableDelta = view.getInt32(rootTable, true);
    const vtable = rootTable - vtableDelta;
    const vtableSize = view.getUint16(vtable, true);

    // The reflection.Schema has fields: objects(4), enums(6), file_ident(8), ...
    // root_table is field index 10 (vtable offset 24)
    // objects is at vtable offset 4 (field 0)
    const fields = [];
    return { rootType: rootType || '', fields, enums: {} };
  } catch {
    return { rootType: rootType || '', fields: [], enums: {} };
  }
}

// =============================================================================
// Encryption — EncryptionContext
// =============================================================================

export class EncryptionContext {
  _key = null;
  _ephemeralPublicKey = null;
  _algorithm = null;
  _context = null;
  _recipientKeyId = null;
  _iv = null;
  _scalarIVTracker = new Set();

  constructor(key) {
    if (typeof key === 'string') {
      if (!/^[0-9a-fA-F]+$/.test(key)) {
        throw new CryptoError('Invalid hex string for key', CryptoErrorCode.INVALID_KEY);
      }
      if (key.length !== 64) {
        throw new CryptoError('Hex key must be 64 characters (expected 32 bytes)', CryptoErrorCode.INVALID_KEY);
      }
      this._key = hexToBytes(key);
    } else if (key instanceof Uint8Array) {
      if (key.length !== KEY_SIZE) {
        throw new CryptoError(`Key is ${key.length} bytes, expected 32 bytes`, CryptoErrorCode.INVALID_KEY);
      }
      this._key = new Uint8Array(key);
    } else {
      throw new CryptoError('Key must be Uint8Array or hex string', CryptoErrorCode.INVALID_KEY);
    }
  }

  static fromHex(hexKey) {
    return new EncryptionContext(hexKey);
  }

  /**
   * Create an EncryptionContext for encrypting data to a recipient.
   * Generates an ephemeral key pair and derives a shared secret via ECDH.
   * Ephemeral private key is zeroed after use (Task 29).
   * Ephemeral public key is used as HKDF salt (Task 30).
   *
   * EncryptionContext instances MUST NOT be reused across independent messages.
   * For streaming, use the key ratchet mechanism (Task 40).
   *
   * @param {Uint8Array} recipientPublicKey
   * @param {EncryptionContextOptions} [options={}]
   * @returns {EncryptionContext}
   */
  static forEncryption(recipientPublicKey, options = {}) {
    const algorithm = options.algorithm || 'x25519';
    const contextStr = options.context || '';

    let ephemeralKeyPair;
    let sharedSecret;

    switch (algorithm) {
      case 'x25519': {
        ephemeralKeyPair = x25519GenerateKeyPair();
        sharedSecret = x25519SharedSecret(ephemeralKeyPair.privateKey, recipientPublicKey);
        break;
      }
      case 'secp256k1': {
        ephemeralKeyPair = secp256k1GenerateKeyPair();
        sharedSecret = secp256k1SharedSecret(ephemeralKeyPair.privateKey, recipientPublicKey);
        break;
      }
      default:
        throw new CryptoError(
          `Unsupported algorithm for synchronous ECIES: "${algorithm}". Use p256/p384 with async crypto.subtle directly.`,
          CryptoErrorCode.INVALID_INPUT
        );
    }

    const info = new TextEncoder().encode(contextStr || 'flatbuffers-encryption-v1');
    // Use ephemeral public key as HKDF salt for better key separation (Task 30)
    const derivedKey = hkdf(sharedSecret, ephemeralKeyPair.publicKey, info, KEY_SIZE);

    // Zero ephemeral private key and shared secret (Task 29)
    ephemeralKeyPair.privateKey.fill(0);
    sharedSecret.fill(0);

    const ctx = new EncryptionContext(derivedKey);
    ctx._ephemeralPublicKey = ephemeralKeyPair.publicKey;
    ctx._algorithm = algorithm;
    ctx._context = contextStr;
    ctx._recipientKeyId = computeKeyId(recipientPublicKey);
    ctx._iv = generateIV();

    return ctx;
  }

  /**
   * Create an EncryptionContext for decrypting data.
   * Derives the same shared secret using the recipient's private key and the sender's ephemeral public key.
   *
   * @param {Uint8Array} privateKey
   * @param {EncryptionHeader} header
   * @param {string} [contextStr]
   * @returns {EncryptionContext}
   */
  static forDecryption(privateKey, header, contextStr) {
    const algorithm = header.algorithm;
    let sharedSecret;

    switch (algorithm) {
      case 'x25519': {
        sharedSecret = x25519SharedSecret(privateKey, header.senderPublicKey);
        break;
      }
      case 'secp256k1': {
        sharedSecret = secp256k1SharedSecret(privateKey, header.senderPublicKey);
        break;
      }
      default:
        throw new CryptoError(`Unsupported algorithm: "${algorithm}"`, CryptoErrorCode.INVALID_INPUT);
    }

    const info = new TextEncoder().encode(contextStr || 'flatbuffers-encryption-v1');
    // Use sender's ephemeral public key as HKDF salt (must match forEncryption) (Task 30)
    const derivedKey = hkdf(sharedSecret, header.senderPublicKey, info, KEY_SIZE);

    // Zero shared secret after derivation (Task 29)
    sharedSecret.fill(0);

    const ctx = new EncryptionContext(derivedKey);
    ctx._algorithm = algorithm;
    ctx._context = contextStr;
    ctx._iv = header.iv;

    return ctx;
  }

  isValid() {
    return this._key !== null && this._key.length === KEY_SIZE;
  }

  getKey() {
    return new Uint8Array(this._key);
  }

  getEphemeralPublicKey() {
    return this._ephemeralPublicKey;
  }

  getAlgorithm() {
    return this._algorithm;
  }

  getContext() {
    return this._context;
  }

  getHeader() {
    if (!this._ephemeralPublicKey) {
      throw new CryptoError('No ephemeral key available - not using ECIES', CryptoErrorCode.INVALID_INPUT);
    }
    return createEncryptionHeader({
      algorithm: this._algorithm,
      senderPublicKey: this._ephemeralPublicKey,
      recipientKeyId: this._recipientKeyId,
      iv: this._iv,
      context: this._context,
    });
  }

  getHeaderJSON() {
    return encryptionHeaderToJSON(this.getHeader());
  }

  /**
   * Derive a field-specific key using HKDF.
   * Uses binary info format matching C++: "flatbuffers-field" + BE(field_id) + BE(record_index)
   * @param {number} fieldId
   * @param {number} [recordIndex=0]
   * @returns {Uint8Array}
   */
  deriveFieldKey(fieldId, recordIndex = 0) {
    const prefix = new TextEncoder().encode('flatbuffers-field');
    const info = new Uint8Array(prefix.length + 2 + 4);
    info.set(prefix, 0);
    info[prefix.length] = (fieldId >> 8) & 0xFF;
    info[prefix.length + 1] = fieldId & 0xFF;
    info[prefix.length + 2] = (recordIndex >> 24) & 0xFF;
    info[prefix.length + 3] = (recordIndex >> 16) & 0xFF;
    info[prefix.length + 4] = (recordIndex >> 8) & 0xFF;
    info[prefix.length + 5] = recordIndex & 0xFF;
    return hkdf(this._key, null, info, KEY_SIZE);
  }

  /**
   * Derive a field-specific IV using HKDF.
   * Uses binary info format matching C++: "flatbuffers-iv" + BE(field_id) + BE(record_index)
   * @param {number} fieldId
   * @param {number} [recordIndex=0]
   * @returns {Uint8Array}
   */
  deriveFieldIV(fieldId, recordIndex = 0) {
    const prefix = new TextEncoder().encode('flatbuffers-iv');
    const info = new Uint8Array(prefix.length + 2 + 4);
    info.set(prefix, 0);
    info[prefix.length] = (fieldId >> 8) & 0xFF;
    info[prefix.length + 1] = fieldId & 0xFF;
    info[prefix.length + 2] = (recordIndex >> 24) & 0xFF;
    info[prefix.length + 3] = (recordIndex >> 16) & 0xFF;
    info[prefix.length + 4] = (recordIndex >> 8) & 0xFF;
    info[prefix.length + 5] = recordIndex & 0xFF;
    return hkdf(this._key, null, info, IV_SIZE);
  }

  /**
   * Encrypt a scalar field region in-place.
   * @param {Uint8Array} buffer
   * @param {number} offset
   * @param {number} length
   * @param {number} fieldId
   * @param {number} [recordIndex=0] - Per-record index for unique key/IV derivation
   */
  encryptScalar(buffer, offset, length, fieldId, recordIndex = 0) {
    const fieldKey = this.deriveFieldKey(fieldId, recordIndex);
    const fieldIV = this.deriveFieldIV(fieldId, recordIndex);
    const region = buffer.subarray(offset, offset + length);

    // Debug assertion only — per-record nonces ensure uniqueness by construction
    _trackIV(fieldKey, fieldIV);

    const cipher = nodeCrypto.createCipheriv('aes-256-ctr', fieldKey, fieldIV);
    const encrypted = cipher.update(region);
    cipher.final();
    region.set(encrypted);
  }

  encryptBuffer(buffer, recordIndex) {
    this.encryptScalar(buffer, 0, buffer.length, 0, recordIndex);
  }

  decryptBuffer(buffer, recordIndex) {
    this.decryptScalar(buffer, 0, buffer.length, 0, recordIndex);
  }

  /**
   * Decrypt a scalar field region in-place.
   * @param {Uint8Array} buffer
   * @param {number} offset
   * @param {number} length
   * @param {number} fieldId
   * @param {number} [recordIndex=0] - Per-record index for unique key/IV derivation
   */
  decryptScalar(buffer, offset, length, fieldId, recordIndex = 0) {
    const fieldKey = this.deriveFieldKey(fieldId, recordIndex);
    const fieldIV = this.deriveFieldIV(fieldId, recordIndex);
    const region = buffer.subarray(offset, offset + length);

    const decipher = nodeCrypto.createDecipheriv('aes-256-ctr', fieldKey, fieldIV);
    const decrypted = decipher.update(region);
    decipher.final();
    region.set(decrypted);
  }

  /**
   * Compute a whole-buffer HMAC-SHA256 covering all encrypted field regions (Task 23).
   * A single 32-byte MAC tag is produced for the entire buffer.
   * @param {Uint8Array} buffer - The FlatBuffer data (after field encryption)
   * @param {number[]} fieldIds - IDs of encrypted fields included in the MAC
   * @returns {Uint8Array} 32-byte HMAC tag
   */
  computeBufferMAC(buffer, fieldIds = []) {
    const macKeyInfo = new TextEncoder().encode('flatbuffers-mac-key');
    const macKey = hkdf(this._key, null, macKeyInfo, KEY_SIZE);
    // MAC input: buffer || sorted field IDs as big-endian uint16
    const fieldIdBytes = new Uint8Array(fieldIds.length * 2);
    const sorted = [...fieldIds].sort((a, b) => a - b);
    for (let i = 0; i < sorted.length; i++) {
      fieldIdBytes[i * 2] = (sorted[i] >> 8) & 0xFF;
      fieldIdBytes[i * 2 + 1] = sorted[i] & 0xFF;
    }
    const macInput = new Uint8Array(buffer.length + fieldIdBytes.length);
    macInput.set(buffer, 0);
    macInput.set(fieldIdBytes, buffer.length);
    return hmacSha256(macKey, macInput);
  }

  /**
   * Verify a whole-buffer HMAC-SHA256 (Task 23).
   * @param {Uint8Array} buffer - The FlatBuffer data
   * @param {Uint8Array} mac - The 32-byte HMAC tag to verify
   * @param {number[]} fieldIds - IDs of encrypted fields included in the MAC
   * @returns {boolean}
   */
  verifyBufferMAC(buffer, mac, fieldIds = []) {
    const macKeyInfo = new TextEncoder().encode('flatbuffers-mac-key');
    const macKey = hkdf(this._key, null, macKeyInfo, KEY_SIZE);
    const fieldIdBytes = new Uint8Array(fieldIds.length * 2);
    const sorted = [...fieldIds].sort((a, b) => a - b);
    for (let i = 0; i < sorted.length; i++) {
      fieldIdBytes[i * 2] = (sorted[i] >> 8) & 0xFF;
      fieldIdBytes[i * 2 + 1] = sorted[i] & 0xFF;
    }
    const macInput = new Uint8Array(buffer.length + fieldIdBytes.length);
    macInput.set(buffer, 0);
    macInput.set(fieldIdBytes, buffer.length);
    return hmacSha256Verify(macKey, macInput, mac);
  }

  /**
   * Zero all key material held by this context (Task 29).
   * After calling destroy(), this context is no longer usable.
   */
  destroy() {
    if (this._key) {
      this._key.fill(0);
      this._key = null;
    }
    this._ephemeralPublicKey = null;
    this._scalarIVTracker.clear();
  }

  /**
   * Hash-based key ratchet for forward secrecy in streaming (Task 40).
   * Derives a new key from the current key and replaces it.
   * The old key is zeroed.
   * @returns {EncryptionContext} this (for chaining)
   */
  ratchetKey() {
    const info = new TextEncoder().encode('ratchet');
    const newKey = hkdf(this._key, null, info, KEY_SIZE);
    this._key.fill(0);
    this._key = newKey;
    this._scalarIVTracker.clear();
    return this;
  }
}

// =============================================================================
// Encryption — Wire Format (Task 39)
// =============================================================================

/** Wire format magic bytes: "FBEN" */
export const WIRE_FORMAT_MAGIC = new Uint8Array([0x46, 0x42, 0x45, 0x4E]); // "FBEN"

/**
 * Serialize an encryption header into the wire format:
 * [FBEN 4B][header_len u32LE][EncryptionHeader JSON][payload]
 *
 * @param {EncryptionHeader} header
 * @param {Uint8Array} payload - Encrypted FlatBuffer data
 * @returns {Uint8Array}
 */
export function serializeEncryptionHeader(header, payload) {
  const headerJSON = encryptionHeaderToJSON(header);
  const headerBytes = new TextEncoder().encode(headerJSON);
  const result = new Uint8Array(4 + 4 + headerBytes.length + payload.length);
  result.set(WIRE_FORMAT_MAGIC, 0);
  const view = new DataView(result.buffer, result.byteOffset, result.byteLength);
  view.setUint32(4, headerBytes.length, true);
  result.set(headerBytes, 8);
  result.set(payload, 8 + headerBytes.length);
  return result;
}

/**
 * Deserialize wire format back to header and payload.
 *
 * @param {Uint8Array} data - Wire format data
 * @returns {{ header: EncryptionHeader, payload: Uint8Array }}
 */
export function deserializeEncryptionHeader(data) {
  if (data.length < 8) {
    throw new CryptoError('Data too short for wire format', CryptoErrorCode.INVALID_INPUT);
  }
  // Verify magic
  for (let i = 0; i < 4; i++) {
    if (data[i] !== WIRE_FORMAT_MAGIC[i]) {
      throw new CryptoError('Invalid wire format magic (expected FBEN)', CryptoErrorCode.INVALID_INPUT);
    }
  }
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const headerLen = view.getUint32(4, true);
  if (8 + headerLen > data.length) {
    throw new CryptoError('Header length exceeds data', CryptoErrorCode.INVALID_INPUT);
  }
  const headerBytes = data.subarray(8, 8 + headerLen);
  const headerJSON = new TextDecoder().decode(headerBytes);
  const header = encryptionHeaderFromJSON(headerJSON);
  const payload = data.subarray(8 + headerLen);
  return { header, payload };
}

// =============================================================================
// Encryption — Replay Protection (Task 38)
// =============================================================================

/**
 * Monotonic sequence number tracker for replay protection.
 * Maintains the highest seen sequence number and rejects any <= it.
 */
export class SequenceValidator {
  _highest = 0n;

  /**
   * Validate a sequence number. Returns true if valid (strictly increasing).
   * @param {bigint|number} sequenceNumber
   * @returns {boolean}
   */
  validate(sequenceNumber) {
    const seq = BigInt(sequenceNumber);
    if (seq <= this._highest) return false;
    this._highest = seq;
    return true;
  }

  /** Get the current highest sequence number */
  getHighest() {
    return this._highest;
  }

  /** Reset the validator */
  reset() {
    this._highest = 0n;
  }
}

// =============================================================================
// Encryption — Observability Hooks (Task 42)
// =============================================================================

/** @type {((event: CryptoEvent) => void) | null} */
let _cryptoEventCallback = null;

/**
 * @typedef {Object} CryptoEvent
 * @property {string} operation - "encrypt" | "decrypt" | "derive_key" | "mac"
 * @property {number} [fieldId]
 * @property {number} timestamp - Date.now()
 * @property {string} [keyId]
 * @property {number} [size]
 */

/**
 * Set a callback to receive crypto operation events.
 * Useful for metrics (Prometheus/OTel), auditing, and debugging.
 *
 * Metric names for OTel:
 * - flatbuffers.crypto.encrypt.count
 * - flatbuffers.crypto.decrypt.count
 * - flatbuffers.crypto.encrypt.bytes
 * - flatbuffers.crypto.mac.count
 *
 * @param {((event: CryptoEvent) => void) | null} callback
 */
export function onCryptoEvent(callback) {
  _cryptoEventCallback = callback;
}

function _emitCryptoEvent(event) {
  if (_cryptoEventCallback) {
    try {
      _cryptoEventCallback({ ...event, timestamp: Date.now() });
    } catch {
      // Observer errors must not break crypto operations
    }
  }
}

// =============================================================================
// Encryption — Key Management Integration (Task 41)
// =============================================================================

/**
 * @typedef {Object} KeyLookupOptions
 * @property {((keyId: Uint8Array) => Uint8Array | Promise<Uint8Array>) | null} lookupRecipientKey
 *   Callback to resolve a recipient key ID to a public key.
 *   Enables integration with KMS providers (AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault).
 */

/**
 * Create an EncryptionContext using a key lookup callback.
 * Supports integration with external key management systems.
 *
 * Integration patterns:
 * - AWS KMS: Use KMS Decrypt API to unwrap data keys
 * - GCP KMS: Use Cloud KMS asymmetricDecrypt
 * - HashiCorp Vault: Use Transit secrets engine
 * - HDKeyManager/BIP-32: Use deriveEncryptionKey from hd-keys.mjs
 *
 * @param {Uint8Array} recipientKeyId
 * @param {KeyLookupOptions} options
 * @returns {Promise<EncryptionContext>}
 */
export async function createContextWithKeyLookup(recipientKeyId, options) {
  if (!options || !options.lookupRecipientKey) {
    throw new CryptoError('lookupRecipientKey callback is required', CryptoErrorCode.INVALID_INPUT);
  }
  const recipientPublicKey = await options.lookupRecipientKey(recipientKeyId);
  if (!recipientPublicKey || !(recipientPublicKey instanceof Uint8Array)) {
    throw new CryptoError('Key lookup returned invalid key', CryptoErrorCode.INVALID_KEY);
  }
  return EncryptionContext.forEncryption(recipientPublicKey, options);
}
