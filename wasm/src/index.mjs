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
import nodeCrypto from 'crypto';

// Aligned codegen exports (zero-copy WASM interop)
export {
  parseSchema,
  computeLayout,
  generateCppHeader,
  generateTypeScript,
  generateJavaScript,
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

// IV reuse tracking: Map<hexKey, Set<hexIV>>
const _ivTracker = new Map();

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
    _ivTracker.set(keyHex, new Set());
  }
  const ivHex = bytesToHex(iv);
  const ivSet = _ivTracker.get(keyHex);
  if (ivSet.has(ivHex)) {
    throw new CryptoError(
      'IV has already been used with this key. IV reuse in CTR mode completely breaks security.',
      CryptoErrorCode.IV_REUSE
    );
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
  } catch {
    // flatc-wasm crypto not available, use Node.js crypto fallback
  }

  _initialized = true;
}

export function isInitialized() {
  return _initialized;
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

  clearIVTracking(encKey);
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
// Encryption — Buffer Encryption (per-field, schema-driven) — stub
// =============================================================================

export function encryptBuffer(buffer, schema, ctx) {
  return buffer;
}

export function decryptBuffer(buffer, schema, ctx) {
  return buffer;
}

// =============================================================================
// Encryption — Schema Parsing (stub)
// =============================================================================

export function parseSchemaForEncryption(schema, rootType) {
  return {
    rootType,
    fields: [],
    enums: {},
  };
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
  _useGlobalIVTracking = false;

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
    const derivedKey = hkdf(sharedSecret, null, info, KEY_SIZE);

    const ctx = new EncryptionContext(derivedKey);
    ctx._ephemeralPublicKey = ephemeralKeyPair.publicKey;
    ctx._algorithm = algorithm;
    ctx._context = contextStr;
    ctx._recipientKeyId = computeKeyId(recipientPublicKey);
    ctx._iv = generateIV();
    ctx._useGlobalIVTracking = true;

    return ctx;
  }

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
    const derivedKey = hkdf(sharedSecret, null, info, KEY_SIZE);

    const ctx = new EncryptionContext(derivedKey);
    ctx._algorithm = algorithm;
    ctx._context = contextStr;
    ctx._iv = header.iv;
    ctx._useGlobalIVTracking = true;

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

  deriveFieldKey(fieldId) {
    const info = new TextEncoder().encode(`field-key-${fieldId}`);
    return hkdf(this._key, null, info, KEY_SIZE);
  }

  deriveFieldIV(fieldId) {
    const info = new TextEncoder().encode(`field-iv-${fieldId}`);
    return hkdf(this._key, null, info, IV_SIZE);
  }

  encryptScalar(buffer, offset, length, fieldId) {
    const fieldKey = this.deriveFieldKey(fieldId);
    const fieldIV = this.deriveFieldIV(fieldId);
    const region = buffer.subarray(offset, offset + length);

    if (this._useGlobalIVTracking) {
      _trackIV(fieldKey, fieldIV);
    } else {
      const ivHex = bytesToHex(fieldKey) + ':' + bytesToHex(fieldIV);
      if (this._scalarIVTracker.has(ivHex)) {
        throw new CryptoError(
          'IV has already been used with this key. IV reuse in CTR mode completely breaks security.',
          CryptoErrorCode.IV_REUSE
        );
      }
      this._scalarIVTracker.add(ivHex);
    }

    const cipher = nodeCrypto.createCipheriv('aes-256-ctr', fieldKey, fieldIV);
    const encrypted = cipher.update(region);
    cipher.final();
    region.set(encrypted);
  }

  encryptBuffer(buffer, recordIndex) {
    this.encryptScalar(buffer, 0, buffer.length, recordIndex);
  }

  decryptBuffer(buffer, recordIndex) {
    this.decryptScalar(buffer, 0, buffer.length, recordIndex);
  }

  decryptScalar(buffer, offset, length, fieldId) {
    const fieldKey = this.deriveFieldKey(fieldId);
    const fieldIV = this.deriveFieldIV(fieldId);
    const region = buffer.subarray(offset, offset + length);

    // No IV tracking for decryption
    const decipher = nodeCrypto.createDecipheriv('aes-256-ctr', fieldKey, fieldIV);
    const decrypted = decipher.update(region);
    decipher.final();
    region.set(decrypted);
  }
}
