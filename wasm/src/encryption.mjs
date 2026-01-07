/**
 * @module encryption
 *
 * FlatBuffers field-level encryption for the WASM module.
 * Encrypts fields marked with the (encrypted) attribute while preserving binary layout.
 */

/**
 * AES S-box for encryption
 * @type {Uint8Array}
 */
const SBOX = new Uint8Array([
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
  0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
  0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
  0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
  0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
  0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
  0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
  0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
  0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
  0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
  0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
  0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
  0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
  0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
  0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
  0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
  0xb0, 0x54, 0xbb, 0x16,
]);

/**
 * AES round constants
 * @type {Uint8Array}
 */
const RCON = new Uint8Array([
  0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
]);

/**
 * GF(2^8) multiplication
 * @param {number} a
 * @param {number} b
 * @returns {number}
 */
function gfMul(a, b) {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hiBit = a & 0x80;
    a = (a << 1) & 0xff;
    if (hiBit) a ^= 0x1b;
    b >>= 1;
  }
  return p;
}

/**
 * Expand AES-256 key to round keys
 * @param {Uint8Array} key - 32-byte key
 * @returns {Uint8Array} - 240-byte round keys
 */
function aes256KeyExpansion(key) {
  const roundKeys = new Uint8Array(240);
  roundKeys.set(key);

  const temp = new Uint8Array(4);
  let i = 8;

  while (i < 60) {
    temp.set(roundKeys.subarray((i - 1) * 4, i * 4));

    if (i % 8 === 0) {
      // RotWord + SubWord + Rcon
      const t = temp[0];
      temp[0] = SBOX[temp[1]] ^ RCON[i / 8];
      temp[1] = SBOX[temp[2]];
      temp[2] = SBOX[temp[3]];
      temp[3] = SBOX[t];
    } else if (i % 8 === 4) {
      // SubWord only
      temp[0] = SBOX[temp[0]];
      temp[1] = SBOX[temp[1]];
      temp[2] = SBOX[temp[2]];
      temp[3] = SBOX[temp[3]];
    }

    for (let j = 0; j < 4; j++) {
      roundKeys[i * 4 + j] = roundKeys[(i - 8) * 4 + j] ^ temp[j];
    }
    i++;
  }

  return roundKeys;
}

/**
 * AES SubBytes transformation
 * @param {Uint8Array} state - 16-byte state
 */
function subBytes(state) {
  for (let i = 0; i < 16; i++) {
    state[i] = SBOX[state[i]];
  }
}

/**
 * AES ShiftRows transformation
 * @param {Uint8Array} state - 16-byte state
 */
function shiftRows(state) {
  // Row 1: shift left by 1
  let temp = state[1];
  state[1] = state[5];
  state[5] = state[9];
  state[9] = state[13];
  state[13] = temp;
  // Row 2: shift left by 2
  temp = state[2];
  state[2] = state[10];
  state[10] = temp;
  temp = state[6];
  state[6] = state[14];
  state[14] = temp;
  // Row 3: shift left by 3
  temp = state[15];
  state[15] = state[11];
  state[11] = state[7];
  state[7] = state[3];
  state[3] = temp;
}

/**
 * AES MixColumns transformation
 * @param {Uint8Array} state - 16-byte state
 */
function mixColumns(state) {
  for (let i = 0; i < 4; i++) {
    const a = [state[i * 4], state[i * 4 + 1], state[i * 4 + 2], state[i * 4 + 3]];
    state[i * 4 + 0] = gfMul(a[0], 2) ^ gfMul(a[1], 3) ^ a[2] ^ a[3];
    state[i * 4 + 1] = a[0] ^ gfMul(a[1], 2) ^ gfMul(a[2], 3) ^ a[3];
    state[i * 4 + 2] = a[0] ^ a[1] ^ gfMul(a[2], 2) ^ gfMul(a[3], 3);
    state[i * 4 + 3] = gfMul(a[0], 3) ^ a[1] ^ a[2] ^ gfMul(a[3], 2);
  }
}

/**
 * AES AddRoundKey transformation
 * @param {Uint8Array} state - 16-byte state
 * @param {Uint8Array} roundKey - 16-byte round key
 */
function addRoundKey(state, roundKey) {
  for (let i = 0; i < 16; i++) {
    state[i] ^= roundKey[i];
  }
}

/**
 * AES-256 encrypt a single 16-byte block
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} input - 16-byte input
 * @returns {Uint8Array} - 16-byte output
 */
function aesEncryptBlock(key, input) {
  const roundKeys = aes256KeyExpansion(key);
  const state = new Uint8Array(input);

  addRoundKey(state, roundKeys.subarray(0, 16));

  for (let round = 1; round < 14; round++) {
    subBytes(state);
    shiftRows(state);
    mixColumns(state);
    addRoundKey(state, roundKeys.subarray(round * 16, (round + 1) * 16));
  }

  subBytes(state);
  shiftRows(state);
  addRoundKey(state, roundKeys.subarray(14 * 16, 15 * 16));

  return state;
}

/**
 * Generate AES-CTR keystream
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} nonce - 16-byte nonce/IV
 * @param {number} length - keystream length
 * @returns {Uint8Array} - keystream
 */
function aesCtrKeystream(key, nonce, length) {
  const keystream = new Uint8Array(length);
  const counter = new Uint8Array(nonce);

  let offset = 0;
  while (offset < length) {
    const block = aesEncryptBlock(key, counter);
    const toCopy = Math.min(16, length - offset);
    keystream.set(block.subarray(0, toCopy), offset);
    offset += toCopy;

    // Increment counter (big-endian)
    for (let i = 15; i >= 0; i--) {
      counter[i]++;
      if (counter[i] !== 0) break;
    }
  }

  return keystream;
}

// =============================================================================
// HMAC-SHA256 Implementation (for HKDF)
// =============================================================================

/**
 * SHA-256 constants (first 32 bits of fractional parts of cube roots of first 64 primes)
 */
const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

/**
 * SHA-256 initial hash values
 */
const SHA256_H0 = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

/**
 * Right rotate 32-bit value
 */
function rotr32(x, n) {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

/**
 * SHA-256 hash function
 * @param {Uint8Array} message - message to hash
 * @returns {Uint8Array} - 32-byte hash
 */
function sha256(message) {
  // Pre-processing: add padding
  const msgLen = message.length;
  const bitLen = msgLen * 8;

  // Message + 1 byte (0x80) + padding + 8 bytes (length)
  const padLen = (64 - ((msgLen + 9) % 64)) % 64;
  const paddedLen = msgLen + 1 + padLen + 8;
  const padded = new Uint8Array(paddedLen);

  padded.set(message);
  padded[msgLen] = 0x80;

  // Append length in bits as big-endian 64-bit integer
  const view = new DataView(padded.buffer);
  view.setUint32(paddedLen - 4, bitLen >>> 0, false);

  // Initialize hash values
  const h = new Uint32Array(SHA256_H0);
  const w = new Uint32Array(64);

  // Process each 64-byte block
  for (let offset = 0; offset < paddedLen; offset += 64) {
    // Copy block into first 16 words
    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(offset + i * 4, false);
    }

    // Extend to 64 words
    for (let i = 16; i < 64; i++) {
      const s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    // Initialize working variables
    let a = h[0], b = h[1], c = h[2], d = h[3];
    let e = h[4], f = h[5], g = h[6], hh = h[7];

    // Main loop
    for (let i = 0; i < 64; i++) {
      const S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (hh + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;

      hh = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    // Add to hash
    h[0] = (h[0] + a) >>> 0;
    h[1] = (h[1] + b) >>> 0;
    h[2] = (h[2] + c) >>> 0;
    h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0;
    h[5] = (h[5] + f) >>> 0;
    h[6] = (h[6] + g) >>> 0;
    h[7] = (h[7] + hh) >>> 0;
  }

  // Convert to bytes
  const result = new Uint8Array(32);
  const resultView = new DataView(result.buffer);
  for (let i = 0; i < 8; i++) {
    resultView.setUint32(i * 4, h[i], false);
  }

  return result;
}

/**
 * HMAC-SHA256
 * @param {Uint8Array} key - HMAC key
 * @param {Uint8Array} message - message to authenticate
 * @returns {Uint8Array} - 32-byte MAC
 */
function hmacSha256(key, message) {
  const blockSize = 64;

  // If key is longer than block size, hash it
  let keyBlock = key;
  if (key.length > blockSize) {
    keyBlock = sha256(key);
  }

  // Pad key to block size
  const paddedKey = new Uint8Array(blockSize);
  paddedKey.set(keyBlock);

  // Create inner and outer padded keys
  const ipad = new Uint8Array(blockSize);
  const opad = new Uint8Array(blockSize);
  for (let i = 0; i < blockSize; i++) {
    ipad[i] = paddedKey[i] ^ 0x36;
    opad[i] = paddedKey[i] ^ 0x5c;
  }

  // Inner hash: H(ipad || message)
  const inner = new Uint8Array(blockSize + message.length);
  inner.set(ipad);
  inner.set(message, blockSize);
  const innerHash = sha256(inner);

  // Outer hash: H(opad || inner_hash)
  const outer = new Uint8Array(blockSize + 32);
  outer.set(opad);
  outer.set(innerHash, blockSize);

  return sha256(outer);
}

// =============================================================================
// HKDF Implementation (RFC 5869)
// =============================================================================

/**
 * HKDF-Extract: Extract a pseudorandom key from input keying material
 * @param {Uint8Array} salt - optional salt (if empty, uses zeros)
 * @param {Uint8Array} ikm - input keying material
 * @returns {Uint8Array} - 32-byte pseudorandom key
 */
function hkdfExtract(salt, ikm) {
  // If salt is empty, use a string of zeros
  const actualSalt = salt.length > 0 ? salt : new Uint8Array(32);
  return hmacSha256(actualSalt, ikm);
}

/**
 * HKDF-Expand: Expand pseudorandom key to desired length
 * @param {Uint8Array} prk - pseudorandom key from Extract
 * @param {Uint8Array} info - context/application-specific info
 * @param {number} length - desired output length (max 255 * 32)
 * @returns {Uint8Array} - output keying material
 */
function hkdfExpand(prk, info, length) {
  const hashLen = 32;
  const n = Math.ceil(length / hashLen);

  if (n > 255) {
    throw new Error("HKDF output length too large");
  }

  const okm = new Uint8Array(n * hashLen);
  let prev = new Uint8Array(0);

  for (let i = 1; i <= n; i++) {
    // T(i) = HMAC(PRK, T(i-1) || info || i)
    const input = new Uint8Array(prev.length + info.length + 1);
    input.set(prev);
    input.set(info, prev.length);
    input[prev.length + info.length] = i;

    prev = hmacSha256(prk, input);
    okm.set(prev, (i - 1) * hashLen);
  }

  return okm.subarray(0, length);
}

/**
 * HKDF: Full HKDF key derivation (RFC 5869)
 * @param {Uint8Array} ikm - input keying material (master key)
 * @param {Uint8Array} salt - optional salt
 * @param {Uint8Array} info - context-specific info
 * @param {number} length - desired output length
 * @returns {Uint8Array} - derived key material
 */
function hkdf(ikm, salt, info, length) {
  const prk = hkdfExtract(salt, ikm);
  return hkdfExpand(prk, info, length);
}

/**
 * Derive key using HKDF (RFC 5869)
 * @param {Uint8Array} masterKey - 32-byte master key
 * @param {Uint8Array} info - context info bytes
 * @param {number} outLength - output length
 * @returns {Uint8Array} - derived key
 */
function deriveKey(masterKey, info, outLength) {
  // Use empty salt (will default to zeros in hkdfExtract)
  // This matches typical HKDF usage when salt is not available
  const salt = new Uint8Array(0);
  return hkdf(masterKey, salt, info, outLength);
}

// =============================================================================
// X25519 (Curve25519 ECDH) Implementation (RFC 7748)
// Uses BigInt for correct arithmetic in GF(2^255-19)
// =============================================================================

/**
 * Prime for Curve25519: p = 2^255 - 19
 */
const P = (1n << 255n) - 19n;

/**
 * Curve constant a24 = 121665 (a24 = (A-2)/4 where A=486662)
 */
const A24 = 121665n;

/**
 * Convert 32 bytes (little-endian) to BigInt
 * @param {Uint8Array} bytes
 * @returns {bigint}
 */
function bytesToBigInt(bytes) {
  let result = 0n;
  for (let i = 31; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

/**
 * Convert BigInt to 32 bytes (little-endian)
 * @param {bigint} n
 * @returns {Uint8Array}
 */
function bigIntToBytes(n) {
  const bytes = new Uint8Array(32);
  let val = n % P;
  if (val < 0n) val += P;
  for (let i = 0; i < 32; i++) {
    bytes[i] = Number(val & 0xffn);
    val >>= 8n;
  }
  return bytes;
}

/**
 * Modular inverse using extended Euclidean algorithm
 * @param {bigint} a
 * @param {bigint} p
 * @returns {bigint}
 */
function modInverse(a, p) {
  a = ((a % p) + p) % p;
  let [old_r, r] = [a, p];
  let [old_s, s] = [1n, 0n];

  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }

  return ((old_s % p) + p) % p;
}

/**
 * Modular addition
 */
function modAdd(a, b, p) {
  return ((a + b) % p + p) % p;
}

/**
 * Modular subtraction
 */
function modSub(a, b, p) {
  return ((a - b) % p + p) % p;
}

/**
 * Modular multiplication
 */
function modMul(a, b, p) {
  return ((a * b) % p + p) % p;
}

/**
 * X25519 scalar multiplication (Montgomery ladder)
 * Implements RFC 7748 precisely
 * @param {Uint8Array} k - 32-byte scalar
 * @param {Uint8Array} u - 32-byte u-coordinate
 * @returns {Uint8Array} - 32-byte result
 */
function x25519ScalarMult(k, u) {
  // Decode scalar and clamp per RFC 7748
  const scalar = new Uint8Array(k);
  scalar[0] &= 248;
  scalar[31] &= 127;
  scalar[31] |= 64;
  const kn = bytesToBigInt(scalar);

  // Decode u-coordinate, clear high bit
  const uClamped = new Uint8Array(u);
  uClamped[31] &= 127;
  const u1 = bytesToBigInt(uClamped) % P;

  // Montgomery ladder variables
  let x_1 = u1;
  let x_2 = 1n;
  let z_2 = 0n;
  let x_3 = u1;
  let z_3 = 1n;

  let swap = 0n;

  // Process bits from 254 down to 0
  for (let t = 254; t >= 0; t--) {
    const k_t = (kn >> BigInt(t)) & 1n;
    swap ^= k_t;

    // Conditional swap
    if (swap === 1n) {
      [x_2, x_3] = [x_3, x_2];
      [z_2, z_3] = [z_3, z_2];
    }
    swap = k_t;

    const A = modAdd(x_2, z_2, P);
    const AA = modMul(A, A, P);
    const B = modSub(x_2, z_2, P);
    const BB = modMul(B, B, P);
    const E = modSub(AA, BB, P);
    const C = modAdd(x_3, z_3, P);
    const D = modSub(x_3, z_3, P);
    const DA = modMul(D, A, P);
    const CB = modMul(C, B, P);

    x_3 = modMul(modAdd(DA, CB, P), modAdd(DA, CB, P), P);
    z_3 = modMul(x_1, modMul(modSub(DA, CB, P), modSub(DA, CB, P), P), P);
    x_2 = modMul(AA, BB, P);
    z_2 = modMul(E, modAdd(AA, modMul(A24, E, P), P), P);
  }

  // Final conditional swap
  if (swap === 1n) {
    [x_2, x_3] = [x_3, x_2];
    [z_2, z_3] = [z_3, z_2];
  }

  // Compute result = x_2 * z_2^(-1) mod p
  const result = modMul(x_2, modInverse(z_2, P), P);
  return bigIntToBytes(result);
}

/**
 * X25519 base point (u = 9)
 */
const X25519_BASEPOINT = new Uint8Array([
  9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
]);

/**
 * Generate X25519 key pair
 * @param {Uint8Array} [privateKey] - Optional 32-byte private key (random if not provided)
 * @returns {{privateKey: Uint8Array, publicKey: Uint8Array}}
 */
export function x25519GenerateKeyPair(privateKey) {
  if (!privateKey) {
    // Generate random private key
    privateKey = new Uint8Array(32);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      crypto.getRandomValues(privateKey);
    } else {
      // Fallback for environments without crypto
      for (let i = 0; i < 32; i++) {
        privateKey[i] = Math.floor(Math.random() * 256);
      }
    }
  }

  const publicKey = x25519ScalarMult(privateKey, X25519_BASEPOINT);

  return { privateKey: new Uint8Array(privateKey), publicKey };
}

/**
 * Perform X25519 ECDH key exchange
 * @param {Uint8Array} privateKey - Our 32-byte private key
 * @param {Uint8Array} publicKey - Their 32-byte public key
 * @returns {Uint8Array} - 32-byte shared secret
 */
export function x25519SharedSecret(privateKey, publicKey) {
  return x25519ScalarMult(privateKey, publicKey);
}

/**
 * Derive symmetric key from X25519 shared secret using HKDF
 * @param {Uint8Array} sharedSecret - 32-byte ECDH shared secret
 * @param {Uint8Array} [context] - Optional context bytes
 * @returns {Uint8Array} - 32-byte symmetric key
 */
export function x25519DeriveKey(sharedSecret, context) {
  const info = new Uint8Array(context ? context.length + 18 : 18);
  const infoStr = "flatbuffers-x25519";
  for (let i = 0; i < infoStr.length; i++) {
    info[i] = infoStr.charCodeAt(i);
  }
  if (context) {
    info.set(context, 18);
  }
  return hkdf(sharedSecret, new Uint8Array(0), info, 32);
}

// =============================================================================
// secp256k1 ECDH Implementation (Bitcoin/Ethereum curve)
// =============================================================================

/**
 * secp256k1 curve parameters
 * y^2 = x^3 + 7 (mod p)
 */
const SECP256K1_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const SECP256K1_GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const SECP256K1_GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

/**
 * P-256 (secp256r1) curve parameters
 * y^2 = x^3 - 3x + b (mod p)
 */
const P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const P256_A = P256_P - 3n; // a = -3 mod p
const P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
const P256_GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n;
const P256_GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n;

/**
 * Elliptic curve point class for Weierstrass curves
 */
class ECPoint {
  constructor(x, y, infinity = false) {
    this.x = x;
    this.y = y;
    this.infinity = infinity;
  }

  static infinity() {
    return new ECPoint(0n, 0n, true);
  }

  isInfinity() {
    return this.infinity;
  }

  equals(other) {
    if (this.infinity && other.infinity) return true;
    if (this.infinity || other.infinity) return false;
    return this.x === other.x && this.y === other.y;
  }
}

/**
 * Point addition on Weierstrass curve
 * @param {ECPoint} p1
 * @param {ECPoint} p2
 * @param {bigint} prime - Field prime
 * @param {bigint} a - Curve parameter a (0 for secp256k1, -3 for P-256)
 * @returns {ECPoint}
 */
function ecPointAdd(p1, p2, prime, a) {
  if (p1.isInfinity()) return p2;
  if (p2.isInfinity()) return p1;

  const x1 = p1.x, y1 = p1.y;
  const x2 = p2.x, y2 = p2.y;

  let lambda;

  if (x1 === x2) {
    if (((y1 + y2) % prime + prime) % prime === 0n) {
      return ECPoint.infinity();
    }
    // Point doubling: lambda = (3*x1^2 + a) / (2*y1)
    const num = ((3n * x1 * x1 + a) % prime + prime) % prime;
    const denom = (2n * y1 % prime + prime) % prime;
    lambda = (num * modInverse(denom, prime)) % prime;
  } else {
    // Point addition: lambda = (y2 - y1) / (x2 - x1)
    const num = ((y2 - y1) % prime + prime) % prime;
    const denom = ((x2 - x1) % prime + prime) % prime;
    lambda = (num * modInverse(denom, prime)) % prime;
  }

  const x3 = ((lambda * lambda - x1 - x2) % prime + prime) % prime;
  const y3 = ((lambda * (x1 - x3) - y1) % prime + prime) % prime;

  return new ECPoint(x3, y3);
}

/**
 * Scalar multiplication using double-and-add
 * @param {bigint} k - Scalar
 * @param {ECPoint} point - Base point
 * @param {bigint} prime - Field prime
 * @param {bigint} a - Curve parameter a
 * @returns {ECPoint}
 */
function ecScalarMult(k, point, prime, a) {
  if (k === 0n || point.isInfinity()) {
    return ECPoint.infinity();
  }

  let result = ECPoint.infinity();
  let addend = new ECPoint(point.x, point.y);

  while (k > 0n) {
    if (k & 1n) {
      result = ecPointAdd(result, addend, prime, a);
    }
    addend = ecPointAdd(addend, addend, prime, a);
    k >>= 1n;
  }

  return result;
}

/**
 * Convert 32 bytes to BigInt (big-endian, as used by secp256k1/P-256)
 */
function bytes32ToBigInt(bytes) {
  let result = 0n;
  for (let i = 0; i < 32; i++) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

/**
 * Convert BigInt to 32 bytes (big-endian)
 */
function bigIntTo32Bytes(n) {
  const bytes = new Uint8Array(32);
  let val = n;
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(val & 0xffn);
    val >>= 8n;
  }
  return bytes;
}

/**
 * Decompress a secp256k1/P-256 public key
 * @param {Uint8Array} compressed - 33-byte compressed key (02/03 prefix + x)
 * @param {bigint} prime - Field prime
 * @param {bigint} a - Curve parameter a
 * @param {bigint} b - Curve parameter b
 * @returns {ECPoint}
 */
function decompressPublicKey(compressed, prime, a, b) {
  if (compressed.length !== 33) {
    throw new Error("Compressed public key must be 33 bytes");
  }

  const prefix = compressed[0];
  if (prefix !== 0x02 && prefix !== 0x03) {
    throw new Error("Invalid compressed public key prefix");
  }

  const x = bytes32ToBigInt(compressed.subarray(1));

  // y^2 = x^3 + ax + b
  const y2 = ((x * x * x + a * x + b) % prime + prime) % prime;

  // Compute square root using Tonelli-Shanks (simplified for p ≡ 3 mod 4)
  // For both secp256k1 and P-256, p ≡ 3 mod 4, so sqrt(y2) = y2^((p+1)/4)
  const y = modPow(y2, (prime + 1n) / 4n, prime);

  // Check which root matches the parity
  const isOdd = (y & 1n) === 1n;
  const needOdd = prefix === 0x03;

  const finalY = isOdd === needOdd ? y : (prime - y);

  return new ECPoint(x, finalY);
}

/**
 * Compress an EC point to 33 bytes
 * @param {ECPoint} point
 * @returns {Uint8Array}
 */
function compressPublicKey(point) {
  const compressed = new Uint8Array(33);
  compressed[0] = (point.y & 1n) === 1n ? 0x03 : 0x02;
  compressed.set(bigIntTo32Bytes(point.x), 1);
  return compressed;
}

/**
 * Modular exponentiation
 */
function modPow(base, exp, mod) {
  let result = 1n;
  base = ((base % mod) + mod) % mod;
  while (exp > 0n) {
    if (exp & 1n) {
      result = (result * base) % mod;
    }
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

// =============================================================================
// secp256k1 Public API
// =============================================================================

/**
 * Generate secp256k1 key pair
 * @param {Uint8Array} [privateKey] - Optional 32-byte private key
 * @returns {{privateKey: Uint8Array, publicKey: Uint8Array}} - publicKey is 33 bytes compressed
 */
export function secp256k1GenerateKeyPair(privateKey) {
  if (!privateKey) {
    privateKey = new Uint8Array(32);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      crypto.getRandomValues(privateKey);
    } else {
      for (let i = 0; i < 32; i++) {
        privateKey[i] = Math.floor(Math.random() * 256);
      }
    }
  }

  let k = bytes32ToBigInt(privateKey);
  // Ensure private key is in valid range [1, n-1]
  k = k % SECP256K1_N;
  if (k === 0n) k = 1n;

  const G = new ECPoint(SECP256K1_GX, SECP256K1_GY);
  const pubPoint = ecScalarMult(k, G, SECP256K1_P, 0n);
  const publicKey = compressPublicKey(pubPoint);

  return { privateKey: bigIntTo32Bytes(k), publicKey };
}

/**
 * Perform secp256k1 ECDH
 * @param {Uint8Array} privateKey - 32-byte private key
 * @param {Uint8Array} publicKey - 33-byte compressed public key
 * @returns {Uint8Array} - 32-byte shared secret (x-coordinate of shared point)
 */
export function secp256k1SharedSecret(privateKey, publicKey) {
  const k = bytes32ToBigInt(privateKey);
  const pubPoint = decompressPublicKey(publicKey, SECP256K1_P, 0n, 7n);
  const sharedPoint = ecScalarMult(k, pubPoint, SECP256K1_P, 0n);

  if (sharedPoint.isInfinity()) {
    throw new Error("Invalid ECDH result (point at infinity)");
  }

  return bigIntTo32Bytes(sharedPoint.x);
}

/**
 * Derive symmetric key from secp256k1 shared secret using HKDF
 * @param {Uint8Array} sharedSecret - 32-byte shared secret
 * @param {Uint8Array} [context] - Optional context bytes
 * @returns {Uint8Array} - 32-byte symmetric key
 */
export function secp256k1DeriveKey(sharedSecret, context) {
  const infoStr = "flatbuffers-secp256k1";
  const info = new Uint8Array(context ? context.length + infoStr.length : infoStr.length);
  for (let i = 0; i < infoStr.length; i++) {
    info[i] = infoStr.charCodeAt(i);
  }
  if (context) {
    info.set(context, infoStr.length);
  }
  return hkdf(sharedSecret, new Uint8Array(0), info, 32);
}

// =============================================================================
// P-256 (secp256r1) Public API
// =============================================================================

/**
 * Generate P-256 key pair
 * @param {Uint8Array} [privateKey] - Optional 32-byte private key
 * @returns {{privateKey: Uint8Array, publicKey: Uint8Array}} - publicKey is 33 bytes compressed
 */
export function p256GenerateKeyPair(privateKey) {
  if (!privateKey) {
    privateKey = new Uint8Array(32);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      crypto.getRandomValues(privateKey);
    } else {
      for (let i = 0; i < 32; i++) {
        privateKey[i] = Math.floor(Math.random() * 256);
      }
    }
  }

  let k = bytes32ToBigInt(privateKey);
  // Ensure private key is in valid range [1, n-1]
  k = k % P256_N;
  if (k === 0n) k = 1n;

  const G = new ECPoint(P256_GX, P256_GY);
  const pubPoint = ecScalarMult(k, G, P256_P, P256_A);
  const publicKey = compressPublicKey(pubPoint);

  return { privateKey: bigIntTo32Bytes(k), publicKey };
}

/**
 * Perform P-256 ECDH
 * @param {Uint8Array} privateKey - 32-byte private key
 * @param {Uint8Array} publicKey - 33-byte compressed public key
 * @returns {Uint8Array} - 32-byte shared secret (x-coordinate of shared point)
 */
export function p256SharedSecret(privateKey, publicKey) {
  const k = bytes32ToBigInt(privateKey);
  const pubPoint = decompressPublicKey(publicKey, P256_P, P256_A, P256_B);
  const sharedPoint = ecScalarMult(k, pubPoint, P256_P, P256_A);

  if (sharedPoint.isInfinity()) {
    throw new Error("Invalid ECDH result (point at infinity)");
  }

  return bigIntTo32Bytes(sharedPoint.x);
}

/**
 * Derive symmetric key from P-256 shared secret using HKDF
 * @param {Uint8Array} sharedSecret - 32-byte shared secret
 * @param {Uint8Array} [context] - Optional context bytes
 * @returns {Uint8Array} - 32-byte symmetric key
 */
export function p256DeriveKey(sharedSecret, context) {
  const infoStr = "flatbuffers-p256";
  const info = new Uint8Array(context ? context.length + infoStr.length : infoStr.length);
  for (let i = 0; i < infoStr.length; i++) {
    info[i] = infoStr.charCodeAt(i);
  }
  if (context) {
    info.set(context, infoStr.length);
  }
  return hkdf(sharedSecret, new Uint8Array(0), info, 32);
}

// =============================================================================
// Key Exchange Algorithm Constants
// =============================================================================

/**
 * Key exchange algorithms supported by EncryptionHeader
 */
export const KeyExchangeAlgorithm = {
  X25519: 0,      // Curve25519 ECDH (RFC 7748)
  Secp256k1: 1,   // Bitcoin/Ethereum curve ECDH
  P256: 2,        // NIST P-256/secp256r1 ECDH
};

/**
 * Symmetric encryption algorithms
 */
export const SymmetricAlgorithm = {
  AES_256_CTR: 0, // AES-256 in CTR mode (size-preserving)
};

/**
 * Key derivation functions
 */
export const KeyDerivationFunction = {
  HKDF_SHA256: 0, // HKDF with SHA-256 (RFC 5869)
};

// =============================================================================
// EncryptionHeader - FlatBuffer header for hybrid encryption
// =============================================================================

/**
 * Build an EncryptionHeader as a simple object (can be serialized to JSON or FlatBuffer)
 * @param {Object} options
 * @param {Uint8Array} options.ephemeralPublicKey - The ephemeral public key
 * @param {number} [options.keyExchange=0] - Key exchange algorithm (KeyExchangeAlgorithm)
 * @param {number} [options.symmetric=0] - Symmetric algorithm (SymmetricAlgorithm)
 * @param {number} [options.kdf=0] - Key derivation function (KeyDerivationFunction)
 * @param {Uint8Array} [options.recipientKeyId] - Optional recipient key identifier
 * @param {string} [options.context] - Optional HKDF context string
 * @param {Uint8Array} [options.schemaHash] - Optional schema hash
 * @param {string} [options.rootType] - Optional root type name
 * @returns {Object} - EncryptionHeader object
 */
export function createEncryptionHeader(options) {
  if (!options.ephemeralPublicKey || options.ephemeralPublicKey.length < 32) {
    throw new Error("ephemeralPublicKey is required and must be at least 32 bytes");
  }

  return {
    version: 1,
    key_exchange: options.keyExchange ?? KeyExchangeAlgorithm.X25519,
    symmetric: options.symmetric ?? SymmetricAlgorithm.AES_256_CTR,
    kdf: options.kdf ?? KeyDerivationFunction.HKDF_SHA256,
    ephemeral_public_key: Array.from(options.ephemeralPublicKey),
    recipient_key_id: options.recipientKeyId ? Array.from(options.recipientKeyId) : undefined,
    context: options.context,
    schema_hash: options.schemaHash ? Array.from(options.schemaHash) : undefined,
    root_type: options.rootType,
    timestamp: Date.now(),
  };
}

/**
 * Serialize EncryptionHeader to JSON string
 * @param {Object} header - EncryptionHeader object
 * @returns {string} - JSON string
 */
export function encryptionHeaderToJSON(header) {
  return JSON.stringify(header);
}

/**
 * Parse EncryptionHeader from JSON string
 * @param {string} json - JSON string
 * @returns {Object} - EncryptionHeader object with Uint8Array fields
 */
export function encryptionHeaderFromJSON(json) {
  const obj = JSON.parse(json);
  return {
    version: obj.version,
    keyExchange: obj.key_exchange,
    symmetric: obj.symmetric,
    kdf: obj.kdf,
    ephemeralPublicKey: new Uint8Array(obj.ephemeral_public_key),
    recipientKeyId: obj.recipient_key_id ? new Uint8Array(obj.recipient_key_id) : undefined,
    context: obj.context,
    schemaHash: obj.schema_hash ? new Uint8Array(obj.schema_hash) : undefined,
    rootType: obj.root_type,
    timestamp: obj.timestamp,
  };
}

/**
 * Compute a key identifier from a public key (first 8 bytes of SHA-256 hash)
 * @param {Uint8Array} publicKey - Public key bytes
 * @returns {Uint8Array} - 8-byte key identifier
 */
export function computeKeyId(publicKey) {
  return sha256(publicKey).subarray(0, 8);
}

// EncryptionHeader schema for FlatBuffer serialization
const ENCRYPTION_HEADER_SCHEMA = `
namespace flatbuffers.encryption;

enum KeyExchangeAlgorithm : byte {
  X25519 = 0,
  Secp256k1 = 1,
  P256 = 2
}

enum SymmetricAlgorithm : byte {
  AES_256_CTR = 0
}

enum KeyDerivationFunction : byte {
  HKDF_SHA256 = 0
}

table EncryptionHeader {
  version: ubyte = 1;
  key_exchange: KeyExchangeAlgorithm = X25519;
  symmetric: SymmetricAlgorithm = AES_256_CTR;
  kdf: KeyDerivationFunction = HKDF_SHA256;
  ephemeral_public_key: [ubyte] (required);
  recipient_key_id: [ubyte];
  context: string;
  schema_hash: [ubyte];
  root_type: string;
  timestamp: ulong;
}

root_type EncryptionHeader;
`;

let _headerRunner = null;

async function getHeaderRunner() {
  if (!_headerRunner) {
    // Dynamic import to avoid circular dependency
    const { FlatcRunner } = await import("./runner.mjs");
    _headerRunner = await FlatcRunner.init();
  }
  return _headerRunner;
}

/**
 * Serialize EncryptionHeader to FlatBuffer binary
 * @param {Object} header - EncryptionHeader object (from createEncryptionHeader or getHeader)
 * @returns {Promise<Uint8Array>} - FlatBuffer binary
 */
export async function encryptionHeaderToBinary(header) {
  const runner = await getHeaderRunner();
  const schemaInput = {
    entry: "/encryption_header.fbs",
    files: { "/encryption_header.fbs": ENCRYPTION_HEADER_SCHEMA },
  };
  return runner.generateBinary(schemaInput, JSON.stringify(header));
}

/**
 * Parse EncryptionHeader from FlatBuffer binary
 * @param {Uint8Array} binary - FlatBuffer binary
 * @returns {Promise<Object>} - EncryptionHeader object with Uint8Array fields
 */
export async function encryptionHeaderFromBinary(binary) {
  const runner = await getHeaderRunner();
  const schemaInput = {
    entry: "/encryption_header.fbs",
    files: { "/encryption_header.fbs": ENCRYPTION_HEADER_SCHEMA },
  };
  const json = runner.generateJSON(schemaInput, {
    path: "/header.bin",
    data: binary,
  });
  return encryptionHeaderFromJSON(json);
}

/**
 * Encryption context for FlatBuffer field encryption.
 * Supports both symmetric (shared secret) and asymmetric (public key) modes.
 */
export class EncryptionContext {
  /** @type {Uint8Array} */
  #key;

  /** @type {boolean} */
  #valid;

  /** @type {Uint8Array|null} */
  #ephemeralPublicKey;

  /** @type {Object|null} */
  #header;

  /**
   * Create an encryption context with a symmetric key
   * @param {Uint8Array|string} key - 32-byte key or hex string
   */
  constructor(key) {
    if (typeof key === "string") {
      // Parse hex string
      this.#key = new Uint8Array(key.length / 2);
      for (let i = 0; i < key.length; i += 2) {
        this.#key[i / 2] = parseInt(key.substring(i, i + 2), 16);
      }
    } else if (key instanceof Uint8Array) {
      this.#key = new Uint8Array(key);
    } else {
      this.#key = new Uint8Array(32);
    }

    this.#valid = this.#key.length === 32;
    this.#ephemeralPublicKey = null;
    this.#header = null;
  }

  /**
   * Create an EncryptionContext for encrypting TO a recipient's public key.
   * Generates an ephemeral key pair and derives a shared secret.
   * The ephemeral public key must be sent to the recipient out-of-band.
   *
   * @param {Uint8Array} recipientPublicKey - Recipient's public key
   *   - X25519: 32 bytes
   *   - secp256k1/P-256: 33 bytes (compressed)
   * @param {Object} [options] - Additional options for the header
   * @param {number} [options.keyExchange=0] - Key exchange algorithm (KeyExchangeAlgorithm)
   * @param {string} [options.context] - HKDF context string
   * @param {Uint8Array} [options.schemaHash] - Schema hash
   * @param {string} [options.rootType] - Root type name
   * @returns {EncryptionContext} - Context ready for encryption
   */
  static forEncryption(recipientPublicKey, options = {}) {
    const keyExchange = options.keyExchange ?? KeyExchangeAlgorithm.X25519;
    const contextBytes = options.context
      ? new TextEncoder().encode(options.context)
      : undefined;

    let ephemeral;
    let sharedSecret;
    let symmetricKey;

    switch (keyExchange) {
      case KeyExchangeAlgorithm.X25519:
        if (!recipientPublicKey || recipientPublicKey.length !== 32) {
          throw new Error("X25519 recipientPublicKey must be 32 bytes");
        }
        ephemeral = x25519GenerateKeyPair();
        sharedSecret = x25519SharedSecret(ephemeral.privateKey, recipientPublicKey);
        symmetricKey = x25519DeriveKey(sharedSecret, contextBytes);
        break;

      case KeyExchangeAlgorithm.Secp256k1:
        if (!recipientPublicKey || recipientPublicKey.length !== 33) {
          throw new Error("secp256k1 recipientPublicKey must be 33 bytes (compressed)");
        }
        ephemeral = secp256k1GenerateKeyPair();
        sharedSecret = secp256k1SharedSecret(ephemeral.privateKey, recipientPublicKey);
        symmetricKey = secp256k1DeriveKey(sharedSecret, contextBytes);
        break;

      case KeyExchangeAlgorithm.P256:
        if (!recipientPublicKey || recipientPublicKey.length !== 33) {
          throw new Error("P-256 recipientPublicKey must be 33 bytes (compressed)");
        }
        ephemeral = p256GenerateKeyPair();
        sharedSecret = p256SharedSecret(ephemeral.privateKey, recipientPublicKey);
        symmetricKey = p256DeriveKey(sharedSecret, contextBytes);
        break;

      default:
        throw new Error(`Unsupported key exchange algorithm: ${keyExchange}`);
    }

    // Create context
    const ctx = new EncryptionContext(symmetricKey);
    ctx.#ephemeralPublicKey = ephemeral.publicKey;

    // Build header for later retrieval
    ctx.#header = createEncryptionHeader({
      ephemeralPublicKey: ephemeral.publicKey,
      keyExchange: keyExchange,
      recipientKeyId: computeKeyId(recipientPublicKey),
      context: options.context,
      schemaHash: options.schemaHash,
      rootType: options.rootType,
    });

    return ctx;
  }

  /**
   * Create an EncryptionContext for decrypting FROM a sender.
   * Uses the recipient's private key and the sender's ephemeral public key.
   *
   * @param {Uint8Array} recipientPrivateKey - Recipient's private key (32 bytes)
   * @param {Uint8Array|Object} headerOrEphemeralKey - EncryptionHeader object or ephemeral public key
   * @param {Object} [options] - Additional options (only used if headerOrEphemeralKey is a public key)
   * @param {number} [options.keyExchange=0] - Key exchange algorithm (required if passing raw ephemeral key)
   * @param {string} [options.context] - HKDF context string (must match encryption context)
   * @returns {EncryptionContext} - Context ready for decryption
   */
  static forDecryption(recipientPrivateKey, headerOrEphemeralKey, options = {}) {
    if (!recipientPrivateKey || recipientPrivateKey.length !== 32) {
      throw new Error("recipientPrivateKey must be 32 bytes");
    }

    let ephemeralPublicKey;
    let context;
    let keyExchange;

    if (headerOrEphemeralKey instanceof Uint8Array) {
      // Direct ephemeral public key
      ephemeralPublicKey = headerOrEphemeralKey;
      context = options.context;
      keyExchange = options.keyExchange ?? KeyExchangeAlgorithm.X25519;
    } else if (typeof headerOrEphemeralKey === 'object') {
      // EncryptionHeader object
      ephemeralPublicKey = headerOrEphemeralKey.ephemeralPublicKey
        || (headerOrEphemeralKey.ephemeral_public_key
          ? new Uint8Array(headerOrEphemeralKey.ephemeral_public_key)
          : null);
      context = headerOrEphemeralKey.context;
      keyExchange = headerOrEphemeralKey.keyExchange
        ?? headerOrEphemeralKey.key_exchange
        ?? KeyExchangeAlgorithm.X25519;
    } else {
      throw new Error("headerOrEphemeralKey must be Uint8Array or EncryptionHeader object");
    }

    const contextBytes = context
      ? new TextEncoder().encode(context)
      : undefined;

    let sharedSecret;
    let symmetricKey;

    switch (keyExchange) {
      case KeyExchangeAlgorithm.X25519:
        if (!ephemeralPublicKey || ephemeralPublicKey.length !== 32) {
          throw new Error("X25519 ephemeralPublicKey must be 32 bytes");
        }
        sharedSecret = x25519SharedSecret(recipientPrivateKey, ephemeralPublicKey);
        symmetricKey = x25519DeriveKey(sharedSecret, contextBytes);
        break;

      case KeyExchangeAlgorithm.Secp256k1:
        if (!ephemeralPublicKey || ephemeralPublicKey.length !== 33) {
          throw new Error("secp256k1 ephemeralPublicKey must be 33 bytes");
        }
        sharedSecret = secp256k1SharedSecret(recipientPrivateKey, ephemeralPublicKey);
        symmetricKey = secp256k1DeriveKey(sharedSecret, contextBytes);
        break;

      case KeyExchangeAlgorithm.P256:
        if (!ephemeralPublicKey || ephemeralPublicKey.length !== 33) {
          throw new Error("P-256 ephemeralPublicKey must be 33 bytes");
        }
        sharedSecret = p256SharedSecret(recipientPrivateKey, ephemeralPublicKey);
        symmetricKey = p256DeriveKey(sharedSecret, contextBytes);
        break;

      default:
        throw new Error(`Unsupported key exchange algorithm: ${keyExchange}`);
    }

    return new EncryptionContext(symmetricKey);
  }

  /**
   * Check if context is valid
   * @returns {boolean}
   */
  isValid() {
    return this.#valid;
  }

  /**
   * Get the ephemeral public key (only available for encryption contexts)
   * @returns {Uint8Array|null} - 32-byte ephemeral public key or null
   */
  getEphemeralPublicKey() {
    return this.#ephemeralPublicKey;
  }

  /**
   * Get the encryption header (only available for encryption contexts)
   * @returns {Object|null} - EncryptionHeader object or null
   */
  getHeader() {
    return this.#header;
  }

  /**
   * Get the encryption header as JSON string (only available for encryption contexts)
   * @returns {string|null} - JSON string or null
   */
  getHeaderJSON() {
    return this.#header ? encryptionHeaderToJSON(this.#header) : null;
  }

  /**
   * Get the encryption header as FlatBuffer binary (only available for encryption contexts)
   * @returns {Promise<Uint8Array|null>} - FlatBuffer binary or null
   */
  async getHeaderBinary() {
    return this.#header ? encryptionHeaderToBinary(this.#header) : null;
  }

  /**
   * Derive a field-specific key
   * @param {number} fieldId - field ID
   * @returns {Uint8Array} - 32-byte derived key
   */
  deriveFieldKey(fieldId) {
    const info = new Uint8Array(19);
    const infoStr = "flatbuffers-field";
    for (let i = 0; i < infoStr.length; i++) {
      info[i] = infoStr.charCodeAt(i);
    }
    info[17] = (fieldId >> 8) & 0xff;
    info[18] = fieldId & 0xff;
    return deriveKey(this.#key, info, 32);
  }

  /**
   * Derive a field-specific IV
   * @param {number} fieldId - field ID
   * @returns {Uint8Array} - 16-byte derived IV
   */
  deriveFieldIV(fieldId) {
    const info = new Uint8Array(16);
    const infoStr = "flatbuffers-iv";
    for (let i = 0; i < infoStr.length; i++) {
      info[i] = infoStr.charCodeAt(i);
    }
    info[14] = (fieldId >> 8) & 0xff;
    info[15] = fieldId & 0xff;
    return deriveKey(this.#key, info, 16);
  }
}

/**
 * Encrypt bytes using AES-CTR (XOR with keystream)
 * @param {Uint8Array} data - data to encrypt (modified in-place)
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} iv - 16-byte IV
 */
export function encryptBytes(data, key, iv) {
  const keystream = aesCtrKeystream(key, iv, data.length);
  for (let i = 0; i < data.length; i++) {
    data[i] ^= keystream[i];
  }
}

/**
 * Decrypt bytes using AES-CTR (same as encrypt)
 * @param {Uint8Array} data - data to decrypt (modified in-place)
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} iv - 16-byte IV
 */
export const decryptBytes = encryptBytes;

/**
 * Encrypt a scalar value
 * @param {Uint8Array} buffer - buffer containing the scalar
 * @param {number} offset - offset of the scalar
 * @param {number} size - size of the scalar (1, 2, 4, or 8)
 * @param {EncryptionContext} ctx - encryption context
 * @param {number} fieldId - field ID
 */
export function encryptScalar(buffer, offset, size, ctx, fieldId) {
  const key = ctx.deriveFieldKey(fieldId);
  const iv = ctx.deriveFieldIV(fieldId);
  const slice = buffer.subarray(offset, offset + size);
  encryptBytes(slice, key, iv);
}

/**
 * Read a 32-bit unsigned integer from buffer (little-endian)
 * @param {Uint8Array} buffer
 * @param {number} offset
 * @returns {number}
 */
function readUint32(buffer, offset) {
  return (
    buffer[offset] |
    (buffer[offset + 1] << 8) |
    (buffer[offset + 2] << 16) |
    (buffer[offset + 3] << 24)
  ) >>> 0;
}

/**
 * Read a 16-bit unsigned integer from buffer (little-endian)
 * @param {Uint8Array} buffer
 * @param {number} offset
 * @returns {number}
 */
function readUint16(buffer, offset) {
  return buffer[offset] | (buffer[offset + 1] << 8);
}

/**
 * Read a 32-bit signed integer from buffer (little-endian)
 * @param {Uint8Array} buffer
 * @param {number} offset
 * @returns {number}
 */
function readInt32(buffer, offset) {
  return (
    buffer[offset] |
    (buffer[offset + 1] << 8) |
    (buffer[offset + 2] << 16) |
    (buffer[offset + 3] << 24)
  );
}

/**
 * Process a FlatBuffer table, encrypting/decrypting marked fields
 * @param {Uint8Array} buffer - the FlatBuffer
 * @param {number} tableOffset - offset to the table
 * @param {Object} schema - parsed schema with field info
 * @param {EncryptionContext} ctx - encryption context
 * @param {boolean} encrypt - true to encrypt, false to decrypt (same for AES-CTR)
 */
function processTable(buffer, tableOffset, schema, ctx, encrypt) {
  // Read vtable offset (signed, relative)
  const vtableOffsetDelta = readInt32(buffer, tableOffset);
  const vtableOffset = tableOffset - vtableOffsetDelta;

  // Read vtable size
  const vtableSize = readUint16(buffer, vtableOffset);

  // Process each field in schema
  for (const field of schema.fields) {
    const fieldId = field.id;
    const fieldVtableIdx = (fieldId + 2) * 2;

    if (fieldVtableIdx >= vtableSize) continue;

    const fieldOffset = readUint16(buffer, vtableOffset + fieldVtableIdx);
    if (fieldOffset === 0) continue; // Field not present

    const fieldLoc = tableOffset + fieldOffset;

    if (!field.encrypted) {
      // Check for nested tables with encrypted fields
      if (field.type === "table" && field.nestedSchema) {
        const nestedOffset = readUint32(buffer, fieldLoc);
        const nestedTableLoc = fieldLoc + nestedOffset;
        processTable(buffer, nestedTableLoc, field.nestedSchema, ctx, encrypt);
      }
      continue;
    }

    // Encrypt/decrypt based on field type
    const key = ctx.deriveFieldKey(fieldId);
    const iv = ctx.deriveFieldIV(fieldId);

    switch (field.type) {
      case "bool":
      case "byte":
      case "ubyte":
        encryptBytes(buffer.subarray(fieldLoc, fieldLoc + 1), key, iv);
        break;

      case "short":
      case "ushort":
        encryptBytes(buffer.subarray(fieldLoc, fieldLoc + 2), key, iv);
        break;

      case "int":
      case "uint":
      case "float":
        encryptBytes(buffer.subarray(fieldLoc, fieldLoc + 4), key, iv);
        break;

      case "long":
      case "ulong":
      case "double":
        encryptBytes(buffer.subarray(fieldLoc, fieldLoc + 8), key, iv);
        break;

      case "string": {
        const stringOffset = readUint32(buffer, fieldLoc);
        const stringLoc = fieldLoc + stringOffset;
        const stringLen = readUint32(buffer, stringLoc);
        const stringData = stringLoc + 4;
        if (stringData + stringLen <= buffer.length) {
          encryptBytes(buffer.subarray(stringData, stringData + stringLen), key, iv);
        }
        break;
      }

      case "vector": {
        const vecOffset = readUint32(buffer, fieldLoc);
        const vecLoc = fieldLoc + vecOffset;
        const vecLen = readUint32(buffer, vecLoc);
        const vecData = vecLoc + 4;
        const elemSize = field.elementSize || 1;
        const totalSize = vecLen * elemSize;
        if (vecData + totalSize <= buffer.length) {
          encryptBytes(buffer.subarray(vecData, vecData + totalSize), key, iv);
        }
        break;
      }

      case "struct": {
        // Structs are inline, encrypt all bytes
        const structSize = field.structSize || 0;
        if (structSize > 0 && fieldLoc + structSize <= buffer.length) {
          encryptBytes(buffer.subarray(fieldLoc, fieldLoc + structSize), key, iv);
        }
        break;
      }

      default:
        // Unsupported type for encryption
        break;
    }
  }
}

/**
 * Parse schema to extract field encryption info
 * This is a simplified parser that looks for the (encrypted) attribute
 * @param {string} schemaContent - FlatBuffers schema content
 * @param {string} rootType - root type name
 * @returns {Object} - parsed schema with encryption info
 */
export function parseSchemaForEncryption(schemaContent, rootType) {
  const schema = { fields: [] };

  // Find the root table definition
  const tableRegex = new RegExp(`table\\s+${rootType}\\s*\\{([^}]+)\\}`, "s");
  const match = schemaContent.match(tableRegex);

  if (!match) {
    return schema;
  }

  const tableBody = match[1];
  const fieldRegex = /(\w+)\s*:\s*(\[?\w+\]?)\s*(?:\(([^)]*)\))?/g;

  let fieldId = 0;
  let fieldMatch;

  while ((fieldMatch = fieldRegex.exec(tableBody)) !== null) {
    const fieldName = fieldMatch[1];
    const fieldType = fieldMatch[2];
    const attributes = fieldMatch[3] || "";

    const isEncrypted = attributes.includes("encrypted");
    const isVector = fieldType.startsWith("[") && fieldType.endsWith("]");
    const baseType = isVector ? fieldType.slice(1, -1) : fieldType;

    const field = {
      name: fieldName,
      id: fieldId,
      type: isVector ? "vector" : getBaseType(baseType),
      encrypted: isEncrypted,
    };

    if (isVector) {
      field.elementType = getBaseType(baseType);
      field.elementSize = getTypeSize(baseType);
    }

    if (field.type === "struct") {
      // Would need to look up struct definition for size
      field.structSize = 0; // TODO: parse struct definitions
    }

    schema.fields.push(field);
    fieldId++;
  }

  return schema;
}

/**
 * Get base type category
 * @param {string} typeName
 * @returns {string}
 */
function getBaseType(typeName) {
  const scalarTypes = [
    "bool", "byte", "ubyte", "short", "ushort",
    "int", "uint", "long", "ulong", "float", "double",
  ];
  if (scalarTypes.includes(typeName)) {
    return typeName;
  }
  if (typeName === "string") {
    return "string";
  }
  // Assume it's a struct or table
  return "struct";
}

/**
 * Get size of scalar type
 * @param {string} typeName
 * @returns {number}
 */
function getTypeSize(typeName) {
  switch (typeName) {
    case "bool":
    case "byte":
    case "ubyte":
      return 1;
    case "short":
    case "ushort":
      return 2;
    case "int":
    case "uint":
    case "float":
      return 4;
    case "long":
    case "ulong":
    case "double":
      return 8;
    default:
      return 0;
  }
}

/**
 * Encrypt a FlatBuffer in-place
 * @param {Uint8Array} buffer - FlatBuffer to encrypt (modified in-place)
 * @param {Object|string} schema - parsed schema or schema content string
 * @param {Uint8Array|string} key - 32-byte encryption key or hex string
 * @param {string} [rootType] - root type name (required if schema is string)
 * @returns {Uint8Array} - the encrypted buffer (same reference)
 */
export function encryptBuffer(buffer, schema, key, rootType) {
  const ctx = key instanceof EncryptionContext ? key : new EncryptionContext(key);

  if (!ctx.isValid()) {
    throw new Error("Invalid encryption key (must be 32 bytes)");
  }

  let parsedSchema = schema;
  if (typeof schema === "string") {
    if (!rootType) {
      throw new Error("rootType is required when schema is a string");
    }
    parsedSchema = parseSchemaForEncryption(schema, rootType);
  }

  // Read root table offset
  const rootOffset = readUint32(buffer, 0);

  processTable(buffer, rootOffset, parsedSchema, ctx, true);

  return buffer;
}

/**
 * Decrypt a FlatBuffer in-place
 * Same as encryptBuffer since AES-CTR is symmetric
 * @param {Uint8Array} buffer - FlatBuffer to decrypt (modified in-place)
 * @param {Object|string} schema - parsed schema or schema content string
 * @param {Uint8Array|string} key - 32-byte encryption key or hex string
 * @param {string} [rootType] - root type name (required if schema is string)
 * @returns {Uint8Array} - the decrypted buffer (same reference)
 */
export const decryptBuffer = encryptBuffer;

// Export sha256 for use in header_store and other modules
export { sha256 };

export default {
  EncryptionContext,
  encryptBytes,
  decryptBytes,
  encryptScalar,
  encryptBuffer,
  decryptBuffer,
  parseSchemaForEncryption,
  // X25519 ECDH functions
  x25519GenerateKeyPair,
  x25519SharedSecret,
  x25519DeriveKey,
  // secp256k1 ECDH functions
  secp256k1GenerateKeyPair,
  secp256k1SharedSecret,
  secp256k1DeriveKey,
  // P-256 ECDH functions
  p256GenerateKeyPair,
  p256SharedSecret,
  p256DeriveKey,
  // EncryptionHeader functions
  createEncryptionHeader,
  encryptionHeaderToJSON,
  encryptionHeaderFromJSON,
  encryptionHeaderToBinary,
  encryptionHeaderFromBinary,
  computeKeyId,
  // Hash functions
  sha256,
  // Constants
  KeyExchangeAlgorithm,
  SymmetricAlgorithm,
  KeyDerivationFunction,
};
