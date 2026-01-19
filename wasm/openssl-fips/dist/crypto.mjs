/**
 * OpenSSL FIPS Crypto Module - JavaScript API
 * Provides a clean async API over the WebAssembly module
 */

import OpenSSLFIPSFactory from './openssl-fips.mjs';

let Module = null;
let initialized = false;
let fipsMode = false;

// Wrapped functions
let _crypto_init_fips;
let _crypto_init_default;
let _crypto_cleanup;
let _crypto_random_bytes;
let _crypto_hkdf_sha256;
let _crypto_aes256_ctr;
let _crypto_aes256_gcm_encrypt;
let _crypto_aes256_gcm_decrypt;
let _crypto_ecdh_p256_keygen;
let _crypto_ecdh_p256_compute;
let _crypto_sha256;

/**
 * Initialize the crypto module
 * @param {Object} options - { fips: true } for FIPS mode
 */
export async function init(options = {}) {
    if (initialized) return;

    Module = await OpenSSLFIPSFactory();

    // Wrap C functions
    _crypto_init_fips = Module.cwrap('crypto_init_fips', 'number', []);
    _crypto_init_default = Module.cwrap('crypto_init_default', 'number', []);
    _crypto_cleanup = Module.cwrap('crypto_cleanup', null, []);
    _crypto_random_bytes = Module.cwrap('crypto_random_bytes', 'number', ['number', 'number']);
    _crypto_hkdf_sha256 = Module.cwrap('crypto_hkdf_sha256', 'number',
        ['number', 'number', 'number', 'number', 'number', 'number', 'number', 'number']);
    _crypto_aes256_ctr = Module.cwrap('crypto_aes256_ctr', 'number',
        ['number', 'number', 'number', 'number']);
    _crypto_aes256_gcm_encrypt = Module.cwrap('crypto_aes256_gcm_encrypt', 'number',
        ['number', 'number', 'number', 'number', 'number', 'number', 'number', 'number']);
    _crypto_aes256_gcm_decrypt = Module.cwrap('crypto_aes256_gcm_decrypt', 'number',
        ['number', 'number', 'number', 'number', 'number', 'number', 'number', 'number']);
    _crypto_ecdh_p256_keygen = Module.cwrap('crypto_ecdh_p256_keygen', 'number',
        ['number', 'number']);
    _crypto_ecdh_p256_compute = Module.cwrap('crypto_ecdh_p256_compute', 'number',
        ['number', 'number', 'number']);
    _crypto_sha256 = Module.cwrap('crypto_sha256', 'number',
        ['number', 'number', 'number']);

    // Initialize in requested mode
    if (options.fips) {
        const result = _crypto_init_fips();
        if (result === 1) {
            fipsMode = true;
            console.log('[OpenSSL FIPS] Initialized in FIPS mode');
        } else if (result === -1) {
            console.warn('[OpenSSL FIPS] FIPS provider not available, using default provider');
            _crypto_init_default();
            fipsMode = false;
        } else {
            throw new Error('Failed to initialize OpenSSL FIPS');
        }
    } else {
        _crypto_init_default();
        fipsMode = false;
        console.log('[OpenSSL] Initialized in default mode');
    }

    initialized = true;
}

/**
 * Check if running in FIPS mode
 */
export function isFIPSMode() {
    return fipsMode;
}

/**
 * Generate cryptographically secure random bytes
 */
export function randomBytes(length) {
    const ptr = Module._malloc(length);
    try {
        const result = _crypto_random_bytes(ptr, length);
        if (result !== length) {
            throw new Error('Failed to generate random bytes');
        }
        const bytes = new Uint8Array(Module.HEAPU8.buffer, ptr, length);
        return new Uint8Array(bytes); // Copy before free
    } finally {
        Module._free(ptr);
    }
}

/**
 * HKDF-SHA256 key derivation
 * @param {Uint8Array} ikm - Input key material
 * @param {Uint8Array} salt - Salt (can be empty)
 * @param {Uint8Array} info - Context info
 * @param {number} length - Output length
 */
export function hkdf(ikm, salt, info, length) {
    const ikmPtr = copyToHeap(ikm);
    const saltPtr = copyToHeap(salt);
    const infoPtr = copyToHeap(info);
    const okmPtr = Module._malloc(length);

    try {
        const result = _crypto_hkdf_sha256(
            ikmPtr, ikm.length,
            saltPtr, salt.length,
            infoPtr, info.length,
            okmPtr, length
        );

        if (result !== 1) {
            throw new Error('HKDF derivation failed');
        }

        const okm = new Uint8Array(Module.HEAPU8.buffer, okmPtr, length);
        return new Uint8Array(okm);
    } finally {
        Module._free(ikmPtr);
        Module._free(saltPtr);
        Module._free(infoPtr);
        Module._free(okmPtr);
    }
}

/**
 * AES-256-CTR encryption/decryption (in-place, same operation)
 * @param {Uint8Array} data - Data to encrypt/decrypt (modified in place)
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} iv - 16-byte IV
 */
export function aes256ctr(data, key, iv) {
    if (key.length !== 32) throw new Error('Key must be 32 bytes');
    if (iv.length !== 16) throw new Error('IV must be 16 bytes');

    const dataPtr = copyToHeap(data);
    const keyPtr = copyToHeap(key);
    const ivPtr = copyToHeap(iv);

    try {
        const result = _crypto_aes256_ctr(dataPtr, data.length, keyPtr, ivPtr);
        if (result !== 1) {
            throw new Error('AES-256-CTR operation failed');
        }

        // Copy result back to input array
        const output = new Uint8Array(Module.HEAPU8.buffer, dataPtr, data.length);
        data.set(output);
        return data;
    } finally {
        Module._free(dataPtr);
        Module._free(keyPtr);
        Module._free(ivPtr);
    }
}

/**
 * AES-256-GCM authenticated encryption
 * @param {Uint8Array} plaintext
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} iv - 12-byte IV
 * @param {Uint8Array} aad - Additional authenticated data (optional)
 * @returns {{ ciphertext: Uint8Array, tag: Uint8Array }}
 */
export function aes256gcmEncrypt(plaintext, key, iv, aad = new Uint8Array(0)) {
    if (key.length !== 32) throw new Error('Key must be 32 bytes');
    if (iv.length !== 12) throw new Error('IV must be 12 bytes');

    const ptPtr = copyToHeap(plaintext);
    const keyPtr = copyToHeap(key);
    const ivPtr = copyToHeap(iv);
    const aadPtr = copyToHeap(aad);
    const ctPtr = Module._malloc(plaintext.length + 16);
    const tagPtr = Module._malloc(16);

    try {
        const ctLen = _crypto_aes256_gcm_encrypt(
            ptPtr, plaintext.length,
            aadPtr, aad.length,
            keyPtr, ivPtr,
            ctPtr, tagPtr
        );

        if (ctLen < 0) {
            throw new Error('AES-256-GCM encryption failed');
        }

        const ciphertext = new Uint8Array(Module.HEAPU8.buffer, ctPtr, ctLen);
        const tag = new Uint8Array(Module.HEAPU8.buffer, tagPtr, 16);

        return {
            ciphertext: new Uint8Array(ciphertext),
            tag: new Uint8Array(tag)
        };
    } finally {
        Module._free(ptPtr);
        Module._free(keyPtr);
        Module._free(ivPtr);
        Module._free(aadPtr);
        Module._free(ctPtr);
        Module._free(tagPtr);
    }
}

/**
 * AES-256-GCM authenticated decryption
 * @param {Uint8Array} ciphertext
 * @param {Uint8Array} tag - 16-byte authentication tag
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} iv - 12-byte IV
 * @param {Uint8Array} aad - Additional authenticated data (optional)
 * @returns {Uint8Array} plaintext
 * @throws {Error} if authentication fails
 */
export function aes256gcmDecrypt(ciphertext, tag, key, iv, aad = new Uint8Array(0)) {
    if (key.length !== 32) throw new Error('Key must be 32 bytes');
    if (iv.length !== 12) throw new Error('IV must be 12 bytes');
    if (tag.length !== 16) throw new Error('Tag must be 16 bytes');

    const ctPtr = copyToHeap(ciphertext);
    const tagPtr = copyToHeap(tag);
    const keyPtr = copyToHeap(key);
    const ivPtr = copyToHeap(iv);
    const aadPtr = copyToHeap(aad);
    const ptPtr = Module._malloc(ciphertext.length);

    try {
        const ptLen = _crypto_aes256_gcm_decrypt(
            ctPtr, ciphertext.length,
            aadPtr, aad.length,
            keyPtr, ivPtr, tagPtr,
            ptPtr
        );

        if (ptLen < 0) {
            throw new Error('AES-256-GCM decryption failed: authentication error');
        }

        const plaintext = new Uint8Array(Module.HEAPU8.buffer, ptPtr, ptLen);
        return new Uint8Array(plaintext);
    } finally {
        Module._free(ctPtr);
        Module._free(tagPtr);
        Module._free(keyPtr);
        Module._free(ivPtr);
        Module._free(aadPtr);
        Module._free(ptPtr);
    }
}

/**
 * Generate ECDH P-256 key pair
 * @returns {{ privateKey: Uint8Array, publicKey: Uint8Array }}
 */
export function ecdhP256Keygen() {
    const privPtr = Module._malloc(32);
    const pubPtr = Module._malloc(65);

    try {
        const result = _crypto_ecdh_p256_keygen(privPtr, pubPtr);
        if (result !== 1) {
            throw new Error('ECDH key generation failed');
        }

        const privateKey = new Uint8Array(Module.HEAPU8.buffer, privPtr, 32);
        const publicKey = new Uint8Array(Module.HEAPU8.buffer, pubPtr, 65);

        return {
            privateKey: new Uint8Array(privateKey),
            publicKey: new Uint8Array(publicKey)
        };
    } finally {
        Module._free(privPtr);
        Module._free(pubPtr);
    }
}

/**
 * Compute ECDH shared secret
 * @param {Uint8Array} privateKey - 32-byte private key
 * @param {Uint8Array} peerPublicKey - 65-byte public key (uncompressed)
 * @returns {Uint8Array} 32-byte shared secret
 */
export function ecdhP256Compute(privateKey, peerPublicKey) {
    if (privateKey.length !== 32) throw new Error('Private key must be 32 bytes');
    if (peerPublicKey.length !== 65) throw new Error('Public key must be 65 bytes (uncompressed)');

    const privPtr = copyToHeap(privateKey);
    const pubPtr = copyToHeap(peerPublicKey);
    const secretPtr = Module._malloc(32);

    try {
        const result = _crypto_ecdh_p256_compute(privPtr, pubPtr, secretPtr);
        if (result !== 1) {
            throw new Error('ECDH computation failed');
        }

        const secret = new Uint8Array(Module.HEAPU8.buffer, secretPtr, 32);
        return new Uint8Array(secret);
    } finally {
        Module._free(privPtr);
        Module._free(pubPtr);
        Module._free(secretPtr);
    }
}

/**
 * SHA-256 hash
 * @param {Uint8Array} data
 * @returns {Uint8Array} 32-byte hash
 */
export function sha256(data) {
    const dataPtr = copyToHeap(data);
    const hashPtr = Module._malloc(32);

    try {
        const result = _crypto_sha256(dataPtr, data.length, hashPtr);
        if (result !== 1) {
            throw new Error('SHA-256 hash failed');
        }

        const hash = new Uint8Array(Module.HEAPU8.buffer, hashPtr, 32);
        return new Uint8Array(hash);
    } finally {
        Module._free(dataPtr);
        Module._free(hashPtr);
    }
}

/**
 * Cleanup resources
 */
export function cleanup() {
    if (initialized) {
        _crypto_cleanup();
        initialized = false;
        fipsMode = false;
    }
}

// Helper: Copy Uint8Array to WASM heap
function copyToHeap(arr) {
    const ptr = Module._malloc(arr.length);
    Module.HEAPU8.set(arr, ptr);
    return ptr;
}

// Default export for convenience
export default {
    init,
    isFIPSMode,
    randomBytes,
    hkdf,
    aes256ctr,
    aes256gcmEncrypt,
    aes256gcmDecrypt,
    ecdhP256Keygen,
    ecdhP256Compute,
    sha256,
    cleanup
};
