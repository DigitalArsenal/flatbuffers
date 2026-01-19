#!/bin/bash
set -e

# OpenSSL FIPS Provider - WebAssembly Build Script
# Compiles OpenSSL 3.x with FIPS Provider to WebAssembly using Emscripten

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
DIST_DIR="${SCRIPT_DIR}/dist"
OPENSSL_VERSION="3.0.9"  # FIPS 140-3 validated version
OPENSSL_DIR="${BUILD_DIR}/openssl-${OPENSSL_VERSION}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    if ! command -v emcc &> /dev/null; then
        log_error "Emscripten (emcc) not found. Please activate emsdk:"
        echo "  source /path/to/emsdk/emsdk_env.sh"
        exit 1
    fi

    if ! command -v perl &> /dev/null; then
        log_error "Perl not found. Required for OpenSSL configure."
        exit 1
    fi

    EMCC_VERSION=$(emcc --version | head -n1)
    log_info "Using $EMCC_VERSION"
}

# Download OpenSSL source
download_openssl() {
    mkdir -p "${BUILD_DIR}"

    if [ -d "${OPENSSL_DIR}" ]; then
        log_info "OpenSSL ${OPENSSL_VERSION} already downloaded"
        return
    fi

    log_info "Downloading OpenSSL ${OPENSSL_VERSION}..."
    cd "${BUILD_DIR}"

    OPENSSL_URL="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"
    curl -L -o "openssl-${OPENSSL_VERSION}.tar.gz" "${OPENSSL_URL}"
    tar -xzf "openssl-${OPENSSL_VERSION}.tar.gz"
    rm "openssl-${OPENSSL_VERSION}.tar.gz"

    log_info "Downloaded and extracted OpenSSL ${OPENSSL_VERSION}"
}

# Configure OpenSSL for Emscripten
configure_openssl() {
    log_info "Configuring OpenSSL for WebAssembly..."
    cd "${OPENSSL_DIR}"

    # Clean previous build if exists
    if [ -f "Makefile" ]; then
        make clean || true
    fi

    # Configure for Emscripten
    # Key flags:
    #   no-asm       - No assembly (required for WASM)
    #   no-threads   - No pthread (simplifies WASM build)
    #   no-shared    - Static libraries only
    #   no-dso       - No dynamic shared objects
    #   no-engine    - No engine support (deprecated in 3.x anyway)
    #   no-async     - No async support (avoids pthread requirements)
    #   enable-fips  - Enable FIPS provider
    #   -Os          - Optimize for size

    emconfigure ./Configure linux-generic32 \
        --prefix="${DIST_DIR}" \
        --openssldir="${DIST_DIR}/ssl" \
        no-asm \
        no-threads \
        no-shared \
        no-dso \
        no-engine \
        no-async \
        no-sock \
        no-dgram \
        no-tests \
        no-ui-console \
        enable-fips \
        -Os \
        -DOPENSSL_NO_SECURE_MEMORY \
        -DOPENSSL_SMALL_FOOTPRINT \
        -D__STDC_NO_ATOMICS__ \
        CFLAGS="-Os -fno-exceptions" \
        CC=emcc \
        AR=emar \
        RANLIB=emranlib

    log_info "OpenSSL configured for WebAssembly build"
}

# Build OpenSSL
build_openssl() {
    log_info "Building OpenSSL (this may take a while)..."
    cd "${OPENSSL_DIR}"

    # Build only libcrypto and the FIPS provider
    # We don't need libssl for our encryption use case
    emmake make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4) build_libs

    log_info "OpenSSL libraries built successfully"
}

# Install to dist directory
install_openssl() {
    log_info "Installing OpenSSL to dist directory..."
    mkdir -p "${DIST_DIR}/lib" "${DIST_DIR}/include"

    cd "${OPENSSL_DIR}"

    # Copy libraries
    cp libcrypto.a "${DIST_DIR}/lib/"

    # Copy FIPS provider if built
    if [ -f "providers/fips.a" ]; then
        cp providers/fips.a "${DIST_DIR}/lib/"
    fi

    # Copy headers
    cp -r include/openssl "${DIST_DIR}/include/"

    log_info "Installation complete"
}

# Create WebAssembly wrapper module
create_wasm_wrapper() {
    log_info "Creating WebAssembly wrapper module..."

    mkdir -p "${DIST_DIR}"

    # Create a C wrapper that exposes the APIs we need
    cat > "${BUILD_DIR}/crypto_wrapper.c" << 'EOF'
/**
 * OpenSSL FIPS Crypto Wrapper for WebAssembly
 * Exposes a simplified API for field-level encryption
 */

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <string.h>
#include <emscripten.h>

// Global context
static OSSL_LIB_CTX *fips_libctx = NULL;
static OSSL_PROVIDER *fips_prov = NULL;
static OSSL_PROVIDER *base_prov = NULL;

/**
 * Initialize OpenSSL FIPS mode
 * Returns 1 on success, 0 on failure
 */
EMSCRIPTEN_KEEPALIVE
int crypto_init_fips(void) {
    // Create a library context for FIPS
    fips_libctx = OSSL_LIB_CTX_new();
    if (fips_libctx == NULL) {
        return 0;
    }

    // Load the FIPS provider
    fips_prov = OSSL_PROVIDER_load(fips_libctx, "fips");
    if (fips_prov == NULL) {
        // FIPS provider not available, fall back to default
        // This allows testing without FIPS but logs a warning
        OSSL_LIB_CTX_free(fips_libctx);
        fips_libctx = NULL;
        return -1; // Indicate fallback mode
    }

    // Load base provider for non-crypto operations
    base_prov = OSSL_PROVIDER_load(fips_libctx, "base");

    return 1;
}

/**
 * Initialize in non-FIPS mode (for development/testing)
 */
EMSCRIPTEN_KEEPALIVE
int crypto_init_default(void) {
    return 1; // OpenSSL default provider is loaded automatically
}

/**
 * Cleanup
 */
EMSCRIPTEN_KEEPALIVE
void crypto_cleanup(void) {
    if (fips_prov) {
        OSSL_PROVIDER_unload(fips_prov);
        fips_prov = NULL;
    }
    if (base_prov) {
        OSSL_PROVIDER_unload(base_prov);
        base_prov = NULL;
    }
    if (fips_libctx) {
        OSSL_LIB_CTX_free(fips_libctx);
        fips_libctx = NULL;
    }
}

/**
 * Generate random bytes
 * Returns number of bytes generated, or -1 on error
 */
EMSCRIPTEN_KEEPALIVE
int crypto_random_bytes(unsigned char *buf, int len) {
    if (RAND_bytes_ex(fips_libctx, buf, len, 0) != 1) {
        return -1;
    }
    return len;
}

/**
 * HKDF key derivation
 * Derives a key using HKDF-SHA256
 * Returns 1 on success, 0 on failure
 */
EMSCRIPTEN_KEEPALIVE
int crypto_hkdf_sha256(
    const unsigned char *ikm, size_t ikm_len,
    const unsigned char *salt, size_t salt_len,
    const unsigned char *info, size_t info_len,
    unsigned char *okm, size_t okm_len
) {
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[5];
    int ret = 0;

    kdf = EVP_KDF_fetch(fips_libctx, "HKDF", NULL);
    if (kdf == NULL) {
        goto cleanup;
    }

    kctx = EVP_KDF_CTX_new(kdf);
    if (kctx == NULL) {
        goto cleanup;
    }

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)ikm, ikm_len);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, salt_len);
    params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)info, info_len);
    params[4] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, okm, okm_len, params) != 1) {
        goto cleanup;
    }

    ret = 1;

cleanup:
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return ret;
}

/**
 * AES-256-CTR encryption/decryption (same operation)
 * Encrypts/decrypts data in place
 * Returns 1 on success, 0 on failure
 */
EMSCRIPTEN_KEEPALIVE
int crypto_aes256_ctr(
    unsigned char *data, size_t data_len,
    const unsigned char *key,  // 32 bytes
    const unsigned char *iv    // 16 bytes
) {
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    int outlen = 0;
    int ret = 0;

    cipher = EVP_CIPHER_fetch(fips_libctx, "AES-256-CTR", NULL);
    if (cipher == NULL) {
        goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        goto cleanup;
    }

    if (EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) != 1) {
        goto cleanup;
    }

    // Process data in place
    if (EVP_EncryptUpdate(ctx, data, &outlen, data, data_len) != 1) {
        goto cleanup;
    }

    ret = 1;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ret;
}

/**
 * AES-256-GCM authenticated encryption
 * Returns ciphertext length on success (includes 16-byte tag), -1 on failure
 */
EMSCRIPTEN_KEEPALIVE
int crypto_aes256_gcm_encrypt(
    const unsigned char *plaintext, size_t plaintext_len,
    const unsigned char *aad, size_t aad_len,
    const unsigned char *key,  // 32 bytes
    const unsigned char *iv,   // 12 bytes
    unsigned char *ciphertext, // plaintext_len + 16 bytes
    unsigned char *tag         // 16 bytes
) {
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    int len = 0;
    int ciphertext_len = 0;
    int ret = -1;

    cipher = EVP_CIPHER_fetch(fips_libctx, "AES-256-GCM", NULL);
    if (cipher == NULL) {
        goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        goto cleanup;
    }

    if (EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) != 1) {
        goto cleanup;
    }

    // Set IV length (12 bytes is recommended for GCM)
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) {
        goto cleanup;
    }

    // Process AAD
    if (aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
            goto cleanup;
        }
    }

    // Encrypt plaintext
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        goto cleanup;
    }
    ciphertext_len = len;

    // Finalize
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        goto cleanup;
    }
    ciphertext_len += len;

    // Get tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        goto cleanup;
    }

    ret = ciphertext_len;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ret;
}

/**
 * AES-256-GCM authenticated decryption
 * Returns plaintext length on success, -1 on failure (including auth failure)
 */
EMSCRIPTEN_KEEPALIVE
int crypto_aes256_gcm_decrypt(
    const unsigned char *ciphertext, size_t ciphertext_len,
    const unsigned char *aad, size_t aad_len,
    const unsigned char *key,  // 32 bytes
    const unsigned char *iv,   // 12 bytes
    const unsigned char *tag,  // 16 bytes
    unsigned char *plaintext
) {
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    int len = 0;
    int plaintext_len = 0;
    int ret = -1;

    cipher = EVP_CIPHER_fetch(fips_libctx, "AES-256-GCM", NULL);
    if (cipher == NULL) {
        goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        goto cleanup;
    }

    if (EVP_DecryptInit_ex2(ctx, cipher, key, iv, NULL) != 1) {
        goto cleanup;
    }

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) {
        goto cleanup;
    }

    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1) {
        goto cleanup;
    }

    // Process AAD
    if (aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
            goto cleanup;
        }
    }

    // Decrypt ciphertext
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        goto cleanup;
    }
    plaintext_len = len;

    // Verify tag
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        // Authentication failed
        goto cleanup;
    }
    plaintext_len += len;

    ret = plaintext_len;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ret;
}

/**
 * ECDH key agreement using P-256 (NIST curve, FIPS approved)
 * Generate a key pair
 * Returns 1 on success, 0 on failure
 */
EMSCRIPTEN_KEEPALIVE
int crypto_ecdh_p256_keygen(
    unsigned char *private_key,  // 32 bytes
    unsigned char *public_key    // 65 bytes (uncompressed point)
) {
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    BIGNUM *priv_bn = NULL;
    size_t pub_len = 65;
    int ret = 0;

    pctx = EVP_PKEY_CTX_new_from_name(fips_libctx, "EC", NULL);
    if (pctx == NULL) {
        goto cleanup;
    }

    if (EVP_PKEY_keygen_init(pctx) != 1) {
        goto cleanup;
    }

    // Set curve to P-256
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) != 1) {
        goto cleanup;
    }

    if (EVP_PKEY_keygen(pctx, &pkey) != 1) {
        goto cleanup;
    }

    // Extract private key
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv_bn) != 1) {
        goto cleanup;
    }
    BN_bn2binpad(priv_bn, private_key, 32);

    // Extract public key (uncompressed)
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                         public_key, 65, &pub_len) != 1) {
        goto cleanup;
    }

    ret = 1;

cleanup:
    BN_free(priv_bn);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

/**
 * ECDH key agreement - compute shared secret
 * Returns 1 on success, 0 on failure
 */
EMSCRIPTEN_KEEPALIVE
int crypto_ecdh_p256_compute(
    const unsigned char *private_key,    // 32 bytes
    const unsigned char *peer_public_key, // 65 bytes
    unsigned char *shared_secret         // 32 bytes output
) {
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *priv_pkey = NULL;
    EVP_PKEY *peer_pkey = NULL;
    OSSL_PARAM params[3];
    size_t secret_len = 32;
    int ret = 0;

    // Build private key
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "P-256", 0);
    params[1] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY, (void *)private_key, 32);
    params[2] = OSSL_PARAM_construct_end();

    pctx = EVP_PKEY_CTX_new_from_name(fips_libctx, "EC", NULL);
    if (EVP_PKEY_fromdata_init(pctx) != 1) {
        goto cleanup;
    }
    if (EVP_PKEY_fromdata(pctx, &priv_pkey, EVP_PKEY_KEYPAIR, params) != 1) {
        goto cleanup;
    }
    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;

    // Build peer's public key
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "P-256", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *)peer_public_key, 65);
    params[2] = OSSL_PARAM_construct_end();

    pctx = EVP_PKEY_CTX_new_from_name(fips_libctx, "EC", NULL);
    if (EVP_PKEY_fromdata_init(pctx) != 1) {
        goto cleanup;
    }
    if (EVP_PKEY_fromdata(pctx, &peer_pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) {
        goto cleanup;
    }
    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;

    // Perform ECDH
    pctx = EVP_PKEY_CTX_new_from_pkey(fips_libctx, priv_pkey, NULL);
    if (EVP_PKEY_derive_init(pctx) != 1) {
        goto cleanup;
    }
    if (EVP_PKEY_derive_set_peer(pctx, peer_pkey) != 1) {
        goto cleanup;
    }
    if (EVP_PKEY_derive(pctx, shared_secret, &secret_len) != 1) {
        goto cleanup;
    }

    ret = 1;

cleanup:
    EVP_PKEY_free(priv_pkey);
    EVP_PKEY_free(peer_pkey);
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

/**
 * SHA-256 hash
 * Returns 1 on success, 0 on failure
 */
EMSCRIPTEN_KEEPALIVE
int crypto_sha256(
    const unsigned char *data, size_t data_len,
    unsigned char *hash  // 32 bytes output
) {
    EVP_MD_CTX *ctx = NULL;
    EVP_MD *md = NULL;
    unsigned int hash_len = 32;
    int ret = 0;

    md = EVP_MD_fetch(fips_libctx, "SHA256", NULL);
    if (md == NULL) {
        goto cleanup;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        goto cleanup;
    }

    if (EVP_DigestInit_ex2(ctx, md, NULL) != 1) {
        goto cleanup;
    }
    if (EVP_DigestUpdate(ctx, data, data_len) != 1) {
        goto cleanup;
    }
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        goto cleanup;
    }

    ret = 1;

cleanup:
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    return ret;
}
EOF

    log_info "Created crypto_wrapper.c"

    # Compile the wrapper with OpenSSL
    cd "${BUILD_DIR}"

    emcc -Os \
        -I"${OPENSSL_DIR}/include" \
        -I"${DIST_DIR}/include" \
        -c crypto_wrapper.c \
        -o crypto_wrapper.o

    # Link everything into a single WebAssembly module
    emcc -Os \
        crypto_wrapper.o \
        "${OPENSSL_DIR}/libcrypto.a" \
        -o "${DIST_DIR}/openssl-fips.mjs" \
        -s WASM=1 \
        -s MODULARIZE=1 \
        -s EXPORT_ES6=1 \
        -s EXPORT_NAME="OpenSSLFIPS" \
        -s EXPORTED_FUNCTIONS='["_crypto_init_fips","_crypto_init_default","_crypto_cleanup","_crypto_random_bytes","_crypto_hkdf_sha256","_crypto_aes256_ctr","_crypto_aes256_gcm_encrypt","_crypto_aes256_gcm_decrypt","_crypto_ecdh_p256_keygen","_crypto_ecdh_p256_compute","_crypto_sha256","_malloc","_free"]' \
        -s EXPORTED_RUNTIME_METHODS='["ccall","cwrap","getValue","setValue","HEAPU8"]' \
        -s ALLOW_MEMORY_GROWTH=1 \
        -s INITIAL_MEMORY=16777216 \
        -s STACK_SIZE=1048576 \
        -s NO_EXIT_RUNTIME=1 \
        --no-entry

    log_info "Created openssl-fips.mjs and openssl-fips.wasm"
}

# Create JavaScript wrapper for easy usage
create_js_wrapper() {
    log_info "Creating JavaScript wrapper..."

    cat > "${DIST_DIR}/crypto.mjs" << 'EOF'
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
EOF

    log_info "Created crypto.mjs wrapper"
}

# Main build sequence
main() {
    log_info "Starting OpenSSL FIPS WebAssembly build"
    log_info "Version: ${OPENSSL_VERSION}"

    check_prerequisites
    download_openssl
    configure_openssl
    build_openssl
    install_openssl
    create_wasm_wrapper
    create_js_wrapper

    log_info ""
    log_info "Build complete!"
    log_info "Output files:"
    log_info "  ${DIST_DIR}/openssl-fips.mjs  - WebAssembly module"
    log_info "  ${DIST_DIR}/openssl-fips.wasm - WebAssembly binary"
    log_info "  ${DIST_DIR}/crypto.mjs        - JavaScript API wrapper"
    log_info ""
    log_info "Usage:"
    log_info "  import crypto from './dist/crypto.mjs';"
    log_info "  await crypto.init({ fips: true });"
    log_info "  const random = crypto.randomBytes(32);"
}

main "$@"
