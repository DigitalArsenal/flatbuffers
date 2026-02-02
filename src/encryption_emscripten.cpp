/*
 * Copyright 2024 Google Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Emscripten-compatible C interface for FlatBuffers encryption
// This file provides EMSCRIPTEN_KEEPALIVE exports with wasm_crypto_* prefix
// for use in the flatc_wasm Emscripten module.
//
// Features:
// - AES-256-CTR symmetric encryption
// - HKDF-SHA256 key derivation
// - X25519 ECDH key exchange
// - secp256k1 ECDH key exchange (Bitcoin/Ethereum compatible)
// - P-256 ECDH key exchange (NIST)
// - P-384 ECDH key exchange (NIST, higher security)
// - Ed25519 signatures
// - ECDSA secp256k1 signatures (Bitcoin/Ethereum compatible)
// - ECDSA P-256 signatures (NIST)
// - ECDSA P-384 signatures (NIST, higher security)
// - Per-field key/IV derivation
// - Entropy injection

#include <emscripten.h>
#include "flatbuffers/encryption.h"
#include <cstdlib>
#include <cstring>

static const char* EMSCRIPTEN_CRYPTO_VERSION = "2.0.0";

extern "C" {

// =============================================================================
// Module Information
// =============================================================================

EMSCRIPTEN_KEEPALIVE
const char* wasm_crypto_get_version() {
  return EMSCRIPTEN_CRYPTO_VERSION;
}

EMSCRIPTEN_KEEPALIVE
int32_t wasm_crypto_has_cryptopp() {
#ifdef FLATBUFFERS_USE_CRYPTOPP
  return 1;
#else
  return 0;
#endif
}

EMSCRIPTEN_KEEPALIVE
int32_t wasm_crypto_has_openssl() {
#ifdef FLATBUFFERS_USE_OPENSSL
  return 1;
#else
  return 0;
#endif
}

// =============================================================================
// Entropy Management
// =============================================================================

EMSCRIPTEN_KEEPALIVE
int32_t wasm_crypto_inject_entropy(const uint8_t* seed, uint32_t size) {
  if (!seed || size == 0) {
    return -1;
  }
  flatbuffers::InjectEntropy(seed, size);
  return 0;
}

// =============================================================================
// Memory Management
// =============================================================================

EMSCRIPTEN_KEEPALIVE
void* wasm_crypto_alloc(uint32_t size) {
  return calloc(1, size);
}

EMSCRIPTEN_KEEPALIVE
void wasm_crypto_dealloc(void* ptr) {
  free(ptr);
}

// =============================================================================
// Symmetric Encryption (AES-256-CTR)
// =============================================================================

EMSCRIPTEN_KEEPALIVE
void* wasm_crypto_encryption_create(const uint8_t* key, uint32_t key_size) {
  if (!key || key_size != flatbuffers::kEncryptionKeySize) {
    return nullptr;
  }

  auto* ctx = new (std::nothrow) flatbuffers::EncryptionContext(key, key_size);
  if (ctx && !ctx->IsValid()) {
    delete ctx;
    return nullptr;
  }
  return ctx;
}

EMSCRIPTEN_KEEPALIVE
void wasm_crypto_encryption_destroy(void* ctx) {
  if (ctx) {
    delete static_cast<flatbuffers::EncryptionContext*>(ctx);
  }
}

EMSCRIPTEN_KEEPALIVE
int32_t wasm_crypto_encrypt_bytes(const uint8_t* key, const uint8_t* iv,
                                   uint8_t* data, uint32_t size) {
  if (!key || !iv || !data || size == 0) {
    return -1;
  }
  flatbuffers::EncryptBytes(data, size, key, iv);
  return 0;
}

EMSCRIPTEN_KEEPALIVE
int32_t wasm_crypto_decrypt_bytes(const uint8_t* key, const uint8_t* iv,
                                   uint8_t* data, uint32_t size) {
  return wasm_crypto_encrypt_bytes(key, iv, data, size);
}

EMSCRIPTEN_KEEPALIVE
int32_t wasm_crypto_derive_field_key(void* ctx, uint16_t field_id,
                                      uint8_t* out_key) {
  if (!ctx || !out_key) {
    return -1;
  }
  auto* enc_ctx = static_cast<flatbuffers::EncryptionContext*>(ctx);
  enc_ctx->DeriveFieldKey(field_id, out_key);
  return 0;
}

EMSCRIPTEN_KEEPALIVE
int32_t wasm_crypto_derive_field_iv(void* ctx, uint16_t field_id,
                                     uint8_t* out_iv) {
  if (!ctx || !out_iv) {
    return -1;
  }
  auto* enc_ctx = static_cast<flatbuffers::EncryptionContext*>(ctx);
  enc_ctx->DeriveFieldIV(field_id, out_iv);
  return 0;
}

// =============================================================================
// Buffer Encryption (per-field, schema-driven)
// =============================================================================

EMSCRIPTEN_KEEPALIVE
int32_t wasm_crypto_encrypt_buffer(uint8_t* buffer, uint32_t buffer_size,
                                    const uint8_t* schema, uint32_t schema_size,
                                    void* ctx) {
  if (!buffer || !schema || !ctx) {
    return -1;
  }
  auto* enc_ctx = static_cast<flatbuffers::EncryptionContext*>(ctx);
  auto result = flatbuffers::EncryptBuffer(buffer, buffer_size, schema,
                                            schema_size, *enc_ctx);
  return result.ok() ? 0 : -1;
}

EMSCRIPTEN_KEEPALIVE
int32_t wasm_crypto_decrypt_buffer(uint8_t* buffer, uint32_t buffer_size,
                                    const uint8_t* schema, uint32_t schema_size,
                                    void* ctx) {
  if (!buffer || !schema || !ctx) {
    return -1;
  }
  auto* enc_ctx = static_cast<flatbuffers::EncryptionContext*>(ctx);
  auto result = flatbuffers::DecryptBuffer(buffer, buffer_size, schema,
                                            schema_size, *enc_ctx);
  return result.ok() ? 0 : -1;
}

// =============================================================================
// Hash Functions
// =============================================================================

EMSCRIPTEN_KEEPALIVE
void wasm_crypto_sha256(const uint8_t* data, uint32_t data_size,
                         uint8_t* hash) {
  if (data && hash) {
    flatbuffers::SHA256(data, data_size, hash);
  }
}

EMSCRIPTEN_KEEPALIVE
void wasm_crypto_hkdf(const uint8_t* ikm, uint32_t ikm_size,
                       const uint8_t* salt, uint32_t salt_size,
                       const uint8_t* info, uint32_t info_size,
                       uint8_t* okm, uint32_t okm_size) {
  if (ikm && okm && okm_size > 0) {
    flatbuffers::HKDF(ikm, ikm_size, salt, salt_size, info, info_size,
                       okm, okm_size);
  }
}

// =============================================================================
// X25519 Key Exchange
// =============================================================================

EMSCRIPTEN_KEEPALIVE
int32_t wasm_crypto_x25519_generate_keypair(uint8_t* private_key,
                                             uint8_t* public_key) {
  if (!private_key || !public_key) {
    return -1;
  }
  auto kp = flatbuffers::X25519GenerateKeyPair();
  if (!kp.valid()) {
    return -1;
  }
  memcpy(private_key, kp.private_key.data(),
         flatbuffers::kX25519PrivateKeySize);
  memcpy(public_key, kp.public_key.data(), flatbuffers::kX25519PublicKeySize);
  return 0;
}

EMSCRIPTEN_KEEPALIVE
int32_t wasm_crypto_x25519_shared_secret(const uint8_t* private_key,
                                          const uint8_t* public_key,
                                          uint8_t* shared_secret) {
  if (!private_key || !public_key || !shared_secret) {
    return -1;
  }
  if (flatbuffers::X25519SharedSecret(private_key, public_key,
                                       shared_secret)) {
    return 0;
  }
  return -1;
}

// =============================================================================
// secp256k1 Key Exchange and Signatures
// =============================================================================

EMSCRIPTEN_KEEPALIVE
int32_t wasm_crypto_secp256k1_generate_keypair(uint8_t* private_key,
                                                uint8_t* public_key) {
  if (!private_key || !public_key) {
    return -1;
  }
  auto kp = flatbuffers::Secp256k1GenerateKeyPair();
  if (!kp.valid()) {
    return -1;
  }
  memcpy(private_key, kp.private_key.data(),
         flatbuffers::kSecp256k1PrivateKeySize);
  memcpy(public_key, kp.public_key.data(),
         flatbuffers::kSecp256k1PublicKeySize);
  return 0;
}

EMSCRIPTEN_KEEPALIVE
int32_t wasm_crypto_secp256k1_shared_secret(const uint8_t* private_key,
                                             const uint8_t* public_key,
                                             uint32_t public_key_size,
                                             uint8_t* shared_secret) {
  if (!private_key || !public_key || !shared_secret) {
    return -1;
  }
  if (flatbuffers::Secp256k1SharedSecret(private_key, public_key,
                                          public_key_size, shared_secret)) {
    return 0;
  }
  return -1;
}

EMSCRIPTEN_KEEPALIVE
int32_t wasm_crypto_secp256k1_sign(const uint8_t* private_key,
                                    const uint8_t* data, uint32_t data_size,
                                    uint8_t* signature,
                                    uint32_t* signature_size) {
  if (!private_key || !data || !signature || !signature_size) {
    return -1;
  }
  auto sig = flatbuffers::Secp256k1Sign(private_key, data, data_size);
  if (!sig.valid()) {
    return -1;
  }
  *signature_size = static_cast<uint32_t>(sig.data.size());
  memcpy(signature, sig.data.data(), sig.data.size());
  return 0;
}

EMSCRIPTEN_KEEPALIVE
int32_t wasm_crypto_secp256k1_verify(const uint8_t* public_key,
                                      uint32_t public_key_size,
                                      const uint8_t* data, uint32_t data_size,
                                      const uint8_t* signature,
                                      uint32_t signature_size) {
  if (!public_key || !data || !signature) {
    return -1;
  }
  if (flatbuffers::Secp256k1Verify(public_key, public_key_size, data,
                                    data_size, signature, signature_size)) {
    return 0;
  }
  return -1;
}

// =============================================================================
// P-256 Key Exchange and Signatures (NIST)
// =============================================================================

EMSCRIPTEN_KEEPALIVE
int32_t wasm_crypto_p256_generate_keypair(uint8_t* private_key,
                                           uint8_t* public_key) {
  if (!private_key || !public_key) {
    return -1;
  }
  auto kp = flatbuffers::P256GenerateKeyPair();
  if (!kp.valid()) {
    return -1;
  }
  memcpy(private_key, kp.private_key.data(), flatbuffers::kP256PrivateKeySize);
  memcpy(public_key, kp.public_key.data(), flatbuffers::kP256PublicKeySize);
  return 0;
}

EMSCRIPTEN_KEEPALIVE
int32_t wasm_crypto_p256_shared_secret(const uint8_t* private_key,
                                        const uint8_t* public_key,
                                        uint32_t public_key_size,
                                        uint8_t* shared_secret) {
  if (!private_key || !public_key || !shared_secret) {
    return -1;
  }
  if (flatbuffers::P256SharedSecret(private_key, public_key, public_key_size,
                                     shared_secret)) {
    return 0;
  }
  return -1;
}

EMSCRIPTEN_KEEPALIVE
int32_t wasm_crypto_p256_sign(const uint8_t* private_key,
                               const uint8_t* data, uint32_t data_size,
                               uint8_t* signature, uint32_t* signature_size) {
  if (!private_key || !data || !signature || !signature_size) {
    return -1;
  }
  auto sig = flatbuffers::P256Sign(private_key, data, data_size);
  if (!sig.valid()) {
    return -1;
  }
  *signature_size = static_cast<uint32_t>(sig.data.size());
  memcpy(signature, sig.data.data(), sig.data.size());
  return 0;
}

EMSCRIPTEN_KEEPALIVE
int32_t wasm_crypto_p256_verify(const uint8_t* public_key,
                                 uint32_t public_key_size,
                                 const uint8_t* data, uint32_t data_size,
                                 const uint8_t* signature,
                                 uint32_t signature_size) {
  if (!public_key || !data || !signature) {
    return -1;
  }
  if (flatbuffers::P256Verify(public_key, public_key_size, data, data_size,
                               signature, signature_size)) {
    return 0;
  }
  return -1;
}

// =============================================================================
// P-384 Key Exchange and Signatures (NIST)
// =============================================================================

EMSCRIPTEN_KEEPALIVE
int32_t wasm_crypto_p384_generate_keypair(uint8_t* private_key,
                                           uint8_t* public_key) {
  if (!private_key || !public_key) {
    return -1;
  }
  auto kp = flatbuffers::P384GenerateKeyPair();
  if (!kp.valid()) {
    return -1;
  }
  memcpy(private_key, kp.private_key.data(), flatbuffers::kP384PrivateKeySize);
  memcpy(public_key, kp.public_key.data(), flatbuffers::kP384PublicKeySize);
  return 0;
}

EMSCRIPTEN_KEEPALIVE
int32_t wasm_crypto_p384_shared_secret(const uint8_t* private_key,
                                        const uint8_t* public_key,
                                        uint32_t public_key_size,
                                        uint8_t* shared_secret) {
  if (!private_key || !public_key || !shared_secret) {
    return -1;
  }
  if (flatbuffers::P384SharedSecret(private_key, public_key, public_key_size,
                                     shared_secret)) {
    return 0;
  }
  return -1;
}

EMSCRIPTEN_KEEPALIVE
int32_t wasm_crypto_p384_sign(const uint8_t* private_key,
                               const uint8_t* data, uint32_t data_size,
                               uint8_t* signature, uint32_t* signature_size) {
  if (!private_key || !data || !signature || !signature_size) {
    return -1;
  }
  auto sig = flatbuffers::P384Sign(private_key, data, data_size);
  if (!sig.valid()) {
    return -1;
  }
  *signature_size = static_cast<uint32_t>(sig.data.size());
  memcpy(signature, sig.data.data(), sig.data.size());
  return 0;
}

EMSCRIPTEN_KEEPALIVE
int32_t wasm_crypto_p384_verify(const uint8_t* public_key,
                                 uint32_t public_key_size,
                                 const uint8_t* data, uint32_t data_size,
                                 const uint8_t* signature,
                                 uint32_t signature_size) {
  if (!public_key || !data || !signature) {
    return -1;
  }
  if (flatbuffers::P384Verify(public_key, public_key_size, data, data_size,
                               signature, signature_size)) {
    return 0;
  }
  return -1;
}

// =============================================================================
// Ed25519 Signatures
// =============================================================================

EMSCRIPTEN_KEEPALIVE
int32_t wasm_crypto_ed25519_generate_keypair(uint8_t* private_key,
                                              uint8_t* public_key) {
  if (!private_key || !public_key) {
    return -1;
  }
  auto kp = flatbuffers::GenerateSigningKeyPair(
      flatbuffers::SignatureAlgorithm::Ed25519);
  if (!kp.valid()) {
    return -1;
  }
  memcpy(private_key, kp.private_key.data(),
         flatbuffers::kEd25519PrivateKeySize);
  memcpy(public_key, kp.public_key.data(), flatbuffers::kEd25519PublicKeySize);
  return 0;
}

EMSCRIPTEN_KEEPALIVE
int32_t wasm_crypto_ed25519_sign(const uint8_t* private_key,
                                  const uint8_t* data, uint32_t data_size,
                                  uint8_t* signature) {
  if (!private_key || !data || !signature) {
    return -1;
  }
  auto sig = flatbuffers::Ed25519Sign(private_key, data, data_size);
  if (!sig.valid()) {
    return -1;
  }
  memcpy(signature, sig.data.data(), flatbuffers::kEd25519SignatureSize);
  return 0;
}

EMSCRIPTEN_KEEPALIVE
int32_t wasm_crypto_ed25519_verify(const uint8_t* public_key,
                                    const uint8_t* data, uint32_t data_size,
                                    const uint8_t* signature) {
  if (!public_key || !data || !signature) {
    return -1;
  }
  if (flatbuffers::Ed25519Verify(public_key, data, data_size, signature)) {
    return 0;
  }
  return -1;
}

// =============================================================================
// Key Derivation Utilities
// =============================================================================

EMSCRIPTEN_KEEPALIVE
void wasm_crypto_derive_symmetric_key(const uint8_t* shared_secret,
                                       const uint8_t* context,
                                       uint32_t context_size, uint8_t* key) {
  if (shared_secret && key) {
    flatbuffers::DeriveSymmetricKey(shared_secret, 32, context, context_size,
                                     key);
  }
}

}  // extern "C"
