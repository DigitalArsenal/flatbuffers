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

// WASI-compatible C interface for FlatBuffers encryption
// This file provides a comprehensive crypto API for use with WASI runtimes
// (wazero, wasmtime, wasmer, etc.)
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

#include "flatbuffers/encryption.h"
#include <cstdlib>
#include <cstring>

// Version string
static const char* WASI_VERSION = "2.0.0";

extern "C" {

// =============================================================================
// Module Information
// =============================================================================

// Get the module version
const char* wasi_get_version() {
  return WASI_VERSION;
}

// Check if Crypto++ is available (1 = yes, 0 = no/fallback)
int32_t wasi_has_cryptopp() {
#ifdef FLATBUFFERS_USE_CRYPTOPP
  return 1;
#else
  return 0;
#endif
}

// =============================================================================
// Entropy Management
// =============================================================================

// Inject external entropy into the RNG pool
// This allows JavaScript to provide entropy from crypto.getRandomValues()
// which has better entropy sources than WASM's limited environment
// seed: entropy bytes (recommended: 32-64 bytes)
// size: size of seed data
// Returns 0 on success, -1 on error
int32_t wasi_inject_entropy(const uint8_t* seed, uint32_t size) {
  if (!seed || size == 0) {
    return -1;
  }
  flatbuffers::InjectEntropy(seed, size);
  return 0;
}

// =============================================================================
// Memory Management
// =============================================================================

// Allocate memory (for languages that need to allocate in WASM memory)
// SECURITY FIX (VULN-NEW-006): Use calloc to zero memory before returning
// This prevents potential information leakage from previous allocations
void* wasi_alloc(uint32_t size) {
  return calloc(1, size);  // Zero-initialized allocation
}

// Free memory
void wasi_dealloc(void* ptr) {
  free(ptr);
}

// =============================================================================
// Symmetric Encryption (AES-256-CTR)
// =============================================================================

// Create an encryption context from a 32-byte key
// Returns a pointer to the context, or nullptr on error
void* wasi_encryption_create(const uint8_t* key, uint32_t key_size) {
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

// Destroy an encryption context
void wasi_encryption_destroy(void* ctx) {
  if (ctx) {
    delete static_cast<flatbuffers::EncryptionContext*>(ctx);
  }
}

// Encrypt bytes in-place using AES-256-CTR
// key: 32-byte encryption key
// iv: 16-byte initialization vector
// data: buffer to encrypt (modified in-place)
// size: size of data buffer
// Returns 0 on success, -1 on error
int32_t wasi_encrypt_bytes(const uint8_t* key, const uint8_t* iv,
                           uint8_t* data, uint32_t size) {
  if (!key || !iv || !data || size == 0) {
    return -1;
  }

  flatbuffers::EncryptBytes(data, size, key, iv);
  return 0;
}

// Decrypt bytes in-place using AES-256-CTR (same as encrypt, CTR is symmetric)
int32_t wasi_decrypt_bytes(const uint8_t* key, const uint8_t* iv,
                           uint8_t* data, uint32_t size) {
  return wasi_encrypt_bytes(key, iv, data, size);
}

// Derive a field-specific key from a master key
// ctx: encryption context (from wasi_encryption_create)
// field_id: field identifier for key derivation
// out_key: output buffer for derived key (must be 32 bytes)
// Returns 0 on success, -1 on error
int32_t wasi_derive_field_key(void* ctx, uint16_t field_id, uint8_t* out_key) {
  if (!ctx || !out_key) {
    return -1;
  }

  auto* enc_ctx = static_cast<flatbuffers::EncryptionContext*>(ctx);
  enc_ctx->DeriveFieldKey(field_id, out_key);
  return 0;
}

// Derive a field-specific IV from a master key
// ctx: encryption context (from wasi_encryption_create)
// field_id: field identifier for IV derivation
// out_iv: output buffer for derived IV (must be 16 bytes)
// Returns 0 on success, -1 on error
int32_t wasi_derive_field_iv(void* ctx, uint16_t field_id, uint8_t* out_iv) {
  if (!ctx || !out_iv) {
    return -1;
  }

  auto* enc_ctx = static_cast<flatbuffers::EncryptionContext*>(ctx);
  enc_ctx->DeriveFieldIV(field_id, out_iv);
  return 0;
}

// =============================================================================
// Hash Functions
// =============================================================================

// SHA-256 hash
// data: input data
// data_size: size of input data
// hash: output buffer (must be 32 bytes)
void wasi_sha256(const uint8_t* data, uint32_t data_size, uint8_t* hash) {
  if (data && hash) {
    flatbuffers::Sha256Hash(data, data_size, hash);
  }
}

// HKDF-SHA256 key derivation
// ikm: input key material
// ikm_size: size of IKM
// salt: optional salt (can be NULL)
// salt_size: size of salt (0 if NULL)
// info: optional info/context (can be NULL)
// info_size: size of info (0 if NULL)
// okm: output key material
// okm_size: desired output size
void wasi_hkdf(const uint8_t* ikm, uint32_t ikm_size,
               const uint8_t* salt, uint32_t salt_size,
               const uint8_t* info, uint32_t info_size,
               uint8_t* okm, uint32_t okm_size) {
  if (ikm && okm && okm_size > 0) {
    flatbuffers::HKDF(ikm, ikm_size, salt, salt_size, info, info_size, okm, okm_size);
  }
}

// =============================================================================
// X25519 Key Exchange
// =============================================================================

// Generate X25519 key pair
// private_key: output buffer for private key (32 bytes)
// public_key: output buffer for public key (32 bytes)
// Returns 0 on success, -1 on error
int32_t wasi_x25519_generate_keypair(uint8_t* private_key, uint8_t* public_key) {
  if (!private_key || !public_key) {
    return -1;
  }

  auto kp = flatbuffers::X25519GenerateKeyPair();
  if (!kp.valid()) {
    return -1;
  }

  memcpy(private_key, kp.private_key.data(), flatbuffers::kX25519PrivateKeySize);
  memcpy(public_key, kp.public_key.data(), flatbuffers::kX25519PublicKeySize);
  return 0;
}

// X25519 ECDH key exchange
// private_key: our private key (32 bytes)
// public_key: their public key (32 bytes)
// shared_secret: output buffer (32 bytes)
// Returns 0 on success, -1 on error
int32_t wasi_x25519_shared_secret(const uint8_t* private_key,
                                  const uint8_t* public_key,
                                  uint8_t* shared_secret) {
  if (!private_key || !public_key || !shared_secret) {
    return -1;
  }

  if (flatbuffers::X25519SharedSecret(private_key, public_key, shared_secret)) {
    return 0;
  }
  return -1;
}

// =============================================================================
// secp256k1 Key Exchange and Signatures (Bitcoin/Ethereum)
// =============================================================================

// Generate secp256k1 key pair
// private_key: output buffer for private key (32 bytes)
// public_key: output buffer for compressed public key (33 bytes)
// Returns 0 on success, -1 on error
int32_t wasi_secp256k1_generate_keypair(uint8_t* private_key, uint8_t* public_key) {
  if (!private_key || !public_key) {
    return -1;
  }

  auto kp = flatbuffers::Secp256k1GenerateKeyPair();
  if (!kp.valid()) {
    return -1;
  }

  memcpy(private_key, kp.private_key.data(), flatbuffers::kSecp256k1PrivateKeySize);
  memcpy(public_key, kp.public_key.data(), flatbuffers::kSecp256k1PublicKeySize);
  return 0;
}

// secp256k1 ECDH key exchange
// private_key: our private key (32 bytes)
// public_key: their compressed public key (33 bytes)
// shared_secret: output buffer (32 bytes)
// Returns 0 on success, -1 on error
int32_t wasi_secp256k1_shared_secret(const uint8_t* private_key,
                                     const uint8_t* public_key,
                                     uint32_t public_key_size,
                                     uint8_t* shared_secret) {
  if (!private_key || !public_key || !shared_secret) {
    return -1;
  }

  if (flatbuffers::Secp256k1SharedSecret(private_key, public_key, public_key_size, shared_secret)) {
    return 0;
  }
  return -1;
}

// secp256k1 ECDSA sign
// private_key: signing private key (32 bytes)
// data: data to sign
// data_size: size of data
// signature: output buffer for signature (64 bytes for r||s)
// signature_size: pointer to receive actual signature size
// Returns 0 on success, -1 on error
int32_t wasi_secp256k1_sign(const uint8_t* private_key,
                            const uint8_t* data, uint32_t data_size,
                            uint8_t* signature, uint32_t* signature_size) {
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

// secp256k1 ECDSA verify
// public_key: verification public key (33 bytes compressed)
// public_key_size: size of public key
// data: original data
// data_size: size of data
// signature: signature to verify
// signature_size: size of signature
// Returns 0 if valid, -1 if invalid or error
int32_t wasi_secp256k1_verify(const uint8_t* public_key, uint32_t public_key_size,
                              const uint8_t* data, uint32_t data_size,
                              const uint8_t* signature, uint32_t signature_size) {
  if (!public_key || !data || !signature) {
    return -1;
  }

  if (flatbuffers::Secp256k1Verify(public_key, public_key_size,
                                   data, data_size,
                                   signature, signature_size)) {
    return 0;
  }
  return -1;
}

// =============================================================================
// P-256 Key Exchange and Signatures (NIST)
// =============================================================================

// Generate P-256 key pair
// private_key: output buffer for private key (32 bytes)
// public_key: output buffer for compressed public key (33 bytes)
// Returns 0 on success, -1 on error
int32_t wasi_p256_generate_keypair(uint8_t* private_key, uint8_t* public_key) {
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

// P-256 ECDH key exchange
// private_key: our private key (32 bytes)
// public_key: their compressed public key (33 bytes)
// shared_secret: output buffer (32 bytes)
// Returns 0 on success, -1 on error
int32_t wasi_p256_shared_secret(const uint8_t* private_key,
                                const uint8_t* public_key,
                                uint32_t public_key_size,
                                uint8_t* shared_secret) {
  if (!private_key || !public_key || !shared_secret) {
    return -1;
  }

  if (flatbuffers::P256SharedSecret(private_key, public_key, public_key_size, shared_secret)) {
    return 0;
  }
  return -1;
}

// P-256 ECDSA sign
// private_key: signing private key (32 bytes)
// data: data to sign
// data_size: size of data
// signature: output buffer for signature (64 bytes for r||s)
// signature_size: pointer to receive actual signature size
// Returns 0 on success, -1 on error
int32_t wasi_p256_sign(const uint8_t* private_key,
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

// P-256 ECDSA verify
// public_key: verification public key (33 bytes compressed)
// public_key_size: size of public key
// data: original data
// data_size: size of data
// signature: signature to verify
// signature_size: size of signature
// Returns 0 if valid, -1 if invalid or error
int32_t wasi_p256_verify(const uint8_t* public_key, uint32_t public_key_size,
                         const uint8_t* data, uint32_t data_size,
                         const uint8_t* signature, uint32_t signature_size) {
  if (!public_key || !data || !signature) {
    return -1;
  }

  if (flatbuffers::P256Verify(public_key, public_key_size,
                              data, data_size,
                              signature, signature_size)) {
    return 0;
  }
  return -1;
}

// =============================================================================
// P-384 Key Exchange and Signatures (NIST)
// =============================================================================

// Generate P-384 key pair
// private_key: output buffer for private key (48 bytes)
// public_key: output buffer for compressed public key (49 bytes)
// Returns 0 on success, -1 on error
int32_t wasi_p384_generate_keypair(uint8_t* private_key, uint8_t* public_key) {
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

// P-384 ECDH key exchange
// private_key: our private key (48 bytes)
// public_key: their compressed public key (49 bytes)
// shared_secret: output buffer (32 bytes)
// Returns 0 on success, -1 on error
int32_t wasi_p384_shared_secret(const uint8_t* private_key,
                                const uint8_t* public_key,
                                uint32_t public_key_size,
                                uint8_t* shared_secret) {
  if (!private_key || !public_key || !shared_secret) {
    return -1;
  }

  if (flatbuffers::P384SharedSecret(private_key, public_key, public_key_size, shared_secret)) {
    return 0;
  }
  return -1;
}

// P-384 ECDSA sign
// private_key: signing private key (48 bytes)
// data: data to sign
// data_size: size of data
// signature: output buffer for signature (96 bytes for r||s)
// signature_size: pointer to receive actual signature size
// Returns 0 on success, -1 on error
int32_t wasi_p384_sign(const uint8_t* private_key,
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

// P-384 ECDSA verify
// public_key: verification public key (49 bytes compressed)
// public_key_size: size of public key
// data: original data
// data_size: size of data
// signature: signature to verify
// signature_size: size of signature
// Returns 0 if valid, -1 if invalid or error
int32_t wasi_p384_verify(const uint8_t* public_key, uint32_t public_key_size,
                         const uint8_t* data, uint32_t data_size,
                         const uint8_t* signature, uint32_t signature_size) {
  if (!public_key || !data || !signature) {
    return -1;
  }

  if (flatbuffers::P384Verify(public_key, public_key_size,
                              data, data_size,
                              signature, signature_size)) {
    return 0;
  }
  return -1;
}

// =============================================================================
// Ed25519 Signatures
// =============================================================================

// Generate Ed25519 signing key pair
// private_key: output buffer for private key (64 bytes: seed + public key)
// public_key: output buffer for public key (32 bytes)
// Returns 0 on success, -1 on error
int32_t wasi_ed25519_generate_keypair(uint8_t* private_key, uint8_t* public_key) {
  if (!private_key || !public_key) {
    return -1;
  }

  auto kp = flatbuffers::GenerateSigningKeyPair(flatbuffers::SignatureAlgorithm::Ed25519);
  if (!kp.valid()) {
    return -1;
  }

  memcpy(private_key, kp.private_key.data(), flatbuffers::kEd25519PrivateKeySize);
  memcpy(public_key, kp.public_key.data(), flatbuffers::kEd25519PublicKeySize);
  return 0;
}

// Ed25519 sign
// private_key: signing private key (64 bytes)
// data: data to sign
// data_size: size of data
// signature: output buffer for signature (64 bytes)
// Returns 0 on success, -1 on error
int32_t wasi_ed25519_sign(const uint8_t* private_key,
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

// Ed25519 verify
// public_key: verification public key (32 bytes)
// data: original data
// data_size: size of data
// signature: signature to verify (64 bytes)
// Returns 0 if valid, -1 if invalid or error
int32_t wasi_ed25519_verify(const uint8_t* public_key,
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

// Derive symmetric key from shared secret
// shared_secret: ECDH shared secret (32 bytes)
// context: optional context/info (can be NULL)
// context_size: size of context (0 if NULL)
// key: output buffer for symmetric key (32 bytes)
void wasi_derive_symmetric_key(const uint8_t* shared_secret,
                               const uint8_t* context, uint32_t context_size,
                               uint8_t* key) {
  if (shared_secret && key) {
    flatbuffers::DeriveSymmetricKey(shared_secret, 32, context, context_size, key);
  }
}

}  // extern "C"
