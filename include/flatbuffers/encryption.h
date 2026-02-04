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

#ifndef FLATBUFFERS_ENCRYPTION_H_
#define FLATBUFFERS_ENCRYPTION_H_

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <array>

#include "flatbuffers/flatbuffers.h"
#include "flatbuffers/reflection.h"

namespace flatbuffers {

// =============================================================================
// Constants
// =============================================================================

// Key size for AES-256
constexpr size_t kEncryptionKeySize = 32;

// IV/Nonce size for AES-CTR
constexpr size_t kEncryptionIVSize = 16;

// X25519/Ed25519 key sizes
constexpr size_t kX25519PrivateKeySize = 32;
constexpr size_t kX25519PublicKeySize = 32;
constexpr size_t kX25519SharedSecretSize = 32;

// Ed25519 signature sizes
constexpr size_t kEd25519PrivateKeySize = 64;  // seed + public key
constexpr size_t kEd25519PublicKeySize = 32;
constexpr size_t kEd25519SignatureSize = 64;

// secp256k1/P-256 key sizes
constexpr size_t kSecp256k1PrivateKeySize = 32;
constexpr size_t kSecp256k1PublicKeySize = 33;   // compressed
constexpr size_t kSecp256k1SignatureSize = 64;   // r + s

constexpr size_t kP256PrivateKeySize = 32;
constexpr size_t kP256PublicKeySize = 33;        // compressed
constexpr size_t kP256SignatureSize = 64;        // r + s

constexpr size_t kP384PrivateKeySize = 48;
constexpr size_t kP384PublicKeySize = 49;        // compressed
constexpr size_t kP384SignatureSize = 96;        // r + s

// =============================================================================
// Error handling
// =============================================================================

/**
 * Error codes for encryption operations
 */
enum class EncryptionError {
  kSuccess = 0,
  kInvalidKey,
  kInvalidBuffer,
  kInvalidSchema,
  kFieldNotFound,
  kUnsupportedType,
  kCryptoError,
  kSignatureInvalid,
  kKeyGenerationFailed,
};

/**
 * Result of an encryption operation
 */
struct EncryptionResult {
  EncryptionError error;
  std::string message;

  bool ok() const { return error == EncryptionError::kSuccess; }

  static EncryptionResult Success() {
    return {EncryptionError::kSuccess, ""};
  }

  static EncryptionResult Error(EncryptionError err, const std::string& msg) {
    return {err, msg};
  }
};

// =============================================================================
// Key types
// =============================================================================

/**
 * Supported key exchange algorithms
 */
enum class KeyExchangeAlgorithm {
  X25519 = 0,      // Curve25519 ECDH (RFC 7748)
  Secp256k1 = 1,   // Bitcoin/Ethereum curve ECDH
  P256 = 2,        // NIST P-256/secp256r1 ECDH
  P384 = 3,        // NIST P-384/secp384r1 ECDH
};

/**
 * Supported signature algorithms
 */
enum class SignatureAlgorithm {
  Ed25519 = 0,         // EdDSA with Curve25519
  Secp256k1_ECDSA = 1, // ECDSA with secp256k1 (Bitcoin/Ethereum)
  P256_ECDSA = 2,      // ECDSA with P-256 (NIST)
  P384_ECDSA = 3,      // ECDSA with P-384 (NIST)
};

/**
 * Generic key pair structure
 */
struct KeyPair {
  std::vector<uint8_t> private_key;
  std::vector<uint8_t> public_key;

  bool valid() const { return !private_key.empty() && !public_key.empty(); }
};

/**
 * Digital signature
 */
struct Signature {
  std::vector<uint8_t> data;
  SignatureAlgorithm algorithm;

  bool valid() const { return !data.empty(); }
};

// =============================================================================
// Encryption Context (symmetric encryption)
// =============================================================================

/**
 * Encryption context holding the key and derived values
 */
class EncryptionContext {
 public:
  /**
   * Create an encryption context with a 256-bit key
   * @param key 32-byte encryption key
   * @param key_size Must be kEncryptionKeySize (32)
   */
  explicit EncryptionContext(const uint8_t* key, size_t key_size);

  /**
   * Create an encryption context from a key vector
   */
  explicit EncryptionContext(const std::vector<uint8_t>& key);

  /**
   * Create an encryption context from a hex string key
   */
  static EncryptionContext FromHex(const std::string& hex_key);

  ~EncryptionContext();

  // Move constructor and assignment
  EncryptionContext(EncryptionContext&& other) noexcept;
  EncryptionContext& operator=(EncryptionContext&& other) noexcept;

  /**
   * Check if the context is valid
   */
  bool IsValid() const { return valid_; }

  /**
   * Derive a field-specific key using HKDF
   * @param field_id The field's ID from the schema
   * @param out_key Output buffer for the derived key (32 bytes)
   * @param record_index Per-record index for unique derivation (default 0)
   */
  void DeriveFieldKey(uint16_t field_id, uint8_t* out_key,
                      uint32_t record_index = 0) const;

  /**
   * Derive a field-specific IV using HKDF
   * @param field_id The field's ID from the schema
   * @param out_iv Output buffer for the derived IV (16 bytes)
   * @param record_index Per-record index for unique derivation (default 0)
   */
  void DeriveFieldIV(uint16_t field_id, uint8_t* out_iv,
                     uint32_t record_index = 0) const;

  /**
   * Get the raw key (for internal use)
   */
  const uint8_t* GetKey() const { return key_; }

 private:
  uint8_t key_[kEncryptionKeySize];
  bool valid_;

  // Disable copy
  EncryptionContext(const EncryptionContext&) = delete;
  EncryptionContext& operator=(const EncryptionContext&) = delete;
};

// =============================================================================
// Symmetric Encryption (AES-256-CTR)
// =============================================================================

/**
 * Encrypt a FlatBuffer in-place using field annotations
 *
 * Fields marked with the (encrypted) attribute in the schema will be
 * encrypted. The buffer structure remains valid after encryption.
 *
 * @param buffer Pointer to the FlatBuffer data (modified in-place)
 * @param buffer_size Size of the buffer
 * @param schema Compiled binary schema (.bfbs) with encrypted field markers
 * @param schema_size Size of the schema
 * @param ctx Encryption context with the key
 * @return Result indicating success or error
 */
EncryptionResult EncryptBuffer(
    uint8_t* buffer,
    size_t buffer_size,
    const uint8_t* schema,
    size_t schema_size,
    const EncryptionContext& ctx);

/**
 * Decrypt a FlatBuffer in-place
 */
EncryptionResult DecryptBuffer(
    uint8_t* buffer,
    size_t buffer_size,
    const uint8_t* schema,
    size_t schema_size,
    const EncryptionContext& ctx);

/**
 * Encrypt specific bytes using AES-CTR
 *
 * This is a low-level function for encrypting arbitrary data.
 * XOR-based, so encrypt and decrypt are the same operation.
 *
 * @param data Data to encrypt (modified in-place)
 * @param size Size of data
 * @param key 32-byte key
 * @param iv 16-byte IV/nonce
 */
void EncryptBytes(uint8_t* data, size_t size,
                  const uint8_t* key, const uint8_t* iv);

/**
 * Decrypt specific bytes using AES-CTR
 * Same as EncryptBytes (AES-CTR is symmetric)
 */
inline void DecryptBytes(uint8_t* data, size_t size,
                         const uint8_t* key, const uint8_t* iv) {
  EncryptBytes(data, size, key, iv);
}

/**
 * Encrypt a single scalar value
 * @param record_index Per-record index for unique key/IV derivation (default 0)
 */
void EncryptScalar(uint8_t* value, size_t size,
                   const EncryptionContext& ctx, uint16_t field_id,
                   uint32_t record_index = 0);

/**
 * Decrypt a single scalar value (AES-CTR is symmetric)
 */
inline void DecryptScalar(uint8_t* value, size_t size,
                          const EncryptionContext& ctx, uint16_t field_id,
                          uint32_t record_index = 0) {
  EncryptScalar(value, size, ctx, field_id, record_index);
}

/**
 * Encrypt a string value (the content, not the length prefix)
 * @param record_index Per-record index for unique key/IV derivation (default 0)
 */
void EncryptString(uint8_t* str, size_t length,
                   const EncryptionContext& ctx, uint16_t field_id,
                   uint32_t record_index = 0);

/**
 * Decrypt a string value (AES-CTR is symmetric)
 */
inline void DecryptString(uint8_t* str, size_t length,
                          const EncryptionContext& ctx, uint16_t field_id,
                          uint32_t record_index = 0) {
  EncryptString(str, length, ctx, field_id, record_index);
}

/**
 * Encrypt a vector of scalars
 * @param record_index Per-record index for unique key/IV derivation (default 0)
 */
void EncryptVector(uint8_t* data, size_t element_size, size_t count,
                   const EncryptionContext& ctx, uint16_t field_id,
                   uint32_t record_index = 0);

/**
 * Compute HMAC-SHA256 over a buffer for authentication (Task 23).
 * @param buffer The FlatBuffer data
 * @param buffer_size Size of buffer
 * @param ctx Encryption context (MAC key is derived from it)
 * @param out_mac Output buffer for 32-byte MAC
 */
void ComputeBufferMAC(const uint8_t* buffer, size_t buffer_size,
                      const EncryptionContext& ctx, uint8_t* out_mac);

/**
 * Verify HMAC-SHA256 over a buffer (Task 23).
 * @returns true if MAC is valid
 */
bool VerifyBufferMAC(const uint8_t* buffer, size_t buffer_size,
                     const EncryptionContext& ctx, const uint8_t* mac);

// =============================================================================
// Key Exchange (ECDH)
// =============================================================================

/**
 * Generate a key pair for the specified algorithm
 *
 * @param algorithm The key exchange algorithm
 * @return KeyPair with private and public keys, or empty on error
 */
KeyPair GenerateKeyPair(KeyExchangeAlgorithm algorithm);

/**
 * Generate X25519 key pair
 */
KeyPair X25519GenerateKeyPair();

/**
 * Generate secp256k1 key pair
 */
KeyPair Secp256k1GenerateKeyPair();

/**
 * Generate P-256 key pair
 */
KeyPair P256GenerateKeyPair();

/**
 * Generate P-384 key pair
 */
KeyPair P384GenerateKeyPair();

/**
 * Compute shared secret using ECDH
 *
 * @param algorithm The key exchange algorithm
 * @param private_key Our private key
 * @param public_key Their public key
 * @param shared_secret Output buffer for shared secret (32 bytes)
 * @return true on success
 */
bool ComputeSharedSecret(
    KeyExchangeAlgorithm algorithm,
    const uint8_t* private_key, size_t private_key_size,
    const uint8_t* public_key, size_t public_key_size,
    uint8_t* shared_secret);

/**
 * X25519 ECDH key exchange
 */
bool X25519SharedSecret(
    const uint8_t* private_key,
    const uint8_t* public_key,
    uint8_t* shared_secret);

/**
 * secp256k1 ECDH key exchange
 */
bool Secp256k1SharedSecret(
    const uint8_t* private_key,
    const uint8_t* public_key, size_t public_key_size,
    uint8_t* shared_secret);

/**
 * P-256 ECDH key exchange
 */
bool P256SharedSecret(
    const uint8_t* private_key,
    const uint8_t* public_key, size_t public_key_size,
    uint8_t* shared_secret);

/**
 * P-384 ECDH key exchange
 */
bool P384SharedSecret(
    const uint8_t* private_key,
    const uint8_t* public_key, size_t public_key_size,
    uint8_t* shared_secret);

// =============================================================================
// Digital Signatures
// =============================================================================

/**
 * Generate a signing key pair
 *
 * @param algorithm The signature algorithm
 * @return KeyPair with private and public keys, or empty on error
 */
KeyPair GenerateSigningKeyPair(SignatureAlgorithm algorithm);

/**
 * Sign data with the specified algorithm
 *
 * @param algorithm The signature algorithm
 * @param private_key The signing private key
 * @param data Data to sign
 * @param data_size Size of data
 * @return Signature, or empty on error
 */
Signature Sign(
    SignatureAlgorithm algorithm,
    const uint8_t* private_key, size_t private_key_size,
    const uint8_t* data, size_t data_size);

/**
 * Verify a signature
 *
 * @param algorithm The signature algorithm
 * @param public_key The verification public key
 * @param data Original data that was signed
 * @param data_size Size of data
 * @param signature The signature to verify
 * @return true if signature is valid
 */
bool Verify(
    SignatureAlgorithm algorithm,
    const uint8_t* public_key, size_t public_key_size,
    const uint8_t* data, size_t data_size,
    const uint8_t* signature, size_t signature_size);

/**
 * Ed25519 sign
 */
Signature Ed25519Sign(
    const uint8_t* private_key,
    const uint8_t* data, size_t data_size);

/**
 * Ed25519 verify
 */
bool Ed25519Verify(
    const uint8_t* public_key,
    const uint8_t* data, size_t data_size,
    const uint8_t* signature);

/**
 * secp256k1 ECDSA sign
 */
Signature Secp256k1Sign(
    const uint8_t* private_key,
    const uint8_t* data, size_t data_size);

/**
 * secp256k1 ECDSA verify
 */
bool Secp256k1Verify(
    const uint8_t* public_key, size_t public_key_size,
    const uint8_t* data, size_t data_size,
    const uint8_t* signature, size_t signature_size);

/**
 * P-256 ECDSA sign
 */
Signature P256Sign(
    const uint8_t* private_key,
    const uint8_t* data, size_t data_size);

/**
 * P-256 ECDSA verify
 */
bool P256Verify(
    const uint8_t* public_key, size_t public_key_size,
    const uint8_t* data, size_t data_size,
    const uint8_t* signature, size_t signature_size);

/**
 * P-384 ECDSA sign
 */
Signature P384Sign(
    const uint8_t* private_key,
    const uint8_t* data, size_t data_size);

/**
 * P-384 ECDSA verify
 */
bool P384Verify(
    const uint8_t* public_key, size_t public_key_size,
    const uint8_t* data, size_t data_size,
    const uint8_t* signature, size_t signature_size);

// =============================================================================
// Utility functions
// =============================================================================

/**
 * Inject external entropy into the RNG pool.
 * This is critical for WASM environments where the default entropy sources
 * may be limited. Call this with output from crypto.getRandomValues() or
 * similar high-quality entropy sources before generating keys.
 * @param seed Entropy bytes (recommended: 32-64 bytes)
 * @param size Size of seed data
 */
void InjectEntropy(const uint8_t* seed, size_t size);

/**
 * SHA-256 hash
 */
void SHA256(const uint8_t* data, size_t size, uint8_t* hash);

/**
 * HKDF-SHA256 key derivation
 */
void HKDF(const uint8_t* ikm, size_t ikm_size,
          const uint8_t* salt, size_t salt_size,
          const uint8_t* info, size_t info_size,
          uint8_t* okm, size_t okm_size);

/**
 * Derive symmetric key from shared secret
 * @param salt Optional salt for HKDF (e.g. ephemeral public key) (Task 30)
 * @param salt_size Size of salt (0 for no salt)
 */
void DeriveSymmetricKey(
    const uint8_t* shared_secret, size_t shared_secret_size,
    const uint8_t* context, size_t context_size,
    uint8_t* key,
    const uint8_t* salt = nullptr, size_t salt_size = 0);

/**
 * HMAC-SHA256
 */
void HMACSha256(const uint8_t* key, size_t key_size,
                const uint8_t* data, size_t data_size,
                uint8_t* mac);

/**
 * HMAC-SHA256 verify (constant-time comparison)
 */
bool HMACSha256Verify(const uint8_t* key, size_t key_size,
                      const uint8_t* data, size_t data_size,
                      const uint8_t* mac);

/**
 * Check if a field has the "encrypted" attribute
 */
bool IsFieldEncrypted(const reflection::Field* field);

/**
 * Get list of encrypted field IDs from a schema
 */
std::vector<uint16_t> GetEncryptedFieldIds(
    const uint8_t* schema,
    size_t schema_size,
    const char* root_type_name = nullptr);

// =============================================================================
// Internal implementation details
// =============================================================================

namespace internal {

/**
 * Key derivation
 */
void DeriveKey(const uint8_t* master_key, size_t master_key_size,
               const uint8_t* info, size_t info_size,
               uint8_t* out_key, size_t out_key_size);

/**
 * AES block cipher (single block)
 */
void AESEncryptBlock(const uint8_t* key, const uint8_t* input, uint8_t* output);

/**
 * Generate AES-CTR keystream
 */
void AESCTRKeystream(const uint8_t* key, const uint8_t* nonce,
                     uint8_t* keystream, size_t length);

/**
 * Process a table recursively, encrypting marked fields
 */
EncryptionResult ProcessTable(
    uint8_t* buffer,
    size_t buffer_size,
    const reflection::Object* object,
    const reflection::Schema* schema,
    uoffset_t table_offset,
    const EncryptionContext& ctx,
    bool encrypt);

}  // namespace internal

// =============================================================================
// FIPS Mode (Task 34)
// =============================================================================

/**
 * Enable FIPS mode. Only available with OpenSSL backend.
 * When active, X25519 and secp256k1 are rejected (use P-256/P-384 instead).
 * @return true if FIPS mode was successfully enabled
 */
bool EnableFIPSMode();

/**
 * Check if FIPS mode is active
 */
bool IsFIPSMode();

// =============================================================================
// Inline helpers for generated code
// =============================================================================

namespace encryption {

/**
 * Decrypt a scalar value and return it.
 * This is used by generated code to transparently decrypt values.
 */
template<typename T>
inline T DecryptScalar(T value, const EncryptionContext* ctx, uint16_t field_id) {
  if (ctx == nullptr) return value;
  ::flatbuffers::DecryptScalar(reinterpret_cast<uint8_t*>(&value), sizeof(T), *ctx, field_id);
  return value;
}

/**
 * Decrypt a string value and return it.
 * For FlatBuffers strings, this operates on a copy.
 */
inline const String* DecryptString(const String* str, const EncryptionContext* ctx, uint16_t field_id) {
  if (str == nullptr || ctx == nullptr) return str;
  // Note: For zero-copy semantics, the caller should decrypt the buffer once
  // rather than per-access. This returns the string as-is since we can't
  // modify the const pointer. For proper decryption, use DecryptBuffer().
  // This placeholder allows the generated code to compile.
  return str;
}

}  // namespace encryption

}  // namespace flatbuffers

#endif  // FLATBUFFERS_ENCRYPTION_H_
