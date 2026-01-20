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
};

/**
 * Supported signature algorithms
 */
enum class SignatureAlgorithm {
  Ed25519 = 0,         // EdDSA with Curve25519
  Secp256k1_ECDSA = 1, // ECDSA with secp256k1 (Bitcoin/Ethereum)
  P256_ECDSA = 2,      // ECDSA with P-256 (NIST)
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
   */
  void DeriveFieldKey(uint16_t field_id, uint8_t* out_key) const;

  /**
   * Derive a field-specific IV using HKDF
   * @param field_id The field's ID from the schema
   * @param out_iv Output buffer for the derived IV (16 bytes)
   */
  void DeriveFieldIV(uint16_t field_id, uint8_t* out_iv) const;

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
 */
void EncryptScalar(uint8_t* value, size_t size,
                   const EncryptionContext& ctx, uint16_t field_id);

/**
 * Encrypt a string value (the content, not the length prefix)
 */
void EncryptString(uint8_t* str, size_t length,
                   const EncryptionContext& ctx, uint16_t field_id);

/**
 * Encrypt a vector of scalars
 */
void EncryptVector(uint8_t* data, size_t element_size, size_t count,
                   const EncryptionContext& ctx, uint16_t field_id);

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

// =============================================================================
// Utility functions
// =============================================================================

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
 */
void DeriveSymmetricKey(
    const uint8_t* shared_secret, size_t shared_secret_size,
    const uint8_t* context, size_t context_size,
    uint8_t* key);

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

}  // namespace flatbuffers

#endif  // FLATBUFFERS_ENCRYPTION_H_
