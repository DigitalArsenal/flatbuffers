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

#include "flatbuffers/flatbuffers.h"
#include "flatbuffers/reflection.h"

namespace flatbuffers {

// Key size for AES-256
constexpr size_t kEncryptionKeySize = 32;

// IV/Nonce size for AES-CTR
constexpr size_t kEncryptionIVSize = 16;

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
 *
 * @param buffer Pointer to the encrypted FlatBuffer data (modified in-place)
 * @param buffer_size Size of the buffer
 * @param schema Compiled binary schema (.bfbs) with encrypted field markers
 * @param schema_size Size of the schema
 * @param ctx Encryption context with the key
 * @return Result indicating success or error
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
 *
 * Same as EncryptBytes (AES-CTR is symmetric)
 */
inline void DecryptBytes(uint8_t* data, size_t size,
                         const uint8_t* key, const uint8_t* iv) {
  EncryptBytes(data, size, key, iv);
}

/**
 * Encrypt a single scalar value
 *
 * @param value Pointer to the scalar value (modified in-place)
 * @param size Size of the scalar (1, 2, 4, or 8 bytes)
 * @param ctx Encryption context
 * @param field_id Field ID for key derivation
 */
void EncryptScalar(uint8_t* value, size_t size,
                   const EncryptionContext& ctx, uint16_t field_id);

/**
 * Encrypt a string value (the content, not the length prefix)
 *
 * @param str Pointer to the string data (after length prefix)
 * @param length Length of the string
 * @param ctx Encryption context
 * @param field_id Field ID for key derivation
 */
void EncryptString(uint8_t* str, size_t length,
                   const EncryptionContext& ctx, uint16_t field_id);

/**
 * Encrypt a vector of scalars
 *
 * @param data Pointer to the vector data (after length prefix)
 * @param element_size Size of each element
 * @param count Number of elements
 * @param ctx Encryption context
 * @param field_id Field ID for key derivation
 */
void EncryptVector(uint8_t* data, size_t element_size, size_t count,
                   const EncryptionContext& ctx, uint16_t field_id);

/**
 * Check if a field has the "encrypted" attribute
 *
 * @param field Field definition from reflection schema
 * @return true if the field should be encrypted
 */
bool IsFieldEncrypted(const reflection::Field* field);

/**
 * Get list of encrypted field IDs from a schema
 *
 * @param schema Compiled binary schema
 * @param schema_size Size of schema
 * @param root_type_name Name of the root type (optional, uses schema default)
 * @return Vector of field IDs that are marked encrypted
 */
std::vector<uint16_t> GetEncryptedFieldIds(
    const uint8_t* schema,
    size_t schema_size,
    const char* root_type_name = nullptr);

// ============================================================================
// Internal implementation details
// ============================================================================

namespace internal {

/**
 * Simple HKDF-like key derivation (SHA-256 based)
 * For production use, consider using a proper crypto library
 */
void DeriveKey(const uint8_t* master_key, size_t master_key_size,
               const uint8_t* info, size_t info_size,
               uint8_t* out_key, size_t out_key_size);

/**
 * AES block cipher (single block)
 * This is a minimal implementation for the CTR mode keystream
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
