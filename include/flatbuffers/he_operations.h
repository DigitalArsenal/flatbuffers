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

#ifndef FLATBUFFERS_HE_OPERATIONS_H_
#define FLATBUFFERS_HE_OPERATIONS_H_

#include "flatbuffers/he_encryption.h"

#include <vector>

namespace flatbuffers {
namespace he {

/**
 * @file he_operations.h
 * @brief Standalone homomorphic operation functions.
 *
 * These free functions provide a convenient interface for performing
 * homomorphic operations on serialized ciphertexts. They are thin wrappers
 * around HEContext methods.
 *
 * All operations work on ciphertext data serialized in FlatBuffers format
 * (with CiphertextHeader prefix).
 *
 * Example:
 *   auto client = HEContext::CreateClient();
 *   auto ct1 = client.EncryptInt64(42);
 *   auto ct2 = client.EncryptInt64(10);
 *
 *   // Server-side operations (public key only)
 *   auto server = HEContext::CreateServer(client.GetPublicKey());
 *   auto sum = Add(ct1, ct2, server);     // Encrypted 52
 *   auto prod = Multiply(ct1, ct2, server); // Encrypted 420
 */

// =============================================================================
// Ciphertext-Ciphertext Operations
// =============================================================================

/**
 * Add two ciphertexts homomorphically.
 * @param ct1 First ciphertext (with header)
 * @param ct2 Second ciphertext (with header)
 * @param ctx HE context (public key sufficient)
 * @return Ciphertext containing ct1 + ct2
 */
inline std::vector<uint8_t> Add(const std::vector<uint8_t>& ct1,
                                 const std::vector<uint8_t>& ct2,
                                 const HEContext& ctx) {
  return ctx.Add(ct1.data(), ct1.size(), ct2.data(), ct2.size());
}

/**
 * Subtract two ciphertexts homomorphically.
 * @param ct1 First ciphertext
 * @param ct2 Second ciphertext
 * @param ctx HE context
 * @return Ciphertext containing ct1 - ct2
 */
inline std::vector<uint8_t> Sub(const std::vector<uint8_t>& ct1,
                                 const std::vector<uint8_t>& ct2,
                                 const HEContext& ctx) {
  return ctx.Sub(ct1.data(), ct1.size(), ct2.data(), ct2.size());
}

/**
 * Multiply two ciphertexts homomorphically.
 * Note: Requires relinearization keys to be set in context.
 * @param ct1 First ciphertext
 * @param ct2 Second ciphertext
 * @param ctx HE context (must have relin keys)
 * @return Ciphertext containing ct1 * ct2
 */
inline std::vector<uint8_t> Multiply(const std::vector<uint8_t>& ct1,
                                      const std::vector<uint8_t>& ct2,
                                      const HEContext& ctx) {
  return ctx.Multiply(ct1.data(), ct1.size(), ct2.data(), ct2.size());
}

/**
 * Negate a ciphertext homomorphically.
 * @param ct Ciphertext to negate
 * @param ctx HE context
 * @return Ciphertext containing -ct
 */
inline std::vector<uint8_t> Negate(const std::vector<uint8_t>& ct,
                                    const HEContext& ctx) {
  return ctx.Negate(ct.data(), ct.size());
}

// =============================================================================
// Ciphertext-Plaintext Operations
// =============================================================================

/**
 * Add a plaintext value to a ciphertext.
 * @param ct Ciphertext
 * @param plain Plaintext value to add
 * @param ctx HE context
 * @return Ciphertext containing ct + plain
 */
inline std::vector<uint8_t> AddPlain(const std::vector<uint8_t>& ct,
                                      int64_t plain, const HEContext& ctx) {
  return ctx.AddPlain(ct.data(), ct.size(), plain);
}

/**
 * Subtract a plaintext value from a ciphertext.
 * @param ct Ciphertext
 * @param plain Plaintext value to subtract
 * @param ctx HE context
 * @return Ciphertext containing ct - plain
 */
inline std::vector<uint8_t> SubPlain(const std::vector<uint8_t>& ct,
                                      int64_t plain, const HEContext& ctx) {
  return ctx.SubPlain(ct.data(), ct.size(), plain);
}

/**
 * Multiply a ciphertext by a plaintext value.
 * @param ct Ciphertext
 * @param plain Plaintext multiplier
 * @param ctx HE context
 * @return Ciphertext containing ct * plain
 */
inline std::vector<uint8_t> MultiplyPlain(const std::vector<uint8_t>& ct,
                                           int64_t plain,
                                           const HEContext& ctx) {
  return ctx.MultiplyPlain(ct.data(), ct.size(), plain);
}

// =============================================================================
// Pointer-based overloads (for raw buffer access)
// =============================================================================

inline std::vector<uint8_t> Add(const uint8_t* ct1, size_t len1,
                                 const uint8_t* ct2, size_t len2,
                                 const HEContext& ctx) {
  return ctx.Add(ct1, len1, ct2, len2);
}

inline std::vector<uint8_t> Sub(const uint8_t* ct1, size_t len1,
                                 const uint8_t* ct2, size_t len2,
                                 const HEContext& ctx) {
  return ctx.Sub(ct1, len1, ct2, len2);
}

inline std::vector<uint8_t> Multiply(const uint8_t* ct1, size_t len1,
                                      const uint8_t* ct2, size_t len2,
                                      const HEContext& ctx) {
  return ctx.Multiply(ct1, len1, ct2, len2);
}

inline std::vector<uint8_t> Negate(const uint8_t* ct, size_t len,
                                    const HEContext& ctx) {
  return ctx.Negate(ct, len);
}

inline std::vector<uint8_t> AddPlain(const uint8_t* ct, size_t len,
                                      int64_t plain, const HEContext& ctx) {
  return ctx.AddPlain(ct, len, plain);
}

inline std::vector<uint8_t> SubPlain(const uint8_t* ct, size_t len,
                                      int64_t plain, const HEContext& ctx) {
  return ctx.SubPlain(ct, len, plain);
}

inline std::vector<uint8_t> MultiplyPlain(const uint8_t* ct, size_t len,
                                           int64_t plain,
                                           const HEContext& ctx) {
  return ctx.MultiplyPlain(ct, len, plain);
}

// =============================================================================
// Utility functions
// =============================================================================

/**
 * Check if a byte buffer contains a valid ciphertext header.
 * @param data Pointer to data
 * @param len Length of data
 * @return true if the header looks valid
 */
inline bool IsValidCiphertext(const uint8_t* data, size_t len) {
  if (len < sizeof(CiphertextHeader)) return false;

  const CiphertextHeader* header =
      reinterpret_cast<const CiphertextHeader*>(data);

  // Basic sanity checks
  if (header->length != len) return false;
  if (header->scheme > static_cast<uint8_t>(HEScheme::BGV)) return false;
  if (header->poly_degree_log2 < 10 || header->poly_degree_log2 > 16)
    return false;

  return true;
}

/**
 * Get the scheme from a ciphertext buffer.
 * @param data Pointer to ciphertext data
 * @param len Length of data
 * @return The HE scheme used, or BFV if invalid
 */
inline HEScheme GetCiphertextScheme(const uint8_t* data, size_t len) {
  if (len < sizeof(CiphertextHeader)) return HEScheme::BFV;
  const CiphertextHeader* header =
      reinterpret_cast<const CiphertextHeader*>(data);
  return static_cast<HEScheme>(header->scheme);
}

/**
 * Get the polynomial modulus degree from a ciphertext buffer.
 * @param data Pointer to ciphertext data
 * @param len Length of data
 * @return The polynomial modulus degree, or 0 if invalid
 */
inline uint32_t GetCiphertextPolyDegree(const uint8_t* data, size_t len) {
  if (len < sizeof(CiphertextHeader)) return 0;
  const CiphertextHeader* header =
      reinterpret_cast<const CiphertextHeader*>(data);
  return 1u << header->poly_degree_log2;
}

}  // namespace he
}  // namespace flatbuffers

#endif  // FLATBUFFERS_HE_OPERATIONS_H_
