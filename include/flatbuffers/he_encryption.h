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

#ifndef FLATBUFFERS_HE_ENCRYPTION_H_
#define FLATBUFFERS_HE_ENCRYPTION_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace flatbuffers {
namespace he {

// =============================================================================
// Constants
// =============================================================================

// Default polynomial modulus degree (affects security and performance)
// 4096 = ~128-bit security, smaller ciphertexts (~2KB)
// 8192 = ~192-bit security, larger ciphertexts (~4KB)
// 16384 = ~256-bit security, largest ciphertexts (~8KB)
constexpr uint32_t kDefaultPolyModulusDegree = 4096;

// Scale factor for fixed-point encoding of floats/doubles
// 2^16 gives ~4-5 decimal digits of precision while fitting
// within the 20-bit BFV plain modulus for typical values
constexpr uint64_t kDefaultFloatScale = 1 << 16;

// =============================================================================
// Error handling
// =============================================================================

enum class HEError {
  kSuccess = 0,
  kInvalidContext,
  kInvalidKey,
  kInvalidCiphertext,
  kEncryptionFailed,
  kDecryptionFailed,
  kOperationFailed,
  kNoSecretKey,
  kSerializationFailed,
  kDeserializationFailed,
  kUnsupportedType,
};

struct HEResult {
  HEError error;
  std::string message;

  bool ok() const { return error == HEError::kSuccess; }

  static HEResult Success() { return {HEError::kSuccess, ""}; }

  static HEResult Error(HEError err, const std::string& msg) {
    return {err, msg};
  }
};

// =============================================================================
// HE Scheme types
// =============================================================================

enum class HEScheme : uint8_t {
  BFV = 0,  // Brakerski/Fan-Vercauteren (integer arithmetic)
  BGV = 1,  // Brakerski-Gentry-Vaikuntanathan (integer arithmetic)
};

// =============================================================================
// Ciphertext header for serialization
// =============================================================================

// Header prepended to serialized ciphertexts in FlatBuffer fields
// Total: 12 bytes header + N bytes SEAL ciphertext data
struct CiphertextHeader {
  uint32_t length;           // Total length including header
  uint8_t scheme;            // HEScheme value
  uint8_t reserved;          // Reserved for future use
  uint16_t poly_degree_log2; // log2(poly_modulus_degree), e.g., 12 for 4096
  uint32_t coeff_count;      // Number of polynomial coefficients
};

static_assert(sizeof(CiphertextHeader) == 12,
              "CiphertextHeader must be 12 bytes");

// =============================================================================
// HEContext - Main interface for homomorphic encryption
// =============================================================================

// Forward declaration for PIMPL
class HEContextImpl;

/**
 * HEContext manages homomorphic encryption keys and operations.
 *
 * Two modes of operation:
 * 1. Client mode (has secret key): Can encrypt and decrypt
 * 2. Server mode (public key only): Can only perform HE operations
 *
 * Example usage:
 *
 *   // Client creates context with secret key
 *   auto client = HEContext::CreateClient();
 *   auto pk = client.GetPublicKey();
 *   auto rk = client.GetRelinKeys();
 *
 *   // Server creates context from public key
 *   auto server = HEContext::CreateServer(pk.data(), pk.size());
 *   server.SetRelinKeys(rk.data(), rk.size());
 *
 *   // Client encrypts
 *   auto ct = client.EncryptInt64(42);
 *
 *   // Server computes (without seeing plaintext)
 *   auto ct2 = client.EncryptInt64(10);
 *   auto result = server.Add(ct, ct2);  // 42 + 10 encrypted
 *
 *   // Client decrypts
 *   int64_t value = client.DecryptInt64(result);  // = 52
 */
class HEContext {
 public:
  ~HEContext();

  // Move only (no copy)
  HEContext(HEContext&& other) noexcept;
  HEContext& operator=(HEContext&& other) noexcept;
  HEContext(const HEContext&) = delete;
  HEContext& operator=(const HEContext&) = delete;

  // -------------------------------------------------------------------------
  // Factory methods
  // -------------------------------------------------------------------------

  /**
   * Create a client context with full key pair (secret + public).
   * @param poly_modulus_degree Power of 2, typically 4096, 8192, or 16384
   * @param scheme BFV or BGV scheme
   * @return Client context that can encrypt, decrypt, and perform operations
   */
  static HEContext CreateClient(
      uint32_t poly_modulus_degree = kDefaultPolyModulusDegree,
      HEScheme scheme = HEScheme::BFV);

  /**
   * Create a server context from serialized public key.
   * Server can only perform homomorphic operations, not decrypt.
   * @param public_key Serialized public key from client
   * @param len Length of public key data
   * @return Server context for computation on ciphertexts
   */
  static HEContext CreateServer(const uint8_t* public_key, size_t len);

  /**
   * Deserialize a full context (client or server) from bytes.
   * @param data Serialized context data
   * @param len Length of data
   * @return Deserialized context
   */
  static HEContext Deserialize(const uint8_t* data, size_t len);

  // -------------------------------------------------------------------------
  // Key management
  // -------------------------------------------------------------------------

  /** Check if context is valid */
  bool IsValid() const;

  /** Check if this context has the secret key (client mode) */
  bool HasSecretKey() const;

  /** Get the HE scheme being used */
  HEScheme GetScheme() const;

  /** Get the polynomial modulus degree */
  uint32_t GetPolyModulusDegree() const;

  /** Serialize public key */
  std::vector<uint8_t> GetPublicKey() const;

  /** Serialize relinearization keys (needed for multiplication) */
  std::vector<uint8_t> GetRelinKeys() const;

  /** Serialize secret key (client only, throws if server mode) */
  std::vector<uint8_t> GetSecretKey() const;

  /** Set relinearization keys (for server context) */
  HEResult SetRelinKeys(const uint8_t* relin_keys, size_t len);

  /** Serialize entire context (keys + parameters) */
  std::vector<uint8_t> Serialize() const;

  // -------------------------------------------------------------------------
  // Encryption (requires client context or public key)
  // -------------------------------------------------------------------------

  std::vector<uint8_t> EncryptInt8(int8_t value) const;
  std::vector<uint8_t> EncryptInt16(int16_t value) const;
  std::vector<uint8_t> EncryptInt32(int32_t value) const;
  std::vector<uint8_t> EncryptInt64(int64_t value) const;
  std::vector<uint8_t> EncryptUInt8(uint8_t value) const;
  std::vector<uint8_t> EncryptUInt16(uint16_t value) const;
  std::vector<uint8_t> EncryptUInt32(uint32_t value) const;
  std::vector<uint8_t> EncryptUInt64(uint64_t value) const;

  // Float/double use fixed-point encoding with configurable scale
  std::vector<uint8_t> EncryptFloat(float value,
                                     uint64_t scale = kDefaultFloatScale) const;
  std::vector<uint8_t> EncryptDouble(double value,
                                      uint64_t scale = kDefaultFloatScale) const;

  // -------------------------------------------------------------------------
  // Decryption (requires secret key - client context only)
  // -------------------------------------------------------------------------

  int8_t DecryptInt8(const uint8_t* ciphertext, size_t len) const;
  int16_t DecryptInt16(const uint8_t* ciphertext, size_t len) const;
  int32_t DecryptInt32(const uint8_t* ciphertext, size_t len) const;
  int64_t DecryptInt64(const uint8_t* ciphertext, size_t len) const;
  uint8_t DecryptUInt8(const uint8_t* ciphertext, size_t len) const;
  uint16_t DecryptUInt16(const uint8_t* ciphertext, size_t len) const;
  uint32_t DecryptUInt32(const uint8_t* ciphertext, size_t len) const;
  uint64_t DecryptUInt64(const uint8_t* ciphertext, size_t len) const;

  float DecryptFloat(const uint8_t* ciphertext, size_t len,
                     uint64_t scale = kDefaultFloatScale) const;
  double DecryptDouble(const uint8_t* ciphertext, size_t len,
                       uint64_t scale = kDefaultFloatScale) const;

  // Convenience overloads taking vector
  int64_t DecryptInt64(const std::vector<uint8_t>& ciphertext) const {
    return DecryptInt64(ciphertext.data(), ciphertext.size());
  }

  // -------------------------------------------------------------------------
  // Homomorphic operations (work with public key only)
  // -------------------------------------------------------------------------

  /** Add two ciphertexts: result = ct1 + ct2 */
  std::vector<uint8_t> Add(const uint8_t* ct1, size_t len1,
                            const uint8_t* ct2, size_t len2) const;

  /** Subtract ciphertexts: result = ct1 - ct2 */
  std::vector<uint8_t> Sub(const uint8_t* ct1, size_t len1,
                            const uint8_t* ct2, size_t len2) const;

  /** Multiply two ciphertexts: result = ct1 * ct2 (requires relin keys) */
  std::vector<uint8_t> Multiply(const uint8_t* ct1, size_t len1,
                                 const uint8_t* ct2, size_t len2) const;

  /** Negate ciphertext: result = -ct */
  std::vector<uint8_t> Negate(const uint8_t* ct, size_t len) const;

  /** Add plaintext to ciphertext: result = ct + plain */
  std::vector<uint8_t> AddPlain(const uint8_t* ct, size_t len,
                                 int64_t plain) const;

  /** Subtract plaintext from ciphertext: result = ct - plain */
  std::vector<uint8_t> SubPlain(const uint8_t* ct, size_t len,
                                 int64_t plain) const;

  /** Multiply ciphertext by plaintext: result = ct * plain */
  std::vector<uint8_t> MultiplyPlain(const uint8_t* ct, size_t len,
                                      int64_t plain) const;

  // Convenience overloads taking vectors
  std::vector<uint8_t> Add(const std::vector<uint8_t>& ct1,
                            const std::vector<uint8_t>& ct2) const {
    return Add(ct1.data(), ct1.size(), ct2.data(), ct2.size());
  }

  std::vector<uint8_t> Multiply(const std::vector<uint8_t>& ct1,
                                 const std::vector<uint8_t>& ct2) const {
    return Multiply(ct1.data(), ct1.size(), ct2.data(), ct2.size());
  }

 private:
  HEContext();
  std::unique_ptr<HEContextImpl> impl_;
};

}  // namespace he
}  // namespace flatbuffers

#endif  // FLATBUFFERS_HE_ENCRYPTION_H_
