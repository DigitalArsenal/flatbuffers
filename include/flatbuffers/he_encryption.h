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

#include <array>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace flatbuffers {
namespace he {

// =============================================================================
// Constants
// =============================================================================

// Polynomial modulus degree: 8192 (default) or 16384. Each degree is also the
// number of slots per ciphertext. The coefficient modulus chain is SEAL's
// CoeffModulus::BFVDefault(n, tc128) table (the HomomorphicEncryption.org
// security standard, 128-bit classical security, ternary secret):
//   n = 8192:  5 primes of 43, 43, 44, 44, 44 bits (218 bits)
//   n = 16384: 9 primes of 48, 48, 48, 49, 49, 49, 49, 49, 49 bits (438 bits)
// The last prime of each chain is the key-switching prime; the others carry
// ciphertexts. GetCoeffModulusBits() reports the chain of a context.
constexpr uint32_t kDefaultPolyModulusDegree = 8192;

// Number of 60-bit plaintext moduli. A value is the CRT combination of one
// residue per modulus; their product T exceeds 2^179.
constexpr uint32_t kPlainModulusCount = 3;
constexpr int kPlainModulusBits = 60;

// Every slot holds a signed integer v with |v| < 2^kMaxBoundBits.
constexpr uint32_t kMaxBoundBits = 178;

// Default bound (bits) for integer and fixed-point vectors.
constexpr uint32_t kDefaultVectorBoundBits = 64;

// Default fixed-point scale (a power of two).
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
  kOutOfRange,             // a value, bound or result outside the range
  kTooManyValues,          // a vector longer than the slot count
  kInvalidScale,           // a fixed-point scale that is not a power of two
  kNoiseBudgetExhausted,   // a ciphertext that can no longer be decrypted
};

/** Name of an error code, e.g. "kOutOfRange". */
const char* HEErrorName(HEError error);

struct HEResult {
  HEError error;
  std::string message;

  bool ok() const { return error == HEError::kSuccess; }

  static HEResult Success() { return {HEError::kSuccess, ""}; }

  static HEResult Error(HEError err, const std::string& msg) {
    return {err, msg};
  }
};

/** Thrown by decryption; carries the refusal code. */
class HEException : public std::runtime_error {
 public:
  HEException(HEError code, const std::string& message)
      : std::runtime_error(message), code_(code) {}
  HEError code() const { return code_; }

 private:
  HEError code_;
};

// =============================================================================
// WideInt - signed integer with a 192-bit magnitude
// =============================================================================

struct WideInt {
  bool negative = false;
  std::array<uint64_t, 3> magnitude{};  // little-endian limbs

  static WideInt FromInt64(int64_t value);
  static WideInt FromUInt64(uint64_t value);
  /** Parse a decimal string ("-123"); false if malformed or above 2^192. */
  static bool Parse(const std::string& text, WideInt* out);

  bool IsZero() const;
  /** Bit length of the magnitude (0 for zero). */
  uint32_t BitLength() const;
  bool FitsInt64() const;
  int64_t ToInt64() const;  // requires FitsInt64()
  /** Nearest double; exact when the magnitude has <= 53 significant bits. */
  double ToDouble() const;
  std::string ToString() const;
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

// Header prepended to serialized ciphertexts in FlatBuffer fields, followed
// by kPlainModulusCount records (4-byte little-endian size + SEAL ciphertext),
// one per plaintext modulus.
struct CiphertextHeader {
  uint32_t length;           // Total length including header
  uint8_t scheme;            // HEScheme value
  uint8_t bound_bits;        // every slot satisfies |v| < 2^bound_bits
  uint16_t poly_degree_log2; // log2(poly_modulus_degree), e.g., 13 for 8192
  uint32_t coeff_count;      // Number of ciphertext polynomials
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
   * Create a client context with deterministic key generation from a seed.
   * The seed is used to initialize the PRNG, producing the same keys
   * for the same seed. This enables HD wallet → HE key derivation.
   * @param seed Seed bytes (at least 32 bytes)
   * @param seed_len Length of seed data
   * @param poly_modulus_degree Power of 2, typically 4096, 8192, or 16384
   * @param scheme BFV or BGV scheme
   * @return Client context with deterministic keys
   */
  static HEContext CreateClientSeeded(
      const uint8_t* seed, size_t seed_len,
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

  /** Slots per ciphertext (equal to the polynomial modulus degree) */
  uint32_t SlotCount() const;

  /** The kPlainModulusCount plaintext moduli */
  std::vector<uint64_t> GetPlainModuli() const;

  /** Bit sizes of the coefficient modulus primes, key-switching prime last */
  std::vector<int> GetCoeffModulusBits() const;

  /**
   * Result of the last Encrypt* or homomorphic operation on this context.
   * A refusal returns an empty ciphertext and records its code here.
   */
  HEResult LastError() const;

  /** Bound (bits) recorded in a ciphertext header; 0 if malformed */
  static uint32_t CiphertextBoundBits(const uint8_t* ciphertext, size_t len);

  /** Remaining noise budget (bits) of a ciphertext; client only */
  int NoiseBudget(const uint8_t* ciphertext, size_t len) const;

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

  // Float/double use fixed-point encoding: the slot holds round(value * scale)
  // (scale a power of two); refused unless |round(value * scale)| <
  // 2^bound_bits.
  std::vector<uint8_t> EncryptFloat(
      float value, uint64_t scale = kDefaultFloatScale,
      uint32_t bound_bits = kDefaultVectorBoundBits) const;
  std::vector<uint8_t> EncryptDouble(
      double value, uint64_t scale = kDefaultFloatScale,
      uint32_t bound_bits = kDefaultVectorBoundBits) const;

  /** Encrypt one wide integer into slot 0 (|value| < 2^bound_bits) */
  std::vector<uint8_t> EncryptWide(const WideInt& value,
                                   uint32_t bound_bits = kMaxBoundBits) const;

  // Batched: up to SlotCount() values, slot i = values[i], other slots 0.
  std::vector<uint8_t> EncryptInt64Vector(
      const std::vector<int64_t>& values,
      uint32_t bound_bits = kDefaultVectorBoundBits) const;
  std::vector<uint8_t> EncryptWideVector(
      const std::vector<WideInt>& values,
      uint32_t bound_bits = kMaxBoundBits) const;
  std::vector<uint8_t> EncryptDoubleVector(
      const std::vector<double>& values, uint64_t scale = kDefaultFloatScale,
      uint32_t bound_bits = kDefaultVectorBoundBits) const;

  // -------------------------------------------------------------------------
  // Decryption (requires secret key - client context only)
  // Scalar decryption reads slot 0. A slot outside the requested type, or
  // outside the ciphertext's bound, throws HEException(kOutOfRange).
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

  WideInt DecryptWide(const uint8_t* ciphertext, size_t len) const;

  // Batched: all SlotCount() slots.
  std::vector<int64_t> DecryptInt64Vector(const uint8_t* ciphertext,
                                          size_t len) const;
  std::vector<WideInt> DecryptWideVector(const uint8_t* ciphertext,
                                         size_t len) const;
  std::vector<double> DecryptDoubleVector(
      const uint8_t* ciphertext, size_t len,
      uint64_t scale = kDefaultFloatScale) const;

  // Convenience overloads taking vector
  int64_t DecryptInt64(const std::vector<uint8_t>& ciphertext) const {
    return DecryptInt64(ciphertext.data(), ciphertext.size());
  }

  // -------------------------------------------------------------------------
  // Homomorphic operations (work with public key only)
  // Slot-wise; a scalar plain operand applies to every slot. An operation
  // whose result bound would exceed kMaxBoundBits is refused (kOutOfRange).
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
