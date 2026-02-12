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

#include "flatbuffers/he_encryption.h"

#include <cmath>
#include <cstring>
#include <stdexcept>
#include <sstream>

#ifdef FLATBUFFERS_HE_USE_SEAL
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wextra-semi"
#endif
#include <seal/seal.h>
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
#endif

namespace flatbuffers {
namespace he {

// =============================================================================
// HEContextImpl - PIMPL implementation
// =============================================================================

class HEContextImpl {
 public:
#ifdef FLATBUFFERS_HE_USE_SEAL
  // SEAL context and keys
  std::shared_ptr<seal::SEALContext> context_;
  std::unique_ptr<seal::KeyGenerator> keygen_;
  std::unique_ptr<seal::PublicKey> public_key_;
  std::unique_ptr<seal::SecretKey> secret_key_;
  std::unique_ptr<seal::RelinKeys> relin_keys_;
  std::unique_ptr<seal::Encryptor> encryptor_;
  std::unique_ptr<seal::Decryptor> decryptor_;
  std::unique_ptr<seal::Evaluator> evaluator_;
  std::unique_ptr<seal::BatchEncoder> batch_encoder_;
#endif

  HEScheme scheme_ = HEScheme::BFV;
  uint32_t poly_modulus_degree_ = kDefaultPolyModulusDegree;
  bool has_secret_key_ = false;
  bool valid_ = false;

  HEContextImpl() = default;

#ifdef FLATBUFFERS_HE_USE_SEAL
  // Initialize client context with full key generation
  bool InitClient(uint32_t poly_modulus_degree, HEScheme scheme) {
    scheme_ = scheme;
    poly_modulus_degree_ = poly_modulus_degree;

    try {
      // Set up encryption parameters
      seal::EncryptionParameters parms(
          scheme == HEScheme::BFV ? seal::scheme_type::bfv
                                   : seal::scheme_type::bgv);

      parms.set_poly_modulus_degree(poly_modulus_degree);

      // Set coefficient modulus (security level depends on this)
      parms.set_coeff_modulus(
          seal::CoeffModulus::BFVDefault(poly_modulus_degree));

      // Set plain modulus for batching (for BFV/BGV)
      parms.set_plain_modulus(
          seal::PlainModulus::Batching(poly_modulus_degree, 20));

      // Create context
      context_ = std::make_shared<seal::SEALContext>(parms);
      if (!context_->parameters_set()) {
        return false;
      }

      // Generate keys
      keygen_ = std::make_unique<seal::KeyGenerator>(*context_);

      secret_key_ = std::make_unique<seal::SecretKey>(keygen_->secret_key());
      has_secret_key_ = true;

      public_key_ = std::make_unique<seal::PublicKey>();
      keygen_->create_public_key(*public_key_);

      relin_keys_ = std::make_unique<seal::RelinKeys>();
      keygen_->create_relin_keys(*relin_keys_);

      // Create encryptor, decryptor, evaluator
      encryptor_ = std::make_unique<seal::Encryptor>(*context_, *public_key_);
      decryptor_ = std::make_unique<seal::Decryptor>(*context_, *secret_key_);
      evaluator_ = std::make_unique<seal::Evaluator>(*context_);

      // Create batch encoder for integer operations
      batch_encoder_ = std::make_unique<seal::BatchEncoder>(*context_);

      valid_ = true;
      return true;
    } catch (const std::exception&) {
      return false;
    }
  }

  // Initialize client context with deterministic key generation from seed.
  // TODO: SEAL 4.1 KeyGenerator does not accept a custom PRNG directly.
  // For now, this falls back to random key generation. Future SEAL versions
  // may support seeded KeyGenerator construction for deterministic recovery.
  bool InitClientSeeded(const uint8_t* seed, size_t seed_len,
                        uint32_t poly_modulus_degree, HEScheme scheme) {
    (void)seed;
    (void)seed_len;
    // Fall back to random key generation for SEAL 4.1 compatibility
    return InitClient(poly_modulus_degree, scheme);
  }

  // Initialize server context from public key
  bool InitServer(const uint8_t* pk_data, size_t pk_len) {
    try {
      std::stringstream ss;
      ss.write(reinterpret_cast<const char*>(pk_data), pk_len);

      // First read the parameters
      seal::EncryptionParameters parms;
      parms.load(ss);

      context_ = std::make_shared<seal::SEALContext>(parms);
      if (!context_->parameters_set()) {
        return false;
      }

      // Read public key
      public_key_ = std::make_unique<seal::PublicKey>();
      public_key_->load(*context_, ss);

      scheme_ = parms.scheme() == seal::scheme_type::bfv ? HEScheme::BFV
                                                          : HEScheme::BGV;
      poly_modulus_degree_ =
          static_cast<uint32_t>(parms.poly_modulus_degree());

      // Create encryptor and evaluator (no decryptor - no secret key)
      encryptor_ = std::make_unique<seal::Encryptor>(*context_, *public_key_);
      evaluator_ = std::make_unique<seal::Evaluator>(*context_);
      batch_encoder_ = std::make_unique<seal::BatchEncoder>(*context_);

      has_secret_key_ = false;
      valid_ = true;
      return true;
    } catch (const std::exception&) {
      return false;
    }
  }

  std::vector<uint8_t> SerializePublicKey() const {
    if (!valid_ || !public_key_) return {};

    std::stringstream ss;
    // Save parameters first
    context_->key_context_data()->parms().save(ss);
    // Then public key
    public_key_->save(ss);

    std::string str = ss.str();
    return std::vector<uint8_t>(str.begin(), str.end());
  }

  std::vector<uint8_t> SerializeRelinKeys() const {
    if (!valid_ || !relin_keys_) return {};

    std::stringstream ss;
    relin_keys_->save(ss);
    std::string str = ss.str();
    return std::vector<uint8_t>(str.begin(), str.end());
  }

  std::vector<uint8_t> SerializeSecretKey() const {
    if (!valid_ || !secret_key_) return {};

    std::stringstream ss;
    secret_key_->save(ss);
    std::string str = ss.str();
    return std::vector<uint8_t>(str.begin(), str.end());
  }

  bool SetRelinKeys(const uint8_t* data, size_t len) {
    if (!valid_) return false;

    try {
      std::stringstream ss;
      ss.write(reinterpret_cast<const char*>(data), len);
      relin_keys_ = std::make_unique<seal::RelinKeys>();
      relin_keys_->load(*context_, ss);
      return true;
    } catch (const std::exception&) {
      return false;
    }
  }

  std::vector<uint8_t> EncryptInt64(int64_t value) const {
    if (!valid_ || !encryptor_) return {};

    try {
      // Encode the value using batch encoder
      std::vector<int64_t> pod_matrix(batch_encoder_->slot_count(), 0);
      pod_matrix[0] = value;

      seal::Plaintext plain;
      batch_encoder_->encode(pod_matrix, plain);

      seal::Ciphertext cipher;
      encryptor_->encrypt(plain, cipher);

      // Serialize with header
      std::stringstream ss;
      cipher.save(ss);
      std::string cipher_data = ss.str();

      // Build result with header
      CiphertextHeader header;
      header.length =
          static_cast<uint32_t>(sizeof(CiphertextHeader) + cipher_data.size());
      header.scheme = static_cast<uint8_t>(scheme_);
      header.reserved = 0;
      header.poly_degree_log2 = static_cast<uint16_t>(
          static_cast<uint32_t>(std::log2(poly_modulus_degree_)));
      header.coeff_count = static_cast<uint32_t>(cipher.size());

      std::vector<uint8_t> result(header.length);
      std::memcpy(result.data(), &header, sizeof(header));
      std::memcpy(result.data() + sizeof(header), cipher_data.data(),
                  cipher_data.size());

      return result;
    } catch (const std::exception&) {
      return {};
    }
  }

  int64_t DecryptInt64(const uint8_t* data, size_t len) const {
    if (!valid_ || !decryptor_ || len < sizeof(CiphertextHeader)) {
      throw std::runtime_error("Invalid context or ciphertext");
    }

    try {
      // Skip header
      const uint8_t* cipher_data = data + sizeof(CiphertextHeader);
      size_t cipher_len = len - sizeof(CiphertextHeader);

      std::stringstream ss;
      ss.write(reinterpret_cast<const char*>(cipher_data), cipher_len);

      seal::Ciphertext cipher;
      cipher.load(*context_, ss);

      seal::Plaintext plain;
      decryptor_->decrypt(cipher, plain);

      std::vector<int64_t> result;
      batch_encoder_->decode(plain, result);

      return result[0];
    } catch (const std::exception& e) {
      throw std::runtime_error(std::string("Decryption failed: ") + e.what());
    }
  }

  std::vector<uint8_t> Add(const uint8_t* ct1, size_t len1, const uint8_t* ct2,
                            size_t len2) const {
    if (!valid_ || !evaluator_) return {};

    try {
      // Load ciphertexts (skip headers)
      seal::Ciphertext c1, c2;
      {
        std::stringstream ss;
        ss.write(reinterpret_cast<const char*>(ct1 + sizeof(CiphertextHeader)),
                 len1 - sizeof(CiphertextHeader));
        c1.load(*context_, ss);
      }
      {
        std::stringstream ss;
        ss.write(reinterpret_cast<const char*>(ct2 + sizeof(CiphertextHeader)),
                 len2 - sizeof(CiphertextHeader));
        c2.load(*context_, ss);
      }

      // Add in place
      seal::Ciphertext result;
      evaluator_->add(c1, c2, result);

      // Serialize result
      std::stringstream ss;
      result.save(ss);
      std::string cipher_data = ss.str();

      CiphertextHeader header;
      header.length =
          static_cast<uint32_t>(sizeof(CiphertextHeader) + cipher_data.size());
      header.scheme = static_cast<uint8_t>(scheme_);
      header.reserved = 0;
      header.poly_degree_log2 = static_cast<uint16_t>(
          static_cast<uint32_t>(std::log2(poly_modulus_degree_)));
      header.coeff_count = static_cast<uint32_t>(result.size());

      std::vector<uint8_t> out(header.length);
      std::memcpy(out.data(), &header, sizeof(header));
      std::memcpy(out.data() + sizeof(header), cipher_data.data(),
                  cipher_data.size());

      return out;
    } catch (const std::exception&) {
      return {};
    }
  }

  std::vector<uint8_t> Sub(const uint8_t* ct1, size_t len1,
                            const uint8_t* ct2, size_t len2) const {
    if (!valid_ || !evaluator_) return {};

    try {
      seal::Ciphertext c1, c2;
      {
        std::stringstream ss;
        ss.write(reinterpret_cast<const char*>(ct1 + sizeof(CiphertextHeader)),
                 len1 - sizeof(CiphertextHeader));
        c1.load(*context_, ss);
      }
      {
        std::stringstream ss;
        ss.write(reinterpret_cast<const char*>(ct2 + sizeof(CiphertextHeader)),
                 len2 - sizeof(CiphertextHeader));
        c2.load(*context_, ss);
      }

      seal::Ciphertext result;
      evaluator_->sub(c1, c2, result);

      std::stringstream ss;
      result.save(ss);
      std::string cipher_data = ss.str();

      CiphertextHeader header;
      header.length =
          static_cast<uint32_t>(sizeof(CiphertextHeader) + cipher_data.size());
      header.scheme = static_cast<uint8_t>(scheme_);
      header.reserved = 0;
      header.poly_degree_log2 = static_cast<uint16_t>(
          static_cast<uint32_t>(std::log2(poly_modulus_degree_)));
      header.coeff_count = static_cast<uint32_t>(result.size());

      std::vector<uint8_t> out(header.length);
      std::memcpy(out.data(), &header, sizeof(header));
      std::memcpy(out.data() + sizeof(header), cipher_data.data(),
                  cipher_data.size());

      return out;
    } catch (const std::exception&) {
      return {};
    }
  }

  std::vector<uint8_t> Negate(const uint8_t* ct, size_t len) const {
    if (!valid_ || !evaluator_) return {};

    try {
      seal::Ciphertext c;
      {
        std::stringstream ss;
        ss.write(reinterpret_cast<const char*>(ct + sizeof(CiphertextHeader)),
                 len - sizeof(CiphertextHeader));
        c.load(*context_, ss);
      }

      seal::Ciphertext result;
      evaluator_->negate(c, result);

      std::stringstream ss;
      result.save(ss);
      std::string cipher_data = ss.str();

      CiphertextHeader header;
      header.length =
          static_cast<uint32_t>(sizeof(CiphertextHeader) + cipher_data.size());
      header.scheme = static_cast<uint8_t>(scheme_);
      header.reserved = 0;
      header.poly_degree_log2 = static_cast<uint16_t>(
          static_cast<uint32_t>(std::log2(poly_modulus_degree_)));
      header.coeff_count = static_cast<uint32_t>(result.size());

      std::vector<uint8_t> out(header.length);
      std::memcpy(out.data(), &header, sizeof(header));
      std::memcpy(out.data() + sizeof(header), cipher_data.data(),
                  cipher_data.size());

      return out;
    } catch (const std::exception&) {
      return {};
    }
  }

  std::vector<uint8_t> Multiply(const uint8_t* ct1, size_t len1,
                                 const uint8_t* ct2, size_t len2) const {
    if (!valid_ || !evaluator_ || !relin_keys_) return {};

    try {
      seal::Ciphertext c1, c2;
      {
        std::stringstream ss;
        ss.write(reinterpret_cast<const char*>(ct1 + sizeof(CiphertextHeader)),
                 len1 - sizeof(CiphertextHeader));
        c1.load(*context_, ss);
      }
      {
        std::stringstream ss;
        ss.write(reinterpret_cast<const char*>(ct2 + sizeof(CiphertextHeader)),
                 len2 - sizeof(CiphertextHeader));
        c2.load(*context_, ss);
      }

      seal::Ciphertext result;
      evaluator_->multiply(c1, c2, result);
      evaluator_->relinearize_inplace(result, *relin_keys_);

      std::stringstream ss;
      result.save(ss);
      std::string cipher_data = ss.str();

      CiphertextHeader header;
      header.length =
          static_cast<uint32_t>(sizeof(CiphertextHeader) + cipher_data.size());
      header.scheme = static_cast<uint8_t>(scheme_);
      header.reserved = 0;
      header.poly_degree_log2 = static_cast<uint16_t>(
          static_cast<uint32_t>(std::log2(poly_modulus_degree_)));
      header.coeff_count = static_cast<uint32_t>(result.size());

      std::vector<uint8_t> out(header.length);
      std::memcpy(out.data(), &header, sizeof(header));
      std::memcpy(out.data() + sizeof(header), cipher_data.data(),
                  cipher_data.size());

      return out;
    } catch (const std::exception&) {
      return {};
    }
  }

  std::vector<uint8_t> AddPlain(const uint8_t* ct, size_t len,
                                 int64_t plain) const {
    if (!valid_ || !evaluator_) return {};

    try {
      seal::Ciphertext c;
      {
        std::stringstream ss;
        ss.write(reinterpret_cast<const char*>(ct + sizeof(CiphertextHeader)),
                 len - sizeof(CiphertextHeader));
        c.load(*context_, ss);
      }

      std::vector<int64_t> pod_matrix(batch_encoder_->slot_count(), 0);
      pod_matrix[0] = plain;
      seal::Plaintext p;
      batch_encoder_->encode(pod_matrix, p);

      seal::Ciphertext result;
      evaluator_->add_plain(c, p, result);

      std::stringstream ss;
      result.save(ss);
      std::string cipher_data = ss.str();

      CiphertextHeader header;
      header.length =
          static_cast<uint32_t>(sizeof(CiphertextHeader) + cipher_data.size());
      header.scheme = static_cast<uint8_t>(scheme_);
      header.reserved = 0;
      header.poly_degree_log2 = static_cast<uint16_t>(
          static_cast<uint32_t>(std::log2(poly_modulus_degree_)));
      header.coeff_count = static_cast<uint32_t>(result.size());

      std::vector<uint8_t> out(header.length);
      std::memcpy(out.data(), &header, sizeof(header));
      std::memcpy(out.data() + sizeof(header), cipher_data.data(),
                  cipher_data.size());

      return out;
    } catch (const std::exception&) {
      return {};
    }
  }

  std::vector<uint8_t> MultiplyPlain(const uint8_t* ct, size_t len,
                                      int64_t plain) const {
    if (!valid_ || !evaluator_) return {};

    try {
      seal::Ciphertext c;
      {
        std::stringstream ss;
        ss.write(reinterpret_cast<const char*>(ct + sizeof(CiphertextHeader)),
                 len - sizeof(CiphertextHeader));
        c.load(*context_, ss);
      }

      std::vector<int64_t> pod_matrix(batch_encoder_->slot_count(), 0);
      pod_matrix[0] = plain;
      seal::Plaintext p;
      batch_encoder_->encode(pod_matrix, p);

      seal::Ciphertext result;
      evaluator_->multiply_plain(c, p, result);

      std::stringstream ss;
      result.save(ss);
      std::string cipher_data = ss.str();

      CiphertextHeader header;
      header.length =
          static_cast<uint32_t>(sizeof(CiphertextHeader) + cipher_data.size());
      header.scheme = static_cast<uint8_t>(scheme_);
      header.reserved = 0;
      header.poly_degree_log2 = static_cast<uint16_t>(
          static_cast<uint32_t>(std::log2(poly_modulus_degree_)));
      header.coeff_count = static_cast<uint32_t>(result.size());

      std::vector<uint8_t> out(header.length);
      std::memcpy(out.data(), &header, sizeof(header));
      std::memcpy(out.data() + sizeof(header), cipher_data.data(),
                  cipher_data.size());

      return out;
    } catch (const std::exception&) {
      return {};
    }
  }

#else
  // Stub implementations when SEAL is not available
  bool InitClient(uint32_t poly_modulus_degree, HEScheme scheme) {
    scheme_ = scheme;
    poly_modulus_degree_ = poly_modulus_degree;
    // Without SEAL, we can't actually do HE
    valid_ = false;
    return false;
  }

  bool InitClientSeeded(const uint8_t*, size_t, uint32_t poly_modulus_degree,
                        HEScheme scheme) {
    scheme_ = scheme;
    poly_modulus_degree_ = poly_modulus_degree;
    valid_ = false;
    return false;
  }

  bool InitServer(const uint8_t*, size_t) { return false; }

  std::vector<uint8_t> SerializePublicKey() const { return {}; }
  std::vector<uint8_t> SerializeRelinKeys() const { return {}; }
  std::vector<uint8_t> SerializeSecretKey() const { return {}; }
  bool SetRelinKeys(const uint8_t*, size_t) { return false; }

  std::vector<uint8_t> EncryptInt64(int64_t) const { return {}; }
  int64_t DecryptInt64(const uint8_t*, size_t) const {
    throw std::runtime_error("SEAL not available");
  }

  std::vector<uint8_t> Add(const uint8_t*, size_t, const uint8_t*,
                            size_t) const {
    return {};
  }
  std::vector<uint8_t> Sub(const uint8_t*, size_t, const uint8_t*,
                            size_t) const {
    return {};
  }
  std::vector<uint8_t> Negate(const uint8_t*, size_t) const { return {}; }
  std::vector<uint8_t> Multiply(const uint8_t*, size_t, const uint8_t*,
                                 size_t) const {
    return {};
  }
  std::vector<uint8_t> AddPlain(const uint8_t*, size_t, int64_t) const {
    return {};
  }
  std::vector<uint8_t> MultiplyPlain(const uint8_t*, size_t, int64_t) const {
    return {};
  }
#endif
};

// =============================================================================
// HEContext public interface implementation
// =============================================================================

HEContext::HEContext() : impl_(std::make_unique<HEContextImpl>()) {}

HEContext::~HEContext() = default;

HEContext::HEContext(HEContext&& other) noexcept = default;
HEContext& HEContext::operator=(HEContext&& other) noexcept = default;

HEContext HEContext::CreateClient(uint32_t poly_modulus_degree,
                                   HEScheme scheme) {
  HEContext ctx;
  ctx.impl_->InitClient(poly_modulus_degree, scheme);
  return ctx;
}

HEContext HEContext::CreateClientSeeded(const uint8_t* seed, size_t seed_len,
                                         uint32_t poly_modulus_degree,
                                         HEScheme scheme) {
  HEContext ctx;
  ctx.impl_->InitClientSeeded(seed, seed_len, poly_modulus_degree, scheme);
  return ctx;
}

HEContext HEContext::CreateServer(const uint8_t* public_key, size_t len) {
  HEContext ctx;
  ctx.impl_->InitServer(public_key, len);
  return ctx;
}

HEContext HEContext::Deserialize(const uint8_t* data, size_t len) {
  // For now, treat as server context (public key only)
  return CreateServer(data, len);
}

bool HEContext::IsValid() const { return impl_->valid_; }

bool HEContext::HasSecretKey() const { return impl_->has_secret_key_; }

HEScheme HEContext::GetScheme() const { return impl_->scheme_; }

uint32_t HEContext::GetPolyModulusDegree() const {
  return impl_->poly_modulus_degree_;
}

std::vector<uint8_t> HEContext::GetPublicKey() const {
  return impl_->SerializePublicKey();
}

std::vector<uint8_t> HEContext::GetRelinKeys() const {
  return impl_->SerializeRelinKeys();
}

std::vector<uint8_t> HEContext::GetSecretKey() const {
  if (!impl_->has_secret_key_) {
    throw std::runtime_error("No secret key available (server context)");
  }
  return impl_->SerializeSecretKey();
}

HEResult HEContext::SetRelinKeys(const uint8_t* relin_keys, size_t len) {
  if (impl_->SetRelinKeys(relin_keys, len)) {
    return HEResult::Success();
  }
  return HEResult::Error(HEError::kDeserializationFailed,
                          "Failed to load relin keys");
}

std::vector<uint8_t> HEContext::Serialize() const {
  return GetPublicKey();  // Simplified: just public key for now
}

// Encryption methods (delegate to impl)
std::vector<uint8_t> HEContext::EncryptInt8(int8_t value) const {
  return impl_->EncryptInt64(static_cast<int64_t>(value));
}

std::vector<uint8_t> HEContext::EncryptInt16(int16_t value) const {
  return impl_->EncryptInt64(static_cast<int64_t>(value));
}

std::vector<uint8_t> HEContext::EncryptInt32(int32_t value) const {
  return impl_->EncryptInt64(static_cast<int64_t>(value));
}

std::vector<uint8_t> HEContext::EncryptInt64(int64_t value) const {
  return impl_->EncryptInt64(value);
}

std::vector<uint8_t> HEContext::EncryptUInt8(uint8_t value) const {
  return impl_->EncryptInt64(static_cast<int64_t>(value));
}

std::vector<uint8_t> HEContext::EncryptUInt16(uint16_t value) const {
  return impl_->EncryptInt64(static_cast<int64_t>(value));
}

std::vector<uint8_t> HEContext::EncryptUInt32(uint32_t value) const {
  return impl_->EncryptInt64(static_cast<int64_t>(value));
}

std::vector<uint8_t> HEContext::EncryptUInt64(uint64_t value) const {
  // Note: Large uint64 values may overflow when cast to int64
  return impl_->EncryptInt64(static_cast<int64_t>(value));
}

std::vector<uint8_t> HEContext::EncryptFloat(float value, uint64_t scale) const {
  // Fixed-point encoding: multiply by scale and round
  int64_t scaled = static_cast<int64_t>(std::round(value * scale));
  return impl_->EncryptInt64(scaled);
}

std::vector<uint8_t> HEContext::EncryptDouble(double value,
                                               uint64_t scale) const {
  int64_t scaled = static_cast<int64_t>(std::round(value * scale));
  return impl_->EncryptInt64(scaled);
}

// Decryption methods
int8_t HEContext::DecryptInt8(const uint8_t* ct, size_t len) const {
  return static_cast<int8_t>(impl_->DecryptInt64(ct, len));
}

int16_t HEContext::DecryptInt16(const uint8_t* ct, size_t len) const {
  return static_cast<int16_t>(impl_->DecryptInt64(ct, len));
}

int32_t HEContext::DecryptInt32(const uint8_t* ct, size_t len) const {
  return static_cast<int32_t>(impl_->DecryptInt64(ct, len));
}

int64_t HEContext::DecryptInt64(const uint8_t* ct, size_t len) const {
  return impl_->DecryptInt64(ct, len);
}

uint8_t HEContext::DecryptUInt8(const uint8_t* ct, size_t len) const {
  return static_cast<uint8_t>(impl_->DecryptInt64(ct, len));
}

uint16_t HEContext::DecryptUInt16(const uint8_t* ct, size_t len) const {
  return static_cast<uint16_t>(impl_->DecryptInt64(ct, len));
}

uint32_t HEContext::DecryptUInt32(const uint8_t* ct, size_t len) const {
  return static_cast<uint32_t>(impl_->DecryptInt64(ct, len));
}

uint64_t HEContext::DecryptUInt64(const uint8_t* ct, size_t len) const {
  return static_cast<uint64_t>(impl_->DecryptInt64(ct, len));
}

float HEContext::DecryptFloat(const uint8_t* ct, size_t len,
                               uint64_t scale) const {
  int64_t scaled = impl_->DecryptInt64(ct, len);
  return static_cast<float>(scaled) / static_cast<float>(scale);
}

double HEContext::DecryptDouble(const uint8_t* ct, size_t len,
                                 uint64_t scale) const {
  int64_t scaled = impl_->DecryptInt64(ct, len);
  return static_cast<double>(scaled) / static_cast<double>(scale);
}

// Homomorphic operations
std::vector<uint8_t> HEContext::Add(const uint8_t* ct1, size_t len1,
                                     const uint8_t* ct2, size_t len2) const {
  return impl_->Add(ct1, len1, ct2, len2);
}

std::vector<uint8_t> HEContext::Sub(const uint8_t* ct1, size_t len1,
                                     const uint8_t* ct2, size_t len2) const {
  return impl_->Sub(ct1, len1, ct2, len2);
}

std::vector<uint8_t> HEContext::Multiply(const uint8_t* ct1, size_t len1,
                                          const uint8_t* ct2,
                                          size_t len2) const {
  return impl_->Multiply(ct1, len1, ct2, len2);
}

std::vector<uint8_t> HEContext::Negate(const uint8_t* ct, size_t len) const {
  return impl_->Negate(ct, len);
}

std::vector<uint8_t> HEContext::AddPlain(const uint8_t* ct, size_t len,
                                          int64_t plain) const {
  return impl_->AddPlain(ct, len, plain);
}

std::vector<uint8_t> HEContext::SubPlain(const uint8_t* ct, size_t len,
                                          int64_t plain) const {
  return AddPlain(ct, len, -plain);
}

std::vector<uint8_t> HEContext::MultiplyPlain(const uint8_t* ct, size_t len,
                                               int64_t plain) const {
  return impl_->MultiplyPlain(ct, len, plain);
}

}  // namespace he
}  // namespace flatbuffers
