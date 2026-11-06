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
#include "flatbuffers/encryption.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <sstream>
#include <stdexcept>

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
// Error names
// =============================================================================

const char* HEErrorName(HEError error) {
  switch (error) {
    case HEError::kSuccess: return "kSuccess";
    case HEError::kInvalidContext: return "kInvalidContext";
    case HEError::kInvalidKey: return "kInvalidKey";
    case HEError::kInvalidCiphertext: return "kInvalidCiphertext";
    case HEError::kEncryptionFailed: return "kEncryptionFailed";
    case HEError::kDecryptionFailed: return "kDecryptionFailed";
    case HEError::kOperationFailed: return "kOperationFailed";
    case HEError::kNoSecretKey: return "kNoSecretKey";
    case HEError::kSerializationFailed: return "kSerializationFailed";
    case HEError::kDeserializationFailed: return "kDeserializationFailed";
    case HEError::kUnsupportedType: return "kUnsupportedType";
    case HEError::kOutOfRange: return "kOutOfRange";
    case HEError::kTooManyValues: return "kTooManyValues";
    case HEError::kInvalidScale: return "kInvalidScale";
    case HEError::kNoiseBudgetExhausted: return "kNoiseBudgetExhausted";
  }
  return "kUnknown";
}

// =============================================================================
// 192-bit helpers and WideInt
// =============================================================================

namespace {

using u128 = unsigned __int128;
using Limbs = std::array<uint64_t, 3>;

int CompareLimbs(const Limbs& a, const Limbs& b) {
  for (int i = 2; i >= 0; --i) {
    if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return 0;
}

Limbs AddLimbs(const Limbs& a, const Limbs& b) {
  Limbs r{};
  u128 carry = 0;
  for (int i = 0; i < 3; ++i) {
    const u128 s = static_cast<u128>(a[i]) + b[i] + carry;
    r[i] = static_cast<uint64_t>(s);
    carry = s >> 64;
  }
  return r;
}

// a - b, requires a >= b.
Limbs SubLimbs(const Limbs& a, const Limbs& b) {
  Limbs r{};
  uint64_t borrow = 0;
  for (int i = 0; i < 3; ++i) {
    const u128 sub = static_cast<u128>(b[i]) + borrow;
    r[i] = static_cast<uint64_t>(static_cast<u128>(a[i]) - sub);
    borrow = static_cast<u128>(a[i]) < sub ? 1 : 0;
  }
  return r;
}

// a * b for a < 2^128, b < 2^64 (result < 2^192).
Limbs MulLimbs(u128 a, uint64_t b) {
  const u128 p0 = static_cast<u128>(static_cast<uint64_t>(a)) * b;
  const u128 p1 = static_cast<u128>(static_cast<uint64_t>(a >> 64)) * b;
  const u128 mid = (p0 >> 64) + static_cast<uint64_t>(p1);
  Limbs r{};
  r[0] = static_cast<uint64_t>(p0);
  r[1] = static_cast<uint64_t>(mid);
  r[2] = static_cast<uint64_t>(mid >> 64) + static_cast<uint64_t>(p1 >> 64);
  return r;
}

uint32_t LimbsBitLength(const Limbs& a) {
  for (int i = 2; i >= 0; --i) {
    if (a[i]) {
      uint32_t bits = 0;
      for (uint64_t v = a[i]; v; v >>= 1) ++bits;
      return static_cast<uint32_t>(64 * i) + bits;
    }
  }
  return 0;
}

uint64_t LimbsMod(const Limbs& a, uint64_t m) {
  u128 r = a[2] % m;
  r = ((r << 64) | a[1]) % m;
  r = ((r << 64) | a[0]) % m;
  return static_cast<uint64_t>(r);
}

uint32_t BitLength64(uint64_t v) {
  uint32_t bits = 0;
  for (; v; v >>= 1) ++bits;
  return bits;
}

bool IsPowerOfTwo(uint64_t v) { return v != 0 && (v & (v - 1)) == 0; }

// round(value * scale) as an exact WideInt. scale must be a power of two.
HEError ScaleToWide(double value, uint64_t scale, WideInt* out) {
  if (!IsPowerOfTwo(scale)) return HEError::kInvalidScale;
  if (!std::isfinite(value)) return HEError::kOutOfRange;
  const double scaled = std::round(value * static_cast<double>(scale));
  if (!std::isfinite(scaled)) return HEError::kOutOfRange;
  const double magnitude = std::fabs(scaled);
  if (magnitude >= std::ldexp(1.0, static_cast<int>(kMaxBoundBits))) {
    return HEError::kOutOfRange;
  }
  WideInt w;
  w.negative = scaled < 0;
  if (magnitude != 0) {
    int exponent = 0;
    const double fraction = std::frexp(magnitude, &exponent);  // [0.5, 1)
    const uint64_t mantissa =
        static_cast<uint64_t>(std::ldexp(fraction, 53));  // exact, 53 bits
    const int shift = exponent - 53;
    if (shift <= 0) {
      w.magnitude[0] = mantissa >> (-shift);
    } else {
      const int limb = shift / 64, bit = shift % 64;
      w.magnitude[limb] = mantissa << bit;
      if (bit && limb + 1 < 3) w.magnitude[limb + 1] = mantissa >> (64 - bit);
    }
  } else {
    w.negative = false;
  }
  *out = w;
  return HEError::kSuccess;
}

double ScaleFromWide(const WideInt& value, uint64_t scale) {
  int log2_scale = 0;
  while ((uint64_t{1} << log2_scale) != scale) ++log2_scale;
  return std::ldexp(value.ToDouble(), -log2_scale);
}

}  // namespace

WideInt WideInt::FromInt64(int64_t value) {
  WideInt w;
  w.negative = value < 0;
  w.magnitude[0] = value < 0 ? uint64_t{0} - static_cast<uint64_t>(value)
                             : static_cast<uint64_t>(value);
  return w;
}

WideInt WideInt::FromUInt64(uint64_t value) {
  WideInt w;
  w.magnitude[0] = value;
  return w;
}

bool WideInt::Parse(const std::string& text, WideInt* out) {
  size_t i = 0;
  bool negative = false;
  if (i < text.size() && (text[i] == '-' || text[i] == '+')) {
    negative = text[i] == '-';
    ++i;
  }
  if (i == text.size()) return false;
  Limbs m{};
  for (; i < text.size(); ++i) {
    const char c = text[i];
    if (c < '0' || c > '9') return false;
    u128 carry = static_cast<uint64_t>(c - '0');
    for (int k = 0; k < 3; ++k) {
      const u128 v = static_cast<u128>(m[k]) * 10 + carry;
      m[k] = static_cast<uint64_t>(v);
      carry = v >> 64;
    }
    if (carry) return false;
  }
  out->magnitude = m;
  out->negative = negative && !out->IsZero();
  return true;
}

bool WideInt::IsZero() const {
  return !magnitude[0] && !magnitude[1] && !magnitude[2];
}

uint32_t WideInt::BitLength() const { return LimbsBitLength(magnitude); }

bool WideInt::FitsInt64() const {
  if (magnitude[1] || magnitude[2]) return false;
  const uint64_t limit = uint64_t{1} << 63;
  return negative ? magnitude[0] <= limit : magnitude[0] < limit;
}

int64_t WideInt::ToInt64() const {
  return negative ? static_cast<int64_t>(uint64_t{0} - magnitude[0])
                  : static_cast<int64_t>(magnitude[0]);
}

double WideInt::ToDouble() const {
  const double v = std::ldexp(static_cast<double>(magnitude[2]), 128) +
                   std::ldexp(static_cast<double>(magnitude[1]), 64) +
                   static_cast<double>(magnitude[0]);
  return negative ? -v : v;
}

std::string WideInt::ToString() const {
  if (IsZero()) return "0";
  constexpr uint64_t kChunk = 10000000000000000000ULL;  // 10^19
  Limbs m = magnitude;
  std::vector<uint64_t> chunks;
  while (m[0] || m[1] || m[2]) {
    u128 rem = 0;
    for (int k = 2; k >= 0; --k) {
      const u128 cur = (rem << 64) | m[k];
      m[k] = static_cast<uint64_t>(cur / kChunk);
      rem = cur % kChunk;
    }
    chunks.push_back(static_cast<uint64_t>(rem));
  }
  std::string s = negative ? "-" : "";
  s += std::to_string(chunks.back());
  for (size_t k = chunks.size() - 1; k-- > 0;) {
    std::string part = std::to_string(chunks[k]);
    s += std::string(19 - part.size(), '0') + part;
  }
  return s;
}

#ifdef FLATBUFFERS_HE_USE_SEAL
namespace {

constexpr size_t kMinimumDeterministicSeedSize = 32;
constexpr char kSeedExpandSalt[] = "flatbuffers-he-seed-expand";
constexpr char kSeedExpandInfo[] = "seal-prng-seed-v2-modulus-";

// One PRNG seed per plaintext modulus, expanded from the caller's seed.
seal::prng_seed_type BuildPrngSeed(const uint8_t* seed, size_t seed_len,
                                   uint32_t modulus_index) {
  std::array<uint8_t, seal::prng_seed_byte_count> normalized_seed{};
  std::string info = kSeedExpandInfo;
  info += static_cast<char>('0' + modulus_index);
  HKDF(seed, seed_len, reinterpret_cast<const uint8_t*>(kSeedExpandSalt),
       std::strlen(kSeedExpandSalt),
       reinterpret_cast<const uint8_t*>(info.data()), info.size(),
       normalized_seed.data(), normalized_seed.size());

  seal::prng_seed_type prng_seed{};
  for (size_t i = 0; i < prng_seed.size(); ++i) {
    uint64_t word = 0;
    for (size_t j = 0; j < sizeof(uint64_t); ++j) {
      word |= static_cast<uint64_t>(normalized_seed[i * sizeof(uint64_t) + j])
              << (j * 8);
    }
    prng_seed[i] = word;
  }
  return prng_seed;
}

uint64_t MulMod(uint64_t a, uint64_t b, uint64_t m) {
  return static_cast<uint64_t>(static_cast<u128>(a) * b % m);
}

uint64_t PowMod(uint64_t a, uint64_t e, uint64_t m) {
  uint64_t r = 1;
  for (a %= m; e; e >>= 1, a = MulMod(a, a, m)) {
    if (e & 1) r = MulMod(r, a, m);
  }
  return r;
}

void AppendU32(std::vector<uint8_t>* out, uint32_t v) {
  for (int i = 0; i < 4; ++i) out->push_back(static_cast<uint8_t>(v >> (8 * i)));
}

bool ReadU32(const uint8_t* data, size_t len, size_t* pos, uint32_t* v) {
  if (*pos + 4 > len) return false;
  *v = 0;
  for (int i = 0; i < 4; ++i) {
    *v |= static_cast<uint32_t>(data[*pos + i]) << (8 * i);
  }
  *pos += 4;
  return true;
}

void AppendRecord(std::vector<uint8_t>* out, const std::string& bytes) {
  AppendU32(out, static_cast<uint32_t>(bytes.size()));
  out->insert(out->end(), bytes.begin(), bytes.end());
}

// Splits [count][size][bytes]... into kPlainModulusCount records.
bool SplitRecords(const uint8_t* data, size_t len,
                  std::array<std::string, kPlainModulusCount>* records) {
  if (!data || len < 1 || data[0] != kPlainModulusCount) return false;
  size_t pos = 1;
  for (uint32_t i = 0; i < kPlainModulusCount; ++i) {
    uint32_t size = 0;
    if (!ReadU32(data, len, &pos, &size) || pos + size > len) return false;
    (*records)[i].assign(reinterpret_cast<const char*>(data + pos), size);
    pos += size;
  }
  return pos == len;
}

uint16_t Log2Degree(uint32_t degree) {
  uint16_t r = 0;
  while ((uint32_t{1} << r) < degree) ++r;
  return r;
}

bool SupportedDegree(uint32_t degree) {
  return degree == 8192 || degree == 16384;
}

}  // namespace
#endif

// =============================================================================
// HEContextImpl - PIMPL implementation
// =============================================================================

enum class BinaryOp { kAdd, kSub, kMultiply };
enum class PlainOp { kAdd, kMultiply };

class HEContextImpl {
 public:
  HEScheme scheme_ = HEScheme::BFV;
  uint32_t poly_modulus_degree_ = kDefaultPolyModulusDegree;
  bool has_secret_key_ = false;
  bool valid_ = false;
  mutable HEResult last_ = HEResult::Success();

  HEContextImpl() = default;

  std::vector<uint8_t> Refuse(HEError code, const std::string& message) const {
    last_ = HEResult::Error(code, message);
    return {};
  }

  [[noreturn]] void Throw(HEError code, const std::string& message) const {
    last_ = HEResult::Error(code, message);
    throw HEException(code, std::string(HEErrorName(code)) + ": " + message);
  }

  static HEError CheckValues(const std::vector<WideInt>& values,
                             uint32_t bound_bits, size_t slots,
                             std::string* message) {
    if (bound_bits > kMaxBoundBits) {
      *message = "bound of " + std::to_string(bound_bits) +
                 " bits exceeds " + std::to_string(kMaxBoundBits);
      return HEError::kOutOfRange;
    }
    if (values.size() > slots) {
      *message = std::to_string(values.size()) + " values exceed " +
                 std::to_string(slots) + " slots";
      return HEError::kTooManyValues;
    }
    for (size_t i = 0; i < values.size(); ++i) {
      if (values[i].BitLength() > bound_bits) {
        *message = "slot " + std::to_string(i) + " value " +
                   values[i].ToString() + " is outside |v| < 2^" +
                   std::to_string(bound_bits);
        return HEError::kOutOfRange;
      }
    }
    return HEError::kSuccess;
  }

#ifdef FLATBUFFERS_HE_USE_SEAL
  struct Lane {
    std::shared_ptr<seal::SEALContext> context;
    std::unique_ptr<seal::PublicKey> public_key;
    std::unique_ptr<seal::SecretKey> secret_key;
    std::unique_ptr<seal::RelinKeys> relin_keys;
    std::unique_ptr<seal::Encryptor> encryptor;
    std::unique_ptr<seal::Decryptor> decryptor;
    std::unique_ptr<seal::Evaluator> evaluator;
    std::unique_ptr<seal::BatchEncoder> batch_encoder;
  };
  std::array<Lane, kPlainModulusCount> lanes_;
  std::array<uint64_t, kPlainModulusCount> t_{};
  uint64_t inv01_ = 0, inv012_ = 0;
  u128 t01_ = 0;
  Limbs T_{}, half_{};

  seal::EncryptionParameters BaseParameters(uint32_t degree,
                                            HEScheme scheme) const {
    seal::EncryptionParameters parms(scheme == HEScheme::BFV
                                         ? seal::scheme_type::bfv
                                         : seal::scheme_type::bgv);
    parms.set_poly_modulus_degree(degree);
    parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(degree));
    return parms;
  }

  // Moduli, CRT constants, and the range check T > 2^179.
  bool SetupModuli() {
    for (uint32_t i = 0; i < kPlainModulusCount; ++i) {
      t_[i] = lanes_[i].context->first_context_data()
                  ->parms().plain_modulus().value();
    }
    if (t_[0] == t_[1] || t_[0] == t_[2] || t_[1] == t_[2]) return false;
    t01_ = static_cast<u128>(t_[0]) * t_[1];
    T_ = MulLimbs(t01_, t_[2]);
    Limbs two179{};
    two179[2] = uint64_t{1} << (179 - 128);
    if (CompareLimbs(T_, two179) <= 0) return false;
    // half = (T - 1) / 2
    Limbs one{};
    one[0] = 1;
    half_ = SubLimbs(T_, one);
    half_[0] = (half_[0] >> 1) | (half_[1] << 63);
    half_[1] = (half_[1] >> 1) | (half_[2] << 63);
    half_[2] >>= 1;
    inv01_ = PowMod(t_[0] % t_[1], t_[1] - 2, t_[1]);
    inv012_ = PowMod(static_cast<uint64_t>(t01_ % t_[2]), t_[2] - 2, t_[2]);
    return true;
  }

  bool InitClient(uint32_t poly_modulus_degree, HEScheme scheme,
                  const uint8_t* seed, size_t seed_len) {
    scheme_ = scheme;
    poly_modulus_degree_ = poly_modulus_degree;
    if (!SupportedDegree(poly_modulus_degree)) return false;
    if (seed && seed_len < kMinimumDeterministicSeedSize) return false;
    try {
      const auto plain = seal::PlainModulus::Batching(
          poly_modulus_degree,
          std::vector<int>(kPlainModulusCount, kPlainModulusBits));
      for (uint32_t i = 0; i < kPlainModulusCount; ++i) {
        auto parms = BaseParameters(poly_modulus_degree, scheme);
        parms.set_plain_modulus(plain[i]);
        if (seed) {
          parms.set_random_generator(
              std::make_shared<seal::SEAL_DEFAULT_PRNG_FACTORY>(
                  BuildPrngSeed(seed, seed_len, i)));
        }
        Lane& lane = lanes_[i];
        lane.context = std::make_shared<seal::SEALContext>(parms);
        if (!lane.context->parameters_set() ||
            !lane.context->first_context_data()->qualifiers().using_batching) {
          return false;
        }
        seal::KeyGenerator keygen(*lane.context);
        lane.secret_key = std::make_unique<seal::SecretKey>(keygen.secret_key());
        lane.public_key = std::make_unique<seal::PublicKey>();
        keygen.create_public_key(*lane.public_key);
        lane.relin_keys = std::make_unique<seal::RelinKeys>();
        keygen.create_relin_keys(*lane.relin_keys);
        lane.encryptor =
            std::make_unique<seal::Encryptor>(*lane.context, *lane.public_key);
        lane.decryptor =
            std::make_unique<seal::Decryptor>(*lane.context, *lane.secret_key);
        lane.evaluator = std::make_unique<seal::Evaluator>(*lane.context);
        lane.batch_encoder = std::make_unique<seal::BatchEncoder>(*lane.context);
      }
      if (!SetupModuli()) return false;
      has_secret_key_ = true;
      valid_ = true;
      return true;
    } catch (const std::exception&) {
      return false;
    }
  }

  bool InitServer(const uint8_t* pk_data, size_t pk_len) {
    std::array<std::string, kPlainModulusCount> records;
    if (!SplitRecords(pk_data, pk_len, &records)) return false;
    try {
      for (uint32_t i = 0; i < kPlainModulusCount; ++i) {
        std::stringstream ss(records[i]);
        seal::EncryptionParameters parms;
        parms.load(ss);
        const uint32_t degree =
            static_cast<uint32_t>(parms.poly_modulus_degree());
        if (!SupportedDegree(degree)) return false;
        if (i > 0 && degree != poly_modulus_degree_) return false;
        poly_modulus_degree_ = degree;
        scheme_ = parms.scheme() == seal::scheme_type::bfv ? HEScheme::BFV
                                                            : HEScheme::BGV;
        Lane& lane = lanes_[i];
        lane.context = std::make_shared<seal::SEALContext>(parms);
        if (!lane.context->parameters_set() ||
            !lane.context->first_context_data()->qualifiers().using_batching) {
          return false;
        }
        lane.public_key = std::make_unique<seal::PublicKey>();
        lane.public_key->load(*lane.context, ss);
        lane.encryptor =
            std::make_unique<seal::Encryptor>(*lane.context, *lane.public_key);
        lane.evaluator = std::make_unique<seal::Evaluator>(*lane.context);
        lane.batch_encoder = std::make_unique<seal::BatchEncoder>(*lane.context);
      }
      if (!SetupModuli()) return false;
      has_secret_key_ = false;
      valid_ = true;
      return true;
    } catch (const std::exception&) {
      return false;
    }
  }

  template <typename SaveFn>
  std::vector<uint8_t> SerializeLanes(SaveFn save) const {
    if (!valid_) return {};
    std::vector<uint8_t> out;
    out.push_back(static_cast<uint8_t>(kPlainModulusCount));
    for (uint32_t i = 0; i < kPlainModulusCount; ++i) {
      std::stringstream ss;
      if (!save(lanes_[i], ss)) return {};
      AppendRecord(&out, ss.str());
    }
    return out;
  }

  std::vector<uint8_t> SerializePublicKey() const {
    return SerializeLanes([](const Lane& lane, std::stringstream& ss) {
      if (!lane.public_key) return false;
      lane.context->key_context_data()->parms().save(ss);
      lane.public_key->save(ss);
      return true;
    });
  }

  std::vector<uint8_t> SerializeRelinKeys() const {
    return SerializeLanes([](const Lane& lane, std::stringstream& ss) {
      if (!lane.relin_keys) return false;
      lane.relin_keys->save(ss);
      return true;
    });
  }

  std::vector<uint8_t> SerializeSecretKey() const {
    return SerializeLanes([](const Lane& lane, std::stringstream& ss) {
      if (!lane.secret_key) return false;
      lane.secret_key->save(ss);
      return true;
    });
  }

  bool SetRelinKeys(const uint8_t* data, size_t len) {
    if (!valid_) return false;
    std::array<std::string, kPlainModulusCount> records;
    if (!SplitRecords(data, len, &records)) return false;
    try {
      std::array<std::unique_ptr<seal::RelinKeys>, kPlainModulusCount> keys;
      for (uint32_t i = 0; i < kPlainModulusCount; ++i) {
        std::stringstream ss(records[i]);
        keys[i] = std::make_unique<seal::RelinKeys>();
        keys[i]->load(*lanes_[i].context, ss);
      }
      for (uint32_t i = 0; i < kPlainModulusCount; ++i) {
        lanes_[i].relin_keys = std::move(keys[i]);
      }
      return true;
    } catch (const std::exception&) {
      return false;
    }
  }

  using Ciphertexts = std::array<seal::Ciphertext, kPlainModulusCount>;

  std::vector<uint8_t> Pack(const Ciphertexts& cts, uint32_t bound_bits) const {
    std::vector<uint8_t> out(sizeof(CiphertextHeader));
    for (uint32_t i = 0; i < kPlainModulusCount; ++i) {
      std::stringstream ss;
      cts[i].save(ss);
      AppendRecord(&out, ss.str());
    }
    CiphertextHeader header;
    header.length = static_cast<uint32_t>(out.size());
    header.scheme = static_cast<uint8_t>(scheme_);
    header.bound_bits = static_cast<uint8_t>(bound_bits);
    header.poly_degree_log2 = Log2Degree(poly_modulus_degree_);
    header.coeff_count = static_cast<uint32_t>(cts[0].size());
    std::memcpy(out.data(), &header, sizeof(header));
    last_ = HEResult::Success();
    return out;
  }

  bool Unpack(const uint8_t* data, size_t len, Ciphertexts* cts,
              uint32_t* bound_bits) const {
    if (!data || len < sizeof(CiphertextHeader)) return false;
    CiphertextHeader header;
    std::memcpy(&header, data, sizeof(header));
    if (header.length != len ||
        header.scheme != static_cast<uint8_t>(scheme_) ||
        header.poly_degree_log2 != Log2Degree(poly_modulus_degree_) ||
        header.bound_bits > kMaxBoundBits) {
      return false;
    }
    size_t pos = sizeof(CiphertextHeader);
    try {
      for (uint32_t i = 0; i < kPlainModulusCount; ++i) {
        uint32_t size = 0;
        if (!ReadU32(data, len, &pos, &size) || pos + size > len) return false;
        std::stringstream ss(std::string(
            reinterpret_cast<const char*>(data + pos), size));
        (*cts)[i].load(*lanes_[i].context, ss);
        pos += size;
      }
    } catch (const std::exception&) {
      return false;
    }
    *bound_bits = header.bound_bits;
    return pos == len;
  }

  // Residues of each value modulo t_i, one slot vector per modulus.
  void Residues(const std::vector<WideInt>& values,
                std::array<std::vector<uint64_t>, kPlainModulusCount>* out)
      const {
    for (uint32_t i = 0; i < kPlainModulusCount; ++i) {
      auto& r = (*out)[i];
      r.assign(poly_modulus_degree_, 0);
      for (size_t j = 0; j < values.size(); ++j) {
        const uint64_t m = LimbsMod(values[j].magnitude, t_[i]);
        r[j] = values[j].negative && m ? t_[i] - m : m;
      }
    }
  }

  std::vector<uint8_t> EncryptSlots(const std::vector<WideInt>& values,
                                    uint32_t bound_bits) const {
    if (!valid_) return Refuse(HEError::kInvalidContext, "invalid context");
    std::string message;
    const HEError check =
        CheckValues(values, bound_bits, poly_modulus_degree_, &message);
    if (check != HEError::kSuccess) return Refuse(check, message);
    try {
      std::array<std::vector<uint64_t>, kPlainModulusCount> residues;
      Residues(values, &residues);
      Ciphertexts cts;
      for (uint32_t i = 0; i < kPlainModulusCount; ++i) {
        seal::Plaintext plain;
        lanes_[i].batch_encoder->encode(residues[i], plain);
        lanes_[i].encryptor->encrypt(plain, cts[i]);
      }
      return Pack(cts, bound_bits);
    } catch (const std::exception& e) {
      return Refuse(HEError::kEncryptionFailed, e.what());
    }
  }

  std::vector<WideInt> DecryptSlots(const uint8_t* data, size_t len) const {
    if (!valid_ || !has_secret_key_) {
      Throw(HEError::kNoSecretKey, "decryption needs a client context");
    }
    Ciphertexts cts;
    uint32_t bound_bits = 0;
    if (!Unpack(data, len, &cts, &bound_bits)) {
      Throw(HEError::kInvalidCiphertext, "malformed ciphertext");
    }
    std::array<std::vector<uint64_t>, kPlainModulusCount> x;
    try {
      for (uint32_t i = 0; i < kPlainModulusCount; ++i) {
        if (lanes_[i].decryptor->invariant_noise_budget(cts[i]) <= 0) {
          Throw(HEError::kNoiseBudgetExhausted,
                "noise budget exhausted for modulus " + std::to_string(i));
        }
        seal::Plaintext plain;
        lanes_[i].decryptor->decrypt(cts[i], plain);
        lanes_[i].batch_encoder->decode(plain, x[i]);
      }
    } catch (const HEException&) {
      throw;
    } catch (const std::exception& e) {
      Throw(HEError::kDecryptionFailed, e.what());
    }
    std::vector<WideInt> out(poly_modulus_degree_);
    for (size_t j = 0; j < out.size(); ++j) {
      // Garner: m = d0 + d1 t0 + d2 t0 t1, 0 <= m < T.
      const uint64_t d0 = x[0][j];
      const uint64_t d1 =
          MulMod((x[1][j] + t_[1] - d0 % t_[1]) % t_[1], inv01_, t_[1]);
      const uint64_t s = (d0 % t_[2] + MulMod(t_[0] % t_[2], d1, t_[2])) % t_[2];
      const uint64_t d2 = MulMod((x[2][j] + t_[2] - s) % t_[2], inv012_, t_[2]);
      Limbs m = AddLimbs(MulLimbs(t01_, d2), MulLimbs(t_[0], d1));
      Limbs low{};
      low[0] = d0;
      m = AddLimbs(m, low);
      WideInt& w = out[j];
      if (CompareLimbs(m, half_) > 0) {
        w.negative = true;
        w.magnitude = SubLimbs(T_, m);
      } else {
        w.magnitude = m;
      }
      if (w.BitLength() > bound_bits) {
        Throw(HEError::kOutOfRange,
              "slot " + std::to_string(j) + " is outside its bound 2^" +
                  std::to_string(bound_bits));
      }
    }
    last_ = HEResult::Success();
    return out;
  }

  int NoiseBudget(const uint8_t* data, size_t len) const {
    if (!valid_ || !has_secret_key_) return -1;
    Ciphertexts cts;
    uint32_t bound_bits = 0;
    if (!Unpack(data, len, &cts, &bound_bits)) return -1;
    int budget = 1 << 30;
    for (uint32_t i = 0; i < kPlainModulusCount; ++i) {
      budget = std::min(budget,
                        lanes_[i].decryptor->invariant_noise_budget(cts[i]));
    }
    return budget;
  }

  std::vector<uint8_t> Binary(const uint8_t* ct1, size_t len1,
                              const uint8_t* ct2, size_t len2,
                              BinaryOp op) const {
    if (!valid_) return Refuse(HEError::kInvalidContext, "invalid context");
    Ciphertexts a, b;
    uint32_t ba = 0, bb = 0;
    if (!Unpack(ct1, len1, &a, &ba) || !Unpack(ct2, len2, &b, &bb)) {
      return Refuse(HEError::kInvalidCiphertext, "malformed ciphertext");
    }
    const uint32_t bound =
        op == BinaryOp::kMultiply ? ba + bb : std::max(ba, bb) + 1;
    if (bound > kMaxBoundBits) {
      return Refuse(HEError::kOutOfRange,
                    "result bound 2^" + std::to_string(bound) + " exceeds 2^" +
                        std::to_string(kMaxBoundBits));
    }
    if (op == BinaryOp::kMultiply) {
      for (const auto& lane : lanes_) {
        if (!lane.relin_keys) {
          return Refuse(HEError::kInvalidKey, "multiply needs relin keys");
        }
      }
    }
    try {
      Ciphertexts r;
      for (uint32_t i = 0; i < kPlainModulusCount; ++i) {
        const auto& ev = *lanes_[i].evaluator;
        switch (op) {
          case BinaryOp::kAdd: ev.add(a[i], b[i], r[i]); break;
          case BinaryOp::kSub: ev.sub(a[i], b[i], r[i]); break;
          case BinaryOp::kMultiply:
            ev.multiply(a[i], b[i], r[i]);
            ev.relinearize_inplace(r[i], *lanes_[i].relin_keys);
            break;
        }
      }
      return Pack(r, bound);
    } catch (const std::exception& e) {
      return Refuse(HEError::kOperationFailed, e.what());
    }
  }

  std::vector<uint8_t> Negate(const uint8_t* ct, size_t len) const {
    if (!valid_) return Refuse(HEError::kInvalidContext, "invalid context");
    Ciphertexts a, r;
    uint32_t bound = 0;
    if (!Unpack(ct, len, &a, &bound)) {
      return Refuse(HEError::kInvalidCiphertext, "malformed ciphertext");
    }
    try {
      for (uint32_t i = 0; i < kPlainModulusCount; ++i) {
        lanes_[i].evaluator->negate(a[i], r[i]);
      }
      return Pack(r, bound);
    } catch (const std::exception& e) {
      return Refuse(HEError::kOperationFailed, e.what());
    }
  }

  std::vector<uint8_t> Plain(const uint8_t* ct, size_t len, const WideInt& p,
                             PlainOp op) const {
    if (!valid_) return Refuse(HEError::kInvalidContext, "invalid context");
    Ciphertexts a, r;
    uint32_t ba = 0;
    if (!Unpack(ct, len, &a, &ba)) {
      return Refuse(HEError::kInvalidCiphertext, "malformed ciphertext");
    }
    const uint32_t bp = p.BitLength();
    const uint32_t bound =
        op == PlainOp::kMultiply ? ba + bp : std::max(ba, bp) + 1;
    if (bound > kMaxBoundBits) {
      return Refuse(HEError::kOutOfRange,
                    "result bound 2^" + std::to_string(bound) + " exceeds 2^" +
                        std::to_string(kMaxBoundBits));
    }
    try {
      for (uint32_t i = 0; i < kPlainModulusCount; ++i) {
        const uint64_t m = LimbsMod(p.magnitude, t_[i]);
        const uint64_t residue = p.negative && m ? t_[i] - m : m;
        seal::Plaintext plain;
        lanes_[i].batch_encoder->encode(
            std::vector<uint64_t>(poly_modulus_degree_, residue), plain);
        if (op == PlainOp::kAdd) {
          lanes_[i].evaluator->add_plain(a[i], plain, r[i]);
        } else {
          lanes_[i].evaluator->multiply_plain(a[i], plain, r[i]);
        }
      }
      return Pack(r, bound);
    } catch (const std::exception& e) {
      return Refuse(HEError::kOperationFailed, e.what());
    }
  }

  std::vector<uint64_t> PlainModuli() const {
    if (!valid_) return {};
    return std::vector<uint64_t>(t_.begin(), t_.end());
  }

#else
  // Stub implementations when SEAL is not available
  bool InitClient(uint32_t poly_modulus_degree, HEScheme scheme,
                  const uint8_t*, size_t) {
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
  std::vector<uint8_t> EncryptSlots(const std::vector<WideInt>&,
                                    uint32_t) const {
    return Refuse(HEError::kInvalidContext, "SEAL not available");
  }
  std::vector<WideInt> DecryptSlots(const uint8_t*, size_t) const {
    Throw(HEError::kInvalidContext, "SEAL not available");
  }
  int NoiseBudget(const uint8_t*, size_t) const { return -1; }
  std::vector<uint8_t> Binary(const uint8_t*, size_t, const uint8_t*, size_t,
                              BinaryOp) const {
    return Refuse(HEError::kInvalidContext, "SEAL not available");
  }
  std::vector<uint8_t> Negate(const uint8_t*, size_t) const {
    return Refuse(HEError::kInvalidContext, "SEAL not available");
  }
  std::vector<uint8_t> Plain(const uint8_t*, size_t, const WideInt&,
                             PlainOp) const {
    return Refuse(HEError::kInvalidContext, "SEAL not available");
  }
  std::vector<uint64_t> PlainModuli() const { return {}; }
#endif

  // Slot 0 as a WideInt.
  WideInt DecryptFirst(const uint8_t* data, size_t len) const {
    return DecryptSlots(data, len)[0];
  }

  int64_t DecryptRange(const uint8_t* data, size_t len, int64_t lo,
                       int64_t hi) const {
    const WideInt w = DecryptFirst(data, len);
    if (!w.FitsInt64() || w.ToInt64() < lo || w.ToInt64() > hi) {
      Throw(HEError::kOutOfRange, w.ToString() + " is outside [" +
                                      std::to_string(lo) + ", " +
                                      std::to_string(hi) + "]");
    }
    return w.ToInt64();
  }

  uint64_t DecryptUnsigned(const uint8_t* data, size_t len,
                           uint64_t hi) const {
    const WideInt w = DecryptFirst(data, len);
    if (w.negative || w.magnitude[1] || w.magnitude[2] || w.magnitude[0] > hi) {
      Throw(HEError::kOutOfRange,
            w.ToString() + " is outside [0, " + std::to_string(hi) + "]");
    }
    return w.magnitude[0];
  }

  void CheckScale(uint64_t scale) const {
    if (!IsPowerOfTwo(scale)) {
      Throw(HEError::kInvalidScale,
            "scale " + std::to_string(scale) + " is not a power of two");
    }
  }

  std::vector<uint8_t> EncryptScaled(const std::vector<double>& values,
                                     uint64_t scale,
                                     uint32_t bound_bits) const {
    std::vector<WideInt> wide(values.size());
    for (size_t i = 0; i < values.size(); ++i) {
      const HEError e = ScaleToWide(values[i], scale, &wide[i]);
      if (e != HEError::kSuccess) {
        return Refuse(e, "slot " + std::to_string(i) +
                             (e == HEError::kInvalidScale
                                  ? ": scale is not a power of two"
                                  : ": value is not finite or outside 2^" +
                                        std::to_string(kMaxBoundBits)));
      }
    }
    return EncryptSlots(wide, bound_bits);
  }
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
  ctx.impl_->InitClient(poly_modulus_degree, scheme, nullptr, 0);
  return ctx;
}

HEContext HEContext::CreateClientSeeded(const uint8_t* seed, size_t seed_len,
                                         uint32_t poly_modulus_degree,
                                         HEScheme scheme) {
  HEContext ctx;
  if (seed) ctx.impl_->InitClient(poly_modulus_degree, scheme, seed, seed_len);
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

uint32_t HEContext::SlotCount() const { return impl_->poly_modulus_degree_; }

std::vector<uint64_t> HEContext::GetPlainModuli() const {
  return impl_->PlainModuli();
}

HEResult HEContext::LastError() const { return impl_->last_; }

uint32_t HEContext::CiphertextBoundBits(const uint8_t* ciphertext,
                                        size_t len) {
  if (!ciphertext || len < sizeof(CiphertextHeader)) return 0;
  CiphertextHeader header;
  std::memcpy(&header, ciphertext, sizeof(header));
  return header.bound_bits;
}

int HEContext::NoiseBudget(const uint8_t* ciphertext, size_t len) const {
  return impl_->NoiseBudget(ciphertext, len);
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
  return impl_->EncryptSlots({WideInt::FromInt64(value)}, 8);
}

std::vector<uint8_t> HEContext::EncryptInt16(int16_t value) const {
  return impl_->EncryptSlots({WideInt::FromInt64(value)}, 16);
}

std::vector<uint8_t> HEContext::EncryptInt32(int32_t value) const {
  return impl_->EncryptSlots({WideInt::FromInt64(value)}, 32);
}

std::vector<uint8_t> HEContext::EncryptInt64(int64_t value) const {
  return impl_->EncryptSlots({WideInt::FromInt64(value)}, 64);
}

std::vector<uint8_t> HEContext::EncryptUInt8(uint8_t value) const {
  return impl_->EncryptSlots({WideInt::FromUInt64(value)}, 8);
}

std::vector<uint8_t> HEContext::EncryptUInt16(uint16_t value) const {
  return impl_->EncryptSlots({WideInt::FromUInt64(value)}, 16);
}

std::vector<uint8_t> HEContext::EncryptUInt32(uint32_t value) const {
  return impl_->EncryptSlots({WideInt::FromUInt64(value)}, 32);
}

std::vector<uint8_t> HEContext::EncryptUInt64(uint64_t value) const {
  return impl_->EncryptSlots({WideInt::FromUInt64(value)}, 64);
}

std::vector<uint8_t> HEContext::EncryptFloat(float value, uint64_t scale,
                                             uint32_t bound_bits) const {
  return impl_->EncryptScaled({static_cast<double>(value)}, scale, bound_bits);
}

std::vector<uint8_t> HEContext::EncryptDouble(double value, uint64_t scale,
                                              uint32_t bound_bits) const {
  return impl_->EncryptScaled({value}, scale, bound_bits);
}

std::vector<uint8_t> HEContext::EncryptWide(const WideInt& value,
                                            uint32_t bound_bits) const {
  return impl_->EncryptSlots({value}, bound_bits);
}

std::vector<uint8_t> HEContext::EncryptInt64Vector(
    const std::vector<int64_t>& values, uint32_t bound_bits) const {
  std::vector<WideInt> wide(values.size());
  for (size_t i = 0; i < values.size(); ++i) {
    wide[i] = WideInt::FromInt64(values[i]);
  }
  return impl_->EncryptSlots(wide, bound_bits);
}

std::vector<uint8_t> HEContext::EncryptWideVector(
    const std::vector<WideInt>& values, uint32_t bound_bits) const {
  return impl_->EncryptSlots(values, bound_bits);
}

std::vector<uint8_t> HEContext::EncryptDoubleVector(
    const std::vector<double>& values, uint64_t scale,
    uint32_t bound_bits) const {
  return impl_->EncryptScaled(values, scale, bound_bits);
}

// Decryption methods
int8_t HEContext::DecryptInt8(const uint8_t* ct, size_t len) const {
  return static_cast<int8_t>(impl_->DecryptRange(ct, len, INT8_MIN, INT8_MAX));
}

int16_t HEContext::DecryptInt16(const uint8_t* ct, size_t len) const {
  return static_cast<int16_t>(
      impl_->DecryptRange(ct, len, INT16_MIN, INT16_MAX));
}

int32_t HEContext::DecryptInt32(const uint8_t* ct, size_t len) const {
  return static_cast<int32_t>(
      impl_->DecryptRange(ct, len, INT32_MIN, INT32_MAX));
}

int64_t HEContext::DecryptInt64(const uint8_t* ct, size_t len) const {
  return impl_->DecryptRange(ct, len, INT64_MIN, INT64_MAX);
}

uint8_t HEContext::DecryptUInt8(const uint8_t* ct, size_t len) const {
  return static_cast<uint8_t>(impl_->DecryptUnsigned(ct, len, UINT8_MAX));
}

uint16_t HEContext::DecryptUInt16(const uint8_t* ct, size_t len) const {
  return static_cast<uint16_t>(impl_->DecryptUnsigned(ct, len, UINT16_MAX));
}

uint32_t HEContext::DecryptUInt32(const uint8_t* ct, size_t len) const {
  return static_cast<uint32_t>(impl_->DecryptUnsigned(ct, len, UINT32_MAX));
}

uint64_t HEContext::DecryptUInt64(const uint8_t* ct, size_t len) const {
  return impl_->DecryptUnsigned(ct, len, UINT64_MAX);
}

float HEContext::DecryptFloat(const uint8_t* ct, size_t len,
                               uint64_t scale) const {
  return static_cast<float>(DecryptDouble(ct, len, scale));
}

double HEContext::DecryptDouble(const uint8_t* ct, size_t len,
                                 uint64_t scale) const {
  impl_->CheckScale(scale);
  return ScaleFromWide(impl_->DecryptFirst(ct, len), scale);
}

WideInt HEContext::DecryptWide(const uint8_t* ct, size_t len) const {
  return impl_->DecryptFirst(ct, len);
}

std::vector<int64_t> HEContext::DecryptInt64Vector(const uint8_t* ct,
                                                   size_t len) const {
  const std::vector<WideInt> wide = impl_->DecryptSlots(ct, len);
  std::vector<int64_t> out(wide.size());
  for (size_t i = 0; i < wide.size(); ++i) {
    if (!wide[i].FitsInt64()) {
      impl_->Throw(HEError::kOutOfRange, "slot " + std::to_string(i) + " " +
                                             wide[i].ToString() +
                                             " is outside int64");
    }
    out[i] = wide[i].ToInt64();
  }
  return out;
}

std::vector<WideInt> HEContext::DecryptWideVector(const uint8_t* ct,
                                                  size_t len) const {
  return impl_->DecryptSlots(ct, len);
}

std::vector<double> HEContext::DecryptDoubleVector(const uint8_t* ct,
                                                   size_t len,
                                                   uint64_t scale) const {
  impl_->CheckScale(scale);
  const std::vector<WideInt> wide = impl_->DecryptSlots(ct, len);
  std::vector<double> out(wide.size());
  for (size_t i = 0; i < wide.size(); ++i) {
    out[i] = ScaleFromWide(wide[i], scale);
  }
  return out;
}

// Homomorphic operations
std::vector<uint8_t> HEContext::Add(const uint8_t* ct1, size_t len1,
                                     const uint8_t* ct2, size_t len2) const {
  return impl_->Binary(ct1, len1, ct2, len2, BinaryOp::kAdd);
}

std::vector<uint8_t> HEContext::Sub(const uint8_t* ct1, size_t len1,
                                     const uint8_t* ct2, size_t len2) const {
  return impl_->Binary(ct1, len1, ct2, len2, BinaryOp::kSub);
}

std::vector<uint8_t> HEContext::Multiply(const uint8_t* ct1, size_t len1,
                                          const uint8_t* ct2,
                                          size_t len2) const {
  return impl_->Binary(ct1, len1, ct2, len2, BinaryOp::kMultiply);
}

std::vector<uint8_t> HEContext::Negate(const uint8_t* ct, size_t len) const {
  return impl_->Negate(ct, len);
}

std::vector<uint8_t> HEContext::AddPlain(const uint8_t* ct, size_t len,
                                          int64_t plain) const {
  return impl_->Plain(ct, len, WideInt::FromInt64(plain), PlainOp::kAdd);
}

std::vector<uint8_t> HEContext::SubPlain(const uint8_t* ct, size_t len,
                                          int64_t plain) const {
  WideInt negated = WideInt::FromInt64(plain);
  negated.negative = !negated.negative && !negated.IsZero();
  return impl_->Plain(ct, len, negated, PlainOp::kAdd);
}

std::vector<uint8_t> HEContext::MultiplyPlain(const uint8_t* ct, size_t len,
                                               int64_t plain) const {
  return impl_->Plain(ct, len, WideInt::FromInt64(plain), PlainOp::kMultiply);
}

}  // namespace he
}  // namespace flatbuffers
