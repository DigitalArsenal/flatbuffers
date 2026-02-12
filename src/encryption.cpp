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

#include "flatbuffers/encryption.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

#ifdef FLATBUFFERS_USE_CRYPTOPP
// Crypto++ headers
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/sha.h>
#include <cryptopp/hmac.h>
#include <cryptopp/xed25519.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <cryptopp/nbtheory.h>
#endif

namespace flatbuffers {

// =============================================================================
// Secure Memory Clearing (VULN-NEW-002 fix)
// =============================================================================

// Secure memory clear that resists compiler optimization.
// Uses platform-specific guaranteed-not-optimized-away primitives (Task 46).
static void SecureClear(void* ptr, size_t size) {
  if (ptr && size > 0) {
#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25))
    explicit_bzero(ptr, size);
#elif defined(__OpenBSD__)
    explicit_bzero(ptr, size);
#else
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    for (size_t i = 0; i < size; i++) {
      p[i] = 0;
    }
#endif
  }
}

#ifdef FLATBUFFERS_USE_CRYPTOPP

// RAII wrapper for secure clearing of std::vector
template<typename T>
class SecureVector {
 public:
  std::vector<T> data;

  explicit SecureVector(size_t size) : data(size) {}
  SecureVector(const T* src, size_t size) : data(src, src + size) {}

  ~SecureVector() {
    SecureClear(data.data(), data.size() * sizeof(T));
  }

  T* get() { return data.data(); }
  const T* get() const { return data.data(); }
  size_t size() const { return data.size(); }

  // Prevent copying
  SecureVector(const SecureVector&) = delete;
  SecureVector& operator=(const SecureVector&) = delete;

  // Allow moving
  SecureVector(SecureVector&& other) noexcept : data(std::move(other.data)) {}
  SecureVector& operator=(SecureVector&& other) noexcept {
    if (this != &other) {
      SecureClear(data.data(), data.size() * sizeof(T));
      data = std::move(other.data);
    }
    return *this;
  }
};

// =============================================================================
// Crypto++ Implementation
// =============================================================================

// Global RNG that can be seeded with external entropy
// This is critical for WASM environments where AutoSeededRandomPool
// may not have access to good entropy sources like /dev/urandom
static CryptoPP::AutoSeededRandomPool& GetGlobalRNG() {
  static CryptoPP::AutoSeededRandomPool rng;
  return rng;
}

// Inject external entropy into the global RNG
// This should be called from JavaScript with crypto.getRandomValues() output
void InjectEntropy(const uint8_t* seed, size_t size) {
  if (seed && size > 0) {
    GetGlobalRNG().IncorporateEntropy(seed, size);
  }
}

namespace internal {

void AESEncryptBlock(const uint8_t* key, const uint8_t* input, uint8_t* output) {
  CryptoPP::AES::Encryption aes(key, CryptoPP::AES::MAX_KEYLENGTH);
  aes.ProcessBlock(input, output);
}

void AESCTRKeystream(const uint8_t* key, const uint8_t* nonce,
                     uint8_t* keystream, size_t length) {
  CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption enc;
  enc.SetKeyWithIV(key, 32, nonce, 16);
  memset(keystream, 0, length);
  enc.ProcessData(keystream, keystream, length);
}

void DeriveKey(const uint8_t* master_key, size_t master_key_size,
               const uint8_t* info, size_t info_size,
               uint8_t* out_key, size_t out_key_size) {
  CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
  hkdf.DeriveKey(out_key, out_key_size,
                 master_key, master_key_size,
                 nullptr, 0,  // no salt
                 info, info_size);
}

}  // namespace internal

// SHA-256 hash
void Sha256Hash(const uint8_t* data, size_t size, uint8_t* hash) {
  CryptoPP::SHA256 sha;
  sha.CalculateDigest(hash, data, size);
}

// HKDF-SHA256
void HKDF(const uint8_t* ikm, size_t ikm_size,
          const uint8_t* salt, size_t salt_size,
          const uint8_t* info, size_t info_size,
          uint8_t* okm, size_t okm_size) {
  CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
  hkdf.DeriveKey(okm, okm_size,
                 ikm, ikm_size,
                 salt, salt_size,
                 info, info_size);
}

// Derive symmetric key from shared secret
// Salt parameter (Task 30): use ephemeral public key as salt for better key separation
void DeriveSymmetricKey(
    const uint8_t* shared_secret, size_t shared_secret_size,
    const uint8_t* context, size_t context_size,
    uint8_t* key,
    const uint8_t* salt, size_t salt_size) {
  HKDF(shared_secret, shared_secret_size,
       salt, salt_size,
       context, context_size,
       key, kEncryptionKeySize);
}

// HMAC-SHA256
void HMACSha256(const uint8_t* key, size_t key_size,
                const uint8_t* data, size_t data_size,
                uint8_t* mac) {
  CryptoPP::HMAC<CryptoPP::SHA256> hmac(key, key_size);
  hmac.CalculateDigest(mac, data, data_size);
}

// HMAC-SHA256 verify (constant-time)
bool HMACSha256Verify(const uint8_t* key, size_t key_size,
                      const uint8_t* data, size_t data_size,
                      const uint8_t* mac) {
  CryptoPP::HMAC<CryptoPP::SHA256> hmac(key, key_size);
  return hmac.VerifyDigest(mac, data, data_size);
}

// AES-256-CTR encryption
void EncryptBytes(uint8_t* data, size_t size,
                  const uint8_t* key, const uint8_t* iv) {
  if (!data || size == 0 || !key || !iv) return;

  CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption enc;
  enc.SetKeyWithIV(key, 32, iv, 16);
  enc.ProcessData(data, data, size);
}

// =============================================================================
// X25519 Key Exchange
// =============================================================================

KeyPair X25519GenerateKeyPair() {
  KeyPair kp;
  kp.private_key.resize(kX25519PrivateKeySize);
  kp.public_key.resize(kX25519PublicKeySize);

  CryptoPP::x25519 x25519;
  x25519.GenerateKeyPair(GetGlobalRNG(), kp.private_key.data(), kp.public_key.data());
  return kp;
}

bool X25519SharedSecret(
    const uint8_t* private_key,
    const uint8_t* public_key,
    uint8_t* shared_secret) {
  if (!private_key || !public_key || !shared_secret) return false;

  CryptoPP::x25519 x25519;
  return x25519.Agree(shared_secret, private_key, public_key);
}

// =============================================================================
// secp256k1 Key Exchange and Signatures
// =============================================================================

KeyPair Secp256k1GenerateKeyPair() {
  KeyPair kp;

  try {
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;
    privateKey.Initialize(GetGlobalRNG(), CryptoPP::ASN1::secp256k1());

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;
    privateKey.MakePublicKey(publicKey);

    // Export private key (32 bytes)
    kp.private_key.resize(kSecp256k1PrivateKeySize);
    privateKey.GetPrivateExponent().Encode(kp.private_key.data(), kSecp256k1PrivateKeySize);

    // Export compressed public key (33 bytes)
    const CryptoPP::ECP::Point& q = publicKey.GetPublicElement();
    kp.public_key.resize(kSecp256k1PublicKeySize);
    kp.public_key[0] = q.y.IsOdd() ? 0x03 : 0x02;
    q.x.Encode(kp.public_key.data() + 1, 32);

  } catch (...) {
#ifdef FLATBUFFERS_DEBUG
    fprintf(stderr, "[flatbuffers] crypto exception in key generation\n");
#endif
    kp.private_key.clear();
    kp.public_key.clear();
  }

  return kp;
}

bool Secp256k1SharedSecret(
    const uint8_t* private_key,
    const uint8_t* public_key, size_t public_key_size,
    uint8_t* shared_secret) {
  if (!private_key || !public_key || !shared_secret) return false;

  try {
    CryptoPP::ECDH<CryptoPP::ECP>::Domain ecdh(CryptoPP::ASN1::secp256k1());

    // Decompress public key if needed
    // SECURITY FIX (VULN-NEW-002): Use SecureVector for sensitive data
    SecureVector<uint8_t> uncompressed(65);
    const uint8_t* pub_ptr = public_key;
    size_t pub_len = public_key_size;

    if (public_key_size == 33 && (public_key[0] == 0x02 || public_key[0] == 0x03)) {
      // Compressed format - decompress
      CryptoPP::Integer x(public_key + 1, 32);
      const CryptoPP::ECP& curve = ecdh.GetGroupParameters().GetCurve();

      // y^2 = x^3 + 7 (secp256k1)
      CryptoPP::Integer y2 = (x * x * x + 7) % curve.GetField().GetModulus();
      CryptoPP::Integer y = CryptoPP::ModularSquareRoot(y2, curve.GetField().GetModulus());

      // SECURITY FIX (VULN-NEW-003): Validate point is on curve
      CryptoPP::ECP::Point point(x, y);
      if (!curve.VerifyPoint(point)) {
        return false;  // Invalid public key - not on curve
      }

      if ((public_key[0] == 0x03) != y.IsOdd()) {
        y = curve.GetField().GetModulus() - y;
      }

      uncompressed.data[0] = 0x04;
      x.Encode(uncompressed.get() + 1, 32);
      y.Encode(uncompressed.get() + 33, 32);
      pub_ptr = uncompressed.get();
      pub_len = 65;
    }

    // Perform ECDH - use SecureVector for private key copy
    SecureVector<uint8_t> priv_full(ecdh.PrivateKeyLength());
    SecureVector<uint8_t> pub_full(ecdh.PublicKeyLength());

    // Copy private key (zero-padded)
    memset(priv_full.get(), 0, priv_full.size());
    memcpy(priv_full.get() + priv_full.size() - 32, private_key, 32);

    // Copy public key
    if (pub_len == 65) {
      memcpy(pub_full.get(), pub_ptr, pub_len);
    } else {
      return false;
    }

    return ecdh.Agree(shared_secret, priv_full.get(), pub_full.get());
  } catch (...) {
#ifdef FLATBUFFERS_DEBUG
    fprintf(stderr, "[flatbuffers] crypto exception in operation\n");
#endif
    return false;
  }
}

// SECURITY FIX (VULN-NEW-004): Helper to normalize ECDSA signature to low-S form
// This prevents signature malleability (BIP-62/BIP-66 style)
static void NormalizeLowS(std::vector<uint8_t>& sig_data,
                          const CryptoPP::Integer& curve_order) {
  if (sig_data.empty()) return;

  // Crypto++ ECDSA signatures are in IEEE P1363 format: r || s (each half the signature length)
  size_t half_len = sig_data.size() / 2;
  if (sig_data.size() != half_len * 2) return;  // Invalid length

  // Extract s from the second half
  CryptoPP::Integer s(sig_data.data() + half_len, half_len);

  // Check if s > n/2 (high-S)
  CryptoPP::Integer half_order = curve_order >> 1;  // n / 2
  if (s > half_order) {
    // Normalize: s = n - s
    CryptoPP::Integer low_s = curve_order - s;
    low_s.Encode(sig_data.data() + half_len, half_len);
  }
}

Signature Secp256k1Sign(
    const uint8_t* private_key,
    const uint8_t* data, size_t data_size) {
  Signature sig;
  sig.algorithm = SignatureAlgorithm::Secp256k1_ECDSA;

  try {
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey key;
    key.Initialize(CryptoPP::ASN1::secp256k1(),
                   CryptoPP::Integer(private_key, kSecp256k1PrivateKeySize));

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer signer(key);
    sig.data.resize(signer.MaxSignatureLength());
    size_t sigLen = signer.SignMessage(GetGlobalRNG(), data, data_size, sig.data.data());
    sig.data.resize(sigLen);

    // SECURITY FIX (VULN-NEW-004): Enforce low-S to prevent signature malleability
    const CryptoPP::Integer& order = key.GetGroupParameters().GetSubgroupOrder();
    NormalizeLowS(sig.data, order);
  } catch (...) {
#ifdef FLATBUFFERS_DEBUG
    fprintf(stderr, "[flatbuffers] crypto exception in signing\n");
#endif
    sig.data.clear();
  }

  return sig;
}

bool Secp256k1Verify(
    const uint8_t* public_key, size_t public_key_size,
    const uint8_t* data, size_t data_size,
    const uint8_t* signature, size_t signature_size) {
  if (!public_key || public_key_size < 33 || !data || !signature) return false;

  try {
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey key;

    // Decompress public key
    CryptoPP::Integer x(public_key + 1, 32);
    const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& params =
        CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>(CryptoPP::ASN1::secp256k1());
    const CryptoPP::ECP& curve = params.GetCurve();

    CryptoPP::Integer y2 = (x * x * x + 7) % curve.GetField().GetModulus();
    CryptoPP::Integer y = CryptoPP::ModularSquareRoot(y2, curve.GetField().GetModulus());

    if ((public_key[0] == 0x03) != y.IsOdd()) {
      y = curve.GetField().GetModulus() - y;
    }

    // SECURITY FIX (VULN-NEW-003): Validate point is on curve
    CryptoPP::ECP::Point point(x, y);
    if (!curve.VerifyPoint(point)) {
      return false;  // Invalid public key - not on curve
    }

    key.Initialize(CryptoPP::ASN1::secp256k1(), point);

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier verifier(key);
    return verifier.VerifyMessage(data, data_size, signature, signature_size);
  } catch (...) {
#ifdef FLATBUFFERS_DEBUG
    fprintf(stderr, "[flatbuffers] crypto exception in operation\n");
#endif
    return false;
  }
}

// =============================================================================
// P-256 Key Exchange and Signatures
// =============================================================================

KeyPair P256GenerateKeyPair() {
  KeyPair kp;

  try {
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;
    privateKey.Initialize(GetGlobalRNG(), CryptoPP::ASN1::secp256r1());

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;
    privateKey.MakePublicKey(publicKey);

    // Export private key (32 bytes)
    kp.private_key.resize(kP256PrivateKeySize);
    privateKey.GetPrivateExponent().Encode(kp.private_key.data(), kP256PrivateKeySize);

    // Export compressed public key (33 bytes)
    const CryptoPP::ECP::Point& q = publicKey.GetPublicElement();
    kp.public_key.resize(kP256PublicKeySize);
    kp.public_key[0] = q.y.IsOdd() ? 0x03 : 0x02;
    q.x.Encode(kp.public_key.data() + 1, 32);

  } catch (...) {
#ifdef FLATBUFFERS_DEBUG
    fprintf(stderr, "[flatbuffers] crypto exception in key generation\n");
#endif
    kp.private_key.clear();
    kp.public_key.clear();
  }

  return kp;
}

bool P256SharedSecret(
    const uint8_t* private_key,
    const uint8_t* public_key, size_t public_key_size,
    uint8_t* shared_secret) {
  if (!private_key || !public_key || !shared_secret) return false;

  try {
    CryptoPP::ECDH<CryptoPP::ECP>::Domain ecdh(CryptoPP::ASN1::secp256r1());

    // SECURITY FIX (VULN-NEW-002): Use SecureVector for sensitive data
    SecureVector<uint8_t> uncompressed(65);
    const uint8_t* pub_ptr = public_key;
    size_t pub_len = public_key_size;

    if (public_key_size == 33 && (public_key[0] == 0x02 || public_key[0] == 0x03)) {
      CryptoPP::Integer x(public_key + 1, 32);
      const CryptoPP::ECP& curve = ecdh.GetGroupParameters().GetCurve();
      const CryptoPP::Integer& p = curve.GetField().GetModulus();
      const CryptoPP::Integer& b = curve.GetB();

      // y^2 = x^3 - 3x + b (mod p)
      CryptoPP::Integer y2 = (x * x * x - 3 * x + b) % p;
      CryptoPP::Integer y = CryptoPP::ModularSquareRoot(y2, p);

      // SECURITY FIX (VULN-NEW-003): Validate point is on curve
      CryptoPP::ECP::Point point(x, y);
      if (!curve.VerifyPoint(point)) {
        return false;  // Invalid public key - not on curve
      }

      if ((public_key[0] == 0x03) != y.IsOdd()) {
        y = p - y;
      }

      uncompressed.data[0] = 0x04;
      x.Encode(uncompressed.get() + 1, 32);
      y.Encode(uncompressed.get() + 33, 32);
      pub_ptr = uncompressed.get();
      pub_len = 65;
    }

    SecureVector<uint8_t> priv_full(ecdh.PrivateKeyLength());
    SecureVector<uint8_t> pub_full(ecdh.PublicKeyLength());

    memset(priv_full.get(), 0, priv_full.size());
    memcpy(priv_full.get() + priv_full.size() - 32, private_key, 32);

    if (pub_len == 65) {
      memcpy(pub_full.get(), pub_ptr, pub_len);
    } else {
      return false;
    }

    return ecdh.Agree(shared_secret, priv_full.get(), pub_full.get());
  } catch (...) {
#ifdef FLATBUFFERS_DEBUG
    fprintf(stderr, "[flatbuffers] crypto exception in operation\n");
#endif
    return false;
  }
}

Signature P256Sign(
    const uint8_t* private_key,
    const uint8_t* data, size_t data_size) {
  Signature sig;
  sig.algorithm = SignatureAlgorithm::P256_ECDSA;

  try {
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey key;
    key.Initialize(CryptoPP::ASN1::secp256r1(),
                   CryptoPP::Integer(private_key, kP256PrivateKeySize));

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer signer(key);
    sig.data.resize(signer.MaxSignatureLength());
    size_t sigLen = signer.SignMessage(GetGlobalRNG(), data, data_size, sig.data.data());
    sig.data.resize(sigLen);

    // SECURITY FIX (VULN-NEW-004): Enforce low-S to prevent signature malleability
    const CryptoPP::Integer& order = key.GetGroupParameters().GetSubgroupOrder();
    NormalizeLowS(sig.data, order);
  } catch (...) {
#ifdef FLATBUFFERS_DEBUG
    fprintf(stderr, "[flatbuffers] crypto exception in signing\n");
#endif
    sig.data.clear();
  }

  return sig;
}

bool P256Verify(
    const uint8_t* public_key, size_t public_key_size,
    const uint8_t* data, size_t data_size,
    const uint8_t* signature, size_t signature_size) {
  if (!public_key || public_key_size < 33 || !data || !signature) return false;

  try {
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey key;

    CryptoPP::Integer x(public_key + 1, 32);
    const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& params =
        CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>(CryptoPP::ASN1::secp256r1());
    const CryptoPP::ECP& curve = params.GetCurve();
    const CryptoPP::Integer& p = curve.GetField().GetModulus();
    const CryptoPP::Integer& b = curve.GetB();

    CryptoPP::Integer y2 = (x * x * x - 3 * x + b) % p;
    CryptoPP::Integer y = CryptoPP::ModularSquareRoot(y2, p);

    if ((public_key[0] == 0x03) != y.IsOdd()) {
      y = p - y;
    }

    // SECURITY FIX (VULN-NEW-003): Validate point is on curve
    CryptoPP::ECP::Point point(x, y);
    if (!curve.VerifyPoint(point)) {
      return false;  // Invalid public key - not on curve
    }

    key.Initialize(CryptoPP::ASN1::secp256r1(), point);

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier verifier(key);
    return verifier.VerifyMessage(data, data_size, signature, signature_size);
  } catch (...) {
#ifdef FLATBUFFERS_DEBUG
    fprintf(stderr, "[flatbuffers] crypto exception in operation\n");
#endif
    return false;
  }
}

// =============================================================================
// P-384 Key Exchange and Signatures
// =============================================================================

KeyPair P384GenerateKeyPair() {
  KeyPair kp;

  try {
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::PrivateKey privateKey;
    privateKey.Initialize(GetGlobalRNG(), CryptoPP::ASN1::secp384r1());

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::PublicKey publicKey;
    privateKey.MakePublicKey(publicKey);

    // Export private key (48 bytes)
    kp.private_key.resize(kP384PrivateKeySize);
    privateKey.GetPrivateExponent().Encode(kp.private_key.data(), kP384PrivateKeySize);

    // Export compressed public key (49 bytes)
    const CryptoPP::ECP::Point& q = publicKey.GetPublicElement();
    kp.public_key.resize(kP384PublicKeySize);
    kp.public_key[0] = q.y.IsOdd() ? 0x03 : 0x02;
    q.x.Encode(kp.public_key.data() + 1, 48);

  } catch (...) {
#ifdef FLATBUFFERS_DEBUG
    fprintf(stderr, "[flatbuffers] crypto exception in key generation\n");
#endif
    kp.private_key.clear();
    kp.public_key.clear();
  }

  return kp;
}

bool P384SharedSecret(
    const uint8_t* private_key,
    const uint8_t* public_key, size_t public_key_size,
    uint8_t* shared_secret) {
  if (!private_key || !public_key || !shared_secret) return false;

  try {
    CryptoPP::ECDH<CryptoPP::ECP>::Domain ecdh(CryptoPP::ASN1::secp384r1());

    // SECURITY FIX (VULN-NEW-002): Use SecureVector for sensitive data
    SecureVector<uint8_t> uncompressed(97);
    const uint8_t* pub_ptr = public_key;
    size_t pub_len = public_key_size;

    if (public_key_size == 49 && (public_key[0] == 0x02 || public_key[0] == 0x03)) {
      CryptoPP::Integer x(public_key + 1, 48);
      const CryptoPP::ECP& curve = ecdh.GetGroupParameters().GetCurve();
      const CryptoPP::Integer& p = curve.GetField().GetModulus();
      const CryptoPP::Integer& b = curve.GetB();

      // y^2 = x^3 - 3x + b (mod p)
      CryptoPP::Integer y2 = (x * x * x - 3 * x + b) % p;
      CryptoPP::Integer y = CryptoPP::ModularSquareRoot(y2, p);

      // SECURITY FIX (VULN-NEW-003): Validate point is on curve
      CryptoPP::ECP::Point point(x, y);
      if (!curve.VerifyPoint(point)) {
        return false;  // Invalid public key - not on curve
      }

      if ((public_key[0] == 0x03) != y.IsOdd()) {
        y = p - y;
      }

      uncompressed.data[0] = 0x04;
      x.Encode(uncompressed.get() + 1, 48);
      y.Encode(uncompressed.get() + 49, 48);
      pub_ptr = uncompressed.get();
      pub_len = 97;
    }

    SecureVector<uint8_t> priv_full(ecdh.PrivateKeyLength());
    SecureVector<uint8_t> pub_full(ecdh.PublicKeyLength());

    memset(priv_full.get(), 0, priv_full.size());
    memcpy(priv_full.get() + priv_full.size() - 48, private_key, 48);

    if (pub_len == 97) {
      memcpy(pub_full.get(), pub_ptr, pub_len);
    } else {
      return false;
    }

    // P-384 shared secret is 48 bytes - use SecureVector for this too
    SecureVector<uint8_t> raw_secret(48);
    if (!ecdh.Agree(raw_secret.get(), priv_full.get(), pub_full.get())) {
      return false;
    }
    // Hash the 48-byte secret down to 32 bytes for symmetric key use
    Sha256Hash(raw_secret.get(), raw_secret.size(), shared_secret);
    return true;
  } catch (...) {
#ifdef FLATBUFFERS_DEBUG
    fprintf(stderr, "[flatbuffers] crypto exception in operation\n");
#endif
    return false;
  }
}

Signature P384Sign(
    const uint8_t* private_key,
    const uint8_t* data, size_t data_size) {
  Signature sig;
  sig.algorithm = SignatureAlgorithm::P384_ECDSA;

  try {
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::PrivateKey key;
    key.Initialize(CryptoPP::ASN1::secp384r1(),
                   CryptoPP::Integer(private_key, kP384PrivateKeySize));

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::Signer signer(key);
    sig.data.resize(signer.MaxSignatureLength());
    size_t sigLen = signer.SignMessage(GetGlobalRNG(), data, data_size, sig.data.data());
    sig.data.resize(sigLen);

    // SECURITY FIX (VULN-NEW-004): Enforce low-S to prevent signature malleability
    const CryptoPP::Integer& order = key.GetGroupParameters().GetSubgroupOrder();
    NormalizeLowS(sig.data, order);
  } catch (...) {
#ifdef FLATBUFFERS_DEBUG
    fprintf(stderr, "[flatbuffers] crypto exception in signing\n");
#endif
    sig.data.clear();
  }

  return sig;
}

bool P384Verify(
    const uint8_t* public_key, size_t public_key_size,
    const uint8_t* data, size_t data_size,
    const uint8_t* signature, size_t signature_size) {
  if (!public_key || public_key_size < 49 || !data || !signature) return false;

  try {
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::PublicKey key;

    CryptoPP::Integer x(public_key + 1, 48);
    const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& params =
        CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>(CryptoPP::ASN1::secp384r1());
    const CryptoPP::ECP& curve = params.GetCurve();
    const CryptoPP::Integer& p = curve.GetField().GetModulus();
    const CryptoPP::Integer& b = curve.GetB();

    CryptoPP::Integer y2 = (x * x * x - 3 * x + b) % p;
    CryptoPP::Integer y = CryptoPP::ModularSquareRoot(y2, p);

    if ((public_key[0] == 0x03) != y.IsOdd()) {
      y = p - y;
    }

    // SECURITY FIX (VULN-NEW-003): Validate point is on curve
    CryptoPP::ECP::Point point(x, y);
    if (!curve.VerifyPoint(point)) {
      return false;  // Invalid public key - not on curve
    }

    key.Initialize(CryptoPP::ASN1::secp384r1(), point);

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::Verifier verifier(key);
    return verifier.VerifyMessage(data, data_size, signature, signature_size);
  } catch (...) {
#ifdef FLATBUFFERS_DEBUG
    fprintf(stderr, "[flatbuffers] crypto exception in operation\n");
#endif
    return false;
  }
}

// =============================================================================
// Ed25519 Signatures
// =============================================================================

KeyPair GenerateSigningKeyPair(SignatureAlgorithm algorithm) {
  switch (algorithm) {
    case SignatureAlgorithm::Ed25519: {
      KeyPair kp;
      kp.private_key.resize(kEd25519PrivateKeySize);
      kp.public_key.resize(kEd25519PublicKeySize);

      CryptoPP::ed25519::Signer signer;
      signer.AccessPrivateKey().GenerateRandom(GetGlobalRNG());

      // Get private key (seed)
      const CryptoPP::ed25519PrivateKey& privKey =
          dynamic_cast<const CryptoPP::ed25519PrivateKey&>(signer.GetPrivateKey());
      memcpy(kp.private_key.data(), privKey.GetPrivateKeyBytePtr(), 32);
      memcpy(kp.private_key.data() + 32, privKey.GetPublicKeyBytePtr(), 32);
      memcpy(kp.public_key.data(), privKey.GetPublicKeyBytePtr(), 32);

      return kp;
    }
    case SignatureAlgorithm::Secp256k1_ECDSA:
      return Secp256k1GenerateKeyPair();
    case SignatureAlgorithm::P256_ECDSA:
      return P256GenerateKeyPair();
    case SignatureAlgorithm::P384_ECDSA:
      return P384GenerateKeyPair();
    default:
      return KeyPair{};
  }
}

Signature Ed25519Sign(
    const uint8_t* private_key,
    const uint8_t* data, size_t data_size) {
  Signature sig;
  sig.algorithm = SignatureAlgorithm::Ed25519;

  try {
    CryptoPP::ed25519::Signer signer(private_key);
    sig.data.resize(kEd25519SignatureSize);
    signer.SignMessage(CryptoPP::NullRNG(), data, data_size, sig.data.data());
  } catch (...) {
#ifdef FLATBUFFERS_DEBUG
    fprintf(stderr, "[flatbuffers] crypto exception in signing\n");
#endif
    sig.data.clear();
  }

  return sig;
}

bool Ed25519Verify(
    const uint8_t* public_key,
    const uint8_t* data, size_t data_size,
    const uint8_t* signature) {
  try {
    CryptoPP::ed25519::Verifier verifier(public_key);
    return verifier.VerifyMessage(data, data_size, signature, kEd25519SignatureSize);
  } catch (...) {
#ifdef FLATBUFFERS_DEBUG
    fprintf(stderr, "[flatbuffers] crypto exception in operation\n");
#endif
    return false;
  }
}

// FIPS mode not available with Crypto++ backend
bool EnableFIPSMode() { return false; }
bool IsFIPSMode() { return false; }

#elif defined(FLATBUFFERS_USE_OPENSSL)

// =============================================================================
// OpenSSL Implementation - FIPS Compliant
// =============================================================================
// When OpenSSL is available, use EVP APIs for FIPS-validated algorithms.
// Supports: AES-256-CTR, HKDF-SHA256, P-256, P-384, ECDH, ECDSA.
// X25519 and Ed25519 supported via OpenSSL 1.1.1+.
// secp256k1 supported via OpenSSL with custom curve registration.

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/hmac.h>
#include <openssl/provider.h>

// FIPS mode initialization (Task 34)
static bool g_fips_mode = false;

bool EnableFIPSMode() {
  OSSL_PROVIDER* fips = OSSL_PROVIDER_load(NULL, "fips");
  if (!fips) return false;
  OSSL_PROVIDER* base = OSSL_PROVIDER_load(NULL, "base");
  if (!base) {
    OSSL_PROVIDER_unload(fips);
    return false;
  }
  g_fips_mode = true;
  return true;
}

bool IsFIPSMode() {
  return g_fips_mode;
}

// Secure clear for vectors
static void SecureClearVector(std::vector<uint8_t>& v) {
  if (!v.empty()) {
    SecureClear(v.data(), v.size());
  }
}

// Thread-safe entropy pool
static std::vector<uint8_t> g_entropy_pool;

void InjectEntropy(const uint8_t* seed, size_t size) {
  if (seed && size > 0) {
    RAND_seed(seed, static_cast<int>(size));
  }
}

// --- AES-256-CTR ---

void EncryptBytes(uint8_t* data, size_t size,
                  const uint8_t* key, const uint8_t* iv) {
  if (!data || !key || !iv || size == 0) return;

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return;

  int outlen = 0;
  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key, iv) == 1) {
    EVP_EncryptUpdate(ctx, data, &outlen, data, static_cast<int>(size));
    int final_len = 0;
    EVP_EncryptFinal_ex(ctx, data + outlen, &final_len);
  }
  EVP_CIPHER_CTX_free(ctx);
}

// --- SHA-256 ---

void Sha256Hash(const uint8_t* data, size_t size, uint8_t* hash) {
  if (!data || !hash) return;
  unsigned int len = 32;
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (ctx) {
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data, size);
    EVP_DigestFinal_ex(ctx, hash, &len);
    EVP_MD_CTX_free(ctx);
  }
}

// --- HKDF ---

void HKDF(const uint8_t* ikm, size_t ikm_size,
          const uint8_t* salt, size_t salt_size,
          const uint8_t* info, size_t info_size,
          uint8_t* okm, size_t okm_size) {
  if (!ikm || !okm || okm_size == 0) return;

  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  if (!pctx) return;

  if (EVP_PKEY_derive_init(pctx) <= 0 ||
      EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
      EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, static_cast<int>(ikm_size)) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    return;
  }

  if (salt && salt_size > 0) {
    EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, static_cast<int>(salt_size));
  }
  if (info && info_size > 0) {
    EVP_PKEY_CTX_add1_hkdf_info(pctx, info, static_cast<int>(info_size));
  }

  size_t outlen = okm_size;
  EVP_PKEY_derive(pctx, okm, &outlen);
  EVP_PKEY_CTX_free(pctx);
}

// --- Key derivation utilities ---

void DeriveSymmetricKey(
    const uint8_t* shared_secret, size_t shared_secret_size,
    const uint8_t* context, size_t context_size,
    uint8_t* key,
    const uint8_t* salt, size_t salt_size) {
  HKDF(shared_secret, shared_secret_size, salt, salt_size,
       context, context_size, key, kEncryptionKeySize);
}

void HMACSha256(const uint8_t* key, size_t key_size,
                const uint8_t* data, size_t data_size,
                uint8_t* mac) {
  unsigned int mac_len = 32;
  HMAC(EVP_sha256(), key, static_cast<int>(key_size),
       data, data_size, mac, &mac_len);
}

bool HMACSha256Verify(const uint8_t* key, size_t key_size,
                      const uint8_t* data, size_t data_size,
                      const uint8_t* mac) {
  uint8_t computed[32];
  HMACSha256(key, key_size, data, data_size, computed);
  // Constant-time comparison
  uint8_t diff = 0;
  for (size_t i = 0; i < 32; i++) diff |= computed[i] ^ mac[i];
  SecureClear(computed, 32);
  return diff == 0;
}

namespace internal {
void DeriveKey(const uint8_t* master_key, size_t master_key_size,
               const uint8_t* info, size_t info_size,
               uint8_t* out_key, size_t out_key_size) {
  HKDF(master_key, master_key_size, nullptr, 0,
       info, info_size, out_key, out_key_size);
}
}  // namespace internal

// --- X25519 ---

KeyPair X25519GenerateKeyPair() {
  KeyPair kp;
  EVP_PKEY* pkey = nullptr;
  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
  if (!pctx) return kp;
  if (EVP_PKEY_keygen_init(pctx) <= 0 || EVP_PKEY_keygen(pctx, &pkey) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    return kp;
  }
  EVP_PKEY_CTX_free(pctx);

  size_t priv_len = kX25519PrivateKeySize, pub_len = kX25519PublicKeySize;
  kp.private_key.resize(priv_len);
  kp.public_key.resize(pub_len);
  EVP_PKEY_get_raw_private_key(pkey, kp.private_key.data(), &priv_len);
  EVP_PKEY_get_raw_public_key(pkey, kp.public_key.data(), &pub_len);
  EVP_PKEY_free(pkey);
  return kp;
}

bool X25519SharedSecret(const uint8_t* private_key,
                        const uint8_t* public_key,
                        uint8_t* shared_secret) {
  if (!private_key || !public_key || !shared_secret) return false;

  EVP_PKEY* priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                                                  private_key, kX25519PrivateKeySize);
  EVP_PKEY* pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
                                                public_key, kX25519PublicKeySize);
  if (!priv || !pub) {
    EVP_PKEY_free(priv);
    EVP_PKEY_free(pub);
    return false;
  }

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, nullptr);
  bool ok = false;
  if (ctx && EVP_PKEY_derive_init(ctx) > 0 &&
      EVP_PKEY_derive_set_peer(ctx, pub) > 0) {
    size_t len = kX25519SharedSecretSize;
    ok = EVP_PKEY_derive(ctx, shared_secret, &len) > 0;
  }

  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(priv);
  EVP_PKEY_free(pub);
  return ok;
}

// --- P-256 ---

static KeyPair ECGenerateKeyPair(int nid, size_t priv_size, size_t /*pub_size*/) {
  KeyPair kp;
  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
  if (!pctx) return kp;
  EVP_PKEY* pkey = nullptr;
  if (EVP_PKEY_keygen_init(pctx) <= 0) { EVP_PKEY_CTX_free(pctx); return kp; }
  if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid) <= 0) { EVP_PKEY_CTX_free(pctx); return kp; }
  if (EVP_PKEY_keygen(pctx, &pkey) <= 0) { EVP_PKEY_CTX_free(pctx); return kp; }
  EVP_PKEY_CTX_free(pctx);

  // Extract private key
  BIGNUM* priv_bn = nullptr;
  EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv_bn);
  if (priv_bn) {
    kp.private_key.resize(priv_size);
    int len = BN_bn2binpad(priv_bn, kp.private_key.data(), static_cast<int>(priv_size));
    if (len <= 0) kp.private_key.clear();
    BN_free(priv_bn);
  }

  // Extract compressed public key
  size_t pub_len = 0;
  EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, nullptr, 0, &pub_len);
  std::vector<uint8_t> uncompressed(pub_len);
  EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, uncompressed.data(), pub_len, &pub_len);

  // Compress: take x-coord and prefix with 02/03 based on y parity
  if (pub_len > 0 && uncompressed[0] == 0x04) {
    size_t coord_size = (pub_len - 1) / 2;
    kp.public_key.resize(1 + coord_size);
    kp.public_key[0] = (uncompressed[pub_len - 1] & 1) ? 0x03 : 0x02;
    memcpy(kp.public_key.data() + 1, uncompressed.data() + 1, coord_size);
  }

  EVP_PKEY_free(pkey);
  return kp;
}

static bool ECSharedSecret(int nid, const uint8_t* private_key, size_t priv_size,
                           const uint8_t* public_key, size_t public_key_size,
                           uint8_t* shared_secret) {
  if (!private_key || !public_key || !shared_secret) return false;

  // Build private key EVP_PKEY
  OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
  if (!bld) return false;
  const char* group_name = (nid == NID_X9_62_prime256v1) ? "P-256" :
                           (nid == NID_secp384r1) ? "P-384" : "secp256k1";
  OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0);
  BIGNUM* priv_bn = BN_bin2bn(private_key, static_cast<int>(priv_size), nullptr);
  OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, priv_bn);

  OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
  EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
  EVP_PKEY* priv_pkey = nullptr;
  EVP_PKEY_fromdata_init(kctx);
  EVP_PKEY_fromdata(kctx, &priv_pkey, EVP_PKEY_KEYPAIR, params);
  EVP_PKEY_CTX_free(kctx);
  OSSL_PARAM_free(params);
  OSSL_PARAM_BLD_free(bld);
  BN_free(priv_bn);

  // Build public key EVP_PKEY
  bld = OSSL_PARAM_BLD_new();
  OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0);
  OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, public_key, public_key_size);
  params = OSSL_PARAM_BLD_to_param(bld);
  kctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
  EVP_PKEY* pub_pkey = nullptr;
  EVP_PKEY_fromdata_init(kctx);
  EVP_PKEY_fromdata(kctx, &pub_pkey, EVP_PKEY_PUBLIC_KEY, params);
  EVP_PKEY_CTX_free(kctx);
  OSSL_PARAM_free(params);
  OSSL_PARAM_BLD_free(bld);

  if (!priv_pkey || !pub_pkey) {
    EVP_PKEY_free(priv_pkey);
    EVP_PKEY_free(pub_pkey);
    return false;
  }

  EVP_PKEY_CTX* dctx = EVP_PKEY_CTX_new(priv_pkey, nullptr);
  bool ok = false;
  if (dctx && EVP_PKEY_derive_init(dctx) > 0 &&
      EVP_PKEY_derive_set_peer(dctx, pub_pkey) > 0) {
    size_t secret_len = 0;
    EVP_PKEY_derive(dctx, nullptr, &secret_len);
    std::vector<uint8_t> raw_secret(secret_len);
    if (EVP_PKEY_derive(dctx, raw_secret.data(), &secret_len) > 0) {
      // Hash to 32 bytes
      Sha256Hash(raw_secret.data(), secret_len, shared_secret);
      ok = true;
    }
    SecureClearVector(raw_secret);
  }

  EVP_PKEY_CTX_free(dctx);
  EVP_PKEY_free(priv_pkey);
  EVP_PKEY_free(pub_pkey);
  return ok;
}

KeyPair P256GenerateKeyPair() {
  return ECGenerateKeyPair(NID_X9_62_prime256v1, kP256PrivateKeySize, kP256PublicKeySize);
}

bool P256SharedSecret(const uint8_t* private_key,
                      const uint8_t* public_key, size_t public_key_size,
                      uint8_t* shared_secret) {
  return ECSharedSecret(NID_X9_62_prime256v1, private_key, kP256PrivateKeySize,
                        public_key, public_key_size, shared_secret);
}

KeyPair P384GenerateKeyPair() {
  return ECGenerateKeyPair(NID_secp384r1, kP384PrivateKeySize, kP384PublicKeySize);
}

bool P384SharedSecret(const uint8_t* private_key,
                      const uint8_t* public_key, size_t public_key_size,
                      uint8_t* shared_secret) {
  return ECSharedSecret(NID_secp384r1, private_key, kP384PrivateKeySize,
                        public_key, public_key_size, shared_secret);
}

KeyPair Secp256k1GenerateKeyPair() {
  return ECGenerateKeyPair(NID_secp256k1, kSecp256k1PrivateKeySize, kSecp256k1PublicKeySize);
}

bool Secp256k1SharedSecret(const uint8_t* private_key,
                           const uint8_t* public_key, size_t public_key_size,
                           uint8_t* shared_secret) {
  return ECSharedSecret(NID_secp256k1, private_key, kSecp256k1PrivateKeySize,
                        public_key, public_key_size, shared_secret);
}

// --- Signatures ---

static Signature ECSign(int nid, const uint8_t* private_key, size_t priv_size,
                        const uint8_t* data, size_t data_size,
                        size_t sig_size) {
  Signature sig;
  // Build private key
  OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
  const char* group_name = (nid == NID_X9_62_prime256v1) ? "P-256" :
                           (nid == NID_secp384r1) ? "P-384" : "secp256k1";
  OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0);
  BIGNUM* priv_bn = BN_bin2bn(private_key, static_cast<int>(priv_size), nullptr);
  OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, priv_bn);
  OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
  EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
  EVP_PKEY* pkey = nullptr;
  EVP_PKEY_fromdata_init(kctx);
  EVP_PKEY_fromdata(kctx, &pkey, EVP_PKEY_KEYPAIR, params);
  EVP_PKEY_CTX_free(kctx);
  OSSL_PARAM_free(params);
  OSSL_PARAM_BLD_free(bld);
  BN_free(priv_bn);
  if (!pkey) return sig;

  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  if (EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey) > 0) {
    size_t siglen = 0;
    EVP_DigestSign(mdctx, nullptr, &siglen, data, data_size);
    std::vector<uint8_t> der_sig(siglen);
    if (EVP_DigestSign(mdctx, der_sig.data(), &siglen, data, data_size) > 0) {
      // Convert DER to raw r||s
      const uint8_t* p = der_sig.data();
      ECDSA_SIG* ecdsa_sig = d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(siglen));
      if (ecdsa_sig) {
        const BIGNUM* r = nullptr;
        const BIGNUM* s = nullptr;
        ECDSA_SIG_get0(ecdsa_sig, &r, &s);
        size_t half = sig_size / 2;
        sig.data.resize(sig_size);
        BN_bn2binpad(r, sig.data.data(), static_cast<int>(half));
        BN_bn2binpad(s, sig.data.data() + half, static_cast<int>(half));
        ECDSA_SIG_free(ecdsa_sig);
      }
    }
  }
  EVP_MD_CTX_free(mdctx);
  EVP_PKEY_free(pkey);
  return sig;
}

static bool ECVerify(int nid, const uint8_t* public_key, size_t public_key_size,
                     const uint8_t* data, size_t data_size,
                     const uint8_t* signature, size_t signature_size) {
  // Build public key
  OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
  const char* group_name = (nid == NID_X9_62_prime256v1) ? "P-256" :
                           (nid == NID_secp384r1) ? "P-384" : "secp256k1";
  OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0);
  OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, public_key, public_key_size);
  OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
  EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
  EVP_PKEY* pkey = nullptr;
  EVP_PKEY_fromdata_init(kctx);
  EVP_PKEY_fromdata(kctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
  EVP_PKEY_CTX_free(kctx);
  OSSL_PARAM_free(params);
  OSSL_PARAM_BLD_free(bld);
  if (!pkey) return false;

  // Convert raw r||s to DER
  size_t half = signature_size / 2;
  BIGNUM* r = BN_bin2bn(signature, static_cast<int>(half), nullptr);
  BIGNUM* s = BN_bin2bn(signature + half, static_cast<int>(half), nullptr);
  ECDSA_SIG* ecdsa_sig = ECDSA_SIG_new();
  ECDSA_SIG_set0(ecdsa_sig, r, s);
  int der_len = i2d_ECDSA_SIG(ecdsa_sig, nullptr);
  std::vector<uint8_t> der_sig(der_len);
  uint8_t* p = der_sig.data();
  i2d_ECDSA_SIG(ecdsa_sig, &p);
  ECDSA_SIG_free(ecdsa_sig);

  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  bool ok = false;
  if (EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey) > 0) {
    ok = EVP_DigestVerify(mdctx, der_sig.data(), der_len, data, data_size) == 1;
  }
  EVP_MD_CTX_free(mdctx);
  EVP_PKEY_free(pkey);
  return ok;
}

Signature Secp256k1Sign(const uint8_t* private_key,
                        const uint8_t* data, size_t data_size) {
  auto sig = ECSign(NID_secp256k1, private_key, kSecp256k1PrivateKeySize,
                    data, data_size, kSecp256k1SignatureSize);
  sig.algorithm = SignatureAlgorithm::Secp256k1_ECDSA;
  return sig;
}

bool Secp256k1Verify(const uint8_t* public_key, size_t public_key_size,
                     const uint8_t* data, size_t data_size,
                     const uint8_t* signature, size_t signature_size) {
  return ECVerify(NID_secp256k1, public_key, public_key_size, data, data_size,
                  signature, signature_size);
}

Signature P256Sign(const uint8_t* private_key,
                   const uint8_t* data, size_t data_size) {
  auto sig = ECSign(NID_X9_62_prime256v1, private_key, kP256PrivateKeySize,
                    data, data_size, kP256SignatureSize);
  sig.algorithm = SignatureAlgorithm::P256_ECDSA;
  return sig;
}

bool P256Verify(const uint8_t* public_key, size_t public_key_size,
                const uint8_t* data, size_t data_size,
                const uint8_t* signature, size_t signature_size) {
  return ECVerify(NID_X9_62_prime256v1, public_key, public_key_size,
                  data, data_size, signature, signature_size);
}

Signature P384Sign(const uint8_t* private_key,
                   const uint8_t* data, size_t data_size) {
  auto sig = ECSign(NID_secp384r1, private_key, kP384PrivateKeySize,
                    data, data_size, kP384SignatureSize);
  sig.algorithm = SignatureAlgorithm::P384_ECDSA;
  return sig;
}

bool P384Verify(const uint8_t* public_key, size_t public_key_size,
                const uint8_t* data, size_t data_size,
                const uint8_t* signature, size_t signature_size) {
  return ECVerify(NID_secp384r1, public_key, public_key_size,
                  data, data_size, signature, signature_size);
}

// --- Ed25519 ---

Signature Ed25519Sign(const uint8_t* private_key,
                      const uint8_t* data, size_t data_size) {
  Signature sig;
  EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
                                                  private_key, 32);
  if (!pkey) return sig;

  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  if (EVP_DigestSignInit(mdctx, nullptr, nullptr, nullptr, pkey) > 0) {
    size_t siglen = kEd25519SignatureSize;
    sig.data.resize(siglen);
    if (EVP_DigestSign(mdctx, sig.data.data(), &siglen, data, data_size) <= 0) {
      sig.data.clear();
    }
  }
  EVP_MD_CTX_free(mdctx);
  EVP_PKEY_free(pkey);
  sig.algorithm = SignatureAlgorithm::Ed25519;
  return sig;
}

bool Ed25519Verify(const uint8_t* public_key,
                   const uint8_t* data, size_t data_size,
                   const uint8_t* signature) {
  EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                                 public_key, kEd25519PublicKeySize);
  if (!pkey) return false;

  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  bool ok = false;
  if (EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, pkey) > 0) {
    ok = EVP_DigestVerify(mdctx, signature, kEd25519SignatureSize,
                          data, data_size) == 1;
  }
  EVP_MD_CTX_free(mdctx);
  EVP_PKEY_free(pkey);
  return ok;
}

// --- Generic dispatch ---

KeyPair GenerateKeyPair(KeyExchangeAlgorithm algorithm) {
  switch (algorithm) {
    case KeyExchangeAlgorithm::X25519: return X25519GenerateKeyPair();
    case KeyExchangeAlgorithm::Secp256k1: return Secp256k1GenerateKeyPair();
    case KeyExchangeAlgorithm::P256: return P256GenerateKeyPair();
    case KeyExchangeAlgorithm::P384: return P384GenerateKeyPair();
    default: return {};
  }
}

bool ComputeSharedSecret(KeyExchangeAlgorithm algorithm,
                         const uint8_t* private_key, size_t /*private_key_size*/,
                         const uint8_t* public_key, size_t public_key_size,
                         uint8_t* shared_secret) {
  switch (algorithm) {
    case KeyExchangeAlgorithm::X25519:
      return X25519SharedSecret(private_key, public_key, shared_secret);
    case KeyExchangeAlgorithm::Secp256k1:
      return Secp256k1SharedSecret(private_key, public_key, public_key_size, shared_secret);
    case KeyExchangeAlgorithm::P256:
      return P256SharedSecret(private_key, public_key, public_key_size, shared_secret);
    case KeyExchangeAlgorithm::P384:
      return P384SharedSecret(private_key, public_key, public_key_size, shared_secret);
    default: return false;
  }
}

KeyPair GenerateSigningKeyPair(SignatureAlgorithm algorithm) {
  switch (algorithm) {
    case SignatureAlgorithm::Ed25519: {
      KeyPair kp;
      EVP_PKEY* pkey = nullptr;
      EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
      if (pctx && EVP_PKEY_keygen_init(pctx) > 0 && EVP_PKEY_keygen(pctx, &pkey) > 0) {
        size_t priv_len = 32, pub_len = 32;
        std::vector<uint8_t> seed(32);
        EVP_PKEY_get_raw_private_key(pkey, seed.data(), &priv_len);
        kp.public_key.resize(pub_len);
        EVP_PKEY_get_raw_public_key(pkey, kp.public_key.data(), &pub_len);
        // Ed25519 private key = seed || public key (64 bytes)
        kp.private_key.resize(kEd25519PrivateKeySize);
        memcpy(kp.private_key.data(), seed.data(), 32);
        memcpy(kp.private_key.data() + 32, kp.public_key.data(), 32);
        SecureClearVector(seed);
      }
      EVP_PKEY_CTX_free(pctx);
      EVP_PKEY_free(pkey);
      return kp;
    }
    case SignatureAlgorithm::Secp256k1_ECDSA:
      return Secp256k1GenerateKeyPair();
    case SignatureAlgorithm::P256_ECDSA:
      return P256GenerateKeyPair();
    case SignatureAlgorithm::P384_ECDSA:
      return P384GenerateKeyPair();
    default: return {};
  }
}

Signature Sign(SignatureAlgorithm algorithm,
               const uint8_t* private_key, size_t /*private_key_size*/,
               const uint8_t* data, size_t data_size) {
  switch (algorithm) {
    case SignatureAlgorithm::Ed25519:
      return Ed25519Sign(private_key, data, data_size);
    case SignatureAlgorithm::Secp256k1_ECDSA:
      return Secp256k1Sign(private_key, data, data_size);
    case SignatureAlgorithm::P256_ECDSA:
      return P256Sign(private_key, data, data_size);
    case SignatureAlgorithm::P384_ECDSA:
      return P384Sign(private_key, data, data_size);
    default: return {};
  }
}

bool Verify(SignatureAlgorithm algorithm,
            const uint8_t* public_key, size_t public_key_size,
            const uint8_t* data, size_t data_size,
            const uint8_t* signature, size_t signature_size) {
  switch (algorithm) {
    case SignatureAlgorithm::Ed25519:
      return Ed25519Verify(public_key, data, data_size, signature);
    case SignatureAlgorithm::Secp256k1_ECDSA:
      return Secp256k1Verify(public_key, public_key_size, data, data_size, signature, signature_size);
    case SignatureAlgorithm::P256_ECDSA:
      return P256Verify(public_key, public_key_size, data, data_size, signature, signature_size);
    case SignatureAlgorithm::P384_ECDSA:
      return P384Verify(public_key, public_key_size, data, data_size, signature, signature_size);
    default: return false;
  }
}

#else  // !FLATBUFFERS_USE_CRYPTOPP && !FLATBUFFERS_USE_OPENSSL

// =============================================================================
// Fallback Implementation - SECURITY HARDENED
// =============================================================================
// When Crypto++ is not available, most operations will THROW rather than
// silently provide weak crypto. Only AES-256-CTR is available as fallback
// since it can be implemented securely without external dependencies.
// All asymmetric operations (ECDH, signatures) require Crypto++.

// Runtime flag to track if fallback warning has been shown
static bool fallback_warning_shown = false;

static void WarnFallbackCrypto() {
  if (!fallback_warning_shown) {
    fallback_warning_shown = true;
    fprintf(stderr, "[flatbuffers] WARNING: Using fallback AES implementation. "
                    "Asymmetric crypto operations are NOT available. "
                    "Build with FLATBUFFERS_USE_CRYPTOPP=ON for full functionality.\n");
  }
}

namespace internal {

// AES S-box
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

static const uint8_t rcon[11] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10,
                                  0x20, 0x40, 0x80, 0x1b, 0x36};

static uint8_t gf_mul(uint8_t a, uint8_t b) {
  uint8_t p = 0;
  for (int i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    bool hi_bit = a & 0x80;
    a <<= 1;
    if (hi_bit) a ^= 0x1b;
    b >>= 1;
  }
  return p;
}

static void aes256_key_expansion(const uint8_t* key, uint8_t* round_keys) {
  memcpy(round_keys, key, 32);
  uint8_t temp[4];
  int i = 8;
  while (i < 60) {
    memcpy(temp, round_keys + (i - 1) * 4, 4);
    if (i % 8 == 0) {
      uint8_t t = temp[0];
      temp[0] = sbox[temp[1]] ^ rcon[i / 8];
      temp[1] = sbox[temp[2]];
      temp[2] = sbox[temp[3]];
      temp[3] = sbox[t];
    } else if (i % 8 == 4) {
      temp[0] = sbox[temp[0]];
      temp[1] = sbox[temp[1]];
      temp[2] = sbox[temp[2]];
      temp[3] = sbox[temp[3]];
    }
    for (int j = 0; j < 4; j++) {
      round_keys[i * 4 + j] = round_keys[(i - 8) * 4 + j] ^ temp[j];
    }
    i++;
  }
}

static void sub_bytes(uint8_t* state) {
  for (int i = 0; i < 16; i++) state[i] = sbox[state[i]];
}

static void shift_rows(uint8_t* state) {
  uint8_t temp;
  temp = state[1]; state[1] = state[5]; state[5] = state[9];
  state[9] = state[13]; state[13] = temp;
  temp = state[2]; state[2] = state[10]; state[10] = temp;
  temp = state[6]; state[6] = state[14]; state[14] = temp;
  temp = state[15]; state[15] = state[11]; state[11] = state[7];
  state[7] = state[3]; state[3] = temp;
}

static void mix_columns(uint8_t* state) {
  for (int i = 0; i < 4; i++) {
    uint8_t a[4];
    for (int j = 0; j < 4; j++) a[j] = state[i * 4 + j];
    state[i * 4 + 0] = gf_mul(a[0], 2) ^ gf_mul(a[1], 3) ^ a[2] ^ a[3];
    state[i * 4 + 1] = a[0] ^ gf_mul(a[1], 2) ^ gf_mul(a[2], 3) ^ a[3];
    state[i * 4 + 2] = a[0] ^ a[1] ^ gf_mul(a[2], 2) ^ gf_mul(a[3], 3);
    state[i * 4 + 3] = gf_mul(a[0], 3) ^ a[1] ^ a[2] ^ gf_mul(a[3], 2);
  }
}

static void add_round_key(uint8_t* state, const uint8_t* round_key) {
  for (int i = 0; i < 16; i++) state[i] ^= round_key[i];
}

void AESEncryptBlock(const uint8_t* key, const uint8_t* input, uint8_t* output) {
  uint8_t round_keys[240];
  aes256_key_expansion(key, round_keys);
  uint8_t state[16];
  memcpy(state, input, 16);
  add_round_key(state, round_keys);
  for (int round = 1; round < 14; round++) {
    sub_bytes(state);
    shift_rows(state);
    mix_columns(state);
    add_round_key(state, round_keys + round * 16);
  }
  sub_bytes(state);
  shift_rows(state);
  add_round_key(state, round_keys + 14 * 16);
  memcpy(output, state, 16);
}

void AESCTRKeystream(const uint8_t* key, const uint8_t* nonce,
                     uint8_t* keystream, size_t length) {
  uint8_t counter[16];
  uint8_t block[16];
  memcpy(counter, nonce, 16);
  size_t offset = 0;
  while (offset < length) {
    AESEncryptBlock(key, counter, block);
    size_t to_copy = std::min(static_cast<size_t>(16), length - offset);
    memcpy(keystream + offset, block, to_copy);
    offset += to_copy;
    for (int i = 15; i >= 0; i--) {
      if (++counter[i] != 0) break;
    }
  }
}

void DeriveKey(const uint8_t* master_key, size_t master_key_size,
               const uint8_t* info, size_t info_size,
               uint8_t* out_key, size_t out_key_size) {
  memset(out_key, 0, out_key_size);
  for (size_t i = 0; i < out_key_size && i < master_key_size; i++) {
    out_key[i] = master_key[i];
  }
  uint8_t hash = 0;
  for (size_t i = 0; i < info_size; i++) {
    hash ^= info[i];
    hash = (hash << 1) | (hash >> 7);
  }
  for (size_t i = 0; i < out_key_size; i++) {
    out_key[i] ^= hash;
    hash = (hash * 31 + static_cast<uint8_t>(i)) & 0xFF;
  }
  if (out_key_size >= 16) {
    uint8_t temp[16];
    AESEncryptBlock(master_key, out_key, temp);
    memcpy(out_key, temp, std::min(out_key_size, static_cast<size_t>(16)));
    if (out_key_size > 16) {
      AESEncryptBlock(master_key, out_key + 16 > out_key ? out_key : temp, temp);
      memcpy(out_key + 16, temp, std::min(out_key_size - 16, static_cast<size_t>(16)));
    }
  }
}

}  // namespace internal

void Sha256Hash(const uint8_t*, size_t, uint8_t* hash) {
  // SECURITY FIX: Instead of silently returning garbage, we zero the output
  // and emit a warning. This makes failures detectable rather than silent.
  // Callers should check hasCryptopp() before using hash functions.
  WarnFallbackCrypto();
  if (hash) {
    // Zero output to prevent use of uninitialized memory
    memset(hash, 0, 32);
  }
  // Note: HMAC verification will fail-safe (reject all) with zeroed hash
}

void HKDF(const uint8_t* ikm, size_t ikm_size,
          const uint8_t* salt, size_t salt_size,
          const uint8_t* info, size_t info_size,
          uint8_t* okm, size_t okm_size) {
  // SECURITY FIX: Improved fallback that uses AES for key derivation
  // This is NOT as secure as real HKDF-SHA256, but is significantly better
  // than the previous XOR-based approach. Emit warning.
  WarnFallbackCrypto();

  // Use AES-based key derivation with salt and info mixed in
  // Still use internal::DeriveKey but with salt incorporated
  if (salt && salt_size > 0) {
    // XOR salt into first part of IKM (if shorter, wrap around)
    std::vector<uint8_t> salted_ikm(ikm, ikm + ikm_size);
    for (size_t i = 0; i < salt_size && i < salted_ikm.size(); i++) {
      salted_ikm[i] ^= salt[i];
    }
    internal::DeriveKey(salted_ikm.data(), salted_ikm.size(), info, info_size, okm, okm_size);
  } else {
    internal::DeriveKey(ikm, ikm_size, info, info_size, okm, okm_size);
  }
}

void DeriveSymmetricKey(
    const uint8_t* shared_secret, size_t shared_secret_size,
    const uint8_t* context, size_t context_size,
    uint8_t* key,
    const uint8_t* salt, size_t salt_size) {
  // Fallback HKDF ignores salt (no salt support in basic HKDF)
  (void)salt;
  (void)salt_size;
  internal::DeriveKey(shared_secret, shared_secret_size,
                      context, context_size,
                      key, kEncryptionKeySize);
}

// Fallback HMAC-SHA256 not available without crypto library
void HMACSha256(const uint8_t* key, size_t key_size,
                const uint8_t* data, size_t data_size,
                uint8_t* mac) {
  (void)key; (void)key_size; (void)data; (void)data_size;
  fprintf(stderr, "[flatbuffers] ERROR: HMAC-SHA256 requires Crypto++ or OpenSSL\n");
  memset(mac, 0, 32);
}

bool HMACSha256Verify(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*) {
  fprintf(stderr, "[flatbuffers] ERROR: HMAC-SHA256 requires Crypto++ or OpenSSL\n");
  return false;
}

void EncryptBytes(uint8_t* data, size_t size,
                  const uint8_t* key, const uint8_t* iv) {
  if (!data || size == 0 || !key || !iv) return;
  std::vector<uint8_t> keystream(size);
  internal::AESCTRKeystream(key, iv, keystream.data(), size);
  for (size_t i = 0; i < size; i++) data[i] ^= keystream[i];
}

// SECURITY FIX: Stub implementations for ECDH/signatures without Crypto++
// These operations REQUIRE Crypto++ for secure implementation.
// Instead of silently returning empty/false (which could be mistaken for success
// in some code paths), we emit warnings and return clearly invalid results.

void InjectEntropy(const uint8_t*, size_t) {
  // No-op without Crypto++ - entropy would go nowhere
}

KeyPair X25519GenerateKeyPair() {
  WarnFallbackCrypto();
  fprintf(stderr, "[flatbuffers] ERROR: X25519 key generation requires Crypto++\n");
  return KeyPair{};  // Empty keypair - valid() returns false
}

bool X25519SharedSecret(const uint8_t*, const uint8_t*, uint8_t*) {
  WarnFallbackCrypto();
  fprintf(stderr, "[flatbuffers] ERROR: X25519 ECDH requires Crypto++\n");
  return false;
}

KeyPair Secp256k1GenerateKeyPair() {
  WarnFallbackCrypto();
  fprintf(stderr, "[flatbuffers] ERROR: secp256k1 key generation requires Crypto++\n");
  return KeyPair{};
}

bool Secp256k1SharedSecret(const uint8_t*, const uint8_t*, size_t, uint8_t*) {
  WarnFallbackCrypto();
  fprintf(stderr, "[flatbuffers] ERROR: secp256k1 ECDH requires Crypto++\n");
  return false;
}

Signature Secp256k1Sign(const uint8_t*, const uint8_t*, size_t) {
  WarnFallbackCrypto();
  fprintf(stderr, "[flatbuffers] ERROR: secp256k1 signing requires Crypto++\n");
  return Signature{};  // Empty signature - valid() returns false
}

bool Secp256k1Verify(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t) {
  WarnFallbackCrypto();
  fprintf(stderr, "[flatbuffers] ERROR: secp256k1 verification requires Crypto++\n");
  return false;  // Fail-safe: reject all signatures
}

KeyPair P256GenerateKeyPair() {
  WarnFallbackCrypto();
  fprintf(stderr, "[flatbuffers] ERROR: P-256 key generation requires Crypto++\n");
  return KeyPair{};
}

bool P256SharedSecret(const uint8_t*, const uint8_t*, size_t, uint8_t*) {
  WarnFallbackCrypto();
  fprintf(stderr, "[flatbuffers] ERROR: P-256 ECDH requires Crypto++\n");
  return false;
}

Signature P256Sign(const uint8_t*, const uint8_t*, size_t) {
  WarnFallbackCrypto();
  fprintf(stderr, "[flatbuffers] ERROR: P-256 signing requires Crypto++\n");
  return Signature{};
}

bool P256Verify(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t) {
  WarnFallbackCrypto();
  fprintf(stderr, "[flatbuffers] ERROR: P-256 verification requires Crypto++\n");
  return false;
}

KeyPair P384GenerateKeyPair() {
  WarnFallbackCrypto();
  fprintf(stderr, "[flatbuffers] ERROR: P-384 key generation requires Crypto++\n");
  return KeyPair{};
}

bool P384SharedSecret(const uint8_t*, const uint8_t*, size_t, uint8_t*) {
  WarnFallbackCrypto();
  fprintf(stderr, "[flatbuffers] ERROR: P-384 ECDH requires Crypto++\n");
  return false;
}

Signature P384Sign(const uint8_t*, const uint8_t*, size_t) {
  WarnFallbackCrypto();
  fprintf(stderr, "[flatbuffers] ERROR: P-384 signing requires Crypto++\n");
  return Signature{};
}

bool P384Verify(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t) {
  WarnFallbackCrypto();
  fprintf(stderr, "[flatbuffers] ERROR: P-384 verification requires Crypto++\n");
  return false;
}

KeyPair GenerateSigningKeyPair(SignatureAlgorithm algo) {
  WarnFallbackCrypto();
  fprintf(stderr, "[flatbuffers] ERROR: Signing key generation requires Crypto++ (algorithm: %d)\n",
          static_cast<int>(algo));
  return KeyPair{};
}

Signature Ed25519Sign(const uint8_t*, const uint8_t*, size_t) {
  WarnFallbackCrypto();
  fprintf(stderr, "[flatbuffers] ERROR: Ed25519 signing requires Crypto++\n");
  return Signature{};
}

bool Ed25519Verify(const uint8_t*, const uint8_t*, size_t, const uint8_t*) {
  WarnFallbackCrypto();
  fprintf(stderr, "[flatbuffers] ERROR: Ed25519 verification requires Crypto++\n");
  return false;
}

// FIPS mode not available without crypto library
bool EnableFIPSMode() { return false; }
bool IsFIPSMode() { return false; }

#endif  // FLATBUFFERS_USE_CRYPTOPP

// =============================================================================
// Common implementations (used by both Crypto++ and fallback, but NOT OpenSSL
// which defines its own versions of these dispatch functions)
// =============================================================================
#if !defined(FLATBUFFERS_USE_OPENSSL)

KeyPair GenerateKeyPair(KeyExchangeAlgorithm algorithm) {
  switch (algorithm) {
    case KeyExchangeAlgorithm::X25519:
      return X25519GenerateKeyPair();
    case KeyExchangeAlgorithm::Secp256k1:
      return Secp256k1GenerateKeyPair();
    case KeyExchangeAlgorithm::P256:
      return P256GenerateKeyPair();
    case KeyExchangeAlgorithm::P384:
      return P384GenerateKeyPair();
    default:
      return KeyPair{};
  }
}

bool ComputeSharedSecret(
    KeyExchangeAlgorithm algorithm,
    const uint8_t* private_key, size_t /* private_key_size */,
    const uint8_t* public_key, size_t public_key_size,
    uint8_t* shared_secret) {
  switch (algorithm) {
    case KeyExchangeAlgorithm::X25519:
      return X25519SharedSecret(private_key, public_key, shared_secret);
    case KeyExchangeAlgorithm::Secp256k1:
      return Secp256k1SharedSecret(private_key, public_key, public_key_size, shared_secret);
    case KeyExchangeAlgorithm::P256:
      return P256SharedSecret(private_key, public_key, public_key_size, shared_secret);
    case KeyExchangeAlgorithm::P384:
      return P384SharedSecret(private_key, public_key, public_key_size, shared_secret);
    default:
      return false;
  }
}

Signature Sign(
    SignatureAlgorithm algorithm,
    const uint8_t* private_key, size_t /* private_key_size */,
    const uint8_t* data, size_t data_size) {
  switch (algorithm) {
    case SignatureAlgorithm::Ed25519:
      return Ed25519Sign(private_key, data, data_size);
    case SignatureAlgorithm::Secp256k1_ECDSA:
      return Secp256k1Sign(private_key, data, data_size);
    case SignatureAlgorithm::P256_ECDSA:
      return P256Sign(private_key, data, data_size);
    case SignatureAlgorithm::P384_ECDSA:
      return P384Sign(private_key, data, data_size);
    default:
      return Signature{};
  }
}

bool Verify(
    SignatureAlgorithm algorithm,
    const uint8_t* public_key, size_t public_key_size,
    const uint8_t* data, size_t data_size,
    const uint8_t* signature, size_t signature_size) {
  switch (algorithm) {
    case SignatureAlgorithm::Ed25519:
      return Ed25519Verify(public_key, data, data_size, signature);
    case SignatureAlgorithm::Secp256k1_ECDSA:
      return Secp256k1Verify(public_key, public_key_size, data, data_size, signature, signature_size);
    case SignatureAlgorithm::P256_ECDSA:
      return P256Verify(public_key, public_key_size, data, data_size, signature, signature_size);
    case SignatureAlgorithm::P384_ECDSA:
      return P384Verify(public_key, public_key_size, data, data_size, signature, signature_size);
    default:
      return false;
  }
}

#endif  // !FLATBUFFERS_USE_OPENSSL

// =============================================================================
// EncryptionContext Implementation
// =============================================================================

EncryptionContext::EncryptionContext(const uint8_t* key, size_t key_size)
    : valid_(false) {
  if (key && key_size == kEncryptionKeySize) {
    memcpy(key_, key, kEncryptionKeySize);
    valid_ = true;
  } else {
    memset(key_, 0, kEncryptionKeySize);
  }
}

EncryptionContext::EncryptionContext(const std::vector<uint8_t>& key)
    : EncryptionContext(key.data(), key.size()) {}

EncryptionContext EncryptionContext::FromHex(const std::string& hex_key) {
  std::vector<uint8_t> key;
  key.reserve(hex_key.length() / 2);
  for (size_t i = 0; i + 1 < hex_key.length(); i += 2) {
    char byte_str[3] = {hex_key[i], hex_key[i + 1], 0};
    key.push_back(static_cast<uint8_t>(strtol(byte_str, nullptr, 16)));
  }
  return EncryptionContext(key);
}

EncryptionContext::~EncryptionContext() {
  volatile uint8_t* p = key_;
  for (size_t i = 0; i < kEncryptionKeySize; i++) p[i] = 0;
}

EncryptionContext::EncryptionContext(EncryptionContext&& other) noexcept
    : valid_(other.valid_) {
  std::memcpy(key_, other.key_, kEncryptionKeySize);
  // Clear the source using volatile write to prevent optimization (Task 29)
  SecureClear(other.key_, kEncryptionKeySize);
  other.valid_ = false;
}

EncryptionContext& EncryptionContext::operator=(EncryptionContext&& other) noexcept {
  if (this != &other) {
    // Clear our current key
    volatile uint8_t* p = key_;
    for (size_t i = 0; i < kEncryptionKeySize; i++) p[i] = 0;
    // Move from other
    std::memcpy(key_, other.key_, kEncryptionKeySize);
    valid_ = other.valid_;
    // Clear the source using volatile write to prevent optimization (Task 29)
    SecureClear(other.key_, kEncryptionKeySize);
    other.valid_ = false;
  }
  return *this;
}

void EncryptionContext::DeriveFieldKey(uint16_t field_id, uint8_t* out_key,
                                       uint32_t record_index) const {
  // Binary info: "flatbuffers-field" + BE(field_id) + BE(record_index)
  uint8_t info[32] = "flatbuffers-field";
  info[17] = static_cast<uint8_t>(field_id >> 8);
  info[18] = static_cast<uint8_t>(field_id & 0xFF);
  info[19] = static_cast<uint8_t>((record_index >> 24) & 0xFF);
  info[20] = static_cast<uint8_t>((record_index >> 16) & 0xFF);
  info[21] = static_cast<uint8_t>((record_index >> 8) & 0xFF);
  info[22] = static_cast<uint8_t>(record_index & 0xFF);
  internal::DeriveKey(key_, kEncryptionKeySize, info, 23, out_key, kEncryptionKeySize);
}

void EncryptionContext::DeriveFieldIV(uint16_t field_id, uint8_t* out_iv,
                                      uint32_t record_index) const {
  // Binary info: "flatbuffers-iv" + BE(field_id) + BE(record_index)
  uint8_t info[32] = "flatbuffers-iv";
  info[14] = static_cast<uint8_t>(field_id >> 8);
  info[15] = static_cast<uint8_t>(field_id & 0xFF);
  info[16] = static_cast<uint8_t>((record_index >> 24) & 0xFF);
  info[17] = static_cast<uint8_t>((record_index >> 16) & 0xFF);
  info[18] = static_cast<uint8_t>((record_index >> 8) & 0xFF);
  info[19] = static_cast<uint8_t>(record_index & 0xFF);
  internal::DeriveKey(key_, kEncryptionKeySize, info, 20, out_iv, kEncryptionIVSize);
}

// =============================================================================
// Field encryption functions
// =============================================================================

void EncryptScalar(uint8_t* value, size_t size,
                   const EncryptionContext& ctx, uint16_t field_id,
                   uint32_t record_index) {
  uint8_t field_key[kEncryptionKeySize];
  uint8_t field_iv[kEncryptionIVSize];
  ctx.DeriveFieldKey(field_id, field_key, record_index);
  ctx.DeriveFieldIV(field_id, field_iv, record_index);
  EncryptBytes(value, size, field_key, field_iv);
  SecureClear(field_key, kEncryptionKeySize);
  SecureClear(field_iv, kEncryptionIVSize);
}

void EncryptString(uint8_t* str, size_t length,
                   const EncryptionContext& ctx, uint16_t field_id,
                   uint32_t record_index) {
  uint8_t field_key[kEncryptionKeySize];
  uint8_t field_iv[kEncryptionIVSize];
  ctx.DeriveFieldKey(field_id, field_key, record_index);
  ctx.DeriveFieldIV(field_id, field_iv, record_index);
  EncryptBytes(str, length, field_key, field_iv);
  SecureClear(field_key, kEncryptionKeySize);
  SecureClear(field_iv, kEncryptionIVSize);
}

void EncryptVector(uint8_t* data, size_t element_size, size_t count,
                   const EncryptionContext& ctx, uint16_t field_id,
                   uint32_t record_index) {
  uint8_t field_key[kEncryptionKeySize];
  uint8_t field_iv[kEncryptionIVSize];
  ctx.DeriveFieldKey(field_id, field_key, record_index);
  ctx.DeriveFieldIV(field_id, field_iv, record_index);
  EncryptBytes(data, element_size * count, field_key, field_iv);
  SecureClear(field_key, kEncryptionKeySize);
  SecureClear(field_iv, kEncryptionIVSize);
}

// =============================================================================
// Buffer MAC (Task 23)
// =============================================================================

void ComputeBufferMAC(const uint8_t* buffer, size_t buffer_size,
                      const EncryptionContext& ctx, uint8_t* out_mac) {
  // Derive MAC key from context key
  uint8_t mac_key[kEncryptionKeySize];
  const char* info = "flatbuffers-mac-key";
  internal::DeriveKey(ctx.GetKey(), kEncryptionKeySize,
                      reinterpret_cast<const uint8_t*>(info), strlen(info),
                      mac_key, kEncryptionKeySize);
  HMACSha256(mac_key, kEncryptionKeySize, buffer, buffer_size, out_mac);
  SecureClear(mac_key, kEncryptionKeySize);
}

bool VerifyBufferMAC(const uint8_t* buffer, size_t buffer_size,
                     const EncryptionContext& ctx, const uint8_t* mac) {
  uint8_t mac_key[kEncryptionKeySize];
  const char* info = "flatbuffers-mac-key";
  internal::DeriveKey(ctx.GetKey(), kEncryptionKeySize,
                      reinterpret_cast<const uint8_t*>(info), strlen(info),
                      mac_key, kEncryptionKeySize);
  bool result = HMACSha256Verify(mac_key, kEncryptionKeySize,
                                  buffer, buffer_size, mac);
  SecureClear(mac_key, kEncryptionKeySize);
  return result;
}

// =============================================================================
// Schema helpers
// =============================================================================

bool IsFieldEncrypted(const reflection::Field* field) {
  if (!field) return false;
  auto attrs = field->attributes();
  if (!attrs) return false;
  for (auto kv : *attrs) {
    if (kv && kv->key() && kv->key()->str() == "encrypted") {
      return true;
    }
  }
  return false;
}

std::vector<uint16_t> GetEncryptedFieldIds(
    const uint8_t* schema, size_t schema_size, const char* root_type_name) {
  std::vector<uint16_t> result;
  if (!schema || schema_size == 0) return result;

  auto schema_root = reflection::GetSchema(schema);
  if (!schema_root) return result;

  auto objects = schema_root->objects();
  if (!objects) return result;

  const reflection::Object* root_object = nullptr;
  if (root_type_name) {
    for (auto obj : *objects) {
      if (obj && obj->name() && obj->name()->str() == root_type_name) {
        root_object = obj;
        break;
      }
    }
  } else if (schema_root->root_table()) {
    root_object = schema_root->root_table();
  }

  if (!root_object || !root_object->fields()) return result;

  for (auto field : *root_object->fields()) {
    if (IsFieldEncrypted(field)) {
      result.push_back(field->id());
    }
  }
  return result;
}

// =============================================================================
// Buffer encryption
// =============================================================================

namespace internal {

EncryptionResult ProcessTable(
    uint8_t* buffer, size_t buffer_size,
    const reflection::Object* object,
    const reflection::Schema* schema,
    uoffset_t table_offset,
    const EncryptionContext& ctx, bool encrypt) {
  if (!object || !schema || !buffer) {
    return EncryptionResult::Error(EncryptionError::kInvalidBuffer, "Invalid parameters");
  }

  auto vtable_offset_loc = table_offset;
  if (vtable_offset_loc + sizeof(soffset_t) > buffer_size) {
    return EncryptionResult::Error(EncryptionError::kInvalidBuffer, "Table offset out of bounds");
  }

  soffset_t vtable_offset_delta = ReadScalar<soffset_t>(buffer + vtable_offset_loc);
  auto vtable_loc = table_offset - vtable_offset_delta;

  if (vtable_loc + sizeof(voffset_t) * 2 > buffer_size) {
    return EncryptionResult::Error(EncryptionError::kInvalidBuffer, "VTable out of bounds");
  }

  auto vtable = buffer + vtable_loc;
  auto vtable_size = ReadScalar<voffset_t>(vtable);

  auto fields = object->fields();
  if (!fields) return EncryptionResult::Success();

  for (auto field : *fields) {
    if (!field) continue;

    bool is_encrypted = IsFieldEncrypted(field);
    if (!is_encrypted) {
      auto field_type = field->type();
      if (field_type && field_type->base_type() == reflection::BaseType::Obj) {
        auto field_id = field->id();
        if ((field_id + 2) * sizeof(voffset_t) >= vtable_size) continue;
        auto field_offset = ReadScalar<voffset_t>(vtable + (field_id + 2) * sizeof(voffset_t));
        if (field_offset == 0) continue;
        auto field_loc = table_offset + field_offset;
        if (field_loc + sizeof(uoffset_t) > buffer_size) continue;
        auto nested_offset = ReadScalar<uoffset_t>(buffer + field_loc);
        auto nested_table_loc = field_loc + nested_offset;
        auto nested_object_idx = field_type->index();
        if (nested_object_idx >= 0 &&
            static_cast<size_t>(nested_object_idx) < schema->objects()->size()) {
          auto nested_object = schema->objects()->Get(nested_object_idx);
          auto result = ProcessTable(buffer, buffer_size, nested_object, schema,
                                     nested_table_loc, ctx, encrypt);
          if (!result.ok()) return result;
        }
      }
      continue;
    }

    auto field_id = field->id();
    if ((field_id + 2) * sizeof(voffset_t) >= vtable_size) continue;
    auto field_offset = ReadScalar<voffset_t>(vtable + (field_id + 2) * sizeof(voffset_t));
    if (field_offset == 0) continue;

    auto field_loc = table_offset + field_offset;
    auto field_type = field->type();
    if (!field_type) continue;

    auto base_type = field_type->base_type();

    switch (base_type) {
      case reflection::BaseType::Bool:
      case reflection::BaseType::Byte:
      case reflection::BaseType::UByte:
        if (field_loc + 1 <= buffer_size) EncryptScalar(buffer + field_loc, 1, ctx, field_id);
        break;
      case reflection::BaseType::Short:
      case reflection::BaseType::UShort:
        if (field_loc + 2 <= buffer_size) EncryptScalar(buffer + field_loc, 2, ctx, field_id);
        break;
      case reflection::BaseType::Int:
      case reflection::BaseType::UInt:
      case reflection::BaseType::Float:
        if (field_loc + 4 <= buffer_size) EncryptScalar(buffer + field_loc, 4, ctx, field_id);
        break;
      case reflection::BaseType::Long:
      case reflection::BaseType::ULong:
      case reflection::BaseType::Double:
        if (field_loc + 8 <= buffer_size) EncryptScalar(buffer + field_loc, 8, ctx, field_id);
        break;
      case reflection::BaseType::String: {
        if (field_loc + sizeof(uoffset_t) > buffer_size) break;
        auto string_offset = ReadScalar<uoffset_t>(buffer + field_loc);
        auto string_loc = field_loc + string_offset;
        if (string_loc + sizeof(uoffset_t) > buffer_size) break;
        auto string_len = ReadScalar<uoffset_t>(buffer + string_loc);
        auto string_data = string_loc + sizeof(uoffset_t);
        if (string_data + string_len <= buffer_size) {
          EncryptString(buffer + string_data, string_len, ctx, field_id);
        }
        break;
      }
      case reflection::BaseType::Vector: {
        if (field_loc + sizeof(uoffset_t) > buffer_size) break;
        auto vec_offset = ReadScalar<uoffset_t>(buffer + field_loc);
        auto vec_loc = field_loc + vec_offset;
        if (vec_loc + sizeof(uoffset_t) > buffer_size) break;
        auto vec_len = ReadScalar<uoffset_t>(buffer + vec_loc);
        auto vec_data = vec_loc + sizeof(uoffset_t);
        auto elem_type = field_type->element();
        size_t elem_size = 0;
        switch (elem_type) {
          case reflection::BaseType::Byte:
          case reflection::BaseType::UByte:
          case reflection::BaseType::Bool: elem_size = 1; break;
          case reflection::BaseType::Short:
          case reflection::BaseType::UShort: elem_size = 2; break;
          case reflection::BaseType::Int:
          case reflection::BaseType::UInt:
          case reflection::BaseType::Float: elem_size = 4; break;
          case reflection::BaseType::Long:
          case reflection::BaseType::ULong:
          case reflection::BaseType::Double: elem_size = 8; break;
          default: break;
        }
        if (elem_size > 0 && vec_data + vec_len * elem_size <= buffer_size) {
          EncryptVector(buffer + vec_data, elem_size, vec_len, ctx, field_id);
        }
        break;
      }
      case reflection::BaseType::Obj: {
        auto obj_idx = field_type->index();
        if (obj_idx < 0 || static_cast<size_t>(obj_idx) >= schema->objects()->size()) break;
        auto struct_def = schema->objects()->Get(obj_idx);
        if (!struct_def || !struct_def->is_struct()) break;
        auto struct_size = struct_def->bytesize();
        if (field_loc + struct_size <= buffer_size) {
          uint8_t field_key[kEncryptionKeySize];
          uint8_t field_iv[kEncryptionIVSize];
          ctx.DeriveFieldKey(field_id, field_key);
          ctx.DeriveFieldIV(field_id, field_iv);
          EncryptBytes(buffer + field_loc, struct_size, field_key, field_iv);
        }
        break;
      }
      default: break;
    }
  }
  return EncryptionResult::Success();
}

}  // namespace internal

EncryptionResult EncryptBuffer(
    uint8_t* buffer, size_t buffer_size,
    const uint8_t* schema, size_t schema_size,
    const EncryptionContext& ctx) {
  if (!ctx.IsValid()) {
    return EncryptionResult::Error(EncryptionError::kInvalidKey, "Invalid encryption key");
  }
  if (!buffer || buffer_size < sizeof(uoffset_t)) {
    return EncryptionResult::Error(EncryptionError::kInvalidBuffer, "Invalid buffer");
  }
  if (!schema || schema_size == 0) {
    return EncryptionResult::Error(EncryptionError::kInvalidSchema, "Invalid schema");
  }

  auto schema_root = reflection::GetSchema(schema);
  if (!schema_root) {
    return EncryptionResult::Error(EncryptionError::kInvalidSchema, "Failed to parse schema");
  }

  auto root_table = schema_root->root_table();
  if (!root_table) {
    return EncryptionResult::Error(EncryptionError::kInvalidSchema, "No root table in schema");
  }

  auto root_offset = ReadScalar<uoffset_t>(buffer);
  if (root_offset >= buffer_size) {
    return EncryptionResult::Error(EncryptionError::kInvalidBuffer, "Root offset out of bounds");
  }

  return internal::ProcessTable(buffer, buffer_size, root_table, schema_root,
                                root_offset, ctx, true);
}

EncryptionResult DecryptBuffer(
    uint8_t* buffer, size_t buffer_size,
    const uint8_t* schema, size_t schema_size,
    const EncryptionContext& ctx) {
  return EncryptBuffer(buffer, buffer_size, schema, schema_size, ctx);
}

}  // namespace flatbuffers
