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
#include <cstring>

#ifdef FLATBUFFERS_USE_CRYPTOPP
// Crypto++ headers
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/sha.h>
#include <cryptopp/xed25519.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <cryptopp/nbtheory.h>
#endif

namespace flatbuffers {

#ifdef FLATBUFFERS_USE_CRYPTOPP

// =============================================================================
// Crypto++ Implementation
// =============================================================================

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
void SHA256(const uint8_t* data, size_t size, uint8_t* hash) {
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
void DeriveSymmetricKey(
    const uint8_t* shared_secret, size_t shared_secret_size,
    const uint8_t* context, size_t context_size,
    uint8_t* key) {
  HKDF(shared_secret, shared_secret_size,
       nullptr, 0,
       context, context_size,
       key, kEncryptionKeySize);
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

  CryptoPP::AutoSeededRandomPool rng;
  CryptoPP::x25519 x25519;

  x25519.GenerateKeyPair(rng, kp.private_key.data(), kp.public_key.data());
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
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;
    privateKey.Initialize(rng, CryptoPP::ASN1::secp256k1());

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
    std::vector<uint8_t> uncompressed;
    const uint8_t* pub_ptr = public_key;
    size_t pub_len = public_key_size;

    if (public_key_size == 33 && (public_key[0] == 0x02 || public_key[0] == 0x03)) {
      // Compressed format - decompress
      CryptoPP::ECP::Point point;
      CryptoPP::Integer x(public_key + 1, 32);
      const CryptoPP::ECP& curve = ecdh.GetGroupParameters().GetCurve();

      // y^2 = x^3 + 7 (secp256k1)
      CryptoPP::Integer y2 = (x * x * x + 7) % curve.GetField().GetModulus();
      CryptoPP::Integer y = CryptoPP::ModularSquareRoot(y2, curve.GetField().GetModulus());

      if ((public_key[0] == 0x03) != y.IsOdd()) {
        y = curve.GetField().GetModulus() - y;
      }

      uncompressed.resize(65);
      uncompressed[0] = 0x04;
      x.Encode(uncompressed.data() + 1, 32);
      y.Encode(uncompressed.data() + 33, 32);
      pub_ptr = uncompressed.data();
      pub_len = 65;
    }

    // Perform ECDH
    std::vector<uint8_t> priv_full(ecdh.PrivateKeyLength());
    std::vector<uint8_t> pub_full(ecdh.PublicKeyLength());

    // Copy private key
    memset(priv_full.data(), 0, priv_full.size());
    memcpy(priv_full.data() + priv_full.size() - 32, private_key, 32);

    // Copy public key
    if (pub_len == 65) {
      memcpy(pub_full.data(), pub_ptr, pub_len);
    } else {
      return false;
    }

    return ecdh.Agree(shared_secret, priv_full.data(), pub_full.data());
  } catch (...) {
    return false;
  }
}

Signature Secp256k1Sign(
    const uint8_t* private_key,
    const uint8_t* data, size_t data_size) {
  Signature sig;
  sig.algorithm = SignatureAlgorithm::Secp256k1_ECDSA;

  try {
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey key;
    key.Initialize(CryptoPP::ASN1::secp256k1(),
                   CryptoPP::Integer(private_key, kSecp256k1PrivateKeySize));

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer signer(key);
    sig.data.resize(signer.MaxSignatureLength());
    size_t sigLen = signer.SignMessage(rng, data, data_size, sig.data.data());
    sig.data.resize(sigLen);
  } catch (...) {
    sig.data.clear();
  }

  return sig;
}

bool Secp256k1Verify(
    const uint8_t* public_key, size_t public_key_size,
    const uint8_t* data, size_t data_size,
    const uint8_t* signature, size_t signature_size) {
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

    key.Initialize(CryptoPP::ASN1::secp256k1(), CryptoPP::ECP::Point(x, y));

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier verifier(key);
    return verifier.VerifyMessage(data, data_size, signature, signature_size);
  } catch (...) {
    return false;
  }
}

// =============================================================================
// P-256 Key Exchange and Signatures
// =============================================================================

KeyPair P256GenerateKeyPair() {
  KeyPair kp;

  try {
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;
    privateKey.Initialize(rng, CryptoPP::ASN1::secp256r1());

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

    // Similar decompression as secp256k1, but with P-256 curve equation
    // y^2 = x^3 - 3x + b
    std::vector<uint8_t> uncompressed;
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

      if ((public_key[0] == 0x03) != y.IsOdd()) {
        y = p - y;
      }

      uncompressed.resize(65);
      uncompressed[0] = 0x04;
      x.Encode(uncompressed.data() + 1, 32);
      y.Encode(uncompressed.data() + 33, 32);
      pub_ptr = uncompressed.data();
      pub_len = 65;
    }

    std::vector<uint8_t> priv_full(ecdh.PrivateKeyLength());
    std::vector<uint8_t> pub_full(ecdh.PublicKeyLength());

    memset(priv_full.data(), 0, priv_full.size());
    memcpy(priv_full.data() + priv_full.size() - 32, private_key, 32);

    if (pub_len == 65) {
      memcpy(pub_full.data(), pub_ptr, pub_len);
    } else {
      return false;
    }

    return ecdh.Agree(shared_secret, priv_full.data(), pub_full.data());
  } catch (...) {
    return false;
  }
}

Signature P256Sign(
    const uint8_t* private_key,
    const uint8_t* data, size_t data_size) {
  Signature sig;
  sig.algorithm = SignatureAlgorithm::P256_ECDSA;

  try {
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey key;
    key.Initialize(CryptoPP::ASN1::secp256r1(),
                   CryptoPP::Integer(private_key, kP256PrivateKeySize));

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer signer(key);
    sig.data.resize(signer.MaxSignatureLength());
    size_t sigLen = signer.SignMessage(rng, data, data_size, sig.data.data());
    sig.data.resize(sigLen);
  } catch (...) {
    sig.data.clear();
  }

  return sig;
}

bool P256Verify(
    const uint8_t* public_key, size_t public_key_size,
    const uint8_t* data, size_t data_size,
    const uint8_t* signature, size_t signature_size) {
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

    key.Initialize(CryptoPP::ASN1::secp256r1(), CryptoPP::ECP::Point(x, y));

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier verifier(key);
    return verifier.VerifyMessage(data, data_size, signature, signature_size);
  } catch (...) {
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

      CryptoPP::AutoSeededRandomPool rng;
      CryptoPP::ed25519::Signer signer;
      signer.AccessPrivateKey().GenerateRandom(rng);

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
    return false;
  }
}

#else  // !FLATBUFFERS_USE_CRYPTOPP

// =============================================================================
// Fallback Implementation (custom crypto - NOT RECOMMENDED FOR PRODUCTION)
// =============================================================================

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

void SHA256(const uint8_t*, size_t, uint8_t*) {
  // Not implemented without Crypto++
}

void HKDF(const uint8_t* ikm, size_t ikm_size,
          const uint8_t*, size_t,
          const uint8_t* info, size_t info_size,
          uint8_t* okm, size_t okm_size) {
  internal::DeriveKey(ikm, ikm_size, info, info_size, okm, okm_size);
}

void DeriveSymmetricKey(
    const uint8_t* shared_secret, size_t shared_secret_size,
    const uint8_t* context, size_t context_size,
    uint8_t* key) {
  internal::DeriveKey(shared_secret, shared_secret_size,
                      context, context_size,
                      key, kEncryptionKeySize);
}

void EncryptBytes(uint8_t* data, size_t size,
                  const uint8_t* key, const uint8_t* iv) {
  if (!data || size == 0 || !key || !iv) return;
  std::vector<uint8_t> keystream(size);
  internal::AESCTRKeystream(key, iv, keystream.data(), size);
  for (size_t i = 0; i < size; i++) data[i] ^= keystream[i];
}

// Stub implementations for ECDH/signatures without Crypto++
KeyPair X25519GenerateKeyPair() { return KeyPair{}; }
bool X25519SharedSecret(const uint8_t*, const uint8_t*, uint8_t*) { return false; }
KeyPair Secp256k1GenerateKeyPair() { return KeyPair{}; }
bool Secp256k1SharedSecret(const uint8_t*, const uint8_t*, size_t, uint8_t*) { return false; }
Signature Secp256k1Sign(const uint8_t*, const uint8_t*, size_t) { return Signature{}; }
bool Secp256k1Verify(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t) { return false; }
KeyPair P256GenerateKeyPair() { return KeyPair{}; }
bool P256SharedSecret(const uint8_t*, const uint8_t*, size_t, uint8_t*) { return false; }
Signature P256Sign(const uint8_t*, const uint8_t*, size_t) { return Signature{}; }
bool P256Verify(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t) { return false; }
KeyPair GenerateSigningKeyPair(SignatureAlgorithm) { return KeyPair{}; }
Signature Ed25519Sign(const uint8_t*, const uint8_t*, size_t) { return Signature{}; }
bool Ed25519Verify(const uint8_t*, const uint8_t*, size_t, const uint8_t*) { return false; }

#endif  // FLATBUFFERS_USE_CRYPTOPP

// =============================================================================
// Common implementations (used by both Crypto++ and fallback)
// =============================================================================

KeyPair GenerateKeyPair(KeyExchangeAlgorithm algorithm) {
  switch (algorithm) {
    case KeyExchangeAlgorithm::X25519:
      return X25519GenerateKeyPair();
    case KeyExchangeAlgorithm::Secp256k1:
      return Secp256k1GenerateKeyPair();
    case KeyExchangeAlgorithm::P256:
      return P256GenerateKeyPair();
    default:
      return KeyPair{};
  }
}

bool ComputeSharedSecret(
    KeyExchangeAlgorithm algorithm,
    const uint8_t* private_key, size_t private_key_size,
    const uint8_t* public_key, size_t public_key_size,
    uint8_t* shared_secret) {
  switch (algorithm) {
    case KeyExchangeAlgorithm::X25519:
      return X25519SharedSecret(private_key, public_key, shared_secret);
    case KeyExchangeAlgorithm::Secp256k1:
      return Secp256k1SharedSecret(private_key, public_key, public_key_size, shared_secret);
    case KeyExchangeAlgorithm::P256:
      return P256SharedSecret(private_key, public_key, public_key_size, shared_secret);
    default:
      return false;
  }
}

Signature Sign(
    SignatureAlgorithm algorithm,
    const uint8_t* private_key, size_t private_key_size,
    const uint8_t* data, size_t data_size) {
  switch (algorithm) {
    case SignatureAlgorithm::Ed25519:
      return Ed25519Sign(private_key, data, data_size);
    case SignatureAlgorithm::Secp256k1_ECDSA:
      return Secp256k1Sign(private_key, data, data_size);
    case SignatureAlgorithm::P256_ECDSA:
      return P256Sign(private_key, data, data_size);
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
    default:
      return false;
  }
}

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

void EncryptionContext::DeriveFieldKey(uint16_t field_id, uint8_t* out_key) const {
  uint8_t info[32] = "flatbuffers-field";
  info[17] = static_cast<uint8_t>(field_id >> 8);
  info[18] = static_cast<uint8_t>(field_id & 0xFF);
  internal::DeriveKey(key_, kEncryptionKeySize, info, 19, out_key, kEncryptionKeySize);
}

void EncryptionContext::DeriveFieldIV(uint16_t field_id, uint8_t* out_iv) const {
  uint8_t info[32] = "flatbuffers-iv";
  info[14] = static_cast<uint8_t>(field_id >> 8);
  info[15] = static_cast<uint8_t>(field_id & 0xFF);
  internal::DeriveKey(key_, kEncryptionKeySize, info, 16, out_iv, kEncryptionIVSize);
}

// =============================================================================
// Field encryption functions
// =============================================================================

void EncryptScalar(uint8_t* value, size_t size,
                   const EncryptionContext& ctx, uint16_t field_id) {
  uint8_t field_key[kEncryptionKeySize];
  uint8_t field_iv[kEncryptionIVSize];
  ctx.DeriveFieldKey(field_id, field_key);
  ctx.DeriveFieldIV(field_id, field_iv);
  EncryptBytes(value, size, field_key, field_iv);
}

void EncryptString(uint8_t* str, size_t length,
                   const EncryptionContext& ctx, uint16_t field_id) {
  uint8_t field_key[kEncryptionKeySize];
  uint8_t field_iv[kEncryptionIVSize];
  ctx.DeriveFieldKey(field_id, field_key);
  ctx.DeriveFieldIV(field_id, field_iv);
  EncryptBytes(str, length, field_key, field_iv);
}

void EncryptVector(uint8_t* data, size_t element_size, size_t count,
                   const EncryptionContext& ctx, uint16_t field_id) {
  uint8_t field_key[kEncryptionKeySize];
  uint8_t field_iv[kEncryptionIVSize];
  ctx.DeriveFieldKey(field_id, field_key);
  ctx.DeriveFieldIV(field_id, field_iv);
  EncryptBytes(data, element_size * count, field_key, field_iv);
}

// =============================================================================
// Schema helpers
// =============================================================================

bool IsFieldEncrypted(const reflection::Field* field) {
  if (!field) return false;
  auto attrs = field->attributes();
  if (!attrs) return false;
  for (size_t i = 0; i < attrs->size(); i++) {
    auto kv = attrs->Get(i);
    if (kv && kv->key() && kv->key()->string_view() == "encrypted") {
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
      if (obj && obj->name() && obj->name()->string_view() == root_type_name) {
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
