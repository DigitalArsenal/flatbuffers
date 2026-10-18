// Open one wallet-sealed field with native flatc C++ (src/encryption.cpp).
//
//   field_encryption_native <x25519-private-hex> <enc-hex> <ciphertext-hex> <field-id>
//
// Prints the plaintext hex, or "refused: <reason>" and exits 2.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "flatbuffers/encryption.h"
#include "flatbuffers/flatbuffers.h"

namespace {

std::vector<uint8_t> FromHex(const char* hex) {
  std::vector<uint8_t> out(std::strlen(hex) / 2);
  for (size_t i = 0; i < out.size(); ++i) {
    unsigned v = 0;
    std::sscanf(hex + 2 * i, "%2x", &v);
    out[i] = static_cast<uint8_t>(v);
  }
  return out;
}

int Refuse(const char* why) {
  std::printf("refused: %s\n", why);
  return 2;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 5) return Refuse("usage");
  const auto priv = FromHex(argv[1]);
  const auto enc = FromHex(argv[2]);
  auto data = FromHex(argv[3]);
  const auto field_id = static_cast<uint16_t>(std::atoi(argv[4]));
  if (priv.size() != 32) return Refuse("private key size");

  flatbuffers::Verifier verifier(enc.data(), enc.size());
  if (!flatbuffers::BufferHasIdentifier(enc.data(), "$ENC")) return Refuse("not an $ENC record");
  const auto* table = flatbuffers::GetRoot<flatbuffers::Table>(enc.data());
  if (!table->VerifyTableStart(verifier)) return Refuse("malformed $ENC");
  // ENC field slots: 4 EPHEMERAL_PUBLIC_KEY, 6 RECIPIENT_KEY_ID, 7 CONTEXT.
  const auto* eph = table->GetPointer<const flatbuffers::Vector<uint8_t>*>(4 + 2 * 4);
  const auto* rid = table->GetPointer<const flatbuffers::Vector<uint8_t>*>(4 + 2 * 6);
  const auto* ctx = table->GetPointer<const flatbuffers::String*>(4 + 2 * 7);
  if (!eph || eph->size() != 32 || !rid || !ctx) return Refuse("incomplete $ENC");
  if (table->GetField<int8_t>(4 + 2 * 1, 0) != 0) return Refuse("not X25519");

  uint8_t pub[32];
  static const uint8_t kBase[32] = {9};
  if (!flatbuffers::X25519SharedSecret(priv.data(), kBase, pub)) return Refuse("public key");
  uint8_t digest[32];
  flatbuffers::Sha256Hash(pub, sizeof pub, digest);
  if (rid->size() != 8 || std::memcmp(rid->data(), digest, 8) != 0) return Refuse("sealed for another wallet");

  uint8_t shared[32];
  if (!flatbuffers::X25519SharedSecret(priv.data(), eph->data(), shared)) return Refuse("ecdh");
  uint8_t key[32];
  flatbuffers::HKDF(shared, sizeof shared, nullptr, 0,
                    reinterpret_cast<const uint8_t*>(ctx->data()), ctx->size(), key, sizeof key);
  flatbuffers::EncryptionContext context(key, sizeof key);
  flatbuffers::DecryptScalar(data.data(), data.size(), context, field_id, 0);
  for (uint8_t b : data) std::printf("%02x", b);
  std::printf("\n");
  return 0;
}
