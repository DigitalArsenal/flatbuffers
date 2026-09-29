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
#include "flatbuffers/flatbuffers.h"
#include "flatbuffers/idl.h"
#include "flatbuffers/reflection.h"
#include "flatbuffers/util.h"

#include <cstdio>
#include <cstring>
#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

// Test utilities
static int num_tests = 0;
static int num_passed = 0;

#define TEST_EQ(expr, expected) \
  do { \
    num_tests++; \
    if ((expr) == (expected)) { \
      num_passed++; \
    } else { \
      std::cerr << "FAILED: " << #expr << " != " << #expected << std::endl; \
    } \
  } while (0)

#define TEST_NOTNULL(expr) \
  do { \
    num_tests++; \
    if ((expr) != nullptr) { \
      num_passed++; \
    } else { \
      std::cerr << "FAILED: " << #expr << " is null" << std::endl; \
    } \
  } while (0)

#define TEST_TRUE(expr) \
  do { \
    num_tests++; \
    if (expr) { \
      num_passed++; \
    } else { \
      std::cerr << "FAILED: " << #expr << " is false" << std::endl; \
    } \
  } while (0)

// Test the EncryptionContext
static void TestEncryptionContext() {
  std::cout << "Testing EncryptionContext..." << std::endl;

  // Test valid key
  uint8_t key[32];
  for (int i = 0; i < 32; i++) key[i] = static_cast<uint8_t>(i);

  flatbuffers::EncryptionContext ctx(key, 32);
  TEST_TRUE(ctx.IsValid());

  // Test invalid key size
  flatbuffers::EncryptionContext ctx_bad(key, 16);
  TEST_TRUE(!ctx_bad.IsValid());

  // Test key derivation produces different keys for different fields
  uint8_t field_key1[32], field_key2[32];
  ctx.DeriveFieldKey(1, field_key1);
  ctx.DeriveFieldKey(2, field_key2);

  bool keys_different = false;
  for (int i = 0; i < 32; i++) {
    if (field_key1[i] != field_key2[i]) {
      keys_different = true;
      break;
    }
  }
  TEST_TRUE(keys_different);

  // Test hex key parsing
  auto ctx_hex = flatbuffers::EncryptionContext::FromHex(
      "000102030405060708090a0b0c0d0e0f"
      "101112131415161718191a1b1c1d1e1f");
  TEST_TRUE(ctx_hex.IsValid());
}

// Test basic byte encryption
static void TestEncryptBytes() {
  std::cout << "Testing EncryptBytes..." << std::endl;

  uint8_t key[32] = {0};
  uint8_t iv[16] = {0};

  // Encrypt some data
  uint8_t data[] = "Hello, World!";
  size_t len = sizeof(data) - 1;  // Exclude null terminator

  uint8_t original[32];
  memcpy(original, data, len);

  flatbuffers::EncryptBytes(data, len, key, iv);

  // Data should be different after encryption
  bool is_different = memcmp(data, original, len) != 0;
  TEST_TRUE(is_different);

  // Decrypt (same operation for CTR mode)
  flatbuffers::DecryptBytes(data, len, key, iv);

  // Should match original
  bool matches = memcmp(data, original, len) == 0;
  TEST_TRUE(matches);
}

// Test scalar encryption
static void TestScalarEncryption() {
  std::cout << "Testing scalar encryption..." << std::endl;

  uint8_t key[32];
  for (int i = 0; i < 32; i++) key[i] = static_cast<uint8_t>(i * 7);

  flatbuffers::EncryptionContext ctx(key, 32);

  // Test int32
  int32_t value32 = 12345678;
  int32_t original32 = value32;

  flatbuffers::EncryptScalar(reinterpret_cast<uint8_t*>(&value32), 4, ctx, 1);
  TEST_TRUE(value32 != original32);

  flatbuffers::EncryptScalar(reinterpret_cast<uint8_t*>(&value32), 4, ctx, 1);
  TEST_EQ(value32, original32);

  // Test double
  double value64 = 3.14159265358979;
  double original64 = value64;

  flatbuffers::EncryptScalar(reinterpret_cast<uint8_t*>(&value64), 8, ctx, 2);
  TEST_TRUE(value64 != original64);

  flatbuffers::EncryptScalar(reinterpret_cast<uint8_t*>(&value64), 8, ctx, 2);
  // For floating point, use memcmp
  TEST_TRUE(memcmp(&value64, &original64, 8) == 0);
}

// Test schema parsing with encrypted attribute
static void TestSchemaWithEncryptedAttribute() {
  std::cout << "Testing schema with encrypted attribute..." << std::endl;

  const char* schema_str = R"(
    table TestTable {
      public_field: int;
      secret_field: string (encrypted);
      another_secret: double (encrypted);
    }
    root_type TestTable;
  )";

  flatbuffers::Parser parser;
  TEST_TRUE(parser.Parse(schema_str));

  // Check that the encrypted attribute is recognized
  auto* table = parser.structs_.Lookup("TestTable");
  TEST_NOTNULL(table);

  auto* public_field = table->fields.Lookup("public_field");
  TEST_NOTNULL(public_field);
  TEST_TRUE(public_field->attributes.Lookup("encrypted") == nullptr);

  auto* secret_field = table->fields.Lookup("secret_field");
  TEST_NOTNULL(secret_field);
  TEST_NOTNULL(secret_field->attributes.Lookup("encrypted"));

  auto* another_secret = table->fields.Lookup("another_secret");
  TEST_NOTNULL(another_secret);
  TEST_NOTNULL(another_secret->attributes.Lookup("encrypted"));
}

// Test full buffer encryption/decryption
static void TestBufferEncryption() {
  std::cout << "Testing buffer encryption..." << std::endl;

  // First, compile a schema to binary
  const char* schema_str = R"(
    table SimpleMessage {
      public_id: uint64;
      secret_value: int (encrypted);
      secret_text: string (encrypted);
    }
    root_type SimpleMessage;
  )";

  flatbuffers::Parser parser;
  // Enable serialization of builtin attributes (like "encrypted")
  parser.opts.binary_schema_builtins = true;
  TEST_TRUE(parser.Parse(schema_str));

  // Generate binary schema
  parser.Serialize();
  auto bfbs_ptr = parser.builder_.GetBufferPointer();
  auto bfbs_size = parser.builder_.GetSize();
  TEST_TRUE(bfbs_size > 0);

  // Build a FlatBuffer
  flatbuffers::FlatBufferBuilder builder;
  auto secret_text = builder.CreateString("This is secret!");

  // Manually build the buffer (since we don't have generated code)
  auto start = builder.StartTable();
  builder.AddElement<uint64_t>(4, 12345, 0);  // public_id at field 0
  builder.AddElement<int32_t>(6, 9999, 0);    // secret_value at field 1
  builder.AddOffset(8, secret_text);           // secret_text at field 2
  auto root = builder.EndTable(start);
  builder.Finish(flatbuffers::Offset<void>(root));

  // Get the buffer
  auto buf = builder.GetBufferPointer();
  auto size = builder.GetSize();

  // Make a copy for comparison
  std::vector<uint8_t> original(buf, buf + size);

  // Create encryption key
  uint8_t key[32];
  for (int i = 0; i < 32; i++) key[i] = static_cast<uint8_t>(i + 42);

  flatbuffers::EncryptionContext ctx(key, 32);

  // Encrypt the buffer
  auto result = flatbuffers::EncryptBuffer(
      buf, size,
      bfbs_ptr, bfbs_size,
      ctx);

  TEST_TRUE(result.ok());

  // Buffer should be different after encryption
  bool buffer_changed = memcmp(buf, original.data(), size) != 0;
  TEST_TRUE(buffer_changed);

  // Decrypt the buffer
  result = flatbuffers::DecryptBuffer(
      buf, size,
      bfbs_ptr, bfbs_size,
      ctx);

  TEST_TRUE(result.ok());

  // Buffer should match original after decryption
  bool buffer_restored = memcmp(buf, original.data(), size) == 0;
  TEST_TRUE(buffer_restored);
}

// Test IsFieldEncrypted helper
static void TestIsFieldEncrypted() {
  std::cout << "Testing IsFieldEncrypted..." << std::endl;

  const char* schema_str = R"(
    table TestTable {
      normal: int;
      secret: string (encrypted);
    }
    root_type TestTable;
  )";

  flatbuffers::Parser parser;
  // Enable serialization of builtin attributes (like "encrypted")
  parser.opts.binary_schema_builtins = true;
  TEST_TRUE(parser.Parse(schema_str));

  parser.Serialize();
  auto bfbs_ptr = parser.builder_.GetBufferPointer();

  auto schema = reflection::GetSchema(bfbs_ptr);
  TEST_NOTNULL(schema);

  auto root_table = schema->root_table();
  TEST_NOTNULL(root_table);

  auto fields = root_table->fields();
  TEST_NOTNULL(fields);

  for (auto field : *fields) {
    if (field->name()->str() == "normal") {
      TEST_TRUE(!flatbuffers::IsFieldEncrypted(field));
    } else if (field->name()->str() == "secret") {
      TEST_TRUE(flatbuffers::IsFieldEncrypted(field));
    }
  }
}

// Test GetEncryptedFieldIds
static void TestGetEncryptedFieldIds() {
  std::cout << "Testing GetEncryptedFieldIds..." << std::endl;

  const char* schema_str = R"(
    table TestTable {
      field0: int;
      field1: string (encrypted);
      field2: double;
      field3: [ubyte] (encrypted);
    }
    root_type TestTable;
  )";

  flatbuffers::Parser parser;
  // Enable serialization of builtin attributes (like "encrypted")
  parser.opts.binary_schema_builtins = true;
  TEST_TRUE(parser.Parse(schema_str));

  parser.Serialize();
  auto bfbs_ptr = parser.builder_.GetBufferPointer();
  auto bfbs_size = parser.builder_.GetSize();

  auto ids = flatbuffers::GetEncryptedFieldIds(bfbs_ptr, bfbs_size);

  // Should have 2 encrypted fields
  TEST_EQ(ids.size(), static_cast<size_t>(2));
}

// =============================================================================
// Format 3: a key stream per encrypted instance
// =============================================================================

namespace {

#if defined(FLATBUFFERS_USE_OPENSSL) || defined(FLATBUFFERS_USE_CRYPTOPP)
std::string Hex(const uint8_t* data, size_t size) {
  static const char kDigits[] = "0123456789abcdef";
  std::string out;
  for (size_t i = 0; i < size; i++) {
    out += kDigits[data[i] >> 4];
    out += kDigits[data[i] & 0xF];
  }
  return out;
}
#endif

// Parses `schema` (keeping builtin attributes such as `encrypted`) into a
// .bfbs, and `json` (when given) into a FlatBuffer.
bool Compile(const char* schema, const char* json, std::vector<uint8_t>* bfbs,
             std::vector<uint8_t>* buf) {
  flatbuffers::Parser parser;
  parser.opts.binary_schema_builtins = true;
  if (!parser.Parse(schema)) {
    std::cerr << "schema: " << parser.error_ << std::endl;
    return false;
  }
  parser.Serialize();
  bfbs->assign(parser.builder_.GetBufferPointer(),
               parser.builder_.GetBufferPointer() + parser.builder_.GetSize());
  if (!json) return true;
  if (!parser.ParseJson(json)) {
    std::cerr << "json: " << parser.error_ << std::endl;
    return false;
  }
  buf->assign(parser.builder_.GetBufferPointer(),
              parser.builder_.GetBufferPointer() + parser.builder_.GetSize());
  return true;
}

// Root and Node give `secret` (id 0) and `pin` (id 1) the same field ids, and
// Node appears as a nested table, in a vector of tables, as a union member and
// in a vector of unions.
const char* kNodeSchema = R"(
  namespace KS;
  table Node {
    secret: string (encrypted);
    pin: int (encrypted);
    child: Node;
  }
  union Member { Node }
  table Root {
    secret: string (encrypted);
    pin: int (encrypted);
    child: Node;
    items: [Node];
    member: Member;
    members: [Member];
  }
  root_type Root;
)";

// Every secret is 16 bytes. The root's is the attacker's known plaintext.
const char* kNodeJson = R"({
  secret: "known plaintext!", pin: 1111,
  child: { secret: "hidden nested B", pin: 2222,
           child: { secret: "hidden nested CC", pin: 3333 } },
  items: [ { secret: "hidden vector DD", pin: 4444 },
           { secret: "hidden vector EE", pin: 5555 } ],
  member_type: "Node", member: { secret: "hidden union FFF", pin: 6666 },
  members_type: [ "Node", "Node" ],
  members: [ { secret: "hidden unions GG", pin: 7777 },
             { secret: "hidden unions HH", pin: 8888 } ]
})";

// vtable offsets of the Root and Node fields.
const flatbuffers::voffset_t kSecret = 4, kPin = 6, kChild = 8, kItems = 10,
                             kMember = 14, kMembers = 18;

struct Instance {
  size_t pos;
  size_t len;
  std::string what;
};

// Collects the positions of a table's secret and pin, then its descendants.
void CollectNode(const uint8_t* buf, const flatbuffers::Table* table,
                 const std::string& what, std::vector<Instance>* secrets,
                 std::vector<Instance>* pins) {
  if (!table) return;
  auto secret = table->GetPointer<const flatbuffers::String*>(kSecret);
  if (secret) {
    Instance i = {static_cast<size_t>(secret->Data() - buf),
                  secret->size(), what + ".secret"};
    secrets->push_back(i);
  }
  auto pin = table->GetAddressOf(kPin);
  if (pin) {
    Instance i = {static_cast<size_t>(pin - buf), 4, what + ".pin"};
    pins->push_back(i);
  }
  CollectNode(buf, table->GetPointer<const flatbuffers::Table*>(kChild),
              what + ".child", secrets, pins);
}

void CollectRoot(const uint8_t* buf, std::vector<Instance>* secrets,
                 std::vector<Instance>* pins) {
  auto root = flatbuffers::GetRoot<flatbuffers::Table>(buf);
  CollectNode(buf, root, "root", secrets, pins);
  auto items = root->GetPointer<
      const flatbuffers::Vector<flatbuffers::Offset<flatbuffers::Table>>*>(kItems);
  for (flatbuffers::uoffset_t i = 0; items && i < items->size(); i++) {
    CollectNode(buf, items->Get(i), "items[" + std::to_string(i) + "]",
                secrets, pins);
  }
  CollectNode(buf, root->GetPointer<const flatbuffers::Table*>(kMember),
              "member", secrets, pins);
  auto members = root->GetPointer<
      const flatbuffers::Vector<flatbuffers::Offset<flatbuffers::Table>>*>(kMembers);
  for (flatbuffers::uoffset_t i = 0; members && i < members->size(); i++) {
    CollectNode(buf, members->Get(i), "members[" + std::to_string(i) + "]",
                secrets, pins);
  }
}

bool Same(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b,
          const Instance& i) {
  return memcmp(a.data() + i.pos, b.data() + i.pos, i.len) == 0;
}

// What an attacker who knows `known`'s plaintext recovers of `other` from the
// ciphertexts when the two share a key stream: c_known ^ c_other ^ p_known.
std::vector<uint8_t> Recover(const std::vector<uint8_t>& plain,
                             const std::vector<uint8_t>& cipher,
                             const Instance& known, const Instance& other) {
  std::vector<uint8_t> out(other.len);
  for (size_t k = 0; k < other.len; k++) {
    out[k] = static_cast<uint8_t>(cipher[known.pos + k] ^
                                  cipher[other.pos + k] ^ plain[known.pos + k]);
  }
  return out;
}

bool Recovers(const std::vector<uint8_t>& plain,
              const std::vector<uint8_t>& cipher, const Instance& known,
              const Instance& other) {
  auto recovered = Recover(plain, cipher, known, other);
  return memcmp(recovered.data(), plain.data() + other.pos, other.len) == 0;
}

bool OutsideUnchanged(const std::vector<uint8_t>& plain,
                      const std::vector<uint8_t>& cipher,
                      const std::vector<Instance>& a,
                      const std::vector<Instance>& b) {
  std::vector<bool> inside(plain.size(), false);
  for (const auto& i : a) {
    for (size_t k = i.pos; k < i.pos + i.len; k++) inside[k] = true;
  }
  for (const auto& i : b) {
    for (size_t k = i.pos; k < i.pos + i.len; k++) inside[k] = true;
  }
  for (size_t k = 0; k < plain.size(); k++) {
    if (!inside[k] && plain[k] != cipher[k]) return false;
  }
  return true;
}

void MakeKey(uint8_t* key, uint8_t seed) {
  for (int i = 0; i < 32; i++) key[i] = static_cast<uint8_t>(seed + i * 3);
}

}  // namespace

// The explicit per-field primitives stay byte-identical (other runtimes
// re-implement them), and format 3's buffer key, IV and key stream match
// independent HKDF-SHA256 / AES-256-CTR (node:crypto; the same vectors are in
// wasm/test/test_field_encryption_v3.mjs).
static void TestDerivationVectors() {
  std::cout << "Testing derivation vectors..." << std::endl;
#if defined(FLATBUFFERS_USE_OPENSSL) || defined(FLATBUFFERS_USE_CRYPTOPP)
  uint8_t key[32];
  for (int i = 0; i < 32; i++) key[i] = static_cast<uint8_t>(i);
  flatbuffers::EncryptionContext ctx(key, 32);

  uint8_t out[32];
  ctx.DeriveFieldKey(4, out, 0);
  TEST_EQ(Hex(out, 32), std::string("675aaf1b9a01567081b6d38908672704"
                                    "d226b23cb1631af6c22dd58c3bb70e30"));
  ctx.DeriveFieldIV(4, out, 0);
  TEST_EQ(Hex(out, 16), std::string("2f21d1ea116d9b6b4930e9230b1a11b3"));

  ctx.DeriveBufferKey(0, out);
  TEST_EQ(Hex(out, 32), std::string("c4c46faf2e2a1f24f04b70f54031ca2c"
                                    "e4bdcc70a57898619ae60981c968c32e"));
  uint8_t buffer_key[32];
  ctx.DeriveBufferKey(7, buffer_key);
  TEST_EQ(Hex(buffer_key, 32), std::string("96dc099cb3f069b6bb6f67567a4bbe5f"
                                           "5c0e83d8257c714278e3da3f8086ba13"));

  uint8_t iv[16];
  flatbuffers::FieldInstanceIV(0x1234, iv);
  TEST_EQ(Hex(iv, 16), std::string("00001234000000000000000000000000"));

  uint8_t stream[20] = {0};
  flatbuffers::EncryptBytes(stream, sizeof(stream), buffer_key, iv);
  TEST_EQ(Hex(stream, 20),
          std::string("6e83aa7422ddbadb1413e5cc5b5f8336866aeb83"));
#else
  std::cout << "  (skipped: the fallback backend has no HKDF-SHA256)"
            << std::endl;
#endif
}

// Equal-id encrypted fields in nested tables, vectors of tables, unions and
// vectors of unions: every instance is ciphertext and no two share a key
// stream. On format 2 (the old default) the nested secrets fall to a
// known-plaintext XOR, and the vector and union members stay plaintext.
static void TestPerInstanceKeyStreams() {
  std::cout << "Testing per-instance key streams..." << std::endl;
  std::vector<uint8_t> bfbs, plain;
  TEST_TRUE(Compile(kNodeSchema, kNodeJson, &bfbs, &plain));
  if (plain.empty()) return;

  std::vector<Instance> secrets, pins;
  CollectRoot(plain.data(), &secrets, &pins);
  TEST_EQ(secrets.size(), static_cast<size_t>(8));
  TEST_EQ(pins.size(), static_cast<size_t>(8));

  uint8_t key[32];
  MakeKey(key, 1);
  flatbuffers::EncryptionContext ctx(key, 32);
  std::vector<uint8_t> cipher = plain;
  auto result = flatbuffers::EncryptBuffer(cipher.data(), cipher.size(),
                                           bfbs.data(), bfbs.size(), ctx);
  TEST_TRUE(result.ok());

  for (const auto& i : secrets) {
    if (Same(plain, cipher, i)) std::cerr << "  plaintext: " << i.what << std::endl;
    TEST_TRUE(!Same(plain, cipher, i));
  }
  for (const auto& i : pins) {
    if (Same(plain, cipher, i)) std::cerr << "  plaintext: " << i.what << std::endl;
    TEST_TRUE(!Same(plain, cipher, i));
  }
  TEST_TRUE(OutsideUnchanged(plain, cipher, secrets, pins));

  // The known-plaintext XOR: knowing root.secret must not reveal any other
  // secret, and knowing any pin must not reveal another.
  for (size_t b = 1; b < secrets.size(); b++) {
    if (Recovers(plain, cipher, secrets[0], secrets[b])) {
      std::cerr << "  XOR with root.secret recovers " << secrets[b].what
                << std::endl;
    }
    TEST_TRUE(!Recovers(plain, cipher, secrets[0], secrets[b]));
  }
  for (size_t a = 0; a < pins.size(); a++) {
    for (size_t b = a + 1; b < pins.size(); b++) {
      TEST_TRUE(!Recovers(plain, cipher, pins[a], pins[b]));
    }
  }

  // Round trip.
  std::vector<uint8_t> decrypted = cipher;
  result = flatbuffers::DecryptBuffer(decrypted.data(), decrypted.size(),
                                      bfbs.data(), bfbs.size(), ctx);
  TEST_TRUE(result.ok());
  TEST_TRUE(decrypted == plain);
}

// The legacy format still decrypts existing data: it is the per-field
// primitives with record 0 on the root table and its table-typed fields.
static void TestLegacyFormatV2() {
  std::cout << "Testing legacy format 2..." << std::endl;
  std::vector<uint8_t> bfbs, plain;
  TEST_TRUE(Compile(kNodeSchema, kNodeJson, &bfbs, &plain));
  if (plain.empty()) return;
  std::vector<Instance> secrets, pins;
  CollectRoot(plain.data(), &secrets, &pins);

  uint8_t key[32];
  MakeKey(key, 2);
  flatbuffers::EncryptionContext ctx(key, 32);

  // The documented format 2: each field is EncryptString/EncryptScalar with
  // its field id and record 0, on the root table and nested tables only.
  std::vector<uint8_t> expected = plain;
  for (size_t k = 0; k < secrets.size(); k++) {
    if (secrets[k].what.compare(0, 4, "root") != 0) continue;
    flatbuffers::EncryptString(expected.data() + secrets[k].pos, secrets[k].len,
                               ctx, 0);
    flatbuffers::EncryptScalar(expected.data() + pins[k].pos, 4, ctx, 1);
  }

  std::vector<uint8_t> v2 = plain;
  auto result = flatbuffers::EncryptBuffer(v2.data(), v2.size(), bfbs.data(),
                                           bfbs.size(), ctx, 0,
                                           flatbuffers::kFieldEncryptionV2);
  TEST_TRUE(result.ok());
  TEST_TRUE(v2 == expected);
  // Why format 3 exists: equal field ids share a key stream in format 2.
  TEST_TRUE(Recovers(plain, v2, secrets[0], secrets[1]));

  std::vector<uint8_t> decrypted = expected;
  result = flatbuffers::DecryptBuffer(decrypted.data(), decrypted.size(),
                                      bfbs.data(), bfbs.size(), ctx, 0,
                                      flatbuffers::kFieldEncryptionV2);
  TEST_TRUE(result.ok());
  TEST_TRUE(decrypted == plain);

  // Format 3 does not decrypt format-2 data.
  decrypted = expected;
  result = flatbuffers::DecryptBuffer(decrypted.data(), decrypted.size(),
                                      bfbs.data(), bfbs.size(), ctx);
  TEST_TRUE(result.ok());
  TEST_TRUE(decrypted != plain);

  result = flatbuffers::EncryptBuffer(v2.data(), v2.size(), bfbs.data(),
                                      bfbs.size(), ctx, 1,
                                      flatbuffers::kFieldEncryptionV2);
  TEST_EQ(result.error, flatbuffers::EncryptionError::kUnsupportedType);
  result = flatbuffers::EncryptBuffer(v2.data(), v2.size(), bfbs.data(),
                                      bfbs.size(), ctx, 0, 9);
  TEST_EQ(result.error, flatbuffers::EncryptionError::kUnsupportedType);
}

// Two buffers under one key with different record indexes share no key
// stream, and only the right record index decrypts.
static void TestRecordIndex() {
  std::cout << "Testing record indexes..." << std::endl;
  std::vector<uint8_t> bfbs, plain;
  TEST_TRUE(Compile(kNodeSchema, kNodeJson, &bfbs, &plain));
  if (plain.empty()) return;
  std::vector<Instance> secrets, pins;
  CollectRoot(plain.data(), &secrets, &pins);

  uint8_t key[32];
  MakeKey(key, 3);
  flatbuffers::EncryptionContext ctx(key, 32);
  std::vector<uint8_t> first = plain, second = plain;
  TEST_TRUE(flatbuffers::EncryptBuffer(first.data(), first.size(), bfbs.data(),
                                       bfbs.size(), ctx, 0).ok());
  TEST_TRUE(flatbuffers::EncryptBuffer(second.data(), second.size(),
                                       bfbs.data(), bfbs.size(), ctx, 1).ok());
  for (const auto& i : secrets) TEST_TRUE(!Same(first, second, i));
  for (const auto& i : pins) TEST_TRUE(!Same(first, second, i));

  std::vector<uint8_t> decrypted = second;
  TEST_TRUE(flatbuffers::DecryptBuffer(decrypted.data(), decrypted.size(),
                                       bfbs.data(), bfbs.size(), ctx, 0).ok());
  TEST_TRUE(decrypted != plain);
  decrypted = second;
  TEST_TRUE(flatbuffers::DecryptBuffer(decrypted.data(), decrypted.size(),
                                       bfbs.data(), bfbs.size(), ctx, 1).ok());
  TEST_TRUE(decrypted == plain);
}

// A table or string shared by offset is encrypted once: walking it twice would
// XOR the same key stream twice and leave plaintext.
static void TestSharedTableAndString() {
  std::cout << "Testing shared tables and strings..." << std::endl;
  std::vector<uint8_t> bfbs, unused;
  TEST_TRUE(Compile(kNodeSchema, nullptr, &bfbs, &unused));

  flatbuffers::FlatBufferBuilder builder;
  auto text = builder.CreateString("shared secret 16");
  auto make_node = [&](int32_t pin) -> flatbuffers::Offset<flatbuffers::Table> {
    auto start = builder.StartTable();
    builder.AddOffset(kSecret, text);
    builder.AddElement<int32_t>(kPin, pin, 0);
    return flatbuffers::Offset<flatbuffers::Table>(builder.EndTable(start));
  };
  auto node = make_node(42);
  auto other = make_node(43);  // shares the string with `node`
  std::vector<flatbuffers::Offset<flatbuffers::Table>> list = {node, node, other};
  auto items = builder.CreateVector(list);
  auto start = builder.StartTable();
  builder.AddOffset(kChild, node);
  builder.AddOffset(kItems, items);
  builder.Finish(flatbuffers::Offset<flatbuffers::Table>(builder.EndTable(start)));
  std::vector<uint8_t> plain(builder.GetBufferPointer(),
                             builder.GetBufferPointer() + builder.GetSize());

  std::vector<Instance> secrets, pins;
  CollectRoot(plain.data(), &secrets, &pins);
  TEST_EQ(secrets.size(), static_cast<size_t>(4));  // child + 3 items

  uint8_t key[32];
  MakeKey(key, 4);
  flatbuffers::EncryptionContext ctx(key, 32);
  std::vector<uint8_t> cipher = plain;
  TEST_TRUE(flatbuffers::EncryptBuffer(cipher.data(), cipher.size(),
                                       bfbs.data(), bfbs.size(), ctx).ok());
  for (const auto& i : secrets) TEST_TRUE(!Same(plain, cipher, i));
  for (const auto& i : pins) TEST_TRUE(!Same(plain, cipher, i));
  std::vector<uint8_t> decrypted = cipher;
  TEST_TRUE(flatbuffers::DecryptBuffer(decrypted.data(), decrypted.size(),
                                       bfbs.data(), bfbs.size(), ctx).ok());
  TEST_TRUE(decrypted == plain);
}

// Vectors of strings and of structs, and structs: each string of a vector gets
// its own key stream.
static void TestEncryptedVectorsAndStructs() {
  std::cout << "Testing encrypted vectors and structs..." << std::endl;
  const char* schema = R"(
    struct Vec2 { x: float; y: float; }
    table Record {
      names: [string] (encrypted);
      points: [Vec2] (encrypted);
      raw: [ubyte] (encrypted);
      where: Vec2 (encrypted);
      flag: bool (encrypted);
      label: string;
    }
    root_type Record;
  )";
  const char* json = R"({
    names: [ "same sixteen txt", "same sixteen txt" ],
    points: [ { x: 1.5, y: 2.5 }, { x: 3.5, y: 4.5 } ],
    raw: [ 1, 2, 3, 4, 5, 6, 7, 8 ],
    where: { x: 9.5, y: 10.5 },
    flag: true,
    label: "public label"
  })";
  std::vector<uint8_t> bfbs, plain;
  TEST_TRUE(Compile(schema, json, &bfbs, &plain));
  if (plain.empty()) return;

  auto root = flatbuffers::GetRoot<flatbuffers::Table>(plain.data());
  auto names = root->GetPointer<
      const flatbuffers::Vector<flatbuffers::Offset<flatbuffers::String>>*>(4);
  auto points = root->GetPointer<const flatbuffers::Vector<uint8_t>*>(6);
  auto raw = root->GetPointer<const flatbuffers::Vector<uint8_t>*>(8);
  auto where = root->GetAddressOf(10);
  auto flag = root->GetAddressOf(12);
  TEST_TRUE(names && points && raw && where && flag);
  if (!(names && points && raw && where && flag)) return;
  auto pos = [&](const void* p) {
    return static_cast<size_t>(static_cast<const uint8_t*>(p) - plain.data());
  };
  std::vector<Instance> all = {
      {pos(names->Get(0)->Data()), 16, "names[0]"},
      {pos(names->Get(1)->Data()), 16, "names[1]"},
      {pos(points->Data()), 16, "points"},
      {pos(raw->Data()), 8, "raw"},
      {pos(where), 8, "where"},
      {pos(flag), 1, "flag"},
  };

  uint8_t key[32];
  MakeKey(key, 5);
  flatbuffers::EncryptionContext ctx(key, 32);
  std::vector<uint8_t> cipher = plain;
  auto result = flatbuffers::EncryptBuffer(cipher.data(), cipher.size(),
                                           bfbs.data(), bfbs.size(), ctx);
  TEST_TRUE(result.ok());
  // A 1-byte bool has a 1 in 256 chance to encrypt to itself; this key does not.
  for (const auto& i : all) TEST_TRUE(!Same(plain, cipher, i));
  TEST_TRUE(!Recovers(plain, cipher, all[0], all[1]));
  TEST_TRUE(OutsideUnchanged(plain, cipher, all, std::vector<Instance>()));
  std::vector<uint8_t> decrypted = cipher;
  TEST_TRUE(flatbuffers::DecryptBuffer(decrypted.data(), decrypted.size(),
                                       bfbs.data(), bfbs.size(), ctx).ok());
  TEST_TRUE(decrypted == plain);
}

// An (encrypted) field the walker cannot encrypt in place is refused with an
// error before any byte changes, never skipped in plaintext.
static void TestUnsupportedFieldsRefused() {
  std::cout << "Testing unsupported (encrypted) fields are refused..."
            << std::endl;
  struct Case {
    const char* what;
    const char* schema;
    const char* json;
  };
  const Case cases[] = {
      {"table", R"(
        table Inner { text: string; }
        table Outer { inner: Inner (encrypted); }
        root_type Outer;)",
       R"({ inner: { text: "plaintext table" } })"},
      {"vector of tables", R"(
        table Inner { text: string; }
        table Outer { items: [Inner] (encrypted); }
        root_type Outer;)",
       R"({ items: [ { text: "plaintext item" } ] })"},
      {"union", R"(
        table Inner { text: string; }
        union U { Inner }
        table Outer { u: U (encrypted); }
        root_type Outer;)",
       R"({ u_type: "Inner", u: { text: "plaintext member" } })"},
      {"struct fields marked one by one", R"(
        struct Pair { a: int (encrypted); b: int; }
        table Outer { pair: Pair; }
        root_type Outer;)",
       R"({ pair: { a: 7, b: 8 } })"},
      {"64-bit offsets", R"(
        table Outer { big: [ubyte] (encrypted, vector64); }
        root_type Outer;)",
       R"({ big: [ 1, 2, 3, 4 ] })"},
      {"a table reached through a vector", R"(
        table Inner { inner: Leaf (encrypted); }
        table Leaf { text: string; }
        table Outer { items: [Inner]; }
        root_type Outer;)",
       R"({ items: [ { inner: { text: "deep plaintext" } } ] })"},
  };
  uint8_t key[32];
  MakeKey(key, 6);
  flatbuffers::EncryptionContext ctx(key, 32);
  for (const auto& c : cases) {
    std::vector<uint8_t> bfbs, plain;
    TEST_TRUE(Compile(c.schema, c.json, &bfbs, &plain));
    if (plain.empty()) continue;
    std::vector<uint8_t> buf = plain;
    auto result = flatbuffers::EncryptBuffer(buf.data(), buf.size(),
                                             bfbs.data(), bfbs.size(), ctx);
    if (result.ok()) std::cerr << "  not refused: " << c.what << std::endl;
    TEST_EQ(result.error, flatbuffers::EncryptionError::kUnsupportedType);
    TEST_TRUE(buf == plain);
  }
}

// A malformed buffer fails before any byte changes; a bad schema is refused.
static void TestMalformedInput() {
  std::cout << "Testing malformed input..." << std::endl;
  std::vector<uint8_t> bfbs, plain;
  TEST_TRUE(Compile(kNodeSchema, kNodeJson, &bfbs, &plain));
  if (plain.empty()) return;
  uint8_t key[32];
  MakeKey(key, 7);
  flatbuffers::EncryptionContext ctx(key, 32);

  // Cut off the tail: the root's own fields still resolve, but deeper
  // references leave the buffer.
  std::vector<uint8_t> truncated(plain.begin(),
                                 plain.begin() + static_cast<std::ptrdiff_t>(plain.size() / 2));
  std::vector<uint8_t> before = truncated;
  auto result = flatbuffers::EncryptBuffer(truncated.data(), truncated.size(),
                                           bfbs.data(), bfbs.size(), ctx);
  TEST_TRUE(!result.ok());
  TEST_TRUE(truncated == before);

  std::vector<uint8_t> bad_schema = bfbs;
  bad_schema.resize(bad_schema.size() / 2);
  std::vector<uint8_t> buf = plain;
  result = flatbuffers::EncryptBuffer(buf.data(), buf.size(), bad_schema.data(),
                                      bad_schema.size(), ctx);
  TEST_EQ(result.error, flatbuffers::EncryptionError::kInvalidSchema);
  TEST_TRUE(buf == plain);
}

// tests/encryption_v3 holds the buffers every generated FlatbuffersEncryption
// helper (Python, Go, Java, Kotlin, C#, PHP, Dart, Rust, Swift) must
// reproduce: the C++ walker must encrypt the plaintext fixtures to exactly
// the ciphertext fixtures. With --write-fixtures it writes them instead.
static void TestGeneratedHelperFixtures(const std::string& dir, bool write) {
  std::cout << "Testing the generated-helper fixtures in " << dir << "..."
            << std::endl;
#if defined(FLATBUFFERS_USE_OPENSSL) || defined(FLATBUFFERS_USE_CRYPTOPP)
  struct Cipher {
    uint32_t record;
    const char* file;
  };
  struct Fixture {
    const char* schema;
    const char* plain;
    std::vector<Cipher> ciphers;
  };
  const std::vector<Fixture> fixtures = {
      {"node.fbs", "node.bin", {{0, "node_r0.bin"}, {1, "node_r1.bin"}}},
      {"bag.fbs", "bag.bin", {{0, "bag_r0.bin"}}},
  };
  uint8_t key[32];
  for (int i = 0; i < 32; i++) key[i] = static_cast<uint8_t>(i);
  flatbuffers::EncryptionContext ctx(key, 32);

  for (const auto& fixture : fixtures) {
    std::string schema_text, plain_text;
    const std::string schema_path = dir + fixture.schema;
    TEST_TRUE(flatbuffers::LoadFile(schema_path.c_str(), false, &schema_text));
    TEST_TRUE(flatbuffers::LoadFile((dir + fixture.plain).c_str(), true,
                                    &plain_text));
    if (schema_text.empty() || plain_text.empty()) continue;

    flatbuffers::Parser parser;
    parser.opts.binary_schema_builtins = true;
    const char* include_paths[] = { dir.c_str(), nullptr };
    TEST_TRUE(parser.Parse(schema_text.c_str(), include_paths,
                           schema_path.c_str()));
    parser.Serialize();
    const std::vector<uint8_t> bfbs(
        parser.builder_.GetBufferPointer(),
        parser.builder_.GetBufferPointer() + parser.builder_.GetSize());
    const std::vector<uint8_t> plain(plain_text.begin(), plain_text.end());

    for (const auto& cipher : fixture.ciphers) {
      std::vector<uint8_t> buf = plain;
      auto result = flatbuffers::EncryptBuffer(buf.data(), buf.size(),
                                               bfbs.data(), bfbs.size(), ctx,
                                               cipher.record);
      TEST_TRUE(result.ok());
      TEST_TRUE(buf != plain);
      const std::string path = dir + cipher.file;
      if (write) {
        TEST_TRUE(flatbuffers::SaveFile(
            path.c_str(), reinterpret_cast<const char*>(buf.data()),
            buf.size(), true));
      } else {
        std::string expected;
        TEST_TRUE(flatbuffers::LoadFile(path.c_str(), true, &expected));
        TEST_TRUE(std::string(buf.begin(), buf.end()) == expected);
      }
      result = flatbuffers::DecryptBuffer(buf.data(), buf.size(), bfbs.data(),
                                          bfbs.size(), ctx, cipher.record);
      TEST_TRUE(result.ok());
      TEST_TRUE(buf == plain);
    }
  }
#else
  (void)dir;
  (void)write;
  std::cout << "  (skipped: the fallback backend has no HKDF-SHA256)"
            << std::endl;
#endif
}

int main(int argc, char* argv[]) {
  std::string fixtures_dir = "tests/encryption_v3/";
  bool write_fixtures = false;
  for (int i = 1; i < argc; i++) {
    const std::string arg = argv[i];
    if (arg == "--write-fixtures") {
      write_fixtures = true;
    } else if (arg == "--fixtures-dir" && i + 1 < argc) {
      fixtures_dir = argv[++i];
      if (!fixtures_dir.empty() && fixtures_dir.back() != '/') {
        fixtures_dir += '/';
      }
    }
  }

  std::cout << "=== FlatBuffers Encryption Tests ===" << std::endl;

  TestEncryptionContext();
  TestEncryptBytes();
  TestScalarEncryption();
  TestSchemaWithEncryptedAttribute();
  TestIsFieldEncrypted();
  TestGetEncryptedFieldIds();
  TestBufferEncryption();
  TestDerivationVectors();
  TestPerInstanceKeyStreams();
  TestLegacyFormatV2();
  TestRecordIndex();
  TestSharedTableAndString();
  TestEncryptedVectorsAndStructs();
  TestUnsupportedFieldsRefused();
  TestMalformedInput();
  TestGeneratedHelperFixtures(fixtures_dir, write_fixtures);

  std::cout << std::endl;
  std::cout << "=== Results ===" << std::endl;
  std::cout << "Passed: " << num_passed << "/" << num_tests << std::endl;

  if (num_passed == num_tests) {
    std::cout << "ALL TESTS PASSED!" << std::endl;
    return 0;
  } else {
    std::cout << "SOME TESTS FAILED!" << std::endl;
    return 1;
  }
}
