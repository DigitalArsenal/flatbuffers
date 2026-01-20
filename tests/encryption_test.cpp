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
#include <iostream>
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
void TestEncryptionContext() {
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
void TestEncryptBytes() {
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
void TestScalarEncryption() {
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
void TestSchemaWithEncryptedAttribute() {
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
void TestBufferEncryption() {
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
  parser.opts.binary_to_compile_output = true;
  TEST_TRUE(parser.Parse(schema_str));

  // Generate binary schema
  std::string bfbs;
  parser.Serialize(&bfbs);
  TEST_TRUE(bfbs.size() > 0);

  // Build a FlatBuffer
  flatbuffers::FlatBufferBuilder builder;
  auto secret_text = builder.CreateString("This is secret!");

  // Manually build the buffer (since we don't have generated code)
  auto start = builder.StartTable();
  builder.AddElement<uint64_t>(4, 12345, 0);  // public_id at field 0
  builder.AddElement<int32_t>(6, 9999, 0);    // secret_value at field 1
  builder.AddOffset(8, secret_text);           // secret_text at field 2
  auto root = builder.EndTable(start);
  builder.Finish(root);

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
      reinterpret_cast<const uint8_t*>(bfbs.data()), bfbs.size(),
      ctx);

  TEST_TRUE(result.ok());

  // Buffer should be different after encryption
  bool buffer_changed = memcmp(buf, original.data(), size) != 0;
  TEST_TRUE(buffer_changed);

  // Decrypt the buffer
  result = flatbuffers::DecryptBuffer(
      buf, size,
      reinterpret_cast<const uint8_t*>(bfbs.data()), bfbs.size(),
      ctx);

  TEST_TRUE(result.ok());

  // Buffer should match original after decryption
  bool buffer_restored = memcmp(buf, original.data(), size) == 0;
  TEST_TRUE(buffer_restored);
}

// Test IsFieldEncrypted helper
void TestIsFieldEncrypted() {
  std::cout << "Testing IsFieldEncrypted..." << std::endl;

  const char* schema_str = R"(
    table TestTable {
      normal: int;
      secret: string (encrypted);
    }
    root_type TestTable;
  )";

  flatbuffers::Parser parser;
  parser.opts.binary_to_compile_output = true;
  TEST_TRUE(parser.Parse(schema_str));

  std::string bfbs;
  parser.Serialize(&bfbs);

  auto schema = flatbuffers::reflection::GetSchema(
      reinterpret_cast<const uint8_t*>(bfbs.data()));
  TEST_NOTNULL(schema);

  auto root_table = schema->root_table();
  TEST_NOTNULL(root_table);

  auto fields = root_table->fields();
  TEST_NOTNULL(fields);

  for (auto field : *fields) {
    if (field->name()->string_view() == "normal") {
      TEST_TRUE(!flatbuffers::IsFieldEncrypted(field));
    } else if (field->name()->string_view() == "secret") {
      TEST_TRUE(flatbuffers::IsFieldEncrypted(field));
    }
  }
}

// Test GetEncryptedFieldIds
void TestGetEncryptedFieldIds() {
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
  parser.opts.binary_to_compile_output = true;
  TEST_TRUE(parser.Parse(schema_str));

  std::string bfbs;
  parser.Serialize(&bfbs);

  auto ids = flatbuffers::GetEncryptedFieldIds(
      reinterpret_cast<const uint8_t*>(bfbs.data()), bfbs.size());

  // Should have 2 encrypted fields
  TEST_EQ(ids.size(), static_cast<size_t>(2));
}

int main(int argc, char* argv[]) {
  (void)argc;
  (void)argv;

  std::cout << "=== FlatBuffers Encryption Tests ===" << std::endl;

  TestEncryptionContext();
  TestEncryptBytes();
  TestScalarEncryption();
  TestSchemaWithEncryptedAttribute();
  TestIsFieldEncrypted();
  TestGetEncryptedFieldIds();
  TestBufferEncryption();

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
