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

// Homomorphic Encryption Tests for FlatBuffers
// These tests require SEAL to be available (FLATBUFFERS_HE_USE_SEAL defined)

#include "flatbuffers/he_encryption.h"
#include "flatbuffers/he_operations.h"
#include "flatbuffers/idl.h"

#include <cstdio>
#include <cstring>
#include <iostream>
#include <vector>

// Test utilities
static int num_tests = 0;
static int num_passed = 0;

#define TEST_EQ(expr, expected)                                        \
  do {                                                                 \
    num_tests++;                                                       \
    auto _test_val = (expr);                                           \
    if (_test_val == (expected)) {                                     \
      num_passed++;                                                    \
    } else {                                                           \
      std::cerr << "FAILED: " << #expr << " != " << #expected          \
                << " (got " << static_cast<int64_t>(_test_val)          \
                << ")" << std::endl;                                   \
    }                                                                  \
  } while (0)

#define TEST_TRUE(expr)                                                \
  do {                                                                 \
    num_tests++;                                                       \
    if (expr) {                                                        \
      num_passed++;                                                    \
    } else {                                                           \
      std::cerr << "FAILED: " << #expr << " is false" << std::endl;    \
    }                                                                  \
  } while (0)

#define TEST_FALSE(expr)                                               \
  do {                                                                 \
    num_tests++;                                                       \
    if (!(expr)) {                                                     \
      num_passed++;                                                    \
    } else {                                                           \
      std::cerr << "FAILED: " << #expr << " is true" << std::endl;     \
    }                                                                  \
  } while (0)

// Test schema with he_encrypted attribute parsing
static void TestHESchemaAttribute() {
  std::cout << "Testing he_encrypted attribute parsing..." << std::endl;

  flatbuffers::IDLOptions opts;
  flatbuffers::Parser parser(opts);

  // Valid schema with he_encrypted on numeric fields
  const char* valid_schema = R"(
    attribute "he_encrypted";

    table EncryptedRecord {
      id: uint64;
      balance: int64 (he_encrypted);
      amount: int32 (he_encrypted);
      rate: double (he_encrypted);
    }

    root_type EncryptedRecord;
  )";

  TEST_TRUE(parser.Parse(valid_schema));

  // Check that fields have the attribute
  auto* record = parser.structs_.Lookup("EncryptedRecord");
  TEST_TRUE(record != nullptr);

  if (record) {
    auto* id_field = record->fields.Lookup("id");
    auto* balance_field = record->fields.Lookup("balance");
    auto* amount_field = record->fields.Lookup("amount");
    auto* rate_field = record->fields.Lookup("rate");

    TEST_TRUE(id_field != nullptr);
    TEST_TRUE(balance_field != nullptr);
    TEST_TRUE(amount_field != nullptr);
    TEST_TRUE(rate_field != nullptr);

    if (id_field && balance_field && amount_field && rate_field) {
      // id should NOT have he_encrypted
      TEST_TRUE(id_field->attributes.Lookup("he_encrypted") == nullptr);
      // balance, amount, rate SHOULD have he_encrypted
      TEST_TRUE(balance_field->attributes.Lookup("he_encrypted") != nullptr);
      TEST_TRUE(amount_field->attributes.Lookup("he_encrypted") != nullptr);
      TEST_TRUE(rate_field->attributes.Lookup("he_encrypted") != nullptr);
    }
  }
}

// Test that he_encrypted fails on unsupported types
static void TestHESchemaValidation() {
  std::cout << "Testing he_encrypted validation..." << std::endl;

  flatbuffers::IDLOptions opts;

  // Test: he_encrypted on string should fail
  {
    flatbuffers::Parser parser(opts);
    const char* bad_schema = R"(
      attribute "he_encrypted";
      table BadRecord {
        name: string (he_encrypted);
      }
    )";
    TEST_FALSE(parser.Parse(bad_schema));
  }

  // Test: he_encrypted on bool should fail
  {
    flatbuffers::Parser parser(opts);
    const char* bad_schema = R"(
      attribute "he_encrypted";
      table BadRecord {
        flag: bool (he_encrypted);
      }
    )";
    TEST_FALSE(parser.Parse(bad_schema));
  }

  // Test: he_encrypted on nested table should fail
  {
    flatbuffers::Parser parser(opts);
    const char* bad_schema = R"(
      attribute "he_encrypted";
      table Inner { x: int32; }
      table BadRecord {
        inner: Inner (he_encrypted);
      }
    )";
    TEST_FALSE(parser.Parse(bad_schema));
  }

  // Test: he_encrypted on vector of integers should succeed
  {
    flatbuffers::Parser parser(opts);
    const char* good_schema = R"(
      attribute "he_encrypted";
      table GoodRecord {
        values: [int64] (he_encrypted);
      }
    )";
    TEST_TRUE(parser.Parse(good_schema));
  }
}

#ifdef FLATBUFFERS_HE_USE_SEAL

using namespace flatbuffers::he;

// Test HEContext creation
static void TestHEContextCreation() {
  std::cout << "Testing HEContext creation..." << std::endl;

  // Create client context
  auto client = HEContext::CreateClient();
  TEST_TRUE(client.IsValid());
  TEST_TRUE(client.HasSecretKey());
  TEST_EQ(client.GetScheme(), HEScheme::BFV);
  TEST_EQ(client.GetPolyModulusDegree(), kDefaultPolyModulusDegree);

  // Get keys
  auto pk = client.GetPublicKey();
  auto rk = client.GetRelinKeys();
  auto sk = client.GetSecretKey();

  TEST_TRUE(!pk.empty());
  TEST_TRUE(!rk.empty());
  TEST_TRUE(!sk.empty());

  // Create server context from public key
  auto server = HEContext::CreateServer(pk.data(), pk.size());
  TEST_TRUE(server.IsValid());
  TEST_FALSE(server.HasSecretKey());

  // Server should be able to set relin keys
  auto result = server.SetRelinKeys(rk.data(), rk.size());
  TEST_TRUE(result.ok());
}

// Test encrypt/decrypt round-trip
static void TestHEEncryptDecrypt() {
  std::cout << "Testing HE encrypt/decrypt..." << std::endl;

  auto client = HEContext::CreateClient();
  TEST_TRUE(client.IsValid());

  // Test int64
  {
    int64_t value = 12345;
    auto ct = client.EncryptInt64(value);
    TEST_TRUE(!ct.empty());

    int64_t decrypted = client.DecryptInt64(ct.data(), ct.size());
    TEST_EQ(decrypted, value);
  }

  // Test negative int64
  {
    int64_t value = -98765;
    auto ct = client.EncryptInt64(value);
    TEST_TRUE(!ct.empty());

    int64_t decrypted = client.DecryptInt64(ct.data(), ct.size());
    TEST_EQ(decrypted, value);
  }

  // Test double (fixed-point)
  {
    double value = 3.14159;
    auto ct = client.EncryptDouble(value);
    TEST_TRUE(!ct.empty());

    double decrypted = client.DecryptDouble(ct.data(), ct.size());
    // Allow small error due to fixed-point encoding
    TEST_TRUE(std::abs(decrypted - value) < 0.0001);
  }
}

// Test homomorphic operations
static void TestHEOperations() {
  std::cout << "Testing HE operations..." << std::endl;

  auto client = HEContext::CreateClient();
  auto pk = client.GetPublicKey();
  auto rk = client.GetRelinKeys();

  // Create server context
  auto server = HEContext::CreateServer(pk.data(), pk.size());
  server.SetRelinKeys(rk.data(), rk.size());

  // Encrypt values on client
  auto ct1 = client.EncryptInt64(42);
  auto ct2 = client.EncryptInt64(10);
  TEST_TRUE(!ct1.empty() && !ct2.empty());

  // Perform operations on server
  auto sum = server.Add(ct1.data(), ct1.size(), ct2.data(), ct2.size());
  auto product = server.Multiply(ct1.data(), ct1.size(), ct2.data(), ct2.size());
  auto sum_plain = server.AddPlain(ct1.data(), ct1.size(), 8);
  auto mul_plain = server.MultiplyPlain(ct1.data(), ct1.size(), 3);

  TEST_TRUE(!sum.empty());
  TEST_TRUE(!product.empty());
  TEST_TRUE(!sum_plain.empty());
  TEST_TRUE(!mul_plain.empty());

  // Decrypt and verify on client
  TEST_EQ(client.DecryptInt64(sum.data(), sum.size()), 52);      // 42 + 10
  TEST_EQ(client.DecryptInt64(product.data(), product.size()), 420);  // 42 * 10
  TEST_EQ(client.DecryptInt64(sum_plain.data(), sum_plain.size()), 50);  // 42 + 8
  TEST_EQ(client.DecryptInt64(mul_plain.data(), mul_plain.size()), 126); // 42 * 3
}

// Test using free functions from he_operations.h
static void TestHEOperationsFunctions() {
  std::cout << "Testing HE operation functions..." << std::endl;

  auto client = HEContext::CreateClient();
  auto pk = client.GetPublicKey();
  auto rk = client.GetRelinKeys();

  auto server = HEContext::CreateServer(pk.data(), pk.size());
  server.SetRelinKeys(rk.data(), rk.size());

  auto ct1 = client.EncryptInt64(100);
  auto ct2 = client.EncryptInt64(25);

  // Use free functions
  auto sum = Add(ct1, ct2, server);
  auto diff = Sub(ct1, ct2, server);
  auto product = Multiply(ct1, ct2, server);

  TEST_EQ(client.DecryptInt64(sum), 125);    // 100 + 25
  TEST_EQ(client.DecryptInt64(diff), 75);    // 100 - 25
  TEST_EQ(client.DecryptInt64(product), 2500); // 100 * 25
}

// Test ciphertext validation
static void TestCiphertextValidation() {
  std::cout << "Testing ciphertext validation..." << std::endl;

  auto client = HEContext::CreateClient();
  auto ct = client.EncryptInt64(123);

  // Valid ciphertext
  TEST_TRUE(IsValidCiphertext(ct.data(), ct.size()));
  TEST_EQ(GetCiphertextScheme(ct.data(), ct.size()), HEScheme::BFV);
  TEST_EQ(GetCiphertextPolyDegree(ct.data(), ct.size()), kDefaultPolyModulusDegree);

  // Invalid ciphertext (too short)
  uint8_t bad_data[4] = {0, 0, 0, 0};
  TEST_FALSE(IsValidCiphertext(bad_data, 4));
}

// Test key serialization/deserialization
static void TestHEKeySerialization() {
  std::cout << "Testing HE key serialization..." << std::endl;

  auto client1 = HEContext::CreateClient();
  auto pk = client1.GetPublicKey();
  auto rk = client1.GetRelinKeys();

  // Create new server from serialized keys
  auto server = HEContext::CreateServer(pk.data(), pk.size());
  TEST_TRUE(server.IsValid());

  auto result = server.SetRelinKeys(rk.data(), rk.size());
  TEST_TRUE(result.ok());

  // Verify operations work with deserialized keys
  auto ct = client1.EncryptInt64(50);
  auto doubled = server.MultiplyPlain(ct.data(), ct.size(), 2);

  TEST_EQ(client1.DecryptInt64(doubled.data(), doubled.size()), 100);
}

// Test: Conjunction assessment between two satellite ephemerides.
//
// Scenario: Two organizations each have a satellite in LEO. Neither wants
// to reveal their precise orbital positions. A trusted assessor generates
// an HE key pair, encrypts both ephemerides, and sends the ciphertexts to
// a computation server. The server computes the squared Euclidean distance
// at each time step entirely on encrypted data, then returns the encrypted
// results. The assessor decrypts and flags any time step where the distance
// is below 15 km.
//
// Homomorphic operations used per time step:
//   3x Sub (dx, dy, dz)
//   3x Multiply (dx^2, dy^2, dz^2)  -- one multiplicative depth
//   2x Add (dx^2 + dy^2 + dz^2)
static void TestHEConjunctionAssessment() {
  std::cout << "Testing HE conjunction assessment..." << std::endl;

  // --- Setup: Assessor creates HE context, server gets public key ---
  auto assessor = HEContext::CreateClient();
  TEST_TRUE(assessor.IsValid());

  auto pk = assessor.GetPublicKey();
  auto rk = assessor.GetRelinKeys();

  auto server = HEContext::CreateServer(pk.data(), pk.size());
  TEST_TRUE(server.IsValid());
  server.SetRelinKeys(rk.data(), rk.size());

  // --- Ephemeris data: positions in km at 5 time steps ---
  // Satellite A (LEO prograde orbit, simplified)
  constexpr int kNumSteps = 5;
  const int64_t sat_a_x[kNumSteps] = {6700, 6695, 6680, 6650, 6610};
  const int64_t sat_a_y[kNumSteps] = {   0,  100,  200,  300,  400};
  const int64_t sat_a_z[kNumSteps] = {   0,   50,  100,  150,  200};

  // Satellite B (crossing orbit -- closest approach at t=1)
  const int64_t sat_b_x[kNumSteps] = {6750, 6700, 6640, 6570, 6490};
  const int64_t sat_b_y[kNumSteps] = { -50,   95,  190,  280,  370};
  const int64_t sat_b_z[kNumSteps] = {  30,   48,   70,   90,  110};

  // Expected squared distances (computed in the clear for verification):
  //   t0: (-50)^2 + (50)^2  + (-30)^2 = 5900   ~76.8 km
  //   t1: (-5)^2  + (5)^2   + (2)^2   = 54     ~7.3 km  ** CONJUNCTION **
  //   t2: (40)^2  + (10)^2  + (30)^2  = 2600   ~51.0 km
  //   t3: (80)^2  + (20)^2  + (60)^2  = 10400  ~102 km
  //   t4: (120)^2 + (30)^2  + (90)^2  = 23400  ~153 km
  const int64_t expected_dist2[kNumSteps] = {5900, 54, 2600, 10400, 23400};

  constexpr int64_t kThresholdKm = 15;
  constexpr int64_t kThresholdSq = kThresholdKm * kThresholdKm;  // 225 km^2

  bool conjunction_detected = false;
  int conjunction_step = -1;

  for (int t = 0; t < kNumSteps; t++) {
    // --- Assessor encrypts both satellites' positions ---
    auto ct_ax = assessor.EncryptInt64(sat_a_x[t]);
    auto ct_ay = assessor.EncryptInt64(sat_a_y[t]);
    auto ct_az = assessor.EncryptInt64(sat_a_z[t]);
    auto ct_bx = assessor.EncryptInt64(sat_b_x[t]);
    auto ct_by = assessor.EncryptInt64(sat_b_y[t]);
    auto ct_bz = assessor.EncryptInt64(sat_b_z[t]);

    TEST_TRUE(!ct_ax.empty() && !ct_bx.empty());

    // --- Server computes squared distance on encrypted data ---

    // Step 1: Component differences (Sub)
    auto ct_dx = server.Sub(ct_ax.data(), ct_ax.size(),
                            ct_bx.data(), ct_bx.size());
    auto ct_dy = server.Sub(ct_ay.data(), ct_ay.size(),
                            ct_by.data(), ct_by.size());
    auto ct_dz = server.Sub(ct_az.data(), ct_az.size(),
                            ct_bz.data(), ct_bz.size());
    TEST_TRUE(!ct_dx.empty() && !ct_dy.empty() && !ct_dz.empty());

    // Step 2: Square each component (Multiply ct with itself)
    auto ct_dx2 = server.Multiply(ct_dx.data(), ct_dx.size(),
                                  ct_dx.data(), ct_dx.size());
    auto ct_dy2 = server.Multiply(ct_dy.data(), ct_dy.size(),
                                  ct_dy.data(), ct_dy.size());
    auto ct_dz2 = server.Multiply(ct_dz.data(), ct_dz.size(),
                                  ct_dz.data(), ct_dz.size());
    TEST_TRUE(!ct_dx2.empty() && !ct_dy2.empty() && !ct_dz2.empty());

    // Step 3: Sum of squares (Add)
    auto ct_partial = server.Add(ct_dx2.data(), ct_dx2.size(),
                                 ct_dy2.data(), ct_dy2.size());
    auto ct_dist2 = server.Add(ct_partial.data(), ct_partial.size(),
                                ct_dz2.data(), ct_dz2.size());
    TEST_TRUE(!ct_dist2.empty());

    // --- Assessor decrypts result ---
    int64_t dist2 = assessor.DecryptInt64(ct_dist2.data(), ct_dist2.size());

    // Verify against expected clear-text result
    TEST_EQ(dist2, expected_dist2[t]);

    // Check conjunction threshold
    if (dist2 < kThresholdSq && !conjunction_detected) {
      conjunction_detected = true;
      conjunction_step = t;
    }
  }

  // Verify: conjunction detected at time step 1 (d ≈ 7.3 km < 15 km)
  TEST_TRUE(conjunction_detected);
  TEST_EQ(conjunction_step, 1);
}

#endif  // FLATBUFFERS_HE_USE_SEAL

int main(int argc, char** argv) {
  (void)argc;
  (void)argv;

  std::cout << "=== FlatBuffers Homomorphic Encryption Tests ===" << std::endl;
  std::cout << std::endl;

  // Schema tests (always run)
  TestHESchemaAttribute();
  TestHESchemaValidation();

#ifdef FLATBUFFERS_HE_USE_SEAL
  std::cout << std::endl;
  std::cout << "SEAL is available, running HE functionality tests..." << std::endl;
  std::cout << std::endl;

  TestHEContextCreation();
  TestHEEncryptDecrypt();
  TestHEOperations();
  TestHEOperationsFunctions();
  TestCiphertextValidation();
  TestHEKeySerialization();
  TestHEConjunctionAssessment();
#else
  std::cout << std::endl;
  std::cout << "SEAL is not available, skipping HE functionality tests." << std::endl;
  std::cout << "To run full tests, build with -DFLATBUFFERS_HE_USE_SEAL=ON" << std::endl;
#endif

  std::cout << std::endl;
  std::cout << "=== Test Results ===" << std::endl;
  std::cout << "Passed: " << num_passed << "/" << num_tests << std::endl;

  return num_passed == num_tests ? 0 : 1;
}
