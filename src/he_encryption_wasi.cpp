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

// WASI-compatible C interface for FlatBuffers Homomorphic Encryption
// This file mirrors the Emscripten HE exports in flatc_wasm.cpp but uses
// the wasi_he_* prefix for WASI runtimes (wazero, wasmtime, wasmer, etc.)
//
// Functions that return variable-length data (ciphertexts, keys) write to
// a static output buffer and return a pointer + set an out_len parameter.
// The host runtime reads from WASM linear memory at the returned pointer.

#ifdef FLATBUFFERS_HE_USE_SEAL

#include "flatbuffers/he_encryption.h"
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <vector>

// Global storage for HE contexts (mirrors flatc_wasm.cpp)
static std::map<int32_t, std::unique_ptr<flatbuffers::he::HEContext>> g_he_contexts;
static int32_t g_next_he_context_id = 1;

// Global buffer for HE output data
static std::vector<uint8_t> g_he_output;

extern "C" {

// =============================================================================
// Context Management
// =============================================================================

// Create a client HE context with full key pair (secret + public).
// poly_degree: polynomial modulus degree (0 = default 4096)
// Returns context ID (>0) on success, -1 on error.
int32_t wasi_he_context_create_client(uint32_t poly_degree) {
  using namespace flatbuffers::he;
  try {
    auto ctx = std::make_unique<HEContext>(
        HEContext::CreateClient(poly_degree > 0 ? poly_degree : kDefaultPolyModulusDegree));
    if (!ctx->IsValid()) {
      return -1;
    }
    int32_t id = g_next_he_context_id++;
    g_he_contexts[id] = std::move(ctx);
    return id;
  } catch (...) {
    return -1;
  }
}

// Create a server HE context from a serialized public key.
// Server can only perform homomorphic operations, not decrypt.
// public_key: serialized public key bytes
// pk_len: length of public key data
// Returns context ID (>0) on success, -1 on error.
int32_t wasi_he_context_create_server(const uint8_t* public_key, uint32_t pk_len) {
  using namespace flatbuffers::he;
  if (!public_key || pk_len == 0) return -1;
  try {
    auto ctx = std::make_unique<HEContext>(
        HEContext::CreateServer(public_key, pk_len));
    if (!ctx->IsValid()) {
      return -1;
    }
    int32_t id = g_next_he_context_id++;
    g_he_contexts[id] = std::move(ctx);
    return id;
  } catch (...) {
    return -1;
  }
}

// Destroy an HE context and free resources.
void wasi_he_context_destroy(int32_t ctx_id) {
  g_he_contexts.erase(ctx_id);
}

// =============================================================================
// Key Management
// =============================================================================

// Get the serialized public key from a context.
// ctx_id: context ID
// out_len: pointer to receive the length of the key data
// Returns pointer to key data in WASM memory, or nullptr on error.
const uint8_t* wasi_he_get_public_key(int32_t ctx_id, uint32_t* out_len) {
  auto it = g_he_contexts.find(ctx_id);
  if (it == g_he_contexts.end() || !out_len) {
    if (out_len) *out_len = 0;
    return nullptr;
  }
  g_he_output = it->second->GetPublicKey();
  *out_len = static_cast<uint32_t>(g_he_output.size());
  return g_he_output.data();
}

// Get the serialized relinearization keys (needed for multiplication).
// ctx_id: context ID
// out_len: pointer to receive the length of the key data
// Returns pointer to key data, or nullptr on error.
const uint8_t* wasi_he_get_relin_keys(int32_t ctx_id, uint32_t* out_len) {
  auto it = g_he_contexts.find(ctx_id);
  if (it == g_he_contexts.end() || !out_len) {
    if (out_len) *out_len = 0;
    return nullptr;
  }
  g_he_output = it->second->GetRelinKeys();
  *out_len = static_cast<uint32_t>(g_he_output.size());
  return g_he_output.data();
}

// Get the serialized secret key (client context only).
// ctx_id: context ID
// out_len: pointer to receive the length of the key data
// Returns pointer to key data, or nullptr on error or if server context.
const uint8_t* wasi_he_get_secret_key(int32_t ctx_id, uint32_t* out_len) {
  auto it = g_he_contexts.find(ctx_id);
  if (it == g_he_contexts.end() || !out_len) {
    if (out_len) *out_len = 0;
    return nullptr;
  }
  try {
    g_he_output = it->second->GetSecretKey();
    *out_len = static_cast<uint32_t>(g_he_output.size());
    return g_he_output.data();
  } catch (...) {
    *out_len = 0;
    return nullptr;
  }
}

// Set relinearization keys on a server context.
// ctx_id: context ID
// rk: serialized relinearization key bytes
// rk_len: length of key data
// Returns 0 on success, -1 on error.
int32_t wasi_he_set_relin_keys(int32_t ctx_id, const uint8_t* rk, uint32_t rk_len) {
  auto it = g_he_contexts.find(ctx_id);
  if (it == g_he_contexts.end() || !rk || rk_len == 0) {
    return -1;
  }
  auto result = it->second->SetRelinKeys(rk, rk_len);
  return result.ok() ? 0 : -1;
}

// =============================================================================
// Encryption
// =============================================================================

// Encrypt a 64-bit integer.
// ctx_id: context ID
// value: integer value to encrypt
// out_len: pointer to receive ciphertext length
// Returns pointer to ciphertext data, or nullptr on error.
const uint8_t* wasi_he_encrypt_int64(int32_t ctx_id, int64_t value, uint32_t* out_len) {
  auto it = g_he_contexts.find(ctx_id);
  if (it == g_he_contexts.end() || !out_len) {
    if (out_len) *out_len = 0;
    return nullptr;
  }
  g_he_output = it->second->EncryptInt64(value);
  if (g_he_output.empty()) {
    *out_len = 0;
    return nullptr;
  }
  *out_len = static_cast<uint32_t>(g_he_output.size());
  return g_he_output.data();
}

// Decrypt a ciphertext to a 64-bit integer.
// ctx_id: context ID (must be client context with secret key)
// ct: ciphertext bytes
// ct_len: ciphertext length
// Returns decrypted value, or 0 on error.
int64_t wasi_he_decrypt_int64(int32_t ctx_id, const uint8_t* ct, uint32_t ct_len) {
  auto it = g_he_contexts.find(ctx_id);
  if (it == g_he_contexts.end() || !ct || ct_len == 0) {
    return 0;
  }
  try {
    return it->second->DecryptInt64(ct, ct_len);
  } catch (...) {
    return 0;
  }
}

// Encrypt a double-precision float.
// ctx_id: context ID
// value: double value to encrypt
// out_len: pointer to receive ciphertext length
// Returns pointer to ciphertext data, or nullptr on error.
const uint8_t* wasi_he_encrypt_double(int32_t ctx_id, double value, uint32_t* out_len) {
  auto it = g_he_contexts.find(ctx_id);
  if (it == g_he_contexts.end() || !out_len) {
    if (out_len) *out_len = 0;
    return nullptr;
  }
  g_he_output = it->second->EncryptDouble(value);
  if (g_he_output.empty()) {
    *out_len = 0;
    return nullptr;
  }
  *out_len = static_cast<uint32_t>(g_he_output.size());
  return g_he_output.data();
}

// Decrypt a ciphertext to a double.
// ctx_id: context ID (must be client context with secret key)
// ct: ciphertext bytes
// ct_len: ciphertext length
// Returns decrypted value, or 0.0 on error.
double wasi_he_decrypt_double(int32_t ctx_id, const uint8_t* ct, uint32_t ct_len) {
  auto it = g_he_contexts.find(ctx_id);
  if (it == g_he_contexts.end() || !ct || ct_len == 0) {
    return 0.0;
  }
  try {
    return it->second->DecryptDouble(ct, ct_len);
  } catch (...) {
    return 0.0;
  }
}

// =============================================================================
// Homomorphic Operations
// =============================================================================

// Add two ciphertexts: result = ct1 + ct2
const uint8_t* wasi_he_add(int32_t ctx_id,
                            const uint8_t* ct1, uint32_t ct1_len,
                            const uint8_t* ct2, uint32_t ct2_len,
                            uint32_t* out_len) {
  auto it = g_he_contexts.find(ctx_id);
  if (it == g_he_contexts.end() || !ct1 || !ct2 || !out_len) {
    if (out_len) *out_len = 0;
    return nullptr;
  }
  g_he_output = it->second->Add(ct1, ct1_len, ct2, ct2_len);
  if (g_he_output.empty()) {
    *out_len = 0;
    return nullptr;
  }
  *out_len = static_cast<uint32_t>(g_he_output.size());
  return g_he_output.data();
}

// Subtract ciphertexts: result = ct1 - ct2
const uint8_t* wasi_he_sub(int32_t ctx_id,
                            const uint8_t* ct1, uint32_t ct1_len,
                            const uint8_t* ct2, uint32_t ct2_len,
                            uint32_t* out_len) {
  auto it = g_he_contexts.find(ctx_id);
  if (it == g_he_contexts.end() || !ct1 || !ct2 || !out_len) {
    if (out_len) *out_len = 0;
    return nullptr;
  }
  g_he_output = it->second->Sub(ct1, ct1_len, ct2, ct2_len);
  if (g_he_output.empty()) {
    *out_len = 0;
    return nullptr;
  }
  *out_len = static_cast<uint32_t>(g_he_output.size());
  return g_he_output.data();
}

// Multiply two ciphertexts: result = ct1 * ct2 (requires relin keys)
const uint8_t* wasi_he_multiply(int32_t ctx_id,
                                 const uint8_t* ct1, uint32_t ct1_len,
                                 const uint8_t* ct2, uint32_t ct2_len,
                                 uint32_t* out_len) {
  auto it = g_he_contexts.find(ctx_id);
  if (it == g_he_contexts.end() || !ct1 || !ct2 || !out_len) {
    if (out_len) *out_len = 0;
    return nullptr;
  }
  g_he_output = it->second->Multiply(ct1, ct1_len, ct2, ct2_len);
  if (g_he_output.empty()) {
    *out_len = 0;
    return nullptr;
  }
  *out_len = static_cast<uint32_t>(g_he_output.size());
  return g_he_output.data();
}

// Negate ciphertext: result = -ct
const uint8_t* wasi_he_negate(int32_t ctx_id,
                               const uint8_t* ct, uint32_t ct_len,
                               uint32_t* out_len) {
  auto it = g_he_contexts.find(ctx_id);
  if (it == g_he_contexts.end() || !ct || !out_len) {
    if (out_len) *out_len = 0;
    return nullptr;
  }
  g_he_output = it->second->Negate(ct, ct_len);
  if (g_he_output.empty()) {
    *out_len = 0;
    return nullptr;
  }
  *out_len = static_cast<uint32_t>(g_he_output.size());
  return g_he_output.data();
}

// Add plaintext to ciphertext: result = ct + plain
const uint8_t* wasi_he_add_plain(int32_t ctx_id,
                                  const uint8_t* ct, uint32_t ct_len,
                                  int64_t plain,
                                  uint32_t* out_len) {
  auto it = g_he_contexts.find(ctx_id);
  if (it == g_he_contexts.end() || !ct || !out_len) {
    if (out_len) *out_len = 0;
    return nullptr;
  }
  g_he_output = it->second->AddPlain(ct, ct_len, plain);
  if (g_he_output.empty()) {
    *out_len = 0;
    return nullptr;
  }
  *out_len = static_cast<uint32_t>(g_he_output.size());
  return g_he_output.data();
}

// Multiply ciphertext by plaintext: result = ct * plain
const uint8_t* wasi_he_multiply_plain(int32_t ctx_id,
                                       const uint8_t* ct, uint32_t ct_len,
                                       int64_t plain,
                                       uint32_t* out_len) {
  auto it = g_he_contexts.find(ctx_id);
  if (it == g_he_contexts.end() || !ct || !out_len) {
    if (out_len) *out_len = 0;
    return nullptr;
  }
  g_he_output = it->second->MultiplyPlain(ct, ct_len, plain);
  if (g_he_output.empty()) {
    *out_len = 0;
    return nullptr;
  }
  *out_len = static_cast<uint32_t>(g_he_output.size());
  return g_he_output.data();
}

}  // extern "C"

#endif  // FLATBUFFERS_HE_USE_SEAL
