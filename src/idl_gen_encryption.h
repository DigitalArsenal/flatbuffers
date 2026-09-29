/*
 * Copyright 2026 Google Inc. All rights reserved.
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

#ifndef FLATBUFFERS_IDL_GEN_ENCRYPTION_H_
#define FLATBUFFERS_IDL_GEN_ENCRYPTION_H_

// Code generation for field-encryption format 3 (see
// include/flatbuffers/encryption.h and docs/source/encryption.md).
//
// A generated FlatbuffersEncryption helper encrypts or decrypts every
// (encrypted) field instance of a buffer in place, exactly as the C++ walker
// (EncryptBuffer/DecryptBuffer, version 3) and flatc-wasm do:
//
//   K  = HKDF-SHA256(key, no salt, "flatbuffers-buffer-v3" || BE32(record))
//   IV = BE32(position of the instance's first byte) || 12 zero bytes
//
// and each instance is AES-256-CTR encrypted with K and its IV. The helper is
// a small interpreter; each table that reaches an (encrypted) field gets a
// "walk program": an int array that lists, for every table reachable from it
// that needs walking, which fields to encrypt and which to follow. The
// program holds only vtable slots, sizes, union type values and table
// indexes, so it never refers to another generated type or namespace.
//
// Program layout:
//   [0]          number of tables N (table 0 is the table itself)
//   [1 .. N]     start of each table's op list
//   op list:     count, then count ops
//   op:          kind, slot, operands (see OpKind in idl_gen_encryption.cpp)

#include <memory>
#include <string>
#include <vector>

#include "flatbuffers/idl.h"

namespace flatbuffers {
namespace encryption_codegen {

// Which tables need walking, their walk programs, and the schema checks, for
// one parsed schema.
class Plan {
 public:
  explicit Plan(const Parser& parser);
  ~Plan();

  // False when an (encrypted) field is one format 3 cannot encrypt; error()
  // says which and why.
  bool ok() const;
  const std::string& error() const;

  // True when the table has an (encrypted) field or reaches one through a
  // table, a vector of tables or a union.
  bool NeedsWalk(const StructDef& def) const;

  // True when a table defined in the file being generated needs walking.
  bool AnyGenerated() const;

  // True when any table of the schema, included ones too, needs walking.
  bool Any() const;

  // The walk program of `root` as comma-separated lines of at most `per_line`
  // integers, each line but the last ending with a comma.
  std::vector<std::string> ProgramLines(const StructDef& root,
                                        size_t per_line = 16) const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;

  Plan(const Plan&);
  Plan& operator=(const Plan&);
};

// For generators without a FlatbuffersEncryption helper whose accessors used
// to call a decrypt helper for (encrypted) scalar and string fields: refuses
// such a schema instead of generating readers that return ciphertext
// silently. Returns the error, or "".
std::string RefuseEncryptedAccessors(const Parser& parser,
                                     const std::string& language);

}  // namespace encryption_codegen
}  // namespace flatbuffers

#endif  // FLATBUFFERS_IDL_GEN_ENCRYPTION_H_
