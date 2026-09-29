/*
 * Copyright 2018 Google Inc. All rights reserved.
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

#include "idl_gen_lobster.h"

#include <string>
#include <unordered_set>

#include "flatbuffers/code_generators.h"
#include "flatbuffers/flatbuffers.h"
#include "flatbuffers/idl.h"
#include "flatbuffers/util.h"
#include "idl_gen_encryption.h"

namespace flatbuffers {
namespace lobster {

class LobsterGenerator : public BaseGenerator {
 public:
  LobsterGenerator(const Parser& parser, const std::string& path,
                   const std::string& file_name)
      : BaseGenerator(parser, path, file_name, "" /* not used */, ".",
                      "lobster"),
        encryption_plan_(parser) {
    static const char* const keywords[] = {
        "nil",    "true",    "false",     "return",  "struct",    "class",
        "import", "int",     "float",     "string",  "any",       "def",
        "is",     "from",    "program",   "private", "coroutine", "resource",
        "enum",   "typeof",  "var",       "let",     "pakfile",   "switch",
        "case",   "default", "namespace", "not",     "and",       "or",
        "bool",
    };
    keywords_.insert(std::begin(keywords), std::end(keywords));
  }

  std::string EscapeKeyword(const std::string& name) const {
    return keywords_.find(name) == keywords_.end() ? name : name + "_";
  }

  std::string NormalizedName(const Definition& definition) const {
    return EscapeKeyword(definition.name);
  }

  std::string NormalizedName(const EnumVal& ev) const {
    return EscapeKeyword(ev.name);
  }

  std::string NamespacedName(const Definition& def) {
    return WrapInNameSpace(def.defined_namespace, NormalizedName(def));
  }

  std::string GenTypeName(const Type& type) {
    auto bits = NumToString(SizeOf(type.base_type) * 8);
    if (IsInteger(type.base_type)) {
      if (IsUnsigned(type.base_type))
        return "uint" + bits;
      else
        return "int" + bits;
    }
    if (IsFloat(type.base_type)) return "float" + bits;
    if (IsString(type)) return "string";
    if (type.base_type == BASE_TYPE_STRUCT) return "table";
    return "none";
  }

  std::string LobsterType(const Type& type) {
    if (IsFloat(type.base_type)) return "float";
    if (IsBool(type.base_type)) return "bool";
    if (IsScalar(type.base_type) && type.enum_def)
      return NormalizedName(*type.enum_def);
    if (!IsScalar(type.base_type)) return "flatbuffers.offset";
    if (IsString(type)) return "string";
    return "int";
  }

  // Returns the method name for use with add/put calls.
  std::string GenMethod(const Type& type) {
    return IsScalar(type.base_type)
               ? ConvertCase(GenTypeBasic(type), Case::kUpperCamel)
               : (IsStruct(type) ? "Struct" : "UOffsetTRelative");
  }

  // This uses Python names for now..
  std::string GenTypeBasic(const Type& type) {
    // clang-format off
    static const char *ctypename[] = {
      #define FLATBUFFERS_TD(ENUM, IDLTYPE, \
              CTYPE, JTYPE, GTYPE, NTYPE, PTYPE, ...) \
        #PTYPE,
        FLATBUFFERS_GEN_TYPES(FLATBUFFERS_TD)
      #undef FLATBUFFERS_TD
    };
    // clang-format on
    return ctypename[type.base_type];
  }

  // Generate a struct field, conditioned on its child type(s).
  void GenStructAccessor(const StructDef& struct_def, const FieldDef& field,
                         std::string* code_ptr) {
    GenComment(field.doc_comment, code_ptr, nullptr, "    ");
    std::string& code = *code_ptr;
    auto offsets = NumToString(field.value.offset);
    auto def = "    def " + NormalizedName(field);
    if (IsScalar(field.value.type.base_type)) {
      std::string acc;
      if (struct_def.fixed) {
        acc = "buf_.read_" + GenTypeName(field.value.type) + "_le(pos_ + " +
              offsets + ")";

      } else {
        auto defval = field.IsOptional()
                          ? (IsFloat(field.value.type.base_type) ? "0.0" : "0")
                          : field.value.constant;
        acc = "flatbuffers.field_" + GenTypeName(field.value.type) +
              "(buf_, pos_, " + offsets + ", " + defval + ")";
        if (IsBool(field.value.type.base_type)) acc = "bool(" + acc + ")";
      }
      if (field.value.type.enum_def)
        acc = NormalizedName(*field.value.type.enum_def) + "(" + acc + ")";
      if (field.IsOptional()) {
        acc += ", flatbuffers.field_present(buf_, pos_, " + offsets + ")";
        code += def + "() -> " + LobsterType(field.value.type) +
                ", bool:\n        return " + acc + "\n";
      } else {
        code += def + "() -> " + LobsterType(field.value.type) +
                ":\n        return " + acc + "\n";
      }
      return;
    }
    switch (field.value.type.base_type) {
      case BASE_TYPE_STRUCT: {
        auto name = NamespacedName(*field.value.type.struct_def);
        if (struct_def.fixed) {
          code += def + "() -> " + name + ":\n        ";
          code += "return " + name + "{ buf_, pos_ + " + offsets + " }\n";
        } else {
          code += def + "() -> " + name;
          if (!field.IsRequired()) code += "?";
          code += ":\n        ";
          code += std::string("let o = flatbuffers.field_") +
                  (field.value.type.struct_def->fixed ? "struct" : "table") +
                  "(buf_, pos_, " + offsets + ")\n        return ";
          if (field.IsRequired()) {
            code += name + " { buf_, assert o }\n";
          } else {
            code += "if o: " + name + " { buf_, o } else: nil\n";
          }
        }
        break;
      }
      case BASE_TYPE_STRING:
        code += def +
                "() -> string:\n        return "
                "flatbuffers.field_string(buf_, pos_, " +
                offsets + ")\n";
        break;
      case BASE_TYPE_VECTOR: {
        auto vectortype = field.value.type.VectorType();
        if (vectortype.base_type == BASE_TYPE_STRUCT) {
          auto start = "flatbuffers.field_vector(buf_, pos_, " + offsets +
                       ") + i * " + NumToString(InlineSize(vectortype));
          if (!(vectortype.struct_def->fixed)) {
            start = "flatbuffers.indirect(buf_, " + start + ")";
          }
          code += def + "(i:int) -> " +
                  NamespacedName(*field.value.type.struct_def) +
                  ":\n        return ";
          code += NamespacedName(*field.value.type.struct_def) + " { buf_, " +
                  start + " }\n";
        } else {
          if (IsString(vectortype)) {
            code += def + "(i:int) -> string:\n        return ";
            code += "flatbuffers.string";
          } else {
            code += def + "(i:int) -> " + LobsterType(vectortype) +
                    ":\n        return ";
            code += "read_" + GenTypeName(vectortype) + "_le";
          }
          code += "(buf_, buf_.flatbuffers.field_vector(pos_, " + offsets +
                  ") + i * " + NumToString(InlineSize(vectortype)) + ")\n";
        }
        break;
      }
      case BASE_TYPE_UNION: {
        for (auto it = field.value.type.enum_def->Vals().begin();
             it != field.value.type.enum_def->Vals().end(); ++it) {
          auto& ev = **it;
          if (ev.IsNonZero()) {
            code += def + "_as_" + ev.name + "():\n        return " +
                    NamespacedName(*ev.union_type.struct_def) +
                    " { buf_, flatbuffers.field_table(buf_, pos_, " + offsets +
                    ") }\n";
          }
        }
        break;
      }
      default:
        FLATBUFFERS_ASSERT(0);
    }
    if (IsVector(field.value.type)) {
      code += def +
              "_length() -> int:\n        return "
              "flatbuffers.field_vector_len(buf_, pos_, " +
              offsets + ")\n";
    }
  }

  // Generate table constructors, conditioned on its members' types.
  void GenTableBuilders(const StructDef& struct_def, std::string* code_ptr) {
    std::string& code = *code_ptr;
    code += "struct " + NormalizedName(struct_def) +
            "Builder:\n    b_:flatbuffers.builder\n";
    code += "    def start():\n        b_.StartObject(" +
            NumToString(struct_def.fields.vec.size()) +
            ")\n        return this\n";
    for (auto it = struct_def.fields.vec.begin();
         it != struct_def.fields.vec.end(); ++it) {
      auto& field = **it;
      if (field.deprecated) continue;
      auto offset = it - struct_def.fields.vec.begin();
      code += "    def add_" + NormalizedName(field) + "(" +
              NormalizedName(field) + ":" + LobsterType(field.value.type) +
              "):\n        b_.Prepend" + GenMethod(field.value.type) + "Slot(" +
              NumToString(offset) + ", " + NormalizedName(field);
      if (IsScalar(field.value.type.base_type) && !field.IsOptional())
        code += ", " + field.value.constant;
      code += ")\n        return this\n";
    }
    code += "    def end():\n        return b_.EndObject()\n\n";
    for (auto it = struct_def.fields.vec.begin();
         it != struct_def.fields.vec.end(); ++it) {
      auto& field = **it;
      if (field.deprecated) continue;
      if (IsVector(field.value.type)) {
        code += "def " + NormalizedName(struct_def) + "Start" +
                ConvertCase(NormalizedName(field), Case::kUpperCamel) +
                "Vector(b_:flatbuffers.builder, n_:int):\n    b_.StartVector(";
        auto vector_type = field.value.type.VectorType();
        auto alignment = InlineAlignment(vector_type);
        auto elem_size = InlineSize(vector_type);
        code +=
            NumToString(elem_size) + ", n_, " + NumToString(alignment) + ")\n";
        if (vector_type.base_type != BASE_TYPE_STRUCT ||
            !vector_type.struct_def->fixed) {
          code += "def " + NormalizedName(struct_def) + "Create" +
                  ConvertCase(NormalizedName(field), Case::kUpperCamel) +
                  "Vector(b_:flatbuffers.builder, v_:[" +
                  LobsterType(vector_type) + "]):\n    b_.StartVector(" +
                  NumToString(elem_size) + ", v_.length, " +
                  NumToString(alignment) + ")\n    reverse(v_) e_: b_.Prepend" +
                  GenMethod(vector_type) +
                  "(e_)\n    return b_.EndVector(v_.length)\n";
        }
        code += "\n";
      }
    }
  }

  void GenStructPreDecl(const StructDef& struct_def, std::string* code_ptr) {
    if (struct_def.generated) return;
    std::string& code = *code_ptr;
    CheckNameSpace(struct_def, &code);
    code += "class " + NormalizedName(struct_def) + "\n\n";
  }

  // Generate struct or table methods.
  // The FlatbuffersEncryption helper (field-encryption format 3), private to
  // the generated file: pure Lobster AES-256 (encryption only, for CTR mode)
  // and SHA-256.
  static std::string EncryptionHelperCode() {
    std::string code;
    code += R"LOBSTER(// Field-encryption format 3: encrypts or decrypts every (encrypted) field
// instance of a buffer exactly as the C++ walker
// (flatbuffers::EncryptBuffer/DecryptBuffer, version 3) and flatc-wasm do.
// The record's key is
// K = HKDF-SHA256(key, no salt, "flatbuffers-buffer-v3" || BE32(record_index)),
// and each instance is AES-256-CTR encrypted with K and the IV
// BE32(position of its first byte in the buffer) || 12 zero bytes, so no two
// instances share a key stream. (key, record_index) must be unique per buffer.
// Generated tables call it with their walk program.

import dictionary

private let flatbuffers_encryption_sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

private let flatbuffers_encryption_k = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

private def flatbuffers_encryption_rotr(x:int, n:int) -> int:
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

private def flatbuffers_encryption_sha256(message:[int]) -> [int]:
    let h = [ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
              0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 ]
    let data = copy(message)
    data.push(0x80)
    while data.length % 64 != 56:
        data.push(0)
    let bits = message.length * 8
    for(8) i:
        data.push((bits >> (8 * (7 - i))) & 0xFF)
    let w = map(64): 0
    var chunk = 0
    while chunk < data.length:
        for(16) i:
            let j = chunk + 4 * i
            w[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | data[j + 3]
        for(48) t:
            let i = t + 16
            let s0 = flatbuffers_encryption_rotr(w[i - 15], 7) ^
                     flatbuffers_encryption_rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            let s1 = flatbuffers_encryption_rotr(w[i - 2], 17) ^
                     flatbuffers_encryption_rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF
        let v = copy(h)
        for(64) i:
            let s1 = flatbuffers_encryption_rotr(v[4], 6) ^ flatbuffers_encryption_rotr(v[4], 11) ^
                     flatbuffers_encryption_rotr(v[4], 25)
            let ch = (v[4] & v[5]) ^ ((v[4] ^ 0xFFFFFFFF) & v[6])
            let t1 = (v[7] + s1 + ch + flatbuffers_encryption_k[i] + w[i]) & 0xFFFFFFFF
            let s0 = flatbuffers_encryption_rotr(v[0], 2) ^ flatbuffers_encryption_rotr(v[0], 13) ^
                     flatbuffers_encryption_rotr(v[0], 22)
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2])
            v[7] = v[6]
            v[6] = v[5]
            v[5] = v[4]
            v[4] = (v[3] + t1) & 0xFFFFFFFF
            v[3] = v[2]
            v[2] = v[1]
            v[1] = v[0]
            v[0] = (t1 + s0 + maj) & 0xFFFFFFFF
        for(8) i:
            h[i] = (h[i] + v[i]) & 0xFFFFFFFF
        chunk += 64
    let out:[int] = []
    for(h) value:
        out.push((value >> 24) & 0xFF)
        out.push((value >> 16) & 0xFF)
        out.push((value >> 8) & 0xFF)
        out.push(value & 0xFF)
    return out

private def flatbuffers_encryption_hmac(key:[int], message:[int]) -> [int]:
    let inner:[int] = []
    let outer:[int] = []
    for(64) i:
        let k = if i < key.length: key[i] else: 0
        inner.push(k ^ 0x36)
        outer.push(k ^ 0x5c)
    for(message) b:
        inner.push(b)
    for(flatbuffers_encryption_sha256(inner)) b:
        outer.push(b)
    return flatbuffers_encryption_sha256(outer)

private def flatbuffers_encryption_bytes(s:string) -> [int]:
    return map(s.length) i: s.read_uint8_le(i)

// HKDF-SHA256(key, no salt, "flatbuffers-buffer-v3" || BE32(record_index)).
private def flatbuffers_encryption_buffer_key(key:string, record_index:int) -> [int]:
    let prk = flatbuffers_encryption_hmac(map(32): 0, flatbuffers_encryption_bytes(key))
    let info = flatbuffers_encryption_bytes("flatbuffers-buffer-v3")
    info.push((record_index >> 24) & 0xFF)
    info.push((record_index >> 16) & 0xFF)
    info.push((record_index >> 8) & 0xFF)
    info.push(record_index & 0xFF)
    info.push(1)
    return flatbuffers_encryption_hmac(prk, info)

private def flatbuffers_encryption_xtime(a:int) -> int:
    return ((a << 1) ^ (if a & 0x80: 0x1b else: 0)) & 0xFF

private def flatbuffers_encryption_expand_key(key:[int]) -> [int]:
    let w = copy(key)
    var rcon = 1
    while w.length < 240:
        let i = w.length
        var t0 = w[i - 4]
        var t1 = w[i - 3]
        var t2 = w[i - 2]
        var t3 = w[i - 1]
        if i % 32 == 0:
            let r0 = flatbuffers_encryption_sbox[t1] ^ rcon
            t1 = flatbuffers_encryption_sbox[t2]
            t2 = flatbuffers_encryption_sbox[t3]
            t3 = flatbuffers_encryption_sbox[t0]
            t0 = r0
            rcon = flatbuffers_encryption_xtime(rcon)
        elif i % 32 == 16:
            t0 = flatbuffers_encryption_sbox[t0]
            t1 = flatbuffers_encryption_sbox[t1]
            t2 = flatbuffers_encryption_sbox[t2]
            t3 = flatbuffers_encryption_sbox[t3]
        w.push(w[i - 32] ^ t0)
        w.push(w[i - 31] ^ t1)
        w.push(w[i - 30] ^ t2)
        w.push(w[i - 29] ^ t3)
    return w

private def flatbuffers_encryption_encrypt_block(w:[int], block:[int]) -> [int]:
    var s = map(16) i: block[i] ^ w[i]
    for(14) r:
        let round = r + 1
        let t = map(s) b: flatbuffers_encryption_sbox[b]
        s = [ t[0], t[5], t[10], t[15], t[4], t[9], t[14], t[3],
              t[8], t[13], t[2], t[7], t[12], t[1], t[6], t[11] ]
        if round < 14:
            for(4) column:
                let c = column * 4
                let a0 = s[c]
                let a1 = s[c + 1]
                let a2 = s[c + 2]
                let a3 = s[c + 3]
                let x = a0 ^ a1 ^ a2 ^ a3
                s[c] = a0 ^ x ^ flatbuffers_encryption_xtime(a0 ^ a1)
                s[c + 1] = a1 ^ x ^ flatbuffers_encryption_xtime(a1 ^ a2)
                s[c + 2] = a2 ^ x ^ flatbuffers_encryption_xtime(a2 ^ a3)
                s[c + 3] = a3 ^ x ^ flatbuffers_encryption_xtime(a3 ^ a0)
        for(16) i:
            s[i] = s[i] ^ w[16 * round + i]
    return s

private def flatbuffers_encryption_guard(body) -> string?:
    body()
    return nil

private def flatbuffers_encryption_fail(what:string):
    return "FlatbuffersEncryption: " + what from flatbuffers_encryption_guard

private class flatbuffers_encryption_walk:
    buf:string
    walk_program:[int]
    round_keys:[int]?  // nil: a dry run that only checks the buffer
    tables:dictionary<int, bool>
    regions:dictionary<int, bool>

)LOBSTER";
    code += R"LOBSTER(    def check(pos:int, length:int):
        if pos < 0 or length < 0 or pos > buf.length or length > buf.length - pos:
            flatbuffers_encryption_fail("the buffer is malformed (offset " + string(pos) +
                                        " out of bounds)")

    def u8(pos:int) -> int:
        check(pos, 1)
        return buf.read_uint8_le(pos)

    def u16(pos:int) -> int:
        check(pos, 2)
        return buf.read_uint16_le(pos)

    def u32(pos:int) -> int:
        check(pos, 4)
        return buf.read_uint32_le(pos)

    def follow(pos:int) -> int:
        let target = pos + u32(pos)
        check(target, 4)
        return target

    def count(pos:int, element_size:int) -> int:
        let n = u32(pos)
        check(pos + 4, n * element_size)
        return n

    def crypt(start:int, length:int):
        if length == 0 or regions.get(start, false):
            return
        regions.set(start, true)
        let w = round_keys
        if not w:
            return
        let counter = map(16): 0
        counter[0] = (start >> 24) & 0xFF
        counter[1] = (start >> 16) & 0xFF
        counter[2] = (start >> 8) & 0xFF
        counter[3] = start & 0xFF
        var done = 0
        while done < length:
            let stream = flatbuffers_encryption_encrypt_block(w, counter)
            for(16) i:
                if done + i < length:
                    let at = start + done + i
                    buf.write_int8_le(at, buf.read_uint8_le(at) ^ stream[i])
            var k = 15
            while k >= 0:
                counter[k] = (counter[k] + 1) & 0xFF
                k = if counter[k] != 0: -1 else: k - 1
            done += 16

    def string_bytes(pos:int):
        let s = follow(pos)
        let n = u32(s)
        check(s + 4, n + 1)
        crypt(s + 4, n)

    def vtable(table:int) -> int:
        let soffset = u32(table)
        return table - (if soffset >= 0x80000000: soffset - 0x100000000 else: soffset)

    def field(table:int, slot:int) -> int:
        let vt = vtable(table)
        if slot + 2 > u16(vt):
            return 0
        let offset = u16(vt + slot)
        return if offset == 0: 0 else: table + offset

    def enter(table:int, depth:int) -> bool:
        if depth > 64:
            flatbuffers_encryption_fail("tables nested deeper than 64 levels")
        if tables.get(table, false):
            return false
        tables.set(table, true)
        let vt = vtable(table)
        check(vt, 4)
        let vtable_size = u16(vt)
        let table_size = u16(vt + 2)
        if vtable_size < 4 or (vtable_size & 1) != 0:
            flatbuffers_encryption_fail("the buffer is malformed (bad vtable)")
        check(vt, vtable_size)
        check(table, table_size)
        var slot = 4
        while slot < vtable_size:
            let offset = u16(vt + slot)
            if offset != 0 and offset >= table_size:
                flatbuffers_encryption_fail("the buffer is malformed (bad field offset)")
            slot += 2
        return true

)LOBSTER";
    code += R"LOBSTER(    def union_member(at:int, n:int, union_type:int) -> int:
        for(n) i:
            if walk_program[at + 2 * i] == union_type:
                return walk_program[at + 2 * i + 1]
        return -1

    def walk(index:int, table:int, depth:int) -> void:
        if not enter(table, depth):
            return
        let p = walk_program
        var at = p[1 + index]
        let ops = p[at]
        at += 1
        for(ops):
            let kind = p[at]
            let slot = p[at + 1]
            at += 2
            var arg = 0
            var type_slot = 0
            var members = 0
            var n = 0
            if kind == 0 or kind == 2 or kind == 4 or kind == 5:
                arg = p[at]
                at += 1
            elif kind == 6 or kind == 7:
                type_slot = p[at]
                n = p[at + 1]
                members = at + 2
                at += 2 + 2 * n
            let loc = field(table, slot)
            if loc != 0:
                if kind == 0:
                    check(loc, arg)
                    crypt(loc, arg)
                elif kind == 1:
                    string_bytes(loc)
                elif kind == 2:
                    let v = follow(loc)
                    crypt(v + 4, count(v, arg) * arg)
                elif kind == 3:
                    let v = follow(loc)
                    for(count(v, 4)) i:
                        string_bytes(v + 4 + 4 * i)
                elif kind == 4:
                    walk(arg, follow(loc), depth + 1)
                elif kind == 5:
                    let v = follow(loc)
                    for(count(v, 4)) i:
                        walk(arg, follow(v + 4 + 4 * i), depth + 1)
                elif kind == 6:
                    let type_loc = field(table, type_slot)
                    if type_loc != 0:
                        let m = union_member(members, n, u8(type_loc))
                        if m >= 0:
                            walk(m, follow(loc), depth + 1)
                elif kind == 7:
                    let type_loc = field(table, type_slot)
                    if type_loc != 0:
                        let types = follow(type_loc)
                        let c = count(types, 1)
                        let values = follow(loc)
                        if count(values, 4) != c:
                            flatbuffers_encryption_fail("the buffer is malformed (union vectors differ)")
                        for(c) i:
                            let m = union_member(members, n, u8(types + 4 + i))
                            if m >= 0:
                                walk(m, follow(values + 4 + 4 * i), depth + 1)
                else:
                    flatbuffers_encryption_fail("unknown walk walk_program op " + string(kind))

// Returns a copy of buf with every (encrypted) field instance encrypted, or
// decrypted (the same operation), by a table's walk walk_program, and "". For a
// bad key or a malformed buffer, returns nil and why.
private def flatbuffers_encryption_crypt_buffer(buf:string, key:string, record_index:int,
                                                walk_program:[int]) -> string?, string:
    if key.length != 32:
        return nil, "FlatbuffersEncryption: the key must be 32 bytes"
    if record_index < 0 or record_index > 0xFFFFFFFF:
        return nil, "FlatbuffersEncryption: record_index must fit in 32 bits"
    if buf.length < 4 or buf.length > 0x7FFFFFFF:
        return nil, "FlatbuffersEncryption: invalid buffer"
    let out = copy(buf)
    let err = flatbuffers_encryption_guard():
        let dry = flatbuffers_encryption_walk { out, walk_program, nil, dictionary<int, bool>(67),
                                                dictionary<int, bool>(67) }
        let root = dry.u32(0)
        dry.check(root, 4)
        dry.walk(0, root, 0)
        let round_keys = flatbuffers_encryption_expand_key(
            flatbuffers_encryption_buffer_key(key, record_index))
        let w = flatbuffers_encryption_walk { out, walk_program, round_keys, dictionary<int, bool>(67),
                                              dictionary<int, bool>(67) }
        w.walk(0, root, 0)
    if err:
        return nil, err
    return out, ""


)LOBSTER";
    return code;
  }

  // EncryptXBuffer/DecryptXBuffer of a table that reaches an (encrypted)
  // field.
  void GenEncryptionFunctions(const StructDef& struct_def,
                              std::string* code_ptr) const {
    std::string& code = *code_ptr;
    const std::string name = NormalizedName(struct_def);
    const std::string program = "flatbuffers_encryption_program_" + name;
    code += "// Field-encryption format 3 walk program of " + name +
            " (see the FlatbuffersEncryption helper above).\n";
    code += "private let " + program + " = [\n";
    for (const auto& line : encryption_plan_.ProgramLines(struct_def)) {
      code += "    " + line + "\n";
    }
    code += "]\n\n";
    const char* kVerbs[] = { "Encrypt", "Decrypt" };
    const char* kParticiples[] = { "encrypted", "decrypted" };
    for (int i = 0; i < 2; i++) {
      code += "// Returns a copy of a " + name +
              " buffer with its (encrypted) fields " + kParticiples[i] +
              " with\n";
      code += "// field-encryption format 3 (key: 32 bytes; record_index: "
              "unique per buffer\n";
      code += "// under the key), and \"\". For a bad key or a malformed "
              "buffer, returns nil and why.\n";
      code += "def " + std::string(kVerbs[i]) + name +
              "Buffer(buf:string, key:string, record_index:int) -> string?, "
              "string:\n";
      code += "    return flatbuffers_encryption_crypt_buffer(buf, key, "
              "record_index, " + program + ")\n\n";
    }
  }

  void GenStruct(const StructDef& struct_def, std::string* code_ptr) {
    if (struct_def.generated) return;
    std::string& code = *code_ptr;
    CheckNameSpace(struct_def, &code);
    GenComment(struct_def.doc_comment, code_ptr, nullptr, "");
    code += "class " + NormalizedName(struct_def) + " : flatbuffers.handle\n";
    for (auto it = struct_def.fields.vec.begin();
         it != struct_def.fields.vec.end(); ++it) {
      auto& field = **it;
      if (field.deprecated) continue;
      GenStructAccessor(struct_def, field, code_ptr);
    }
    code += "\n";
    if (!struct_def.fixed) {
      // Generate a special accessor for the table that has been declared as
      // the root type.
      code += "def GetRootAs" + NormalizedName(struct_def) +
              "(buf:string): return " + NormalizedName(struct_def) +
              " { buf, flatbuffers.indirect(buf, 0) }\n\n";
      if (encryption_plan_.NeedsWalk(struct_def)) {
        GenEncryptionFunctions(struct_def, code_ptr);
      }
    }
    if (struct_def.fixed) {
      // create a struct constructor function
      GenStructBuilder(struct_def, code_ptr);
    } else {
      // Create a set of functions that allow table construction.
      GenTableBuilders(struct_def, code_ptr);
    }
  }

  // Generate enum declarations.
  void GenEnum(const EnumDef& enum_def, std::string* code_ptr) {
    if (enum_def.generated) return;
    std::string& code = *code_ptr;
    CheckNameSpace(enum_def, &code);
    GenComment(enum_def.doc_comment, code_ptr, nullptr, "");
    code += "enum " + NormalizedName(enum_def) + ":\n";
    for (auto it = enum_def.Vals().begin(); it != enum_def.Vals().end(); ++it) {
      auto& ev = **it;
      GenComment(ev.doc_comment, code_ptr, nullptr, "    ");
      code += "    " + enum_def.name + "_" + NormalizedName(ev) + " = " +
              enum_def.ToString(ev) + "\n";
    }
    code += "\n";
  }

  // Recursively generate arguments for a constructor, to deal with nested
  // structs.
  void StructBuilderArgs(const StructDef& struct_def, const char* nameprefix,
                         std::string* code_ptr) {
    for (auto it = struct_def.fields.vec.begin();
         it != struct_def.fields.vec.end(); ++it) {
      auto& field = **it;
      if (IsStruct(field.value.type)) {
        // Generate arguments for a struct inside a struct. To ensure names
        // don't clash, and to make it obvious these arguments are constructing
        // a nested struct, prefix the name with the field name.
        StructBuilderArgs(*field.value.type.struct_def,
                          (nameprefix + (NormalizedName(field) + "_")).c_str(),
                          code_ptr);
      } else {
        std::string& code = *code_ptr;
        code += ", " + (nameprefix + NormalizedName(field)) + ":" +
                LobsterType(field.value.type);
      }
    }
  }

  // Recursively generate struct construction statements and instert manual
  // padding.
  void StructBuilderBody(const StructDef& struct_def, const char* nameprefix,
                         std::string* code_ptr) {
    std::string& code = *code_ptr;
    code += "    b_.Prep(" + NumToString(struct_def.minalign) + ", " +
            NumToString(struct_def.bytesize) + ")\n";
    for (auto it = struct_def.fields.vec.rbegin();
         it != struct_def.fields.vec.rend(); ++it) {
      auto& field = **it;
      if (field.padding)
        code += "    b_.Pad(" + NumToString(field.padding) + ")\n";
      if (IsStruct(field.value.type)) {
        StructBuilderBody(*field.value.type.struct_def,
                          (nameprefix + (NormalizedName(field) + "_")).c_str(),
                          code_ptr);
      } else {
        code += "    b_.Prepend" + GenMethod(field.value.type) + "(" +
                nameprefix + NormalizedName(field) + ")\n";
      }
    }
  }

  // Create a struct with a builder and the struct's arguments.
  void GenStructBuilder(const StructDef& struct_def, std::string* code_ptr) {
    std::string& code = *code_ptr;
    code +=
        "def Create" + NormalizedName(struct_def) + "(b_:flatbuffers.builder";
    StructBuilderArgs(struct_def, "", code_ptr);
    code += "):\n";
    StructBuilderBody(struct_def, "", code_ptr);
    code += "    return b_.Offset()\n\n";
  }

  void CheckNameSpace(const Definition& def, std::string* code_ptr) {
    auto ns = GetNameSpace(def);
    if (ns == current_namespace_) return;
    current_namespace_ = ns;
    std::string& code = *code_ptr;
    code += "namespace " + ns + "\n\n";
  }

  bool generate() {
    std::string code;
    code += std::string("// ") + FlatBuffersGeneratedWarning() +
            "\nimport flatbuffers\n\n";
    if (encryption_plan_.AnyGenerated()) code += EncryptionHelperCode();
    for (auto it = parser_.enums_.vec.begin(); it != parser_.enums_.vec.end();
         ++it) {
      auto& enum_def = **it;
      GenEnum(enum_def, &code);
    }
    for (auto it = parser_.structs_.vec.begin();
         it != parser_.structs_.vec.end(); ++it) {
      auto& struct_def = **it;
      GenStructPreDecl(struct_def, &code);
    }
    for (auto it = parser_.structs_.vec.begin();
         it != parser_.structs_.vec.end(); ++it) {
      auto& struct_def = **it;
      GenStruct(struct_def, &code);
    }
    return parser_.opts.file_saver->SaveFile(
        GeneratedFileName(path_, file_name_, parser_.opts).c_str(), code,
        false);
  }

 private:
  std::unordered_set<std::string> keywords_;
  std::string current_namespace_;
  const encryption_codegen::Plan encryption_plan_;
};

}  // namespace lobster

static bool GenerateLobster(const Parser& parser, const std::string& path,
                            const std::string& file_name) {
  lobster::LobsterGenerator generator(parser, path, file_name);
  return generator.generate();
}

namespace {

class LobsterCodeGenerator : public CodeGenerator {
 public:
  Status GenerateCode(const Parser& parser, const std::string& path,
                      const std::string& filename) override {
    const encryption_codegen::Plan plan(parser);
    if (!plan.ok()) {
      status_detail = ": " + plan.error();
      return Status::ERROR;
    }
    if (!GenerateLobster(parser, path, filename)) {
      return Status::ERROR;
    }
    return Status::OK;
  }

  Status GenerateCode(const uint8_t*, int64_t, const CodeGenOptions&) override {
    return Status::NOT_IMPLEMENTED;
  }

  Status GenerateMakeRule(const Parser& parser, const std::string& path,
                          const std::string& filename,
                          std::string& output) override {
    (void)parser;
    (void)path;
    (void)filename;
    (void)output;
    return Status::NOT_IMPLEMENTED;
  }

  Status GenerateGrpcCode(const Parser& parser, const std::string& path,
                          const std::string& filename) override {
    (void)parser;
    (void)path;
    (void)filename;
    return Status::NOT_IMPLEMENTED;
  }

  Status GenerateRootFile(const Parser& parser,
                          const std::string& path) override {
    (void)parser;
    (void)path;
    return Status::NOT_IMPLEMENTED;
  }

  bool IsSchemaOnly() const override { return true; }

  bool SupportsBfbsGeneration() const override { return false; }

  bool SupportsRootFileGeneration() const override { return false; }

  IDLOptions::Language Language() const override {
    return IDLOptions::kLobster;
  }

  std::string LanguageName() const override { return "Lobster"; }
};
}  // namespace

std::unique_ptr<CodeGenerator> NewLobsterCodeGenerator() {
  return std::unique_ptr<LobsterCodeGenerator>(new LobsterCodeGenerator());
}

}  // namespace flatbuffers
