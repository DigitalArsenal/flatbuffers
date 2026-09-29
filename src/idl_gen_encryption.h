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
//   op:          kind, slot, operands (see OpKind)

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "flatbuffers/idl.h"
#include "flatbuffers/util.h"

namespace flatbuffers {
namespace encryption_codegen {

// Op kinds of a walk program. Keep in sync with every generated helper.
enum OpKind {
  kOpBytes = 0,        // slot, size: a scalar or a struct, in place
  kOpString = 1,       // slot: the bytes of a string
  kOpVector = 2,       // slot, element size: the elements of a vector
  kOpStringVector = 3, // slot: the bytes of each string of a vector
  kOpTable = 4,        // slot, table index: walk a table
  kOpTableVector = 5,  // slot, table index: walk each table of a vector
  kOpUnion = 6,        // slot, type slot, n, n x (type, table index)
  kOpUnionVector = 7,  // slot, type slot, n, n x (type, table index)
};

inline bool IsEncrypted(const FieldDef& field) {
  return field.attributes.Lookup("encrypted") != nullptr;
}

// Byte size of a scalar format 3 encrypts, or 0.
inline size_t ScalarSize(BaseType type) {
  switch (type) {
    case BASE_TYPE_BOOL:
    case BASE_TYPE_CHAR:
    case BASE_TYPE_UCHAR: return 1;
    case BASE_TYPE_SHORT:
    case BASE_TYPE_USHORT: return 2;
    case BASE_TYPE_INT:
    case BASE_TYPE_UINT:
    case BASE_TYPE_FLOAT: return 4;
    case BASE_TYPE_LONG:
    case BASE_TYPE_ULONG:
    case BASE_TYPE_DOUBLE: return 8;
    default: return 0;
  }
}

inline bool IsTableStruct(const StructDef* def) {
  return def != nullptr && !def->fixed;
}

inline bool IsFixedStruct(const StructDef* def) {
  return def != nullptr && def->fixed;
}

// Fields in the order the C++ walker visits them: reflection sorts an
// object's fields by name.
inline std::vector<const FieldDef*> FieldsByName(const StructDef& def) {
  std::vector<const FieldDef*> fields(def.fields.vec.begin(),
                                      def.fields.vec.end());
  std::stable_sort(fields.begin(), fields.end(),
                   [](const FieldDef* a, const FieldDef* b) {
                     return a->name < b->name;
                   });
  return fields;
}

// True when a struct (or a struct nested in it) marks its own fields
// (encrypted). Format 3 encrypts a struct only as a whole.
inline bool StructHasEncryptedField(const StructDef& def, int depth = 0) {
  if (depth > 64) return false;
  for (auto field : def.fields.vec) {
    if (IsEncrypted(*field)) return true;
    const Type& type = field->value.type;
    const StructDef* nested = nullptr;
    if (type.base_type == BASE_TYPE_STRUCT) nested = type.struct_def;
    if (IsArray(type) && type.element == BASE_TYPE_STRUCT) {
      nested = type.struct_def;
    }
    if (IsFixedStruct(nested) &&
        StructHasEncryptedField(*nested, depth + 1)) {
      return true;
    }
  }
  return false;
}

struct UnionMember {
  int64_t type;
  const StructDef* table;
};

struct Op {
  OpKind kind;
  const FieldDef* field;
  size_t size;               // kOpBytes: bytes; kOpVector: element size
  const StructDef* table;    // kOpTable, kOpTableVector
  const FieldDef* type_field;  // kOpUnion, kOpUnionVector
  std::vector<UnionMember> members;  // kOpUnion, kOpUnionVector
};

// Which tables need walking, their ops, and the schema checks, for one
// parsed schema.
class Plan {
 public:
  explicit Plan(const Parser& parser) : parser_(parser) {
    Validate();
    if (!ok()) return;
    // A table needs walking when it has an (encrypted) field or reaches a
    // table that does. Iterate to a fixed point (schemas may be recursive).
    bool changed = true;
    while (changed) {
      changed = false;
      for (auto def : parser_.structs_.vec) {
        if (def->fixed || needs_.count(def)) continue;
        if (ComputeNeeds(*def)) {
          needs_.insert(def);
          changed = true;
        }
      }
    }
    for (auto def : parser_.structs_.vec) {
      if (NeedsWalk(*def)) ops_[def] = BuildOps(*def);
    }
  }

  bool ok() const { return error_.empty(); }
  const std::string& error() const { return error_; }

  bool NeedsWalk(const StructDef& def) const {
    return needs_.count(&def) != 0;
  }

  // True when a table of this namespace (defined in the file being
  // generated) needs walking, so the namespace needs a helper.
  bool NamespaceNeedsHelper(const Namespace* ns) const {
    for (auto def : parser_.structs_.vec) {
      if (!def->generated && def->defined_namespace == ns && NeedsWalk(*def)) {
        return true;
      }
    }
    return false;
  }

  // True when a table defined in the file being generated needs walking.
  bool AnyGenerated() const {
    for (auto def : parser_.structs_.vec) {
      if (!def->generated && NeedsWalk(*def)) return true;
    }
    return false;
  }

  // True when any table of the schema, included ones too, needs walking.
  bool Any() const { return !needs_.empty(); }

  const std::vector<Op>& Ops(const StructDef& def) const {
    static const std::vector<Op> kNone;
    auto it = ops_.find(&def);
    return it == ops_.end() ? kNone : it->second;
  }

  // The walk program of `root` (see the layout above).
  std::vector<int64_t> Program(const StructDef& root) const {
    std::vector<const StructDef*> order;
    std::map<const StructDef*, int64_t> index;
    order.push_back(&root);
    index[&root] = 0;
    for (size_t i = 0; i < order.size(); i++) {
      for (const auto& op : Ops(*order[i])) {
        std::vector<const StructDef*> targets;
        if (op.table) targets.push_back(op.table);
        for (const auto& m : op.members) targets.push_back(m.table);
        for (auto target : targets) {
          if (index.count(target)) continue;
          index[target] = static_cast<int64_t>(order.size());
          order.push_back(target);
        }
      }
    }
    std::vector<int64_t> program;
    program.push_back(static_cast<int64_t>(order.size()));
    program.resize(1 + order.size());
    for (size_t i = 0; i < order.size(); i++) {
      program[1 + i] = static_cast<int64_t>(program.size());
      const auto& ops = Ops(*order[i]);
      program.push_back(static_cast<int64_t>(ops.size()));
      for (const auto& op : ops) {
        program.push_back(op.kind);
        program.push_back(op.field->value.offset);
        switch (op.kind) {
          case kOpBytes:
          case kOpVector:
            program.push_back(static_cast<int64_t>(op.size));
            break;
          case kOpString:
          case kOpStringVector: break;
          case kOpTable:
          case kOpTableVector: program.push_back(index[op.table]); break;
          case kOpUnion:
          case kOpUnionVector:
            program.push_back(op.type_field->value.offset);
            program.push_back(static_cast<int64_t>(op.members.size()));
            for (const auto& m : op.members) {
              program.push_back(m.type);
              program.push_back(index[m.table]);
            }
            break;
        }
      }
    }
    return program;
  }

  // The program as a comma-separated list of integers.
  std::string ProgramText(const StructDef& root) const {
    std::string text;
    for (auto value : Program(root)) {
      if (!text.empty()) text += ", ";
      text += NumToString(value);
    }
    return text;
  }

  // The program as comma-separated lines of at most `per_line` integers,
  // each line but the last ending with a comma.
  std::vector<std::string> ProgramLines(const StructDef& root,
                                        size_t per_line = 16) const {
    std::vector<std::string> lines;
    const auto program = Program(root);
    for (size_t i = 0; i < program.size(); i += per_line) {
      std::string line;
      for (size_t j = i; j < program.size() && j < i + per_line; j++) {
        if (j > i) line += ", ";
        line += NumToString(program[j]);
      }
      if (i + per_line < program.size()) line += ",";
      lines.push_back(line);
    }
    return lines;
  }

 private:
  static std::string Name(const StructDef& def, const FieldDef& field) {
    return def.name + "." + field.name;
  }

  void Refuse(const StructDef& def, const FieldDef& field,
              const std::string& reason) {
    if (error_.empty()) error_ = "field " + Name(def, field) + ": " + reason;
  }

  // Mirrors CheckEncryptable/ValidateObject in src/encryption.cpp for every
  // table, so a schema the format cannot encrypt is refused at generation
  // time instead of leaving a field in plaintext.
  void Validate() {
    for (auto def : parser_.structs_.vec) {
      if (def->fixed) continue;
      for (auto field : def->fields.vec) {
        const Type& type = field->value.type;
        if (IsEncrypted(*field)) {
          CheckEncryptable(*def, *field);
          continue;
        }
        if ((type.base_type == BASE_TYPE_STRUCT ||
             (IsVector(type) && type.element == BASE_TYPE_STRUCT)) &&
            IsFixedStruct(type.struct_def) &&
            StructHasEncryptedField(*type.struct_def)) {
          Refuse(*def, *field,
                 "its struct marks fields (encrypted) one by one, which is "
                 "not supported; mark the struct-typed field (encrypted) to "
                 "encrypt the whole struct");
          continue;
        }
        if (type.enum_def && type.enum_def->is_union &&
            (type.base_type == BASE_TYPE_UNION ||
             (IsVector(type) && type.element == BASE_TYPE_UNION))) {
          for (auto val : type.enum_def->Vals()) {
            const StructDef* member = val->union_type.struct_def;
            if (val->union_type.base_type == BASE_TYPE_STRUCT &&
                IsFixedStruct(member) && StructHasEncryptedField(*member)) {
              Refuse(*def, *field,
                     "a union member struct marks fields (encrypted), which "
                     "is not supported");
            }
          }
        }
      }
    }
  }

  void CheckEncryptable(const StructDef& def, const FieldDef& field) {
    const Type& type = field.value.type;
    if (field.offset64) {
      Refuse(def, field,
             "(encrypted) on a field with 64-bit offsets is not supported");
      return;
    }
    if (ScalarSize(type.base_type) > 0 || IsString(type)) return;
    if (type.base_type == BASE_TYPE_STRUCT) {
      if (IsFixedStruct(type.struct_def)) return;
      Refuse(def, field,
             "(encrypted) on a table is not supported: its offsets must stay "
             "readable; mark the fields inside the table (encrypted)");
      return;
    }
    if (IsVector(type)) {
      const BaseType element = type.element;
      if (ScalarSize(element) > 0 || element == BASE_TYPE_STRING) return;
      if (element == BASE_TYPE_STRUCT) {
        if (IsFixedStruct(type.struct_def)) return;
        Refuse(def, field,
               "(encrypted) on a vector of tables is not supported: its "
               "offsets must stay readable; mark the fields inside the table "
               "(encrypted)");
        return;
      }
      Refuse(def, field,
             "(encrypted) on a vector of unions is not supported; mark the "
             "fields inside the member tables (encrypted)");
      return;
    }
    if (type.base_type == BASE_TYPE_UTYPE) {
      Refuse(def, field,
             "(encrypted) on a union type field is not supported: the type "
             "selects how the value is read");
      return;
    }
    if (type.base_type == BASE_TYPE_UNION) {
      Refuse(def, field,
             "(encrypted) on a union is not supported; mark the fields inside "
             "the member tables (encrypted)");
      return;
    }
    Refuse(def, field, "(encrypted) is not supported on this field type");
  }

  std::vector<UnionMember> WalkedMembers(const EnumDef& union_def) const {
    std::vector<UnionMember> members;
    for (auto val : union_def.Vals()) {
      if (val->IsZero()) continue;
      const StructDef* member = val->union_type.struct_def;
      if (val->union_type.base_type != BASE_TYPE_STRUCT ||
          !IsTableStruct(member) || !NeedsWalk(*member)) {
        continue;
      }
      members.push_back(UnionMember{ val->GetAsInt64(), member });
    }
    return members;
  }

  bool ComputeNeeds(const StructDef& def) const {
    for (auto field : def.fields.vec) {
      const Type& type = field->value.type;
      if (IsEncrypted(*field)) return true;
      if (type.base_type == BASE_TYPE_STRUCT &&
          IsTableStruct(type.struct_def) && NeedsWalk(*type.struct_def)) {
        return true;
      }
      if (IsVector(type) && type.element == BASE_TYPE_STRUCT &&
          IsTableStruct(type.struct_def) && NeedsWalk(*type.struct_def)) {
        return true;
      }
      if ((type.base_type == BASE_TYPE_UNION ||
           (IsVector(type) && type.element == BASE_TYPE_UNION)) &&
          type.enum_def && !WalkedMembers(*type.enum_def).empty()) {
        return true;
      }
    }
    return false;
  }

  std::vector<Op> BuildOps(const StructDef& def) const {
    std::vector<Op> ops;
    for (auto field : FieldsByName(def)) {
      const Type& type = field->value.type;
      Op op{ kOpBytes, field, 0, nullptr, nullptr, {} };
      if (IsEncrypted(*field)) {
        if (ScalarSize(type.base_type) > 0) {
          op.size = ScalarSize(type.base_type);
        } else if (IsString(type)) {
          op.kind = kOpString;
        } else if (type.base_type == BASE_TYPE_STRUCT) {
          op.size = type.struct_def->bytesize;
        } else if (type.element == BASE_TYPE_STRING) {
          op.kind = kOpStringVector;
        } else {
          op.kind = kOpVector;
          op.size = type.element == BASE_TYPE_STRUCT
                        ? type.struct_def->bytesize
                        : ScalarSize(type.element);
        }
        ops.push_back(op);
        continue;
      }
      if (field->offset64) continue;
      if (type.base_type == BASE_TYPE_STRUCT &&
          IsTableStruct(type.struct_def) && NeedsWalk(*type.struct_def)) {
        op.kind = kOpTable;
        op.table = type.struct_def;
        ops.push_back(op);
      } else if (IsVector(type) && type.element == BASE_TYPE_STRUCT &&
                 IsTableStruct(type.struct_def) &&
                 NeedsWalk(*type.struct_def)) {
        op.kind = kOpTableVector;
        op.table = type.struct_def;
        ops.push_back(op);
      } else if ((type.base_type == BASE_TYPE_UNION ||
                  (IsVector(type) && type.element == BASE_TYPE_UNION)) &&
                 type.enum_def && field->sibling_union_field) {
        op.members = WalkedMembers(*type.enum_def);
        if (op.members.empty()) continue;
        op.kind = type.base_type == BASE_TYPE_UNION ? kOpUnion : kOpUnionVector;
        op.type_field = field->sibling_union_field;
        ops.push_back(op);
      }
    }
    return ops;
  }

  const Parser& parser_;
  std::string error_;
  std::set<const StructDef*> needs_;
  std::map<const StructDef*, std::vector<Op>> ops_;
};

// For generators without a FlatbuffersEncryption helper whose accessors used
// to call a decrypt helper for (encrypted) scalar and string fields (one that
// never worked): refuses such a schema instead of generating readers that
// return ciphertext silently. Returns the error, or "".
inline std::string RefuseEncryptedAccessors(const Parser& parser,
                                            const std::string& language) {
  for (auto def : parser.structs_.vec) {
    if (def->fixed || def->generated) continue;
    for (auto field : def->fields.vec) {
      if (!IsEncrypted(*field) || field->deprecated) continue;
      const Type& type = field->value.type;
      if (ScalarSize(type.base_type) > 0 || IsString(type)) {
        return "field " + def->name + "." + field->name +
               " is (encrypted), and the " + language +
               " generator has no field decryption. Generate a language with "
               "a FlatbuffersEncryption helper (field-encryption format 3: "
               "C#, Dart, Go, Java, Kotlin, Lobster, PHP, Python, Rust, "
               "Swift), or "
               "decrypt buffers with flatbuffers::DecryptBuffer or flatc-wasm "
               "and generate " + language +
               " code from a copy of the schema without (encrypted)";
      }
    }
  }
  return "";
}

}  // namespace encryption_codegen
}  // namespace flatbuffers

#endif  // FLATBUFFERS_IDL_GEN_ENCRYPTION_H_
