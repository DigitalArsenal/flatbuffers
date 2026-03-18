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

#include "idl_gen_aligned.h"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "aligned_compiler.h"
#include "flatbuffers/code_generators.h"
#include "flatbuffers/idl.h"

namespace flatbuffers {

namespace aligned {

namespace {

std::string CppNamespacePrefix(const StructDef& def) {
  if (!def.defined_namespace || def.defined_namespace->components.empty()) {
    return "::Aligned::";
  }
  std::string result = "::";
  for (size_t i = 0; i < def.defined_namespace->components.size(); ++i) {
    if (i) { result += "::"; }
    result += def.defined_namespace->components[i];
  }
  result += "::Aligned::";
  return result;
}

std::string CppQualifiedRecordName(const RecordLayout& record) {
  return CppNamespacePrefix(*record.def) + record.name;
}

std::string TsIdentifier(const std::string& value) {
  std::string result;
  result.reserve(value.size());
  for (size_t i = 0; i < value.size(); ++i) {
    const char c = value[i];
    result += std::isalnum(static_cast<unsigned char>(c)) ? c : '_';
  }
  return result;
}

std::string CppScalarType(const InlineLayout& layout) {
  if (layout.enum_def && layout.kind == InlineLayout::Kind::kScalar &&
      layout.base_type != BASE_TYPE_UTYPE) {
    return layout.enum_def->name;
  }
  switch (layout.base_type) {
    case BASE_TYPE_BOOL: return "bool";
    case BASE_TYPE_CHAR: return "int8_t";
    case BASE_TYPE_UCHAR:
    case BASE_TYPE_UTYPE: return "uint8_t";
    case BASE_TYPE_SHORT: return "int16_t";
    case BASE_TYPE_USHORT: return "uint16_t";
    case BASE_TYPE_INT: return "int32_t";
    case BASE_TYPE_UINT: return "uint32_t";
    case BASE_TYPE_LONG: return "int64_t";
    case BASE_TYPE_ULONG: return "uint64_t";
    case BASE_TYPE_FLOAT: return "float";
    case BASE_TYPE_DOUBLE: return "double";
    default: return "uint8_t";
  }
}

size_t ScalarByteWidth(BaseType base_type) {
  switch (base_type) {
    case BASE_TYPE_BOOL:
    case BASE_TYPE_CHAR:
    case BASE_TYPE_UCHAR:
    case BASE_TYPE_UTYPE: return 1;
    case BASE_TYPE_SHORT:
    case BASE_TYPE_USHORT: return 2;
    case BASE_TYPE_INT:
    case BASE_TYPE_UINT:
    case BASE_TYPE_FLOAT: return 4;
    case BASE_TYPE_LONG:
    case BASE_TYPE_ULONG:
    case BASE_TYPE_DOUBLE: return 8;
    default: return 1;
  }
}

std::string TsScalarType(const InlineLayout& layout) {
  if (layout.enum_def && layout.base_type != BASE_TYPE_UTYPE) { return "number"; }
  switch (layout.base_type) {
    case BASE_TYPE_BOOL: return "boolean";
    case BASE_TYPE_LONG:
    case BASE_TYPE_ULONG: return "bigint";
    default: return "number";
  }
}

std::string TsGetterName(BaseType base_type) {
  switch (base_type) {
    case BASE_TYPE_BOOL:
    case BASE_TYPE_UCHAR:
    case BASE_TYPE_UTYPE: return "getUint8";
    case BASE_TYPE_CHAR: return "getInt8";
    case BASE_TYPE_SHORT: return "getInt16";
    case BASE_TYPE_USHORT: return "getUint16";
    case BASE_TYPE_INT: return "getInt32";
    case BASE_TYPE_UINT: return "getUint32";
    case BASE_TYPE_LONG: return "getBigInt64";
    case BASE_TYPE_ULONG: return "getBigUint64";
    case BASE_TYPE_FLOAT: return "getFloat32";
    case BASE_TYPE_DOUBLE: return "getFloat64";
    default: return "getUint8";
  }
}

std::string TsSetterName(BaseType base_type) {
  switch (base_type) {
    case BASE_TYPE_BOOL:
    case BASE_TYPE_UCHAR:
    case BASE_TYPE_UTYPE: return "setUint8";
    case BASE_TYPE_CHAR: return "setInt8";
    case BASE_TYPE_SHORT: return "setInt16";
    case BASE_TYPE_USHORT: return "setUint16";
    case BASE_TYPE_INT: return "setInt32";
    case BASE_TYPE_UINT: return "setUint32";
    case BASE_TYPE_LONG: return "setBigInt64";
    case BASE_TYPE_ULONG: return "setBigUint64";
    case BASE_TYPE_FLOAT: return "setFloat32";
    case BASE_TYPE_DOUBLE: return "setFloat64";
    default: return "setUint8";
  }
}

std::string CppFieldType(const FieldLayout& field, const InlineLayout& layout,
                         const std::string& union_cell_type);

std::string CppInlineType(const InlineLayout& layout,
                          const std::string& union_cell_type) {
  switch (layout.kind) {
    case InlineLayout::Kind::kScalar: return CppScalarType(layout);
    case InlineLayout::Kind::kRecord: return CppQualifiedRecordName(*layout.record);
    case InlineLayout::Kind::kString:
      return "::flatbuffers::aligned_runtime::AlignedString<" +
             NumToString(layout.max_length) + ">";
    case InlineLayout::Kind::kVector: {
      const std::string element_type =
          CppInlineType(*layout.element, union_cell_type);
      return "::flatbuffers::aligned_runtime::AlignedVector<" + element_type +
             ", " + NumToString(layout.max_count) + ">";
    }
    case InlineLayout::Kind::kUnion: return union_cell_type;
    case InlineLayout::Kind::kArray:
      return CppInlineType(*layout.element, union_cell_type);
  }
  return "uint8_t";
}

std::string CppFieldType(const FieldLayout& field, const InlineLayout& layout,
                         const std::string& union_cell_type) {
  if (layout.kind == InlineLayout::Kind::kArray) {
    return CppInlineType(*layout.element, union_cell_type) + " " + field.name +
           "[" + NumToString(layout.fixed_length) + "]";
  }
  return CppInlineType(layout, union_cell_type) + " " + field.name;
}

std::string TsRecordType(const RecordLayout& record) { return record.name; }

std::string BuildTsReadScalar(const std::string& view_expr,
                              const InlineLayout& layout,
                              const std::string& offset_expr) {
  std::string result = view_expr + "." + TsGetterName(layout.base_type) + "(" +
                       offset_expr + ", true)";
  if (layout.base_type == BASE_TYPE_BOOL) { result = "(" + result + " !== 0)"; }
  return result;
}

std::string BuildTsWriteScalar(const std::string& view_expr,
                               const InlineLayout& layout,
                               const std::string& offset_expr,
                               const std::string& value_expr) {
  std::string rhs = value_expr;
  if (layout.base_type == BASE_TYPE_BOOL) { rhs = "(" + value_expr + " ? 1 : 0)"; }
  return view_expr + "." + TsSetterName(layout.base_type) + "(" + offset_expr +
         ", " + rhs + ", true);";
}

struct GeneratedOutputs {
  std::string cpp;
  std::string ts;
  std::string js;
  std::string layout_json;
};

class Generator : public BaseGenerator {
 public:
  Generator(const Parser& parser, const std::string& path,
            const std::string& file_name)
      : BaseGenerator(parser, path, file_name, "", "::", "h") {}

  bool generate() override {
    std::string error;
    if (!CompileSchemaLayout(parser_, &schema_layout_, &error)) {
      error_ = error;
      return false;
    }
    if (schema_layout_.records.empty()) {
      error_ = "aligned mode requires at least one table or struct";
      return false;
    }
    outputs_.layout_json = GenerateLayoutJson(schema_layout_);
    outputs_.cpp = GenerateCpp();
    outputs_.ts = GenerateTs(/*typescript=*/true);
    outputs_.js = GenerateTs(/*typescript=*/false);
    return true;
  }

  bool save() const {
    const std::string cpp_path = path_ + file_name_ + "_aligned.h";
    if (!parser_.opts.file_saver->SaveFile(cpp_path.c_str(), outputs_.cpp, false)) {
      return false;
    }
    const std::string ts_path = path_ + file_name_ + "_aligned.ts";
    if (!parser_.opts.file_saver->SaveFile(ts_path.c_str(), outputs_.ts, false)) {
      return false;
    }
    const std::string js_path = path_ + file_name_ + "_aligned.js";
    if (!parser_.opts.file_saver->SaveFile(js_path.c_str(), outputs_.js, false)) {
      return false;
    }
    const std::string json_path = path_ + file_name_ + "_layouts.json";
    return parser_.opts.file_saver->SaveFile(json_path.c_str(),
                                             outputs_.layout_json, false);
  }

  const std::string& error() const { return error_; }

  std::string CombinedOutput() const {
    std::ostringstream ss;
    ss << "{";
    ss << "\"cpp\":" << EscapeJson(outputs_.cpp) << ",";
    ss << "\"ts\":" << EscapeJson(outputs_.ts) << ",";
    ss << "\"js\":" << EscapeJson(outputs_.js) << ",";
    ss << "\"layouts\":" << outputs_.layout_json;
    ss << "}";
    return ss.str();
  }

 private:
  static std::string EscapeJson(const std::string& value) {
    std::ostringstream ss;
    ss << '"';
    for (size_t i = 0; i < value.size(); ++i) {
      const char c = value[i];
      switch (c) {
        case '"': ss << "\\\""; break;
        case '\\': ss << "\\\\"; break;
        case '\n': ss << "\\n"; break;
        case '\r': ss << "\\r"; break;
        case '\t': ss << "\\t"; break;
        default: ss << c; break;
      }
    }
    ss << '"';
    return ss.str();
  }

  std::string PresenceMask(const FieldLayout& field) const {
    const size_t byte_index = field.presence_index / 8;
    const size_t bit_index = field.presence_index % 8;
    return "__presence[" + NumToString(byte_index) + "] & " +
           NumToString(static_cast<uint32_t>(1u << bit_index));
  }

  std::string GenerateCpp() const {
    std::ostringstream ss;
    ss << "// Auto-generated aligned fixed-layout bindings.\n";
    ss << "// DO NOT EDIT - Generated by flatc --aligned\n\n";
    ss << "#pragma once\n\n";
    ss << "#include <algorithm>\n";
    ss << "#include <cstddef>\n";
    ss << "#include <cstdint>\n";
    ss << "#include <cstring>\n";
    ss << "#include <string>\n\n";
    ss << "namespace flatbuffers {\n";
    ss << "namespace aligned_runtime {\n\n";
    ss << "template <size_t MaxLength>\n";
    ss << "struct AlignedString {\n";
    ss << "  uint8_t length;\n";
    ss << "  char data[MaxLength];\n\n";
    ss << "  void clear() {\n";
    ss << "    length = 0;\n";
    ss << "    std::memset(data, 0, MaxLength);\n";
    ss << "  }\n\n";
    ss << "  std::string str() const {\n";
    ss << "    const size_t size = std::min<size_t>(length, MaxLength);\n";
    ss << "    return std::string(data, data + size);\n";
    ss << "  }\n\n";
    ss << "  void set(const std::string& value) {\n";
    ss << "    const size_t size = std::min<size_t>(value.size(), MaxLength);\n";
    ss << "    length = static_cast<uint8_t>(size);\n";
    ss << "    if (size) { std::memcpy(data, value.data(), size); }\n";
    ss << "    if (size < MaxLength) { std::memset(data + size, 0, MaxLength - size); }\n";
    ss << "  }\n";
    ss << "};\n\n";
    ss << "template <typename T, size_t MaxCount>\n";
    ss << "struct AlignedVector {\n";
    ss << "  uint32_t length;\n";
    ss << "  T values[MaxCount];\n\n";
    ss << "  uint32_t size() const {\n";
    ss << "    return std::min<uint32_t>(length, static_cast<uint32_t>(MaxCount));\n";
    ss << "  }\n\n";
    ss << "  void clear() { length = 0; }\n";
    ss << "};\n\n";
    ss << "}  // namespace aligned_runtime\n";
    ss << "}  // namespace flatbuffers\n\n";

    for (size_t i = 0; i < schema_layout_.records.size(); ++i) {
      const RecordLayout& record = *schema_layout_.records[i];
      const std::vector<std::string>& components =
          record.def->defined_namespace ? record.def->defined_namespace->components
                                        : std::vector<std::string>();
      for (size_t c = 0; c < components.size(); ++c) {
        ss << "namespace " << components[c] << " {\n";
      }
      ss << "namespace Aligned {\n\n";

      for (size_t f = 0; f < record.fields.size(); ++f) {
        const FieldLayout& field = record.fields[f];
        const InlineLayout& layout = *field.layout;
        if (layout.kind != InlineLayout::Kind::kUnion &&
            !(layout.kind == InlineLayout::Kind::kVector &&
              layout.element &&
              layout.element->kind == InlineLayout::Kind::kUnion)) {
          continue;
        }
        const std::string helper_name =
            record.name + "_" + field.name + "_UnionCell";
        const InlineLayout& union_layout =
            layout.kind == InlineLayout::Kind::kUnion ? layout : *layout.element;
        const size_t discrim_size = ScalarByteWidth(union_layout.base_type);
        ss << "struct " << helper_name << " {\n";
        ss << "  " << CppScalarType(union_layout) << " type;\n";
        if (union_layout.payload_offset > discrim_size) {
          ss << "  uint8_t __padding["
             << NumToString(union_layout.payload_offset - discrim_size)
             << "];\n";
        }
        ss << "  alignas(" << union_layout.payload_align << ") "
           << "uint8_t payload[" << NumToString(union_layout.payload_size) << "];\n";
        ss << "};\n";
        ss << "static_assert(sizeof(" << helper_name << ") == "
           << union_layout.size << ", \"" << helper_name
           << " size mismatch\");\n";
        ss << "static_assert(alignof(" << helper_name << ") == "
           << union_layout.align << ", \"" << helper_name
           << " alignment mismatch\");\n\n";
      }

      ss << "struct " << record.name << " {\n";
      if (record.presence_bytes) {
        ss << "  uint8_t __presence[" << record.presence_bytes << "];\n";
      }
      for (size_t f = 0; f < record.fields.size(); ++f) {
        const FieldLayout& field = record.fields[f];
        const std::string union_cell_type =
            record.name + "_" + field.name + "_UnionCell";
        ss << "  " << CppFieldType(field, *field.layout, union_cell_type) << ";\n";
      }
      ss << "\n";
      for (size_t f = 0; f < record.fields.size(); ++f) {
        const FieldLayout& field = record.fields[f];
        if (field.presence_index == FieldLayout::kNoPresence) { continue; }
        const size_t byte_index = field.presence_index / 8;
        const size_t bit_index = field.presence_index % 8;
        ss << "  bool has_" << field.name << "() const {\n";
        ss << "    return (__presence[" << byte_index << "] & "
           << NumToString(static_cast<uint32_t>(1u << bit_index))
           << ") != 0;\n";
        ss << "  }\n";
        ss << "  void set_has_" << field.name << "(bool value) {\n";
        ss << "    if (value) __presence[" << byte_index << "] |= "
           << NumToString(static_cast<uint32_t>(1u << bit_index)) << ";\n";
        ss << "    else __presence[" << byte_index << "] &= ~"
           << NumToString(static_cast<uint32_t>(1u << bit_index)) << ";\n";
        ss << "  }\n";
      }
      ss << "\n";
      ss << "  static " << record.name << "* fromBytes(void* data) {\n";
      ss << "    return reinterpret_cast<" << record.name << "*>(data);\n";
      ss << "  }\n";
      ss << "  static const " << record.name << "* fromBytes(const void* data) {\n";
      ss << "    return reinterpret_cast<const " << record.name << "*>(data);\n";
      ss << "  }\n";
      ss << "  void copyTo(void* dest) const { std::memcpy(dest, this, "
         << record.size << "); }\n";
      ss << "  void copyFrom(const " << record.name
         << "& src) { std::memcpy(this, &src, " << record.size << "); }\n";
      ss << "};\n";
      ss << "static_assert(sizeof(" << record.name << ") == " << record.size
         << ", \"" << record.name << " size mismatch\");\n";
      ss << "static_assert(alignof(" << record.name << ") == " << record.align
         << ", \"" << record.name << " alignment mismatch\");\n";
      for (size_t f = 0; f < record.fields.size(); ++f) {
        const FieldLayout& field = record.fields[f];
        ss << "static_assert(offsetof(" << record.name << ", " << field.name << ") == "
           << field.offset << ", \"" << record.name << "." << field.name
           << " offset mismatch\");\n";
      }
      ss << "constexpr size_t " << TsIdentifier(record.name) << "_SIZE = "
         << record.size << ";\n";
      ss << "constexpr size_t " << TsIdentifier(record.name) << "_ALIGN = "
         << record.align << ";\n\n";
      ss << "}  // namespace Aligned\n";
      for (size_t c = components.size(); c > 0; --c) {
        ss << "}  // namespace " << components[c - 1] << "\n";
      }
      ss << "\n";
    }

    return ss.str();
  }

  std::string GenerateTs(bool typescript) const {
    std::ostringstream ss;
    ss << "// Auto-generated aligned fixed-layout bindings.\n";
    ss << "// DO NOT EDIT - Generated by flatc --aligned\n\n";
    if (typescript) {
      ss << "type BufferLike = ArrayBufferLike;\n\n";
    }
    ss << "function __readPresence(view, base, bitIndex) {\n";
    ss << "  const byteIndex = Math.floor(bitIndex / 8);\n";
    ss << "  const mask = 1 << (bitIndex % 8);\n";
    ss << "  return (view.getUint8(base + byteIndex) & mask) !== 0;\n";
    ss << "}\n\n";
    ss << "function __writePresence(view, base, bitIndex, value) {\n";
    ss << "  const byteIndex = Math.floor(bitIndex / 8);\n";
    ss << "  const mask = 1 << (bitIndex % 8);\n";
    ss << "  const current = view.getUint8(base + byteIndex);\n";
    ss << "  view.setUint8(base + byteIndex, value ? (current | mask) : (current & ~mask));\n";
    ss << "}\n\n";
    ss << "function __decodeString(view, offset, maxLength) {\n";
    ss << "  const length = Math.min(view.getUint8(offset), maxLength);\n";
    ss << "  const bytes = new Uint8Array(view.buffer, view.byteOffset + offset + 1, length);\n";
    ss << "  return new TextDecoder().decode(bytes);\n";
    ss << "}\n\n";
    ss << "function __encodeString(view, offset, maxLength, value) {\n";
    ss << "  const encoder = new TextEncoder();\n";
    ss << "  const bytes = encoder.encode(value);\n";
    ss << "  const length = Math.min(bytes.length, maxLength);\n";
    ss << "  view.setUint8(offset, length);\n";
    ss << "  const target = new Uint8Array(view.buffer, view.byteOffset + offset + 1, maxLength);\n";
    ss << "  target.fill(0);\n";
    ss << "  target.set(bytes.subarray(0, length));\n";
    ss << "}\n\n";

    for (size_t i = 0; i < schema_layout_.records.size(); ++i) {
      const RecordLayout& record = *schema_layout_.records[i];
      const std::string class_name = TsRecordType(record);
      if (typescript) {
        ss << "export class " << class_name << " {\n";
        ss << "  static readonly SIZE = " << record.size << ";\n";
        ss << "  static readonly ALIGN = " << record.align << ";\n";
        ss << "  static fromPointer(buffer: BufferLike, offset = 0): " << class_name
           << " { return new " << class_name << "(buffer, offset); }\n\n";
        ss << "  readonly view: DataView;\n";
        ss << "  constructor(public readonly buffer: BufferLike, public readonly offset = 0) {\n";
        ss << "    this.view = new DataView(buffer);\n";
        ss << "  }\n\n";
      } else {
        ss << "export class " << class_name << " {\n";
        ss << "  static SIZE = " << record.size << ";\n";
        ss << "  static ALIGN = " << record.align << ";\n";
        ss << "  static fromPointer(buffer, offset = 0) { return new " << class_name << "(buffer, offset); }\n\n";
        ss << "  constructor(buffer, offset = 0) {\n";
        ss << "    this.buffer = buffer;\n";
        ss << "    this.offset = offset;\n";
        ss << "    this.view = new DataView(buffer);\n";
        ss << "  }\n\n";
      }

      for (size_t f = 0; f < record.fields.size(); ++f) {
        const FieldLayout& field = record.fields[f];
        const InlineLayout& layout = *field.layout;
        const std::string field_offset = "this.offset + " + NumToString(field.offset);

        if (field.presence_index != FieldLayout::kNoPresence) {
          ss << "  " << (typescript ? "" : "") << "has" << field.name << "() {\n";
          ss << "    return __readPresence(this.view, this.offset, "
             << field.presence_index << ");\n";
          ss << "  }\n\n";
        }

        if (layout.kind == InlineLayout::Kind::kScalar) {
          ss << "  get " << field.name << "()";
          if (typescript) { ss << ": " << TsScalarType(layout); }
          ss << " {\n";
          ss << "    return " << BuildTsReadScalar("this.view", layout, field_offset)
             << ";\n";
          ss << "  }\n\n";
          ss << "  set " << field.name << "(value";
          if (typescript) { ss << ": " << TsScalarType(layout); }
          ss << ") {\n";
          ss << "    " << BuildTsWriteScalar("this.view", layout, field_offset, "value")
             << "\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "    __writePresence(this.view, this.offset, "
               << field.presence_index << ", true);\n";
          }
          ss << "  }\n\n";
          continue;
        }

        if (layout.kind == InlineLayout::Kind::kRecord) {
          ss << "  get " << field.name << "()";
          if (typescript) {
            ss << ": " << layout.record->name;
            if (field.presence_index != FieldLayout::kNoPresence) { ss << " | null"; }
          }
          ss << " {\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "    if (!this.has" << field.name << "()) { return null; }\n";
          }
          ss << "    return new " << layout.record->name << "(this.buffer, "
             << field_offset << ");\n";
          ss << "  }\n\n";
          continue;
        }

        if (layout.kind == InlineLayout::Kind::kString) {
          ss << "  get " << field.name << "()";
          if (typescript) {
            ss << ": string";
            if (field.presence_index != FieldLayout::kNoPresence) { ss << " | null"; }
          }
          ss << " {\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "    if (!this.has" << field.name << "()) { return null; }\n";
          }
          ss << "    return __decodeString(this.view, " << field_offset << ", "
             << layout.max_length << ");\n";
          ss << "  }\n\n";
          ss << "  set " << field.name << "(value";
          if (typescript) { ss << ": string"; }
          ss << ") {\n";
          ss << "    __encodeString(this.view, " << field_offset << ", "
             << layout.max_length << ", value);\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "    __writePresence(this.view, this.offset, "
               << field.presence_index << ", true);\n";
          }
          ss << "  }\n\n";
          continue;
        }

        if (layout.kind == InlineLayout::Kind::kArray) {
          ss << "  get " << field.name << "()";
          if (typescript) { ss << ": Array<any>"; }
          ss << " {\n";
          ss << "    const result = [];\n";
          ss << "    for (let i = 0; i < " << layout.fixed_length << "; ++i) {\n";
          if (layout.element->kind == InlineLayout::Kind::kScalar) {
            ss << "      result.push(" << BuildTsReadScalar(
                "this.view", *layout.element,
                field_offset + " + i * " + NumToString(layout.stride))
               << ");\n";
          } else if (layout.element->kind == InlineLayout::Kind::kRecord) {
            ss << "      result.push(new " << layout.element->record->name
               << "(this.buffer, " << field_offset << " + i * "
               << layout.stride << "));\n";
          } else if (layout.element->kind == InlineLayout::Kind::kString) {
            ss << "      result.push(__decodeString(this.view, " << field_offset
               << " + i * " << layout.stride << ", "
               << layout.element->max_length << "));\n";
          }
          ss << "    }\n";
          ss << "    return result;\n";
          ss << "  }\n\n";
          continue;
        }

        if (layout.kind == InlineLayout::Kind::kVector) {
          ss << "  get " << field.name << "()";
          if (typescript) { ss << ": Array<any>"; }
          ss << " {\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "    if (!this.has" << field.name << "()) { return []; }\n";
          }
          ss << "    const length = Math.min(this.view.getUint32(" << field_offset
             << ", true), " << layout.max_count << ");\n";
          ss << "    const result = [];\n";
          ss << "    for (let i = 0; i < length; ++i) {\n";
          const std::string elem_offset =
              field_offset + " + " + NumToString(layout.data_offset) +
              " + i * " + NumToString(layout.stride);
          if (layout.element->kind == InlineLayout::Kind::kScalar) {
            ss << "      result.push(" << BuildTsReadScalar("this.view",
                                                             *layout.element,
                                                             elem_offset)
               << ");\n";
          } else if (layout.element->kind == InlineLayout::Kind::kRecord) {
            ss << "      result.push(new " << layout.element->record->name
               << "(this.buffer, " << elem_offset << "));\n";
          } else if (layout.element->kind == InlineLayout::Kind::kString) {
            ss << "      result.push(__decodeString(this.view, " << elem_offset
               << ", " << layout.element->max_length << "));\n";
          } else {
            ss << "      result.push({ offset: " << elem_offset << " });\n";
          }
          ss << "    }\n";
          ss << "    return result;\n";
          ss << "  }\n\n";
          continue;
        }

        if (layout.kind == InlineLayout::Kind::kUnion) {
          ss << "  get " << field.name << "Type()";
          if (typescript) { ss << ": number"; }
          ss << " {\n";
          ss << "    return " << BuildTsReadScalar("this.view", layout, field_offset)
             << ";\n";
          ss << "  }\n\n";
        }
      }

      ss << "}\n\n";
    }

    return ss.str();
  }

  SchemaLayout schema_layout_;
  std::string error_;
  GeneratedOutputs outputs_;
};

}  // namespace

}  // namespace aligned

namespace {

class AlignedCodeGenerator : public CodeGenerator {
 public:
  Status GenerateCode(const Parser& parser, const std::string& path,
                      const std::string& filename) override {
    aligned::Generator generator(parser, path, filename);
    if (!generator.generate()) {
      status_detail = ": " + generator.error();
      return Status::ERROR;
    }
    return generator.save() ? Status::OK : Status::ERROR;
  }

  Status GenerateCode(const uint8_t*, int64_t, const CodeGenOptions&) override {
    return Status::NOT_IMPLEMENTED;
  }

  Status GenerateCodeString(const Parser& parser, const std::string& filename,
                            std::string& output) override {
    aligned::Generator generator(parser, "", filename);
    if (!generator.generate()) {
      status_detail = ": " + generator.error();
      return Status::ERROR;
    }
    output = generator.CombinedOutput();
    return Status::OK;
  }

  Status GenerateMakeRule(const Parser&, const std::string&,
                          const std::string&, std::string&) override {
    return Status::NOT_IMPLEMENTED;
  }

  Status GenerateGrpcCode(const Parser&, const std::string&,
                          const std::string&) override {
    return Status::NOT_IMPLEMENTED;
  }

  Status GenerateRootFile(const Parser&, const std::string&) override {
    return Status::NOT_IMPLEMENTED;
  }

  bool IsSchemaOnly() const override { return true; }
  bool SupportsBfbsGeneration() const override { return false; }
  bool SupportsRootFileGeneration() const override { return false; }
  IDLOptions::Language Language() const override {
    return static_cast<IDLOptions::Language>(0);
  }
  std::string LanguageName() const override { return "Aligned"; }
};

}  // namespace

std::unique_ptr<CodeGenerator> NewAlignedCodeGenerator() {
  return std::unique_ptr<CodeGenerator>(new AlignedCodeGenerator());
}

}  // namespace flatbuffers
