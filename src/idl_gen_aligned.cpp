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

std::string PascalCase(const std::string& value) {
  if (value.empty()) { return value; }
  std::string result = TsIdentifier(value);
  result[0] = static_cast<char>(
      std::toupper(static_cast<unsigned char>(result[0])));
  return result;
}

std::string UpperSnake(const std::string& value) {
  std::string result;
  for (size_t i = 0; i < value.size(); ++i) {
    const char c = value[i];
    if (std::isalnum(static_cast<unsigned char>(c))) {
      result += static_cast<char>(
          std::toupper(static_cast<unsigned char>(c)));
    } else {
      result += '_';
    }
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
  std::string go;
  std::string python;
  std::string rust;
  std::string java;
  std::string csharp;
  std::string kotlin;
  std::string dart;
  std::string swift;
  std::string php;
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
    outputs_.go = GenerateGo();
    outputs_.python = GeneratePython();
    outputs_.rust = GenerateRust();
    outputs_.java = GenerateJava();
    outputs_.csharp = GenerateCSharp();
    outputs_.kotlin = GenerateKotlin();
    outputs_.dart = GenerateDart();
    outputs_.swift = GenerateSwift();
    outputs_.php = GeneratePhp();
    return true;
  }

  bool SaveLegacyBundle() const {
    return SaveOutputFile(path_ + file_name_ + "_aligned.h", outputs_.cpp) &&
           SaveOutputFile(path_ + file_name_ + "_aligned.ts", outputs_.ts) &&
           SaveOutputFile(path_ + file_name_ + "_aligned.js", outputs_.js) &&
           SaveOutputFile(path_ + file_name_ + "_layouts.json",
                          outputs_.layout_json);
  }

  bool SaveLanguageOutput(IDLOptions::Language language) const {
    const std::string* output = OutputForLanguage(language);
    if (!output) { return false; }
    return SaveOutputFile(OutputPathForLanguage(language), *output);
  }

  const std::string& error() const { return error_; }

  const std::string* OutputForLanguage(IDLOptions::Language language) const {
    switch (language) {
      case IDLOptions::kCpp: return &outputs_.cpp;
      case IDLOptions::kTs: return &outputs_.ts;
      case IDLOptions::kGo: return &outputs_.go;
      case IDLOptions::kPython: return &outputs_.python;
      case IDLOptions::kRust: return &outputs_.rust;
      case IDLOptions::kJava: return &outputs_.java;
      case IDLOptions::kCSharp: return &outputs_.csharp;
      case IDLOptions::kKotlin:
      case IDLOptions::kKotlinKmp: return &outputs_.kotlin;
      case IDLOptions::kDart: return &outputs_.dart;
      case IDLOptions::kSwift: return &outputs_.swift;
      case IDLOptions::kPhp: return &outputs_.php;
      default: return nullptr;
    }
  }

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

  bool SaveOutputFile(const std::string& path, const std::string& contents) const {
    return parser_.opts.file_saver->SaveFile(path.c_str(), contents, false);
  }

  std::string OutputPathForLanguage(IDLOptions::Language language) const {
    switch (language) {
      case IDLOptions::kCpp: return path_ + file_name_ + "_aligned.h";
      case IDLOptions::kTs: return path_ + file_name_ + "_aligned.ts";
      case IDLOptions::kGo: return path_ + file_name_ + "_aligned.go";
      case IDLOptions::kPython: return path_ + file_name_ + "_aligned.py";
      case IDLOptions::kRust: return path_ + file_name_ + "_aligned.rs";
      case IDLOptions::kJava: return path_ + file_name_ + "_aligned.java";
      case IDLOptions::kCSharp: return path_ + file_name_ + "_aligned.cs";
      case IDLOptions::kKotlin:
      case IDLOptions::kKotlinKmp: return path_ + file_name_ + "_aligned.kt";
      case IDLOptions::kDart: return path_ + file_name_ + "_aligned.dart";
      case IDLOptions::kSwift: return path_ + file_name_ + "_aligned.swift";
      case IDLOptions::kPhp: return path_ + file_name_ + "_aligned.php";
      default: return std::string();
    }
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

  std::string GenerateGo() const {
    std::ostringstream ss;
    ss << "// Auto-generated aligned fixed-layout metadata scaffolds.\n";
    ss << "// DO NOT EDIT - Generated by flatc --aligned\n\n";
    ss << "package aligned\n\n";
    ss << "func __readPresence(buffer []byte, base int, bitIndex int) bool {\n";
    ss << "  byteIndex := bitIndex / 8\n";
    ss << "  mask := byte(1 << uint(bitIndex%8))\n";
    ss << "  return (buffer[base+byteIndex] & mask) != 0\n";
    ss << "}\n\n";

    for (size_t i = 0; i < schema_layout_.records.size(); ++i) {
      const RecordLayout& record = *schema_layout_.records[i];
      ss << "type " << record.name << " struct {\n";
      ss << "  Buffer []byte\n";
      ss << "  Offset int\n";
      ss << "}\n\n";
      ss << "const (\n";
      ss << "  " << record.name << "Size = " << record.size << "\n";
      ss << "  " << record.name << "Align = " << record.align << "\n";
      ss << "  " << record.name << "PresenceBytes = " << record.presence_bytes
         << "\n";
      for (size_t f = 0; f < record.fields.size(); ++f) {
        const FieldLayout& field = record.fields[f];
        const InlineLayout& layout = *field.layout;
        const std::string prefix = record.name + PascalCase(field.name);
        ss << "  " << prefix << "Offset = " << field.offset << "\n";
        ss << "  " << prefix << "Size = " << field.size << "\n";
        ss << "  " << prefix << "Align = " << field.align << "\n";
        if (field.presence_index != FieldLayout::kNoPresence) {
          ss << "  " << prefix << "PresenceBit = " << field.presence_index
             << "\n";
        }
        if (layout.kind == InlineLayout::Kind::kString) {
          ss << "  " << prefix << "MaxLength = " << layout.max_length << "\n";
        } else if (layout.kind == InlineLayout::Kind::kVector) {
          ss << "  " << prefix << "MaxCount = " << layout.max_count << "\n";
          ss << "  " << prefix << "DataOffset = " << layout.data_offset
             << "\n";
          ss << "  " << prefix << "Stride = " << layout.stride << "\n";
        } else if (layout.kind == InlineLayout::Kind::kArray) {
          ss << "  " << prefix << "Length = " << layout.fixed_length << "\n";
          ss << "  " << prefix << "Stride = " << layout.stride << "\n";
        } else if (layout.kind == InlineLayout::Kind::kUnion) {
          ss << "  " << prefix << "PayloadOffset = " << layout.payload_offset
             << "\n";
          ss << "  " << prefix << "PayloadSize = " << layout.payload_size
             << "\n";
          ss << "  " << prefix << "PayloadAlign = " << layout.payload_align
             << "\n";
        }
      }
      ss << ")\n\n";
      ss << "func " << record.name << "FromPointer(buffer []byte, offset int) "
         << record.name << " {\n";
      ss << "  return " << record.name << "{Buffer: buffer, Offset: offset}\n";
      ss << "}\n\n";
      for (size_t f = 0; f < record.fields.size(); ++f) {
        const FieldLayout& field = record.fields[f];
        if (field.presence_index == FieldLayout::kNoPresence) { continue; }
        ss << "func (r " << record.name << ") Has" << PascalCase(field.name)
           << "() bool {\n";
        ss << "  return __readPresence(r.Buffer, r.Offset, "
           << record.name << PascalCase(field.name) << "PresenceBit)\n";
        ss << "}\n\n";
      }
    }

    return ss.str();
  }

  std::string GeneratePython() const {
    std::ostringstream ss;
    ss << "# Auto-generated aligned fixed-layout metadata scaffolds.\n";
    ss << "# DO NOT EDIT - Generated by flatc --aligned\n\n";
    ss << "def _read_presence(buffer, base, bit_index):\n";
    ss << "    byte_index = bit_index // 8\n";
    ss << "    mask = 1 << (bit_index % 8)\n";
    ss << "    return (buffer[base + byte_index] & mask) != 0\n\n";

    for (size_t i = 0; i < schema_layout_.records.size(); ++i) {
      const RecordLayout& record = *schema_layout_.records[i];
      ss << "class " << record.name << ":\n";
      ss << "    SIZE = " << record.size << "\n";
      ss << "    ALIGN = " << record.align << "\n";
      ss << "    PRESENCE_BYTES = " << record.presence_bytes << "\n";
      for (size_t f = 0; f < record.fields.size(); ++f) {
        const FieldLayout& field = record.fields[f];
        const InlineLayout& layout = *field.layout;
        const std::string prefix = UpperSnake(field.name);
        ss << "    " << prefix << "_OFFSET = " << field.offset << "\n";
        ss << "    " << prefix << "_SIZE = " << field.size << "\n";
        ss << "    " << prefix << "_ALIGN = " << field.align << "\n";
        if (field.presence_index != FieldLayout::kNoPresence) {
          ss << "    " << prefix << "_PRESENCE_BIT = " << field.presence_index
             << "\n";
        }
        if (layout.kind == InlineLayout::Kind::kString) {
          ss << "    " << prefix << "_MAX_LENGTH = " << layout.max_length
             << "\n";
        } else if (layout.kind == InlineLayout::Kind::kVector) {
          ss << "    " << prefix << "_MAX_COUNT = " << layout.max_count
             << "\n";
          ss << "    " << prefix << "_DATA_OFFSET = " << layout.data_offset
             << "\n";
          ss << "    " << prefix << "_STRIDE = " << layout.stride << "\n";
        } else if (layout.kind == InlineLayout::Kind::kArray) {
          ss << "    " << prefix << "_LENGTH = " << layout.fixed_length << "\n";
          ss << "    " << prefix << "_STRIDE = " << layout.stride << "\n";
        } else if (layout.kind == InlineLayout::Kind::kUnion) {
          ss << "    " << prefix << "_PAYLOAD_OFFSET = " << layout.payload_offset
             << "\n";
          ss << "    " << prefix << "_PAYLOAD_SIZE = " << layout.payload_size
             << "\n";
          ss << "    " << prefix << "_PAYLOAD_ALIGN = " << layout.payload_align
             << "\n";
        }
      }
      ss << "\n";
      ss << "    def __init__(self, buffer, offset=0):\n";
      ss << "        self.buffer = memoryview(buffer)\n";
      ss << "        self.offset = offset\n\n";
      ss << "    @classmethod\n";
      ss << "    def from_bytes(cls, buffer, offset=0):\n";
      ss << "        return cls(buffer, offset)\n\n";
      for (size_t f = 0; f < record.fields.size(); ++f) {
        const FieldLayout& field = record.fields[f];
        if (field.presence_index == FieldLayout::kNoPresence) { continue; }
        ss << "    def has_" << field.name << "(self):\n";
        ss << "        return _read_presence(self.buffer, self.offset, self."
           << UpperSnake(field.name) << "_PRESENCE_BIT)\n\n";
      }
    }

    return ss.str();
  }

  std::string GenerateRust() const {
    std::ostringstream ss;
    ss << "// Auto-generated aligned fixed-layout metadata scaffolds.\n";
    ss << "// DO NOT EDIT - Generated by flatc --aligned\n\n";
    ss << "fn __read_presence(buffer: &[u8], base: usize, bit_index: usize) -> bool {\n";
    ss << "    let byte_index = bit_index / 8;\n";
    ss << "    let mask = 1u8 << (bit_index % 8);\n";
    ss << "    (buffer[base + byte_index] & mask) != 0\n";
    ss << "}\n\n";

    for (size_t i = 0; i < schema_layout_.records.size(); ++i) {
      const RecordLayout& record = *schema_layout_.records[i];
      ss << "pub struct " << record.name << "<'a> {\n";
      ss << "    pub buffer: &'a [u8],\n";
      ss << "    pub offset: usize,\n";
      ss << "}\n\n";
      ss << "impl<'a> " << record.name << "<'a> {\n";
      ss << "    pub const SIZE: usize = " << record.size << ";\n";
      ss << "    pub const ALIGN: usize = " << record.align << ";\n";
      ss << "    pub const PRESENCE_BYTES: usize = " << record.presence_bytes
         << ";\n";
      for (size_t f = 0; f < record.fields.size(); ++f) {
        const FieldLayout& field = record.fields[f];
        const InlineLayout& layout = *field.layout;
        const std::string prefix = UpperSnake(field.name);
        ss << "    pub const " << prefix << "_OFFSET: usize = " << field.offset
           << ";\n";
        ss << "    pub const " << prefix << "_SIZE: usize = " << field.size
           << ";\n";
        ss << "    pub const " << prefix << "_ALIGN: usize = " << field.align
           << ";\n";
        if (field.presence_index != FieldLayout::kNoPresence) {
          ss << "    pub const " << prefix
             << "_PRESENCE_BIT: usize = " << field.presence_index << ";\n";
        }
        if (layout.kind == InlineLayout::Kind::kString) {
          ss << "    pub const " << prefix << "_MAX_LENGTH: usize = "
             << layout.max_length << ";\n";
        } else if (layout.kind == InlineLayout::Kind::kVector) {
          ss << "    pub const " << prefix << "_MAX_COUNT: usize = "
             << layout.max_count << ";\n";
          ss << "    pub const " << prefix << "_DATA_OFFSET: usize = "
             << layout.data_offset << ";\n";
          ss << "    pub const " << prefix << "_STRIDE: usize = "
             << layout.stride << ";\n";
        } else if (layout.kind == InlineLayout::Kind::kArray) {
          ss << "    pub const " << prefix << "_LENGTH: usize = "
             << layout.fixed_length << ";\n";
          ss << "    pub const " << prefix << "_STRIDE: usize = "
             << layout.stride << ";\n";
        } else if (layout.kind == InlineLayout::Kind::kUnion) {
          ss << "    pub const " << prefix << "_PAYLOAD_OFFSET: usize = "
             << layout.payload_offset << ";\n";
          ss << "    pub const " << prefix << "_PAYLOAD_SIZE: usize = "
             << layout.payload_size << ";\n";
          ss << "    pub const " << prefix << "_PAYLOAD_ALIGN: usize = "
             << layout.payload_align << ";\n";
        }
      }
      ss << "\n";
      ss << "    pub fn from_pointer(buffer: &'a [u8], offset: usize) -> Self {\n";
      ss << "        Self { buffer, offset }\n";
      ss << "    }\n";
      for (size_t f = 0; f < record.fields.size(); ++f) {
        const FieldLayout& field = record.fields[f];
        if (field.presence_index == FieldLayout::kNoPresence) { continue; }
        ss << "\n";
        ss << "    pub fn has_" << field.name << "(&self) -> bool {\n";
        ss << "        __read_presence(self.buffer, self.offset, Self::"
           << UpperSnake(field.name) << "_PRESENCE_BIT)\n";
        ss << "    }\n";
      }
      ss << "}\n\n";
    }

    return ss.str();
  }

  std::string GenerateJava() const {
    std::ostringstream ss;
    ss << "// Auto-generated aligned fixed-layout metadata scaffolds.\n";
    ss << "// DO NOT EDIT - Generated by flatc --aligned\n\n";
    ss << "import java.nio.ByteBuffer;\n\n";
    ss << "final class AlignedSupport {\n";
    ss << "  static boolean readPresence(ByteBuffer buffer, int base, int bitIndex) {\n";
    ss << "    final int byteIndex = bitIndex / 8;\n";
    ss << "    final int mask = 1 << (bitIndex % 8);\n";
    ss << "    return (buffer.get(base + byteIndex) & mask) != 0;\n";
    ss << "  }\n";
    ss << "}\n\n";

    for (size_t i = 0; i < schema_layout_.records.size(); ++i) {
      const RecordLayout& record = *schema_layout_.records[i];
      ss << "final class " << record.name << " {\n";
      ss << "  static final int SIZE = " << record.size << ";\n";
      ss << "  static final int ALIGN = " << record.align << ";\n";
      ss << "  static final int PRESENCE_BYTES = " << record.presence_bytes
         << ";\n";
      for (size_t f = 0; f < record.fields.size(); ++f) {
        const FieldLayout& field = record.fields[f];
        const InlineLayout& layout = *field.layout;
        const std::string prefix = UpperSnake(field.name);
        ss << "  static final int " << prefix << "_OFFSET = " << field.offset
           << ";\n";
        ss << "  static final int " << prefix << "_SIZE = " << field.size
           << ";\n";
        ss << "  static final int " << prefix << "_ALIGN = " << field.align
           << ";\n";
        if (field.presence_index != FieldLayout::kNoPresence) {
          ss << "  static final int " << prefix << "_PRESENCE_BIT = "
             << field.presence_index << ";\n";
        }
        if (layout.kind == InlineLayout::Kind::kString) {
          ss << "  static final int " << prefix << "_MAX_LENGTH = "
             << layout.max_length << ";\n";
        } else if (layout.kind == InlineLayout::Kind::kVector) {
          ss << "  static final int " << prefix << "_MAX_COUNT = "
             << layout.max_count << ";\n";
          ss << "  static final int " << prefix << "_DATA_OFFSET = "
             << layout.data_offset << ";\n";
          ss << "  static final int " << prefix << "_STRIDE = " << layout.stride
             << ";\n";
        } else if (layout.kind == InlineLayout::Kind::kArray) {
          ss << "  static final int " << prefix << "_LENGTH = "
             << layout.fixed_length << ";\n";
          ss << "  static final int " << prefix << "_STRIDE = " << layout.stride
             << ";\n";
        } else if (layout.kind == InlineLayout::Kind::kUnion) {
          ss << "  static final int " << prefix << "_PAYLOAD_OFFSET = "
             << layout.payload_offset << ";\n";
          ss << "  static final int " << prefix << "_PAYLOAD_SIZE = "
             << layout.payload_size << ";\n";
          ss << "  static final int " << prefix << "_PAYLOAD_ALIGN = "
             << layout.payload_align << ";\n";
        }
      }
      ss << "\n";
      ss << "  final ByteBuffer buffer;\n";
      ss << "  final int offset;\n\n";
      ss << "  private " << record.name << "(ByteBuffer buffer, int offset) {\n";
      ss << "    this.buffer = buffer;\n";
      ss << "    this.offset = offset;\n";
      ss << "  }\n\n";
      ss << "  static " << record.name
         << " fromPointer(ByteBuffer buffer, int offset) {\n";
      ss << "    return new " << record.name << "(buffer, offset);\n";
      ss << "  }\n";
      for (size_t f = 0; f < record.fields.size(); ++f) {
        const FieldLayout& field = record.fields[f];
        if (field.presence_index == FieldLayout::kNoPresence) { continue; }
        ss << "\n";
        ss << "  boolean has" << PascalCase(field.name) << "() {\n";
        ss << "    return AlignedSupport.readPresence(buffer, offset, "
           << UpperSnake(field.name) << "_PRESENCE_BIT);\n";
        ss << "  }\n";
      }
      ss << "}\n\n";
    }

    return ss.str();
  }

  std::string GenerateCSharp() const {
    std::ostringstream ss;
    ss << "// Auto-generated aligned fixed-layout metadata scaffolds.\n";
    ss << "// DO NOT EDIT - Generated by flatc --aligned\n\n";
    ss << "using System;\n\n";
    ss << "internal static class AlignedSupport {\n";
    ss << "  internal static bool ReadPresence(ReadOnlySpan<byte> buffer, int baseOffset, int bitIndex) {\n";
    ss << "    var byteIndex = bitIndex / 8;\n";
    ss << "    var mask = (byte)(1 << (bitIndex % 8));\n";
    ss << "    return (buffer[baseOffset + byteIndex] & mask) != 0;\n";
    ss << "  }\n";
    ss << "}\n\n";

    for (size_t i = 0; i < schema_layout_.records.size(); ++i) {
      const RecordLayout& record = *schema_layout_.records[i];
      ss << "public sealed class " << record.name << " {\n";
      ss << "  public const int SIZE = " << record.size << ";\n";
      ss << "  public const int ALIGN = " << record.align << ";\n";
      ss << "  public const int PRESENCE_BYTES = " << record.presence_bytes
         << ";\n";
      for (size_t f = 0; f < record.fields.size(); ++f) {
        const FieldLayout& field = record.fields[f];
        const InlineLayout& layout = *field.layout;
        const std::string prefix = UpperSnake(field.name);
        ss << "  public const int " << prefix << "_OFFSET = " << field.offset
           << ";\n";
        ss << "  public const int " << prefix << "_SIZE = " << field.size
           << ";\n";
        ss << "  public const int " << prefix << "_ALIGN = " << field.align
           << ";\n";
        if (field.presence_index != FieldLayout::kNoPresence) {
          ss << "  public const int " << prefix << "_PRESENCE_BIT = "
             << field.presence_index << ";\n";
        }
        if (layout.kind == InlineLayout::Kind::kString) {
          ss << "  public const int " << prefix << "_MAX_LENGTH = "
             << layout.max_length << ";\n";
        } else if (layout.kind == InlineLayout::Kind::kVector) {
          ss << "  public const int " << prefix << "_MAX_COUNT = "
             << layout.max_count << ";\n";
          ss << "  public const int " << prefix << "_DATA_OFFSET = "
             << layout.data_offset << ";\n";
          ss << "  public const int " << prefix << "_STRIDE = "
             << layout.stride << ";\n";
        } else if (layout.kind == InlineLayout::Kind::kArray) {
          ss << "  public const int " << prefix << "_LENGTH = "
             << layout.fixed_length << ";\n";
          ss << "  public const int " << prefix << "_STRIDE = "
             << layout.stride << ";\n";
        } else if (layout.kind == InlineLayout::Kind::kUnion) {
          ss << "  public const int " << prefix << "_PAYLOAD_OFFSET = "
             << layout.payload_offset << ";\n";
          ss << "  public const int " << prefix << "_PAYLOAD_SIZE = "
             << layout.payload_size << ";\n";
          ss << "  public const int " << prefix << "_PAYLOAD_ALIGN = "
             << layout.payload_align << ";\n";
        }
      }
      ss << "\n";
      ss << "  public ReadOnlyMemory<byte> Buffer { get; }\n";
      ss << "  public int Offset { get; }\n\n";
      ss << "  private " << record.name
         << "(ReadOnlyMemory<byte> buffer, int offset) {\n";
      ss << "    Buffer = buffer;\n";
      ss << "    Offset = offset;\n";
      ss << "  }\n\n";
      ss << "  public static " << record.name
         << " FromPointer(ReadOnlyMemory<byte> buffer, int offset = 0) {\n";
      ss << "    return new " << record.name << "(buffer, offset);\n";
      ss << "  }\n";
      for (size_t f = 0; f < record.fields.size(); ++f) {
        const FieldLayout& field = record.fields[f];
        if (field.presence_index == FieldLayout::kNoPresence) { continue; }
        ss << "\n";
        ss << "  public bool Has" << PascalCase(field.name) << "() {\n";
        ss << "    return AlignedSupport.ReadPresence(Buffer.Span, Offset, "
           << UpperSnake(field.name) << "_PRESENCE_BIT);\n";
        ss << "  }\n";
      }
      ss << "}\n\n";
    }

    return ss.str();
  }

  std::string GenerateKotlin() const {
    std::ostringstream ss;
    ss << "// Auto-generated aligned fixed-layout metadata scaffolds.\n";
    ss << "// DO NOT EDIT - Generated by flatc --aligned\n\n";
    ss << "private fun readPresence(buffer: ByteArray, base: Int, bitIndex: Int): Boolean {\n";
    ss << "  val byteIndex = bitIndex / 8\n";
    ss << "  val mask = 1 shl (bitIndex % 8)\n";
    ss << "  return (buffer[base + byteIndex].toInt() and mask) != 0\n";
    ss << "}\n\n";

    for (size_t i = 0; i < schema_layout_.records.size(); ++i) {
      const RecordLayout& record = *schema_layout_.records[i];
      ss << "class " << record.name
         << "(val buffer: ByteArray, val offset: Int = 0) {\n";
      ss << "  companion object {\n";
      ss << "    const val SIZE: Int = " << record.size << "\n";
      ss << "    const val ALIGN: Int = " << record.align << "\n";
      ss << "    const val PRESENCE_BYTES: Int = " << record.presence_bytes
         << "\n";
      for (size_t f = 0; f < record.fields.size(); ++f) {
        const FieldLayout& field = record.fields[f];
        const InlineLayout& layout = *field.layout;
        const std::string prefix = UpperSnake(field.name);
        ss << "    const val " << prefix << "_OFFSET: Int = " << field.offset
           << "\n";
        ss << "    const val " << prefix << "_SIZE: Int = " << field.size
           << "\n";
        ss << "    const val " << prefix << "_ALIGN: Int = " << field.align
           << "\n";
        if (field.presence_index != FieldLayout::kNoPresence) {
          ss << "    const val " << prefix << "_PRESENCE_BIT: Int = "
             << field.presence_index << "\n";
        }
        if (layout.kind == InlineLayout::Kind::kString) {
          ss << "    const val " << prefix << "_MAX_LENGTH: Int = "
             << layout.max_length << "\n";
        } else if (layout.kind == InlineLayout::Kind::kVector) {
          ss << "    const val " << prefix << "_MAX_COUNT: Int = "
             << layout.max_count << "\n";
          ss << "    const val " << prefix << "_DATA_OFFSET: Int = "
             << layout.data_offset << "\n";
          ss << "    const val " << prefix << "_STRIDE: Int = "
             << layout.stride << "\n";
        } else if (layout.kind == InlineLayout::Kind::kArray) {
          ss << "    const val " << prefix << "_LENGTH: Int = "
             << layout.fixed_length << "\n";
          ss << "    const val " << prefix << "_STRIDE: Int = "
             << layout.stride << "\n";
        } else if (layout.kind == InlineLayout::Kind::kUnion) {
          ss << "    const val " << prefix << "_PAYLOAD_OFFSET: Int = "
             << layout.payload_offset << "\n";
          ss << "    const val " << prefix << "_PAYLOAD_SIZE: Int = "
             << layout.payload_size << "\n";
          ss << "    const val " << prefix << "_PAYLOAD_ALIGN: Int = "
             << layout.payload_align << "\n";
        }
      }
      ss << "\n";
      ss << "    fun fromPointer(buffer: ByteArray, offset: Int = 0): "
         << record.name << " = " << record.name << "(buffer, offset)\n";
      ss << "  }\n";
      for (size_t f = 0; f < record.fields.size(); ++f) {
        const FieldLayout& field = record.fields[f];
        if (field.presence_index == FieldLayout::kNoPresence) { continue; }
        ss << "\n";
        ss << "  fun has" << PascalCase(field.name) << "(): Boolean {\n";
        ss << "    return readPresence(buffer, offset, "
           << UpperSnake(field.name) << "_PRESENCE_BIT)\n";
        ss << "  }\n";
      }
      ss << "}\n\n";
    }

    return ss.str();
  }

  std::string GenerateDart() const {
    std::ostringstream ss;
    ss << "// Auto-generated aligned fixed-layout metadata scaffolds.\n";
    ss << "// DO NOT EDIT - Generated by flatc --aligned\n\n";
    ss << "import 'dart:typed_data';\n\n";
    ss << "bool _readPresence(ByteData data, int base, int bitIndex) {\n";
    ss << "  final byteIndex = bitIndex ~/ 8;\n";
    ss << "  final mask = 1 << (bitIndex % 8);\n";
    ss << "  return (data.getUint8(base + byteIndex) & mask) != 0;\n";
    ss << "}\n\n";

    for (size_t i = 0; i < schema_layout_.records.size(); ++i) {
      const RecordLayout& record = *schema_layout_.records[i];
      ss << "class " << record.name << " {\n";
      ss << "  static const int SIZE = " << record.size << ";\n";
      ss << "  static const int ALIGN = " << record.align << ";\n";
      ss << "  static const int PRESENCE_BYTES = " << record.presence_bytes
         << ";\n";
      for (size_t f = 0; f < record.fields.size(); ++f) {
        const FieldLayout& field = record.fields[f];
        const InlineLayout& layout = *field.layout;
        const std::string prefix = UpperSnake(field.name);
        ss << "  static const int " << prefix << "_OFFSET = " << field.offset
           << ";\n";
        ss << "  static const int " << prefix << "_SIZE = " << field.size
           << ";\n";
        ss << "  static const int " << prefix << "_ALIGN = " << field.align
           << ";\n";
        if (field.presence_index != FieldLayout::kNoPresence) {
          ss << "  static const int " << prefix << "_PRESENCE_BIT = "
             << field.presence_index << ";\n";
        }
        if (layout.kind == InlineLayout::Kind::kString) {
          ss << "  static const int " << prefix << "_MAX_LENGTH = "
             << layout.max_length << ";\n";
        } else if (layout.kind == InlineLayout::Kind::kVector) {
          ss << "  static const int " << prefix << "_MAX_COUNT = "
             << layout.max_count << ";\n";
          ss << "  static const int " << prefix << "_DATA_OFFSET = "
             << layout.data_offset << ";\n";
          ss << "  static const int " << prefix << "_STRIDE = "
             << layout.stride << ";\n";
        } else if (layout.kind == InlineLayout::Kind::kArray) {
          ss << "  static const int " << prefix << "_LENGTH = "
             << layout.fixed_length << ";\n";
          ss << "  static const int " << prefix << "_STRIDE = "
             << layout.stride << ";\n";
        } else if (layout.kind == InlineLayout::Kind::kUnion) {
          ss << "  static const int " << prefix << "_PAYLOAD_OFFSET = "
             << layout.payload_offset << ";\n";
          ss << "  static const int " << prefix << "_PAYLOAD_SIZE = "
             << layout.payload_size << ";\n";
          ss << "  static const int " << prefix << "_PAYLOAD_ALIGN = "
             << layout.payload_align << ";\n";
        }
      }
      ss << "\n";
      ss << "  final ByteData data;\n";
      ss << "  final int offset;\n\n";
      ss << "  " << record.name << "(this.data, [this.offset = 0]);\n\n";
      ss << "  factory " << record.name
         << ".fromPointer(ByteData data, [int offset = 0]) {\n";
      ss << "    return " << record.name << "(data, offset);\n";
      ss << "  }\n";
      for (size_t f = 0; f < record.fields.size(); ++f) {
        const FieldLayout& field = record.fields[f];
        if (field.presence_index == FieldLayout::kNoPresence) { continue; }
        ss << "\n";
        ss << "  bool has" << PascalCase(field.name) << "() {\n";
        ss << "    return _readPresence(data, offset, " << UpperSnake(field.name)
           << "_PRESENCE_BIT);\n";
        ss << "  }\n";
      }
      ss << "}\n\n";
    }

    return ss.str();
  }

  std::string GenerateSwift() const {
    std::ostringstream ss;
    ss << "// Auto-generated aligned fixed-layout metadata scaffolds.\n";
    ss << "// DO NOT EDIT - Generated by flatc --aligned\n\n";
    ss << "import Foundation\n\n";
    ss << "private func __readPresence(_ buffer: [UInt8], _ base: Int, _ bitIndex: Int) -> Bool {\n";
    ss << "    let byteIndex = bitIndex / 8\n";
    ss << "    let mask = UInt8(1 << (bitIndex % 8))\n";
    ss << "    return (buffer[base + byteIndex] & mask) != 0\n";
    ss << "}\n\n";

    for (size_t i = 0; i < schema_layout_.records.size(); ++i) {
      const RecordLayout& record = *schema_layout_.records[i];
      ss << "struct " << record.name << " {\n";
      ss << "    static let SIZE = " << record.size << "\n";
      ss << "    static let ALIGN = " << record.align << "\n";
      ss << "    static let PRESENCE_BYTES = " << record.presence_bytes << "\n";
      for (size_t f = 0; f < record.fields.size(); ++f) {
        const FieldLayout& field = record.fields[f];
        const InlineLayout& layout = *field.layout;
        const std::string prefix = UpperSnake(field.name);
        ss << "    static let " << prefix << "_OFFSET = " << field.offset
           << "\n";
        ss << "    static let " << prefix << "_SIZE = " << field.size << "\n";
        ss << "    static let " << prefix << "_ALIGN = " << field.align
           << "\n";
        if (field.presence_index != FieldLayout::kNoPresence) {
          ss << "    static let " << prefix << "_PRESENCE_BIT = "
             << field.presence_index << "\n";
        }
        if (layout.kind == InlineLayout::Kind::kString) {
          ss << "    static let " << prefix << "_MAX_LENGTH = "
             << layout.max_length << "\n";
        } else if (layout.kind == InlineLayout::Kind::kVector) {
          ss << "    static let " << prefix << "_MAX_COUNT = "
             << layout.max_count << "\n";
          ss << "    static let " << prefix << "_DATA_OFFSET = "
             << layout.data_offset << "\n";
          ss << "    static let " << prefix << "_STRIDE = " << layout.stride
             << "\n";
        } else if (layout.kind == InlineLayout::Kind::kArray) {
          ss << "    static let " << prefix << "_LENGTH = "
             << layout.fixed_length << "\n";
          ss << "    static let " << prefix << "_STRIDE = " << layout.stride
             << "\n";
        } else if (layout.kind == InlineLayout::Kind::kUnion) {
          ss << "    static let " << prefix << "_PAYLOAD_OFFSET = "
             << layout.payload_offset << "\n";
          ss << "    static let " << prefix << "_PAYLOAD_SIZE = "
             << layout.payload_size << "\n";
          ss << "    static let " << prefix << "_PAYLOAD_ALIGN = "
             << layout.payload_align << "\n";
        }
      }
      ss << "\n";
      ss << "    let buffer: [UInt8]\n";
      ss << "    let offset: Int\n\n";
      ss << "    init(_ buffer: [UInt8], _ offset: Int = 0) {\n";
      ss << "        self.buffer = buffer\n";
      ss << "        self.offset = offset\n";
      ss << "    }\n\n";
      ss << "    static func fromPointer(_ buffer: [UInt8], _ offset: Int = 0) -> "
         << record.name << " {\n";
      ss << "        return " << record.name << "(buffer, offset)\n";
      ss << "    }\n";
      for (size_t f = 0; f < record.fields.size(); ++f) {
        const FieldLayout& field = record.fields[f];
        if (field.presence_index == FieldLayout::kNoPresence) { continue; }
        ss << "\n";
        ss << "    func has" << PascalCase(field.name) << "() -> Bool {\n";
        ss << "        return __readPresence(buffer, offset, Self."
           << UpperSnake(field.name) << "_PRESENCE_BIT)\n";
        ss << "    }\n";
      }
      ss << "}\n\n";
    }

    return ss.str();
  }

  std::string GeneratePhp() const {
    std::ostringstream ss;
    ss << "<?php\n";
    ss << "// Auto-generated aligned fixed-layout metadata scaffolds.\n";
    ss << "// DO NOT EDIT - Generated by flatc --aligned\n\n";
    ss << "final class AlignedSupport {\n";
    ss << "    public static function readPresence(string $buffer, int $base, int $bitIndex): bool {\n";
    ss << "        $byteIndex = intdiv($bitIndex, 8);\n";
    ss << "        $mask = 1 << ($bitIndex % 8);\n";
    ss << "        return (ord($buffer[$base + $byteIndex]) & $mask) !== 0;\n";
    ss << "    }\n";
    ss << "}\n\n";

    for (size_t i = 0; i < schema_layout_.records.size(); ++i) {
      const RecordLayout& record = *schema_layout_.records[i];
      ss << "final class " << record.name << " {\n";
      ss << "    public const SIZE = " << record.size << ";\n";
      ss << "    public const ALIGN = " << record.align << ";\n";
      ss << "    public const PRESENCE_BYTES = " << record.presence_bytes
         << ";\n";
      for (size_t f = 0; f < record.fields.size(); ++f) {
        const FieldLayout& field = record.fields[f];
        const InlineLayout& layout = *field.layout;
        const std::string prefix = UpperSnake(field.name);
        ss << "    public const " << prefix << "_OFFSET = " << field.offset
           << ";\n";
        ss << "    public const " << prefix << "_SIZE = " << field.size
           << ";\n";
        ss << "    public const " << prefix << "_ALIGN = " << field.align
           << ";\n";
        if (field.presence_index != FieldLayout::kNoPresence) {
          ss << "    public const " << prefix << "_PRESENCE_BIT = "
             << field.presence_index << ";\n";
        }
        if (layout.kind == InlineLayout::Kind::kString) {
          ss << "    public const " << prefix << "_MAX_LENGTH = "
             << layout.max_length << ";\n";
        } else if (layout.kind == InlineLayout::Kind::kVector) {
          ss << "    public const " << prefix << "_MAX_COUNT = "
             << layout.max_count << ";\n";
          ss << "    public const " << prefix << "_DATA_OFFSET = "
             << layout.data_offset << ";\n";
          ss << "    public const " << prefix << "_STRIDE = "
             << layout.stride << ";\n";
        } else if (layout.kind == InlineLayout::Kind::kArray) {
          ss << "    public const " << prefix << "_LENGTH = "
             << layout.fixed_length << ";\n";
          ss << "    public const " << prefix << "_STRIDE = "
             << layout.stride << ";\n";
        } else if (layout.kind == InlineLayout::Kind::kUnion) {
          ss << "    public const " << prefix << "_PAYLOAD_OFFSET = "
             << layout.payload_offset << ";\n";
          ss << "    public const " << prefix << "_PAYLOAD_SIZE = "
             << layout.payload_size << ";\n";
          ss << "    public const " << prefix << "_PAYLOAD_ALIGN = "
             << layout.payload_align << ";\n";
        }
      }
      ss << "\n";
      ss << "    private string $buffer;\n";
      ss << "    private int $offset;\n\n";
      ss << "    private function __construct(string $buffer, int $offset = 0) {\n";
      ss << "        $this->buffer = $buffer;\n";
      ss << "        $this->offset = $offset;\n";
      ss << "    }\n\n";
      ss << "    public static function fromPointer(string $buffer, int $offset = 0): self {\n";
      ss << "        return new self($buffer, $offset);\n";
      ss << "    }\n";
      for (size_t f = 0; f < record.fields.size(); ++f) {
        const FieldLayout& field = record.fields[f];
        if (field.presence_index == FieldLayout::kNoPresence) { continue; }
        ss << "\n";
        ss << "    public function has" << PascalCase(field.name)
           << "(): bool {\n";
        ss << "        return AlignedSupport::readPresence($this->buffer, $this->offset, self::"
           << UpperSnake(field.name) << "_PRESENCE_BIT);\n";
        ss << "    }\n";
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

std::string AlignedLanguageName(IDLOptions::Language language) {
  switch (language) {
    case IDLOptions::kJava: return "Java";
    case IDLOptions::kCSharp: return "C#";
    case IDLOptions::kGo: return "Go";
    case IDLOptions::kCpp: return "C++";
    case IDLOptions::kPython: return "Python";
    case IDLOptions::kPhp: return "PHP";
    case IDLOptions::kTs: return "TypeScript";
    case IDLOptions::kDart: return "Dart";
    case IDLOptions::kRust: return "Rust";
    case IDLOptions::kKotlin: return "Kotlin";
    case IDLOptions::kSwift: return "Swift";
    case IDLOptions::kKotlinKmp: return "Kotlin";
    default: return "Unsupported";
  }
}

class AlignedCodeGenerator : public CodeGenerator {
 public:
  Status GenerateCode(const Parser& parser, const std::string& path,
                      const std::string& filename) override {
    aligned::Generator generator(parser, path, filename);
    if (!generator.generate()) {
      status_detail = ": " + generator.error();
      return Status::ERROR;
    }
    if (!generator.SaveLegacyBundle()) {
      status_detail = ": failed to save aligned compatibility outputs";
      return Status::ERROR;
    }
    return Status::OK;
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

class AlignedLanguageCodeGenerator : public CodeGenerator {
 public:
  explicit AlignedLanguageCodeGenerator(IDLOptions::Language language)
      : language_(language) {}

  Status GenerateCode(const Parser& parser, const std::string& path,
                      const std::string& filename) override {
    aligned::Generator generator(parser, path, filename);
    if (!generator.generate()) {
      status_detail = ": " + generator.error();
      return Status::ERROR;
    }
    if (!generator.SaveLanguageOutput(language_)) {
      status_detail = ": aligned output is not implemented for " +
                      AlignedLanguageName(language_);
      return Status::ERROR;
    }
    return Status::OK;
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
    const std::string* generated = generator.OutputForLanguage(language_);
    if (!generated) {
      status_detail = ": aligned output is not implemented for " +
                      AlignedLanguageName(language_);
      return Status::ERROR;
    }
    output = *generated;
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
  IDLOptions::Language Language() const override { return language_; }
  std::string LanguageName() const override {
    return "Aligned " + AlignedLanguageName(language_);
  }

 private:
  IDLOptions::Language language_;
};

}  // namespace

std::unique_ptr<CodeGenerator> NewAlignedCodeGenerator() {
  return std::unique_ptr<CodeGenerator>(new AlignedCodeGenerator());
}

bool IsAlignedLanguageSupported(IDLOptions::Language language) {
  switch (language) {
    case IDLOptions::kJava:
    case IDLOptions::kCSharp:
    case IDLOptions::kGo:
    case IDLOptions::kCpp:
    case IDLOptions::kPython:
    case IDLOptions::kPhp:
    case IDLOptions::kTs:
    case IDLOptions::kDart:
    case IDLOptions::kRust:
    case IDLOptions::kKotlin:
    case IDLOptions::kSwift:
    case IDLOptions::kKotlinKmp: return true;
    default: return false;
  }
}

std::unique_ptr<CodeGenerator> NewAlignedLanguageCodeGenerator(
    IDLOptions::Language language) {
  if (!IsAlignedLanguageSupported(language)) { return nullptr; }
  return std::unique_ptr<CodeGenerator>(
      new AlignedLanguageCodeGenerator(language));
}

}  // namespace flatbuffers
