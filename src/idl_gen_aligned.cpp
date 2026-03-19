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

std::string LowerCamelCase(const std::string& value) {
  if (value.empty()) { return value; }
  std::string result = PascalCase(value);
  result[0] = static_cast<char>(
      std::tolower(static_cast<unsigned char>(result[0])));
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

std::string LowerCase(const std::string& value) {
  std::string result = value;
  for (size_t i = 0; i < result.size(); ++i) {
    result[i] = static_cast<char>(
        std::tolower(static_cast<unsigned char>(result[i])));
  }
  return result;
}

std::string ScalarHelperSuffix(BaseType base_type) {
  switch (base_type) {
    case BASE_TYPE_BOOL: return "Bool";
    case BASE_TYPE_CHAR: return "Int8";
    case BASE_TYPE_UCHAR:
    case BASE_TYPE_UTYPE: return "UInt8";
    case BASE_TYPE_SHORT: return "Int16";
    case BASE_TYPE_USHORT: return "UInt16";
    case BASE_TYPE_INT: return "Int32";
    case BASE_TYPE_UINT: return "UInt32";
    case BASE_TYPE_LONG: return "Int64";
    case BASE_TYPE_ULONG: return "UInt64";
    case BASE_TYPE_FLOAT: return "Float32";
    case BASE_TYPE_DOUBLE: return "Float64";
    default: return "UInt8";
  }
}

std::string UnionCellName(const RecordLayout& record, const FieldLayout& field) {
  return record.name + PascalCase(field.name) + "UnionCell";
}

bool IsUnionLayout(const InlineLayout& layout) {
  return layout.kind == InlineLayout::Kind::kUnion;
}

bool IsVectorOfUnionLayout(const InlineLayout& layout) {
  return layout.kind == InlineLayout::Kind::kVector && layout.element &&
         layout.element->kind == InlineLayout::Kind::kUnion;
}

const InlineLayout& UnionLayoutForField(const InlineLayout& layout) {
  return IsUnionLayout(layout) ? layout : *layout.element;
}

std::string GoScalarType(const InlineLayout& layout) {
  switch (layout.base_type) {
    case BASE_TYPE_BOOL: return "bool";
    case BASE_TYPE_CHAR: return "int8";
    case BASE_TYPE_UCHAR:
    case BASE_TYPE_UTYPE: return "uint8";
    case BASE_TYPE_SHORT: return "int16";
    case BASE_TYPE_USHORT: return "uint16";
    case BASE_TYPE_INT: return "int32";
    case BASE_TYPE_UINT: return "uint32";
    case BASE_TYPE_LONG: return "int64";
    case BASE_TYPE_ULONG: return "uint64";
    case BASE_TYPE_FLOAT: return "float32";
    case BASE_TYPE_DOUBLE: return "float64";
    default: return "uint8";
  }
}

std::string RustScalarType(const InlineLayout& layout) {
  switch (layout.base_type) {
    case BASE_TYPE_BOOL: return "bool";
    case BASE_TYPE_CHAR: return "i8";
    case BASE_TYPE_UCHAR:
    case BASE_TYPE_UTYPE: return "u8";
    case BASE_TYPE_SHORT: return "i16";
    case BASE_TYPE_USHORT: return "u16";
    case BASE_TYPE_INT: return "i32";
    case BASE_TYPE_UINT: return "u32";
    case BASE_TYPE_LONG: return "i64";
    case BASE_TYPE_ULONG: return "u64";
    case BASE_TYPE_FLOAT: return "f32";
    case BASE_TYPE_DOUBLE: return "f64";
    default: return "u8";
  }
}

std::string JavaScalarType(const InlineLayout& layout) {
  switch (layout.base_type) {
    case BASE_TYPE_BOOL: return "boolean";
    case BASE_TYPE_CHAR: return "byte";
    case BASE_TYPE_UCHAR:
    case BASE_TYPE_UTYPE: return "short";
    case BASE_TYPE_SHORT: return "short";
    case BASE_TYPE_USHORT: return "int";
    case BASE_TYPE_INT: return "int";
    case BASE_TYPE_UINT: return "long";
    case BASE_TYPE_LONG:
    case BASE_TYPE_ULONG: return "long";
    case BASE_TYPE_FLOAT: return "float";
    case BASE_TYPE_DOUBLE: return "double";
    default: return "byte";
  }
}

std::string CSharpScalarType(const InlineLayout& layout) {
  switch (layout.base_type) {
    case BASE_TYPE_BOOL: return "bool";
    case BASE_TYPE_CHAR: return "sbyte";
    case BASE_TYPE_UCHAR:
    case BASE_TYPE_UTYPE: return "byte";
    case BASE_TYPE_SHORT: return "short";
    case BASE_TYPE_USHORT: return "ushort";
    case BASE_TYPE_INT: return "int";
    case BASE_TYPE_UINT: return "uint";
    case BASE_TYPE_LONG: return "long";
    case BASE_TYPE_ULONG: return "ulong";
    case BASE_TYPE_FLOAT: return "float";
    case BASE_TYPE_DOUBLE: return "double";
    default: return "byte";
  }
}

std::string KotlinScalarType(const InlineLayout& layout) {
  switch (layout.base_type) {
    case BASE_TYPE_BOOL: return "Boolean";
    case BASE_TYPE_CHAR: return "Byte";
    case BASE_TYPE_UCHAR:
    case BASE_TYPE_UTYPE: return "UByte";
    case BASE_TYPE_SHORT: return "Short";
    case BASE_TYPE_USHORT: return "UShort";
    case BASE_TYPE_INT: return "Int";
    case BASE_TYPE_UINT: return "UInt";
    case BASE_TYPE_LONG: return "Long";
    case BASE_TYPE_ULONG: return "ULong";
    case BASE_TYPE_FLOAT: return "Float";
    case BASE_TYPE_DOUBLE: return "Double";
    default: return "Byte";
  }
}

std::string KotlinConversion(BaseType base_type) {
  switch (base_type) {
    case BASE_TYPE_CHAR: return ".toByte()";
    case BASE_TYPE_UCHAR:
    case BASE_TYPE_UTYPE: return ".toUByte()";
    case BASE_TYPE_SHORT: return ".toShort()";
    case BASE_TYPE_USHORT: return ".toUShort()";
    case BASE_TYPE_INT: return ".toInt()";
    case BASE_TYPE_UINT: return ".toUInt()";
    case BASE_TYPE_LONG: return ".toLong()";
    case BASE_TYPE_ULONG: return ".toULong()";
    case BASE_TYPE_FLOAT: return ".toFloat()";
    case BASE_TYPE_DOUBLE: return ".toDouble()";
    default: return "";
  }
}

std::string DartScalarType(const InlineLayout& layout) {
  switch (layout.base_type) {
    case BASE_TYPE_BOOL: return "bool";
    case BASE_TYPE_FLOAT:
    case BASE_TYPE_DOUBLE: return "double";
    default: return "int";
  }
}

std::string SwiftScalarType(const InlineLayout& layout) {
  switch (layout.base_type) {
    case BASE_TYPE_BOOL: return "Bool";
    case BASE_TYPE_CHAR: return "Int8";
    case BASE_TYPE_UCHAR:
    case BASE_TYPE_UTYPE: return "UInt8";
    case BASE_TYPE_SHORT: return "Int16";
    case BASE_TYPE_USHORT: return "UInt16";
    case BASE_TYPE_INT: return "Int32";
    case BASE_TYPE_UINT: return "UInt32";
    case BASE_TYPE_LONG: return "Int64";
    case BASE_TYPE_ULONG: return "UInt64";
    case BASE_TYPE_FLOAT: return "Float";
    case BASE_TYPE_DOUBLE: return "Double";
    default: return "UInt8";
  }
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
    ss << "// Auto-generated aligned fixed-layout bindings.\n";
    ss << "// DO NOT EDIT - Generated by flatc --aligned\n\n";
    ss << "package aligned\n\n";
    ss << "import (\n";
    ss << "  \"encoding/binary\"\n";
    ss << "  \"math\"\n";
    ss << ")\n\n";
    ss << "func __readPresence(buffer []byte, base int, bitIndex int) bool {\n";
    ss << "  byteIndex := bitIndex / 8\n";
    ss << "  mask := byte(1 << uint(bitIndex%8))\n";
    ss << "  return (buffer[base+byteIndex] & mask) != 0\n";
    ss << "}\n\n";
    ss << "func __writePresence(buffer []byte, base int, bitIndex int, value bool) {\n";
    ss << "  byteIndex := bitIndex / 8\n";
    ss << "  mask := byte(1 << uint(bitIndex%8))\n";
    ss << "  if value {\n";
    ss << "    buffer[base+byteIndex] |= mask\n";
    ss << "  } else {\n";
    ss << "    buffer[base+byteIndex] &^= mask\n";
    ss << "  }\n";
    ss << "}\n\n";
    ss << "func __readBool(buffer []byte, offset int) bool { return buffer[offset] != 0 }\n";
    ss << "func __writeBool(buffer []byte, offset int, value bool) {\n";
    ss << "  if value { buffer[offset] = 1 } else { buffer[offset] = 0 }\n";
    ss << "}\n";
    ss << "func __readInt8(buffer []byte, offset int) int8 { return int8(buffer[offset]) }\n";
    ss << "func __writeInt8(buffer []byte, offset int, value int8) { buffer[offset] = byte(value) }\n";
    ss << "func __readUInt8(buffer []byte, offset int) uint8 { return buffer[offset] }\n";
    ss << "func __writeUInt8(buffer []byte, offset int, value uint8) { buffer[offset] = value }\n";
    ss << "func __readInt16(buffer []byte, offset int) int16 { return int16(binary.LittleEndian.Uint16(buffer[offset:])) }\n";
    ss << "func __writeInt16(buffer []byte, offset int, value int16) { binary.LittleEndian.PutUint16(buffer[offset:], uint16(value)) }\n";
    ss << "func __readUInt16(buffer []byte, offset int) uint16 { return binary.LittleEndian.Uint16(buffer[offset:]) }\n";
    ss << "func __writeUInt16(buffer []byte, offset int, value uint16) { binary.LittleEndian.PutUint16(buffer[offset:], value) }\n";
    ss << "func __readInt32(buffer []byte, offset int) int32 { return int32(binary.LittleEndian.Uint32(buffer[offset:])) }\n";
    ss << "func __writeInt32(buffer []byte, offset int, value int32) { binary.LittleEndian.PutUint32(buffer[offset:], uint32(value)) }\n";
    ss << "func __readUInt32(buffer []byte, offset int) uint32 { return binary.LittleEndian.Uint32(buffer[offset:]) }\n";
    ss << "func __writeUInt32(buffer []byte, offset int, value uint32) { binary.LittleEndian.PutUint32(buffer[offset:], value) }\n";
    ss << "func __readInt64(buffer []byte, offset int) int64 { return int64(binary.LittleEndian.Uint64(buffer[offset:])) }\n";
    ss << "func __writeInt64(buffer []byte, offset int, value int64) { binary.LittleEndian.PutUint64(buffer[offset:], uint64(value)) }\n";
    ss << "func __readUInt64(buffer []byte, offset int) uint64 { return binary.LittleEndian.Uint64(buffer[offset:]) }\n";
    ss << "func __writeUInt64(buffer []byte, offset int, value uint64) { binary.LittleEndian.PutUint64(buffer[offset:], value) }\n";
    ss << "func __readFloat32(buffer []byte, offset int) float32 { return math.Float32frombits(binary.LittleEndian.Uint32(buffer[offset:])) }\n";
    ss << "func __writeFloat32(buffer []byte, offset int, value float32) { binary.LittleEndian.PutUint32(buffer[offset:], math.Float32bits(value)) }\n";
    ss << "func __readFloat64(buffer []byte, offset int) float64 { return math.Float64frombits(binary.LittleEndian.Uint64(buffer[offset:])) }\n";
    ss << "func __writeFloat64(buffer []byte, offset int, value float64) { binary.LittleEndian.PutUint64(buffer[offset:], math.Float64bits(value)) }\n\n";
    ss << "func __decodeString(buffer []byte, offset int, maxLength int) string {\n";
    ss << "  length := int(buffer[offset])\n";
    ss << "  if length > maxLength { length = maxLength }\n";
    ss << "  return string(buffer[offset+1 : offset+1+length])\n";
    ss << "}\n\n";
    ss << "func __encodeString(buffer []byte, offset int, maxLength int, value string) {\n";
    ss << "  raw := []byte(value)\n";
    ss << "  length := len(raw)\n";
    ss << "  if length > maxLength { length = maxLength }\n";
    ss << "  buffer[offset] = byte(length)\n";
    ss << "  target := buffer[offset+1 : offset+1+maxLength]\n";
    ss << "  clear(target)\n";
    ss << "  copy(target, raw[:length])\n";
    ss << "}\n\n";

    for (size_t i = 0; i < schema_layout_.records.size(); ++i) {
      const RecordLayout& record = *schema_layout_.records[i];
      for (size_t f = 0; f < record.fields.size(); ++f) {
        const FieldLayout& field = record.fields[f];
        const InlineLayout& layout = *field.layout;
        if (!IsUnionLayout(layout) && !IsVectorOfUnionLayout(layout)) { continue; }

        const InlineLayout& union_layout = UnionLayoutForField(layout);
        const std::string helper_name = UnionCellName(record, field);
        const std::string type_name = GoScalarType(union_layout);
        ss << "type " << helper_name << " struct {\n";
        ss << "  Buffer []byte\n";
        ss << "  Offset int\n";
        ss << "}\n\n";
        if (!union_layout.union_members.empty()) {
          ss << "const (\n";
          for (size_t m = 0; m < union_layout.union_members.size(); ++m) {
            const UnionMemberLayout& member = union_layout.union_members[m];
            ss << "  " << helper_name << PascalCase(member.value->name)
               << "Type = " << member.value->GetAsUInt64() << "\n";
          }
          ss << ")\n\n";
        }
        ss << "func " << helper_name
           << "FromPointer(buffer []byte, offset int) " << helper_name << " {\n";
        ss << "  return " << helper_name << "{Buffer: buffer, Offset: offset}\n";
        ss << "}\n\n";
        ss << "func (c " << helper_name << ") Type() " << type_name << " {\n";
        ss << "  return __read" << ScalarHelperSuffix(union_layout.base_type)
           << "(c.Buffer, c.Offset + " << union_layout.discriminator_offset << ")\n";
        ss << "}\n\n";
        ss << "func (c " << helper_name << ") MutateType(value " << type_name
           << ") {\n";
        ss << "  __write" << ScalarHelperSuffix(union_layout.base_type)
           << "(c.Buffer, c.Offset + " << union_layout.discriminator_offset
           << ", value)\n";
        ss << "}\n\n";

        for (size_t m = 0; m < union_layout.union_members.size(); ++m) {
          const UnionMemberLayout& member = union_layout.union_members[m];
          const InlineLayout& member_layout = *member.layout;
          const std::string member_name = PascalCase(member.value->name);
          const std::string payload_offset =
              "c.Offset + " + NumToString(union_layout.payload_offset);
          ss << "func (c " << helper_name << ") Is" << member_name
             << "() bool {\n";
          ss << "  return c.Type() == " << helper_name << member_name
             << "Type\n";
          ss << "}\n\n";
          if (member_layout.kind == InlineLayout::Kind::kScalar) {
            ss << "func (c " << helper_name << ") " << member_name << "() "
               << GoScalarType(member_layout) << " {\n";
            ss << "  return __read" << ScalarHelperSuffix(member_layout.base_type)
               << "(c.Buffer, " << payload_offset << ")\n";
            ss << "}\n\n";
            ss << "func (c " << helper_name << ") Mutate" << member_name
               << "(value " << GoScalarType(member_layout) << ") {\n";
            ss << "  __write" << ScalarHelperSuffix(member_layout.base_type)
               << "(c.Buffer, " << payload_offset << ", value)\n";
            ss << "  c.MutateType(" << helper_name << member_name << "Type)\n";
            ss << "}\n\n";
          } else if (member_layout.kind == InlineLayout::Kind::kRecord) {
            ss << "func (c " << helper_name << ") " << member_name << "() "
               << member_layout.record->name << " {\n";
            ss << "  return " << member_layout.record->name
               << "FromPointer(c.Buffer, " << payload_offset << ")\n";
            ss << "}\n\n";
            ss << "func (c " << helper_name << ") Mutate" << member_name
               << "From(src " << member_layout.record->name << ") {\n";
            ss << "  copy(c.Buffer[" << payload_offset << ":" << payload_offset
               << " + " << member_layout.size << "], src.Buffer[src.Offset:src.Offset + "
               << member_layout.size << "])\n";
            ss << "  c.MutateType(" << helper_name << member_name << "Type)\n";
            ss << "}\n\n";
          } else if (member_layout.kind == InlineLayout::Kind::kString) {
            ss << "func (c " << helper_name << ") " << member_name
               << "() string {\n";
            ss << "  return __decodeString(c.Buffer, " << payload_offset << ", "
               << member_layout.max_length << ")\n";
            ss << "}\n\n";
            ss << "func (c " << helper_name << ") Mutate" << member_name
               << "(value string) {\n";
            ss << "  __encodeString(c.Buffer, " << payload_offset << ", "
               << member_layout.max_length << ", value)\n";
            ss << "  c.MutateType(" << helper_name << member_name << "Type)\n";
            ss << "}\n\n";
          }
        }
      }

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
        const InlineLayout& layout = *field.layout;
        const std::string field_name = PascalCase(field.name);
        const std::string field_offset =
            "r.Offset + " + record.name + field_name + "Offset";
        if (field.presence_index != FieldLayout::kNoPresence) {
          ss << "func (r " << record.name << ") Has" << field_name
             << "() bool {\n";
          ss << "  return __readPresence(r.Buffer, r.Offset, "
             << record.name << field_name << "PresenceBit)\n";
          ss << "}\n\n";
          ss << "func (r " << record.name << ") MutateHas" << field_name
             << "(value bool) {\n";
          ss << "  __writePresence(r.Buffer, r.Offset, " << record.name
             << field_name << "PresenceBit, value)\n";
          ss << "}\n\n";
        }

        if (layout.kind == InlineLayout::Kind::kScalar) {
          ss << "func (r " << record.name << ") " << field_name << "() "
             << GoScalarType(layout) << " {\n";
          ss << "  return __read" << ScalarHelperSuffix(layout.base_type)
             << "(r.Buffer, " << field_offset << ")\n";
          ss << "}\n\n";
          ss << "func (r " << record.name << ") Mutate" << field_name
             << "(value " << GoScalarType(layout) << ") {\n";
          ss << "  __write" << ScalarHelperSuffix(layout.base_type)
             << "(r.Buffer, " << field_offset << ", value)\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "  r.MutateHas" << field_name << "(true)\n";
          }
          ss << "}\n\n";
          continue;
        }

        if (layout.kind == InlineLayout::Kind::kRecord) {
          ss << "func (r " << record.name << ") " << field_name << "() "
             << layout.record->name << " {\n";
          ss << "  return " << layout.record->name << "FromPointer(r.Buffer, "
             << field_offset << ")\n";
          ss << "}\n\n";
          continue;
        }

        if (layout.kind == InlineLayout::Kind::kString) {
          ss << "func (r " << record.name << ") " << field_name
             << "() string {\n";
          ss << "  return __decodeString(r.Buffer, " << field_offset << ", "
             << layout.max_length << ")\n";
          ss << "}\n\n";
          ss << "func (r " << record.name << ") Mutate" << field_name
             << "(value string) {\n";
          ss << "  __encodeString(r.Buffer, " << field_offset << ", "
             << layout.max_length << ", value)\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "  r.MutateHas" << field_name << "(true)\n";
          }
          ss << "}\n\n";
          continue;
        }

        if (layout.kind == InlineLayout::Kind::kArray) {
          ss << "func (r " << record.name << ") " << field_name
             << "Length() int {\n";
          ss << "  return " << layout.fixed_length << "\n";
          ss << "}\n\n";
          const std::string element_offset =
              field_offset + " + j * " + NumToString(layout.stride);
          if (layout.element->kind == InlineLayout::Kind::kScalar) {
            ss << "func (r " << record.name << ") " << field_name
               << "(j int) " << GoScalarType(*layout.element) << " {\n";
            ss << "  return __read" << ScalarHelperSuffix(layout.element->base_type)
               << "(r.Buffer, " << element_offset << ")\n";
            ss << "}\n\n";
            ss << "func (r " << record.name << ") Mutate" << field_name
               << "(j int, value " << GoScalarType(*layout.element) << ") {\n";
            ss << "  __write" << ScalarHelperSuffix(layout.element->base_type)
               << "(r.Buffer, " << element_offset << ", value)\n";
            ss << "}\n\n";
          } else if (layout.element->kind == InlineLayout::Kind::kRecord) {
            ss << "func (r " << record.name << ") " << field_name
               << "(j int) " << layout.element->record->name << " {\n";
            ss << "  return " << layout.element->record->name
               << "FromPointer(r.Buffer, " << element_offset << ")\n";
            ss << "}\n\n";
          } else if (layout.element->kind == InlineLayout::Kind::kString) {
            ss << "func (r " << record.name << ") " << field_name
               << "(j int) string {\n";
            ss << "  return __decodeString(r.Buffer, " << element_offset << ", "
               << layout.element->max_length << ")\n";
            ss << "}\n\n";
            ss << "func (r " << record.name << ") Mutate" << field_name
               << "(j int, value string) {\n";
            ss << "  __encodeString(r.Buffer, " << element_offset << ", "
               << layout.element->max_length << ", value)\n";
            ss << "}\n\n";
          }
          continue;
        }

        if (layout.kind == InlineLayout::Kind::kVector) {
          ss << "func (r " << record.name << ") " << field_name
             << "Length() int {\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "  if !r.Has" << field_name << "() { return 0 }\n";
          }
          ss << "  length := int(__readUInt32(r.Buffer, " << field_offset << "))\n";
          ss << "  if length > " << layout.max_count << " { length = "
             << layout.max_count << " }\n";
          ss << "  return length\n";
          ss << "}\n\n";
          ss << "func (r " << record.name << ") Mutate" << field_name
             << "Length(length int) {\n";
          ss << "  if length < 0 { length = 0 }\n";
          ss << "  if length > " << layout.max_count << " { length = "
             << layout.max_count << " }\n";
          ss << "  __writeUInt32(r.Buffer, " << field_offset
             << ", uint32(length))\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "  r.MutateHas" << field_name << "(true)\n";
          }
          ss << "}\n\n";
          const std::string element_offset =
              field_offset + " + " + record.name + field_name +
              "DataOffset + j * " + record.name + field_name + "Stride";
          if (layout.element->kind == InlineLayout::Kind::kScalar) {
            ss << "func (r " << record.name << ") " << field_name
               << "(j int) " << GoScalarType(*layout.element) << " {\n";
            ss << "  return __read" << ScalarHelperSuffix(layout.element->base_type)
               << "(r.Buffer, " << element_offset << ")\n";
            ss << "}\n\n";
            ss << "func (r " << record.name << ") Mutate" << field_name
               << "(j int, value " << GoScalarType(*layout.element) << ") {\n";
            ss << "  __write" << ScalarHelperSuffix(layout.element->base_type)
               << "(r.Buffer, " << element_offset << ", value)\n";
            if (field.presence_index != FieldLayout::kNoPresence) {
              ss << "  r.MutateHas" << field_name << "(true)\n";
            }
            ss << "}\n\n";
          } else if (layout.element->kind == InlineLayout::Kind::kRecord) {
            ss << "func (r " << record.name << ") " << field_name
               << "(j int) " << layout.element->record->name << " {\n";
            ss << "  return " << layout.element->record->name
               << "FromPointer(r.Buffer, " << element_offset << ")\n";
            ss << "}\n\n";
          } else if (layout.element->kind == InlineLayout::Kind::kString) {
            ss << "func (r " << record.name << ") " << field_name
               << "(j int) string {\n";
            ss << "  return __decodeString(r.Buffer, " << element_offset << ", "
               << layout.element->max_length << ")\n";
            ss << "}\n\n";
            ss << "func (r " << record.name << ") Mutate" << field_name
               << "(j int, value string) {\n";
            ss << "  __encodeString(r.Buffer, " << element_offset << ", "
               << layout.element->max_length << ", value)\n";
            if (field.presence_index != FieldLayout::kNoPresence) {
              ss << "  r.MutateHas" << field_name << "(true)\n";
            }
            ss << "}\n\n";
          } else if (layout.element->kind == InlineLayout::Kind::kUnion) {
            const std::string helper_name = UnionCellName(record, field);
            ss << "func (r " << record.name << ") " << field_name
               << "(j int) " << helper_name << " {\n";
            ss << "  return " << helper_name << "FromPointer(r.Buffer, "
               << element_offset << ")\n";
            ss << "}\n\n";
          }
          continue;
        }

        if (layout.kind == InlineLayout::Kind::kUnion) {
          const std::string helper_name = UnionCellName(record, field);
          ss << "func (r " << record.name << ") " << field_name
             << "Type() " << GoScalarType(layout) << " {\n";
          ss << "  return __read" << ScalarHelperSuffix(layout.base_type)
             << "(r.Buffer, " << field_offset << " + "
             << layout.discriminator_offset << ")\n";
          ss << "}\n\n";
          ss << "func (r " << record.name << ") Mutate" << field_name
             << "Type(value " << GoScalarType(layout) << ") {\n";
          ss << "  __write" << ScalarHelperSuffix(layout.base_type)
             << "(r.Buffer, " << field_offset << " + "
             << layout.discriminator_offset << ", value)\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "  r.MutateHas" << field_name << "(true)\n";
          }
          ss << "}\n\n";
          ss << "func (r " << record.name << ") " << field_name
             << "() " << helper_name << " {\n";
          ss << "  return " << helper_name << "FromPointer(r.Buffer, "
             << field_offset << ")\n";
          ss << "}\n\n";
        }
      }
    }

    return ss.str();
  }

  std::string GeneratePython() const {
    std::ostringstream ss;
    ss << "# Auto-generated aligned fixed-layout bindings.\n";
    ss << "# DO NOT EDIT - Generated by flatc --aligned\n\n";
    ss << "import struct\n\n";
    ss << "def _read_presence(buffer, base, bit_index):\n";
    ss << "    byte_index = bit_index // 8\n";
    ss << "    mask = 1 << (bit_index % 8)\n";
    ss << "    return (buffer[base + byte_index] & mask) != 0\n\n";
    ss << "def _write_presence(buffer, base, bit_index, value):\n";
    ss << "    byte_index = bit_index // 8\n";
    ss << "    mask = 1 << (bit_index % 8)\n";
    ss << "    current = buffer[base + byte_index]\n";
    ss << "    buffer[base + byte_index] = (current | mask) if value else (current & ~mask)\n\n";
    ss << "def _read_bool(buffer, offset): return buffer[offset] != 0\n";
    ss << "def _write_bool(buffer, offset, value): buffer[offset] = 1 if value else 0\n";
    ss << "def _read_int8(buffer, offset): return int.from_bytes(buffer[offset:offset + 1], 'little', signed=True)\n";
    ss << "def _write_int8(buffer, offset, value): buffer[offset:offset + 1] = int(value).to_bytes(1, 'little', signed=True)\n";
    ss << "def _read_uint8(buffer, offset): return buffer[offset]\n";
    ss << "def _write_uint8(buffer, offset, value): buffer[offset] = int(value) & 0xFF\n";
    ss << "def _read_int16(buffer, offset): return int.from_bytes(buffer[offset:offset + 2], 'little', signed=True)\n";
    ss << "def _write_int16(buffer, offset, value): buffer[offset:offset + 2] = int(value).to_bytes(2, 'little', signed=True)\n";
    ss << "def _read_uint16(buffer, offset): return int.from_bytes(buffer[offset:offset + 2], 'little', signed=False)\n";
    ss << "def _write_uint16(buffer, offset, value): buffer[offset:offset + 2] = int(value).to_bytes(2, 'little', signed=False)\n";
    ss << "def _read_int32(buffer, offset): return int.from_bytes(buffer[offset:offset + 4], 'little', signed=True)\n";
    ss << "def _write_int32(buffer, offset, value): buffer[offset:offset + 4] = int(value).to_bytes(4, 'little', signed=True)\n";
    ss << "def _read_uint32(buffer, offset): return int.from_bytes(buffer[offset:offset + 4], 'little', signed=False)\n";
    ss << "def _write_uint32(buffer, offset, value): buffer[offset:offset + 4] = int(value).to_bytes(4, 'little', signed=False)\n";
    ss << "def _read_int64(buffer, offset): return int.from_bytes(buffer[offset:offset + 8], 'little', signed=True)\n";
    ss << "def _write_int64(buffer, offset, value): buffer[offset:offset + 8] = int(value).to_bytes(8, 'little', signed=True)\n";
    ss << "def _read_uint64(buffer, offset): return int.from_bytes(buffer[offset:offset + 8], 'little', signed=False)\n";
    ss << "def _write_uint64(buffer, offset, value): buffer[offset:offset + 8] = int(value).to_bytes(8, 'little', signed=False)\n";
    ss << "def _read_float32(buffer, offset): return struct.unpack_from('<f', buffer, offset)[0]\n";
    ss << "def _write_float32(buffer, offset, value): struct.pack_into('<f', buffer, offset, value)\n";
    ss << "def _read_float64(buffer, offset): return struct.unpack_from('<d', buffer, offset)[0]\n";
    ss << "def _write_float64(buffer, offset, value): struct.pack_into('<d', buffer, offset, value)\n\n";
    ss << "def _decode_string(buffer, offset, max_length):\n";
    ss << "    length = min(buffer[offset], max_length)\n";
    ss << "    return bytes(buffer[offset + 1:offset + 1 + length]).decode('utf-8')\n\n";
    ss << "def _encode_string(buffer, offset, max_length, value):\n";
    ss << "    raw = value.encode('utf-8')\n";
    ss << "    length = min(len(raw), max_length)\n";
    ss << "    buffer[offset] = length\n";
    ss << "    buffer[offset + 1:offset + 1 + max_length] = b'\\x00' * max_length\n";
    ss << "    buffer[offset + 1:offset + 1 + length] = raw[:length]\n\n";

    for (size_t i = 0; i < schema_layout_.records.size(); ++i) {
      const RecordLayout& record = *schema_layout_.records[i];
      for (size_t f = 0; f < record.fields.size(); ++f) {
        const FieldLayout& field = record.fields[f];
        const InlineLayout& layout = *field.layout;
        if (!IsUnionLayout(layout) && !IsVectorOfUnionLayout(layout)) { continue; }

        const InlineLayout& union_layout = UnionLayoutForField(layout);
        const std::string helper_name = UnionCellName(record, field);
        ss << "class " << helper_name << ":\n";
        if (!union_layout.union_members.empty()) {
          for (size_t m = 0; m < union_layout.union_members.size(); ++m) {
            const UnionMemberLayout& member = union_layout.union_members[m];
            ss << "    " << UpperSnake(member.value->name) << "_TYPE = "
               << member.value->GetAsUInt64() << "\n";
          }
          ss << "\n";
        }
        ss << "    def __init__(self, buffer, offset=0):\n";
        ss << "        self.buffer = memoryview(buffer).cast('B')\n";
        ss << "        self.offset = offset\n\n";
        ss << "    @classmethod\n";
        ss << "    def from_bytes(cls, buffer, offset=0):\n";
        ss << "        return cls(buffer, offset)\n\n";
        ss << "    def Type(self):\n";
        ss << "        return _read_" << LowerCase(ScalarHelperSuffix(union_layout.base_type))
           << "(self.buffer, self.offset + " << union_layout.discriminator_offset << ")\n\n";
        ss << "    def MutateType(self, value):\n";
        ss << "        _write_" << LowerCase(ScalarHelperSuffix(union_layout.base_type))
           << "(self.buffer, self.offset + " << union_layout.discriminator_offset
           << ", value)\n\n";
        for (size_t m = 0; m < union_layout.union_members.size(); ++m) {
          const UnionMemberLayout& member = union_layout.union_members[m];
          const InlineLayout& member_layout = *member.layout;
          const std::string member_name = PascalCase(member.value->name);
          const std::string payload_offset =
              "self.offset + " + NumToString(union_layout.payload_offset);
          ss << "    def Is" << member_name << "(self):\n";
          ss << "        return self.Type() == self." << UpperSnake(member.value->name)
             << "_TYPE\n\n";
          if (member_layout.kind == InlineLayout::Kind::kScalar) {
            ss << "    def " << member_name << "(self):\n";
            ss << "        return _read_"
               << LowerCase(ScalarHelperSuffix(member_layout.base_type))
               << "(self.buffer, " << payload_offset << ")\n\n";
            ss << "    def Mutate" << member_name << "(self, value):\n";
            ss << "        _write_"
               << LowerCase(ScalarHelperSuffix(member_layout.base_type))
               << "(self.buffer, " << payload_offset << ", value)\n";
            ss << "        self.MutateType(self." << UpperSnake(member.value->name)
               << "_TYPE)\n\n";
          } else if (member_layout.kind == InlineLayout::Kind::kRecord) {
            ss << "    def " << member_name << "(self):\n";
            ss << "        return " << member_layout.record->name
               << ".from_bytes(self.buffer, " << payload_offset << ")\n\n";
            ss << "    def Mutate" << member_name << "From(self, src):\n";
            ss << "        self.buffer[" << payload_offset << ":" << payload_offset
               << " + " << member_layout.size << "] = src.buffer[src.offset:src.offset + "
               << member_layout.size << "]\n";
            ss << "        self.MutateType(self." << UpperSnake(member.value->name)
               << "_TYPE)\n\n";
          } else if (member_layout.kind == InlineLayout::Kind::kString) {
            ss << "    def " << member_name << "(self):\n";
            ss << "        return _decode_string(self.buffer, " << payload_offset
               << ", " << member_layout.max_length << ")\n\n";
            ss << "    def Mutate" << member_name << "(self, value):\n";
            ss << "        _encode_string(self.buffer, " << payload_offset << ", "
               << member_layout.max_length << ", value)\n";
            ss << "        self.MutateType(self." << UpperSnake(member.value->name)
               << "_TYPE)\n\n";
          }
        }

      }

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
      ss << "        self.buffer = memoryview(buffer).cast('B')\n";
      ss << "        self.offset = offset\n\n";
      ss << "    @classmethod\n";
      ss << "    def from_bytes(cls, buffer, offset=0):\n";
      ss << "        return cls(buffer, offset)\n\n";
      for (size_t f = 0; f < record.fields.size(); ++f) {
        const FieldLayout& field = record.fields[f];
        const InlineLayout& layout = *field.layout;
        const std::string field_name = PascalCase(field.name);
        const std::string field_offset =
            "self.offset + self." + UpperSnake(field.name) + "_OFFSET";
        if (field.presence_index != FieldLayout::kNoPresence) {
          ss << "    def Has" << field_name << "(self):\n";
          ss << "        return _read_presence(self.buffer, self.offset, self."
             << UpperSnake(field.name) << "_PRESENCE_BIT)\n\n";
          ss << "    def MutateHas" << field_name << "(self, value):\n";
          ss << "        _write_presence(self.buffer, self.offset, self."
             << UpperSnake(field.name) << "_PRESENCE_BIT, value)\n\n";
        }
        if (layout.kind == InlineLayout::Kind::kScalar) {
          ss << "    def " << field_name << "(self):\n";
          ss << "        return _read_" << LowerCase(ScalarHelperSuffix(layout.base_type))
             << "(self.buffer, " << field_offset << ")\n\n";
          ss << "    def Mutate" << field_name << "(self, value):\n";
          ss << "        _write_" << LowerCase(ScalarHelperSuffix(layout.base_type))
             << "(self.buffer, " << field_offset << ", value)\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "        self.MutateHas" << field_name << "(True)\n";
          }
          ss << "\n";
          continue;
        }
        if (layout.kind == InlineLayout::Kind::kRecord) {
          ss << "    def " << field_name << "(self):\n";
          ss << "        return " << layout.record->name << ".from_bytes(self.buffer, "
             << field_offset << ")\n\n";
          continue;
        }
        if (layout.kind == InlineLayout::Kind::kString) {
          ss << "    def " << field_name << "(self):\n";
          ss << "        return _decode_string(self.buffer, " << field_offset << ", "
             << layout.max_length << ")\n\n";
          ss << "    def Mutate" << field_name << "(self, value):\n";
          ss << "        _encode_string(self.buffer, " << field_offset << ", "
             << layout.max_length << ", value)\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "        self.MutateHas" << field_name << "(True)\n";
          }
          ss << "\n";
          continue;
        }
        if (layout.kind == InlineLayout::Kind::kArray) {
          ss << "    def " << field_name << "Length(self):\n";
          ss << "        return " << layout.fixed_length << "\n\n";
          const std::string element_offset =
              field_offset + " + j * " + NumToString(layout.stride);
          if (layout.element->kind == InlineLayout::Kind::kScalar) {
            ss << "    def " << field_name << "(self, j):\n";
            ss << "        return _read_"
               << LowerCase(ScalarHelperSuffix(layout.element->base_type))
               << "(self.buffer, " << element_offset << ")\n\n";
            ss << "    def Mutate" << field_name << "(self, j, value):\n";
            ss << "        _write_"
               << LowerCase(ScalarHelperSuffix(layout.element->base_type))
               << "(self.buffer, " << element_offset << ", value)\n\n";
          } else if (layout.element->kind == InlineLayout::Kind::kRecord) {
            ss << "    def " << field_name << "(self, j):\n";
            ss << "        return " << layout.element->record->name
               << ".from_bytes(self.buffer, " << element_offset << ")\n\n";
          } else if (layout.element->kind == InlineLayout::Kind::kString) {
            ss << "    def " << field_name << "(self, j):\n";
            ss << "        return _decode_string(self.buffer, " << element_offset
               << ", " << layout.element->max_length << ")\n\n";
            ss << "    def Mutate" << field_name << "(self, j, value):\n";
            ss << "        _encode_string(self.buffer, " << element_offset << ", "
               << layout.element->max_length << ", value)\n\n";
          }
          continue;
        }
        if (layout.kind == InlineLayout::Kind::kVector) {
          ss << "    def " << field_name << "Length(self):\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "        if not self.Has" << field_name << "():\n";
            ss << "            return 0\n";
          }
          ss << "        length = _read_uint32(self.buffer, " << field_offset << ")\n";
          ss << "        return min(length, " << layout.max_count << ")\n\n";
          ss << "    def Mutate" << field_name << "Length(self, length):\n";
          ss << "        length = max(0, min(int(length), " << layout.max_count << "))\n";
          ss << "        _write_uint32(self.buffer, " << field_offset << ", length)\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "        self.MutateHas" << field_name << "(True)\n";
          }
          ss << "\n";
          const std::string element_offset =
              field_offset + " + self." + UpperSnake(field.name) +
              "_DATA_OFFSET + j * self." + UpperSnake(field.name) + "_STRIDE";
          if (layout.element->kind == InlineLayout::Kind::kScalar) {
            ss << "    def " << field_name << "(self, j):\n";
            ss << "        return _read_"
               << LowerCase(ScalarHelperSuffix(layout.element->base_type))
               << "(self.buffer, " << element_offset << ")\n\n";
            ss << "    def Mutate" << field_name << "(self, j, value):\n";
            ss << "        _write_"
               << LowerCase(ScalarHelperSuffix(layout.element->base_type))
               << "(self.buffer, " << element_offset << ", value)\n";
            if (field.presence_index != FieldLayout::kNoPresence) {
              ss << "        self.MutateHas" << field_name << "(True)\n";
            }
            ss << "\n";
          } else if (layout.element->kind == InlineLayout::Kind::kRecord) {
            ss << "    def " << field_name << "(self, j):\n";
            ss << "        return " << layout.element->record->name
               << ".from_bytes(self.buffer, " << element_offset << ")\n\n";
          } else if (layout.element->kind == InlineLayout::Kind::kString) {
            ss << "    def " << field_name << "(self, j):\n";
            ss << "        return _decode_string(self.buffer, " << element_offset
               << ", " << layout.element->max_length << ")\n\n";
            ss << "    def Mutate" << field_name << "(self, j, value):\n";
            ss << "        _encode_string(self.buffer, " << element_offset << ", "
               << layout.element->max_length << ", value)\n";
            if (field.presence_index != FieldLayout::kNoPresence) {
              ss << "        self.MutateHas" << field_name << "(True)\n";
            }
            ss << "\n";
          } else if (layout.element->kind == InlineLayout::Kind::kUnion) {
            const std::string helper_name = UnionCellName(record, field);
            ss << "    def " << field_name << "(self, j):\n";
            ss << "        return " << helper_name
               << ".from_bytes(self.buffer, " << element_offset << ")\n\n";
          }
          continue;
        }
        if (layout.kind == InlineLayout::Kind::kUnion) {
          const std::string helper_name = UnionCellName(record, field);
          ss << "    def " << field_name << "Type(self):\n";
          ss << "        return _read_" << LowerCase(ScalarHelperSuffix(layout.base_type))
             << "(self.buffer, " << field_offset << " + "
             << layout.discriminator_offset << ")\n\n";
          ss << "    def Mutate" << field_name << "Type(self, value):\n";
          ss << "        _write_" << LowerCase(ScalarHelperSuffix(layout.base_type))
             << "(self.buffer, " << field_offset << " + "
             << layout.discriminator_offset << ", value)\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "        self.MutateHas" << field_name << "(True)\n";
          }
          ss << "\n";
          ss << "    def " << field_name << "(self):\n";
          ss << "        return " << helper_name << ".from_bytes(self.buffer, "
             << field_offset << ")\n\n";
        }
      }
    }

    return ss.str();
  }

  std::string GenerateRust() const {
    std::ostringstream ss;
    ss << "// Auto-generated aligned fixed-layout bindings.\n";
    ss << "// DO NOT EDIT - Generated by flatc --aligned\n\n";
    ss << "use std::convert::TryInto;\n";
    ss << "use std::marker::PhantomData;\n\n";
    ss << "fn __read_presence(buffer: &[u8], base: usize, bit_index: usize) -> bool {\n";
    ss << "    let byte_index = bit_index / 8;\n";
    ss << "    let mask = 1u8 << (bit_index % 8);\n";
    ss << "    (buffer[base + byte_index] & mask) != 0\n";
    ss << "}\n\n";
    ss << "fn __write_presence(buffer: &mut [u8], base: usize, bit_index: usize, value: bool) {\n";
    ss << "    let byte_index = bit_index / 8;\n";
    ss << "    let mask = 1u8 << (bit_index % 8);\n";
    ss << "    if value {\n";
    ss << "        buffer[base + byte_index] |= mask;\n";
    ss << "    } else {\n";
    ss << "        buffer[base + byte_index] &= !mask;\n";
    ss << "    }\n";
    ss << "}\n\n";
    ss << "fn __read_bool(buffer: &[u8], offset: usize) -> bool { buffer[offset] != 0 }\n";
    ss << "fn __write_bool(buffer: &mut [u8], offset: usize, value: bool) { buffer[offset] = if value { 1 } else { 0 }; }\n";
    ss << "fn __read_int8(buffer: &[u8], offset: usize) -> i8 { buffer[offset] as i8 }\n";
    ss << "fn __write_int8(buffer: &mut [u8], offset: usize, value: i8) { buffer[offset] = value as u8; }\n";
    ss << "fn __read_uint8(buffer: &[u8], offset: usize) -> u8 { buffer[offset] }\n";
    ss << "fn __write_uint8(buffer: &mut [u8], offset: usize, value: u8) { buffer[offset] = value; }\n";
    ss << "fn __read_int16(buffer: &[u8], offset: usize) -> i16 { i16::from_le_bytes(buffer[offset..offset + 2].try_into().unwrap()) }\n";
    ss << "fn __write_int16(buffer: &mut [u8], offset: usize, value: i16) { buffer[offset..offset + 2].copy_from_slice(&value.to_le_bytes()); }\n";
    ss << "fn __read_uint16(buffer: &[u8], offset: usize) -> u16 { u16::from_le_bytes(buffer[offset..offset + 2].try_into().unwrap()) }\n";
    ss << "fn __write_uint16(buffer: &mut [u8], offset: usize, value: u16) { buffer[offset..offset + 2].copy_from_slice(&value.to_le_bytes()); }\n";
    ss << "fn __read_int32(buffer: &[u8], offset: usize) -> i32 { i32::from_le_bytes(buffer[offset..offset + 4].try_into().unwrap()) }\n";
    ss << "fn __write_int32(buffer: &mut [u8], offset: usize, value: i32) { buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes()); }\n";
    ss << "fn __read_uint32(buffer: &[u8], offset: usize) -> u32 { u32::from_le_bytes(buffer[offset..offset + 4].try_into().unwrap()) }\n";
    ss << "fn __write_uint32(buffer: &mut [u8], offset: usize, value: u32) { buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes()); }\n";
    ss << "fn __read_int64(buffer: &[u8], offset: usize) -> i64 { i64::from_le_bytes(buffer[offset..offset + 8].try_into().unwrap()) }\n";
    ss << "fn __write_int64(buffer: &mut [u8], offset: usize, value: i64) { buffer[offset..offset + 8].copy_from_slice(&value.to_le_bytes()); }\n";
    ss << "fn __read_uint64(buffer: &[u8], offset: usize) -> u64 { u64::from_le_bytes(buffer[offset..offset + 8].try_into().unwrap()) }\n";
    ss << "fn __write_uint64(buffer: &mut [u8], offset: usize, value: u64) { buffer[offset..offset + 8].copy_from_slice(&value.to_le_bytes()); }\n";
    ss << "fn __read_float32(buffer: &[u8], offset: usize) -> f32 { f32::from_le_bytes(buffer[offset..offset + 4].try_into().unwrap()) }\n";
    ss << "fn __write_float32(buffer: &mut [u8], offset: usize, value: f32) { buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes()); }\n";
    ss << "fn __read_float64(buffer: &[u8], offset: usize) -> f64 { f64::from_le_bytes(buffer[offset..offset + 8].try_into().unwrap()) }\n";
    ss << "fn __write_float64(buffer: &mut [u8], offset: usize, value: f64) { buffer[offset..offset + 8].copy_from_slice(&value.to_le_bytes()); }\n\n";
    ss << "fn __decode_string(buffer: &[u8], offset: usize, max_length: usize) -> String {\n";
    ss << "    let length = usize::min(buffer[offset] as usize, max_length);\n";
    ss << "    String::from_utf8_lossy(&buffer[offset + 1..offset + 1 + length]).into_owned()\n";
    ss << "}\n\n";
    ss << "fn __encode_string(buffer: &mut [u8], offset: usize, max_length: usize, value: &str) {\n";
    ss << "    let raw = value.as_bytes();\n";
    ss << "    let length = usize::min(raw.len(), max_length);\n";
    ss << "    buffer[offset] = length as u8;\n";
    ss << "    buffer[offset + 1..offset + 1 + max_length].fill(0);\n";
    ss << "    buffer[offset + 1..offset + 1 + length].copy_from_slice(&raw[..length]);\n";
    ss << "}\n\n";

    for (size_t i = 0; i < schema_layout_.records.size(); ++i) {
      const RecordLayout& record = *schema_layout_.records[i];
      for (size_t f = 0; f < record.fields.size(); ++f) {
        const FieldLayout& field = record.fields[f];
        const InlineLayout& layout = *field.layout;
        if (!IsUnionLayout(layout) && !IsVectorOfUnionLayout(layout)) { continue; }
        const InlineLayout& union_layout = UnionLayoutForField(layout);
        const std::string helper_name = UnionCellName(record, field);
        ss << "#[derive(Copy, Clone)]\n";
        ss << "pub struct " << helper_name << "<'a> {\n";
        ss << "    ptr: *mut u8,\n";
        ss << "    len: usize,\n";
        ss << "    offset: usize,\n";
        ss << "    _marker: PhantomData<&'a mut [u8]>,\n";
        ss << "}\n\n";
        ss << "impl<'a> " << helper_name << "<'a> {\n";
        if (!union_layout.union_members.empty()) {
          for (size_t m = 0; m < union_layout.union_members.size(); ++m) {
            const UnionMemberLayout& member = union_layout.union_members[m];
            ss << "    pub const " << UpperSnake(member.value->name) << "_TYPE: "
               << RustScalarType(union_layout) << " = "
               << member.value->GetAsUInt64() << ";\n";
          }
          ss << "\n";
        }
        ss << "    fn from_raw_parts(ptr: *mut u8, len: usize, offset: usize) -> Self {\n";
        ss << "        Self { ptr, len, offset, _marker: PhantomData }\n";
        ss << "    }\n\n";
        ss << "    pub fn from_pointer(buffer: &'a mut [u8], offset: usize) -> Self {\n";
        ss << "        Self::from_raw_parts(buffer.as_mut_ptr(), buffer.len(), offset)\n";
        ss << "    }\n\n";
        ss << "    fn bytes(&self) -> &[u8] {\n";
        ss << "        unsafe { std::slice::from_raw_parts(self.ptr as *const u8, self.len) }\n";
        ss << "    }\n\n";
        ss << "    fn bytes_mut(&mut self) -> &mut [u8] {\n";
        ss << "        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }\n";
        ss << "    }\n\n";
        ss << "    pub fn type_(&self) -> " << RustScalarType(union_layout) << " {\n";
        ss << "        __read_" << LowerCase(ScalarHelperSuffix(union_layout.base_type))
           << "(self.bytes(), self.offset + " << union_layout.discriminator_offset
           << ")\n";
        ss << "    }\n\n";
        ss << "    pub fn mutate_type(&mut self, value: " << RustScalarType(union_layout)
           << ") {\n";
        ss << "        let offset = self.offset + "
           << union_layout.discriminator_offset << ";\n";
        ss << "        __write_" << LowerCase(ScalarHelperSuffix(union_layout.base_type))
           << "(self.bytes_mut(), offset, value);\n";
        ss << "    }\n";
        for (size_t m = 0; m < union_layout.union_members.size(); ++m) {
          const UnionMemberLayout& member = union_layout.union_members[m];
          const InlineLayout& member_layout = *member.layout;
          const std::string member_fn = LowerCamelCase(member.value->name);
          const std::string payload_offset =
              "self.offset + " + NumToString(union_layout.payload_offset);
          ss << "\n";
          ss << "    pub fn is_" << member_fn << "(&self) -> bool {\n";
          ss << "        self.type_() == Self::" << UpperSnake(member.value->name)
             << "_TYPE\n";
          ss << "    }\n";
          if (member_layout.kind == InlineLayout::Kind::kScalar) {
            ss << "\n";
            ss << "    pub fn " << member_fn << "(&self) -> "
               << RustScalarType(member_layout) << " {\n";
            ss << "        __read_" << LowerCase(ScalarHelperSuffix(member_layout.base_type))
               << "(self.bytes(), " << payload_offset << ")\n";
            ss << "    }\n";
            ss << "\n";
            ss << "    pub fn mutate_" << member_fn << "(&mut self, value: "
               << RustScalarType(member_layout) << ") {\n";
            ss << "        let offset = " << payload_offset << ";\n";
            ss << "        __write_" << LowerCase(ScalarHelperSuffix(member_layout.base_type))
               << "(self.bytes_mut(), offset, value);\n";
            ss << "        self.mutate_type(Self::" << UpperSnake(member.value->name)
               << "_TYPE);\n";
            ss << "    }\n";
          } else if (member_layout.kind == InlineLayout::Kind::kRecord) {
            ss << "\n";
            ss << "    pub fn " << member_fn << "(&self) -> "
               << member_layout.record->name << "<'a> {\n";
            ss << "        " << member_layout.record->name
               << "::from_raw_parts(self.ptr, self.len, " << payload_offset << ")\n";
            ss << "    }\n";
            ss << "\n";
            ss << "    pub fn mutate_" << member_fn << "_from(&mut self, src: "
               << member_layout.record->name << "<'a>) {\n";
            ss << "        let start = " << payload_offset << ";\n";
            ss << "        let end = start + " << member_layout.size << ";\n";
            ss << "        self.bytes_mut()[start..end].copy_from_slice(&src.bytes()[src.offset..src.offset + "
               << member_layout.size << "]);\n";
            ss << "        self.mutate_type(Self::" << UpperSnake(member.value->name)
               << "_TYPE);\n";
            ss << "    }\n";
          } else if (member_layout.kind == InlineLayout::Kind::kString) {
            ss << "\n";
            ss << "    pub fn " << member_fn << "(&self) -> String {\n";
            ss << "        __decode_string(self.bytes(), " << payload_offset << ", "
               << member_layout.max_length << ")\n";
            ss << "    }\n";
            ss << "\n";
            ss << "    pub fn mutate_" << member_fn
               << "(&mut self, value: &str) {\n";
            ss << "        let offset = " << payload_offset << ";\n";
            ss << "        __encode_string(self.bytes_mut(), offset, "
               << member_layout.max_length << ", value);\n";
            ss << "        self.mutate_type(Self::" << UpperSnake(member.value->name)
               << "_TYPE);\n";
            ss << "    }\n";
          }
        }
        ss << "}\n\n";
      }

      ss << "#[derive(Copy, Clone)]\n";
      ss << "pub struct " << record.name << "<'a> {\n";
      ss << "    ptr: *mut u8,\n";
      ss << "    len: usize,\n";
      ss << "    offset: usize,\n";
      ss << "    _marker: PhantomData<&'a mut [u8]>,\n";
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
      ss << "    fn from_raw_parts(ptr: *mut u8, len: usize, offset: usize) -> Self {\n";
      ss << "        Self { ptr, len, offset, _marker: PhantomData }\n";
      ss << "    }\n\n";
      ss << "    pub fn from_pointer(buffer: &'a mut [u8], offset: usize) -> Self {\n";
      ss << "        Self::from_raw_parts(buffer.as_mut_ptr(), buffer.len(), offset)\n";
      ss << "    }\n\n";
      ss << "    fn bytes(&self) -> &[u8] {\n";
      ss << "        unsafe { std::slice::from_raw_parts(self.ptr as *const u8, self.len) }\n";
      ss << "    }\n\n";
      ss << "    fn bytes_mut(&mut self) -> &mut [u8] {\n";
      ss << "        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }\n";
      ss << "    }\n";
      for (size_t f = 0; f < record.fields.size(); ++f) {
        const FieldLayout& field = record.fields[f];
        const InlineLayout& layout = *field.layout;
        const std::string field_name = field.name;
        const std::string field_offset =
            "self.offset + Self::" + UpperSnake(field.name) + "_OFFSET";
        if (field.presence_index != FieldLayout::kNoPresence) {
          ss << "\n";
          ss << "    pub fn has_" << field_name << "(&self) -> bool {\n";
          ss << "        __read_presence(self.bytes(), self.offset, Self::"
             << UpperSnake(field.name) << "_PRESENCE_BIT)\n";
          ss << "    }\n";
          ss << "\n";
          ss << "    pub fn mutate_has_" << field_name << "(&mut self, value: bool) {\n";
          ss << "        let base = self.offset;\n";
          ss << "        __write_presence(self.bytes_mut(), base, Self::"
             << UpperSnake(field.name) << "_PRESENCE_BIT, value);\n";
          ss << "    }\n";
        }
        if (layout.kind == InlineLayout::Kind::kScalar) {
          ss << "\n";
          ss << "    pub fn " << field_name << "(&self) -> "
             << RustScalarType(layout) << " {\n";
          ss << "        __read_" << LowerCase(ScalarHelperSuffix(layout.base_type))
             << "(self.bytes(), " << field_offset << ")\n";
          ss << "    }\n";
          ss << "\n";
          ss << "    pub fn mutate_" << field_name << "(&mut self, value: "
             << RustScalarType(layout) << ") {\n";
          ss << "        let offset = " << field_offset << ";\n";
          ss << "        __write_" << LowerCase(ScalarHelperSuffix(layout.base_type))
             << "(self.bytes_mut(), offset, value);\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "        self.mutate_has_" << field_name << "(true);\n";
          }
          ss << "    }\n";
          continue;
        }
        if (layout.kind == InlineLayout::Kind::kRecord) {
          ss << "\n";
          ss << "    pub fn " << field_name << "(&self) -> "
             << layout.record->name << "<'a> {\n";
          ss << "        " << layout.record->name
             << "::from_raw_parts(self.ptr, self.len, " << field_offset << ")\n";
          ss << "    }\n";
          continue;
        }
        if (layout.kind == InlineLayout::Kind::kString) {
          ss << "\n";
          ss << "    pub fn " << field_name << "(&self) -> String {\n";
          ss << "        __decode_string(self.bytes(), " << field_offset << ", "
             << layout.max_length << ")\n";
          ss << "    }\n";
          ss << "\n";
          ss << "    pub fn mutate_" << field_name
             << "(&mut self, value: &str) {\n";
          ss << "        let offset = " << field_offset << ";\n";
          ss << "        __encode_string(self.bytes_mut(), offset, "
             << layout.max_length << ", value);\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "        self.mutate_has_" << field_name << "(true);\n";
          }
          ss << "    }\n";
          continue;
        }
        if (layout.kind == InlineLayout::Kind::kArray) {
          const std::string element_offset =
              field_offset + " + j * " + NumToString(layout.stride);
          ss << "\n";
          ss << "    pub fn " << field_name << "_length(&self) -> usize {\n";
          ss << "        " << layout.fixed_length << "\n";
          ss << "    }\n";
          if (layout.element->kind == InlineLayout::Kind::kScalar) {
            ss << "\n";
            ss << "    pub fn " << field_name << "(&self, j: usize) -> "
               << RustScalarType(*layout.element) << " {\n";
            ss << "        __read_"
               << LowerCase(ScalarHelperSuffix(layout.element->base_type))
               << "(self.bytes(), " << element_offset << ")\n";
            ss << "    }\n";
            ss << "\n";
            ss << "    pub fn mutate_" << field_name << "(&mut self, j: usize, value: "
               << RustScalarType(*layout.element) << ") {\n";
            ss << "        let offset = " << element_offset << ";\n";
            ss << "        __write_"
               << LowerCase(ScalarHelperSuffix(layout.element->base_type))
               << "(self.bytes_mut(), offset, value);\n";
            ss << "    }\n";
          } else if (layout.element->kind == InlineLayout::Kind::kRecord) {
            ss << "\n";
            ss << "    pub fn " << field_name << "(&self, j: usize) -> "
               << layout.element->record->name << "<'a> {\n";
            ss << "        " << layout.element->record->name
               << "::from_raw_parts(self.ptr, self.len, " << element_offset << ")\n";
            ss << "    }\n";
          } else if (layout.element->kind == InlineLayout::Kind::kString) {
            ss << "\n";
            ss << "    pub fn " << field_name << "(&self, j: usize) -> String {\n";
            ss << "        __decode_string(self.bytes(), " << element_offset << ", "
               << layout.element->max_length << ")\n";
            ss << "    }\n";
            ss << "\n";
            ss << "    pub fn mutate_" << field_name
               << "(&mut self, j: usize, value: &str) {\n";
            ss << "        let offset = " << element_offset << ";\n";
            ss << "        __encode_string(self.bytes_mut(), offset, "
               << layout.element->max_length << ", value);\n";
            ss << "    }\n";
          }
          continue;
        }
        if (layout.kind == InlineLayout::Kind::kVector) {
          const std::string element_offset =
              field_offset + " + Self::" + UpperSnake(field.name) +
              "_DATA_OFFSET + j * Self::" + UpperSnake(field.name) + "_STRIDE";
          ss << "\n";
          ss << "    pub fn " << field_name << "_length(&self) -> usize {\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "        if !self.has_" << field_name << "() { return 0; }\n";
          }
          ss << "        usize::min(__read_uint32(self.bytes(), " << field_offset
             << ") as usize, " << layout.max_count << ")\n";
          ss << "    }\n";
          ss << "\n";
          ss << "    pub fn mutate_" << field_name
             << "_length(&mut self, length: usize) {\n";
          ss << "        let offset = " << field_offset << ";\n";
          ss << "        __write_uint32(self.bytes_mut(), offset, usize::min(length, "
             << layout.max_count << ") as u32);\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "        self.mutate_has_" << field_name << "(true);\n";
          }
          ss << "    }\n";
          if (layout.element->kind == InlineLayout::Kind::kScalar) {
            ss << "\n";
            ss << "    pub fn " << field_name << "(&self, j: usize) -> "
               << RustScalarType(*layout.element) << " {\n";
            ss << "        __read_"
               << LowerCase(ScalarHelperSuffix(layout.element->base_type))
               << "(self.bytes(), " << element_offset << ")\n";
            ss << "    }\n";
            ss << "\n";
            ss << "    pub fn mutate_" << field_name << "(&mut self, j: usize, value: "
               << RustScalarType(*layout.element) << ") {\n";
            ss << "        let offset = " << element_offset << ";\n";
            ss << "        __write_"
               << LowerCase(ScalarHelperSuffix(layout.element->base_type))
               << "(self.bytes_mut(), offset, value);\n";
            if (field.presence_index != FieldLayout::kNoPresence) {
              ss << "        self.mutate_has_" << field_name << "(true);\n";
            }
            ss << "    }\n";
          } else if (layout.element->kind == InlineLayout::Kind::kRecord) {
            ss << "\n";
            ss << "    pub fn " << field_name << "(&self, j: usize) -> "
               << layout.element->record->name << "<'a> {\n";
            ss << "        " << layout.element->record->name
               << "::from_raw_parts(self.ptr, self.len, " << element_offset << ")\n";
            ss << "    }\n";
          } else if (layout.element->kind == InlineLayout::Kind::kString) {
            ss << "\n";
            ss << "    pub fn " << field_name << "(&self, j: usize) -> String {\n";
            ss << "        __decode_string(self.bytes(), " << element_offset << ", "
               << layout.element->max_length << ")\n";
            ss << "    }\n";
            ss << "\n";
            ss << "    pub fn mutate_" << field_name
               << "(&mut self, j: usize, value: &str) {\n";
            ss << "        let offset = " << element_offset << ";\n";
            ss << "        __encode_string(self.bytes_mut(), offset, "
               << layout.element->max_length << ", value);\n";
            if (field.presence_index != FieldLayout::kNoPresence) {
              ss << "        self.mutate_has_" << field_name << "(true);\n";
            }
            ss << "    }\n";
          } else if (layout.element->kind == InlineLayout::Kind::kUnion) {
            const std::string helper_name = UnionCellName(record, field);
            ss << "\n";
            ss << "    pub fn " << field_name << "(&self, j: usize) -> "
               << helper_name << "<'a> {\n";
            ss << "        " << helper_name
               << "::from_raw_parts(self.ptr, self.len, " << element_offset << ")\n";
            ss << "    }\n";
          }
          continue;
        }
        if (layout.kind == InlineLayout::Kind::kUnion) {
          const std::string helper_name = UnionCellName(record, field);
          ss << "\n";
          ss << "    pub fn " << field_name << "_type(&self) -> "
             << RustScalarType(layout) << " {\n";
          ss << "        __read_" << LowerCase(ScalarHelperSuffix(layout.base_type))
             << "(self.bytes(), " << field_offset << " + "
             << layout.discriminator_offset << ")\n";
          ss << "    }\n";
          ss << "\n";
          ss << "    pub fn mutate_" << field_name << "_type(&mut self, value: "
             << RustScalarType(layout) << ") {\n";
          ss << "        let offset = " << field_offset << " + "
             << layout.discriminator_offset << ";\n";
          ss << "        __write_" << LowerCase(ScalarHelperSuffix(layout.base_type))
             << "(self.bytes_mut(), offset, value);\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "        self.mutate_has_" << field_name << "(true);\n";
          }
          ss << "    }\n";
          ss << "\n";
          ss << "    pub fn " << field_name << "(&self) -> " << helper_name
             << "<'a> {\n";
          ss << "        " << helper_name << "::from_raw_parts(self.ptr, self.len, "
             << field_offset << ")\n";
          ss << "    }\n";
        }
      }
      ss << "}\n\n";
    }

    return ss.str();
  }

  std::string GenerateJava() const {
    std::ostringstream ss;
    ss << "// Auto-generated aligned fixed-layout bindings.\n";
    ss << "// DO NOT EDIT - Generated by flatc --aligned\n\n";
    ss << "import java.nio.charset.StandardCharsets;\n\n";
    ss << "final class AlignedSupport {\n";
    ss << "  static boolean readPresence(byte[] buffer, int base, int bitIndex) {\n";
    ss << "    final int byteIndex = bitIndex / 8;\n";
    ss << "    final int mask = 1 << (bitIndex % 8);\n";
    ss << "    return (buffer[base + byteIndex] & mask) != 0;\n";
    ss << "  }\n";
    ss << "  static void writePresence(byte[] buffer, int base, int bitIndex, boolean value) {\n";
    ss << "    final int byteIndex = bitIndex / 8;\n";
    ss << "    final int mask = 1 << (bitIndex % 8);\n";
    ss << "    if (value) buffer[base + byteIndex] = (byte)(buffer[base + byteIndex] | mask);\n";
    ss << "    else buffer[base + byteIndex] = (byte)(buffer[base + byteIndex] & ~mask);\n";
    ss << "  }\n";
    ss << "  static boolean readBool(byte[] buffer, int offset) { return buffer[offset] != 0; }\n";
    ss << "  static void writeBool(byte[] buffer, int offset, boolean value) { buffer[offset] = (byte)(value ? 1 : 0); }\n";
    ss << "  static byte readInt8(byte[] buffer, int offset) { return buffer[offset]; }\n";
    ss << "  static void writeInt8(byte[] buffer, int offset, byte value) { buffer[offset] = value; }\n";
    ss << "  static short readUInt8(byte[] buffer, int offset) { return (short)(buffer[offset] & 0xFF); }\n";
    ss << "  static void writeUInt8(byte[] buffer, int offset, short value) { buffer[offset] = (byte)(value & 0xFF); }\n";
    ss << "  static short readInt16(byte[] buffer, int offset) {\n";
    ss << "    return (short)(((buffer[offset + 1] & 0xFF) << 8) | (buffer[offset] & 0xFF));\n";
    ss << "  }\n";
    ss << "  static void writeInt16(byte[] buffer, int offset, short value) {\n";
    ss << "    buffer[offset] = (byte)(value & 0xFF);\n";
    ss << "    buffer[offset + 1] = (byte)((value >>> 8) & 0xFF);\n";
    ss << "  }\n";
    ss << "  static int readUInt16(byte[] buffer, int offset) {\n";
    ss << "    return ((buffer[offset + 1] & 0xFF) << 8) | (buffer[offset] & 0xFF);\n";
    ss << "  }\n";
    ss << "  static void writeUInt16(byte[] buffer, int offset, int value) {\n";
    ss << "    buffer[offset] = (byte)(value & 0xFF);\n";
    ss << "    buffer[offset + 1] = (byte)((value >>> 8) & 0xFF);\n";
    ss << "  }\n";
    ss << "  static int readInt32(byte[] buffer, int offset) {\n";
    ss << "    return ((buffer[offset + 3] & 0xFF) << 24) | ((buffer[offset + 2] & 0xFF) << 16) | ((buffer[offset + 1] & 0xFF) << 8) | (buffer[offset] & 0xFF);\n";
    ss << "  }\n";
    ss << "  static void writeInt32(byte[] buffer, int offset, int value) {\n";
    ss << "    buffer[offset] = (byte)(value & 0xFF);\n";
    ss << "    buffer[offset + 1] = (byte)((value >>> 8) & 0xFF);\n";
    ss << "    buffer[offset + 2] = (byte)((value >>> 16) & 0xFF);\n";
    ss << "    buffer[offset + 3] = (byte)((value >>> 24) & 0xFF);\n";
    ss << "  }\n";
    ss << "  static long readUInt32(byte[] buffer, int offset) { return readInt32(buffer, offset) & 0xFFFFFFFFL; }\n";
    ss << "  static void writeUInt32(byte[] buffer, int offset, long value) { writeInt32(buffer, offset, (int)(value & 0xFFFFFFFFL)); }\n";
    ss << "  static long readInt64(byte[] buffer, int offset) {\n";
    ss << "    return ((long)(buffer[offset + 7] & 0xFF) << 56) | ((long)(buffer[offset + 6] & 0xFF) << 48) | ((long)(buffer[offset + 5] & 0xFF) << 40) | ((long)(buffer[offset + 4] & 0xFF) << 32) | ((long)(buffer[offset + 3] & 0xFF) << 24) | ((long)(buffer[offset + 2] & 0xFF) << 16) | ((long)(buffer[offset + 1] & 0xFF) << 8) | ((long)(buffer[offset] & 0xFF));\n";
    ss << "  }\n";
    ss << "  static void writeInt64(byte[] buffer, int offset, long value) {\n";
    ss << "    for (int i = 0; i < 8; ++i) buffer[offset + i] = (byte)((value >>> (i * 8)) & 0xFF);\n";
    ss << "  }\n";
    ss << "  static long readUInt64(byte[] buffer, int offset) { return readInt64(buffer, offset); }\n";
    ss << "  static void writeUInt64(byte[] buffer, int offset, long value) { writeInt64(buffer, offset, value); }\n";
    ss << "  static float readFloat32(byte[] buffer, int offset) { return Float.intBitsToFloat(readInt32(buffer, offset)); }\n";
    ss << "  static void writeFloat32(byte[] buffer, int offset, float value) { writeInt32(buffer, offset, Float.floatToRawIntBits(value)); }\n";
    ss << "  static double readFloat64(byte[] buffer, int offset) { return Double.longBitsToDouble(readInt64(buffer, offset)); }\n";
    ss << "  static void writeFloat64(byte[] buffer, int offset, double value) { writeInt64(buffer, offset, Double.doubleToRawLongBits(value)); }\n";
    ss << "  static String decodeString(byte[] buffer, int offset, int maxLength) {\n";
    ss << "    final int length = Math.min(buffer[offset] & 0xFF, maxLength);\n";
    ss << "    return new String(buffer, offset + 1, length, StandardCharsets.UTF_8);\n";
    ss << "  }\n";
    ss << "  static void encodeString(byte[] buffer, int offset, int maxLength, String value) {\n";
    ss << "    final byte[] raw = value.getBytes(StandardCharsets.UTF_8);\n";
    ss << "    final int length = Math.min(raw.length, maxLength);\n";
    ss << "    buffer[offset] = (byte)length;\n";
    ss << "    for (int i = 0; i < maxLength; ++i) buffer[offset + 1 + i] = 0;\n";
    ss << "    System.arraycopy(raw, 0, buffer, offset + 1, length);\n";
    ss << "  }\n";
    ss << "}\n\n";

    for (size_t i = 0; i < schema_layout_.records.size(); ++i) {
      const RecordLayout& record = *schema_layout_.records[i];
      for (size_t f = 0; f < record.fields.size(); ++f) {
        const FieldLayout& field = record.fields[f];
        const InlineLayout& layout = *field.layout;
        if (!IsUnionLayout(layout) && !IsVectorOfUnionLayout(layout)) { continue; }
        const InlineLayout& union_layout = UnionLayoutForField(layout);
        const std::string helper_name = UnionCellName(record, field);
        ss << "final class " << helper_name << " {\n";
        if (!union_layout.union_members.empty()) {
          for (size_t m = 0; m < union_layout.union_members.size(); ++m) {
            const UnionMemberLayout& member = union_layout.union_members[m];
            ss << "  static final " << JavaScalarType(union_layout) << " "
               << UpperSnake(member.value->name) << "_TYPE = "
               << member.value->GetAsUInt64() << ";\n";
          }
          ss << "\n";
        }
        ss << "  final byte[] buffer;\n";
        ss << "  final int offset;\n\n";
        ss << "  private " << helper_name << "(byte[] buffer, int offset) {\n";
        ss << "    this.buffer = buffer;\n";
        ss << "    this.offset = offset;\n";
        ss << "  }\n\n";
        ss << "  static " << helper_name
           << " fromPointer(byte[] buffer, int offset) {\n";
        ss << "    return new " << helper_name << "(buffer, offset);\n";
        ss << "  }\n\n";
        ss << "  " << JavaScalarType(union_layout) << " type() {\n";
        ss << "    return AlignedSupport.read" << ScalarHelperSuffix(union_layout.base_type)
           << "(buffer, offset + " << union_layout.discriminator_offset << ");\n";
        ss << "  }\n\n";
        ss << "  void mutateType(" << JavaScalarType(union_layout)
           << " value) {\n";
        ss << "    AlignedSupport.write" << ScalarHelperSuffix(union_layout.base_type)
           << "(buffer, offset + " << union_layout.discriminator_offset
           << ", value);\n";
        ss << "  }\n";
        for (size_t m = 0; m < union_layout.union_members.size(); ++m) {
          const UnionMemberLayout& member = union_layout.union_members[m];
          const InlineLayout& member_layout = *member.layout;
          const std::string member_name = LowerCamelCase(member.value->name);
          const std::string payload_offset =
              "offset + " + NumToString(union_layout.payload_offset);
          ss << "\n";
          ss << "  boolean is" << PascalCase(member.value->name) << "() {\n";
          ss << "    return type() == " << UpperSnake(member.value->name) << "_TYPE;\n";
          ss << "  }\n";
          if (member_layout.kind == InlineLayout::Kind::kScalar) {
            ss << "\n";
            ss << "  " << JavaScalarType(member_layout) << " " << member_name
               << "() {\n";
            ss << "    return AlignedSupport.read" << ScalarHelperSuffix(member_layout.base_type)
               << "(buffer, " << payload_offset << ");\n";
            ss << "  }\n\n";
            ss << "  void mutate" << PascalCase(member.value->name) << "("
               << JavaScalarType(member_layout) << " value) {\n";
            ss << "    AlignedSupport.write" << ScalarHelperSuffix(member_layout.base_type)
               << "(buffer, " << payload_offset << ", value);\n";
            ss << "    mutateType(" << UpperSnake(member.value->name) << "_TYPE);\n";
            ss << "  }\n";
          } else if (member_layout.kind == InlineLayout::Kind::kRecord) {
            ss << "\n";
            ss << "  " << member_layout.record->name << " " << member_name << "() {\n";
            ss << "    return " << member_layout.record->name
               << ".fromPointer(buffer, " << payload_offset << ");\n";
            ss << "  }\n\n";
            ss << "  void mutate" << PascalCase(member.value->name) << "From("
               << member_layout.record->name << " src) {\n";
            ss << "    System.arraycopy(src.buffer, src.offset, buffer, "
               << payload_offset << ", " << member_layout.size << ");\n";
            ss << "    mutateType(" << UpperSnake(member.value->name) << "_TYPE);\n";
            ss << "  }\n";
          } else if (member_layout.kind == InlineLayout::Kind::kString) {
            ss << "\n";
            ss << "  String " << member_name << "() {\n";
            ss << "    return AlignedSupport.decodeString(buffer, " << payload_offset
               << ", " << member_layout.max_length << ");\n";
            ss << "  }\n\n";
            ss << "  void mutate" << PascalCase(member.value->name)
               << "(String value) {\n";
            ss << "    AlignedSupport.encodeString(buffer, " << payload_offset
               << ", " << member_layout.max_length << ", value);\n";
            ss << "    mutateType(" << UpperSnake(member.value->name) << "_TYPE);\n";
            ss << "  }\n";
          }
        }
        ss << "}\n\n";
      }

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
      ss << "  final byte[] buffer;\n";
      ss << "  final int offset;\n\n";
      ss << "  private " << record.name << "(byte[] buffer, int offset) {\n";
      ss << "    this.buffer = buffer;\n";
      ss << "    this.offset = offset;\n";
      ss << "  }\n\n";
      ss << "  static " << record.name
         << " fromPointer(byte[] buffer, int offset) {\n";
      ss << "    return new " << record.name << "(buffer, offset);\n";
      ss << "  }\n";
      for (size_t f = 0; f < record.fields.size(); ++f) {
        const FieldLayout& field = record.fields[f];
        const InlineLayout& layout = *field.layout;
        const std::string field_name = LowerCamelCase(field.name);
        const std::string field_offset =
            "offset + " + UpperSnake(field.name) + "_OFFSET";
        if (field.presence_index != FieldLayout::kNoPresence) {
          ss << "\n";
          ss << "  boolean has" << PascalCase(field.name) << "() {\n";
          ss << "    return AlignedSupport.readPresence(buffer, offset, "
             << UpperSnake(field.name) << "_PRESENCE_BIT);\n";
          ss << "  }\n\n";
          ss << "  void mutateHas" << PascalCase(field.name)
             << "(boolean value) {\n";
          ss << "    AlignedSupport.writePresence(buffer, offset, "
             << UpperSnake(field.name) << "_PRESENCE_BIT, value);\n";
          ss << "  }\n";
        }
        if (layout.kind == InlineLayout::Kind::kScalar) {
          ss << "\n";
          ss << "  " << JavaScalarType(layout) << " " << field_name << "() {\n";
          ss << "    return AlignedSupport.read" << ScalarHelperSuffix(layout.base_type)
             << "(buffer, " << field_offset << ");\n";
          ss << "  }\n\n";
          ss << "  void mutate" << PascalCase(field.name) << "("
             << JavaScalarType(layout) << " value) {\n";
          ss << "    AlignedSupport.write" << ScalarHelperSuffix(layout.base_type)
             << "(buffer, " << field_offset << ", value);\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "    mutateHas" << PascalCase(field.name) << "(true);\n";
          }
          ss << "  }\n";
          continue;
        }
        if (layout.kind == InlineLayout::Kind::kRecord) {
          ss << "\n";
          ss << "  " << layout.record->name << " " << field_name << "() {\n";
          ss << "    return " << layout.record->name << ".fromPointer(buffer, "
             << field_offset << ");\n";
          ss << "  }\n";
          continue;
        }
        if (layout.kind == InlineLayout::Kind::kString) {
          ss << "\n";
          ss << "  String " << field_name << "() {\n";
          ss << "    return AlignedSupport.decodeString(buffer, " << field_offset
             << ", " << layout.max_length << ");\n";
          ss << "  }\n\n";
          ss << "  void mutate" << PascalCase(field.name)
             << "(String value) {\n";
          ss << "    AlignedSupport.encodeString(buffer, " << field_offset << ", "
             << layout.max_length << ", value);\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "    mutateHas" << PascalCase(field.name) << "(true);\n";
          }
          ss << "  }\n";
          continue;
        }
        if (layout.kind == InlineLayout::Kind::kArray) {
          const std::string element_offset =
              field_offset + " + j * " + NumToString(layout.stride);
          ss << "\n";
          ss << "  int " << field_name << "Length() {\n";
          ss << "    return " << layout.fixed_length << ";\n";
          ss << "  }\n";
          if (layout.element->kind == InlineLayout::Kind::kScalar) {
            ss << "\n";
            ss << "  " << JavaScalarType(*layout.element) << " " << field_name
               << "(int j) {\n";
            ss << "    return AlignedSupport.read"
               << ScalarHelperSuffix(layout.element->base_type)
               << "(buffer, " << element_offset << ");\n";
            ss << "  }\n\n";
            ss << "  void mutate" << PascalCase(field.name) << "(int j, "
               << JavaScalarType(*layout.element) << " value) {\n";
            ss << "    AlignedSupport.write"
               << ScalarHelperSuffix(layout.element->base_type)
               << "(buffer, " << element_offset << ", value);\n";
            ss << "  }\n";
          } else if (layout.element->kind == InlineLayout::Kind::kRecord) {
            ss << "\n";
            ss << "  " << layout.element->record->name << " " << field_name
               << "(int j) {\n";
            ss << "    return " << layout.element->record->name
               << ".fromPointer(buffer, " << element_offset << ");\n";
            ss << "  }\n";
          } else if (layout.element->kind == InlineLayout::Kind::kString) {
            ss << "\n";
            ss << "  String " << field_name << "(int j) {\n";
            ss << "    return AlignedSupport.decodeString(buffer, " << element_offset
               << ", " << layout.element->max_length << ");\n";
            ss << "  }\n\n";
            ss << "  void mutate" << PascalCase(field.name)
               << "(int j, String value) {\n";
            ss << "    AlignedSupport.encodeString(buffer, " << element_offset
               << ", " << layout.element->max_length << ", value);\n";
            ss << "  }\n";
          }
          continue;
        }
        if (layout.kind == InlineLayout::Kind::kVector) {
          const std::string element_offset =
              field_offset + " + " + UpperSnake(field.name) +
              "_DATA_OFFSET + j * " + UpperSnake(field.name) + "_STRIDE";
          ss << "\n";
          ss << "  int " << field_name << "Length() {\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "    if (!has" << PascalCase(field.name) << "()) return 0;\n";
          }
          ss << "    return Math.min((int)AlignedSupport.readUInt32(buffer, "
             << field_offset << "), " << layout.max_count << ");\n";
          ss << "  }\n\n";
          ss << "  void mutate" << PascalCase(field.name)
             << "Length(int length) {\n";
          ss << "    AlignedSupport.writeUInt32(buffer, " << field_offset
             << ", Math.min(Math.max(length, 0), " << layout.max_count << "));\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "    mutateHas" << PascalCase(field.name) << "(true);\n";
          }
          ss << "  }\n";
          if (layout.element->kind == InlineLayout::Kind::kScalar) {
            ss << "\n";
            ss << "  " << JavaScalarType(*layout.element) << " " << field_name
               << "(int j) {\n";
            ss << "    return AlignedSupport.read"
               << ScalarHelperSuffix(layout.element->base_type)
               << "(buffer, " << element_offset << ");\n";
            ss << "  }\n\n";
            ss << "  void mutate" << PascalCase(field.name) << "(int j, "
               << JavaScalarType(*layout.element) << " value) {\n";
            ss << "    AlignedSupport.write"
               << ScalarHelperSuffix(layout.element->base_type)
               << "(buffer, " << element_offset << ", value);\n";
            if (field.presence_index != FieldLayout::kNoPresence) {
              ss << "    mutateHas" << PascalCase(field.name) << "(true);\n";
            }
            ss << "  }\n";
          } else if (layout.element->kind == InlineLayout::Kind::kRecord) {
            ss << "\n";
            ss << "  " << layout.element->record->name << " " << field_name
               << "(int j) {\n";
            ss << "    return " << layout.element->record->name
               << ".fromPointer(buffer, " << element_offset << ");\n";
            ss << "  }\n";
          } else if (layout.element->kind == InlineLayout::Kind::kString) {
            ss << "\n";
            ss << "  String " << field_name << "(int j) {\n";
            ss << "    return AlignedSupport.decodeString(buffer, " << element_offset
               << ", " << layout.element->max_length << ");\n";
            ss << "  }\n\n";
            ss << "  void mutate" << PascalCase(field.name)
               << "(int j, String value) {\n";
            ss << "    AlignedSupport.encodeString(buffer, " << element_offset
               << ", " << layout.element->max_length << ", value);\n";
            if (field.presence_index != FieldLayout::kNoPresence) {
              ss << "    mutateHas" << PascalCase(field.name) << "(true);\n";
            }
            ss << "  }\n";
          } else if (layout.element->kind == InlineLayout::Kind::kUnion) {
            const std::string helper_name = UnionCellName(record, field);
            ss << "\n";
            ss << "  " << helper_name << " " << field_name << "(int j) {\n";
            ss << "    return " << helper_name << ".fromPointer(buffer, "
               << element_offset << ");\n";
            ss << "  }\n";
          }
          continue;
        }
        if (layout.kind == InlineLayout::Kind::kUnion) {
          const std::string helper_name = UnionCellName(record, field);
          ss << "\n";
          ss << "  " << JavaScalarType(layout) << " " << field_name << "Type() {\n";
          ss << "    return AlignedSupport.read" << ScalarHelperSuffix(layout.base_type)
             << "(buffer, " << field_offset << " + "
             << layout.discriminator_offset << ");\n";
          ss << "  }\n\n";
          ss << "  void mutate" << PascalCase(field.name) << "Type("
             << JavaScalarType(layout) << " value) {\n";
          ss << "    AlignedSupport.write" << ScalarHelperSuffix(layout.base_type)
             << "(buffer, " << field_offset << " + "
             << layout.discriminator_offset << ", value);\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "    mutateHas" << PascalCase(field.name) << "(true);\n";
          }
          ss << "  }\n\n";
          ss << "  " << helper_name << " " << field_name << "() {\n";
          ss << "    return " << helper_name << ".fromPointer(buffer, "
             << field_offset << ");\n";
          ss << "  }\n";
        }
      }
      ss << "}\n\n";
    }

    return ss.str();
  }

  std::string GenerateCSharp() const {
    std::ostringstream ss;
    ss << "// Auto-generated aligned fixed-layout bindings.\n";
    ss << "// DO NOT EDIT - Generated by flatc --aligned\n\n";
    ss << "using System;\n";
    ss << "using System.Buffers.Binary;\n";
    ss << "using System.Text;\n\n";
    ss << "internal static class AlignedSupport {\n";
    ss << "  internal static bool ReadPresence(byte[] buffer, int baseOffset, int bitIndex) {\n";
    ss << "    var byteIndex = bitIndex / 8;\n";
    ss << "    var mask = (byte)(1 << (bitIndex % 8));\n";
    ss << "    return (buffer[baseOffset + byteIndex] & mask) != 0;\n";
    ss << "  }\n";
    ss << "  internal static void WritePresence(byte[] buffer, int baseOffset, int bitIndex, bool value) {\n";
    ss << "    var byteIndex = bitIndex / 8;\n";
    ss << "    var mask = (byte)(1 << (bitIndex % 8));\n";
    ss << "    buffer[baseOffset + byteIndex] = value\n";
    ss << "        ? (byte)(buffer[baseOffset + byteIndex] | mask)\n";
    ss << "        : (byte)(buffer[baseOffset + byteIndex] & ~mask);\n";
    ss << "  }\n";
    ss << "  internal static bool ReadBool(byte[] buffer, int offset) => buffer[offset] != 0;\n";
    ss << "  internal static void WriteBool(byte[] buffer, int offset, bool value) => buffer[offset] = value ? (byte)1 : (byte)0;\n";
    ss << "  internal static sbyte ReadInt8(byte[] buffer, int offset) => unchecked((sbyte)buffer[offset]);\n";
    ss << "  internal static void WriteInt8(byte[] buffer, int offset, sbyte value) => buffer[offset] = unchecked((byte)value);\n";
    ss << "  internal static byte ReadUInt8(byte[] buffer, int offset) => buffer[offset];\n";
    ss << "  internal static void WriteUInt8(byte[] buffer, int offset, byte value) => buffer[offset] = value;\n";
    ss << "  internal static short ReadInt16(byte[] buffer, int offset) => BinaryPrimitives.ReadInt16LittleEndian(buffer.AsSpan(offset, 2));\n";
    ss << "  internal static void WriteInt16(byte[] buffer, int offset, short value) => BinaryPrimitives.WriteInt16LittleEndian(buffer.AsSpan(offset, 2), value);\n";
    ss << "  internal static ushort ReadUInt16(byte[] buffer, int offset) => BinaryPrimitives.ReadUInt16LittleEndian(buffer.AsSpan(offset, 2));\n";
    ss << "  internal static void WriteUInt16(byte[] buffer, int offset, ushort value) => BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(offset, 2), value);\n";
    ss << "  internal static int ReadInt32(byte[] buffer, int offset) => BinaryPrimitives.ReadInt32LittleEndian(buffer.AsSpan(offset, 4));\n";
    ss << "  internal static void WriteInt32(byte[] buffer, int offset, int value) => BinaryPrimitives.WriteInt32LittleEndian(buffer.AsSpan(offset, 4), value);\n";
    ss << "  internal static uint ReadUInt32(byte[] buffer, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(offset, 4));\n";
    ss << "  internal static void WriteUInt32(byte[] buffer, int offset, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(offset, 4), value);\n";
    ss << "  internal static long ReadInt64(byte[] buffer, int offset) => BinaryPrimitives.ReadInt64LittleEndian(buffer.AsSpan(offset, 8));\n";
    ss << "  internal static void WriteInt64(byte[] buffer, int offset, long value) => BinaryPrimitives.WriteInt64LittleEndian(buffer.AsSpan(offset, 8), value);\n";
    ss << "  internal static ulong ReadUInt64(byte[] buffer, int offset) => BinaryPrimitives.ReadUInt64LittleEndian(buffer.AsSpan(offset, 8));\n";
    ss << "  internal static void WriteUInt64(byte[] buffer, int offset, ulong value) => BinaryPrimitives.WriteUInt64LittleEndian(buffer.AsSpan(offset, 8), value);\n";
    ss << "  internal static float ReadFloat32(byte[] buffer, int offset) => BitConverter.Int32BitsToSingle(ReadInt32(buffer, offset));\n";
    ss << "  internal static void WriteFloat32(byte[] buffer, int offset, float value) => WriteInt32(buffer, offset, BitConverter.SingleToInt32Bits(value));\n";
    ss << "  internal static double ReadFloat64(byte[] buffer, int offset) => BitConverter.Int64BitsToDouble(ReadInt64(buffer, offset));\n";
    ss << "  internal static void WriteFloat64(byte[] buffer, int offset, double value) => WriteInt64(buffer, offset, BitConverter.DoubleToInt64Bits(value));\n";
    ss << "  internal static string DecodeString(byte[] buffer, int offset, int maxLength) {\n";
    ss << "    var length = Math.Min(buffer[offset], maxLength);\n";
    ss << "    return Encoding.UTF8.GetString(buffer, offset + 1, length);\n";
    ss << "  }\n";
    ss << "  internal static void EncodeString(byte[] buffer, int offset, int maxLength, string value) {\n";
    ss << "    var raw = Encoding.UTF8.GetBytes(value);\n";
    ss << "    var length = Math.Min(raw.Length, maxLength);\n";
    ss << "    buffer[offset] = (byte)length;\n";
    ss << "    Array.Clear(buffer, offset + 1, maxLength);\n";
    ss << "    Buffer.BlockCopy(raw, 0, buffer, offset + 1, length);\n";
    ss << "  }\n";
    ss << "}\n\n";

    for (size_t i = 0; i < schema_layout_.records.size(); ++i) {
      const RecordLayout& record = *schema_layout_.records[i];
      for (size_t f = 0; f < record.fields.size(); ++f) {
        const FieldLayout& field = record.fields[f];
        const InlineLayout& layout = *field.layout;
        if (!IsUnionLayout(layout) && !IsVectorOfUnionLayout(layout)) { continue; }
        const InlineLayout& union_layout = UnionLayoutForField(layout);
        const std::string helper_name = UnionCellName(record, field);
        ss << "public sealed class " << helper_name << " {\n";
        if (!union_layout.union_members.empty()) {
          for (size_t m = 0; m < union_layout.union_members.size(); ++m) {
            const UnionMemberLayout& member = union_layout.union_members[m];
            ss << "  public const " << CSharpScalarType(union_layout) << " "
               << UpperSnake(member.value->name) << "_TYPE = "
               << member.value->GetAsUInt64() << ";\n";
          }
          ss << "\n";
        }
        ss << "  internal readonly byte[] buffer;\n";
        ss << "  internal readonly int offset;\n\n";
        ss << "  private " << helper_name << "(byte[] buffer, int offset) {\n";
        ss << "    this.buffer = buffer;\n";
        ss << "    this.offset = offset;\n";
        ss << "  }\n\n";
        ss << "  public static " << helper_name
           << " FromPointer(byte[] buffer, int offset = 0) {\n";
        ss << "    return new " << helper_name << "(buffer, offset);\n";
        ss << "  }\n\n";
        ss << "  public " << CSharpScalarType(union_layout) << " Type() {\n";
        ss << "    return AlignedSupport.Read" << ScalarHelperSuffix(union_layout.base_type)
           << "(buffer, offset + " << union_layout.discriminator_offset << ");\n";
        ss << "  }\n\n";
        ss << "  public void MutateType(" << CSharpScalarType(union_layout)
           << " value) {\n";
        ss << "    AlignedSupport.Write" << ScalarHelperSuffix(union_layout.base_type)
           << "(buffer, offset + " << union_layout.discriminator_offset
           << ", value);\n";
        ss << "  }\n";
        for (size_t m = 0; m < union_layout.union_members.size(); ++m) {
          const UnionMemberLayout& member = union_layout.union_members[m];
          const InlineLayout& member_layout = *member.layout;
          const std::string member_name = PascalCase(member.value->name);
          const std::string payload_offset =
              "offset + " + NumToString(union_layout.payload_offset);
          ss << "\n";
          ss << "  public bool Is" << member_name << "() {\n";
          ss << "    return Type() == " << UpperSnake(member.value->name) << "_TYPE;\n";
          ss << "  }\n";
          if (member_layout.kind == InlineLayout::Kind::kScalar) {
            ss << "\n";
            ss << "  public " << CSharpScalarType(member_layout) << " " << member_name
               << "() {\n";
            ss << "    return AlignedSupport.Read"
               << ScalarHelperSuffix(member_layout.base_type)
               << "(buffer, " << payload_offset << ");\n";
            ss << "  }\n\n";
            ss << "  public void Mutate" << member_name << "("
               << CSharpScalarType(member_layout) << " value) {\n";
            ss << "    AlignedSupport.Write"
               << ScalarHelperSuffix(member_layout.base_type)
               << "(buffer, " << payload_offset << ", value);\n";
            ss << "    MutateType(" << UpperSnake(member.value->name) << "_TYPE);\n";
            ss << "  }\n";
          } else if (member_layout.kind == InlineLayout::Kind::kRecord) {
            ss << "\n";
            ss << "  public global::" << member_layout.record->name << " " << member_name
               << "() {\n";
            ss << "    return global::" << member_layout.record->name
               << ".FromPointer(buffer, " << payload_offset << ");\n";
            ss << "  }\n\n";
            ss << "  public void Mutate" << member_name << "From(global::"
               << member_layout.record->name << " src) {\n";
            ss << "    Buffer.BlockCopy(src.buffer, src.offset, buffer, "
               << payload_offset << ", " << member_layout.size << ");\n";
            ss << "    MutateType(" << UpperSnake(member.value->name) << "_TYPE);\n";
            ss << "  }\n";
          } else if (member_layout.kind == InlineLayout::Kind::kString) {
            ss << "\n";
            ss << "  public string " << member_name << "() {\n";
            ss << "    return AlignedSupport.DecodeString(buffer, " << payload_offset
               << ", " << member_layout.max_length << ");\n";
            ss << "  }\n\n";
            ss << "  public void Mutate" << member_name
               << "(string value) {\n";
            ss << "    AlignedSupport.EncodeString(buffer, " << payload_offset
               << ", " << member_layout.max_length << ", value);\n";
            ss << "    MutateType(" << UpperSnake(member.value->name) << "_TYPE);\n";
            ss << "  }\n";
          }
        }
        ss << "}\n\n";
      }

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
      ss << "  internal readonly byte[] buffer;\n";
      ss << "  internal readonly int offset;\n\n";
      ss << "  private " << record.name
         << "(byte[] buffer, int offset) {\n";
      ss << "    this.buffer = buffer;\n";
      ss << "    this.offset = offset;\n";
      ss << "  }\n\n";
      ss << "  public static " << record.name
         << " FromPointer(byte[] buffer, int offset = 0) {\n";
      ss << "    return new " << record.name << "(buffer, offset);\n";
      ss << "  }\n";
      for (size_t f = 0; f < record.fields.size(); ++f) {
        const FieldLayout& field = record.fields[f];
        const InlineLayout& layout = *field.layout;
        const std::string field_name = PascalCase(field.name);
        const std::string field_offset =
            "offset + " + UpperSnake(field.name) + "_OFFSET";
        if (field.presence_index != FieldLayout::kNoPresence) {
          ss << "\n";
          ss << "  public bool Has" << field_name << "() {\n";
          ss << "    return AlignedSupport.ReadPresence(buffer, offset, "
             << UpperSnake(field.name) << "_PRESENCE_BIT);\n";
          ss << "  }\n\n";
          ss << "  public void MutateHas" << field_name
             << "(bool value) {\n";
          ss << "    AlignedSupport.WritePresence(buffer, offset, "
             << UpperSnake(field.name) << "_PRESENCE_BIT, value);\n";
          ss << "  }\n";
        }
        if (layout.kind == InlineLayout::Kind::kScalar) {
          ss << "\n";
          ss << "  public " << CSharpScalarType(layout) << " " << field_name
             << "() {\n";
          ss << "    return AlignedSupport.Read" << ScalarHelperSuffix(layout.base_type)
             << "(buffer, " << field_offset << ");\n";
          ss << "  }\n\n";
          ss << "  public void Mutate" << field_name << "("
             << CSharpScalarType(layout) << " value) {\n";
          ss << "    AlignedSupport.Write" << ScalarHelperSuffix(layout.base_type)
             << "(buffer, " << field_offset << ", value);\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "    MutateHas" << field_name << "(true);\n";
          }
          ss << "  }\n";
          continue;
        }
        if (layout.kind == InlineLayout::Kind::kRecord) {
          ss << "\n";
          ss << "  public global::" << layout.record->name << " " << field_name << "() {\n";
          ss << "    return global::" << layout.record->name << ".FromPointer(buffer, "
             << field_offset << ");\n";
          ss << "  }\n";
          continue;
        }
        if (layout.kind == InlineLayout::Kind::kString) {
          ss << "\n";
          ss << "  public string " << field_name << "() {\n";
          ss << "    return AlignedSupport.DecodeString(buffer, " << field_offset
             << ", " << layout.max_length << ");\n";
          ss << "  }\n\n";
          ss << "  public void Mutate" << field_name << "(string value) {\n";
          ss << "    AlignedSupport.EncodeString(buffer, " << field_offset << ", "
             << layout.max_length << ", value);\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "    MutateHas" << field_name << "(true);\n";
          }
          ss << "  }\n";
          continue;
        }
        if (layout.kind == InlineLayout::Kind::kArray) {
          const std::string element_offset =
              field_offset + " + j * " + NumToString(layout.stride);
          ss << "\n";
          ss << "  public int " << field_name << "Length() {\n";
          ss << "    return " << layout.fixed_length << ";\n";
          ss << "  }\n";
          if (layout.element->kind == InlineLayout::Kind::kScalar) {
            ss << "\n";
            ss << "  public " << CSharpScalarType(*layout.element) << " "
               << field_name << "(int j) {\n";
            ss << "    return AlignedSupport.Read"
               << ScalarHelperSuffix(layout.element->base_type)
               << "(buffer, " << element_offset << ");\n";
            ss << "  }\n\n";
            ss << "  public void Mutate" << field_name << "(int j, "
               << CSharpScalarType(*layout.element) << " value) {\n";
            ss << "    AlignedSupport.Write"
               << ScalarHelperSuffix(layout.element->base_type)
               << "(buffer, " << element_offset << ", value);\n";
            ss << "  }\n";
          } else if (layout.element->kind == InlineLayout::Kind::kRecord) {
            ss << "\n";
            ss << "  public global::" << layout.element->record->name << " "
               << field_name << "(int j) {\n";
            ss << "    return global::" << layout.element->record->name
               << ".FromPointer(buffer, " << element_offset << ");\n";
            ss << "  }\n";
          } else if (layout.element->kind == InlineLayout::Kind::kString) {
            ss << "\n";
            ss << "  public string " << field_name << "(int j) {\n";
            ss << "    return AlignedSupport.DecodeString(buffer, " << element_offset
               << ", " << layout.element->max_length << ");\n";
            ss << "  }\n\n";
            ss << "  public void Mutate" << field_name
               << "(int j, string value) {\n";
            ss << "    AlignedSupport.EncodeString(buffer, " << element_offset
               << ", " << layout.element->max_length << ", value);\n";
            ss << "  }\n";
          }
          continue;
        }
        if (layout.kind == InlineLayout::Kind::kVector) {
          const std::string element_offset =
              field_offset + " + " + UpperSnake(field.name) +
              "_DATA_OFFSET + j * " + UpperSnake(field.name) + "_STRIDE";
          ss << "\n";
          ss << "  public int " << field_name << "Length() {\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "    if (!Has" << field_name << "()) return 0;\n";
          }
          ss << "    return Math.Min((int)AlignedSupport.ReadUInt32(buffer, "
             << field_offset << "), " << layout.max_count << ");\n";
          ss << "  }\n\n";
          ss << "  public void Mutate" << field_name << "Length(int length) {\n";
          ss << "    AlignedSupport.WriteUInt32(buffer, " << field_offset
             << ", (uint)Math.Min(Math.Max(length, 0), " << layout.max_count << "));\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "    MutateHas" << field_name << "(true);\n";
          }
          ss << "  }\n";
          if (layout.element->kind == InlineLayout::Kind::kScalar) {
            ss << "\n";
            ss << "  public " << CSharpScalarType(*layout.element) << " "
               << field_name << "(int j) {\n";
            ss << "    return AlignedSupport.Read"
               << ScalarHelperSuffix(layout.element->base_type)
               << "(buffer, " << element_offset << ");\n";
            ss << "  }\n\n";
            ss << "  public void Mutate" << field_name << "(int j, "
               << CSharpScalarType(*layout.element) << " value) {\n";
            ss << "    AlignedSupport.Write"
               << ScalarHelperSuffix(layout.element->base_type)
               << "(buffer, " << element_offset << ", value);\n";
            if (field.presence_index != FieldLayout::kNoPresence) {
              ss << "    MutateHas" << field_name << "(true);\n";
            }
            ss << "  }\n";
          } else if (layout.element->kind == InlineLayout::Kind::kRecord) {
            ss << "\n";
            ss << "  public global::" << layout.element->record->name << " "
               << field_name << "(int j) {\n";
            ss << "    return global::" << layout.element->record->name
               << ".FromPointer(buffer, " << element_offset << ");\n";
            ss << "  }\n";
          } else if (layout.element->kind == InlineLayout::Kind::kString) {
            ss << "\n";
            ss << "  public string " << field_name << "(int j) {\n";
            ss << "    return AlignedSupport.DecodeString(buffer, " << element_offset
               << ", " << layout.element->max_length << ");\n";
            ss << "  }\n\n";
            ss << "  public void Mutate" << field_name
               << "(int j, string value) {\n";
            ss << "    AlignedSupport.EncodeString(buffer, " << element_offset
               << ", " << layout.element->max_length << ", value);\n";
            if (field.presence_index != FieldLayout::kNoPresence) {
              ss << "    MutateHas" << field_name << "(true);\n";
            }
            ss << "  }\n";
          } else if (layout.element->kind == InlineLayout::Kind::kUnion) {
            const std::string helper_name = UnionCellName(record, field);
            ss << "\n";
            ss << "  public " << helper_name << " " << field_name << "(int j) {\n";
            ss << "    return " << helper_name << ".FromPointer(buffer, "
               << element_offset << ");\n";
            ss << "  }\n";
          }
          continue;
        }
        if (layout.kind == InlineLayout::Kind::kUnion) {
          const std::string helper_name = UnionCellName(record, field);
          ss << "\n";
          ss << "  public " << CSharpScalarType(layout) << " " << field_name
             << "Type() {\n";
          ss << "    return AlignedSupport.Read" << ScalarHelperSuffix(layout.base_type)
             << "(buffer, " << field_offset << " + "
             << layout.discriminator_offset << ");\n";
          ss << "  }\n\n";
          ss << "  public void Mutate" << field_name << "Type("
             << CSharpScalarType(layout) << " value) {\n";
          ss << "    AlignedSupport.Write" << ScalarHelperSuffix(layout.base_type)
             << "(buffer, " << field_offset << " + "
             << layout.discriminator_offset << ", value);\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "    MutateHas" << field_name << "(true);\n";
          }
          ss << "  }\n\n";
          ss << "  public " << helper_name << " " << field_name << "() {\n";
          ss << "    return " << helper_name << ".FromPointer(buffer, "
             << field_offset << ");\n";
          ss << "  }\n";
        }
      }
      ss << "}\n\n";
    }

    return ss.str();
  }

  std::string GenerateKotlin() const {
    std::ostringstream ss;
    ss << "// Auto-generated aligned fixed-layout bindings.\n";
    ss << "// DO NOT EDIT - Generated by flatc --aligned\n\n";
    ss << "private fun readPresence(buffer: ByteArray, base: Int, bitIndex: Int): Boolean {\n";
    ss << "  val byteIndex = bitIndex / 8\n";
    ss << "  val mask = 1 shl (bitIndex % 8)\n";
    ss << "  return (buffer[base + byteIndex].toInt() and mask) != 0\n";
    ss << "}\n\n";
    ss << "private fun writePresence(buffer: ByteArray, base: Int, bitIndex: Int, value: Boolean) {\n";
    ss << "  val byteIndex = bitIndex / 8\n";
    ss << "  val mask = 1 shl (bitIndex % 8)\n";
    ss << "  val current = buffer[base + byteIndex].toInt() and 0xFF\n";
    ss << "  buffer[base + byteIndex] = if (value) (current or mask).toByte() else (current and mask.inv()).toByte()\n";
    ss << "}\n\n";
    ss << "private fun readBool(buffer: ByteArray, offset: Int): Boolean = buffer[offset] != 0.toByte()\n";
    ss << "private fun writeBool(buffer: ByteArray, offset: Int, value: Boolean) { buffer[offset] = if (value) 1 else 0 }\n";
    ss << "private fun readInt8(buffer: ByteArray, offset: Int): Byte = buffer[offset]\n";
    ss << "private fun writeInt8(buffer: ByteArray, offset: Int, value: Byte) { buffer[offset] = value }\n";
    ss << "private fun readUInt8(buffer: ByteArray, offset: Int): UByte = buffer[offset].toUByte()\n";
    ss << "private fun writeUInt8(buffer: ByteArray, offset: Int, value: UByte) { buffer[offset] = value.toByte() }\n";
    ss << "private fun readInt16(buffer: ByteArray, offset: Int): Short = (((buffer[offset + 1].toInt() and 0xFF) shl 8) or (buffer[offset].toInt() and 0xFF)).toShort()\n";
    ss << "private fun writeInt16(buffer: ByteArray, offset: Int, value: Short) {\n";
    ss << "  val raw = value.toInt()\n";
    ss << "  buffer[offset] = raw.toByte()\n";
    ss << "  buffer[offset + 1] = (raw ushr 8).toByte()\n";
    ss << "}\n";
    ss << "private fun readUInt16(buffer: ByteArray, offset: Int): UShort = ((((buffer[offset + 1].toInt() and 0xFF) shl 8) or (buffer[offset].toInt() and 0xFF))).toUShort()\n";
    ss << "private fun writeUInt16(buffer: ByteArray, offset: Int, value: UShort) {\n";
    ss << "  val raw = value.toInt()\n";
    ss << "  buffer[offset] = raw.toByte()\n";
    ss << "  buffer[offset + 1] = (raw ushr 8).toByte()\n";
    ss << "}\n";
    ss << "private fun readInt32(buffer: ByteArray, offset: Int): Int =\n";
    ss << "  ((buffer[offset + 3].toInt() and 0xFF) shl 24) or ((buffer[offset + 2].toInt() and 0xFF) shl 16) or ((buffer[offset + 1].toInt() and 0xFF) shl 8) or (buffer[offset].toInt() and 0xFF)\n";
    ss << "private fun writeInt32(buffer: ByteArray, offset: Int, value: Int) {\n";
    ss << "  buffer[offset] = value.toByte()\n";
    ss << "  buffer[offset + 1] = (value ushr 8).toByte()\n";
    ss << "  buffer[offset + 2] = (value ushr 16).toByte()\n";
    ss << "  buffer[offset + 3] = (value ushr 24).toByte()\n";
    ss << "}\n";
    ss << "private fun readUInt32(buffer: ByteArray, offset: Int): UInt = readInt32(buffer, offset).toUInt()\n";
    ss << "private fun writeUInt32(buffer: ByteArray, offset: Int, value: UInt) = writeInt32(buffer, offset, value.toInt())\n";
    ss << "private fun readInt64(buffer: ByteArray, offset: Int): Long {\n";
    ss << "  var value = 0L\n";
    ss << "  for (i in 0 until 8) value = value or ((buffer[offset + i].toLong() and 0xFF) shl (8 * i))\n";
    ss << "  return value\n";
    ss << "}\n";
    ss << "private fun writeInt64(buffer: ByteArray, offset: Int, value: Long) {\n";
    ss << "  for (i in 0 until 8) buffer[offset + i] = ((value ushr (8 * i)) and 0xFF).toByte()\n";
    ss << "}\n";
    ss << "private fun readUInt64(buffer: ByteArray, offset: Int): ULong = readInt64(buffer, offset).toULong()\n";
    ss << "private fun writeUInt64(buffer: ByteArray, offset: Int, value: ULong) = writeInt64(buffer, offset, value.toLong())\n";
    ss << "private fun readFloat32(buffer: ByteArray, offset: Int): Float = Float.fromBits(readInt32(buffer, offset))\n";
    ss << "private fun writeFloat32(buffer: ByteArray, offset: Int, value: Float) = writeInt32(buffer, offset, value.toRawBits())\n";
    ss << "private fun readFloat64(buffer: ByteArray, offset: Int): Double = Double.fromBits(readInt64(buffer, offset))\n";
    ss << "private fun writeFloat64(buffer: ByteArray, offset: Int, value: Double) = writeInt64(buffer, offset, value.toRawBits())\n";
    ss << "private fun decodeString(buffer: ByteArray, offset: Int, maxLength: Int): String {\n";
    ss << "  val length = minOf(buffer[offset].toInt() and 0xFF, maxLength)\n";
    ss << "  return buffer.copyOfRange(offset + 1, offset + 1 + length).decodeToString()\n";
    ss << "}\n";
    ss << "private fun encodeString(buffer: ByteArray, offset: Int, maxLength: Int, value: String) {\n";
    ss << "  val raw = value.encodeToByteArray()\n";
    ss << "  val length = minOf(raw.size, maxLength)\n";
    ss << "  buffer[offset] = length.toByte()\n";
    ss << "  for (i in 0 until maxLength) buffer[offset + 1 + i] = 0\n";
    ss << "  raw.copyInto(buffer, offset + 1, 0, length)\n";
    ss << "}\n\n";

    for (size_t i = 0; i < schema_layout_.records.size(); ++i) {
      const RecordLayout& record = *schema_layout_.records[i];
      for (size_t f = 0; f < record.fields.size(); ++f) {
        const FieldLayout& field = record.fields[f];
        const InlineLayout& layout = *field.layout;
        if (!IsUnionLayout(layout) && !IsVectorOfUnionLayout(layout)) { continue; }
        const InlineLayout& union_layout = UnionLayoutForField(layout);
        const std::string helper_name = UnionCellName(record, field);
        ss << "class " << helper_name
           << " internal constructor(internal val buffer: ByteArray, internal val offset: Int = 0) {\n";
        ss << "  companion object {\n";
        for (size_t m = 0; m < union_layout.union_members.size(); ++m) {
          const UnionMemberLayout& member = union_layout.union_members[m];
          ss << "    const val " << UpperSnake(member.value->name) << "_TYPE: Int = "
             << member.value->GetAsUInt64() << "\n";
        }
        ss << "\n";
        ss << "    fun fromPointer(buffer: ByteArray, offset: Int = 0): "
           << helper_name << " = " << helper_name << "(buffer, offset)\n";
        ss << "  }\n\n";
        ss << "  fun type(): " << KotlinScalarType(union_layout) << " = read"
           << ScalarHelperSuffix(union_layout.base_type) << "(buffer, offset + "
           << union_layout.discriminator_offset << ")\n\n";
        ss << "  fun mutateType(value: " << KotlinScalarType(union_layout)
           << ") {\n";
        ss << "    write" << ScalarHelperSuffix(union_layout.base_type)
           << "(buffer, offset + " << union_layout.discriminator_offset
           << ", value)\n";
        ss << "  }\n";
        for (size_t m = 0; m < union_layout.union_members.size(); ++m) {
          const UnionMemberLayout& member = union_layout.union_members[m];
          const InlineLayout& member_layout = *member.layout;
          const std::string member_name = LowerCamelCase(member.value->name);
          const std::string member_pascal = PascalCase(member.value->name);
          const std::string payload_offset =
              "offset + " + NumToString(union_layout.payload_offset);
          ss << "\n";
          ss << "  fun is" << member_pascal << "(): Boolean = type().toInt() == "
             << UpperSnake(member.value->name) << "_TYPE\n";
          if (member_layout.kind == InlineLayout::Kind::kScalar) {
            ss << "\n";
            ss << "  fun " << member_name << "(): " << KotlinScalarType(member_layout)
               << " = read" << ScalarHelperSuffix(member_layout.base_type)
               << "(buffer, " << payload_offset << ")\n\n";
            ss << "  fun mutate" << member_pascal << "(value: "
               << KotlinScalarType(member_layout) << ") {\n";
            ss << "    write" << ScalarHelperSuffix(member_layout.base_type)
               << "(buffer, " << payload_offset << ", value)\n";
            ss << "    mutateType(" << UpperSnake(member.value->name)
               << "_TYPE" << KotlinConversion(union_layout.base_type)
               << ")\n";
            ss << "  }\n";
          } else if (member_layout.kind == InlineLayout::Kind::kRecord) {
            ss << "\n";
            ss << "  fun " << member_name << "(): " << member_layout.record->name
               << " = " << member_layout.record->name << ".fromPointer(buffer, "
               << payload_offset << ")\n\n";
            ss << "  fun mutate" << member_pascal << "From(src: "
               << member_layout.record->name << ") {\n";
            ss << "    src.buffer.copyInto(buffer, " << payload_offset << ", src.offset, src.offset + "
               << member_layout.size << ")\n";
            ss << "    mutateType(" << UpperSnake(member.value->name)
               << "_TYPE" << KotlinConversion(union_layout.base_type)
               << ")\n";
            ss << "  }\n";
          } else if (member_layout.kind == InlineLayout::Kind::kString) {
            ss << "\n";
            ss << "  fun " << member_name << "(): String = decodeString(buffer, "
               << payload_offset << ", " << member_layout.max_length << ")\n\n";
            ss << "  fun mutate" << member_pascal << "(value: String) {\n";
            ss << "    encodeString(buffer, " << payload_offset << ", "
               << member_layout.max_length << ", value)\n";
            ss << "    mutateType(" << UpperSnake(member.value->name)
               << "_TYPE" << KotlinConversion(union_layout.base_type)
               << ")\n";
            ss << "  }\n";
          }
        }
        ss << "}\n\n";
      }

      ss << "class " << record.name
         << " internal constructor(internal val buffer: ByteArray, internal val offset: Int = 0) {\n";
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
        const InlineLayout& layout = *field.layout;
        const std::string field_name = LowerCamelCase(field.name);
        const std::string field_pascal = PascalCase(field.name);
        const std::string field_offset =
            "offset + " + UpperSnake(field.name) + "_OFFSET";
        if (field.presence_index != FieldLayout::kNoPresence) {
          ss << "\n";
          ss << "  fun has" << field_pascal << "(): Boolean = readPresence(buffer, offset, "
             << UpperSnake(field.name) << "_PRESENCE_BIT)\n\n";
          ss << "  fun mutateHas" << field_pascal << "(value: Boolean) {\n";
          ss << "    writePresence(buffer, offset, " << UpperSnake(field.name)
             << "_PRESENCE_BIT, value)\n";
          ss << "  }\n";
        }
        if (layout.kind == InlineLayout::Kind::kScalar) {
          ss << "\n";
          ss << "  fun " << field_name << "(): " << KotlinScalarType(layout)
             << " = read" << ScalarHelperSuffix(layout.base_type)
             << "(buffer, " << field_offset << ")\n\n";
          ss << "  fun mutate" << field_pascal << "(value: "
             << KotlinScalarType(layout) << ") {\n";
          ss << "    write" << ScalarHelperSuffix(layout.base_type)
             << "(buffer, " << field_offset << ", value)\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "    mutateHas" << field_pascal << "(true)\n";
          }
          ss << "  }\n";
          continue;
        }
        if (layout.kind == InlineLayout::Kind::kRecord) {
          ss << "\n";
          ss << "  fun " << field_name << "(): " << layout.record->name << " = "
             << layout.record->name << ".fromPointer(buffer, " << field_offset
             << ")\n";
          continue;
        }
        if (layout.kind == InlineLayout::Kind::kString) {
          ss << "\n";
          ss << "  fun " << field_name << "(): String = decodeString(buffer, "
             << field_offset << ", " << layout.max_length << ")\n\n";
          ss << "  fun mutate" << field_pascal << "(value: String) {\n";
          ss << "    encodeString(buffer, " << field_offset << ", "
             << layout.max_length << ", value)\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "    mutateHas" << field_pascal << "(true)\n";
          }
          ss << "  }\n";
          continue;
        }
        if (layout.kind == InlineLayout::Kind::kArray) {
          const std::string element_offset =
              field_offset + " + j * " + NumToString(layout.stride);
          ss << "\n";
          ss << "  fun " << field_name << "Length(): Int = " << layout.fixed_length << "\n";
          if (layout.element->kind == InlineLayout::Kind::kScalar) {
            ss << "\n";
            ss << "  fun " << field_name << "(j: Int): "
               << KotlinScalarType(*layout.element) << " = read"
               << ScalarHelperSuffix(layout.element->base_type)
               << "(buffer, " << element_offset << ")\n\n";
            ss << "  fun mutate" << field_pascal << "(j: Int, value: "
               << KotlinScalarType(*layout.element) << ") {\n";
            ss << "    write" << ScalarHelperSuffix(layout.element->base_type)
               << "(buffer, " << element_offset << ", value)\n";
            ss << "  }\n";
          } else if (layout.element->kind == InlineLayout::Kind::kRecord) {
            ss << "\n";
            ss << "  fun " << field_name << "(j: Int): "
               << layout.element->record->name << " = "
               << layout.element->record->name << ".fromPointer(buffer, "
               << element_offset << ")\n";
          } else if (layout.element->kind == InlineLayout::Kind::kString) {
            ss << "\n";
            ss << "  fun " << field_name << "(j: Int): String = decodeString(buffer, "
               << element_offset << ", " << layout.element->max_length << ")\n\n";
            ss << "  fun mutate" << field_pascal << "(j: Int, value: String) {\n";
            ss << "    encodeString(buffer, " << element_offset << ", "
               << layout.element->max_length << ", value)\n";
            ss << "  }\n";
          }
          continue;
        }
        if (layout.kind == InlineLayout::Kind::kVector) {
          const std::string element_offset =
              field_offset + " + " + UpperSnake(field.name) +
              "_DATA_OFFSET + j * " + UpperSnake(field.name) + "_STRIDE";
          ss << "\n";
          ss << "  fun " << field_name << "Length(): Int {\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "    if (!has" << field_pascal << "()) return 0\n";
          }
          ss << "    return minOf(readUInt32(buffer, " << field_offset
             << ").toInt(), " << layout.max_count << ")\n";
          ss << "  }\n\n";
          ss << "  fun mutate" << field_pascal << "Length(length: Int) {\n";
          ss << "    writeUInt32(buffer, " << field_offset << ", minOf(maxOf(length, 0), "
             << layout.max_count << ").toUInt())\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "    mutateHas" << field_pascal << "(true)\n";
          }
          ss << "  }\n";
          if (layout.element->kind == InlineLayout::Kind::kScalar) {
            ss << "\n";
            ss << "  fun " << field_name << "(j: Int): "
               << KotlinScalarType(*layout.element) << " = read"
               << ScalarHelperSuffix(layout.element->base_type)
               << "(buffer, " << element_offset << ")\n\n";
            ss << "  fun mutate" << field_pascal << "(j: Int, value: "
               << KotlinScalarType(*layout.element) << ") {\n";
            ss << "    write" << ScalarHelperSuffix(layout.element->base_type)
               << "(buffer, " << element_offset << ", value)\n";
            if (field.presence_index != FieldLayout::kNoPresence) {
              ss << "    mutateHas" << field_pascal << "(true)\n";
            }
            ss << "  }\n";
          } else if (layout.element->kind == InlineLayout::Kind::kRecord) {
            ss << "\n";
            ss << "  fun " << field_name << "(j: Int): "
               << layout.element->record->name << " = "
               << layout.element->record->name << ".fromPointer(buffer, "
               << element_offset << ")\n";
          } else if (layout.element->kind == InlineLayout::Kind::kString) {
            ss << "\n";
            ss << "  fun " << field_name << "(j: Int): String = decodeString(buffer, "
               << element_offset << ", " << layout.element->max_length << ")\n\n";
            ss << "  fun mutate" << field_pascal << "(j: Int, value: String) {\n";
            ss << "    encodeString(buffer, " << element_offset << ", "
               << layout.element->max_length << ", value)\n";
            if (field.presence_index != FieldLayout::kNoPresence) {
              ss << "    mutateHas" << field_pascal << "(true)\n";
            }
            ss << "  }\n";
          } else if (layout.element->kind == InlineLayout::Kind::kUnion) {
            const std::string helper_name = UnionCellName(record, field);
            ss << "\n";
            ss << "  fun " << field_name << "(j: Int): " << helper_name << " = "
               << helper_name << ".fromPointer(buffer, " << element_offset << ")\n";
          }
          continue;
        }
        if (layout.kind == InlineLayout::Kind::kUnion) {
          const std::string helper_name = UnionCellName(record, field);
          ss << "\n";
          ss << "  fun " << field_name << "Type(): " << KotlinScalarType(layout)
             << " = read" << ScalarHelperSuffix(layout.base_type)
             << "(buffer, " << field_offset << " + "
             << layout.discriminator_offset << ")\n\n";
          ss << "  fun mutate" << field_pascal << "Type(value: "
             << KotlinScalarType(layout) << ") {\n";
          ss << "    write" << ScalarHelperSuffix(layout.base_type)
             << "(buffer, " << field_offset << " + "
             << layout.discriminator_offset << ", value)\n";
          if (field.presence_index != FieldLayout::kNoPresence) {
            ss << "    mutateHas" << field_pascal << "(true)\n";
          }
          ss << "  }\n\n";
          ss << "  fun " << field_name << "(): " << helper_name << " = "
             << helper_name << ".fromPointer(buffer, " << field_offset << ")\n";
        }
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
