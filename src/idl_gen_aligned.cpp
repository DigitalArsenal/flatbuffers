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

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "flatbuffers/code_generators.h"
#include "flatbuffers/idl.h"

namespace flatbuffers {

namespace aligned {

namespace {

// Type information for layout calculation
struct TypeInfo {
  size_t size;
  size_t align;
  std::string cpp_type;
  std::string ts_getter;
  std::string ts_setter;
  std::string ts_type;
};

static const TypeInfo* GetScalarTypeInfo(BaseType type) {
  // clang-format off
  static const TypeInfo type_info[] = {
    // BASE_TYPE_NONE = 0
    { 0, 0, "", "", "", "" },
    // BASE_TYPE_UTYPE = 1
    { 1, 1, "uint8_t", "getUint8", "setUint8", "number" },
    // BASE_TYPE_BOOL = 2
    { 1, 1, "bool", "getUint8", "setUint8", "boolean" },
    // BASE_TYPE_CHAR = 3 (int8)
    { 1, 1, "int8_t", "getInt8", "setInt8", "number" },
    // BASE_TYPE_UCHAR = 4 (uint8)
    { 1, 1, "uint8_t", "getUint8", "setUint8", "number" },
    // BASE_TYPE_SHORT = 5 (int16)
    { 2, 2, "int16_t", "getInt16", "setInt16", "number" },
    // BASE_TYPE_USHORT = 6 (uint16)
    { 2, 2, "uint16_t", "getUint16", "setUint16", "number" },
    // BASE_TYPE_INT = 7 (int32)
    { 4, 4, "int32_t", "getInt32", "setInt32", "number" },
    // BASE_TYPE_UINT = 8 (uint32)
    { 4, 4, "uint32_t", "getUint32", "setUint32", "number" },
    // BASE_TYPE_LONG = 9 (int64)
    { 8, 8, "int64_t", "getBigInt64", "setBigInt64", "bigint" },
    // BASE_TYPE_ULONG = 10 (uint64)
    { 8, 8, "uint64_t", "getBigUint64", "setBigUint64", "bigint" },
    // BASE_TYPE_FLOAT = 11
    { 4, 4, "float", "getFloat32", "setFloat32", "number" },
    // BASE_TYPE_DOUBLE = 12
    { 8, 8, "double", "getFloat64", "setFloat64", "number" },
    // BASE_TYPE_STRING = 13 (not supported in aligned)
    { 0, 0, "", "", "", "" },
    // BASE_TYPE_VECTOR = 14 (not supported in aligned without fixed length)
    { 0, 0, "", "", "", "" },
    // BASE_TYPE_STRUCT = 15
    { 0, 0, "", "", "", "" },
    // BASE_TYPE_UNION = 16 (not supported in aligned)
    { 0, 0, "", "", "", "" },
    // BASE_TYPE_ARRAY = 17 (fixed-length arrays)
    { 0, 0, "", "", "", "" },
    // BASE_TYPE_VECTOR64 = 18 (not supported in aligned)
    { 0, 0, "", "", "", "" },
  };
  // clang-format on

  if (type >= 0 && type < static_cast<int>(sizeof(type_info) / sizeof(type_info[0]))) {
    return &type_info[type];
  }
  return nullptr;
}

static size_t AlignTo(size_t offset, size_t alignment) {
  return (offset + alignment - 1) & ~(alignment - 1);
}

// Field layout information
struct FieldLayout {
  std::string name;
  std::string cpp_type;
  std::string ts_getter;
  std::string ts_setter;
  std::string ts_type;
  size_t offset;
  size_t size;
  size_t align;
  size_t array_length;  // 0 if not an array
  bool is_struct;
  std::string struct_name;
};

// Struct layout information
struct StructLayout {
  std::string name;
  std::string namespace_path;
  std::vector<FieldLayout> fields;
  size_t size;
  size_t align;
};

}  // namespace

class AlignedGenerator : public BaseGenerator {
 private:
  std::string cpp_code_;
  std::string ts_code_;
  std::string js_code_;
  std::string json_code_;
  std::vector<StructLayout> layouts_;

  bool ComputeLayout(const StructDef& struct_def, StructLayout& layout) {
    layout.name = struct_def.name;
    layout.namespace_path = "";
    if (struct_def.defined_namespace) {
      for (const auto& ns : struct_def.defined_namespace->components) {
        if (!layout.namespace_path.empty()) layout.namespace_path += "::";
        layout.namespace_path += ns;
      }
    }

    size_t offset = 0;
    size_t max_align = 1;

    for (const auto* field : struct_def.fields.vec) {
      FieldLayout fl;
      fl.name = field->name;
      fl.array_length = 0;
      fl.is_struct = false;

      const Type& type = field->value.type;

      if (type.base_type == BASE_TYPE_STRUCT && type.struct_def) {
        // Nested struct
        fl.is_struct = true;
        fl.struct_name = type.struct_def->name;
        fl.size = type.struct_def->bytesize;
        fl.align = type.struct_def->minalign;
        fl.cpp_type = type.struct_def->name;
        fl.ts_type = type.struct_def->name;
      } else if (type.base_type == BASE_TYPE_ARRAY) {
        // Fixed-length array
        fl.array_length = type.fixed_length;
        const TypeInfo* elem_info = GetScalarTypeInfo(type.element);
        if (!elem_info || elem_info->size == 0) {
          // Check if it's an array of structs
          if (type.struct_def) {
            fl.is_struct = true;
            fl.struct_name = type.struct_def->name;
            fl.size = type.struct_def->bytesize * type.fixed_length;
            fl.align = type.struct_def->minalign;
            fl.cpp_type = type.struct_def->name;
            fl.ts_type = type.struct_def->name;
          } else {
            return false;  // Unsupported array element type
          }
        } else {
          fl.size = elem_info->size * type.fixed_length;
          fl.align = elem_info->align;
          fl.cpp_type = elem_info->cpp_type;
          fl.ts_getter = elem_info->ts_getter;
          fl.ts_setter = elem_info->ts_setter;
          fl.ts_type = elem_info->ts_type;
        }
      } else {
        // Scalar type
        const TypeInfo* info = GetScalarTypeInfo(type.base_type);
        if (!info || info->size == 0) {
          // Check for enum
          if (type.enum_def) {
            const TypeInfo* enum_info = GetScalarTypeInfo(type.enum_def->underlying_type.base_type);
            if (enum_info && enum_info->size > 0) {
              fl.size = enum_info->size;
              fl.align = enum_info->align;
              fl.cpp_type = type.enum_def->name;
              fl.ts_getter = enum_info->ts_getter;
              fl.ts_setter = enum_info->ts_setter;
              fl.ts_type = "number";
            } else {
              return false;
            }
          } else {
            return false;  // Unsupported type
          }
        } else {
          fl.size = info->size;
          fl.align = info->align;
          fl.cpp_type = info->cpp_type;
          fl.ts_getter = info->ts_getter;
          fl.ts_setter = info->ts_setter;
          fl.ts_type = info->ts_type;
        }
      }

      // Align the offset
      offset = AlignTo(offset, fl.align);
      fl.offset = offset;
      offset += fl.size;

      if (fl.align > max_align) max_align = fl.align;

      layout.fields.push_back(fl);
    }

    // Final size aligned to max alignment
    layout.size = AlignTo(offset, max_align);
    layout.align = max_align;
    return true;
  }

  void GenerateCppHeader() {
    std::ostringstream ss;

    ss << "// Auto-generated aligned struct header for zero-copy WASM interop\n";
    ss << "// DO NOT EDIT - Generated by flatc --aligned\n\n";

    ss << "#pragma once\n\n";
    ss << "#include <cstdint>\n";
    ss << "#include <cstring>\n\n";

    // Get namespace from first struct if available
    std::string ns;
    if (!layouts_.empty() && !layouts_[0].namespace_path.empty()) {
      ns = layouts_[0].namespace_path;
      // Convert :: to nested namespaces
      std::string open_ns;
      std::string current;
      for (size_t i = 0; i < ns.size(); ++i) {
        if (ns[i] == ':' && i + 1 < ns.size() && ns[i + 1] == ':') {
          open_ns += "namespace " + current + " {\n";
          current.clear();
          ++i;  // Skip second :
        } else {
          current += ns[i];
        }
      }
      if (!current.empty()) {
        open_ns += "namespace " + current + " {\n";
      }
      ss << open_ns << "\n";
    }

    // Forward declarations
    for (const auto& layout : layouts_) {
      ss << "struct " << layout.name << ";\n";
    }
    ss << "\n";

    // Struct definitions
    for (const auto& layout : layouts_) {
      ss << "#pragma pack(push, 1)\n";
      ss << "struct alignas(" << layout.align << ") " << layout.name << " {\n";

      size_t current_offset = 0;
      int padding_count = 0;

      for (const auto& field : layout.fields) {
        // Add padding if needed
        if (field.offset > current_offset) {
          size_t padding = field.offset - current_offset;
          ss << "  uint8_t _padding" << padding_count++ << "[" << padding << "];\n";
        }

        if (field.array_length > 0) {
          if (field.is_struct) {
            ss << "  " << field.cpp_type << " " << field.name << "[" << field.array_length << "];\n";
          } else {
            ss << "  " << field.cpp_type << " " << field.name << "[" << field.array_length << "];\n";
          }
        } else if (field.is_struct) {
          ss << "  " << field.cpp_type << " " << field.name << ";\n";
        } else {
          ss << "  " << field.cpp_type << " " << field.name << ";\n";
        }

        current_offset = field.offset + field.size;
      }

      // Add tail padding if needed
      if (layout.size > current_offset) {
        size_t padding = layout.size - current_offset;
        ss << "  uint8_t _padding" << padding_count << "[" << padding << "];\n";
      }

      ss << "};\n";
      ss << "#pragma pack(pop)\n\n";

      ss << "static_assert(sizeof(" << layout.name << ") == " << layout.size
         << ", \"" << layout.name << " size mismatch\");\n";
      ss << "static_assert(alignof(" << layout.name << ") == " << layout.align
         << ", \"" << layout.name << " alignment mismatch\");\n\n";
    }

    // Close namespaces
    if (!ns.empty()) {
      size_t depth = 1;
      for (char c : ns) {
        if (c == ':') ++depth;
      }
      depth /= 2;  // Each :: counts as one namespace
      for (size_t i = 0; i <= depth; ++i) {
        ss << "}  // namespace\n";
      }
    }

    cpp_code_ = ss.str();
  }

  void GenerateLayoutsJSON() {
    std::ostringstream ss;
    ss << "// __LAYOUTS_JSON_START__\n";
    ss << "{\n";

    bool first_struct = true;
    for (const auto& layout : layouts_) {
      if (!first_struct) ss << ",\n";
      first_struct = false;

      ss << "  \"" << layout.name << "\": {\n";
      ss << "    \"size\": " << layout.size << ",\n";
      ss << "    \"align\": " << layout.align << ",\n";
      ss << "    \"fields\": [\n";

      bool first_field = true;
      for (const auto& field : layout.fields) {
        if (!first_field) ss << ",\n";
        first_field = false;

        ss << "      {\n";
        ss << "        \"name\": \"" << field.name << "\",\n";
        ss << "        \"offset\": " << field.offset << ",\n";
        ss << "        \"size\": " << field.size << ",\n";
        ss << "        \"align\": " << field.align;
        if (field.array_length > 0) {
          ss << ",\n        \"arraySize\": " << field.array_length;
        }
        if (field.is_struct) {
          ss << ",\n        \"isNestedStruct\": true";
          ss << ",\n        \"type\": \"" << field.struct_name << "\"";
        }
        ss << "\n      }";
      }

      ss << "\n    ]\n";
      ss << "  }";
    }

    ss << "\n}\n";
    ss << "// __LAYOUTS_JSON_END__\n";

    json_code_ = ss.str();
  }

  void GenerateTypeScript() {
    std::ostringstream ss;

    ss << "// Auto-generated aligned struct TypeScript views for zero-copy WASM interop\n";
    ss << "// DO NOT EDIT - Generated by flatc --aligned\n\n";

    for (const auto& layout : layouts_) {
      ss << "/**\n";
      ss << " * " << layout.name << " - Zero-copy view into WASM linear memory\n";
      ss << " * Size: " << layout.size << " bytes, Alignment: " << layout.align << " bytes\n";
      ss << " */\n";
      ss << "export class " << layout.name << " {\n";
      ss << "  static readonly SIZE = " << layout.size << ";\n";
      ss << "  static readonly ALIGN = " << layout.align << ";\n\n";
      ss << "  private readonly view: DataView;\n";
      ss << "  private readonly offset: number;\n\n";

      // Constructor
      ss << "  constructor(buffer: ArrayBuffer, offset: number = 0) {\n";
      ss << "    this.view = new DataView(buffer);\n";
      ss << "    this.offset = offset;\n";
      ss << "  }\n\n";

      // Static factory from pointer
      ss << "  static fromPointer(memory: WebAssembly.Memory, ptr: number): " << layout.name << " {\n";
      ss << "    return new " << layout.name << "(memory.buffer, ptr);\n";
      ss << "  }\n\n";

      // Getters and setters
      for (const auto& field : layout.fields) {
        if (field.array_length > 0) {
          // Array field
          if (field.is_struct) {
            ss << "  " << field.name << "(index: number): " << field.ts_type << " {\n";
            ss << "    const elemSize = " << (field.size / field.array_length) << ";\n";
            ss << "    return new " << field.struct_name << "(this.view.buffer, this.offset + " << field.offset << " + index * elemSize);\n";
            ss << "  }\n\n";
          } else {
            // Getter for array element
            ss << "  get" << field.name << "(index: number): " << field.ts_type << " {\n";
            size_t elem_size = field.size / field.array_length;
            ss << "    return this.view." << field.ts_getter << "(this.offset + " << field.offset << " + index * " << elem_size << ", true)";
            if (field.ts_type == "boolean") {
              ss << " !== 0";
            }
            ss << ";\n";
            ss << "  }\n\n";

            // Setter for array element
            ss << "  set" << field.name << "(index: number, value: " << field.ts_type << "): void {\n";
            ss << "    this.view." << field.ts_setter << "(this.offset + " << field.offset << " + index * " << elem_size << ", ";
            if (field.ts_type == "boolean") {
              ss << "value ? 1 : 0";
            } else {
              ss << "value";
            }
            ss << ", true);\n";
            ss << "  }\n\n";

            // Array length getter
            ss << "  get " << field.name << "Length(): number { return " << field.array_length << "; }\n\n";
          }
        } else if (field.is_struct) {
          // Nested struct field
          ss << "  get " << field.name << "(): " << field.ts_type << " {\n";
          ss << "    return new " << field.struct_name << "(this.view.buffer, this.offset + " << field.offset << ");\n";
          ss << "  }\n\n";
        } else {
          // Scalar field getter
          ss << "  get " << field.name << "(): " << field.ts_type << " {\n";
          ss << "    return this.view." << field.ts_getter << "(this.offset + " << field.offset << ", true)";
          if (field.ts_type == "boolean") {
            ss << " !== 0";
          }
          ss << ";\n";
          ss << "  }\n\n";

          // Scalar field setter
          ss << "  set " << field.name << "(value: " << field.ts_type << ") {\n";
          ss << "    this.view." << field.ts_setter << "(this.offset + " << field.offset << ", ";
          if (field.ts_type == "boolean") {
            ss << "value ? 1 : 0";
          } else {
            ss << "value";
          }
          ss << ", true);\n";
          ss << "  }\n\n";
        }
      }

      ss << "}\n\n";
    }

    ts_code_ = ss.str();
  }

  void GenerateJavaScript() {
    std::ostringstream ss;

    ss << "// Auto-generated aligned struct JavaScript views for zero-copy WASM interop\n";
    ss << "// DO NOT EDIT - Generated by flatc --aligned\n\n";

    for (const auto& layout : layouts_) {
      ss << "/**\n";
      ss << " * " << layout.name << " - Zero-copy view into WASM linear memory\n";
      ss << " * Size: " << layout.size << " bytes, Alignment: " << layout.align << " bytes\n";
      ss << " */\n";
      ss << "export class " << layout.name << " {\n";
      ss << "  static SIZE = " << layout.size << ";\n";
      ss << "  static ALIGN = " << layout.align << ";\n\n";

      // Constructor
      ss << "  constructor(buffer, offset = 0) {\n";
      ss << "    this.view = new DataView(buffer);\n";
      ss << "    this.offset = offset;\n";
      ss << "  }\n\n";

      // Static factory from pointer
      ss << "  static fromPointer(memory, ptr) {\n";
      ss << "    return new " << layout.name << "(memory.buffer, ptr);\n";
      ss << "  }\n\n";

      // Getters and setters
      for (const auto& field : layout.fields) {
        if (field.array_length > 0) {
          // Array field
          if (field.is_struct) {
            ss << "  " << field.name << "(index) {\n";
            ss << "    const elemSize = " << (field.size / field.array_length) << ";\n";
            ss << "    return new " << field.struct_name << "(this.view.buffer, this.offset + " << field.offset << " + index * elemSize);\n";
            ss << "  }\n\n";
          } else {
            // Getter for array element
            ss << "  get" << field.name << "(index) {\n";
            size_t elem_size = field.size / field.array_length;
            ss << "    return this.view." << field.ts_getter << "(this.offset + " << field.offset << " + index * " << elem_size << ", true)";
            if (field.ts_type == "boolean") {
              ss << " !== 0";
            }
            ss << ";\n";
            ss << "  }\n\n";

            // Setter for array element
            ss << "  set" << field.name << "(index, value) {\n";
            ss << "    this.view." << field.ts_setter << "(this.offset + " << field.offset << " + index * " << elem_size << ", ";
            if (field.ts_type == "boolean") {
              ss << "value ? 1 : 0";
            } else {
              ss << "value";
            }
            ss << ", true);\n";
            ss << "  }\n\n";

            // Array length getter
            ss << "  get " << field.name << "Length() { return " << field.array_length << "; }\n\n";
          }
        } else if (field.is_struct) {
          // Nested struct field
          ss << "  get " << field.name << "() {\n";
          ss << "    return new " << field.struct_name << "(this.view.buffer, this.offset + " << field.offset << ");\n";
          ss << "  }\n\n";
        } else {
          // Scalar field getter
          ss << "  get " << field.name << "() {\n";
          ss << "    return this.view." << field.ts_getter << "(this.offset + " << field.offset << ", true)";
          if (field.ts_type == "boolean") {
            ss << " !== 0";
          }
          ss << ";\n";
          ss << "  }\n\n";

          // Scalar field setter
          ss << "  set " << field.name << "(value) {\n";
          ss << "    this.view." << field.ts_setter << "(this.offset + " << field.offset << ", ";
          if (field.ts_type == "boolean") {
            ss << "value ? 1 : 0";
          } else {
            ss << "value";
          }
          ss << ", true);\n";
          ss << "  }\n\n";
        }
      }

      ss << "}\n\n";
    }

    js_code_ = ss.str();
  }

 public:
  AlignedGenerator(const Parser& parser, const std::string& path,
                   const std::string& file_name)
      : BaseGenerator(parser, path, file_name, "", "::", "h") {}

  bool generate() override {
    // Only process fixed structs (not tables)
    for (const auto* struct_def : parser_.structs_.vec) {
      if (!struct_def->fixed) {
        // Skip tables - only process structs
        continue;
      }

      StructLayout layout;
      if (!ComputeLayout(*struct_def, layout)) {
        std::cerr << "Warning: Skipping struct " << struct_def->name
                  << " - contains unsupported types for aligned generation\n";
        continue;
      }
      layouts_.push_back(layout);
    }

    if (layouts_.empty()) {
      std::cerr << "No fixed structs found for aligned generation\n";
      return false;
    }

    GenerateCppHeader();
    GenerateTypeScript();
    GenerateJavaScript();
    GenerateLayoutsJSON();
    return true;
  }

  bool save() const {
    // Save C++ header
    const std::string cpp_path = path_ + file_name_ + "_aligned.h";
    if (!parser_.opts.file_saver->SaveFile(cpp_path.c_str(), cpp_code_, false)) {
      return false;
    }

    // Save TypeScript
    const std::string ts_path = path_ + file_name_ + "_aligned.ts";
    if (!parser_.opts.file_saver->SaveFile(ts_path.c_str(), ts_code_, false)) {
      return false;
    }

    // Save JavaScript
    const std::string js_path = path_ + file_name_ + "_aligned.js";
    if (!parser_.opts.file_saver->SaveFile(js_path.c_str(), js_code_, false)) {
      return false;
    }

    // Save JSON layouts
    const std::string json_path = path_ + file_name_ + "_layouts.json";
    if (!parser_.opts.file_saver->SaveFile(json_path.c_str(), json_code_, false)) {
      return false;
    }

    return true;
  }

  const std::string& GetCppCode() const { return cpp_code_; }
  const std::string& GetTsCode() const { return ts_code_; }
  const std::string& GetJsCode() const { return js_code_; }
  const std::string& GetJsonCode() const { return json_code_; }

  // Get combined output as single JSON object
  std::string GetCombinedOutput() const {
    std::ostringstream ss;
    ss << "{";
    ss << "\"cpp\":" << EscapeJsonString(cpp_code_) << ",";
    ss << "\"ts\":" << EscapeJsonString(ts_code_) << ",";
    ss << "\"js\":" << EscapeJsonString(js_code_) << ",";
    // layouts is already JSON, just embed it directly
    // Extract the JSON object from json_code_ (strip markers)
    std::string layouts_json = "{}";
    size_t start = json_code_.find('{');
    size_t end = json_code_.rfind('}');
    if (start != std::string::npos && end != std::string::npos && end > start) {
      layouts_json = json_code_.substr(start, end - start + 1);
    }
    ss << "\"layouts\":" << layouts_json;
    ss << "}";
    return ss.str();
  }

 private:
  static std::string EscapeJsonString(const std::string& s) {
    std::ostringstream ss;
    ss << '"';
    for (char c : s) {
      switch (c) {
        case '"': ss << "\\\""; break;
        case '\\': ss << "\\\\"; break;
        case '\n': ss << "\\n"; break;
        case '\r': ss << "\\r"; break;
        case '\t': ss << "\\t"; break;
        default:
          if (static_cast<unsigned char>(c) < 0x20) {
            ss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
          } else {
            ss << c;
          }
      }
    }
    ss << '"';
    return ss.str();
  }
};

}  // namespace aligned

namespace {

class AlignedCodeGenerator : public CodeGenerator {
 public:
  Status GenerateCode(const Parser& parser, const std::string& path,
                      const std::string& filename) override {
    aligned::AlignedGenerator generator(parser, path, filename);
    if (!generator.generate()) {
      return Status::ERROR;
    }
    return generator.save() ? Status::OK : Status::ERROR;
  }

  Status GenerateCode(const uint8_t*, int64_t, const CodeGenOptions&) override {
    return Status::NOT_IMPLEMENTED;
  }

  Status GenerateCodeString(const Parser& parser, const std::string& filename,
                            std::string& output) override {
    aligned::AlignedGenerator generator(parser, "", filename);
    if (!generator.generate()) {
      return Status::ERROR;
    }
    output = generator.GetCombinedOutput();
    return Status::OK;
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
    return IDLOptions::kMAX;  // No specific language flag yet
  }

  std::string LanguageName() const override { return "Aligned"; }
};

}  // namespace

std::unique_ptr<CodeGenerator> NewAlignedCodeGenerator() {
  return std::unique_ptr<AlignedCodeGenerator>(new AlignedCodeGenerator());
}

}  // namespace flatbuffers
