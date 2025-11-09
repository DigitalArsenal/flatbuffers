/*
 * Copyright 2014 Google Inc. All rights reserved.
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

#include "idl_gen_json_schema.h"

#include <algorithm>
#include <iostream>
#include <limits>
#include <map>
#include <set>

#include "flatbuffers/code_generators.h"
#include "flatbuffers/idl.h"
#include "flatbuffers/util.h"

namespace flatbuffers {

namespace jsons {

namespace {

template <class T>
static std::string GenFullName(const T* enum_def) {
  std::string full_name;
  const auto& name_spaces = enum_def->defined_namespace->components;
  for (auto ns = name_spaces.cbegin(); ns != name_spaces.cend(); ++ns) {
    full_name.append(*ns + "_");
  }
  full_name.append(enum_def->name);
  return full_name;
}

template <class T>
static std::string GenTypeRef(const T* enum_def) {
  return "\"$ref\" : \"#/definitions/" + GenFullName(enum_def) + "\"";
}

static std::string GenType(const std::string& name) {
  return "\"type\" : \"" + name + "\"";
}

static std::string GenType(BaseType type) {
  switch (type) {
    case BASE_TYPE_BOOL:
      return "\"type\" : \"boolean\"";
    case BASE_TYPE_CHAR:
      return "\"type\" : \"integer\", \"minimum\" : " +
             NumToString(std::numeric_limits<int8_t>::min()) +
             ", \"maximum\" : " +
             NumToString(std::numeric_limits<int8_t>::max());
    case BASE_TYPE_UCHAR:
      return "\"type\" : \"integer\", \"minimum\" : 0, \"maximum\" :" +
             NumToString(std::numeric_limits<uint8_t>::max());
    case BASE_TYPE_SHORT:
      return "\"type\" : \"integer\", \"minimum\" : " +
             NumToString(std::numeric_limits<int16_t>::min()) +
             ", \"maximum\" : " +
             NumToString(std::numeric_limits<int16_t>::max());
    case BASE_TYPE_USHORT:
      return "\"type\" : \"integer\", \"minimum\" : 0, \"maximum\" : " +
             NumToString(std::numeric_limits<uint16_t>::max());
    case BASE_TYPE_INT:
      return "\"type\" : \"integer\", \"minimum\" : " +
             NumToString(std::numeric_limits<int32_t>::min()) +
             ", \"maximum\" : " +
             NumToString(std::numeric_limits<int32_t>::max());
    case BASE_TYPE_UINT:
      return "\"type\" : \"integer\", \"minimum\" : 0, \"maximum\" : " +
             NumToString(std::numeric_limits<uint32_t>::max());
    case BASE_TYPE_LONG:
      return "\"type\" : \"integer\", \"minimum\" : " +
             NumToString(std::numeric_limits<int64_t>::min()) +
             ", \"maximum\" : " +
             NumToString(std::numeric_limits<int64_t>::max());
    case BASE_TYPE_ULONG:
      return "\"type\" : \"integer\", \"minimum\" : 0, \"maximum\" : " +
             NumToString(std::numeric_limits<uint64_t>::max());
    case BASE_TYPE_FLOAT:
    case BASE_TYPE_DOUBLE:
      return "\"type\" : \"number\"";
    case BASE_TYPE_STRING:
      return "\"type\" : \"string\"";
    default:
      return "";
  }
}

static std::string GenBaseType(const Type& type) {
  if (type.struct_def != nullptr) {
    return GenTypeRef(type.struct_def);
  }
  if (type.enum_def != nullptr) {
    return GenTypeRef(type.enum_def);
  }
  return GenType(type.base_type);
}

static std::string GenArrayType(const Type& type) {
  std::string element_type;
  if (type.struct_def != nullptr) {
    element_type = GenTypeRef(type.struct_def);
  } else if (type.enum_def != nullptr) {
    element_type = GenTypeRef(type.enum_def);
  } else {
    element_type = GenType(type.element);
  }

  return "\"type\" : \"array\", \"items\" : {" + element_type + "}";
}

static std::string GenType(const Type& type) {
  switch (type.base_type) {
    case BASE_TYPE_ARRAY:
      FLATBUFFERS_FALLTHROUGH();  // fall thru
    case BASE_TYPE_VECTOR: {
      return GenArrayType(type);
    }
    case BASE_TYPE_STRUCT: {
      return GenTypeRef(type.struct_def);
    }
    case BASE_TYPE_UNION: {
      std::string union_type_string("\"anyOf\": [");
      const auto& union_types = type.enum_def->Vals();
      for (auto ut = union_types.cbegin(); ut < union_types.cend(); ++ut) {
        const auto& union_type = *ut;
        if (union_type->union_type.base_type == BASE_TYPE_NONE) {
          continue;
        }
        if (union_type->union_type.base_type == BASE_TYPE_STRUCT) {
          union_type_string.append(
              "{ " + GenTypeRef(union_type->union_type.struct_def) + " }");
        }
        if (union_type != *type.enum_def->Vals().rbegin()) {
          union_type_string.append(",");
        }
      }
      union_type_string.append("]");
      return union_type_string;
    }
    case BASE_TYPE_UTYPE:
      return GenTypeRef(type.enum_def);
    default: {
      return GenBaseType(type);
    }
  }
}

}  // namespace

std::string BuildJsonSchemaIrDefs(const Parser& parser,
                                  const std::string& file_name);
bool GenerateJsonSchemaIr(const Parser& parser, const std::string& path,
                          const std::string& file_name);

class JsonSchemaGenerator : public BaseGenerator {
 private:
  std::string code_;

 public:
  JsonSchemaGenerator(const Parser& parser, const std::string& path,
                      const std::string& file_name)
      : BaseGenerator(parser, path, file_name, "", "", "json") {}

  explicit JsonSchemaGenerator(const BaseGenerator& base_generator)
      : BaseGenerator(base_generator) {}

  std::string GeneratedFileName(const std::string& path,
                                const std::string& file_name,
                                const IDLOptions& options /* unused */) const {
    (void)options;
    return path + file_name + ".schema.json";
  }

  // If indentation is less than 0, that indicates we don't want any newlines
  // either.
  std::string NewLine() const {
    return parser_.opts.indent_step >= 0 ? "\n" : "";
  }

  std::string Indent(int indent) const {
    const auto num_spaces = indent * std::max(parser_.opts.indent_step, 0);
    return std::string(num_spaces, ' ');
  }

  std::string PrepareDescription(
      const std::vector<std::string>& comment_lines) {
    std::string comment;
    for (auto line_iterator = comment_lines.cbegin();
         line_iterator != comment_lines.cend(); ++line_iterator) {
      const auto& comment_line = *line_iterator;

      // remove leading and trailing spaces from comment line
      const auto start = std::find_if(comment_line.begin(), comment_line.end(),
                                      [](char c) { return !isspace(c); });
      const auto end =
          std::find_if(comment_line.rbegin(), comment_line.rend(), [](char c) {
            return !isspace(c);
          }).base();
      if (start < end) {
        comment.append(start, end);
      } else {
        comment.append(comment_line);
      }

      if (line_iterator + 1 != comment_lines.cend()) comment.append("\n");
    }
    if (!comment.empty()) {
      std::string description;
      if (EscapeString(comment.c_str(), comment.length(), &description, true,
                       true)) {
        return description;
      }
      return "";
    }
    return "";
  }

  bool generate() {
    code_ = "";
    if (parser_.root_struct_def_ == nullptr) {
      std::cerr << "Error: Binary schema not generated, no root struct found\n";
      return false;
    }
    code_ += "{" + NewLine();
    code_ += Indent(1) +
             "\"$schema\": \"https://json-schema.org/draft/2019-09/schema\"," +
             NewLine();
    code_ += Indent(1) + "\"definitions\": {" + NewLine();
    for (auto e = parser_.enums_.vec.cbegin(); e != parser_.enums_.vec.cend();
         ++e) {
      code_ += Indent(2) + "\"" + GenFullName(*e) + "\" : {" + NewLine();
      code_ += Indent(3) + GenType("string") + "," + NewLine();
      auto enumdef(Indent(3) + "\"enum\": [");
      for (auto enum_value = (*e)->Vals().begin();
           enum_value != (*e)->Vals().end(); ++enum_value) {
        enumdef.append("\"" + (*enum_value)->name + "\"");
        if (*enum_value != (*e)->Vals().back()) {
          enumdef.append(", ");
        }
      }
      enumdef.append("]");
      code_ += enumdef + NewLine();
      code_ += Indent(2) + "}," + NewLine();  // close type
    }
    for (auto s = parser_.structs_.vec.cbegin();
         s != parser_.structs_.vec.cend(); ++s) {
      const auto& structure = *s;
      code_ += Indent(2) + "\"" + GenFullName(structure) + "\" : {" + NewLine();
      code_ += Indent(3) + GenType("object") + "," + NewLine();
      const auto& comment_lines = structure->doc_comment;
      auto comment = PrepareDescription(comment_lines);
      if (comment != "") {
        code_ += Indent(3) + "\"description\" : " + comment + "," + NewLine();
      }

      code_ += Indent(3) + "\"properties\" : {" + NewLine();

      const auto& properties = structure->fields.vec;
      for (auto prop = properties.cbegin(); prop != properties.cend(); ++prop) {
        const auto& property = *prop;
        std::string arrayInfo = "";
        if (IsArray(property->value.type)) {
          arrayInfo = "," + NewLine() + Indent(8) + "\"minItems\": " +
                      NumToString(property->value.type.fixed_length) + "," +
                      NewLine() + Indent(8) + "\"maxItems\": " +
                      NumToString(property->value.type.fixed_length);
        }
        std::string deprecated_info = "";
        if (property->deprecated) {
          deprecated_info =
              "," + NewLine() + Indent(8) + "\"deprecated\" : true";
        }
        std::string typeLine = Indent(4) + "\"" + property->name + "\"";
        typeLine += " : {" + NewLine() + Indent(8);
        typeLine += GenType(property->value.type);
        typeLine += arrayInfo;
        typeLine += deprecated_info;
        auto description = PrepareDescription(property->doc_comment);
        if (description != "") {
          typeLine +=
              "," + NewLine() + Indent(8) + "\"description\" : " + description;
        }

        typeLine += NewLine() + Indent(7) + "}";
        if (property != properties.back()) {
          typeLine.append(",");
        }
        code_ += typeLine + NewLine();
      }
      code_ += Indent(3) + "}," + NewLine();  // close properties

      std::vector<FieldDef*> requiredProperties;
      std::copy_if(properties.begin(), properties.end(),
                   back_inserter(requiredProperties),
                   [](FieldDef const* prop) { return prop->IsRequired(); });
      if (!requiredProperties.empty()) {
        auto required_string(Indent(3) + "\"required\" : [");
        for (auto req_prop = requiredProperties.cbegin();
             req_prop != requiredProperties.cend(); ++req_prop) {
          required_string.append("\"" + (*req_prop)->name + "\"");
          if (*req_prop != requiredProperties.back()) {
            required_string.append(", ");
          }
        }
        required_string.append("],");
        code_ += required_string + NewLine();
      }
      code_ += Indent(3) + "\"additionalProperties\" : false" + NewLine();
      auto closeType(Indent(2) + "}");
      if (*s != parser_.structs_.vec.back()) {
        closeType.append(",");
      }
      code_ += closeType + NewLine();  // close type
    }
    code_ += Indent(1) + "}," + NewLine();  // close definitions

    if (parser_.ShouldEmitJsonSchemaIrMetadata()) {
      std::string ir_defs = BuildJsonSchemaIrDefs(parser_, file_name_);
      if (!ir_defs.empty()) {
        if (parser_.opts.indent_step >= 0) {
          const std::string indent = Indent(1);
          size_t pos = 0;
          while ((pos = ir_defs.find('\n', pos)) != std::string::npos) {
            pos += 1;
            if (pos < ir_defs.size()) {
              ir_defs.insert(pos, indent);
              pos += indent.size();
            }
          }
        }
        code_ += Indent(1) + "\"$defs\" : " + ir_defs + "," + NewLine();
      }
    }

    // mark root type
    code_ += Indent(1) + "\"$ref\" : \"#/definitions/" +
             GenFullName(parser_.root_struct_def_) + "\"" + NewLine();

    code_ += "}" + NewLine();  // close schema root
    return true;
  }

  bool save() const {
    const auto file_path = GeneratedFileName(path_, file_name_, parser_.opts);
    return SaveFile(file_path.c_str(), code_, false);
  }

  const std::string getJson() { return code_; }
};

class JsonWriter {
 public:
  explicit JsonWriter(int indent_step)
      : indent_step_(indent_step >= 0 ? indent_step : 2),
        expecting_value_(false) {}

  void BeginObject() {
    StartValue();
    out_ += "{";
    frames_.push_back(Frame{/*is_object=*/true, /*first=*/true});
  }

  void EndObject() {
    FLATBUFFERS_ASSERT(!frames_.empty() && frames_.back().is_object);
    const auto frame = frames_.back();
    frames_.pop_back();
    if (!frame.first) {
      out_ += "\n";
      AppendIndent(frames_.size());
    }
    out_ += "}";
  }

  void BeginArray() {
    StartValue();
    out_ += "[";
    frames_.push_back(Frame{/*is_object=*/false, /*first=*/true});
  }

  void EndArray() {
    FLATBUFFERS_ASSERT(!frames_.empty() && !frames_.back().is_object);
    const auto frame = frames_.back();
    frames_.pop_back();
    if (!frame.first) {
      out_ += "\n";
      AppendIndent(frames_.size());
    }
    out_ += "]";
  }

  void Key(const std::string& key) {
    FLATBUFFERS_ASSERT(!frames_.empty() && frames_.back().is_object);
    auto& frame = frames_.back();
    if (!frame.first) {
      out_ += ",\n";
    } else {
      out_ += "\n";
      frame.first = false;
    }
    AppendIndent(frames_.size());
    out_ += JsonString(key);
    out_ += " : ";
    expecting_value_ = true;
  }

  void String(const std::string& value) {
    StartValue();
    out_ += JsonString(value);
  }

  void Bool(bool value) {
    StartValue();
    out_ += value ? "true" : "false";
  }

  void Int(int64_t value) {
    StartValue();
    out_ += NumToString(value);
  }

  void Uint(uint64_t value) {
    StartValue();
    out_ += NumToString(value);
  }

  void Double(double value) {
    StartValue();
    out_ += FloatToString(value, std::numeric_limits<double>::max_digits10);
  }

  void Null() {
    StartValue();
    out_ += "null";
  }

  std::string Release() {
    FLATBUFFERS_ASSERT(frames_.empty());
    return out_;
  }

 private:
  struct Frame {
    bool is_object;
    bool first;
  };

  void StartValue() {
    if (expecting_value_) {
      expecting_value_ = false;
      return;
    }
    if (frames_.empty()) return;
    auto& frame = frames_.back();
    if (!frame.first) {
      out_ += ",\n";
    } else {
      out_ += "\n";
      frame.first = false;
    }
    AppendIndent(frames_.size());
  }

  void AppendIndent(size_t depth) {
    out_.append(static_cast<size_t>(indent_step_) * depth, ' ');
  }

  static std::string JsonString(const std::string& value) {
    std::string escaped;
    if (!EscapeString(value.c_str(), value.length(), &escaped, true, true))
      return "\"\"";
    return escaped;
  }

  std::string out_;
  std::vector<Frame> frames_;
  int indent_step_;
  bool expecting_value_;
};

const char* BaseTypeToString(BaseType base_type) {
  switch (base_type) {
    case BASE_TYPE_NONE: return "none";
    case BASE_TYPE_UTYPE: return "utype";
    case BASE_TYPE_BOOL: return "bool";
    case BASE_TYPE_CHAR: return "byte";
    case BASE_TYPE_UCHAR: return "ubyte";
    case BASE_TYPE_SHORT: return "short";
    case BASE_TYPE_USHORT: return "ushort";
    case BASE_TYPE_INT: return "int";
    case BASE_TYPE_UINT: return "uint";
    case BASE_TYPE_LONG: return "long";
    case BASE_TYPE_ULONG: return "ulong";
    case BASE_TYPE_FLOAT: return "float";
    case BASE_TYPE_DOUBLE: return "double";
    case BASE_TYPE_STRING: return "string";
    case BASE_TYPE_STRUCT: return "struct";
    case BASE_TYPE_VECTOR: return "vector";
    case BASE_TYPE_VECTOR64: return "vector64";
    case BASE_TYPE_ARRAY: return "array";
    case BASE_TYPE_UNION: return "union";
    default: return "unknown";
  }
}

std::string QualifiedName(const Definition& def) {
  if (!def.defined_namespace) return def.name;
  return def.defined_namespace->GetFullyQualifiedName(def.name);
}

void WriteStringArray(JsonWriter& writer,
                      const std::vector<std::string>& values) {
  writer.BeginArray();
  for (const auto& value : values) {
    writer.String(value);
  }
  writer.EndArray();
}

void WriteNamespace(JsonWriter& writer, const Namespace* ns) {
  std::vector<std::string> components;
  if (ns) components = ns->components;
  WriteStringArray(writer, components);
}

void WriteDoc(JsonWriter& writer, const std::vector<std::string>& doc) {
  WriteStringArray(writer, doc);
}

void WriteType(const Type& type, JsonWriter& writer);

void WriteAttributes(JsonWriter& writer, const SymbolTable<Value>& attributes) {
  writer.BeginArray();
  for (const auto& it : attributes.dict) {
    writer.BeginObject();
    writer.Key("name");
    writer.String(it.first);
    writer.Key("value");
    writer.String(it.second->constant);
    writer.Key("type");
    writer.String(BaseTypeToString(it.second->type.base_type));
    writer.EndObject();
  }
  writer.EndArray();
}

void WriteType(const Type& type, JsonWriter& writer) {
  writer.BeginObject();
  writer.Key("base_type");
  writer.String(BaseTypeToString(type.base_type));
  if (type.element != BASE_TYPE_NONE) {
    writer.Key("element");
    writer.String(BaseTypeToString(type.element));
  }
  if (type.fixed_length) {
    writer.Key("fixed_length");
    writer.Uint(type.fixed_length);
  }
  if (type.struct_def) {
    writer.Key("struct");
    writer.String(QualifiedName(*type.struct_def));
  }
  if (type.enum_def) {
    writer.Key("enum");
    writer.String(QualifiedName(*type.enum_def));
  }
  writer.EndObject();
}

void WriteField(const FieldDef& field, JsonWriter& writer) {
  writer.BeginObject();
  writer.Key("name");
  writer.String(field.name);
  writer.Key("id");
  writer.Int(field.value.offset ==
                     static_cast<voffset_t>(~static_cast<voffset_t>(0))
                 ? -1
                 : static_cast<int64_t>(field.value.offset));
  writer.Key("presence");
  const char* presence = "default";
  if (field.IsRequired()) presence = "required";
  else if (field.IsOptional()) presence = "optional";
  writer.String(presence);
  writer.Key("deprecated");
  writer.Bool(field.deprecated);
  writer.Key("key");
  writer.Bool(field.key);
  writer.Key("shared");
  writer.Bool(field.shared);
  writer.Key("native_inline");
  writer.Bool(field.native_inline);
  writer.Key("flexbuffer");
  writer.Bool(field.flexbuffer);
  writer.Key("offset64");
  writer.Bool(field.offset64);
  writer.Key("doc");
  WriteDoc(writer, field.doc_comment);
  writer.Key("attributes");
  WriteAttributes(writer, field.attributes);
  writer.Key("type");
  WriteType(field.value.type, writer);
  writer.Key("default");
  writer.String(field.value.constant);
  if (field.nested_flatbuffer) {
    writer.Key("nested_flatbuffer");
    writer.String(QualifiedName(*field.nested_flatbuffer));
  }
  if (field.sibling_union_field) {
    writer.Key("sibling");
    writer.String(field.sibling_union_field->name);
  }
  writer.EndObject();
}

void WriteFields(const StructDef& def, JsonWriter& writer) {
  writer.BeginArray();
  for (auto field_it = def.fields.vec.begin(); field_it != def.fields.vec.end();
       ++field_it) {
    WriteField(**field_it, writer);
  }
  writer.EndArray();
}

void WriteTable(const StructDef& def, JsonWriter& writer) {
  writer.BeginObject();
  writer.Key("kind");
  writer.String(def.fixed ? "struct" : "table");
  writer.Key("name");
  writer.String(def.name);
  writer.Key("namespace");
  WriteNamespace(writer, def.defined_namespace);
  writer.Key("doc");
  WriteDoc(writer, def.doc_comment);
  writer.Key("attributes");
  WriteAttributes(writer, def.attributes);
  writer.Key("fields");
  WriteFields(def, writer);
  writer.Key("sortbysize");
  writer.Bool(def.sortbysize);
  writer.Key("has_key");
  writer.Bool(def.has_key);
  writer.Key("file");
  writer.String(PosixPath(def.file));
  if (def.declaration_file) {
    writer.Key("declaration_file");
    writer.String(*def.declaration_file);
  }
  if (def.fixed) {
    writer.Key("minalign");
    writer.Uint(def.minalign);
    writer.Key("bytesize");
    writer.Uint(def.bytesize);
  }
  writer.EndObject();
}

void WriteEnumValues(const EnumDef& def, JsonWriter& writer) {
  writer.BeginArray();
  for (auto it = def.Vals().begin(); it != def.Vals().end(); ++it) {
    const EnumVal& val = **it;
    writer.BeginObject();
    writer.Key("name");
    writer.String(val.name);
    writer.Key("value");
    writer.Int(val.GetAsInt64());
    writer.Key("doc");
    WriteDoc(writer, val.doc_comment);
    writer.Key("attributes");
    WriteAttributes(writer, val.attributes);
    if (def.is_union) {
      writer.Key("union_type");
      WriteType(val.union_type, writer);
    }
    writer.EndObject();
  }
  writer.EndArray();
}

void WriteEnum(const EnumDef& def, JsonWriter& writer) {
  writer.BeginObject();
  writer.Key("kind");
  writer.String("enum");
  writer.Key("name");
  writer.String(def.name);
  writer.Key("namespace");
  WriteNamespace(writer, def.defined_namespace);
  writer.Key("doc");
  WriteDoc(writer, def.doc_comment);
  writer.Key("attributes");
  WriteAttributes(writer, def.attributes);
  writer.Key("underlying_type");
  WriteType(def.underlying_type, writer);
  writer.Key("is_union");
  writer.Bool(def.is_union);
  writer.Key("values");
  WriteEnumValues(def, writer);
  writer.Key("file");
  writer.String(PosixPath(def.file));
  if (def.declaration_file) {
    writer.Key("declaration_file");
    writer.String(*def.declaration_file);
  }
  writer.EndObject();
}

struct FileDefinitions {
  std::vector<const StructDef*> tables;
  std::vector<const StructDef*> structs;
  std::vector<const EnumDef*> enums;
  std::vector<const ServiceDef*> services;
};

FileDefinitions CollectDefinitions(const Parser& parser,
                                   const std::string& file_name) {
  FileDefinitions defs;
  const std::string target = PosixPath(file_name);
  for (auto it = parser.structs_.vec.begin(); it != parser.structs_.vec.end();
       ++it) {
    const StructDef* def = *it;
    if (PosixPath(def->file) != target) continue;
    if (def->fixed)
      defs.structs.push_back(def);
    else
      defs.tables.push_back(def);
  }
  for (auto it = parser.enums_.vec.begin(); it != parser.enums_.vec.end();
       ++it) {
    const EnumDef* def = *it;
    if (PosixPath(def->file) != target) continue;
    defs.enums.push_back(def);
  }
  for (auto it = parser.services_.vec.begin();
       it != parser.services_.vec.end(); ++it) {
    const ServiceDef* def = *it;
    if (PosixPath(def->file) != target) continue;
    defs.services.push_back(def);
  }
  return defs;
}

std::string ResolveSchemaSource(const Parser& parser,
                                const std::string& file_base) {
  const std::string suffix = file_base + ".fbs";
  auto match = [&suffix](const Definition& def) -> bool {
    if (def.file.empty()) return false;
    std::string def_file = PosixPath(def.file);
    return def_file.size() >= suffix.size() &&
           def_file.compare(def_file.size() - suffix.size(), suffix.size(),
                            suffix) == 0;
  };

  for (auto it = parser.structs_.vec.begin(); it != parser.structs_.vec.end();
       ++it) {
    if (match(**it)) return PosixPath((*it)->file);
  }
  for (auto it = parser.enums_.vec.begin(); it != parser.enums_.vec.end();
       ++it) {
    if (match(**it)) return PosixPath((*it)->file);
  }
  for (auto it = parser.services_.vec.begin();
       it != parser.services_.vec.end(); ++it) {
    if (match(**it)) return PosixPath((*it)->file);
  }
  return suffix;
}

std::vector<std::string> SplitPathComponents(const std::string& path) {
  std::vector<std::string> components;
  size_t start = 0;
  while (start < path.size()) {
    size_t end = path.find(kPathSeparator, start);
    size_t length = (end == std::string::npos) ? std::string::npos : end - start;
    std::string part = path.substr(start, length);
    if (!part.empty() && part != ".") components.push_back(part);
    if (end == std::string::npos) break;
    start = end + 1;
  }
  return components;
}

std::string RelativePathFrom(const std::string& from_dir,
                             const std::string& to_path) {
  if (from_dir.empty()) return to_path;
  std::string from = PosixPath(from_dir);
  std::string to = PosixPath(to_path);

  if (!from.empty() && from.back() == kPathSeparator) from.pop_back();
  if (!to.empty() && to.back() == kPathSeparator) to.pop_back();

  const bool from_abs = !from.empty() && from.front() == kPathSeparator;
  const bool to_abs = !to.empty() && to.front() == kPathSeparator;

  if (from.empty()) return to;
  if (from_abs != to_abs) return to;

  std::vector<std::string> from_parts = SplitPathComponents(from);
  std::vector<std::string> to_parts = SplitPathComponents(to);

  size_t common = 0;
  while (common < from_parts.size() && common < to_parts.size() &&
         from_parts[common] == to_parts[common]) {
    ++common;
  }

  std::string result;
  for (size_t i = common; i < from_parts.size(); ++i) {
    if (!result.empty()) result += kPathSeparator;
    result += "..";
  }
  for (size_t i = common; i < to_parts.size(); ++i) {
    if (!result.empty()) result += kPathSeparator;
    result += to_parts[i];
  }

  if (result.empty()) return ".";
  return result;
}

std::vector<std::string> CollectIncludes(
    const Parser& parser, const std::string& file_name) {
  std::vector<std::string> includes;
  auto it = parser.files_included_per_file_.find(file_name);
  if (it == parser.files_included_per_file_.end()) {
    std::string posix = PosixPath(file_name);
    it = parser.files_included_per_file_.find(posix);
  }
  if (it == parser.files_included_per_file_.end()) {
    std::string abs = AbsolutePath(file_name);
    if (!abs.empty()) {
      abs = PosixPath(abs);
      it = parser.files_included_per_file_.find(abs);
    }
  }
  if (it == parser.files_included_per_file_.end()) return includes;

  const std::string source_abs = PosixPath(AbsolutePath(file_name));
  const std::string source_dir =
      PosixPath(StripFileName(source_abs.empty() ? file_name : source_abs));

  std::set<std::string> seen;
  for (const auto& included : it->second) {
    std::string include_path = included.filename.empty()
                                   ? included.schema_name
                                   : included.filename;
    if (include_path.empty()) continue;
    include_path = PosixPath(AbsolutePath(include_path));
    if (include_path.empty()) continue;
    if (include_path == source_abs) continue;
    if (!seen.insert(include_path).second) continue;

    std::string relative =
        RelativePathFrom(source_dir.empty() ? "." : source_dir, include_path);
    if (relative == ".") continue;
    relative = PosixPath(relative);
    std::string no_ext = StripExtension(relative);
    includes.push_back(no_ext + ".ir.schema.json");
  }
  std::sort(includes.begin(), includes.end());
  includes.erase(std::unique(includes.begin(), includes.end()), includes.end());
  return includes;
}

void WriteFileMetadata(JsonWriter& writer, const Parser& parser,
                       const std::string& schema_source,
                       const FileDefinitions& defs) {
  writer.BeginObject();
  writer.Key("const");
  writer.BeginObject();
  writer.Key("source");
  writer.String(schema_source);

  if (parser.root_struct_def_ &&
      PosixPath(parser.root_struct_def_->file) == PosixPath(schema_source)) {
    writer.Key("root_type");
    writer.String(QualifiedName(*parser.root_struct_def_));
  }

  if (parser.file_identifier_.length() == kFileIdentifierLength) {
    writer.Key("file_identifier");
    writer.String(parser.file_identifier_);
  }
  if (!parser.file_extension_.empty()) {
    writer.Key("file_extension");
    writer.String(parser.file_extension_);
  }

  std::set<std::string> attributes;
  for (const auto* table : defs.tables) {
    for (const auto& attr : table->attributes.dict) {
      attributes.insert(attr.first);
    }
  }
  for (const auto* strct : defs.structs) {
    for (const auto& attr : strct->attributes.dict) {
      attributes.insert(attr.first);
    }
  }
  for (const auto& attr : parser.known_attributes_) {
    attributes.insert(attr.first);
  }
  for (const auto* en : defs.enums) {
    for (const auto& attr : en->attributes.dict) {
      attributes.insert(attr.first);
    }
  }
  if (!attributes.empty()) {
    writer.Key("attributes");
    writer.BeginArray();
    for (const auto& name : attributes) writer.String(name);
    writer.EndArray();
  }

  writer.EndObject();
  writer.EndObject();
}

void EmitJsonSchemaIrDefinitions(const Parser& parser,
                                 const std::string& schema_source,
                                 const FileDefinitions& defs,
                                 JsonWriter& writer) {
  writer.Key("$file");
  WriteFileMetadata(writer, parser, schema_source, defs);

  std::map<std::string, const StructDef*> struct_index;
  for (const auto* def : defs.tables) {
    struct_index[QualifiedName(*def)] = def;
  }
  for (const auto* def : defs.structs) {
    struct_index[QualifiedName(*def)] = def;
  }
  std::map<std::string, const EnumDef*> enum_index;
  for (const auto* def : defs.enums) {
    enum_index[QualifiedName(*def)] = def;
  }

  const std::string schema_source_posix = PosixPath(schema_source);

  std::vector<std::string> definition_order;
  for (const auto* enum_def : parser.enums_.vec) {
    if (PosixPath(enum_def->file) == schema_source_posix) {
      definition_order.push_back(QualifiedName(*enum_def));
    }
  }
  for (const auto* struct_def : parser.structs_.vec) {
    if (PosixPath(struct_def->file) == schema_source_posix) {
      definition_order.push_back(QualifiedName(*struct_def));
    }
  }

  if (definition_order.empty()) {
    for (const auto* enum_def : defs.enums) {
      definition_order.push_back(QualifiedName(*enum_def));
    }
    for (const auto* def : defs.tables) {
      definition_order.push_back(QualifiedName(*def));
    }
    for (const auto* def : defs.structs) {
      definition_order.push_back(QualifiedName(*def));
    }
  }

  if (!definition_order.empty()) {
    writer.Key("$order");
    writer.BeginObject();
    writer.Key("const");
    writer.BeginArray();
    for (const auto& name : definition_order) writer.String(name);
    writer.EndArray();
    writer.EndObject();
  }

  std::set<std::string> emitted;
  for (const auto& name : definition_order) {
    auto struct_it = struct_index.find(name);
    if (struct_it != struct_index.end()) {
      writer.Key(name);
      writer.BeginObject();
      writer.Key("const");
      WriteTable(*struct_it->second, writer);
      writer.EndObject();
      emitted.insert(name);
      continue;
    }
    auto enum_it = enum_index.find(name);
    if (enum_it != enum_index.end()) {
      writer.Key(name);
      writer.BeginObject();
      writer.Key("const");
      WriteEnum(*enum_it->second, writer);
      writer.EndObject();
      emitted.insert(name);
      continue;
    }
  }

  auto emit_remaining_structs = [&](const std::vector<const StructDef*>& list) {
    for (const auto* def : list) {
      const std::string name = QualifiedName(*def);
      if (emitted.count(name)) continue;
      writer.Key(name);
      writer.BeginObject();
      writer.Key("const");
      WriteTable(*def, writer);
      writer.EndObject();
      emitted.insert(name);
    }
  };
  emit_remaining_structs(defs.tables);
  emit_remaining_structs(defs.structs);
  for (const auto* enum_def : defs.enums) {
    const std::string name = QualifiedName(*enum_def);
    if (emitted.count(name)) continue;
    writer.Key(name);
    writer.BeginObject();
    writer.Key("const");
    WriteEnum(*enum_def, writer);
    writer.EndObject();
    emitted.insert(name);
  }
}

std::string BuildJsonSchemaIrDefsInternal(const Parser& parser,
                                          const std::string& schema_source,
                                          const FileDefinitions& defs) {
  JsonWriter writer(parser.opts.indent_step);
  writer.BeginObject();
  EmitJsonSchemaIrDefinitions(parser, schema_source, defs, writer);
  writer.EndObject();
  std::string out = writer.Release();
  if (parser.opts.indent_step >= 0) out += "\n";
  return out;
}

std::string BuildJsonSchemaIrDefs(const Parser& parser,
                                  const std::string& file_name) {
  const std::string schema_source = ResolveSchemaSource(parser, file_name);
  const FileDefinitions defs = CollectDefinitions(parser, schema_source);
  return BuildJsonSchemaIrDefsInternal(parser, schema_source, defs);
}

bool GenerateJsonSchemaIr(const Parser& parser, const std::string& path,
                          const std::string& file_name) {
  const std::string schema_source = ResolveSchemaSource(parser, file_name);
  const FileDefinitions defs = CollectDefinitions(parser, schema_source);
  JsonWriter writer(parser.opts.indent_step);
  writer.BeginObject();

  writer.Key("$schema");
  writer.String("https://json-schema.org/draft/2020-12/schema");

  const std::string schema_id =
      PosixPath(StripExtension(schema_source) + ".ir.schema.json");
  writer.Key("$id");
  writer.String(schema_id);

  if (parser.root_struct_def_ &&
      PosixPath(parser.root_struct_def_->file) == PosixPath(schema_source)) {
    writer.Key("$ref");
    writer.String("#/$defs/" + QualifiedName(*parser.root_struct_def_));
  }

  const std::vector<std::string> includes =
      CollectIncludes(parser, schema_source);
  if (!includes.empty()) {
    writer.Key("allOf");
    writer.BeginArray();
    for (const auto& include : includes) {
      writer.BeginObject();
      writer.Key("$ref");
      writer.String(include);
      writer.EndObject();
    }
    writer.EndArray();
  }

  writer.Key("$defs");
  writer.BeginObject();
  EmitJsonSchemaIrDefinitions(parser, schema_source, defs, writer);
  writer.EndObject();
  writer.EndObject();

  std::string output = writer.Release();
  if (parser.opts.indent_step >= 0) output += "\n";

  std::string relative_output =
      PosixPath(StripExtension(schema_source) + ".ir.schema.json");
  std::string file_path =
      ConCatPathFileName(path, relative_output);
  EnsureDirExists(StripFileName(file_path));
  return SaveFile(file_path.c_str(), output, false);
}

class JsonSchemaIrCodeGenerator : public CodeGenerator {
 public:
  Status GenerateCode(const Parser& parser, const std::string& path,
                      const std::string& filename) override {
    if (!GenerateJsonSchemaIr(parser, path, filename)) {
      return Status::ERROR;
    }
    return Status::OK;
  }

  Status GenerateCode(const uint8_t*, int64_t,
                      const CodeGenOptions&) override {
    return Status::NOT_IMPLEMENTED;
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
    return IDLOptions::kJsonSchema;
  }

  std::string LanguageName() const override { return "JsonSchemaIR"; }
};
}  // namespace jsons

static bool GenerateJsonSchema(const Parser& parser, const std::string& path,
                               const std::string& file_name) {
  jsons::JsonSchemaGenerator generator(parser, path, file_name);
  if (!generator.generate()) {
    return false;
  }
  return generator.save();
}

namespace {

class JsonSchemaCodeGenerator : public CodeGenerator {
 public:
  Status GenerateCode(const Parser& parser, const std::string& path,
                      const std::string& filename) override {
    if (!GenerateJsonSchema(parser, path, filename)) {
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
    return IDLOptions::kJsonSchema;
  }

  std::string LanguageName() const override { return "JsonSchema"; }
};
}  // namespace

std::unique_ptr<CodeGenerator> CreateJsonSchemaCodeGenerator() {
  return std::unique_ptr<JsonSchemaCodeGenerator>(
      new JsonSchemaCodeGenerator());
}

std::unique_ptr<CodeGenerator> CreateJsonSchemaIrCodeGenerator() {
  return std::unique_ptr<jsons::JsonSchemaIrCodeGenerator>(
      new jsons::JsonSchemaIrCodeGenerator());
}
}  // namespace flatbuffers
