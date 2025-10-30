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
#include <cctype>
#include <iostream>
#include <limits>

#include "flatbuffers/code_generators.h"
#include "flatbuffers/idl.h"
#include "flatbuffers/util.h"

namespace flatbuffers {

namespace jsons {

namespace {

static std::string EncodeBase64(const uint8_t* data, size_t len) {
  static const char kAlphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((len + 2) / 3) * 4);
  size_t i = 0;
  while (i + 3 <= len) {
    uint32_t chunk = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
    out.push_back(kAlphabet[(chunk >> 18) & 0x3F]);
    out.push_back(kAlphabet[(chunk >> 12) & 0x3F]);
    out.push_back(kAlphabet[(chunk >> 6) & 0x3F]);
    out.push_back(kAlphabet[chunk & 0x3F]);
    i += 3;
  }
  if (i < len) {
    uint32_t chunk = static_cast<uint32_t>(data[i]) << 16;
    out.push_back(kAlphabet[(chunk >> 18) & 0x3F]);
    if (i + 1 < len) {
      chunk |= static_cast<uint32_t>(data[i + 1]) << 8;
      out.push_back(kAlphabet[(chunk >> 12) & 0x3F]);
      out.push_back(kAlphabet[(chunk >> 6) & 0x3F]);
      out.push_back('=');
    } else {
      out.push_back(kAlphabet[(chunk >> 12) & 0x3F]);
      out.push_back('=');
      out.push_back('=');
    }
  }
  return out;
}

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

class JsonSchemaGenerator : public BaseGenerator {
 private:
  std::string code_;
  std::string schema_bfbs_base64_;

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

  std::string JsonBool(bool value) const { return value ? "true" : "false"; }

  std::string JsonString(const std::string& value) const {
    std::string escaped;
    if (!EscapeString(value.c_str(), value.length(), &escaped, true, true))
      return "\"\"";
    return escaped;
  }

  template <typename T>
  std::string QualifiedNameString(const T* def) const {
    if (!def) return std::string();
    if (def->defined_namespace) {
      return def->defined_namespace->GetFullyQualifiedName(def->name);
    }
    return def->name;
  }

  std::string CanonicalDefaultValue(const FieldDef& field) const {
    const std::string& constant = field.value.constant;
    if (constant.empty()) return constant;
    if (!IsFloat(field.value.type.base_type)) return constant;
    std::string prefix;
    std::string token = constant;
    if (!token.empty() && (token[0] == '+' || token[0] == '-')) {
      prefix = token.substr(0, 1);
      token.erase(0, 1);
    }
    std::string lowered = token;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                   [](unsigned char c) {
                     return static_cast<char>(std::tolower(c));
                   });
    if (lowered == "inf" || lowered == "infinity")
      return prefix == "-" ? "-inf" : "inf";
    if (lowered == "nan") return prefix == "-" ? "-nan" : "nan";
    if (field.value.type.base_type == BASE_TYPE_FLOAT) {
      float numeric = 0.0f;
      if (StringToNumber(constant.c_str(), &numeric)) {
        return FloatToString(static_cast<double>(numeric),
                             std::numeric_limits<float>::max_digits10);
      }
    } else {
      double numeric = 0.0;
      if (StringToNumber(constant.c_str(), &numeric)) {
        return FloatToString(numeric,
                             std::numeric_limits<double>::max_digits10);
      }
    }
    return constant;
  }

  std::string GenAttributesMetadata(const SymbolTable<Value>& attributes,
                                    int indent) const {
    if (attributes.dict.empty()) return "";
    std::string out = Indent(indent) + "\"attributes\" : {" + NewLine();
    size_t index = 0;
    for (auto it = attributes.dict.cbegin(); it != attributes.dict.cend();
         ++it, ++index) {
      out += Indent(indent + 1) + JsonString(it->first) + " : " +
             JsonString(it->second->constant);
      if (index + 1 != attributes.dict.size()) out += ",";
      out += NewLine();
    }
    out += Indent(indent) + "}";
    return out;
  }

  std::string GenDocMetadata(const std::vector<std::string>& comments,
                             int indent) const {
    if (comments.empty()) return "";
    std::string out = Indent(indent) + "\"doc\" : [" + NewLine();
    for (size_t i = 0; i < comments.size(); ++i) {
      out += Indent(indent + 1) + JsonString(comments[i]);
      if (i + 1 != comments.size()) out += ",";
      out += NewLine();
    }
    out += Indent(indent) + "]";
    return out;
  }

  std::string GenTypeMetadata(const Type& type, int indent) const {
    std::string out = Indent(indent) + "\"base_type\" : " +
                     JsonString(reflection::EnumNameBaseType(
                         static_cast<reflection::BaseType>(type.base_type)));
    if (type.element != BASE_TYPE_NONE) {
      out += "," + NewLine() + Indent(indent) +
             "\"element\" : " +
             JsonString(reflection::EnumNameBaseType(
                 static_cast<reflection::BaseType>(type.element)));
    }
    if (type.fixed_length) {
      out += "," + NewLine() + Indent(indent) +
             "\"fixed_length\" : " +
             NumToString(type.fixed_length);
    }
    if (type.struct_def != nullptr) {
      out += "," + NewLine() + Indent(indent) +
             "\"struct\" : " +
             JsonString(QualifiedNameString(type.struct_def));
    }
    if (type.enum_def != nullptr) {
      out += "," + NewLine() + Indent(indent) +
             "\"enum\" : " +
             JsonString(QualifiedNameString(type.enum_def));
    }
    return "{" + NewLine() + out + NewLine() + Indent(indent - 1) + "}";
  }

  std::string GenFieldMetadata(const FieldDef& field, int indent) const {
    std::string out = Indent(indent) + "\"name\" : " + JsonString(field.name) +
                     "," + NewLine() + Indent(indent) +
                     "\"type\" : " +
                     GenTypeMetadata(field.value.type, indent + 1);
    out += "," + NewLine() + Indent(indent) +
           "\"presence\" : " +
           JsonString([&]() {
             switch (field.presence) {
               case FieldDef::kRequired: return std::string("required");
               case FieldDef::kOptional: return std::string("optional");
               default: return std::string("default");
             }
           }());
    out += "," + NewLine() + Indent(indent) +
           "\"offset\" : " + NumToString(field.value.offset);
    if (!field.value.constant.empty()) {
      out += "," + NewLine() + Indent(indent) +
             "\"default\" : " + JsonString(CanonicalDefaultValue(field));
    }
    out += "," + NewLine() + Indent(indent) +
           "\"deprecated\" : " + JsonBool(field.deprecated);
    out += "," + NewLine() + Indent(indent) +
           "\"key\" : " + JsonBool(field.key);
    out += "," + NewLine() + Indent(indent) +
           "\"shared\" : " + JsonBool(field.shared);
    out += "," + NewLine() + Indent(indent) +
           "\"flexbuffer\" : " + JsonBool(field.flexbuffer);
    out += "," + NewLine() + Indent(indent) +
           "\"native_inline\" : " + JsonBool(field.native_inline);
    out += "," + NewLine() + Indent(indent) +
           "\"offset64\" : " + JsonBool(field.offset64);
    out += "," + NewLine() + Indent(indent) +
           "\"optional\" : " + JsonBool(field.presence == FieldDef::kOptional);
    if (field.padding) {
      out += "," + NewLine() + Indent(indent) +
             "\"padding\" : " + NumToString(field.padding);
    }
    if (field.nested_flatbuffer != nullptr) {
      out += "," + NewLine() + Indent(indent) +
             "\"nested_flatbuffer\" : " +
             JsonString(QualifiedNameString(field.nested_flatbuffer));
    }
    if (field.sibling_union_field != nullptr) {
      out += "," + NewLine() + Indent(indent) +
             "\"sibling_union_key\" : " +
             JsonString(field.sibling_union_field->name);
    }
    std::string attrs = GenAttributesMetadata(field.attributes, indent + 1);
    if (!attrs.empty()) {
      out += "," + NewLine() + attrs;
    }
    std::string docs = GenDocMetadata(field.doc_comment, indent + 1);
    if (!docs.empty()) {
      out += "," + NewLine() + docs;
    }
    return "{" + NewLine() + out + NewLine() + Indent(indent - 1) + "}";
  }

  std::string GenStructMetadata(const StructDef& structure,
                                int indent) const {
    std::string out = Indent(indent) + "\"definition\" : " +
                     JsonString(structure.fixed ? "struct" : "table");
    out += "," + NewLine() + Indent(indent) +
           "\"name\" : " + JsonString(QualifiedNameString(&structure));
    out += "," + NewLine() + Indent(indent) + "\"namespace\" : [" +
           NewLine();
    if (structure.defined_namespace != nullptr) {
      const auto& ns_components = structure.defined_namespace->components;
      for (size_t i = 0; i < ns_components.size(); ++i) {
        out += Indent(indent + 1) + JsonString(ns_components[i]);
        if (i + 1 != ns_components.size()) out += ",";
        out += NewLine();
      }
    }
    out += Indent(indent) + "]";
    out += "," + NewLine() + Indent(indent) +
           "\"bytesize\" : " + NumToString(structure.bytesize);
    out += "," + NewLine() + Indent(indent) +
           "\"minalign\" : " + NumToString(structure.minalign);
    out += "," + NewLine() + Indent(indent) +
           "\"sortbysize\" : " + JsonBool(structure.sortbysize);
    out += "," + NewLine() + Indent(indent) +
           "\"has_key\" : " + JsonBool(structure.has_key);
    std::string attrs = GenAttributesMetadata(structure.attributes, indent + 1);
    if (!attrs.empty()) {
      out += "," + NewLine() + attrs;
    }
    std::string docs = GenDocMetadata(structure.doc_comment, indent + 1);
    if (!docs.empty()) {
      out += "," + NewLine() + docs;
    }
    return "{" + NewLine() + out + NewLine() + Indent(indent - 1) + "}";
  }

  std::string GenEnumMetadata(const EnumDef& enum_def, int indent) const {
    std::string out = Indent(indent) + "\"definition\" : " +
                     JsonString(enum_def.is_union ? "union" : "enum");
    out += "," + NewLine() + Indent(indent) +
           "\"name\" : " + JsonString(QualifiedNameString(&enum_def));
    out += "," + NewLine() + Indent(indent) + "\"namespace\" : [" +
           NewLine();
    if (enum_def.defined_namespace != nullptr) {
      const auto& ns_components = enum_def.defined_namespace->components;
      for (size_t i = 0; i < ns_components.size(); ++i) {
        out += Indent(indent + 1) + JsonString(ns_components[i]);
        if (i + 1 != ns_components.size()) out += ",";
        out += NewLine();
      }
    }
    out += Indent(indent) + "]";
    out += "," + NewLine() + Indent(indent) +
           "\"underlying_type\" : " +
           JsonString(reflection::EnumNameBaseType(static_cast<reflection::BaseType>(
               enum_def.underlying_type.base_type)));
    std::string attrs = GenAttributesMetadata(enum_def.attributes, indent + 1);
    if (!attrs.empty()) {
      out += "," + NewLine() + attrs;
    }
    std::string docs = GenDocMetadata(enum_def.doc_comment, indent + 1);
    if (!docs.empty()) {
      out += "," + NewLine() + docs;
    }
    std::string values = Indent(indent) + "\"values\" : [" + NewLine();
    for (auto it = enum_def.Vals().begin(); it != enum_def.Vals().end(); ++it) {
      auto& val = **it;
      std::string entry = Indent(indent + 1) + "{" + NewLine();
      entry += Indent(indent + 2) + "\"name\" : " + JsonString(val.name) +
               "," + NewLine() + Indent(indent + 2) +
               "\"value\" : " + NumToString(val.GetAsInt64());
      entry += "," + NewLine() + Indent(indent + 2) +
               "\"base_type\" : " +
               JsonString(reflection::EnumNameBaseType(
                   static_cast<reflection::BaseType>(
                       val.union_type.base_type)));
      if (val.union_type.struct_def) {
        entry += "," + NewLine() + Indent(indent + 2) +
                 "\"struct\" : " +
                 JsonString(QualifiedNameString(val.union_type.struct_def));
      }
      if (val.union_type.enum_def) {
        entry += "," + NewLine() + Indent(indent + 2) +
                 "\"enum\" : " +
                 JsonString(QualifiedNameString(val.union_type.enum_def));
      }
      std::string attrs_val =
          GenAttributesMetadata(val.attributes, indent + 2);
      if (!attrs_val.empty()) {
        entry += "," + NewLine() + attrs_val;
      }
      std::string docs_val = GenDocMetadata(val.doc_comment, indent + 2);
      if (!docs_val.empty()) {
        entry += "," + NewLine() + docs_val;
      }
      entry += NewLine() + Indent(indent + 1) + "}";
      if (it + 1 != enum_def.Vals().end()) entry += ",";
      entry += NewLine();
      values += entry;
    }
    values += Indent(indent) + "]";
    out += "," + NewLine() + values;
    return "{" + NewLine() + out + NewLine() + Indent(indent - 1) + "}";
  }

  std::string GenRootMetadata(int indent) const {
    std::string out = Indent(indent) + "\"root_type\" : " +
                      JsonString(QualifiedNameString(parser_.root_struct_def_));
    out += "," + NewLine() + Indent(indent) +
           "\"file_identifier\" : " +
           JsonString(parser_.file_identifier_);
    out += "," + NewLine() + Indent(indent) +
           "\"file_extension\" : " +
           JsonString(parser_.file_extension_);
    out += "," + NewLine() + Indent(indent) +
           "\"advanced_features\" : " +
           NumToString(parser_.advanced_features_);
    if (!schema_bfbs_base64_.empty()) {
      out += "," + NewLine() + Indent(indent) +
             "\"schema_bfbs\" : " + JsonString(schema_bfbs_base64_);
    }
    return "{" + NewLine() + out + NewLine() + Indent(indent - 1) + "}";
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
    auto& mutable_parser = const_cast<Parser&>(parser_);
    const uint8_t* bfbs_ptr = mutable_parser.builder_.GetBufferPointer();
    size_t bfbs_size = static_cast<size_t>(mutable_parser.builder_.GetSize());
    schema_bfbs_base64_.clear();
    if (!mutable_parser.imported_schema_bfbs_base64_.empty()) {
      schema_bfbs_base64_ = mutable_parser.imported_schema_bfbs_base64_;
    } else if (bfbs_ptr != nullptr && bfbs_size != 0) {
      schema_bfbs_base64_ = EncodeBase64(bfbs_ptr, bfbs_size);
      mutable_parser.imported_schema_bfbs_base64_ = schema_bfbs_base64_;
      mutable_parser.imported_schema_bfbs_raw_.assign(bfbs_ptr,
                                                      bfbs_ptr + bfbs_size);
    } else {
      mutable_parser.imported_schema_bfbs_base64_.clear();
      mutable_parser.imported_schema_bfbs_raw_.clear();
    }
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
      code_ += enumdef + "," + NewLine();
      code_ += Indent(3) + "\"x-flatbuffers\" : " +
               GenEnumMetadata(**e, 4) + NewLine();
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
        typeLine +=
            "," + NewLine() + Indent(8) + "\"x-flatbuffers\" : " +
            GenFieldMetadata(*property, 9);
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
      code_ += Indent(3) + "\"additionalProperties\" : false," + NewLine();
      code_ += Indent(3) + "\"x-flatbuffers\" : " +
               GenStructMetadata(*structure, 4) + NewLine();
      auto closeType(Indent(2) + "}");
      if (*s != parser_.structs_.vec.back()) {
        closeType.append(",");
      }
      code_ += closeType + NewLine();  // close type
    }
    code_ += Indent(1) + "}," + NewLine();  // close definitions

    // mark root type
    code_ += Indent(1) + "\"$ref\" : \"#/definitions/" +
             GenFullName(parser_.root_struct_def_) + "\"";
    code_ += "," + NewLine();
    code_ += Indent(1) + "\"x-flatbuffers\" : " + GenRootMetadata(2) +
             NewLine();

    code_ += "}" + NewLine();  // close schema root
    return true;
  }

  bool save() const {
    const auto file_path = GeneratedFileName(path_, file_name_, parser_.opts);
    return SaveFile(file_path.c_str(), code_, false);
  }

  const std::string getJson() { return code_; }
};
}  // namespace jsons

static bool GenerateJsonSchema(const Parser& parser, const std::string& path,
                               const std::string& file_name) {
  auto& mutable_parser = const_cast<Parser&>(parser);
  const bool previous_builtins = mutable_parser.opts.binary_schema_builtins;
  const bool previous_comments = mutable_parser.opts.binary_schema_comments;
  mutable_parser.opts.binary_schema_builtins = true;
  mutable_parser.opts.binary_schema_comments = true;
  mutable_parser.Serialize();
  mutable_parser.opts.binary_schema_builtins = previous_builtins;
  mutable_parser.opts.binary_schema_comments = previous_comments;
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

std::unique_ptr<CodeGenerator> NewJsonSchemaCodeGenerator() {
  return std::unique_ptr<JsonSchemaCodeGenerator>(
      new JsonSchemaCodeGenerator());
}
}  // namespace flatbuffers
