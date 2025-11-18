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
#include <sstream>
#include <unordered_map>
#include <vector>

#include "flatbuffers/code_generators.h"
#include "flatbuffers/idl.h"
#include "flatbuffers/reflection_generated.h"
#include "flatbuffers/util.h"

namespace flatbuffers {

namespace jsons {

namespace {

static std::string QuoteString(const std::string& value) {
  std::string escaped;
  EscapeString(value.c_str(), value.length(), &escaped, true, true);
  return escaped;
}

static std::string BoolToString(bool value) { return value ? "true" : "false"; }

class JsonObjectBuilder {
 public:
  void Add(const std::string& key, const std::string& value_literal) {
    if (value_literal.empty()) return;
    if (!body_.empty()) body_ += ",";
    body_ += "\"" + key + "\":" + value_literal;
  }

  bool Empty() const { return body_.empty(); }

  std::string Finish() const { return "{" + body_ + "}"; }

 private:
  std::string body_;
};

static std::string BuildArrayLiteral(const std::vector<std::string>& entries) {
  std::string array = "[";
  for (size_t i = 0; i < entries.size(); ++i) {
    array += entries[i];
    if (i + 1 < entries.size()) array += ",";
  }
  array += "]";
  return array;
}

static std::string CommentFromBuilder(const JsonObjectBuilder& builder) {
  if (builder.Empty()) return QuoteString("{}");
  return QuoteString(builder.Finish());
}

static std::string DefPath(const std::string& bucket, const std::string& name) {
  return "#/$defs/" + bucket + "/" + name;
}

static std::vector<std::string> SplitPathComponents(const std::string& path) {
  std::vector<std::string> components;
  std::stringstream ss(path);
  std::string item;
  while (std::getline(ss, item, '/')) {
    if (!item.empty()) components.push_back(item);
  }
  return components;
}

static std::string JoinPathComponents(const std::vector<std::string>& comps) {
  std::string joined;
  for (size_t i = 0; i < comps.size(); ++i) {
    if (i) joined.push_back('/');
    joined += comps[i];
  }
  return joined;
}

struct SchemaDoc {
  std::string normalized_fbs_path;
  std::string schema_rel_path;
  std::string schema_abs_path;
  std::string schema_id;
  std::vector<const StructDef*> structs;
  std::vector<const EnumDef*> enums;
  std::vector<const ServiceDef*> services;
};

static std::string BuildStringArrayLiteral(
    const std::vector<std::string>& values) {
  std::vector<std::string> quoted;
  quoted.reserve(values.size());
  for (const auto& value : values) {
    quoted.push_back(QuoteString(value));
  }
  return BuildArrayLiteral(quoted);
}

static std::string QualifiedName(const Namespace* ns,
                                 const std::string& name) {
  if (ns == nullptr || ns->components.empty()) { return name; }
  std::string qualified;
  for (size_t i = 0; i < ns->components.size(); ++i) {
    if (i != 0) qualified.push_back('.');
    qualified.append(ns->components[i]);
  }
  qualified.push_back('.');
  qualified.append(name);
  return qualified;
}

static std::string QualifiedName(const Definition& def) {
  return QualifiedName(def.defined_namespace, def.name);
}

static std::string QualifiedName(const StructDef& def) {
  return QualifiedName(def.defined_namespace, def.name);
}

static std::string QualifiedName(const EnumDef& def) {
  return QualifiedName(def.defined_namespace, def.name);
}

static std::string QualifiedName(const ServiceDef& def) {
  return QualifiedName(def.defined_namespace, def.name);
}

static std::string ScalarTypeProperties(BaseType type) {
  switch (type) {
    case BASE_TYPE_BOOL:
      return "\"type\": \"boolean\"";
    case BASE_TYPE_CHAR:
      return "\"type\": \"integer\", \"minimum\": " +
             NumToString(std::numeric_limits<int8_t>::min()) +
             ", \"maximum\": " +
             NumToString(std::numeric_limits<int8_t>::max());
    case BASE_TYPE_UCHAR:
      return "\"type\": \"integer\", \"minimum\": 0, \"maximum\": " +
             NumToString(std::numeric_limits<uint8_t>::max());
    case BASE_TYPE_SHORT:
      return "\"type\": \"integer\", \"minimum\": " +
             NumToString(std::numeric_limits<int16_t>::min()) +
             ", \"maximum\": " +
             NumToString(std::numeric_limits<int16_t>::max());
    case BASE_TYPE_USHORT:
      return "\"type\": \"integer\", \"minimum\": 0, \"maximum\": " +
             NumToString(std::numeric_limits<uint16_t>::max());
    case BASE_TYPE_INT:
      return "\"type\": \"integer\", \"minimum\": " +
             NumToString(std::numeric_limits<int32_t>::min()) +
             ", \"maximum\": " +
             NumToString(std::numeric_limits<int32_t>::max());
    case BASE_TYPE_UINT:
      return "\"type\": \"integer\", \"minimum\": 0, \"maximum\": " +
             NumToString(std::numeric_limits<uint32_t>::max());
    case BASE_TYPE_LONG:
      return "\"type\": \"integer\", \"minimum\": " +
             NumToString(std::numeric_limits<int64_t>::min()) +
             ", \"maximum\": " +
             NumToString(std::numeric_limits<int64_t>::max());
    case BASE_TYPE_ULONG:
      return "\"type\": \"integer\", \"minimum\": 0, \"maximum\": " +
             NumToString(std::numeric_limits<uint64_t>::max());
    case BASE_TYPE_FLOAT:
    case BASE_TYPE_DOUBLE:
      return "\"type\": \"number\"";
    case BASE_TYPE_STRING:
      return "\"type\": \"string\"";
    default:
      return "";
  }
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

}  // namespace

class JsonSchemaGenerator : public BaseGenerator {
 private:
  std::string code_;
  std::map<std::string, SchemaDoc> documents_;
  const SchemaDoc* root_doc_ = nullptr;
  std::unordered_map<const StructDef*, SchemaDoc*> struct_doc_lookup_;
  std::unordered_map<const EnumDef*, SchemaDoc*> enum_doc_lookup_;
  std::unordered_map<const ServiceDef*, SchemaDoc*> service_doc_lookup_;
  std::string default_schema_file_;

  bool BuildDocuments();
  bool GenerateDocument(SchemaDoc& doc);
  bool SaveDocument(const SchemaDoc& doc) const;

  std::string BuildScalarDefinitions(const SchemaDoc& doc) const;
  std::string BuildEnumDefinitions(const SchemaDoc& doc);
  std::string BuildFieldDefinitions(const SchemaDoc& doc);
  std::string BuildTypeDefinitions(const SchemaDoc& doc);
  std::string BuildServiceDefinitions(const SchemaDoc& doc);
  std::string BuildTopLevelComment(const SchemaDoc& doc) const;
  std::string BuildStructMetadata(const StructDef& structure) const;
  std::string BuildFieldMetadata(const FieldDef& field,
                                 uint16_t field_index) const;
  std::vector<std::string> BuildTypeEntries(const Type& type,
                                            const SchemaDoc& doc) const;
  std::string BuildDefaultLiteral(const FieldDef& field) const;
  std::string BuildUnionAnyOf(const EnumDef& enum_def,
                              const SchemaDoc& doc) const;
  std::string BuildEnumMetadata(const EnumDef& enum_def) const;
  std::string BuildServiceMetadata(const ServiceDef& service) const;
  std::string BuildCallMetadata(const RPCCall& call) const;
  std::string BuildAttributesArray(
      const SymbolTable<Value>& attributes) const;
  std::string BuildSchemaFilesMetadata() const;
  std::string TypeReferenceLiteral(const Type& type,
                                   const SchemaDoc& current_doc) const;
  std::string BuildAdvancedFeaturesArray() const;

  const SchemaDoc* DocForStruct(const StructDef* def) const;
  const SchemaDoc* DocForEnum(const EnumDef* def) const;
  const SchemaDoc* DocForService(const ServiceDef* def) const;
  SchemaDoc* GetOrCreateDoc(const std::string& normalized_path);
  std::string NormalizeDeclarationFile(const std::string* decl) const;
  std::string SchemaFileName(const std::string& normalized_path) const;
  std::string RelativePathBetween(const std::string& from_file,
                                  const std::string& to_file) const;
  std::string BuildRef(const SchemaDoc& from, const SchemaDoc& to,
                       const std::string& bucket,
                       const std::string& name) const;

 public:
  JsonSchemaGenerator(const Parser& parser, const std::string& path,
                      const std::string& file_name)
      : BaseGenerator(parser, path, file_name, "", "", "json") {}

  explicit JsonSchemaGenerator(const BaseGenerator& base_generator)
      : BaseGenerator(base_generator) {}

  bool generate() {
    if (parser_.root_struct_def_ == nullptr) {
      std::cerr << "Error: Binary schema not generated, no root struct found\n";
      return false;
    }
    if (!BuildDocuments()) return false;
    for (auto& entry : documents_) {
      if (!GenerateDocument(entry.second)) return false;
      if (!SaveDocument(entry.second)) return false;
    }
    return true;
  }

  bool save() const { return true; }

  const std::string getJson() { return code_; }

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
};

bool JsonSchemaGenerator::BuildDocuments() {
  documents_.clear();
  struct_doc_lookup_.clear();
  enum_doc_lookup_.clear();
  service_doc_lookup_.clear();
  root_doc_ = nullptr;

  if (parser_.root_struct_def_ &&
      parser_.root_struct_def_->declaration_file != nullptr) {
    default_schema_file_ =
        NormalizeDeclarationFile(parser_.root_struct_def_->declaration_file);
  } else {
    default_schema_file_ = file_name_ + ".fbs";
  }

  for (const auto* structure : parser_.structs_.vec) {
    auto* doc = GetOrCreateDoc(
        NormalizeDeclarationFile(structure->declaration_file));
    doc->structs.push_back(structure);
    struct_doc_lookup_[structure] = doc;
  }

  for (const auto* enum_def : parser_.enums_.vec) {
    auto* doc =
        GetOrCreateDoc(NormalizeDeclarationFile(enum_def->declaration_file));
    doc->enums.push_back(enum_def);
    enum_doc_lookup_[enum_def] = doc;
  }

  for (const auto* service : parser_.services_.vec) {
    auto* doc =
        GetOrCreateDoc(NormalizeDeclarationFile(service->declaration_file));
    doc->services.push_back(service);
    service_doc_lookup_[service] = doc;
  }

  if (parser_.root_struct_def_) {
    root_doc_ = DocForStruct(parser_.root_struct_def_);
  }
  if (!root_doc_) {
    root_doc_ = GetOrCreateDoc(default_schema_file_);
  }
  return true;
}

SchemaDoc* JsonSchemaGenerator::GetOrCreateDoc(
    const std::string& normalized_path) {
  const auto key =
      normalized_path.empty() ? default_schema_file_ : normalized_path;
  auto it = documents_.find(key);
  if (it != documents_.end()) return &it->second;

  SchemaDoc doc;
  doc.normalized_fbs_path = key;
  doc.schema_rel_path = SchemaFileName(key);
  doc.schema_abs_path =
      flatbuffers::ConCatPathFileName(path_, doc.schema_rel_path);
  doc.schema_id = doc.schema_rel_path;
  auto inserted = documents_.emplace(key, std::move(doc));
  return &inserted.first->second;
}

const SchemaDoc* JsonSchemaGenerator::DocForStruct(
    const StructDef* def) const {
  auto it = struct_doc_lookup_.find(def);
  if (it != struct_doc_lookup_.end()) return it->second;
  return root_doc_;
}

const SchemaDoc* JsonSchemaGenerator::DocForEnum(const EnumDef* def) const {
  auto it = enum_doc_lookup_.find(def);
  if (it != enum_doc_lookup_.end()) return it->second;
  return root_doc_;
}

const SchemaDoc* JsonSchemaGenerator::DocForService(
    const ServiceDef* def) const {
  auto it = service_doc_lookup_.find(def);
  if (it != service_doc_lookup_.end()) return it->second;
  return root_doc_;
}

std::string JsonSchemaGenerator::NormalizeDeclarationFile(
    const std::string* decl) const {
  if (decl != nullptr && !decl->empty()) {
    std::string normalized = *decl;
    if (normalized.compare(0, 2, "//") == 0) {
      normalized = normalized.substr(2);
    }
    normalized = flatbuffers::PosixPath(normalized);
    while (!normalized.empty() && normalized.front() == '/') {
      normalized.erase(normalized.begin());
    }
    return normalized;
  }
  return default_schema_file_;
}

std::string JsonSchemaGenerator::SchemaFileName(
    const std::string& normalized_path) const {
  std::string path =
      normalized_path.empty() ? default_schema_file_ : normalized_path;
  path = flatbuffers::PosixPath(path);
  auto dot = path.find_last_of('.');
  if (dot == std::string::npos) return path + ".schema.json";
  return path.substr(0, dot) + ".schema.json";
}

std::string JsonSchemaGenerator::RelativePathBetween(
    const std::string& from_file, const std::string& to_file) const {
  auto from_dir = flatbuffers::StripFileName(from_file);
  auto from_parts = SplitPathComponents(flatbuffers::PosixPath(from_dir));
  auto to_parts = SplitPathComponents(flatbuffers::PosixPath(to_file));

  size_t common = 0;
  while (common < from_parts.size() && common < to_parts.size() &&
         from_parts[common] == to_parts[common]) {
    ++common;
  }

  std::vector<std::string> rel_parts;
  for (size_t i = common; i < from_parts.size(); ++i) {
    rel_parts.push_back("..");
  }
  for (size_t i = common; i < to_parts.size(); ++i) {
    rel_parts.push_back(to_parts[i]);
  }
  if (rel_parts.empty()) return flatbuffers::StripPath(to_file);
  return JoinPathComponents(rel_parts);
}

std::string JsonSchemaGenerator::BuildRef(const SchemaDoc& from,
                                          const SchemaDoc& to,
                                          const std::string& bucket,
                                          const std::string& name) const {
  if (&from == &to) {
    return "\"$ref\": \"" + DefPath(bucket, name) + "\"";
  }
  auto rel = RelativePathBetween(from.schema_rel_path, to.schema_rel_path);
  std::string target = rel.empty() ? to.schema_rel_path : rel;
  return "\"$ref\": \"" + target + "#/$defs/" + bucket + "/" + name + "\"";
}

bool JsonSchemaGenerator::GenerateDocument(SchemaDoc& doc) {
  code_.clear();
  code_ += "{" + NewLine();
  code_ += Indent(1) +
           "\"$schema\": \"https://json-schema.org/draft/2019-09/schema\"," +
           NewLine();
  code_ += Indent(1) + "\"$id\": " + QuoteString(doc.schema_id) + "," +
           NewLine();
  code_ += Indent(1) + "\"$comment\": " + BuildTopLevelComment(doc) + "," +
           NewLine();
  code_ += Indent(1) + "\"$defs\": {" + NewLine();

  std::vector<std::string> sections = {
      BuildScalarDefinitions(doc), BuildEnumDefinitions(doc),
      BuildFieldDefinitions(doc),  BuildTypeDefinitions(doc),
      BuildServiceDefinitions(doc)};
  for (size_t i = 0; i < sections.size(); ++i) {
    code_ += sections[i];
    code_ += (i + 1 < sections.size() ? "," : "") + NewLine();
  }

  code_ += Indent(1) + "}";
  if (&doc == root_doc_) {
    code_ += "," + NewLine();
    code_ += Indent(1) + "\"$ref\": \"" +
             DefPath("types", GenFullName(parser_.root_struct_def_)) + "\"" +
             NewLine();
  } else {
    code_ += NewLine();
  }
  code_ += "}" + NewLine();
  return true;
}

bool JsonSchemaGenerator::SaveDocument(const SchemaDoc& doc) const {
  auto directory = flatbuffers::StripFileName(doc.schema_abs_path);
  flatbuffers::EnsureDirExists(directory);
  return SaveFile(doc.schema_abs_path.c_str(), code_, false);
}

std::string JsonSchemaGenerator::BuildScalarDefinitions(
    const SchemaDoc& doc) const {
  (void)doc;
  const std::vector<BaseType> scalar_types = {
      BASE_TYPE_BOOL,   BASE_TYPE_CHAR,  BASE_TYPE_UCHAR,
      BASE_TYPE_SHORT,  BASE_TYPE_USHORT, BASE_TYPE_INT,
      BASE_TYPE_UINT,   BASE_TYPE_LONG,  BASE_TYPE_ULONG,
      BASE_TYPE_FLOAT,  BASE_TYPE_DOUBLE, BASE_TYPE_STRING};

  std::string section;
  section += Indent(2) + "\"scalars\": {" + NewLine();
  for (size_t i = 0; i < scalar_types.size(); ++i) {
    const auto base_type = scalar_types[i];
    const auto* name =
        reflection::EnumNameBaseType(static_cast<reflection::BaseType>(
            base_type));
    section += Indent(3) + "\"" + std::string(name) + "\": {" + NewLine();
    JsonObjectBuilder meta;
    meta.Add("base_type", QuoteString(name));
    section += Indent(4) + "\"$comment\": " + CommentFromBuilder(meta) + "," +
               NewLine();
    section += Indent(4) + ScalarTypeProperties(base_type) + NewLine();
    section += Indent(3) + "}";
    if (i + 1 < scalar_types.size()) section += ",";
    section += NewLine();
  }
  section += Indent(2) + "}";
  return section;
}

std::string JsonSchemaGenerator::BuildEnumDefinitions(const SchemaDoc& doc) {
  std::string section;
  section += Indent(2) + "\"enums\": {" + NewLine();
  for (size_t i = 0; i < doc.enums.size(); ++i) {
    const auto* enum_def = doc.enums[i];
    const auto full_name = GenFullName(enum_def);
    section += Indent(3) + "\"" + full_name + "\": {" + NewLine();
    section += Indent(4) + "\"$anchor\": \"" + full_name + "\"," + NewLine();
    section += Indent(4) + "\"$comment\": " + BuildEnumMetadata(*enum_def) +
               "," + NewLine();
    section += Indent(4) + "\"type\": \"string\"," + NewLine();
    std::string enum_values = "\"enum\": [";
    for (size_t v = 0; v < enum_def->Vals().size(); ++v) {
      const auto* val = enum_def->Vals()[v];
      enum_values += QuoteString(val->name);
      if (v + 1 < enum_def->Vals().size()) enum_values += ", ";
    }
    enum_values += "]";
    section += Indent(4) + enum_values;
    auto description = PrepareDescription(enum_def->doc_comment);
    if (!description.empty()) {
      section += "," + NewLine();
      section += Indent(4) + "\"description\": " + description;
    }
    section += NewLine() + Indent(3) + "}";
    if (i + 1 < doc.enums.size()) section += ",";
    section += NewLine();
  }
  section += Indent(2) + "}";
  return section;
}

std::string JsonSchemaGenerator::BuildFieldDefinitions(const SchemaDoc& doc) {
  std::string section;
  section += Indent(2) + "\"fields\": {" + NewLine();
  for (size_t i = 0; i < doc.structs.size(); ++i) {
    const auto* structure = doc.structs[i];
    const auto full_name = GenFullName(structure);
    section += Indent(3) + "\"" + full_name + "\": {" + NewLine();
    const auto& fields = structure->fields.vec;
    for (size_t f = 0; f < fields.size(); ++f) {
      const auto* field = fields[f];
      section += Indent(4) + "\"" + field->name + "\": {" + NewLine();
      std::vector<std::string> entries;
      entries.push_back("\"$comment\": " +
                        BuildFieldMetadata(*field,
                                           static_cast<uint16_t>(f)));
      auto type_entries = BuildTypeEntries(field->value.type, doc);
      entries.insert(entries.end(), type_entries.begin(), type_entries.end());
      auto default_literal = BuildDefaultLiteral(*field);
      if (!default_literal.empty()) {
        entries.push_back("\"default\": " + default_literal);
      }
      if (field->deprecated) {
        entries.push_back("\"deprecated\": true");
      }
      auto description = PrepareDescription(field->doc_comment);
      if (!description.empty()) {
        entries.push_back("\"description\": " + description);
      }
      for (size_t e = 0; e < entries.size(); ++e) {
        section += Indent(5) + entries[e];
        if (e + 1 < entries.size()) section += ",";
        section += NewLine();
      }
      section += Indent(4) + "}";
      if (f + 1 < fields.size()) section += ",";
      section += NewLine();
    }
    section += Indent(3) + "}";
    if (i + 1 < doc.structs.size()) section += ",";
    section += NewLine();
  }
  section += Indent(2) + "}";
  return section;
}

std::string JsonSchemaGenerator::BuildTypeDefinitions(const SchemaDoc& doc) {
  std::string section;
  section += Indent(2) + "\"types\": {" + NewLine();
  for (size_t i = 0; i < doc.structs.size(); ++i) {
    const auto* structure = doc.structs[i];
    const auto full_name = GenFullName(structure);
    section += Indent(3) + "\"" + full_name + "\": {" + NewLine();
    std::vector<std::string> entries;
    entries.push_back("\"$anchor\": \"" + full_name + "\"");
    entries.push_back("\"$comment\": " + BuildStructMetadata(*structure));
    entries.push_back("\"type\": \"object\"");
    auto description = PrepareDescription(structure->doc_comment);
    if (!description.empty()) {
      entries.push_back("\"description\": " + description);
    }

    std::string properties = "\"properties\": {" + NewLine();
    const auto& fields = structure->fields.vec;
    for (size_t f = 0; f < fields.size(); ++f) {
      const auto* field = fields[f];
      const auto field_ref =
          "#/$defs/fields/" + full_name + "/" + field->name;
      properties += Indent(5) + "\"" + field->name +
                    "\": { \"$ref\": \"" + field_ref + "\" }";
      if (f + 1 < fields.size()) properties += ",";
      properties += NewLine();
    }
    properties += Indent(4) + "}";
    entries.push_back(properties);

    std::vector<std::string> required_fields;
    for (const auto* field : fields) {
      if (field->IsRequired()) required_fields.push_back(field->name);
    }
    if (!required_fields.empty()) {
      std::string required = "\"required\": [";
      for (size_t r = 0; r < required_fields.size(); ++r) {
        required += QuoteString(required_fields[r]);
        if (r + 1 < required_fields.size()) required += ", ";
      }
      required += "]";
      entries.push_back(required);
    }

    entries.push_back("\"additionalProperties\": false");

    for (size_t e = 0; e < entries.size(); ++e) {
      section += Indent(4) + entries[e];
      if (e + 1 < entries.size()) section += ",";
      section += NewLine();
    }
    section += Indent(3) + "}";
    if (i + 1 < doc.structs.size()) section += ",";
    section += NewLine();
  }
  section += Indent(2) + "}";
  return section;
}

std::string JsonSchemaGenerator::BuildServiceDefinitions(
    const SchemaDoc& doc) {
  std::string section;
  section += Indent(2) + "\"services\": {" + NewLine();
  for (size_t i = 0; i < doc.services.size(); ++i) {
    const auto* service = doc.services[i];
    const auto full_name = GenFullName(service);
    section += Indent(3) + "\"" + full_name + "\": {" + NewLine();
    std::vector<std::string> entries;
    entries.push_back("\"$comment\": " + BuildServiceMetadata(*service));
    entries.push_back("\"type\": \"object\"");
    auto description = PrepareDescription(service->doc_comment);
    if (!description.empty()) {
      entries.push_back("\"description\": " + description);
    }

    std::string properties = "\"properties\": {" + NewLine();
    const auto& calls = service->calls.vec;
    for (size_t c = 0; c < calls.size(); ++c) {
      const auto* call = calls[c];
      properties += Indent(5) + "\"" + call->name + "\": {" + NewLine();
      std::vector<std::string> call_entries;
      call_entries.push_back("\"$comment\": " + BuildCallMetadata(*call));
      call_entries.push_back("\"type\": \"object\"");
      const auto* request_doc = DocForStruct(call->request);
      const auto* response_doc = DocForStruct(call->response);
      std::string props = "\"properties\": {\"request\": { " +
                          BuildRef(doc, *request_doc, "types",
                                   GenFullName(call->request)) +
                          " }, \"response\": { " +
                          BuildRef(doc, *response_doc, "types",
                                   GenFullName(call->response)) +
                          " }}";
      call_entries.push_back(props);
      call_entries.push_back("\"required\": [\"request\", \"response\"]");
      call_entries.push_back("\"additionalProperties\": false");
      for (size_t ce = 0; ce < call_entries.size(); ++ce) {
        properties += Indent(6) + call_entries[ce];
        if (ce + 1 < call_entries.size()) properties += ",";
        properties += NewLine();
      }
      properties += Indent(5) + "}";
      if (c + 1 < calls.size()) properties += ",";
      properties += NewLine();
    }
    properties += Indent(4) + "}";
    entries.push_back(properties);
    entries.push_back("\"additionalProperties\": false");

    for (size_t e = 0; e < entries.size(); ++e) {
      section += Indent(4) + entries[e];
      if (e + 1 < entries.size()) section += ",";
      section += NewLine();
    }
    section += Indent(3) + "}";
    if (i + 1 < doc.services.size()) section += ",";
    section += NewLine();
  }
  section += Indent(2) + "}";
  return section;
}

std::string JsonSchemaGenerator::BuildTopLevelComment(
    const SchemaDoc& doc) const {
  JsonObjectBuilder meta;
  meta.Add("source", QuoteString(doc.normalized_fbs_path));
  if (&doc == root_doc_) {
    meta.Add("file_ident", QuoteString(parser_.file_identifier_));
    meta.Add("file_ext", QuoteString(parser_.file_extension_));
    meta.Add("advanced_features", BuildAdvancedFeaturesArray());
    meta.Add("fbs_files", BuildSchemaFilesMetadata());
  }
  return CommentFromBuilder(meta);
}

std::string JsonSchemaGenerator::BuildStructMetadata(
    const StructDef& structure) const {
  JsonObjectBuilder meta;
  meta.Add("name", QuoteString(structure.name));
  if (structure.defined_namespace != nullptr &&
      !structure.defined_namespace->components.empty()) {
    meta.Add("namespace",
             BuildStringArrayLiteral(structure.defined_namespace->components));
  }
  meta.Add("qualified_name", QuoteString(QualifiedName(structure)));
  meta.Add("is_struct", BoolToString(structure.fixed));
  meta.Add("minalign", NumToString(structure.minalign));
  meta.Add("bytesize", NumToString(structure.bytesize));
  if (structure.declaration_file != nullptr) {
    meta.Add("declaration_file", QuoteString(*structure.declaration_file));
  }
  if (!structure.reserved_ids.empty()) {
    std::vector<std::string> ids;
    for (const auto id : structure.reserved_ids) {
      ids.push_back(NumToString(id));
    }
    meta.Add("reserved_ids", BuildArrayLiteral(ids));
  }
  const auto attributes = BuildAttributesArray(structure.attributes);
  if (!attributes.empty()) {
    meta.Add("attributes", attributes);
  }
  return CommentFromBuilder(meta);
}

std::string JsonSchemaGenerator::BuildFieldMetadata(
    const FieldDef& field, uint16_t field_index) const {
  JsonObjectBuilder meta;
  meta.Add("name", QuoteString(field.name));
  meta.Add("id", NumToString(field_index));
  if (field.value.offset !=
      static_cast<voffset_t>(~(static_cast<voffset_t>(0U)))) {
    meta.Add("offset", NumToString(field.value.offset));
  }
  meta.Add("key", BoolToString(field.key));
  meta.Add("required", BoolToString(field.IsRequired()));
  meta.Add("optional", BoolToString(field.IsOptional()));
  if (field.padding != 0) {
    meta.Add("padding", NumToString(field.padding));
  }
  if (field.offset64) {
    meta.Add("offset64", "true");
  }
  if (field.shared) {
    meta.Add("shared", "true");
  }
  if (field.native_inline) {
    meta.Add("native_inline", "true");
  }
  if (field.flexbuffer) {
    meta.Add("flexbuffer", "true");
  }
  if (field.nested_flatbuffer != nullptr) {
    meta.Add("nested_flatbuffer",
             QuoteString(QualifiedName(*field.nested_flatbuffer)));
  }
  if (!field.value.constant.empty()) {
    meta.Add("default_literal", QuoteString(field.value.constant));
  }
  if (IsUnion(field.value.type)) {
    meta.Add("union_enum",
             QuoteString(QualifiedName(*field.value.type.enum_def)));
  }
  const auto attributes = BuildAttributesArray(field.attributes);
  if (!attributes.empty()) {
    meta.Add("attributes", attributes);
  }
  return CommentFromBuilder(meta);
}

std::vector<std::string> JsonSchemaGenerator::BuildTypeEntries(
    const Type& type, const SchemaDoc& doc) const {
  std::vector<std::string> entries;
  const bool is_vector =
      type.base_type == BASE_TYPE_VECTOR || type.base_type == BASE_TYPE_VECTOR64;
  if (type.base_type == BASE_TYPE_ARRAY || is_vector) {
    entries.push_back("\"type\": \"array\"");
    const auto element_type = type.VectorType();
    if (element_type.base_type == BASE_TYPE_UNION) {
      entries.push_back("\"items\": { \"anyOf\": " +
                        BuildUnionAnyOf(*element_type.enum_def, doc) + " }");
    } else {
      entries.push_back("\"items\": " +
                        TypeReferenceLiteral(element_type, doc));
    }
    if (type.base_type == BASE_TYPE_ARRAY && type.fixed_length > 0) {
      const auto length = NumToString(type.fixed_length);
      entries.push_back("\"minItems\": " + length);
      entries.push_back("\"maxItems\": " + length);
    }
    return entries;
  }

  if (type.base_type == BASE_TYPE_UNION) {
    entries.push_back("\"anyOf\": " + BuildUnionAnyOf(*type.enum_def, doc));
    return entries;
  }

  if (type.struct_def != nullptr) {
    const auto* target_doc = DocForStruct(type.struct_def);
    entries.push_back("\"allOf\": [{ " +
                      BuildRef(doc, *target_doc, "types",
                               GenFullName(type.struct_def)) +
                      " }]");
    return entries;
  }

  if (type.enum_def != nullptr) {
    const auto* target_doc = DocForEnum(type.enum_def);
    entries.push_back("\"allOf\": [{ " +
                      BuildRef(doc, *target_doc, "enums",
                               GenFullName(type.enum_def)) +
                      " }]");
    return entries;
  }

  const auto* base_name = reflection::EnumNameBaseType(
      static_cast<reflection::BaseType>(type.base_type));
  if (base_name && *base_name) {
    entries.push_back("\"allOf\": [{ \"$ref\": \"" +
                      DefPath("scalars", base_name) + "\" }]");
  }
  return entries;
}

std::string JsonSchemaGenerator::BuildDefaultLiteral(
    const FieldDef& field) const {
  const auto& type = field.value.type;
  if (type.enum_def != nullptr) {
    const auto* enum_val = type.enum_def->FindByValue(field.value.constant);
    if (enum_val != nullptr) {
      return QuoteString(enum_val->name);
    }
    return "";
  }

  switch (type.base_type) {
    case BASE_TYPE_BOOL:
      return field.value.constant == "0" ? "false" : "true";
    case BASE_TYPE_CHAR:
    case BASE_TYPE_UCHAR:
    case BASE_TYPE_SHORT:
    case BASE_TYPE_USHORT:
    case BASE_TYPE_INT:
    case BASE_TYPE_UINT:
    case BASE_TYPE_LONG:
    case BASE_TYPE_ULONG:
      return field.value.constant;
    case BASE_TYPE_FLOAT:
    case BASE_TYPE_DOUBLE:
      if (StringIsFlatbufferNan(field.value.constant) ||
          StringIsFlatbufferPositiveInfinity(field.value.constant) ||
          StringIsFlatbufferNegativeInfinity(field.value.constant)) {
        return "";
      }
      return field.value.constant;
    default:
      return "";
  }
}

std::string JsonSchemaGenerator::BuildUnionAnyOf(
    const EnumDef& enum_def, const SchemaDoc& doc) const {
  std::vector<std::string> options;
  for (const auto* enum_val : enum_def.Vals()) {
    const auto& union_type = enum_val->union_type;
    if (union_type.base_type == BASE_TYPE_NONE) continue;
    if (union_type.struct_def != nullptr) {
      const auto* target_doc = DocForStruct(union_type.struct_def);
      options.push_back("{ " +
                        BuildRef(doc, *target_doc, "types",
                                 GenFullName(union_type.struct_def)) +
                        " }");
    }
  }
  return BuildArrayLiteral(options);
}

std::string JsonSchemaGenerator::BuildEnumMetadata(
    const EnumDef& enum_def) const {
  JsonObjectBuilder meta;
  meta.Add("name", QuoteString(enum_def.name));
  if (enum_def.defined_namespace != nullptr &&
      !enum_def.defined_namespace->components.empty()) {
    meta.Add("namespace",
             BuildStringArrayLiteral(enum_def.defined_namespace->components));
  }
  meta.Add("qualified_name", QuoteString(QualifiedName(enum_def)));
  meta.Add("is_union", BoolToString(enum_def.is_union));
  const auto* underlying = reflection::EnumNameBaseType(
      static_cast<reflection::BaseType>(enum_def.underlying_type.base_type));
  if (underlying) {
    meta.Add("underlying", QuoteString(underlying));
  }
  std::vector<std::string> values;
  for (const auto* enum_val : enum_def.Vals()) {
    JsonObjectBuilder value_obj;
    value_obj.Add("name", QuoteString(enum_val->name));
    value_obj.Add("value", NumToString(enum_val->GetAsInt64()));
    if (enum_def.is_union && enum_val->union_type.struct_def != nullptr) {
      value_obj.Add(
          "type", QuoteString(QualifiedName(*enum_val->union_type.struct_def)));
    }
    values.push_back(value_obj.Finish());
  }
  meta.Add("values", BuildArrayLiteral(values));
  if (enum_def.declaration_file != nullptr) {
    meta.Add("declaration_file", QuoteString(*enum_def.declaration_file));
  }
  const auto attributes = BuildAttributesArray(enum_def.attributes);
  if (!attributes.empty()) {
    meta.Add("attributes", attributes);
  }
  return CommentFromBuilder(meta);
}

std::string JsonSchemaGenerator::BuildServiceMetadata(
    const ServiceDef& service) const {
  JsonObjectBuilder meta;
  meta.Add("name", QuoteString(service.name));
  if (service.defined_namespace != nullptr &&
      !service.defined_namespace->components.empty()) {
    meta.Add("namespace",
             BuildStringArrayLiteral(service.defined_namespace->components));
  }
  meta.Add("qualified_name", QuoteString(QualifiedName(service)));
  if (service.declaration_file != nullptr) {
    meta.Add("declaration_file", QuoteString(*service.declaration_file));
  }
  const auto attributes = BuildAttributesArray(service.attributes);
  if (!attributes.empty()) {
    meta.Add("attributes", attributes);
  }
  return CommentFromBuilder(meta);
}

std::string JsonSchemaGenerator::BuildCallMetadata(
    const RPCCall& call) const {
  JsonObjectBuilder meta;
  meta.Add("name", QuoteString(call.name));
  const auto attributes = BuildAttributesArray(call.attributes);
  if (!attributes.empty()) {
    meta.Add("attributes", attributes);
  }
  return CommentFromBuilder(meta);
}

std::string JsonSchemaGenerator::BuildAttributesArray(
    const SymbolTable<Value>& attributes) const {
  if (attributes.vec.empty()) return "";
  std::vector<std::string> entries;
  for (const auto& kv : attributes.dict) {
    JsonObjectBuilder attr;
    attr.Add("name", QuoteString(kv.first));
    attr.Add("value", QuoteString(kv.second->constant));
    entries.push_back(attr.Finish());
  }
  return BuildArrayLiteral(entries);
}

std::string JsonSchemaGenerator::BuildSchemaFilesMetadata() const {
  std::vector<std::string> files;
  for (const auto& entry : parser_.files_included_per_file_) {
    JsonObjectBuilder file_obj;
    file_obj.Add("filename", QuoteString(entry.first));
    std::vector<std::string> includes;
    for (const auto& included : entry.second) {
      includes.push_back(QuoteString(included.filename));
    }
    file_obj.Add("included_filenames", BuildArrayLiteral(includes));
    files.push_back(file_obj.Finish());
  }
  return BuildArrayLiteral(files);
}

std::string JsonSchemaGenerator::TypeReferenceLiteral(
    const Type& type, const SchemaDoc& current_doc) const {
  if (type.base_type == BASE_TYPE_UNION) {
    return "{ \"anyOf\": " + BuildUnionAnyOf(*type.enum_def, current_doc) +
           " }";
  }
  if (type.struct_def != nullptr) {
    const auto* target = DocForStruct(type.struct_def);
    return "{ " + BuildRef(current_doc, *target, "types",
                           GenFullName(type.struct_def)) +
           " }";
  }
  if (type.enum_def != nullptr) {
    const auto* target = DocForEnum(type.enum_def);
    return "{ " + BuildRef(current_doc, *target, "enums",
                           GenFullName(type.enum_def)) +
           " }";
  }
  const auto* base_name = reflection::EnumNameBaseType(
      static_cast<reflection::BaseType>(type.base_type));
  if (base_name && *base_name) {
    return "{ \"$ref\": \"" + DefPath("scalars", base_name) + "\" }";
  }
  return "{}";
}

std::string JsonSchemaGenerator::BuildAdvancedFeaturesArray() const {
  std::vector<std::string> features;
  const auto mask =
      static_cast<uint64_t>(parser_.advanced_features_);
  for (const auto feature : reflection::EnumValuesAdvancedFeatures()) {
    if (mask & static_cast<uint64_t>(feature)) {
      const auto* name = reflection::EnumNameAdvancedFeatures(feature);
      if (name && *name) {
        features.push_back(QuoteString(name));
      }
    }
  }
  return BuildArrayLiteral(features);
}
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

std::unique_ptr<CodeGenerator> NewJsonSchemaCodeGenerator() {
  return std::unique_ptr<JsonSchemaCodeGenerator>(
      new JsonSchemaCodeGenerator());
}
}  // namespace flatbuffers
