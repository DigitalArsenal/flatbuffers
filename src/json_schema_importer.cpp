#include "json_schema_importer.h"

#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "flatbuffers/flexbuffers.h"
#include "flatbuffers/reflection_generated.h"
#include "flatbuffers/util.h"

namespace flatbuffers {

namespace {

using AttributeList = std::vector<std::pair<std::string, std::string>>;

struct SchemaFileDesc {
  std::string filename;
  std::vector<std::string> includes;
};

struct FieldTypeDesc {
  reflection::BaseType base_type = reflection::None;
  reflection::BaseType element = reflection::None;
  std::string ref_name;           // Qualified name for struct/enum.
  std::string element_ref_name;   // Qualified name for element struct/enum.
  uint16_t fixed_length = 0;
};

struct FieldSchema {
  std::string name;
  FieldTypeDesc type;
  uint16_t id = 0;
  uint16_t offset = 0;
  bool deprecated = false;
  bool required = false;
  bool optional = false;
  bool key = false;
  bool shared = false;
  bool native_inline = false;
  bool flexbuffer = false;
  bool offset64 = false;
  uint16_t padding = 0;
  int64_t default_integer = 0;
  double default_real = 0.0;
  std::string union_enum;  // Qualified name.
  std::vector<std::string> doc_comment;
  AttributeList attributes;
  std::string nested_flatbuffer;  // Qualified name.
};

struct ObjectSchema {
  std::string json_name;
  std::string name;
  std::vector<std::string> namespace_components;
  std::string qualified_name;
  bool is_struct = false;
  int32_t minalign = 0;
  int32_t bytesize = 0;
  std::string declaration_file;
  AttributeList attributes;
  std::vector<std::string> doc_comment;
  std::vector<std::string> field_order;
  std::set<std::string> required_fields;
  std::vector<int64_t> reserved_ids;
};

struct EnumValueDesc {
  std::string name;
  int64_t value = 0;
  std::string struct_type;  // Qualified name for union target.
};

struct EnumSchema {
  std::string json_name;
  std::string name;
  std::vector<std::string> namespace_components;
  std::string qualified_name;
  bool is_union = false;
  reflection::BaseType underlying = reflection::None;
  std::vector<EnumValueDesc> values;
  std::vector<std::string> doc_comment;
  AttributeList attributes;
  std::string declaration_file;
};

struct RPCCallSchema {
  std::string name;
  std::string request_type;   // Qualified name.
  std::string response_type;  // Qualified name.
  AttributeList attributes;
  std::vector<std::string> doc_comment;
};

struct ServiceSchema {
  std::string json_name;
  std::string name;
  std::vector<std::string> namespace_components;
  std::string qualified_name;
  std::vector<RPCCallSchema> calls;
  AttributeList attributes;
  std::vector<std::string> doc_comment;
  std::string declaration_file;
};

uint32_t BaseTypeSize(reflection::BaseType type) {
  return static_cast<uint32_t>(
      SizeOf(static_cast<BaseType>(static_cast<int>(type))));
}

std::vector<std::string> SplitDescription(const std::string& description) {
  std::vector<std::string> result;
  if (description.empty()) return result;
  std::stringstream ss(description);
  std::string line;
  while (std::getline(ss, line)) {
    result.push_back(line);
  }
  return result;
}

reflection::AdvancedFeatures AdvancedFeatureFromString(
    const std::string& name) {
  const auto* names = reflection::EnumNamesAdvancedFeatures();
  const auto& values = reflection::EnumValuesAdvancedFeatures();
  for (size_t i = 0; names[i]; ++i) {
    if (names[i][0] == '\0') continue;
    if (name == names[i]) return values[i];
  }
  return static_cast<reflection::AdvancedFeatures>(0);
}

reflection::BaseType BaseTypeFromString(const std::string& name) {
  const auto& values = reflection::EnumValuesBaseType();
  for (size_t i = 0;
       i < sizeof(values) / sizeof(values[0]); ++i) {
    const auto value = values[i];
    const char* enum_name = reflection::EnumNameBaseType(value);
    if (enum_name && name == enum_name) {
      return value;
    }
  }
  return reflection::None;
}

class JsonSchemaImporterImpl {
 public:
  JsonSchemaImporterImpl(Parser* parser, std::string filename)
      : parser_(parser), filename_(std::move(filename)) {}

  bool Import(const std::string& json_schema, std::string* error);

 private:
  using CommentVisitor =
      std::function<bool(const flexbuffers::Map& map, std::string* error)>;

  bool ParseDocument(const std::string& json_schema, std::string* error);
  bool ParseTopLevelMetadata(std::string* error);
  bool ParseScalars(std::string* error);
  bool ParseEnums(std::string* error);
  bool ParseFields(std::string* error);
  bool ParseTypes(std::string* error);
  bool ParseServices(std::string* error);
  bool BuildReflection(std::string* error);

  bool VisitCommentMap(const std::string& comment_json,
                       const std::string& context,
                       const CommentVisitor& visitor, std::string* error);
  bool ParseAttributes(const flexbuffers::Map& map, AttributeList* out,
                       std::string* error);
  bool ParseNamespace(const flexbuffers::Map& map,
                      std::vector<std::string>* out);
  std::string QualifiedName(const std::vector<std::string>& components,
                            const std::string& name) const;
  bool ParseFieldType(const flexbuffers::Map& schema, FieldTypeDesc* type,
                      std::string* error);
  bool ParseTypeRef(const std::string& ref, FieldTypeDesc* type,
                    bool is_element, std::string* error);
  bool ParseArrayType(const flexbuffers::Map& schema, FieldTypeDesc* type,
                      std::string* error);
  bool ExpectRefCategory(const std::string& ref, const std::string& category,
                         std::string* target) const;
  reflection::AdvancedFeatures AdvancedFeaturesMask() const;
  Offset<reflection::Type> CreateTypeOffset(
      const FieldTypeDesc& type_desc,
      const std::unordered_map<std::string, int32_t>& object_indices,
      const std::unordered_map<std::string, int32_t>& enum_indices,
      const std::unordered_map<std::string, ObjectSchema*>& object_lookup,
      FlatBufferBuilder* builder, std::string* error);
  Offset<reflection::Type> CreateUnionType(
      const std::string& union_enum,
      const std::unordered_map<std::string, int32_t>& enum_indices,
      FlatBufferBuilder* builder, std::string* error);
  flatbuffers::Offset<
      flatbuffers::Vector<flatbuffers::Offset<reflection::KeyValue>>>
  CreateAttributes(const AttributeList& attrs, FlatBufferBuilder* builder);
  flexbuffers::Map RootMap() const;
  flexbuffers::Map DefsMap() const;

  Parser* parser_;
  std::string filename_;
  std::vector<uint8_t> document_storage_;

  std::string root_type_ref_;
  std::string file_identifier_;
  std::string file_extension_;
  std::vector<std::string> advanced_features_;
  std::vector<SchemaFileDesc> schema_files_;

  std::unordered_map<std::string, reflection::BaseType> scalars_;
  std::unordered_map<std::string, EnumSchema> enums_;
  std::unordered_map<std::string, ObjectSchema> objects_;
  std::unordered_map<std::string, ServiceSchema> services_;
  std::unordered_map<std::string,
                     std::unordered_map<std::string, FieldSchema>>
      fields_;
};

bool JsonSchemaImporterImpl::Import(const std::string& json_schema,
                                    std::string* error) {
  if (!ParseDocument(json_schema, error)) return false;
  if (!ParseTopLevelMetadata(error)) return false;
  if (!ParseScalars(error)) return false;
  if (!ParseEnums(error)) return false;
  if (!ParseFields(error)) return false;
  if (!ParseTypes(error)) return false;
  if (!ParseServices(error)) return false;
  if (!BuildReflection(error)) return false;
  return true;
}

bool JsonSchemaImporterImpl::ParseDocument(const std::string& json_schema,
                                           std::string* error) {
  flatbuffers::Parser schema_parser;
  flexbuffers::Builder builder;
  if (!schema_parser.ParseFlexBuffer(json_schema.c_str(), filename_.c_str(),
                                     &builder)) {
    if (error) *error = schema_parser.error_;
    return false;
  }
  const auto& buffer = builder.GetBuffer();
  document_storage_.assign(buffer.begin(), buffer.end());
  auto root_map = flexbuffers::GetRoot(document_storage_).AsMap();
  auto defs = root_map["$defs"];
  if (!defs.IsMap()) {
    if (error) *error = "JSON schema missing $defs section.";
    return false;
  }
  return true;
}

bool JsonSchemaImporterImpl::ParseTopLevelMetadata(std::string* error) {
  auto root_map = RootMap();
  auto comment_ref = root_map["$comment"];
  if (!comment_ref.IsString()) {
    if (error) *error = "JSON schema missing $comment metadata.";
    return false;
  }
  const auto comment = comment_ref.AsString().str();
  const auto visitor = [this](const flexbuffers::Map& map,
                              std::string* error) -> bool {
    auto ident = map["file_ident"];
    if (ident.IsString()) file_identifier_ = ident.AsString().str();
    auto ext = map["file_ext"];
    if (ext.IsString()) file_extension_ = ext.AsString().str();
    auto features = map["advanced_features"];
    if (features.IsVector()) {
      auto vec = features.AsVector();
      for (size_t i = 0; i < vec.size(); ++i) {
        if (vec[i].IsString()) {
          advanced_features_.push_back(vec[i].AsString().str());
        }
      }
    }
    auto files = map["fbs_files"];
    if (files.IsVector()) {
      auto vec = files.AsVector();
      for (size_t i = 0; i < vec.size(); ++i) {
        auto file_map = vec[i].AsMap();
        SchemaFileDesc desc;
        auto fn = file_map["filename"];
        if (fn.IsString()) desc.filename = fn.AsString().str();
        auto includes = file_map["included_filenames"];
        if (includes.IsVector()) {
          auto inc_vec = includes.AsVector();
          for (size_t j = 0; j < inc_vec.size(); ++j) {
            if (inc_vec[j].IsString()) {
              desc.includes.push_back(inc_vec[j].AsString().str());
            }
          }
        }
        schema_files_.push_back(std::move(desc));
      }
    }
    return true;
  };
  if (!VisitCommentMap(comment, "$comment", visitor, error)) return false;

  auto ref = root_map["$ref"];
  if (!ref.IsString()) {
    if (error) *error = "JSON schema missing $ref root pointer.";
    return false;
  }
  root_type_ref_ = ref.AsString().str();
  return true;
}

bool JsonSchemaImporterImpl::ParseScalars(std::string* error) {
  auto defs_map = DefsMap();
  auto scalars_ref = defs_map["scalars"];
  if (!scalars_ref.IsMap()) return true;
  auto scalars_map = scalars_ref.AsMap();
  auto keys = scalars_map.Keys();
  for (size_t i = 0; i < keys.size(); ++i) {
    const std::string name = keys[i].AsKey();
    auto meta = scalars_map[name];
    auto comment = meta.AsMap()["$comment"];
    if (!comment.IsString()) continue;
    const auto visitor = [this, &name](const flexbuffers::Map& map,
                                       std::string* /*error*/) -> bool {
      auto base_type = map["base_type"];
      if (base_type.IsString()) {
        const auto bt_name = base_type.AsString().str();
        scalars_[name] = BaseTypeFromString(bt_name);
      }
      return true;
    };
    VisitCommentMap(comment.AsString().str(), name, visitor, error);
  }
  return true;
}

bool JsonSchemaImporterImpl::ParseEnums(std::string* error) {
  auto defs_map = DefsMap();
  auto enums_ref = defs_map["enums"];
  if (!enums_ref.IsMap()) return true;
  auto enums_map = enums_ref.AsMap();
  auto keys = enums_map.Keys();
  for (size_t i = 0; i < keys.size(); ++i) {
    const std::string json_name = keys[i].AsKey();
    auto entry = enums_map[json_name].AsMap();
    EnumSchema schema;
    schema.json_name = json_name;
    auto description = entry["description"];
    if (description.IsString()) {
      schema.doc_comment = SplitDescription(description.AsString().str());
    }
    auto comment = entry["$comment"];
    if (!comment.IsString()) {
      if (error) {
        *error = std::string("Enum ") + json_name +
                 " missing metadata $comment field.";
      }
      return false;
    }
    const auto visitor = [&schema, this](
                             const flexbuffers::Map& map,
                             std::string* /*error*/) -> bool {
      auto name = map["name"];
      if (name.IsString()) schema.name = name.AsString().str();
      ParseNamespace(map, &schema.namespace_components);
      schema.qualified_name =
          QualifiedName(schema.namespace_components, schema.name);
      auto is_union = map["is_union"];
      if (is_union.IsBool()) schema.is_union = is_union.AsBool();
      auto underlying = map["underlying"];
      if (underlying.IsString()) {
        schema.underlying = BaseTypeFromString(underlying.AsString().str());
      }
      auto declaration = map["declaration_file"];
      if (declaration.IsString())
        schema.declaration_file = declaration.AsString().str();
      ParseAttributes(map, &schema.attributes, nullptr);
      auto values = map["values"];
      if (values.IsVector()) {
        auto vec = values.AsVector();
        for (size_t j = 0; j < vec.size(); ++j) {
          auto value_map = vec[j].AsMap();
          EnumValueDesc value_desc;
          auto value_name = value_map["name"];
          if (value_name.IsString())
            value_desc.name = value_name.AsString().str();
          value_desc.value = value_map["value"].AsInt64();
          auto type = value_map["type"];
          if (type.IsString()) value_desc.struct_type = type.AsString().str();
          schema.values.push_back(std::move(value_desc));
        }
      }
      return true;
    };
    if (!VisitCommentMap(comment.AsString().str(), json_name, visitor, error))
      return false;
    enums_[json_name] = std::move(schema);
  }
  return true;
}

bool JsonSchemaImporterImpl::ParseFields(std::string* error) {
  auto defs_map = DefsMap();
  auto fields_ref = defs_map["fields"];
  if (!fields_ref.IsMap()) return true;
  auto fields_map = fields_ref.AsMap();
  auto owners = fields_map.Keys();
  for (size_t i = 0; i < owners.size(); ++i) {
    const std::string owner = owners[i].AsKey();
    auto field_map = fields_map[owner].AsMap();
    auto keys = field_map.Keys();
    for (size_t j = 0; j < keys.size(); ++j) {
      const std::string field_name = keys[j].AsKey();
      auto field_obj = field_map[field_name].AsMap();
      FieldSchema schema;
      schema.name = field_name;
      schema.required = false;
      auto deprecated = field_obj["deprecated"];
      if (deprecated.IsBool()) schema.deprecated = deprecated.AsBool();
      auto description = field_obj["description"];
      if (description.IsString()) {
        schema.doc_comment = SplitDescription(description.AsString().str());
      }
      auto comment = field_obj["$comment"];
      if (!comment.IsString()) {
        if (error) {
          *error = std::string("Field ") + owner + "." + field_name +
                   " missing metadata $comment.";
        }
        return false;
      }
      const auto visitor = [&schema, this](const flexbuffers::Map& map,
                                           std::string* /*error*/) -> bool {
        auto id = map["id"];
        if (id.IsInt()) schema.id = static_cast<uint16_t>(id.AsInt64());
        auto offset = map["offset"];
        if (offset.IsInt())
          schema.offset = static_cast<uint16_t>(offset.AsInt64());
        auto key = map["key"];
        if (key.IsBool()) schema.key = key.AsBool();
        auto required = map["required"];
        if (required.IsBool()) schema.required = required.AsBool();
        auto optional = map["optional"];
        if (optional.IsBool()) schema.optional = optional.AsBool();
        auto padding = map["padding"];
        if (padding.IsInt())
          schema.padding = static_cast<uint16_t>(padding.AsInt64());
        auto offset64 = map["offset64"];
        if (offset64.IsBool()) schema.offset64 = offset64.AsBool();
        auto shared = map["shared"];
        if (shared.IsBool()) schema.shared = shared.AsBool();
        auto native_inline = map["native_inline"];
        if (native_inline.IsBool())
          schema.native_inline = native_inline.AsBool();
        auto flexbuffer = map["flexbuffer"];
        if (flexbuffer.IsBool()) schema.flexbuffer = flexbuffer.AsBool();
        auto nested = map["nested_flatbuffer"];
        if (nested.IsString()) schema.nested_flatbuffer = nested.AsString().str();
        auto union_enum = map["union_enum"];
        if (union_enum.IsString()) schema.union_enum = union_enum.AsString().str();
        ParseAttributes(map, &schema.attributes, nullptr);
        return true;
      };
      if (!VisitCommentMap(comment.AsString().str(),
                           owner + "." + field_name,
                           visitor, error))
        return false;
      if (!ParseFieldType(field_obj, &schema.type, error)) return false;
      auto json_default = field_obj["default"];
      if (json_default.IsInt() || json_default.IsUInt()) {
        schema.default_integer = json_default.IsInt()
                                     ? json_default.AsInt64()
                                     : static_cast<int64_t>(
                                           json_default.AsUInt64());
      } else if (json_default.IsBool()) {
        schema.default_integer = json_default.AsBool() ? 1 : 0;
      } else if (json_default.IsFloat()) {
        schema.default_real = json_default.AsDouble();
      } else if (json_default.IsString()) {
        const auto enum_it = enums_.find(schema.type.ref_name);
        if (enum_it != enums_.end()) {
          const auto value_name = json_default.AsString().str();
          for (const auto& enum_val : enum_it->second.values) {
            if (enum_val.name == value_name) {
              schema.default_integer = enum_val.value;
              break;
            }
          }
        }
      }
      if (schema.type.base_type == reflection::Union &&
          schema.union_enum.empty()) {
        if (error) {
          *error = std::string("Union field ") + owner + "." + field_name +
                   " missing union_enum metadata.";
        }
        return false;
      }
      fields_[owner][field_name] = std::move(schema);
    }
  }
  return true;
}

bool JsonSchemaImporterImpl::ParseTypes(std::string* error) {
  auto defs_map = DefsMap();
  auto types_ref = defs_map["types"];
  if (!types_ref.IsMap()) return true;
  auto types_map = types_ref.AsMap();
  auto keys = types_map.Keys();
  for (size_t i = 0; i < keys.size(); ++i) {
    const std::string json_name = keys[i].AsKey();
    auto type_map = types_map[json_name].AsMap();
    ObjectSchema schema;
    schema.json_name = json_name;
    auto description = type_map["description"];
    if (description.IsString()) {
      schema.doc_comment = SplitDescription(description.AsString().str());
    }
    auto comment = type_map["$comment"];
    if (!comment.IsString()) {
      if (error) {
        *error = std::string("Type ") + json_name +
                 " missing metadata $comment field.";
      }
      return false;
    }
    const auto visitor = [&schema, this](const flexbuffers::Map& map,
                                         std::string* /*error*/) -> bool {
      auto name = map["name"];
      if (name.IsString()) schema.name = name.AsString().str();
      ParseNamespace(map, &schema.namespace_components);
      schema.qualified_name =
          QualifiedName(schema.namespace_components, schema.name);
      auto is_struct = map["is_struct"];
      if (is_struct.IsBool()) schema.is_struct = is_struct.AsBool();
      auto minalign = map["minalign"];
      if (minalign.IsInt())
        schema.minalign = static_cast<int32_t>(minalign.AsInt64());
      auto bytesize = map["bytesize"];
      if (bytesize.IsInt())
        schema.bytesize = static_cast<int32_t>(bytesize.AsInt64());
      auto declaration = map["declaration_file"];
      if (declaration.IsString())
        schema.declaration_file = declaration.AsString().str();
      auto reserved_ids = map["reserved_ids"];
      if (reserved_ids.IsVector()) {
        auto vec = reserved_ids.AsVector();
        for (size_t j = 0; j < vec.size(); ++j) {
          schema.reserved_ids.push_back(vec[j].AsInt64());
        }
      }
      ParseAttributes(map, &schema.attributes, nullptr);
      return true;
    };
    if (!VisitCommentMap(comment.AsString().str(), json_name, visitor, error))
      return false;
    auto properties = type_map["properties"];
    if (!properties.IsMap()) {
      if (error) {
        *error = std::string("Type ") + json_name +
                 " missing properties map.";
      }
        return false;
    }
    auto props_map = properties.AsMap();
    auto prop_keys = props_map.Keys();
    for (size_t j = 0; j < prop_keys.size(); ++j) {
      const auto field_name = prop_keys[j].AsKey();
      schema.field_order.push_back(field_name);
    }
    auto required = type_map["required"];
    if (required.IsVector()) {
      auto vec = required.AsVector();
      for (size_t j = 0; j < vec.size(); ++j) {
        if (vec[j].IsString())
          schema.required_fields.insert(vec[j].AsString().str());
      }
    }
    objects_[json_name] = std::move(schema);
  }
  return true;
}

bool JsonSchemaImporterImpl::ParseServices(std::string* error) {
  auto defs_map = DefsMap();
  auto services_ref = defs_map["services"];
  if (!services_ref.IsMap()) return true;
  auto services_map = services_ref.AsMap();
  auto service_keys = services_map.Keys();
  for (size_t i = 0; i < service_keys.size(); ++i) {
    const std::string json_name = service_keys[i].AsKey();
    auto service_map = services_map[json_name].AsMap();
    ServiceSchema schema;
    schema.json_name = json_name;
    auto description = service_map["description"];
    if (description.IsString()) {
      schema.doc_comment = SplitDescription(description.AsString().str());
    }
    auto comment = service_map["$comment"];
    if (!comment.IsString()) {
      if (error) {
        *error = std::string("Service ") + json_name +
                 " missing metadata $comment.";
      }
      return false;
    }
    const auto visitor = [&schema, this](const flexbuffers::Map& map,
                                         std::string* /*error*/) -> bool {
      auto name = map["name"];
      if (name.IsString()) schema.name = name.AsString().str();
      ParseNamespace(map, &schema.namespace_components);
      schema.qualified_name =
          QualifiedName(schema.namespace_components, schema.name);
      auto declaration = map["declaration_file"];
      if (declaration.IsString())
        schema.declaration_file = declaration.AsString().str();
      ParseAttributes(map, &schema.attributes, nullptr);
      return true;
    };
    if (!VisitCommentMap(comment.AsString().str(), json_name, visitor, error))
      return false;
    auto properties = service_map["properties"];
    if (properties.IsMap()) {
      auto props_map = properties.AsMap();
      auto call_keys = props_map.Keys();
      for (size_t j = 0; j < call_keys.size(); ++j) {
        RPCCallSchema call;
        call.name = call_keys[j].AsKey();
        auto call_map = props_map[call.name].AsMap();
        auto call_comment = call_map["$comment"];
        if (call_comment.IsString()) {
          const auto call_visitor =
              [&call, this](const flexbuffers::Map& map,
                      std::string* /*error*/) -> bool {
            ParseAttributes(map, &call.attributes, nullptr);
            auto name = map["name"];
            if (name.IsString()) call.name = name.AsString().str();
            return true;
          };
          VisitCommentMap(call_comment.AsString().str(),
                          json_name + "." + call.name, call_visitor, nullptr);
        }
        auto call_description = call_map["description"];
        if (call_description.IsString()) {
          call.doc_comment =
              SplitDescription(call_description.AsString().str());
        }
        auto call_properties = call_map["properties"];
        if (call_properties.IsMap()) {
          auto cp_map = call_properties.AsMap();
          auto request = cp_map["request"];
          if (request.IsMap()) {
            auto ref = request.AsMap()["$ref"];
            if (ref.IsString() &&
                !ExpectRefCategory(ref.AsString().str(), "types",
                                   &call.request_type)) {
              if (error)
                *error = std::string(
                             "Invalid request type reference in service ") +
                         json_name + "." + call.name;
              return false;
            }
          }
          auto response = cp_map["response"];
          if (response.IsMap()) {
            auto ref = response.AsMap()["$ref"];
            if (ref.IsString() &&
                !ExpectRefCategory(ref.AsString().str(), "types",
                                   &call.response_type)) {
              if (error)
                *error = std::string(
                             "Invalid response type reference in service ") +
                         json_name + "." + call.name;
              return false;
            }
          }
        }
        schema.calls.push_back(std::move(call));
      }
    }
    services_[json_name] = std::move(schema);
  }
  return true;
}

bool JsonSchemaImporterImpl::ExpectRefCategory(const std::string& ref,
                                               const std::string& category,
                                               std::string* target) const {
  const std::string prefix = std::string("#/$defs/") + category + "/";
  if (ref.compare(0, prefix.size(), prefix) != 0) {
    return false;
  }
  *target = ref.substr(prefix.size());
  return true;
}

bool JsonSchemaImporterImpl::VisitCommentMap(const std::string& comment_json,
                                             const std::string& context,
                                             const CommentVisitor& visitor,
                                             std::string* error) {
  flatbuffers::Parser parser;
  flexbuffers::Builder builder;
  const char* payload = comment_json.empty() ? "{}" : comment_json.c_str();
  if (!parser.ParseFlexBuffer(payload, context.c_str(), &builder)) {
    if (error) {
      *error = std::string("Failed to parse $comment for ") + context +
               ": " + parser.error_;
    }
    return false;
  }
  const auto& buffer = builder.GetBuffer();
  std::vector<uint8_t> storage(buffer.begin(), buffer.end());
  auto map = flexbuffers::GetRoot(storage).AsMap();
  return visitor(map, error);
}

flexbuffers::Map JsonSchemaImporterImpl::RootMap() const {
  return flexbuffers::GetRoot(document_storage_).AsMap();
}

flexbuffers::Map JsonSchemaImporterImpl::DefsMap() const {
  auto root = RootMap();
  auto defs = root["$defs"];
  FLATBUFFERS_ASSERT(defs.IsMap());
  return defs.AsMap();
}

bool JsonSchemaImporterImpl::ParseNamespace(
    const flexbuffers::Map& map, std::vector<std::string>* out) {
  auto ns = map["namespace"];
  if (!ns.IsVector()) return true;
  auto vec = ns.AsVector();
  for (size_t i = 0; i < vec.size(); ++i) {
    if (vec[i].IsString()) out->push_back(vec[i].AsString().str());
  }
  return true;
}

std::string JsonSchemaImporterImpl::QualifiedName(
    const std::vector<std::string>& components,
    const std::string& name) const {
  if (components.empty()) return name;
  std::string qualified;
  for (size_t i = 0; i < components.size(); ++i) {
    if (i != 0) qualified.push_back('.');
    qualified.append(components[i]);
  }
  qualified.push_back('.');
  qualified.append(name);
  return qualified;
}

bool JsonSchemaImporterImpl::ParseAttributes(const flexbuffers::Map& map,
                                             AttributeList* out,
                                             std::string* /*error*/) {
  auto attrs = map["attributes"];
  if (!attrs.IsVector()) return true;
  auto vec = attrs.AsVector();
  for (size_t i = 0; i < vec.size(); ++i) {
    auto attr_map = vec[i].AsMap();
    auto name = attr_map["name"];
    auto value = attr_map["value"];
    if (name.IsString()) {
      out->emplace_back(name.AsString().str(),
                        value.IsString() ? value.AsString().str() : "");
    }
  }
  return true;
}

bool JsonSchemaImporterImpl::ParseTypeRef(const std::string& ref,
                                          FieldTypeDesc* type, bool is_element,
                                          std::string* error) {
  static const std::string prefix = "#/$defs/";
  if (ref.compare(0, prefix.size(), prefix) != 0) {
    if (error)
      *error = std::string("Unsupported $ref format: ") + ref;
    return false;
  }
  const auto rest = ref.substr(prefix.size());
  const auto slash = rest.find('/');
  if (slash == std::string::npos) {
    if (error)
      *error = std::string(
                   "Incomplete $ref path (missing component): ") +
               ref;
    return false;
  }
  const auto category = rest.substr(0, slash);
  const auto target = rest.substr(slash + 1);
  if (category == "scalars") {
    auto it = scalars_.find(target);
    if (it == scalars_.end()) {
      if (error)
        *error = std::string("Unknown scalar reference: ") + ref;
      return false;
    }
    if (is_element)
      type->element = it->second;
    else
      type->base_type = it->second;
  } else if (category == "types") {
    if (is_element) {
      type->element = reflection::Obj;
      type->element_ref_name = target;
    } else {
      type->base_type = reflection::Obj;
      type->ref_name = target;
    }
  } else if (category == "enums") {
    if (is_element) {
      type->element = reflection::UType;
      type->element_ref_name = target;
    } else {
      type->base_type = reflection::UType;
      type->ref_name = target;
    }
  } else {
    if (error)
      *error = std::string("Unsupported $ref category: ") + ref;
    return false;
  }
  return true;
}

bool JsonSchemaImporterImpl::ParseArrayType(const flexbuffers::Map& schema,
                                            FieldTypeDesc* type,
                                            std::string* error) {
  auto items = schema["items"];
  if (!items.IsMap()) {
    if (error) *error = "Array schema missing items definition.";
    return false;
  }
  auto items_map = items.AsMap();
  auto ref = items_map["$ref"];
  if (ref.IsString()) {
    if (!ParseTypeRef(ref.AsString().str(), type, true, error)) return false;
  } else {
    auto all_of = items_map["allOf"];
    if (all_of.IsVector() && all_of.AsVector().size() > 0) {
      auto first = all_of.AsVector()[0].AsMap()["$ref"];
      if (first.IsString()) {
        if (!ParseTypeRef(first.AsString().str(), type, true, error))
          return false;
      }
    }
  }
  auto min_items = schema["minItems"];
  auto max_items = schema["maxItems"];
  if (min_items.IsInt() && max_items.IsInt() &&
      min_items.AsInt64() == max_items.AsInt64()) {
    type->base_type = reflection::Array;
    type->fixed_length = static_cast<uint16_t>(min_items.AsInt64());
  } else {
    type->base_type = reflection::Vector;
  }
  return true;
}

bool JsonSchemaImporterImpl::ParseFieldType(const flexbuffers::Map& schema,
                                            FieldTypeDesc* type,
                                            std::string* error) {
  auto any_of = schema["anyOf"];
  if (any_of.IsVector()) {
    type->base_type = reflection::Union;
    return true;
  }
  auto type_ref = schema["$ref"];
  if (type_ref.IsString()) {
    return ParseTypeRef(type_ref.AsString().str(), type, false, error);
  }
  auto all_of = schema["allOf"];
  if (all_of.IsVector() && all_of.AsVector().size() > 0) {
    auto entry = all_of.AsVector()[0].AsMap();
    auto ref = entry["$ref"];
    if (ref.IsString()) {
      return ParseTypeRef(ref.AsString().str(), type, false, error);
    }
  }
  auto type_string = schema["type"];
  if (type_string.IsString()) {
    const auto t = type_string.AsString().str();
    if (t == "array") {
      return ParseArrayType(schema, type, error);
    } else if (t == "string") {
      type->base_type = reflection::String;
      return true;
    } else if (t == "boolean") {
      type->base_type = reflection::Bool;
      return true;
    } else if (t == "number") {
      type->base_type = reflection::Double;
      return true;
    } else if (t == "integer") {
      type->base_type = reflection::Int;
      return true;
    }
  }
  if (error) *error = "Unable to determine field type.";
  return false;
}

flatbuffers::Offset<
    flatbuffers::Vector<flatbuffers::Offset<reflection::KeyValue>>>
JsonSchemaImporterImpl::CreateAttributes(const AttributeList& attrs,
                                         FlatBufferBuilder* builder) {
  if (attrs.empty()) return 0;
  std::vector<Offset<reflection::KeyValue>> kv_offsets;
  kv_offsets.reserve(attrs.size());
  for (const auto& attr : attrs) {
    auto key = builder->CreateString(attr.first);
    auto value = builder->CreateString(attr.second);
    kv_offsets.push_back(reflection::CreateKeyValue(*builder, key, value));
  }
  return builder->CreateVectorOfSortedTables(&kv_offsets);
}

reflection::AdvancedFeatures JsonSchemaImporterImpl::AdvancedFeaturesMask()
    const {
  uint64_t mask = 0;
  for (const auto& feature : advanced_features_) {
    auto value = AdvancedFeatureFromString(feature);
    mask |= static_cast<uint64_t>(value);
  }
  return static_cast<reflection::AdvancedFeatures>(mask);
}

Offset<reflection::Type> JsonSchemaImporterImpl::CreateTypeOffset(
    const FieldTypeDesc& type_desc,
    const std::unordered_map<std::string, int32_t>& object_indices,
    const std::unordered_map<std::string, int32_t>& enum_indices,
    const std::unordered_map<std::string, ObjectSchema*>& object_lookup,
    FlatBufferBuilder* builder, std::string* error) {
  int32_t index = -1;
  reflection::BaseType base = type_desc.base_type;
  reflection::BaseType element = type_desc.element;
  if (base == reflection::Obj) {
    auto it = object_indices.find(type_desc.ref_name);
    if (it == object_indices.end()) {
      if (error)
        *error = std::string("Unknown object reference: ") +
                 type_desc.ref_name;
      return 0;
    }
    index = it->second;
  } else if (base == reflection::UType) {
    auto it = enum_indices.find(type_desc.ref_name);
    if (it == enum_indices.end()) {
      if (error)
        *error = std::string("Unknown enum reference: ") +
                 type_desc.ref_name;
      return 0;
    }
    index = it->second;
  } else if ((base == reflection::Vector || base == reflection::Array) &&
             element == reflection::Obj) {
    auto it = object_indices.find(type_desc.element_ref_name);
    if (it == object_indices.end()) {
      if (error)
        *error = std::string("Unknown vector element reference: ") +
                 type_desc.element_ref_name;
      return 0;
    }
    index = it->second;
  } else if ((base == reflection::Vector || base == reflection::Array) &&
             element == reflection::UType) {
    auto it = enum_indices.find(type_desc.element_ref_name);
    if (it == enum_indices.end()) {
      if (error)
        *error = std::string("Unknown vector enum reference: ") +
                 type_desc.element_ref_name;
      return 0;
    }
    index = it->second;
  }
  uint32_t element_size = BaseTypeSize(element);
  if ((base == reflection::Vector || base == reflection::Array) &&
      element == reflection::Obj) {
    auto lookup = object_lookup.find(type_desc.element_ref_name);
    if (lookup != object_lookup.end()) {
      element_size = static_cast<uint32_t>(lookup->second->bytesize);
    }
  }
  return reflection::CreateType(*builder, base, element, index,
                                type_desc.fixed_length,
                                BaseTypeSize(base), element_size);
}

Offset<reflection::Type> JsonSchemaImporterImpl::CreateUnionType(
    const std::string& union_enum,
    const std::unordered_map<std::string, int32_t>& enum_indices,
    FlatBufferBuilder* builder, std::string* error) {
  auto it = enum_indices.find(union_enum);
  if (it == enum_indices.end()) {
    if (error)
      *error = std::string("Unknown union enum reference: ") + union_enum;
    return 0;
  }
  return reflection::CreateType(*builder, reflection::Union,
                                reflection::None, it->second, 0,
                                BaseTypeSize(reflection::Union), 0);
}

bool JsonSchemaImporterImpl::BuildReflection(std::string* error) {
  FlatBufferBuilder builder(1024);

  // Sort objects/enums/services deterministically.
  std::vector<ObjectSchema*> object_list;
  object_list.reserve(objects_.size());
  for (auto& entry : objects_) object_list.push_back(&entry.second);
  std::sort(object_list.begin(), object_list.end(),
            [](const ObjectSchema* lhs, const ObjectSchema* rhs) {
              return lhs->qualified_name < rhs->qualified_name;
            });

  std::vector<EnumSchema*> enum_list;
  enum_list.reserve(enums_.size());
  for (auto& entry : enums_) enum_list.push_back(&entry.second);
  std::sort(enum_list.begin(), enum_list.end(),
            [](const EnumSchema* lhs, const EnumSchema* rhs) {
              return lhs->qualified_name < rhs->qualified_name;
            });

  std::vector<ServiceSchema*> service_list;
  service_list.reserve(services_.size());
  for (auto& entry : services_) service_list.push_back(&entry.second);
  std::sort(service_list.begin(), service_list.end(),
            [](const ServiceSchema* lhs, const ServiceSchema* rhs) {
              return lhs->qualified_name < rhs->qualified_name;
            });

  std::unordered_map<std::string, ObjectSchema*> object_lookup;
  std::unordered_map<std::string, int32_t> object_indices;
  std::unordered_map<std::string, std::string> object_json_by_qualified;
  for (size_t i = 0; i < object_list.size(); ++i) {
    object_indices[object_list[i]->json_name] = static_cast<int32_t>(i);
    object_lookup[object_list[i]->json_name] = object_list[i];
    object_json_by_qualified[object_list[i]->qualified_name] =
        object_list[i]->json_name;
  }
  std::unordered_map<std::string, int32_t> enum_indices;
  for (size_t i = 0; i < enum_list.size(); ++i) {
    enum_indices[enum_list[i]->json_name] = static_cast<int32_t>(i);
  }
  std::unordered_map<std::string, std::string> enum_json_by_qualified;
  for (const auto* enum_def : enum_list) {
    enum_json_by_qualified[enum_def->qualified_name] = enum_def->json_name;
  }

  std::vector<Offset<reflection::Object>> object_offsets;
  std::unordered_map<std::string, Offset<reflection::Object>>
      object_offset_by_json;
  object_offsets.reserve(object_list.size());
  for (const auto* object : object_list) {
    std::vector<Offset<reflection::Field>> field_offsets;
    field_offsets.reserve(object->field_order.size());
    const auto empty_field_map =
        std::unordered_map<std::string, FieldSchema>();
    const auto* owner_fields = &empty_field_map;
    auto owner_it = fields_.find(object->json_name);
    if (owner_it != fields_.end()) {
      owner_fields = &owner_it->second;
    }
    for (const auto& field_name : object->field_order) {
      auto it = owner_fields->find(field_name);
      if (it == owner_fields->end()) {
        if (error)
          *error = std::string("Missing field definition for ") +
                   object->json_name + "." + field_name;
        return false;
      }
      const auto& field = it->second;
      Offset<reflection::Type> type_offset = 0;
      if (field.type.base_type == reflection::Union &&
          !field.union_enum.empty()) {
        auto lookup = enum_json_by_qualified.find(field.union_enum);
        std::string enum_key =
            lookup != enum_json_by_qualified.end() ? lookup->second
                                                   : field.union_enum;
        type_offset =
            CreateUnionType(enum_key, enum_indices, &builder, error);
        if (!type_offset.o) return false;
      } else {
        FieldTypeDesc type_desc = field.type;
        if (field.type.base_type == reflection::UType &&
            !field.union_enum.empty()) {
          auto lookup = enum_json_by_qualified.find(field.union_enum);
          type_desc.ref_name =
              lookup != enum_json_by_qualified.end() ? lookup->second
                                                     : field.union_enum;
        }
        type_offset =
            CreateTypeOffset(type_desc, object_indices, enum_indices,
                             object_lookup, &builder, error);
        if (!type_offset.o) return false;
      }
      const bool is_required =
          field.required ||
          object->required_fields.find(field.name) !=
              object->required_fields.end();
      auto name_offset = builder.CreateString(field.name);
      auto attrs_offset = CreateAttributes(field.attributes, &builder);
      auto docs_offset = field.doc_comment.empty()
                             ? 0
                             : builder.CreateVectorOfStrings(field.doc_comment);
      field_offsets.push_back(reflection::CreateField(
          builder, name_offset, type_offset, field.id, field.offset,
          field.default_integer, field.default_real, field.deprecated,
          is_required, field.key, attrs_offset, docs_offset,
          field.optional, field.padding, field.offset64));
    }
    auto fields_vector =
        builder.CreateVectorOfSortedTables(&field_offsets);
    auto name_offset = builder.CreateString(object->qualified_name);
    auto docs_offset = object->doc_comment.empty()
                           ? 0
                           : builder.CreateVectorOfStrings(object->doc_comment);
    auto attrs_offset = CreateAttributes(object->attributes, &builder);
    auto decl_offset = object->declaration_file.empty()
                           ? 0
                           : builder.CreateString(object->declaration_file);
    object_offsets.push_back(reflection::CreateObject(
        builder, name_offset, fields_vector, object->is_struct,
        object->minalign, object->bytesize, attrs_offset, docs_offset,
        decl_offset));
    object_offset_by_json[object->json_name] = object_offsets.back();
  }

  std::vector<Offset<reflection::Enum>> enum_offsets;
  enum_offsets.reserve(enum_list.size());
  for (const auto* enum_def : enum_list) {
    std::vector<Offset<reflection::EnumVal>> value_offsets;
    value_offsets.reserve(enum_def->values.size());
    for (const auto& value : enum_def->values) {
      Offset<reflection::Type> union_type_offset = 0;
      if (!value.struct_type.empty()) {
        FieldTypeDesc union_type_desc;
        union_type_desc.base_type = reflection::Obj;
        auto lookup = object_json_by_qualified.find(value.struct_type);
        union_type_desc.ref_name = lookup != object_json_by_qualified.end()
                                       ? lookup->second
                                       : value.struct_type;
        union_type_offset = CreateTypeOffset(
            union_type_desc, object_indices, enum_indices, object_lookup,
            &builder, error);
        if (!union_type_offset.o) return false;
      }
      auto name_offset = builder.CreateString(value.name);
      value_offsets.push_back(reflection::CreateEnumVal(
          builder, name_offset, value.value, union_type_offset, 0, 0));
    }
    auto values_vector =
        builder.CreateVectorOfSortedTables(&value_offsets);
    FieldTypeDesc underlying_desc;
    underlying_desc.base_type = enum_def->underlying;
    if (enum_def->is_union) {
      underlying_desc.ref_name = enum_def->json_name;
    }
    auto underlying_type = CreateTypeOffset(
        underlying_desc, object_indices, enum_indices, object_lookup, &builder,
        error);
    if (!underlying_type.o) return false;
    auto name_offset = builder.CreateString(enum_def->qualified_name);
    auto docs_offset =
        enum_def->doc_comment.empty()
            ? 0
            : builder.CreateVectorOfStrings(enum_def->doc_comment);
    auto attrs_offset = CreateAttributes(enum_def->attributes, &builder);
    auto decl_offset = enum_def->declaration_file.empty()
                           ? 0
                           : builder.CreateString(enum_def->declaration_file);
    enum_offsets.push_back(reflection::CreateEnum(
        builder, name_offset, values_vector, enum_def->is_union,
        underlying_type, attrs_offset, docs_offset, decl_offset));
  }

  std::vector<Offset<reflection::Service>> service_offsets;
  service_offsets.reserve(service_list.size());
  for (const auto* service : service_list) {
    std::vector<Offset<reflection::RPCCall>> call_offsets;
    call_offsets.reserve(service->calls.size());
    for (const auto& call : service->calls) {
      auto request_it = object_offset_by_json.find(call.request_type);
      auto response_it = object_offset_by_json.find(call.response_type);
      if (request_it == object_offset_by_json.end() ||
          response_it == object_offset_by_json.end()) {
        if (error)
          *error = "Unknown RPC type reference in service " +
                   service->qualified_name;
        return false;
      }
      auto request_obj = request_it->second;
      auto response_obj = response_it->second;
      auto name_offset = builder.CreateString(call.name);
      auto attrs_offset = CreateAttributes(call.attributes, &builder);
      auto docs_offset =
          call.doc_comment.empty()
              ? 0
              : builder.CreateVectorOfStrings(call.doc_comment);
      call_offsets.push_back(reflection::CreateRPCCall(
          builder, name_offset, request_obj, response_obj, attrs_offset,
          docs_offset));
    }
    auto calls_vector = builder.CreateVectorOfSortedTables(&call_offsets);
    auto name_offset = builder.CreateString(service->qualified_name);
    auto attrs_offset = CreateAttributes(service->attributes, &builder);
    auto docs_offset =
        service->doc_comment.empty()
            ? 0
            : builder.CreateVectorOfStrings(service->doc_comment);
    auto decl_offset = service->declaration_file.empty()
                           ? 0
                           : builder.CreateString(service->declaration_file);
    service_offsets.push_back(reflection::CreateService(
        builder, name_offset, calls_vector, attrs_offset, docs_offset,
        decl_offset));
  }

  Offset<flatbuffers::Vector<Offset<reflection::SchemaFile>>>
      schema_files_offset = 0;
  if (!schema_files_.empty()) {
    std::vector<Offset<reflection::SchemaFile>> files;
    files.reserve(schema_files_.size());
    for (const auto& file : schema_files_) {
      auto filename = builder.CreateString(file.filename);
      std::vector<Offset<flatbuffers::String>> includes;
      includes.reserve(file.includes.size());
      for (const auto& inc : file.includes) {
        includes.push_back(builder.CreateString(inc));
      }
      auto includes_vector = builder.CreateVector(includes);
      files.push_back(
          reflection::CreateSchemaFile(builder, filename, includes_vector));
    }
    schema_files_offset = builder.CreateVectorOfSortedTables(&files);
  }

  auto objects_vec = builder.CreateVectorOfSortedTables(&object_offsets);
  auto enums_vec = builder.CreateVectorOfSortedTables(&enum_offsets);
  auto services_vec = builder.CreateVectorOfSortedTables(&service_offsets);
  auto file_ident = builder.CreateString(file_identifier_);
  auto file_ext = builder.CreateString(file_extension_);

  Offset<reflection::Object> root_object = 0;
  std::string root_json_name;
  if (!root_type_ref_.empty() &&
      ExpectRefCategory(root_type_ref_, "types", &root_json_name)) {
    auto it = object_offset_by_json.find(root_json_name);
    if (it != object_offset_by_json.end()) root_object = it->second;
  }

  auto schema_offset = reflection::CreateSchema(
      builder, objects_vec, enums_vec, file_ident, file_ext, root_object,
      services_vec, AdvancedFeaturesMask(), schema_files_offset);
  builder.Finish(schema_offset, reflection::SchemaIdentifier());

  if (!parser_->Deserialize(builder.GetBufferPointer(),
                            builder.GetSize())) {
    if (error)
      *error = "Failed to deserialize reflection schema into parser.";
    return false;
  }
  return true;
}

}  // namespace

bool ImportJsonSchema(const std::string& json_schema,
                      const std::string& filename, Parser* parser,
                      std::string* error) {
  JsonSchemaImporterImpl importer(parser, filename);
  return importer.Import(json_schema, error);
}

}  // namespace flatbuffers
