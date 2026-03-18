#include "aligned_compiler.h"

#include <algorithm>
#include <iomanip>
#include <set>
#include <sstream>
#include <utility>

#include "flatbuffers/util.h"

namespace flatbuffers {
namespace aligned {

namespace {

static const char* kAlignedMaxLengthAttr = "aligned_max_length";
static const char* kAlignedMaxCountAttr = "aligned_max_count";

size_t AlignTo(size_t offset, size_t alignment) {
  FLATBUFFERS_ASSERT(alignment > 0);
  return (offset + alignment - 1) & ~(alignment - 1);
}

std::string QualifiedName(const StructDef& def) {
  if (!def.defined_namespace) { return def.name; }
  return def.defined_namespace->GetFullyQualifiedName(def.name);
}

bool IsSkippedUnionTypeField(const FieldDef& field) {
  if (!field.sibling_union_field) { return false; }
  if (field.value.type.base_type == BASE_TYPE_UTYPE) { return true; }
  return IsVector(field.value.type) && field.value.type.element == BASE_TYPE_UTYPE;
}

bool NeedsPresenceBit(const FieldDef& field) {
  if (field.IsRequired()) { return false; }
  const auto& type = field.value.type;
  if (field.IsScalarOptional()) { return true; }
  if (IsString(type) || IsVector(type)) { return true; }
  if (type.base_type == BASE_TYPE_STRUCT) { return true; }
  return false;
}

bool GetScalarSizeAlign(BaseType base_type, size_t* size, size_t* align) {
  switch (base_type) {
    case BASE_TYPE_BOOL:
    case BASE_TYPE_CHAR:
    case BASE_TYPE_UCHAR:
    case BASE_TYPE_UTYPE: *size = 1; *align = 1; return true;
    case BASE_TYPE_SHORT:
    case BASE_TYPE_USHORT: *size = 2; *align = 2; return true;
    case BASE_TYPE_INT:
    case BASE_TYPE_UINT:
    case BASE_TYPE_FLOAT: *size = 4; *align = 4; return true;
    case BASE_TYPE_LONG:
    case BASE_TYPE_ULONG:
    case BASE_TYPE_DOUBLE: *size = 8; *align = 8; return true;
    default: return false;
  }
}

BaseType ScalarBaseType(const Type& type) {
  if (type.enum_def && !IsVector(type) && type.base_type != BASE_TYPE_UTYPE &&
      type.base_type != BASE_TYPE_UNION && type.base_type != BASE_TYPE_ARRAY) {
    return type.enum_def->underlying_type.base_type;
  }
  return type.base_type;
}

std::string TypeDescription(const Type& type) {
  if (type.base_type == BASE_TYPE_STRUCT && type.struct_def) {
    return QualifiedName(*type.struct_def);
  }
  if (type.base_type == BASE_TYPE_UNION && type.enum_def) { return type.enum_def->name; }
  if (IsVector(type)) { return "[" + TypeDescription(type.VectorType()) + "]"; }
  if (type.base_type == BASE_TYPE_ARRAY) {
    return "[" + TypeDescription(type.VectorType()) + ":" +
           NumToString(type.fixed_length) + "]";
  }
  if (type.enum_def) { return type.enum_def->name; }
  return std::string(TypeName(type.base_type));
}

std::string JsonEscape(const std::string& value) {
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
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          ss << "\\u" << std::hex << std::setw(4) << std::setfill('0')
             << static_cast<int>(static_cast<unsigned char>(c)) << std::dec
             << std::setfill(' ');
        } else {
          ss << c;
        }
    }
  }
  ss << '"';
  return ss.str();
}

std::string LayoutKindName(InlineLayout::Kind kind) {
  switch (kind) {
    case InlineLayout::Kind::kScalar: return "scalar";
    case InlineLayout::Kind::kRecord: return "record";
    case InlineLayout::Kind::kString: return "string";
    case InlineLayout::Kind::kVector: return "vector";
    case InlineLayout::Kind::kArray: return "array";
    case InlineLayout::Kind::kUnion: return "union";
  }
  return "unknown";
}

class Compiler {
 public:
  Compiler(const Parser& parser, SchemaLayout* schema_layout,
           std::string* error, const CompileOptions& options)
      : parser_(parser),
        schema_layout_(schema_layout),
        error_(error),
        options_(options) {}

  bool Compile() {
    for (auto it = parser_.structs_.vec.begin(); it != parser_.structs_.vec.end();
         ++it) {
      const RecordLayout* layout = nullptr;
      if (!CompileRecord(*it, &layout)) { return false; }
    }
    return true;
  }

 private:
  bool Fail(const std::string& message) {
    if (error_) { *error_ = message; }
    return false;
  }

  bool CompileRecord(const StructDef* def, const RecordLayout** out) {
    if (active_records_.count(def)) {
      return Fail("aligned mode does not support recursive/cyclic inline "
                  "layouts: " + QualifiedName(*def));
    }
    auto existing = schema_layout_->by_def.find(def);
    if (existing != schema_layout_->by_def.end()) {
      *out = existing->second;
      return true;
    }

    std::unique_ptr<RecordLayout> record(new RecordLayout());
    record->def = def;
    record->name = def->name;
    record->qualified_name = QualifiedName(*def);
    record->fixed = def->fixed;

    RecordLayout* record_ptr = record.get();
    schema_layout_->records.push_back(std::move(record));
    schema_layout_->by_def[def] = record_ptr;
    schema_layout_->by_name[record_ptr->name] = record_ptr;
    schema_layout_->by_name[record_ptr->qualified_name] = record_ptr;
    active_records_.insert(def);

    size_t presence_count = 0;
    if (!def->fixed) {
      for (auto fit = def->fields.vec.begin(); fit != def->fields.vec.end();
           ++fit) {
        if (IsSkippedUnionTypeField(**fit)) { continue; }
        if (NeedsPresenceBit(**fit)) { ++presence_count; }
      }
      record_ptr->presence_bytes = (presence_count + 7) / 8;
    }

    size_t offset = record_ptr->presence_bytes;
    size_t max_align = 1;
    size_t presence_index = 0;

    for (auto fit = def->fields.vec.begin(); fit != def->fields.vec.end(); ++fit) {
      const FieldDef* field = *fit;
      if (IsSkippedUnionTypeField(*field)) { continue; }

      FieldLayout field_layout;
      field_layout.field = field;
      field_layout.name = field->name;

      if (!CompileInlineLayout(field->value.type, field, &field_layout.layout)) {
        return false;
      }

      field_layout.size = field_layout.layout->size;
      field_layout.align = field_layout.layout->align;
      offset = AlignTo(offset, field_layout.align);
      field_layout.offset = offset;
      if (NeedsPresenceBit(*field)) {
        field_layout.presence_index = presence_index++;
      }

      offset += field_layout.size;
      max_align = std::max(max_align, field_layout.align);
      record_ptr->fields.push_back(field_layout);
    }

    record_ptr->align = max_align;
    record_ptr->size = std::max<size_t>(1, AlignTo(offset, max_align));

    if (def->fixed) {
      if (record_ptr->align != def->minalign || record_ptr->size != def->bytesize) {
        return Fail("aligned layout mismatch while lowering struct " +
                    record_ptr->qualified_name);
      }
    }

    active_records_.erase(def);
    *out = record_ptr;
    return true;
  }

  bool CompileInlineLayout(const Type& type, const FieldDef* field,
                           std::shared_ptr<InlineLayout>* out) {
    std::shared_ptr<InlineLayout> layout(new InlineLayout());
    layout->base_type = type.base_type;
    layout->enum_def = type.enum_def;

    const BaseType scalar_type = ScalarBaseType(type);
    if (IsScalar(scalar_type) || type.base_type == BASE_TYPE_UTYPE ||
        (type.enum_def && !IsVector(type) && type.base_type != BASE_TYPE_UNION &&
         type.base_type != BASE_TYPE_ARRAY)) {
      size_t size = 0;
      size_t align = 0;
      if (!GetScalarSizeAlign(scalar_type, &size, &align)) {
        return Fail("unsupported aligned scalar type: " + TypeDescription(type));
      }
      layout->kind = InlineLayout::Kind::kScalar;
      layout->base_type = scalar_type;
      layout->size = size;
      layout->align = align;
      *out = layout;
      return true;
    }

    if (type.base_type == BASE_TYPE_STRUCT && type.struct_def) {
      const RecordLayout* record = nullptr;
      if (!CompileRecord(type.struct_def, &record)) { return false; }
      layout->kind = InlineLayout::Kind::kRecord;
      layout->record = record;
      layout->size = record->size;
      layout->align = record->align;
      *out = layout;
      return true;
    }

    if (type.base_type == BASE_TYPE_STRING) {
      uint32_t max_length = options_.default_string_max_length;
      uint32_t explicit_length = 0;
      if (field && GetAttributeUInt(*field, kAlignedMaxLengthAttr, &explicit_length)) {
        max_length = explicit_length;
      }
      layout->kind = InlineLayout::Kind::kString;
      layout->max_length = max_length;
      layout->size = static_cast<size_t>(1 + max_length);
      layout->align = 1;
      layout->length_offset = 0;
      layout->data_offset = 1;
      *out = layout;
      return true;
    }

    if (type.base_type == BASE_TYPE_ARRAY) {
      if (!CompileInlineLayout(type.VectorType(), nullptr, &layout->element)) {
        return false;
      }
      layout->kind = InlineLayout::Kind::kArray;
      layout->fixed_length = type.fixed_length;
      layout->stride = AlignTo(layout->element->size, layout->element->align);
      layout->size = layout->stride * type.fixed_length;
      layout->align = layout->element->align;
      *out = layout;
      return true;
    }

    if (IsVector(type) || type.base_type == BASE_TYPE_VECTOR64) {
      uint32_t max_count = 0;
      if (!field || !GetAttributeUInt(*field, kAlignedMaxCountAttr, &max_count)) {
        return Fail("aligned vector field `" +
                    (field ? field->name : TypeDescription(type)) +
                    "` requires the `" + kAlignedMaxCountAttr + "` attribute");
      }
      if (max_count == 0) {
        return Fail("`" + std::string(kAlignedMaxCountAttr) +
                    "` must be at least 1 for field `" + field->name + "`");
      }

      if (!CompileInlineLayout(type.VectorType(), nullptr, &layout->element)) {
        return false;
      }

      layout->kind = InlineLayout::Kind::kVector;
      layout->max_count = max_count;
      layout->length_offset = 0;
      layout->data_offset = AlignTo(sizeof(uint32_t), layout->element->align);
      layout->stride = AlignTo(layout->element->size, layout->element->align);
      layout->align = std::max<size_t>(4, layout->element->align);
      layout->size =
          AlignTo(layout->data_offset + layout->stride * max_count, layout->align);
      *out = layout;
      return true;
    }

    if (type.base_type == BASE_TYPE_UNION) {
      size_t discrim_size = 0;
      size_t discrim_align = 0;
      const BaseType discrim_type =
          type.enum_def ? type.enum_def->underlying_type.base_type : BASE_TYPE_UTYPE;
      if (!GetScalarSizeAlign(discrim_type, &discrim_size, &discrim_align)) {
        return Fail("unsupported aligned union discriminator for `" +
                    TypeDescription(type) + "`");
      }

      layout->kind = InlineLayout::Kind::kUnion;
      layout->base_type = discrim_type;
      layout->enum_def = type.enum_def;
      layout->discriminator_offset = 0;
      layout->payload_align = 1;

      if (type.enum_def) {
        for (auto it = type.enum_def->Vals().begin(); it != type.enum_def->Vals().end();
             ++it) {
          const EnumVal* value = *it;
          if (value->union_type.base_type == BASE_TYPE_NONE) { continue; }

          UnionMemberLayout member;
          member.value = value;
          if (!CompileInlineLayout(value->union_type, nullptr, &member.layout)) {
            return false;
          }
          layout->payload_size = std::max(layout->payload_size, member.layout->size);
          layout->payload_align =
              std::max(layout->payload_align, member.layout->align);
          layout->union_members.push_back(member);
        }
      }

      layout->payload_offset = AlignTo(discrim_size, layout->payload_align);
      layout->align = std::max(discrim_align, layout->payload_align);
      layout->size =
          AlignTo(layout->payload_offset + layout->payload_size, layout->align);
      *out = layout;
      return true;
    }

    return Fail("aligned mode does not define a fixed-size lowering for `" +
                TypeDescription(type) + "`");
  }

  const Parser& parser_;
  SchemaLayout* schema_layout_;
  std::string* error_;
  CompileOptions options_;
  std::set<const StructDef*> active_records_;
};

}  // namespace

const RecordLayout* SchemaLayout::Lookup(const StructDef* def) const {
  auto it = by_def.find(def);
  return it == by_def.end() ? nullptr : it->second;
}

const RecordLayout* SchemaLayout::Lookup(const std::string& name) const {
  auto it = by_name.find(name);
  return it == by_name.end() ? nullptr : it->second;
}

bool GetAttributeUInt(const FieldDef& field, const char* attribute_name,
                      uint32_t* value) {
  const Value* attr = field.attributes.Lookup(attribute_name);
  if (!attr) { return false; }
  return StringToNumber(attr->constant.c_str(), value);
}

bool CompileSchemaLayout(const Parser& parser, SchemaLayout* schema_layout,
                         std::string* error, const CompileOptions& options) {
  if (!schema_layout) {
    if (error) { *error = "null schema layout"; }
    return false;
  }
  schema_layout->records.clear();
  schema_layout->by_def.clear();
  schema_layout->by_name.clear();
  Compiler compiler(parser, schema_layout, error, options);
  return compiler.Compile();
}

std::string GenerateLayoutJson(const SchemaLayout& schema_layout) {
  std::ostringstream ss;
  ss << "{";
  for (size_t i = 0; i < schema_layout.records.size(); ++i) {
    const RecordLayout& record = *schema_layout.records[i];
    if (i) { ss << ","; }
    ss << JsonEscape(record.name) << ":{";
    ss << "\"qualified_name\":" << JsonEscape(record.qualified_name) << ",";
    ss << "\"size\":" << record.size << ",";
    ss << "\"align\":" << record.align << ",";
    ss << "\"fixed\":" << (record.fixed ? "true" : "false") << ",";
    ss << "\"presence_bytes\":" << record.presence_bytes << ",";
    ss << "\"fields\":[";
    for (size_t f = 0; f < record.fields.size(); ++f) {
      const FieldLayout& field = record.fields[f];
      if (f) { ss << ","; }
      ss << "{";
      ss << "\"name\":" << JsonEscape(field.name) << ",";
      ss << "\"offset\":" << field.offset << ",";
      ss << "\"size\":" << field.size << ",";
      ss << "\"align\":" << field.align << ",";
      ss << "\"kind\":" << JsonEscape(LayoutKindName(field.layout->kind));
      if (field.presence_index != FieldLayout::kNoPresence) {
        ss << ",\"presence_index\":" << field.presence_index;
      }
      if (field.layout->kind == InlineLayout::Kind::kString) {
        ss << ",\"max_length\":" << field.layout->max_length;
      }
      if (field.layout->kind == InlineLayout::Kind::kVector) {
        ss << ",\"max_count\":" << field.layout->max_count;
        ss << ",\"data_offset\":" << field.layout->data_offset;
        ss << ",\"stride\":" << field.layout->stride;
      }
      if (field.layout->kind == InlineLayout::Kind::kArray) {
        ss << ",\"fixed_length\":" << field.layout->fixed_length;
        ss << ",\"stride\":" << field.layout->stride;
      }
      if (field.layout->kind == InlineLayout::Kind::kUnion) {
        ss << ",\"payload_offset\":" << field.layout->payload_offset;
        ss << ",\"payload_size\":" << field.layout->payload_size;
      }
      ss << "}";
    }
    ss << "]}";
  }
  ss << "}";
  return ss.str();
}

}  // namespace aligned
}  // namespace flatbuffers
