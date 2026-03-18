#ifndef FLATBUFFERS_ALIGNED_COMPILER_H_
#define FLATBUFFERS_ALIGNED_COMPILER_H_

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "flatbuffers/idl.h"

namespace flatbuffers {
namespace aligned {

struct RecordLayout;
struct InlineLayout;

struct UnionMemberLayout {
  const EnumVal* value = nullptr;
  std::shared_ptr<InlineLayout> layout;
};

struct InlineLayout {
  enum class Kind {
    kScalar,
    kRecord,
    kString,
    kVector,
    kArray,
    kUnion,
  };

  Kind kind = Kind::kScalar;
  BaseType base_type = BASE_TYPE_NONE;
  const EnumDef* enum_def = nullptr;
  const RecordLayout* record = nullptr;

  size_t size = 0;
  size_t align = 1;

  uint32_t max_length = 0;
  uint32_t max_count = 0;
  uint32_t fixed_length = 0;

  size_t length_offset = 0;
  size_t data_offset = 0;
  size_t stride = 0;

  size_t discriminator_offset = 0;
  size_t payload_offset = 0;
  size_t payload_size = 0;
  size_t payload_align = 1;

  std::shared_ptr<InlineLayout> element;
  std::vector<UnionMemberLayout> union_members;
};

struct FieldLayout {
  static const size_t kNoPresence = static_cast<size_t>(-1);

  const FieldDef* field = nullptr;
  std::string name;
  size_t offset = 0;
  size_t size = 0;
  size_t align = 1;
  size_t presence_index = kNoPresence;
  std::shared_ptr<InlineLayout> layout;
};

struct RecordLayout {
  const StructDef* def = nullptr;
  std::string name;
  std::string qualified_name;
  bool fixed = false;
  size_t size = 0;
  size_t align = 1;
  size_t presence_bytes = 0;
  std::vector<FieldLayout> fields;
};

struct SchemaLayout {
  std::vector<std::unique_ptr<RecordLayout>> records;
  std::map<const StructDef*, const RecordLayout*> by_def;
  std::map<std::string, const RecordLayout*> by_name;

  const RecordLayout* Lookup(const StructDef* def) const;
  const RecordLayout* Lookup(const std::string& name) const;
};

struct CompileOptions {
  uint32_t default_string_max_length = 255;
};

bool GetAttributeUInt(const FieldDef& field, const char* attribute_name,
                      uint32_t* value);

bool CompileSchemaLayout(const Parser& parser, SchemaLayout* schema_layout,
                         std::string* error,
                         const CompileOptions& options = CompileOptions());

std::string GenerateLayoutJson(const SchemaLayout& schema_layout);

}  // namespace aligned
}  // namespace flatbuffers

#endif  // FLATBUFFERS_ALIGNED_COMPILER_H_
