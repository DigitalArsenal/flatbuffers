#include "aligned_layout_test.h"

#include <string>

#include "aligned_compiler.h"
#include "flatbuffers/idl.h"
#include "test_assert.h"

namespace flatbuffers {
namespace tests {
namespace {

bool BuildLayout(const char* schema, aligned::SchemaLayout* layout,
                 std::string* error = nullptr) {
  IDLOptions opts;
  opts.generate_aligned = true;
  Parser parser(opts);
  if (!parser.Parse(schema)) {
    if (error) { *error = parser.error_; }
    return false;
  }
  return aligned::CompileSchemaLayout(parser, layout, error);
}

}  // namespace

void AlignedLayoutTest() {
  aligned::SchemaLayout layout;
  std::string error;
  TEST_ASSERT(BuildLayout(R"(
    namespace Layout;

    table Child {
      value:int;
    }

    table Extra {
      label:string (aligned_max_length: 8);
    }

    union Item {
      Child,
      Extra
    }

    table Root {
      id:uint;
      name:string (aligned_max_length: 16);
      scores:[short] (aligned_max_count: 4);
      tags:[string] (aligned_max_count: 2);
      children:[Child] (aligned_max_count: 2);
      item:Item;
      items:[Item] (aligned_max_count: 2);
      child:Child;
    }

    root_type Root;
  )",
                          &layout, &error));

  const auto* child = layout.Lookup("Child");
  TEST_NOTNULL(child);
  TEST_EQ(4u, static_cast<unsigned>(child->size));
  TEST_EQ(4u, static_cast<unsigned>(child->align));
  TEST_EQ(0u, static_cast<unsigned>(child->fields[0].offset));

  const auto* extra = layout.Lookup("Extra");
  TEST_NOTNULL(extra);
  TEST_EQ(10u, static_cast<unsigned>(extra->size));
  TEST_EQ(1u, static_cast<unsigned>(extra->align));
  TEST_EQ(1u, static_cast<unsigned>(extra->presence_bytes));

  const auto* root = layout.Lookup("Root");
  TEST_NOTNULL(root);
  TEST_EQ(624u, static_cast<unsigned>(root->size));
  TEST_EQ(4u, static_cast<unsigned>(root->align));
  TEST_EQ(1u, static_cast<unsigned>(root->presence_bytes));
  TEST_EQ(4u, static_cast<unsigned>(root->fields[0].offset));    // id
  TEST_EQ(8u, static_cast<unsigned>(root->fields[1].offset));    // name
  TEST_EQ(28u, static_cast<unsigned>(root->fields[2].offset));   // scores
  TEST_EQ(40u, static_cast<unsigned>(root->fields[3].offset));   // tags
  TEST_EQ(556u, static_cast<unsigned>(root->fields[4].offset));  // children
  TEST_EQ(568u, static_cast<unsigned>(root->fields[5].offset));  // item
  TEST_EQ(584u, static_cast<unsigned>(root->fields[6].offset));  // items
  TEST_EQ(620u, static_cast<unsigned>(root->fields[7].offset));  // child

  const auto& name = *root->fields[1].layout;
  TEST_EQ(aligned::InlineLayout::Kind::kString, name.kind);
  TEST_EQ(17u, static_cast<unsigned>(name.size));
  TEST_EQ(16u, name.max_length);
  TEST_EQ(0u, static_cast<unsigned>(root->fields[1].presence_index));

  const auto& scores = *root->fields[2].layout;
  TEST_EQ(aligned::InlineLayout::Kind::kVector, scores.kind);
  TEST_EQ(4u, scores.max_count);
  TEST_EQ(4u, static_cast<unsigned>(scores.data_offset));
  TEST_EQ(2u, static_cast<unsigned>(scores.stride));
  TEST_EQ(12u, static_cast<unsigned>(scores.size));

  const auto& tags = *root->fields[3].layout;
  TEST_EQ(aligned::InlineLayout::Kind::kVector, tags.kind);
  TEST_EQ(aligned::InlineLayout::Kind::kString, tags.element->kind);
  TEST_EQ(255u, tags.element->max_length);
  TEST_EQ(256u, static_cast<unsigned>(tags.stride));
  TEST_EQ(516u, static_cast<unsigned>(tags.size));

  const auto& children = *root->fields[4].layout;
  TEST_EQ(aligned::InlineLayout::Kind::kVector, children.kind);
  TEST_EQ(aligned::InlineLayout::Kind::kRecord, children.element->kind);
  TEST_EQ(4u, static_cast<unsigned>(children.stride));
  TEST_EQ(12u, static_cast<unsigned>(children.size));

  const auto& item = *root->fields[5].layout;
  TEST_EQ(aligned::InlineLayout::Kind::kUnion, item.kind);
  TEST_EQ(4u, static_cast<unsigned>(item.payload_offset));
  TEST_EQ(10u, static_cast<unsigned>(item.payload_size));
  TEST_EQ(16u, static_cast<unsigned>(item.size));
  TEST_EQ(2u, static_cast<unsigned>(item.union_members.size()));

  const auto& items = *root->fields[6].layout;
  TEST_EQ(aligned::InlineLayout::Kind::kVector, items.kind);
  TEST_EQ(aligned::InlineLayout::Kind::kUnion, items.element->kind);
  TEST_EQ(16u, static_cast<unsigned>(items.stride));
  TEST_EQ(36u, static_cast<unsigned>(items.size));

  TEST_ASSERT(!BuildLayout(R"(
    namespace Layout;
    table MissingBounds {
      values:[int];
    }
    root_type MissingBounds;
  )",
                           &layout, &error));
  TEST_ASSERT(error.find("aligned_max_count") != std::string::npos);

  TEST_ASSERT(!BuildLayout(R"(
    namespace Layout;
    table Node {
      next:Node;
    }
    root_type Node;
  )",
                           &layout, &error));
  TEST_ASSERT(error.find("recursive/cyclic") != std::string::npos);
}

}  // namespace tests
}  // namespace flatbuffers
