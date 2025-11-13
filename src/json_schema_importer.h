#ifndef FLATBUFFERS_JSON_SCHEMA_IMPORTER_H_
#define FLATBUFFERS_JSON_SCHEMA_IMPORTER_H_

#include <string>

#include "flatbuffers/idl.h"

namespace flatbuffers {

// Parses a Draft 2019-09 JSON Schema produced by idl_gen_json_schema and
// populates the supplied Parser with the corresponding FlatBuffers schema.
// On failure, returns false and populates |error|.
bool ImportJsonSchema(const std::string& json_schema,
                      const std::string& filename, Parser* parser,
                      std::string* error);

}  // namespace flatbuffers

#endif  // FLATBUFFERS_JSON_SCHEMA_IMPORTER_H_
