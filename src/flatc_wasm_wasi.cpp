// flatc_wasm_wasi.cpp - standalone WASI JSON <-> FlatBuffer converter.
//
// Builds to flatc-wasi.wasm (CMake target flatc_wasi): a WASI reactor that
// imports only wasi_snapshot_preview1, so WasmEdge, wasmtime and Node's WASI
// load it without JavaScript glue. The export contract is documented in
// wasm/WASI.md; keep the two in sync.
//
// Built with -fno-exceptions: every failure returns a status code and leaves
// a message for flatc_last_error_*. Only allocation failure aborts.

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "flatbuffers/flatbuffers.h"
#include "flatbuffers/flexbuffers.h"
#include "flatbuffers/idl.h"
#include "flatbuffers/reflection.h"
#include "flatbuffers/util.h"

#define FLATC_API extern "C" __attribute__((used, visibility("default")))

namespace {

// Contract version reported by flatc_abi_version. Bump on any change to an
// export's signature or semantics.
constexpr uint32_t kAbiVersion = 1;

enum Status : int32_t {
  kOk = 0,
  kErrInvalidArgument = -1,
  kErrSchemaNotFound = -2,
  kErrSchemaParse = -3,
  kErrNoRootType = -4,
  kErrJsonParse = -5,
  kErrInvalidBinary = -6,
  kErrJsonGeneration = -7,
  kErrBufferTooSmall = -8,
  kErrFileNotFound = -9,
  kErrUnknownOption = -10,
};

enum Option : uint32_t {
  kOptSizePrefixed = 1u << 0,
  kOptForceDefaults = 1u << 1,
  kOptStrictJson = 1u << 2,
  kOptNaturalUtf8 = 1u << 3,
  kOptSkipUnknownFields = 1u << 4,
  kOptCompactJson = 1u << 5,
};
constexpr uint32_t kKnownOptions = kOptSizePrefixed | kOptForceDefaults |
                                   kOptStrictJson | kOptNaturalUtf8 |
                                   kOptSkipUnknownFields | kOptCompactJson;

using FileMap = std::map<std::string, std::string>;

struct Schema {
  std::string path;
  std::string source;
  // Every file the schema pulled in, captured at add time so a rebuild never
  // depends on the virtual file map as it is later.
  FileMap files;
  // Null after a failed JSON parse; rebuilt from source on next use.
  std::unique_ptr<flatbuffers::Parser> parser;
  // Binary schema (bfbs) used to verify untrusted input before GenText.
  std::vector<uint8_t> bfbs;
  // True when some field is a union or holds a nested FlatBuffer or
  // FlexBuffer: cases the reflection verifier leaves open (see DeepVerifier).
  bool needs_deep_check = false;
};

struct State {
  std::string error;
  FileMap vfs;
  std::map<int32_t, Schema> schemas;
  int32_t next_id = 1;
  // File source for the include hooks while a schema is parsed.
  const FileMap* read_files = nullptr;
  FileMap* record_files = nullptr;
};

State& S();

// Collapses "." and ".." and duplicate separators. Fails on paths that climb
// above the root. A leading "/" is dropped: the file map has a single root.
bool NormalizePath(const char* in, size_t len, std::string* out) {
  std::vector<std::string> parts;
  std::string part;
  for (size_t i = 0; i <= len; i++) {
    const char c = i < len ? in[i] : '/';
    if (c == '\0') return false;
    if (c == '/' || c == '\\') {
      if (part == "..") {
        if (parts.empty()) return false;
        parts.pop_back();
      } else if (!part.empty() && part != ".") {
        parts.push_back(part);
      }
      part.clear();
    } else {
      part += c;
    }
  }
  if (parts.empty()) return false;
  out->clear();
  for (size_t i = 0; i < parts.size(); i++) {
    if (i) *out += '/';
    *out += parts[i];
  }
  return true;
}

const std::string* FindFile(const char* name) {
  State& s = S();
  if (!s.read_files || !name) return nullptr;
  std::string key;
  if (!NormalizePath(name, strlen(name), &key)) return nullptr;
  auto it = s.read_files->find(key);
  return it == s.read_files->end() ? nullptr : &it->second;
}

bool VfsFileExists(const char* name) { return FindFile(name) != nullptr; }

bool VfsLoadFile(const char* name, bool /*binary*/, std::string* buf) {
  const std::string* data = FindFile(name);
  if (!data) return false;
  *buf = *data;
  State& s = S();
  if (s.record_files) {
    std::string key;
    NormalizePath(name, strlen(name), &key);
    (*s.record_files)[key] = *data;
  }
  return true;
}

State& S() {
  static State* state = [] {
    // The parser reaches files only through these hooks; there is no real
    // filesystem behind the WASI imports.
    flatbuffers::SetFileExistsFunction(VfsFileExists);
    flatbuffers::SetLoadFileFunction(VfsLoadFile);
    return new State();
  }();
  return *state;
}

int32_t Fail(int32_t status, const std::string& message) {
  S().error = message;
  return status;
}

flatbuffers::IDLOptions BaseOptions() {
  flatbuffers::IDLOptions opts;
  opts.no_warnings = true;
  return opts;
}

// Parses schema.source into a fresh parser. With record set, captures the
// included files into schema.files; otherwise reads them from schema.files.
int32_t BuildParser(Schema& schema, bool record) {
  State& s = S();
  auto parser = std::make_unique<flatbuffers::Parser>(BaseOptions());
  if (record) {
    schema.files.clear();
    s.read_files = &s.vfs;
    s.record_files = &schema.files;
  } else {
    s.read_files = &schema.files;
    s.record_files = nullptr;
  }
  const bool ok = parser->Parse(schema.source.c_str(), nullptr,
                                schema.path.c_str());
  s.read_files = nullptr;
  s.record_files = nullptr;
  if (!ok) return Fail(kErrSchemaParse, parser->error_);
  if (!parser->root_struct_def_) {
    return Fail(kErrNoRootType, schema.path + ": schema declares no root_type");
  }
  parser->error_.clear();
  schema.parser = std::move(parser);
  return kOk;
}

bool NeedsDeepCheck(const flatbuffers::Parser& parser) {
  for (const auto* sd : parser.structs_.vec) {
    for (const auto* fd : sd->fields.vec) {
      const auto& type = fd->value.type;
      if (fd->nested_flatbuffer || fd->flexbuffer ||
          type.base_type == flatbuffers::BASE_TYPE_UNION ||
          type.element == flatbuffers::BASE_TYPE_UNION) {
        return true;
      }
    }
  }
  return false;
}

Schema* FindSchema(int32_t id) {
  auto& schemas = S().schemas;
  auto it = schemas.find(id);
  return it == schemas.end() ? nullptr : &it->second;
}

// Returns the schema's parser, rebuilding it if a failed parse discarded it.
flatbuffers::Parser* ReadyParser(Schema& schema, int32_t* status) {
  if (!schema.parser) {
    *status = BuildParser(schema, /*record=*/false);
    if (*status != kOk) return nullptr;
  }
  *status = kOk;
  return schema.parser.get();
}

int32_t CopyOut(const uint8_t* data, size_t size, uint8_t* out,
                uint32_t out_cap, uint32_t* out_len) {
  if (size > UINT32_MAX) {
    return Fail(kErrInvalidArgument, "result exceeds 4 GiB");
  }
  *out_len = static_cast<uint32_t>(size);
  if (size > out_cap) {
    return Fail(kErrBufferTooSmall,
                "output needs " + flatbuffers::NumToString(size) +
                    " bytes; buffer holds " +
                    flatbuffers::NumToString(out_cap));
  }
  if (size) memcpy(out, data, size);
  return kOk;
}

// Walks a table that already passed reflection verification and closes what
// that verifier leaves open, so GenText never follows an unchecked offset:
//  - nested FlatBuffers and FlexBuffers are verified;
//  - a union value whose type is NONE is rejected (reflection skips the
//    value, and GenText would read a type byte from the previous field).
class DeepVerifier {
 public:
  DeepVerifier(const reflection::Schema& schema, std::string* error)
      : schema_(schema), error_(error) {}

  bool Table(const flatbuffers::StructDef& sd, const flatbuffers::Table* table,
             int depth) {
    if (!table) return true;
    if (depth > 64) return Error("nesting deeper than 64 tables");
    // Deprecated fields included: GenText prints them when present.
    for (const auto* fd : sd.fields.vec) {
      if (!Field(*fd, table, depth)) return false;
    }
    return true;
  }

 private:
  bool Error(const std::string& message) {
    *error_ = message;
    return false;
  }

  bool Value(const flatbuffers::Type& type, const void* value,
             uint8_t union_type, int depth) {
    using flatbuffers::BASE_TYPE_STRUCT;
    using flatbuffers::BASE_TYPE_UNION;
    if (type.base_type == BASE_TYPE_STRUCT && !type.struct_def->fixed) {
      return Table(*type.struct_def,
                   reinterpret_cast<const flatbuffers::Table*>(value),
                   depth + 1);
    }
    if (type.base_type == BASE_TYPE_UNION) {
      const auto* ev = type.enum_def->ReverseLookup(union_type, false);
      if (!ev) return true;  // unknown member; GenText reports it.
      return Value(ev->union_type, value, 0, depth);
    }
    return true;
  }

  bool Bytes(const flatbuffers::FieldDef& fd, const uint8_t* data,
             size_t size, int depth) {
    if (fd.flexbuffer) {
      if (!flexbuffers::VerifyBuffer(data, size)) {
        return Error("field " + fd.name + ": invalid nested FlexBuffer");
      }
      return true;
    }
    const std::string name =
        fd.nested_flatbuffer->defined_namespace->GetFullyQualifiedName(
            fd.nested_flatbuffer->name);
    const auto* object = schema_.objects()->LookupByKey(name.c_str());
    if (!object) return Error("field " + fd.name + ": nested type not found");
    if (!flatbuffers::Verify(schema_, *object, data, size)) {
      return Error("field " + fd.name + ": invalid nested FlatBuffer");
    }
    return Table(*fd.nested_flatbuffer,
                 flatbuffers::GetRoot<flatbuffers::Table>(data), depth + 1);
  }

  bool Field(const flatbuffers::FieldDef& fd, const flatbuffers::Table* table,
             int depth) {
    using namespace flatbuffers;
    const Type& type = fd.value.type;
    const voffset_t off = fd.value.offset;
    switch (type.base_type) {
      case BASE_TYPE_STRUCT:
        if (type.struct_def->fixed) return true;
        return Value(type, table->GetPointer<const void*>(off), 0, depth);
      case BASE_TYPE_UNION: {
        if (!table->GetOptionalFieldOffset(off)) return true;
        const uint8_t utype =
            fd.sibling_union_field
                ? table->GetField<uint8_t>(fd.sibling_union_field->value.offset,
                                           0)
                : 0;
        if (!utype) {
          return Error("union field " + fd.name + " has a value but no type");
        }
        return Value(type, table->GetPointer<const void*>(off), utype, depth);
      }
      case BASE_TYPE_VECTOR: {
        const Type elem = type.VectorType();
        if ((fd.nested_flatbuffer || fd.flexbuffer) &&
            (elem.base_type == BASE_TYPE_UCHAR ||
             elem.base_type == BASE_TYPE_CHAR)) {
          const auto* vec = table->GetPointer<const Vector<uint8_t>*>(off);
          return !vec || Bytes(fd, vec->data(), vec->size(), depth);
        }
        if (elem.base_type == BASE_TYPE_STRUCT && !elem.struct_def->fixed) {
          const auto* vec =
              table->GetPointer<const Vector<Offset<flatbuffers::Table>>*>(
                  off);
          if (!vec) return true;
          for (uoffset_t i = 0; i < vec->size(); i++) {
            if (!Table(*elem.struct_def, vec->Get(i), depth + 1)) return false;
          }
          return true;
        }
        if (elem.base_type == BASE_TYPE_UNION) {
          const auto* vec =
              table->GetPointer<const Vector<Offset<void>>*>(off);
          if (!vec || !vec->size()) return true;
          const auto* types =
              fd.sibling_union_field
                  ? table->GetPointer<const Vector<uint8_t>*>(
                        fd.sibling_union_field->value.offset)
                  : nullptr;
          if (!types || types->size() != vec->size()) {
            return Error("union vector " + fd.name + " has no matching types");
          }
          for (uoffset_t i = 0; i < vec->size(); i++) {
            if (!Value(elem, vec->Get(i), types->Get(i), depth)) return false;
          }
        }
        return true;
      }
      case BASE_TYPE_VECTOR64: {
        if (!fd.nested_flatbuffer && !fd.flexbuffer) return true;
        const auto* vec =
            table->GetPointer64<const Vector64<uint8_t>*>(off);
        return !vec || Bytes(fd, vec->data(), vec->size(), depth);
      }
      default:
        return true;
    }
  }

  const reflection::Schema& schema_;
  std::string* error_;
};

bool ValidOptions(uint32_t options, int32_t* status) {
  if (options & ~kKnownOptions) {
    *status = Fail(kErrUnknownOption,
                   "unknown option bits 0x" +
                       flatbuffers::IntToStringHex(
                           static_cast<int>(options & ~kKnownOptions), 8));
    return false;
  }
  *status = kOk;
  return true;
}

}  // namespace

// ---------------------------------------------------------------------------
// Module information and errors
// ---------------------------------------------------------------------------

FLATC_API uint32_t flatc_abi_version() { return kAbiVersion; }

FLATC_API const char* flatc_version() {
  return flatbuffers::FLATBUFFERS_VERSION();
}

FLATC_API const char* flatc_last_error_ptr() { return S().error.c_str(); }

FLATC_API uint32_t flatc_last_error_len() {
  return static_cast<uint32_t>(S().error.size());
}

// ---------------------------------------------------------------------------
// Virtual file map (include resolution)
// ---------------------------------------------------------------------------

FLATC_API int32_t flatc_vfs_put(const char* path, uint32_t path_len,
                                const uint8_t* data, uint32_t data_len) {
  State& s = S();
  s.error.clear();
  if (!path || (!data && data_len)) {
    return Fail(kErrInvalidArgument, "null path or data pointer");
  }
  std::string key;
  if (!NormalizePath(path, path_len, &key)) {
    return Fail(kErrInvalidArgument,
                "invalid path: " + std::string(path, path_len));
  }
  s.vfs[key].assign(reinterpret_cast<const char*>(data), data_len);
  return kOk;
}

FLATC_API int32_t flatc_vfs_remove(const char* path, uint32_t path_len) {
  State& s = S();
  s.error.clear();
  std::string key;
  if (!path || !NormalizePath(path, path_len, &key)) {
    return Fail(kErrInvalidArgument, "invalid path");
  }
  if (!s.vfs.erase(key)) return Fail(kErrFileNotFound, "no file " + key);
  return kOk;
}

FLATC_API void flatc_vfs_clear() {
  State& s = S();
  s.error.clear();
  s.vfs.clear();
}

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

FLATC_API int32_t flatc_schema_add(const char* path, uint32_t path_len,
                                   const char* source, uint32_t source_len) {
  State& s = S();
  s.error.clear();
  if (!path || (!source && source_len)) {
    return Fail(kErrInvalidArgument, "null path or source pointer");
  }
  Schema schema;
  if (!NormalizePath(path, path_len, &schema.path)) {
    return Fail(kErrInvalidArgument,
                "invalid path: " + std::string(path, path_len));
  }
  if (source_len) {
    schema.source.assign(source, source_len);
  } else {
    auto it = s.vfs.find(schema.path);
    if (it == s.vfs.end()) {
      return Fail(kErrFileNotFound, "no file " + schema.path);
    }
    schema.source = it->second;
  }
  if (memchr(schema.source.data(), 0, schema.source.size())) {
    return Fail(kErrInvalidArgument, "schema source contains a NUL byte");
  }

  int32_t status = BuildParser(schema, /*record=*/true);
  if (status != kOk) return status;

  // A second parser serializes the reflection schema, leaving the
  // conversion parser untouched.
  flatbuffers::Parser reflect(BaseOptions());
  s.read_files = &schema.files;
  const bool ok =
      reflect.Parse(schema.source.c_str(), nullptr, schema.path.c_str());
  s.read_files = nullptr;
  if (!ok) return Fail(kErrSchemaParse, reflect.error_);
  reflect.Serialize();
  schema.bfbs.assign(reflect.builder_.GetBufferPointer(),
                     reflect.builder_.GetBufferPointer() +
                         reflect.builder_.GetSize());
  schema.needs_deep_check = NeedsDeepCheck(*schema.parser);

  const int32_t id = s.next_id++;
  s.schemas.emplace(id, std::move(schema));
  return id;
}

FLATC_API int32_t flatc_schema_remove(int32_t schema_id) {
  State& s = S();
  s.error.clear();
  if (!s.schemas.erase(schema_id)) {
    return Fail(kErrSchemaNotFound,
                "no schema " + flatbuffers::NumToString(schema_id));
  }
  return kOk;
}

// ---------------------------------------------------------------------------
// Conversion
// ---------------------------------------------------------------------------

FLATC_API int32_t flatc_json_to_binary(int32_t schema_id, const char* json,
                                       uint32_t json_len, uint32_t options,
                                       uint8_t* out, uint32_t out_cap,
                                       uint32_t* out_len) {
  State& s = S();
  s.error.clear();
  if (!out_len || (!json && json_len) || (!out && out_cap)) {
    return Fail(kErrInvalidArgument, "null pointer argument");
  }
  *out_len = 0;
  int32_t status;
  if (!ValidOptions(options, &status)) return status;
  Schema* schema = FindSchema(schema_id);
  if (!schema) {
    return Fail(kErrSchemaNotFound,
                "no schema " + flatbuffers::NumToString(schema_id));
  }
  if (json_len && memchr(json, 0, json_len)) {
    return Fail(kErrJsonParse, "JSON contains a NUL byte");
  }
  flatbuffers::Parser* parser = ReadyParser(*schema, &status);
  if (!parser) return status;

  parser->opts.strict_json = (options & kOptStrictJson) != 0;
  parser->opts.skip_unexpected_fields_in_json =
      (options & kOptSkipUnknownFields) != 0;
  parser->opts.size_prefixed = (options & kOptSizePrefixed) != 0;
  parser->opts.force_defaults = (options & kOptForceDefaults) != 0;
  parser->builder_.ForceDefaults(parser->opts.force_defaults);
  parser->error_.clear();

  const std::string text(json ? json : "", json_len);
  if (!parser->ParseJson(text.c_str())) {
    const std::string message = parser->error_;
    // Parser state after a failed parse is not guaranteed clean.
    schema->parser.reset();
    return Fail(kErrJsonParse, message);
  }
  return CopyOut(parser->builder_.GetBufferPointer(),
                 parser->builder_.GetSize(), out, out_cap, out_len);
}

FLATC_API int32_t flatc_binary_to_json(int32_t schema_id, const uint8_t* bin,
                                       uint32_t bin_len, uint32_t options,
                                       uint8_t* out, uint32_t out_cap,
                                       uint32_t* out_len) {
  using flatbuffers::uoffset_t;
  State& s = S();
  s.error.clear();
  if (!out_len || (!bin && bin_len) || (!out && out_cap)) {
    return Fail(kErrInvalidArgument, "null pointer argument");
  }
  *out_len = 0;
  int32_t status;
  if (!ValidOptions(options, &status)) return status;
  Schema* schema = FindSchema(schema_id);
  if (!schema) {
    return Fail(kErrSchemaNotFound,
                "no schema " + flatbuffers::NumToString(schema_id));
  }
  const bool size_prefixed = (options & kOptSizePrefixed) != 0;
  const size_t header = size_prefixed ? 2 * sizeof(uoffset_t)
                                      : sizeof(uoffset_t);
  if (bin_len < header) {
    return Fail(kErrInvalidBinary, "buffer shorter than a FlatBuffer header");
  }
  if (size_prefixed) {
    const uoffset_t prefix = flatbuffers::ReadScalar<uoffset_t>(bin);
    if (static_cast<uint64_t>(prefix) + sizeof(uoffset_t) != bin_len) {
      return Fail(kErrInvalidBinary,
                  "size prefix " + flatbuffers::NumToString(prefix) +
                      " does not match buffer length " +
                      flatbuffers::NumToString(bin_len) + " - 4");
    }
  }
  // The verifier checks alignment relative to the buffer start, and WASM
  // loads tolerate any address, so the input needs no aligned copy.
  const uint8_t* data = bin;

  const auto* rs = reflection::GetSchema(schema->bfbs.data());
  const auto* root = rs->root_table();
  const bool verified =
      size_prefixed ? flatbuffers::VerifySizePrefixed(*rs, *root, data, bin_len)
                    : flatbuffers::Verify(*rs, *root, data, bin_len);
  if (!verified) {
    return Fail(kErrInvalidBinary,
                "buffer failed verification against root type " +
                    rs->root_table()->name()->str());
  }

  flatbuffers::Parser* parser = ReadyParser(*schema, &status);
  if (!parser) return status;

  if (schema->needs_deep_check) {
    std::string error;
    DeepVerifier deep(*rs, &error);
    const auto* table =
        size_prefixed
            ? flatbuffers::GetSizePrefixedRoot<flatbuffers::Table>(data)
            : flatbuffers::GetRoot<flatbuffers::Table>(data);
    if (!deep.Table(*parser->root_struct_def_, table, 0)) {
      return Fail(kErrInvalidBinary, error);
    }
  }

  parser->opts.size_prefixed = size_prefixed;
  parser->opts.strict_json = true;
  parser->opts.output_default_scalars_in_json =
      (options & kOptForceDefaults) != 0;
  parser->opts.natural_utf8 = (options & kOptNaturalUtf8) != 0;
  parser->opts.indent_step = (options & kOptCompactJson) ? -1 : 2;

  std::string text;
  const char* err = flatbuffers::GenText(*parser, data, &text);
  if (err) return Fail(kErrJsonGeneration, err);
  return CopyOut(reinterpret_cast<const uint8_t*>(text.data()), text.size(),
                 out, out_cap, out_len);
}
