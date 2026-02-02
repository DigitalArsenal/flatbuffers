// flatc_wasm.cpp - Emscripten bindings for flatc
//
// Provides a WebAssembly API for:
// - Schema management (add, remove, list, export)
// - Two-way conversion (JSON ↔ FlatBuffer binary)
// - Format auto-detection
// - Code generation for multiple languages
// - Streaming input support
//
// Uses direct memory access for streaming and performance.

#include <emscripten.h>
#include <emscripten/bind.h>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "flatbuffers/flatbuffers.h"
#include "flatbuffers/idl.h"
#include "flatbuffers/util.h"
#include "flatbuffers/file_manager.h"
#include "flatbuffers/encryption.h"

// Code generators
#include "idl_gen_fbs.h"
#include "idl_gen_cpp.h"
#include "idl_gen_csharp.h"
#include "idl_gen_dart.h"
#include "idl_gen_go.h"
#include "idl_gen_java.h"
#include "idl_gen_json_schema.h"
#include "idl_gen_kotlin.h"
#include "idl_gen_python.h"
#include "idl_gen_rust.h"
#include "idl_gen_swift.h"
#include "idl_gen_ts.h"
#include "idl_gen_php.h"

// Note: LogCompilerWarn/LogCompilerError and GRPC generators are provided
// by flatc_main.cpp and grpc/src/compiler/*.cc which are linked into WASM.

namespace flatbuffers {
namespace wasm {

// Global error message buffer
static std::string g_last_error;

// Output buffer for conversion results (reused between calls)
static std::vector<uint8_t> g_output_buffer;

// Streaming input buffer
static std::vector<uint8_t> g_stream_buffer;

// Language enum for code generation
enum class Language : int32_t {
  CPP = 0,
  CSHARP = 1,
  DART = 2,
  GO = 3,
  JAVA = 4,
  KOTLIN = 5,
  PYTHON = 6,
  RUST = 7,
  SWIFT = 8,
  TYPESCRIPT = 9,
  PHP = 10,
  JSON_SCHEMA = 11,
  FBS = 12,  // Regenerate .fbs from parsed schema
};

// Create code generator for specified language
static std::unique_ptr<CodeGenerator> CreateGenerator(Language lang) {
  switch (lang) {
    case Language::CPP: return NewCppCodeGenerator();
    case Language::CSHARP: return NewCSharpCodeGenerator();
    case Language::DART: return NewDartCodeGenerator();
    case Language::GO: return NewGoCodeGenerator();
    case Language::JAVA: return NewJavaCodeGenerator();
    case Language::KOTLIN: return NewKotlinCodeGenerator();
    case Language::PYTHON: return NewPythonCodeGenerator();
    case Language::RUST: return NewRustCodeGenerator();
    case Language::SWIFT: return NewSwiftCodeGenerator();
    case Language::TYPESCRIPT: return NewTsCodeGenerator();
    case Language::PHP: return NewPhpCodeGenerator();
    case Language::JSON_SCHEMA: return NewJsonSchemaCodeGenerator();
    case Language::FBS: return NewFBSCodeGenerator(true);
    default: return nullptr;
  }
}

// Get language name for error messages
static const char* GetLanguageName(Language lang) {
  switch (lang) {
    case Language::CPP: return "C++";
    case Language::CSHARP: return "C#";
    case Language::DART: return "Dart";
    case Language::GO: return "Go";
    case Language::JAVA: return "Java";
    case Language::KOTLIN: return "Kotlin";
    case Language::PYTHON: return "Python";
    case Language::RUST: return "Rust";
    case Language::SWIFT: return "Swift";
    case Language::TYPESCRIPT: return "TypeScript";
    case Language::PHP: return "PHP";
    case Language::JSON_SCHEMA: return "JSON Schema";
    case Language::FBS: return "FlatBuffers IDL";
    default: return "Unknown";
  }
}

// Schema registry - stores parsed schemas by ID
struct SchemaEntry {
  std::string name;
  std::string source;          // Original source (.fbs or .schema.json)
  bool is_json_schema;         // True if source was JSON Schema
  std::unique_ptr<Parser> parser;
};

// Memory-based FileSaver for capturing generated code
class MemoryFileSaver : public FileSaver {
 public:
  bool SaveFile(const char* /*name*/, const char* buf, size_t len,
                bool /*binary*/) override {
    // Concatenate all saved files (most generators produce one file)
    output_.append(buf, len);
    return true;
  }

  std::string& output() { return output_; }
  void clear() { output_.clear(); }

 private:
  std::string output_;
};

static std::map<int32_t, SchemaEntry> g_schemas;
static int32_t g_next_schema_id = 1;

// Helper to set error message
static void SetError(const std::string& msg) {
  g_last_error = msg;
}

// Helper to detect if data looks like JSON
static bool LooksLikeJson(const uint8_t* data, uint32_t len) {
  if (len == 0) return false;

  // Skip whitespace
  uint32_t i = 0;
  while (i < len && (data[i] == ' ' || data[i] == '\t' ||
                     data[i] == '\n' || data[i] == '\r')) {
    i++;
  }

  if (i >= len) return false;

  // JSON starts with { or [
  return data[i] == '{' || data[i] == '[';
}

// Helper to detect FlatBuffer by checking for valid root offset
static bool LooksLikeFlatBuffer(const uint8_t* data, uint32_t len) {
  if (len < 8) return false;  // Minimum: 4-byte offset + some data

  // Read root offset (little-endian uint32)
  uint32_t root_offset = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);

  // Root offset should point within the buffer, typically small
  // and should point to a vtable offset which is also reasonable
  return root_offset >= 4 && root_offset < len - 4;
}

}  // namespace wasm
}  // namespace flatbuffers

// ============================================================================
// C-style exports for direct memory access
// These functions are callable from JavaScript via Module._functionName()
// ============================================================================

extern "C" {

// ----------------------------------------------------------------------------
// Utility exports
// ----------------------------------------------------------------------------

EMSCRIPTEN_KEEPALIVE
const char* wasm_get_version() {
  return flatbuffers::FLATBUFFERS_VERSION();
}

EMSCRIPTEN_KEEPALIVE
const char* wasm_get_last_error() {
  return flatbuffers::wasm::g_last_error.c_str();
}

EMSCRIPTEN_KEEPALIVE
void wasm_clear_error() {
  flatbuffers::wasm::g_last_error.clear();
}

// ----------------------------------------------------------------------------
// Memory management exports
// These allow JS to track allocations made on the WASM heap
// ----------------------------------------------------------------------------

EMSCRIPTEN_KEEPALIVE
void* wasm_malloc(uint32_t size) {
  return malloc(size);
}

EMSCRIPTEN_KEEPALIVE
void wasm_free(void* ptr) {
  free(ptr);
}

EMSCRIPTEN_KEEPALIVE
void* wasm_realloc(void* ptr, uint32_t size) {
  return realloc(ptr, size);
}

// ----------------------------------------------------------------------------
// Schema management
// ----------------------------------------------------------------------------

// Add a schema from source (.fbs or .schema.json)
// Returns schema ID on success, -1 on error
EMSCRIPTEN_KEEPALIVE
int32_t wasm_schema_add(const char* name, uint32_t name_len,
                        const uint8_t* source, uint32_t source_len) {
  using namespace flatbuffers;
  using namespace flatbuffers::wasm;

  std::string schema_name(name, name_len);
  std::string schema_source(reinterpret_cast<const char*>(source), source_len);

  // Detect if this is JSON Schema based on content
  bool is_json_schema = false;
  if (source_len > 0 && LooksLikeJson(source, source_len)) {
    // Check for JSON Schema markers
    if (schema_source.find("\"$schema\"") != std::string::npos ||
        schema_source.find("\"definitions\"") != std::string::npos ||
        schema_source.find("\"$defs\"") != std::string::npos ||
        schema_source.find("\"components\"") != std::string::npos) {
      is_json_schema = true;
    }
  }

  // Also check filename extension
  if (schema_name.size() > 12 &&
      schema_name.substr(schema_name.size() - 12) == ".schema.json") {
    is_json_schema = true;
  }

  // Create parser with default options
  IDLOptions opts;
  opts.strict_json = false;  // Allow FlatBuffers relaxed JSON (unquoted keys)
  opts.output_default_scalars_in_json = true;

  auto parser = std::make_unique<Parser>(opts);

  bool parse_ok = false;
  if (is_json_schema) {
    parse_ok = parser->ParseJsonSchema(schema_source.c_str(), schema_name.c_str());
  } else {
    parse_ok = parser->Parse(schema_source.c_str(), nullptr, schema_name.c_str());
  }

  if (!parse_ok) {
    SetError("Schema parse error: " + parser->error_);
    return -1;
  }

  // Check for root type
  if (!parser->root_struct_def_) {
    SetError("Schema has no root type defined");
    return -1;
  }

  int32_t id = g_next_schema_id++;
  g_schemas[id] = SchemaEntry{
    schema_name,
    schema_source,
    is_json_schema,
    std::move(parser)
  };

  return id;
}

// Remove a schema by ID
// Returns 0 on success, -1 if not found
EMSCRIPTEN_KEEPALIVE
int32_t wasm_schema_remove(int32_t schema_id) {
  using namespace flatbuffers::wasm;

  auto it = g_schemas.find(schema_id);
  if (it == g_schemas.end()) {
    SetError("Schema not found");
    return -1;
  }

  g_schemas.erase(it);
  return 0;
}

// List all schema IDs
// Writes up to max_count IDs to out_ids, returns actual count
EMSCRIPTEN_KEEPALIVE
int32_t wasm_schema_list(int32_t* out_ids, uint32_t max_count) {
  using namespace flatbuffers::wasm;

  uint32_t count = 0;
  for (const auto& pair : g_schemas) {
    if (count >= max_count) break;
    out_ids[count++] = pair.first;
  }
  return static_cast<int32_t>(count);
}

// Get schema count
EMSCRIPTEN_KEEPALIVE
int32_t wasm_schema_count() {
  return static_cast<int32_t>(flatbuffers::wasm::g_schemas.size());
}

// Get schema name by ID
// Returns pointer to name string (valid until schema removed)
EMSCRIPTEN_KEEPALIVE
const char* wasm_schema_get_name(int32_t schema_id) {
  using namespace flatbuffers::wasm;

  auto it = g_schemas.find(schema_id);
  if (it == g_schemas.end()) {
    SetError("Schema not found");
    return nullptr;
  }

  return it->second.name.c_str();
}

// Export schema in specified format
// format: 0 = .fbs, 1 = .schema.json (FBJSON)
// Writes result to g_output_buffer, returns pointer and sets length
EMSCRIPTEN_KEEPALIVE
const uint8_t* wasm_schema_export(int32_t schema_id, int32_t format,
                                  uint32_t* out_len) {
  using namespace flatbuffers;
  using namespace flatbuffers::wasm;

  auto it = g_schemas.find(schema_id);
  if (it == g_schemas.end()) {
    SetError("Schema not found");
    *out_len = 0;
    return nullptr;
  }

  const Parser& parser = *it->second.parser;
  std::string output;

  if (format == 0) {
    // Export as .fbs
    auto gen = NewFBSCodeGenerator(true);  // no_log = true
    auto status = gen->GenerateCodeString(parser, it->second.name, output);
    if (status != CodeGenerator::Status::OK) {
      SetError("Failed to generate .fbs output");
      *out_len = 0;
      return nullptr;
    }
  } else if (format == 1) {
    // Export as JSON Schema
    // For now, return the original source if it was JSON Schema
    // TODO: Implement proper JSON Schema generation from parser
    if (it->second.is_json_schema) {
      output = it->second.source;
    } else {
      SetError("JSON Schema export from .fbs not yet implemented in WASM API");
      *out_len = 0;
      return nullptr;
    }
  } else {
    SetError("Unknown export format");
    *out_len = 0;
    return nullptr;
  }

  g_output_buffer.assign(output.begin(), output.end());
  *out_len = static_cast<uint32_t>(g_output_buffer.size());
  return g_output_buffer.data();
}

// ----------------------------------------------------------------------------
// Conversion: JSON → FlatBuffer binary
// ----------------------------------------------------------------------------

EMSCRIPTEN_KEEPALIVE
const uint8_t* wasm_json_to_binary(int32_t schema_id,
                                   const char* json, uint32_t json_len,
                                   uint32_t* out_len) {
  using namespace flatbuffers;
  using namespace flatbuffers::wasm;

  auto it = g_schemas.find(schema_id);
  if (it == g_schemas.end()) {
    SetError("Schema not found");
    *out_len = 0;
    return nullptr;
  }

  // Create a fresh parser with the same schema for JSON parsing
  // (Parser's builder state is modified during JSON parsing)
  IDLOptions opts = it->second.parser->opts;
  Parser json_parser(opts);

  // Re-parse the schema to get a clean parser state
  bool schema_ok;
  if (it->second.is_json_schema) {
    schema_ok = json_parser.ParseJsonSchema(it->second.source.c_str(),
                                            it->second.name.c_str());
  } else {
    schema_ok = json_parser.Parse(it->second.source.c_str(), nullptr,
                                  it->second.name.c_str());
  }

  if (!schema_ok) {
    SetError("Failed to re-parse schema: " + json_parser.error_);
    *out_len = 0;
    return nullptr;
  }

  // Now parse the JSON data
  std::string json_str(json, json_len);
  if (!json_parser.ParseJson(json_str.c_str())) {
    SetError("JSON parse error: " + json_parser.error_);
    *out_len = 0;
    return nullptr;
  }

  // Get the built FlatBuffer
  const uint8_t* buf = json_parser.builder_.GetBufferPointer();
  size_t size = json_parser.builder_.GetSize();

  // Copy to output buffer (builder may be reused)
  g_output_buffer.assign(buf, buf + size);
  *out_len = static_cast<uint32_t>(size);
  return g_output_buffer.data();
}

// ----------------------------------------------------------------------------
// Conversion: FlatBuffer binary → JSON
// ----------------------------------------------------------------------------

EMSCRIPTEN_KEEPALIVE
const char* wasm_binary_to_json(int32_t schema_id,
                                const uint8_t* binary, uint32_t binary_len,
                                uint32_t* out_len) {
  using namespace flatbuffers;
  using namespace flatbuffers::wasm;

  auto it = g_schemas.find(schema_id);
  if (it == g_schemas.end()) {
    SetError("Schema not found");
    *out_len = 0;
    return nullptr;
  }

  Parser& parser = *it->second.parser;

  // Basic sanity check on buffer size
  if (binary_len < 8) {
    SetError("Buffer too small to be a valid FlatBuffer");
    *out_len = 0;
    return nullptr;
  }

  // Temporarily enable strict_json for output (to generate standard JSON)
  bool original_strict_json = parser.opts.strict_json;
  parser.opts.strict_json = true;

  // Generate JSON text
  // Note: GenText will fail gracefully if the buffer is invalid
  std::string json_output;
  const char* err = GenText(parser, binary, &json_output);

  // Restore original setting
  parser.opts.strict_json = original_strict_json;

  if (err) {
    SetError(std::string("JSON generation error: ") + err);
    *out_len = 0;
    return nullptr;
  }

  g_output_buffer.assign(json_output.begin(), json_output.end());
  g_output_buffer.push_back('\0');  // Null terminate for convenience
  *out_len = static_cast<uint32_t>(json_output.size());
  return reinterpret_cast<const char*>(g_output_buffer.data());
}

// ----------------------------------------------------------------------------
// Conversion: Auto-detect format and convert
// Returns: 0 = input was JSON (output is binary)
//          1 = input was binary (output is JSON)
//         -1 = error
// ----------------------------------------------------------------------------

EMSCRIPTEN_KEEPALIVE
int32_t wasm_convert_auto(int32_t schema_id,
                          const uint8_t* data, uint32_t data_len,
                          const uint8_t** out_ptr, uint32_t* out_len) {
  using namespace flatbuffers::wasm;

  if (LooksLikeJson(data, data_len)) {
    // Input is JSON, convert to binary
    const uint8_t* result = wasm_json_to_binary(
        schema_id,
        reinterpret_cast<const char*>(data), data_len,
        out_len);
    if (!result) return -1;
    *out_ptr = result;
    return 0;
  } else if (LooksLikeFlatBuffer(data, data_len)) {
    // Input is binary, convert to JSON
    const char* result = wasm_binary_to_json(
        schema_id,
        data, data_len,
        out_len);
    if (!result) return -1;
    *out_ptr = reinterpret_cast<const uint8_t*>(result);
    return 1;
  } else {
    SetError("Unable to detect input format (not JSON or FlatBuffer)");
    *out_ptr = nullptr;
    *out_len = 0;
    return -1;
  }
}

// ----------------------------------------------------------------------------
// Detect format without conversion
// Returns: 0 = JSON, 1 = FlatBuffer, -1 = unknown
// ----------------------------------------------------------------------------

EMSCRIPTEN_KEEPALIVE
int32_t wasm_detect_format(const uint8_t* data, uint32_t data_len) {
  using namespace flatbuffers::wasm;

  if (LooksLikeJson(data, data_len)) return 0;
  if (LooksLikeFlatBuffer(data, data_len)) return 1;
  return -1;
}

// ----------------------------------------------------------------------------
// Output buffer management
// For zero-copy access to conversion results
// ----------------------------------------------------------------------------

// Get pointer to current output buffer
EMSCRIPTEN_KEEPALIVE
const uint8_t* wasm_get_output_ptr() {
  return flatbuffers::wasm::g_output_buffer.data();
}

// Get size of current output buffer
EMSCRIPTEN_KEEPALIVE
uint32_t wasm_get_output_size() {
  return static_cast<uint32_t>(flatbuffers::wasm::g_output_buffer.size());
}

// Reserve output buffer capacity (optional optimization)
EMSCRIPTEN_KEEPALIVE
void wasm_reserve_output(uint32_t capacity) {
  flatbuffers::wasm::g_output_buffer.reserve(capacity);
}

// Clear output buffer
EMSCRIPTEN_KEEPALIVE
void wasm_clear_output() {
  flatbuffers::wasm::g_output_buffer.clear();
}

// ----------------------------------------------------------------------------
// Streaming input buffer management
// For accumulating large inputs without multiple JS→WASM copies
// ----------------------------------------------------------------------------

// Clear/reset stream buffer
EMSCRIPTEN_KEEPALIVE
void wasm_stream_reset() {
  flatbuffers::wasm::g_stream_buffer.clear();
}

// Get pointer to write position in stream buffer
// Grows buffer if needed, returns pointer for direct write
EMSCRIPTEN_KEEPALIVE
uint8_t* wasm_stream_prepare(uint32_t additional_bytes) {
  using namespace flatbuffers::wasm;
  size_t current_size = g_stream_buffer.size();
  g_stream_buffer.resize(current_size + additional_bytes);
  return g_stream_buffer.data() + current_size;
}

// Confirm bytes written to stream (after wasm_stream_prepare)
// This is a no-op if the correct number of bytes was written
EMSCRIPTEN_KEEPALIVE
void wasm_stream_commit(uint32_t bytes_written) {
  // Buffer was already resized in prepare, this just confirms
  // In case fewer bytes were written, we could shrink, but typically not needed
  (void)bytes_written;
}

// Get current stream size
EMSCRIPTEN_KEEPALIVE
uint32_t wasm_stream_size() {
  return static_cast<uint32_t>(flatbuffers::wasm::g_stream_buffer.size());
}

// Get stream buffer pointer (for reading accumulated data)
EMSCRIPTEN_KEEPALIVE
const uint8_t* wasm_stream_data() {
  return flatbuffers::wasm::g_stream_buffer.data();
}

// Convert streamed data (uses accumulated stream buffer)
// Returns same as wasm_convert_auto but uses stream buffer as input
EMSCRIPTEN_KEEPALIVE
int32_t wasm_stream_convert(int32_t schema_id,
                            const uint8_t** out_ptr, uint32_t* out_len) {
  using namespace flatbuffers::wasm;

  if (g_stream_buffer.empty()) {
    SetError("Stream buffer is empty");
    *out_ptr = nullptr;
    *out_len = 0;
    return -1;
  }

  // Use the convert_auto function with stream buffer
  int32_t result = wasm_convert_auto(
      schema_id,
      g_stream_buffer.data(),
      static_cast<uint32_t>(g_stream_buffer.size()),
      out_ptr, out_len);

  return result;
}

// Parse streamed schema data (for adding schemas via streaming)
EMSCRIPTEN_KEEPALIVE
int32_t wasm_stream_add_schema(const char* name, uint32_t name_len) {
  using namespace flatbuffers::wasm;

  if (g_stream_buffer.empty()) {
    SetError("Stream buffer is empty");
    return -1;
  }

  return wasm_schema_add(
      name, name_len,
      g_stream_buffer.data(),
      static_cast<uint32_t>(g_stream_buffer.size()));
}

// ----------------------------------------------------------------------------
// Code Generation
// ----------------------------------------------------------------------------

// Generate code for specified language
// language: see Language enum (0=C++, 1=C#, etc.)
// Returns pointer to generated code, sets out_len
EMSCRIPTEN_KEEPALIVE
const char* wasm_generate_code(int32_t schema_id, int32_t language,
                               uint32_t* out_len) {
  using namespace flatbuffers;
  using namespace flatbuffers::wasm;

  auto it = g_schemas.find(schema_id);
  if (it == g_schemas.end()) {
    SetError("Schema not found");
    *out_len = 0;
    return nullptr;
  }

  Language lang = static_cast<Language>(language);
  auto generator = CreateGenerator(lang);
  if (!generator) {
    SetError(std::string("Unknown language: ") + std::to_string(language));
    *out_len = 0;
    return nullptr;
  }

  // Create a copy of parser with our memory-based file saver
  // We need to copy options since they're modified by code generation
  Parser& original_parser = *it->second.parser;
  std::string output;

  // First try GenerateCodeString (only implemented by FBS generator)
  auto status = generator->GenerateCodeString(original_parser, it->second.name, output);

  // If not implemented, use GenerateCode with memory file saver
  if (status == CodeGenerator::Status::NOT_IMPLEMENTED) {
    // Set up memory-based file saver
    MemoryFileSaver memory_saver;
    original_parser.opts.file_saver = &memory_saver;

    // Extract filename without extension for generator
    std::string filename = it->second.name;
    auto dot_pos = filename.rfind('.');
    if (dot_pos != std::string::npos) {
      filename = filename.substr(0, dot_pos);
    }

    // Generate to memory
    status = generator->GenerateCode(original_parser, "", filename);

    // Clean up - don't leave dangling pointer
    original_parser.opts.file_saver = nullptr;

    if (status == CodeGenerator::Status::OK) {
      output = std::move(memory_saver.output());
    }
  }

  if (status != CodeGenerator::Status::OK) {
    std::string detail = generator->status_detail;
    if (detail.empty()) {
      SetError(std::string("Code generation failed for ") + GetLanguageName(lang));
    } else {
      SetError(std::string("Code generation failed for ") + GetLanguageName(lang) + ": " + detail);
    }
    *out_len = 0;
    return nullptr;
  }

  g_output_buffer.assign(output.begin(), output.end());
  g_output_buffer.push_back('\0');  // Null terminate
  *out_len = static_cast<uint32_t>(output.size());
  return reinterpret_cast<const char*>(g_output_buffer.data());
}

// Get list of supported languages
// Returns comma-separated list of language names
EMSCRIPTEN_KEEPALIVE
const char* wasm_get_supported_languages() {
  static const char* languages =
      "cpp,csharp,dart,go,java,kotlin,python,rust,swift,typescript,php,jsonschema,fbs";
  return languages;
}

// Get language ID from name
// Returns language ID or -1 if unknown
EMSCRIPTEN_KEEPALIVE
int32_t wasm_get_language_id(const char* name) {
  using namespace flatbuffers::wasm;

  std::string lang(name);
  // Convert to lowercase for comparison
  for (char& c : lang) c = std::tolower(c);

  if (lang == "cpp" || lang == "c++") return static_cast<int32_t>(Language::CPP);
  if (lang == "csharp" || lang == "c#" || lang == "cs") return static_cast<int32_t>(Language::CSHARP);
  if (lang == "dart") return static_cast<int32_t>(Language::DART);
  if (lang == "go" || lang == "golang") return static_cast<int32_t>(Language::GO);
  if (lang == "java") return static_cast<int32_t>(Language::JAVA);
  if (lang == "kotlin" || lang == "kt") return static_cast<int32_t>(Language::KOTLIN);
  if (lang == "python" || lang == "py") return static_cast<int32_t>(Language::PYTHON);
  if (lang == "rust" || lang == "rs") return static_cast<int32_t>(Language::RUST);
  if (lang == "swift") return static_cast<int32_t>(Language::SWIFT);
  if (lang == "typescript" || lang == "ts") return static_cast<int32_t>(Language::TYPESCRIPT);
  if (lang == "php") return static_cast<int32_t>(Language::PHP);
  if (lang == "jsonschema" || lang == "json-schema" || lang == "json_schema")
    return static_cast<int32_t>(Language::JSON_SCHEMA);
  if (lang == "fbs" || lang == "flatbuffers") return static_cast<int32_t>(Language::FBS);

  return -1;
}

// ----------------------------------------------------------------------------
// Encrypted Conversion: JSON → Encrypted FlatBuffer Binary
// ----------------------------------------------------------------------------

// Encryption output: header + encrypted data stored contiguously
static std::vector<uint8_t> g_encryption_header_buf;

EMSCRIPTEN_KEEPALIVE
const uint8_t* wasm_json_to_binary_encrypted(
    int32_t schema_id,
    const char* json, uint32_t json_len,
    const uint8_t* encryption_config, uint32_t config_len,
    uint32_t* out_len, uint32_t* out_header_len) {
  using namespace flatbuffers;
  using namespace flatbuffers::wasm;

  // First, do the normal JSON → binary conversion
  uint32_t binary_len = 0;
  const uint8_t* binary = wasm_json_to_binary(schema_id, json, json_len,
                                               &binary_len);
  if (!binary) {
    *out_len = 0;
    *out_header_len = 0;
    return nullptr;
  }

  // Copy binary data since g_output_buffer will be reused
  std::vector<uint8_t> binary_copy(binary, binary + binary_len);

  // Extract encryption key from config (first 32 bytes)
  if (config_len < kEncryptionKeySize) {
    SetError("Encryption config too small: need at least 32 bytes for key");
    *out_len = 0;
    *out_header_len = 0;
    return nullptr;
  }

  EncryptionContext ctx(encryption_config, kEncryptionKeySize);
  if (!ctx.IsValid()) {
    SetError("Invalid encryption key");
    *out_len = 0;
    *out_header_len = 0;
    return nullptr;
  }

  // Get schema entry for binary schema (.bfbs) generation
  auto it = g_schemas.find(schema_id);
  if (it == g_schemas.end()) {
    SetError("Schema not found");
    *out_len = 0;
    *out_header_len = 0;
    return nullptr;
  }

  // Serialize schema to .bfbs for reflection-based encryption
  Parser& parser = *it->second.parser;
  parser.Serialize();
  const auto& bfbs = parser.builder_.GetBufferPointer();
  const auto bfbs_size = parser.builder_.GetSize();

  // Encrypt the buffer in-place
  auto result = EncryptBuffer(binary_copy.data(), binary_copy.size(),
                               bfbs, bfbs_size, ctx);
  if (!result.ok()) {
    SetError("Encryption failed: " + result.message);
    *out_len = 0;
    *out_header_len = 0;
    return nullptr;
  }

  // Store result in output buffer
  g_output_buffer = std::move(binary_copy);
  *out_header_len = 0;  // Header generation handled at JS layer
  *out_len = static_cast<uint32_t>(g_output_buffer.size());
  return g_output_buffer.data();
}

// ----------------------------------------------------------------------------
// Decrypted Conversion: Encrypted FlatBuffer Binary → JSON
// ----------------------------------------------------------------------------

EMSCRIPTEN_KEEPALIVE
const char* wasm_binary_to_json_decrypted(
    int32_t schema_id,
    const uint8_t* binary, uint32_t binary_len,
    const uint8_t* key, uint32_t key_len,
    uint32_t* out_len) {
  using namespace flatbuffers;
  using namespace flatbuffers::wasm;

  if (key_len < kEncryptionKeySize) {
    SetError("Decryption key too small: need 32 bytes");
    *out_len = 0;
    return nullptr;
  }

  auto it = g_schemas.find(schema_id);
  if (it == g_schemas.end()) {
    SetError("Schema not found");
    *out_len = 0;
    return nullptr;
  }

  // Copy binary so we can decrypt in-place
  std::vector<uint8_t> decrypted(binary, binary + binary_len);

  EncryptionContext ctx(key, kEncryptionKeySize);
  if (!ctx.IsValid()) {
    SetError("Invalid decryption key");
    *out_len = 0;
    return nullptr;
  }

  // Get binary schema
  Parser& parser = *it->second.parser;
  parser.Serialize();
  const auto& bfbs = parser.builder_.GetBufferPointer();
  const auto bfbs_size = parser.builder_.GetSize();

  // Decrypt in-place
  auto result = DecryptBuffer(decrypted.data(), decrypted.size(),
                               bfbs, bfbs_size, ctx);
  if (!result.ok()) {
    SetError("Decryption failed: " + result.message);
    *out_len = 0;
    return nullptr;
  }

  // Now convert decrypted binary to JSON
  return wasm_binary_to_json(schema_id, decrypted.data(),
                              static_cast<uint32_t>(decrypted.size()), out_len);
}

// ----------------------------------------------------------------------------
// Auto-detect Encrypted Conversion
// ----------------------------------------------------------------------------

EMSCRIPTEN_KEEPALIVE
int32_t wasm_convert_auto_encrypted(
    int32_t schema_id,
    const uint8_t* data, uint32_t data_len,
    const uint8_t* encryption_config, uint32_t config_len,
    const uint8_t** out_ptr, uint32_t* out_len) {
  using namespace flatbuffers::wasm;

  if (LooksLikeJson(data, data_len)) {
    // Input is JSON → encrypt to binary
    uint32_t header_len = 0;
    const uint8_t* result = wasm_json_to_binary_encrypted(
        schema_id,
        reinterpret_cast<const char*>(data), data_len,
        encryption_config, config_len,
        out_len, &header_len);
    if (!result) return -1;
    *out_ptr = result;
    return 0;
  } else if (LooksLikeFlatBuffer(data, data_len)) {
    // Input is binary → decrypt to JSON
    const char* result = wasm_binary_to_json_decrypted(
        schema_id,
        data, data_len,
        encryption_config, config_len,
        out_len);
    if (!result) return -1;
    *out_ptr = reinterpret_cast<const uint8_t*>(result);
    return 1;
  } else {
    SetError("Unable to detect input format");
    *out_ptr = nullptr;
    *out_len = 0;
    return -1;
  }
}

// ----------------------------------------------------------------------------
// Streaming Encryption Configuration
// ----------------------------------------------------------------------------

static std::unique_ptr<flatbuffers::EncryptionContext> g_stream_encryption_ctx;

EMSCRIPTEN_KEEPALIVE
int32_t wasm_stream_set_encryption(const uint8_t* config_ptr,
                                    uint32_t config_size) {
  using namespace flatbuffers;
  using namespace flatbuffers::wasm;

  if (!config_ptr || config_size < kEncryptionKeySize) {
    SetError("Encryption config too small");
    return -1;
  }

  g_stream_encryption_ctx = std::make_unique<EncryptionContext>(
      config_ptr, kEncryptionKeySize);

  if (!g_stream_encryption_ctx->IsValid()) {
    g_stream_encryption_ctx.reset();
    SetError("Invalid encryption key");
    return -1;
  }

  return 0;
}

EMSCRIPTEN_KEEPALIVE
void wasm_stream_clear_encryption() {
  g_stream_encryption_ctx.reset();
}

}  // extern "C"

// ============================================================================
// Embind bindings for higher-level object tracking
// These provide a nicer API for managing handles from JavaScript
// ============================================================================

namespace flatbuffers {
namespace wasm {

// Handle class for tracking schema objects
class SchemaHandle {
 public:
  SchemaHandle() : id_(-1) {}
  explicit SchemaHandle(int32_t id) : id_(id) {}

  int32_t id() const { return id_; }
  bool valid() const { return id_ >= 0 && g_schemas.count(id_) > 0; }

  std::string name() const {
    if (!valid()) return "";
    return g_schemas[id_].name;
  }

  void release() {
    if (valid()) {
      g_schemas.erase(id_);
    }
    id_ = -1;
  }

 private:
  int32_t id_;
};

// Factory function for creating schemas
SchemaHandle createSchema(const std::string& name, const std::string& source) {
  int32_t id = wasm_schema_add(
      name.c_str(), static_cast<uint32_t>(name.size()),
      reinterpret_cast<const uint8_t*>(source.c_str()),
      static_cast<uint32_t>(source.size()));
  return SchemaHandle(id);
}

// Get all schema handles
std::vector<SchemaHandle> getAllSchemas() {
  std::vector<SchemaHandle> handles;
  for (const auto& pair : g_schemas) {
    handles.push_back(SchemaHandle(pair.first));
  }
  return handles;
}

// Version info
std::string getVersion() {
  return flatbuffers::FLATBUFFERS_VERSION();
}

std::string getLastError() {
  return g_last_error;
}

}  // namespace wasm
}  // namespace flatbuffers

EMSCRIPTEN_BINDINGS(flatc_wasm) {
  using namespace emscripten;
  using namespace flatbuffers::wasm;

  // Version and error functions
  function("getVersion", &getVersion);
  function("getLastError", &getLastError);

  // Schema handle class for object tracking
  class_<SchemaHandle>("SchemaHandle")
    .constructor<>()
    .function("id", &SchemaHandle::id)
    .function("valid", &SchemaHandle::valid)
    .function("name", &SchemaHandle::name)
    .function("release", &SchemaHandle::release);

  // Factory functions
  function("createSchema", &createSchema);
  function("getAllSchemas", &getAllSchemas);

  // Register vector type for getAllSchemas return
  register_vector<SchemaHandle>("VectorSchemaHandle");
}
