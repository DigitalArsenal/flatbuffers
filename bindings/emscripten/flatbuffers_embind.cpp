#include <dirent.h>
#include <emscripten/bind.h>

#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include "bfbs_gen_lua.h"
#include "bfbs_gen_nim.h"
#include "flatbuffers/base.h"
#include "flatbuffers/code_generator.h"
#include "flatbuffers/flatc.h"
#include "flatbuffers/idl.h"
#include "flatbuffers/util.h"
#include "idl_gen_binary.h"
#include "idl_gen_cpp.h"
#include "idl_gen_csharp.h"
#include "idl_gen_dart.h"
#include "idl_gen_fbs.h"
#include "idl_gen_go.h"
#include "idl_gen_java.h"
#include "idl_gen_json_schema.h"
#include "idl_gen_kotlin.h"
#include "idl_gen_lobster.h"
#include "idl_gen_php.h"
#include "idl_gen_python.h"
#include "idl_gen_rust.h"
#include "idl_gen_swift.h"
#include "idl_gen_text.h"
#include "idl_gen_ts.h"

using namespace emscripten;

static const char *g_program_name = "flatc_embind";

static void Warn(const flatbuffers::FlatCompiler *flatc,
                 const std::string &warn, bool show_exe_name) {
  (void)flatc;
  if (show_exe_name) { printf("%s: ", g_program_name); }
  fprintf(stderr, "\nwarning:\n  %s\n\n", warn.c_str());
}

static void Error(const flatbuffers::FlatCompiler *flatc,
                  const std::string &err, bool usage, bool show_exe_name) {
  if (show_exe_name) { printf("%s: ", g_program_name); }
  if (usage && flatc) {
    fprintf(stderr, "%s\n", flatc->GetShortUsageString(g_program_name).c_str());
  }
  fprintf(stderr, "\nerror:\n  %s\n\n", err.c_str());
  exit(1);
}

flatbuffers::FlatCompiler *initCompiler() {
  flatbuffers::FlatCompiler::InitParams params;
  params.warn_fn = Warn;
  params.error_fn = Error;
  flatbuffers::FlatCompiler *flatc = new flatbuffers::FlatCompiler(params);

  const std::string version(flatbuffers::FLATBUFFERS_VERSION());
  flatc->RegisterCodeGenerator(
      { "b", "binary", "",
        "Generate wire format binaries for any data definitions" },
      flatbuffers::NewBinaryCodeGenerator());
  flatc->RegisterCodeGenerator(
      { "c", "cpp", "", "Generate C++ headers for tables/structs" },
      flatbuffers::NewCppCodeGenerator());
  flatc->RegisterCodeGenerator(
      { "n", "csharp", "", "Generate C# classes for tables/structs" },
      flatbuffers::NewCSharpCodeGenerator());
  flatc->RegisterCodeGenerator(
      { "d", "dart", "", "Generate Dart classes for tables/structs" },
      flatbuffers::NewDartCodeGenerator());
  flatc->RegisterCodeGenerator(
      { "", "proto", "", "Input is a .proto, translate to .fbs" },
      flatbuffers::NewFBSCodeGenerator());
  flatc->RegisterCodeGenerator(
      { "g", "go", "", "Generate Go files for tables/structs" },
      flatbuffers::NewGoCodeGenerator());
  flatc->RegisterCodeGenerator(
      { "j", "java", "", "Generate Java classes for tables/structs" },
      flatbuffers::NewJavaCodeGenerator());
  flatc->RegisterCodeGenerator({ "", "jsonschema", "", "Generate Json schema" },
                               flatbuffers::NewJsonSchemaCodeGenerator());
  flatc->RegisterCodeGenerator(
      { "", "kotlin", "", "Generate Kotlin classes for tables/structs" },
      flatbuffers::NewKotlinCodeGenerator());
  flatc->RegisterCodeGenerator(
      { "", "lobster", "", "Generate Lobster files for tables/structs" },
      flatbuffers::NewLobsterCodeGenerator());
  flatc->RegisterCodeGenerator(
      { "l", "lua", "", "Generate Lua files for tables/structs" },
      flatbuffers::NewLuaBfbsGenerator(version));
  flatc->RegisterCodeGenerator(
      { "", "nim", "", "Generate Nim files for tables/structs" },
      flatbuffers::NewNimBfbsGenerator(version));
  flatc->RegisterCodeGenerator(
      { "p", "python", "", "Generate Python files for tables/structs" },
      flatbuffers::NewPythonCodeGenerator());
  flatc->RegisterCodeGenerator(
      { "", "php", "", "Generate PHP files for tables/structs" },
      flatbuffers::NewPhpCodeGenerator());
  flatc->RegisterCodeGenerator(
      { "r", "rust", "", "Generate Rust files for tables/structs" },
      flatbuffers::NewRustCodeGenerator());
  flatc->RegisterCodeGenerator(
      { "t", "json", "", "Generate text output for any data definitions" },
      flatbuffers::NewTextCodeGenerator());
  flatc->RegisterCodeGenerator(
      { "", "swift", "", "Generate Swift files for tables/structs" },
      flatbuffers::NewSwiftCodeGenerator());
  flatc->RegisterCodeGenerator(
      { "T", "ts", "", "Generate TypeScript code for tables/structs" },
      flatbuffers::NewTsCodeGenerator());

  return flatc;
}

int runFlatC(const std::vector<std::string> &args) {
  std::vector<char *> argv;
  argv.reserve(args.size() + 1);
  for (const auto &arg : args) {
    argv.push_back(const_cast<char *>(arg.c_str()));
  }
  argv.push_back(nullptr);
  int argc = static_cast<int>(args.size());

  flatbuffers::FlatCompiler *flatc = initCompiler();
  const flatbuffers::FlatCOptions &options =
      flatc->ParseFromCommandLineArguments(
          argc, const_cast<const char **>(argv.data()));
  int result = flatc->Compile(options);
  delete flatc;
  return result;
}

std::vector<uint8_t> jsonToFlatBuffer(const std::string &json_str,
                                      const std::string &schema_str) {
  flatbuffers::Parser parser;
  const char *includes[] = { nullptr };
  if (!parser.Parse(schema_str.c_str(), includes, "schema.fbs")) {
    throw std::runtime_error(parser.error_);
  }
  if (!parser.Parse(json_str.c_str(), includes, "data.json")) {
    throw std::runtime_error(parser.error_);
  }
  auto buf = parser.builder_.GetBufferPointer();
  auto size = parser.builder_.GetSize();
  return std::vector<uint8_t>(buf, buf + size);
}

std::string flatBufferToJson(const std::vector<uint8_t> &buffer,
                             const std::string &schema_str) {
  flatbuffers::Parser parser;
  const char *includes[] = { nullptr };
  if (!parser.Parse(schema_str.c_str(), includes, "schema.fbs")) {
    throw std::runtime_error(parser.error_);
  }
  std::string json_out;
  if (!flatbuffers::GenerateText(parser, buffer.data(), &json_out)) {
    throw std::runtime_error("Failed to generate JSON");
  }
  return json_out;
}

void collectFiles(const std::string &dir_path,
                  std::vector<std::string> &out_paths) {
  DIR *dp = opendir(dir_path.c_str());
  if (!dp) return;
  struct dirent *entry;
  while ((entry = readdir(dp))) {
    if (!std::strcmp(entry->d_name, ".") || !std::strcmp(entry->d_name, ".."))
      continue;
    std::string path = dir_path + "/" + entry->d_name;
    if (entry->d_type == DT_DIR) {
      collectFiles(path, out_paths);
    } else if (entry->d_type == DT_REG) {
      out_paths.push_back(path);
    }
  }
  closedir(dp);
}

val generateCodeRaw(const std::string &schema_str,
                    const std::vector<std::string> &cliArgs) {
  const char *schema_file = "schema.fbs";
  flatbuffers::SaveFile(schema_file, schema_str, false);

  std::vector<std::string> args;
  args.push_back("flatc");
  for (auto &arg : cliArgs) args.push_back(arg);
  args.push_back("-o");
  args.push_back("gen");
  args.push_back(schema_file);

  int result = runFlatC(args);
  if (result != 0) {
    throw std::runtime_error("flatc failed with code " +
                             std::to_string(result));
  }

  std::vector<std::string> files;
  collectFiles("gen", files);

  val fileObj = val::object();
  for (auto &path : files) {
    std::string rel = path.substr(strlen("gen/"));
    std::string content;
    if (!flatbuffers::LoadFile(path.c_str(), true, &content)) continue;
    std::vector<uint8_t> data(content.begin(), content.end());
    auto memView = typed_memory_view(data.size(), data.data());
    val array = val(memView);
    fileObj.set(rel, array);
  }

  flatbuffers::SaveFile(schema_file, std::string(), false);
  return fileObj;
}

EMSCRIPTEN_BINDINGS(flatbuffers_module) {
  register_vector<uint8_t>("VectorUInt8");
  function("jsonToFlatBuffer", &jsonToFlatBuffer);
  function("flatBufferToJson", &flatBufferToJson);
  function("generateCodeRaw", &generateCodeRaw);
}
