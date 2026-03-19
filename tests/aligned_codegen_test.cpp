#include "aligned_codegen_test.h"

#include <memory>
#include <string>

#include "flatbuffers/code_generator.h"
#include "flatbuffers/idl.h"
#include "idl_gen_aligned.h"
#include "test_assert.h"

namespace flatbuffers {
namespace tests {
namespace {

Parser BuildParser() {
  IDLOptions opts;
  opts.generate_aligned = true;
  Parser parser(opts);
  const char* schema = R"(
    namespace Layout;

    table Child {
      value:uint;
    }

    union Payload {
      Child
    }

    table Root {
      id:uint;
      name:string (aligned_max_length: 12);
      values:[ushort] (aligned_max_count: 4);
      children:[Child] (aligned_max_count: 2);
      payload:Payload;
      payloads:[Payload] (aligned_max_count: 2);
    }

    root_type Root;
  )";
  TEST_EQ(true, parser.Parse(schema));
  return parser;
}

}  // namespace

void AlignedCodegenTest() {
  {
    Parser parser = BuildParser();
    std::unique_ptr<CodeGenerator> generator =
        NewAlignedLanguageCodeGenerator(IDLOptions::kCpp);
    TEST_NOTNULL(generator);
    std::string output;
    TEST_EQ(CodeGenerator::Status::OK,
            generator->GenerateCodeString(parser, "aligned_test", output));
    TEST_ASSERT(output.find("struct Root {") != std::string::npos);
    TEST_ASSERT(output.find("AlignedString<12>") != std::string::npos);
    TEST_ASSERT(output.find("AlignedVector<uint16_t, 4>") !=
                std::string::npos);
  }

  {
    Parser parser = BuildParser();
    std::unique_ptr<CodeGenerator> generator =
        NewAlignedLanguageCodeGenerator(IDLOptions::kTs);
    TEST_NOTNULL(generator);
    std::string output;
    TEST_EQ(CodeGenerator::Status::OK,
            generator->GenerateCodeString(parser, "aligned_test", output));
    TEST_ASSERT(output.find("export class Root {") != std::string::npos);
    TEST_ASSERT(output.find("static readonly SIZE =") != std::string::npos);
    TEST_ASSERT(output.find("__decodeString") != std::string::npos);
  }

  struct LanguageCase {
    IDLOptions::Language language;
    const char* marker_a;
    const char* marker_b;
  };

  const LanguageCase language_cases[] = {
      { IDLOptions::kGo, "type Root struct", "func (r Root) MutateName(value string)" },
      { IDLOptions::kPython, "class Root:", "def MutateName(self, value):" },
      { IDLOptions::kRust, "pub struct Root<'a>", "pub fn mutate_name(&mut self, value: &str)" },
      { IDLOptions::kJava, "final class Root {", "void mutateName(String value)" },
      { IDLOptions::kCSharp, "public sealed class Root {", "public void MutateName(string value)" },
      { IDLOptions::kKotlin, "class Root internal constructor", "fun mutateName(value: String)" },
      { IDLOptions::kKotlinKmp, "class Root internal constructor", "fun mutateName(value: String)" },
      { IDLOptions::kDart, "class Root {", "void mutateName(String value)" },
      { IDLOptions::kSwift, "final class Root {", "func mutateName(_ value: String)" },
      { IDLOptions::kPhp, "final class Root {", "public function mutateName(string $value): void" },
  };

  for (size_t i = 0; i < sizeof(language_cases) / sizeof(language_cases[0]);
       ++i) {
    Parser parser = BuildParser();
    std::unique_ptr<CodeGenerator> generator =
        NewAlignedLanguageCodeGenerator(language_cases[i].language);
    TEST_NOTNULL(generator);
    std::string output;
    TEST_EQ(CodeGenerator::Status::OK,
            generator->GenerateCodeString(parser, "aligned_test", output));
    TEST_ASSERT(output.find(language_cases[i].marker_a) != std::string::npos);
    TEST_ASSERT(output.find(language_cases[i].marker_b) != std::string::npos);
  }

  {
    Parser parser = BuildParser();
    std::unique_ptr<CodeGenerator> generator = NewAlignedCodeGenerator();
    TEST_NOTNULL(generator);
    std::string output;
    TEST_EQ(CodeGenerator::Status::OK,
            generator->GenerateCodeString(parser, "aligned_test", output));
    TEST_ASSERT(output.find("\"cpp\"") != std::string::npos);
    TEST_ASSERT(output.find("\"qualified_name\"") != std::string::npos);
  }
}

}  // namespace tests
}  // namespace flatbuffers
