/*
 * Copyright 2020 Google Inc. All rights reserved.
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

#include "idl_gen_swift.h"

#include <cctype>
#include <unordered_set>

#include "flatbuffers/code_generators.h"
#include "flatbuffers/flatbuffers.h"
#include "flatbuffers/idl.h"
#include "flatbuffers/util.h"
#include "idl_namer.h"

namespace flatbuffers {

namespace swift {

namespace {

static Namer::Config SwiftDefaultConfig() {
  return {/*types=*/Case::kKeep,
          /*constants=*/Case::kLowerCamel,
          /*methods=*/Case::kLowerCamel,
          /*functions=*/Case::kLowerCamel,
          /*fields=*/Case::kLowerCamel,
          /*variables=*/Case::kLowerCamel,
          /*variants=*/Case::kLowerCamel,
          /*enum_variant_seperator=*/".",
          /*escape_keywords=*/Namer::Config::Escape::AfterConvertingCase,
          /*namespaces=*/Case::kKeep,
          /*namespace_seperator=*/"_",
          /*object_prefix=*/"",
          /*object_suffix=*/"T",
          /*keyword_prefix=*/"",
          /*keyword_suffix=*/"_",
          /*keywords_casing=*/Namer::Config::KeywordsCasing::CaseSensitive,
          /*filenames=*/Case::kKeep,
          /*directories=*/Case::kKeep,
          /*output_path=*/"",
          /*filename_suffix=*/"_generated",
          /*filename_extension=*/".swift"};
}

static std::set<std::string> SwiftKeywords() {
  return {
      "associatedtype",
      "class",
      "deinit",
      "enum",
      "extension",
      "fileprivate",
      "func",
      "import",
      "init",
      "inout",
      "internal",
      "let",
      "open",
      "operator",
      "private",
      "protocol",
      "public",
      "rethrows",
      "static",
      "struct",
      "subscript",
      "typealias",
      "var",
      "break",
      "case",
      "continue",
      "default",
      "defer",
      "do",
      "else",
      "fallthrough",
      "for",
      "guard",
      "if",
      "in",
      "repeat",
      "return",
      "switch",
      "where",
      "while",
      "Any",
      "catch",
      "false",
      "is",
      "nil",
      "super",
      "self",
      "Self",
      "throw",
      "throws",
      "true",
      "try",
      "associativity",
      "convenience",
      "dynamic",
      "didSet",
      "final",
      "get",
      "infix",
      "indirect",
      "lazy",
      "left",
      "mutating",
      "none",
      "nonmutating",
      "optional",
      "override",
      "postfix",
      "precedence",
      "prefix",
      "Protocol",
      "required",
      "right",
      "set",
      "Type",
      "unowned",
      "weak",
      "willSet",
      "Void",
  };
}

static std::string GenIndirect(const std::string& reading) {
  return "{{ACCESS}}.indirect(" + reading + ")";
}

}  // namespace

class SwiftGenerator : public BaseGenerator {
 private:
  CodeWriter code_;
  std::unordered_set<std::string> keywords_;
  int namespace_depth;

 public:
  SwiftGenerator(const Parser& parser, const std::string& path,
                 const std::string& file_name)
      : BaseGenerator(parser, path, file_name, "", "_", "swift"),
        namer_(WithFlagOptions(SwiftDefaultConfig(), parser.opts, path),
               SwiftKeywords()) {
    namespace_depth = 0;
    code_.SetPadding("  ");
  }

  // Check if a struct has any encrypted fields
  bool HasEncryptedFields(const StructDef& struct_def) const {
    for (auto it = struct_def.fields.vec.begin();
         it != struct_def.fields.vec.end(); ++it) {
      if ((*it)->attributes.Lookup("encrypted") != nullptr) {
        return true;
      }
    }
    return false;
  }

  // Generate the FlatbuffersEncryption class with pure Swift AES-256-CTR
  void GenerateEncryptionClass() {
    code_ += "// MARK: - FlatbuffersEncryption\n";
    code_ += "/// FlatBuffers field-level encryption support using AES-256-CTR.";
    code_ += "/// Pure Swift implementation - no external dependencies.";
    code_ += "public class FlatbuffersEncryption {";
    Indent();
    code_ += "";
    // AES S-box
    code_ += "private static let sbox: [UInt8] = [";
    code_ += "  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,";
    code_ += "  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,";
    code_ += "  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,";
    code_ += "  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,";
    code_ += "  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,";
    code_ += "  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,";
    code_ += "  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,";
    code_ += "  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,";
    code_ += "  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,";
    code_ += "  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,";
    code_ += "  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,";
    code_ += "  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,";
    code_ += "  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,";
    code_ += "  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,";
    code_ += "  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,";
    code_ += "  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16";
    code_ += "]";
    code_ += "private static let rcon: [UInt8] = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]";
    code_ += "";
    code_ += "private static func xtime(_ x: UInt8) -> UInt8 { ((x << 1) ^ ((x & 0x80) != 0 ? 0x1b : 0)) }";
    code_ += "";
    code_ += "private static func expandKey(_ key: [UInt8]) -> [UInt8] {";
    Indent();
    code_ += "var expanded = [UInt8](repeating: 0, count: 240)";
    code_ += "for i in 0..<32 { expanded[i] = key[i] }";
    code_ += "var rconIdx = 0";
    code_ += "var i = 32";
    code_ += "while i < 240 {";
    Indent();
    code_ += "var t = [expanded[i-4], expanded[i-3], expanded[i-2], expanded[i-1]]";
    code_ += "if i % 32 == 0 {";
    Indent();
    code_ += "t = [sbox[Int(t[1])] ^ rcon[rconIdx], sbox[Int(t[2])], sbox[Int(t[3])], sbox[Int(t[0])]]";
    code_ += "rconIdx += 1";
    Outdent();
    code_ += "} else if i % 32 == 16 {";
    Indent();
    code_ += "t = [sbox[Int(t[0])], sbox[Int(t[1])], sbox[Int(t[2])], sbox[Int(t[3])]]";
    Outdent();
    code_ += "}";
    code_ += "for j in 0..<4 { expanded[i + j] = expanded[i - 32 + j] ^ t[j] }";
    code_ += "i += 4";
    Outdent();
    code_ += "}";
    code_ += "return expanded";
    Outdent();
    code_ += "}";
    code_ += "";
    code_ += "private static func aesEncryptBlock(_ block: [UInt8], _ expandedKey: [UInt8]) -> [UInt8] {";
    Indent();
    code_ += "var state = block";
    code_ += "for i in 0..<16 { state[i] ^= expandedKey[i] }";
    code_ += "for round in 1...14 {";
    Indent();
    code_ += "for i in 0..<16 { state[i] = sbox[Int(state[i])] }";
    code_ += "let t1 = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t1";
    code_ += "let t2 = state[2]; state[2] = state[10]; state[10] = t2";
    code_ += "let t6 = state[6]; state[6] = state[14]; state[14] = t6";
    code_ += "let t3 = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t3";
    code_ += "if round < 14 {";
    Indent();
    code_ += "for c in 0..<4 {";
    Indent();
    code_ += "let idx = c * 4";
    code_ += "let (s0, s1, s2, s3) = (state[idx], state[idx+1], state[idx+2], state[idx+3])";
    code_ += "let x = s0 ^ s1 ^ s2 ^ s3";
    code_ += "state[idx] ^= x ^ xtime(s0 ^ s1)";
    code_ += "state[idx+1] ^= x ^ xtime(s1 ^ s2)";
    code_ += "state[idx+2] ^= x ^ xtime(s2 ^ s3)";
    code_ += "state[idx+3] ^= x ^ xtime(s3 ^ s0)";
    Outdent();
    code_ += "}";
    Outdent();
    code_ += "}";
    code_ += "let offset = round * 16";
    code_ += "for i in 0..<16 { state[i] ^= expandedKey[offset + i] }";
    Outdent();
    code_ += "}";
    code_ += "return state";
    Outdent();
    code_ += "}";
    code_ += "";
    code_ += "private static func incrementCounter(_ counter: inout [UInt8]) {";
    Indent();
    code_ += "for i in stride(from: 15, through: 0, by: -1) {";
    Indent();
    code_ += "counter[i] = counter[i] &+ 1";
    code_ += "if counter[i] != 0 { break }";
    Outdent();
    code_ += "}";
    Outdent();
    code_ += "}";
    code_ += "";
    code_ += "private static func deriveNonce(_ ctx: [UInt8], fieldId: Int) -> [UInt8] {";
    Indent();
    code_ += "var nonce = [UInt8](repeating: 0, count: 16)";
    code_ += "for i in 0..<12 { nonce[i] = ctx[i] }";
    code_ += "let fieldOffset = UInt32(fieldId)";
    code_ += "nonce[12] = UInt8(fieldOffset & 0xFF)";
    code_ += "nonce[13] = UInt8((fieldOffset >> 8) & 0xFF)";
    code_ += "nonce[14] = UInt8((fieldOffset >> 16) & 0xFF)";
    code_ += "nonce[15] = UInt8((fieldOffset >> 24) & 0xFF)";
    code_ += "return nonce";
    Outdent();
    code_ += "}";
    code_ += "";
    code_ += "private static func decryptBytes(_ data: [UInt8], ctx: [UInt8], fieldId: Int) -> [UInt8] {";
    Indent();
    code_ += "guard ctx.count >= 32 else { return data }";
    code_ += "let key = Array(ctx[0..<32])";
    code_ += "var counter = deriveNonce(ctx, fieldId: fieldId)";
    code_ += "let expandedKey = expandKey(key)";
    code_ += "var result = [UInt8](repeating: 0, count: data.count)";
    code_ += "var i = 0";
    code_ += "while i < data.count {";
    Indent();
    code_ += "let keystream = aesEncryptBlock(counter, expandedKey)";
    code_ += "let blockLen = min(16, data.count - i)";
    code_ += "for j in 0..<blockLen { result[i + j] = data[i + j] ^ keystream[j] }";
    code_ += "incrementCounter(&counter)";
    code_ += "i += 16";
    Outdent();
    code_ += "}";
    code_ += "return result";
    Outdent();
    code_ += "}";
    code_ += "";
    code_ += "public static func decryptScalar<T: FixedWidthInteger>(_ value: T, encryptionCtx: [UInt8]?, fieldId: Int) -> T {";
    Indent();
    code_ += "guard let ctx = encryptionCtx, ctx.count >= 32 else { return value }";
    code_ += "let bytes = withUnsafeBytes(of: value.littleEndian) { Array($0) }";
    code_ += "let decrypted = decryptBytes(bytes, ctx: ctx, fieldId: fieldId)";
    code_ += "return decrypted.withUnsafeBytes { $0.load(as: T.self) }.littleEndian";
    Outdent();
    code_ += "}";
    code_ += "";
    code_ += "public static func decryptScalar(_ value: Float, encryptionCtx: [UInt8]?, fieldId: Int) -> Float {";
    Indent();
    code_ += "guard let ctx = encryptionCtx, ctx.count >= 32 else { return value }";
    code_ += "let bits = value.bitPattern";
    code_ += "let bytes = withUnsafeBytes(of: bits.littleEndian) { Array($0) }";
    code_ += "let decrypted = decryptBytes(bytes, ctx: ctx, fieldId: fieldId)";
    code_ += "let decryptedBits = decrypted.withUnsafeBytes { $0.load(as: UInt32.self) }.littleEndian";
    code_ += "return Float(bitPattern: decryptedBits)";
    Outdent();
    code_ += "}";
    code_ += "";
    code_ += "public static func decryptScalar(_ value: Double, encryptionCtx: [UInt8]?, fieldId: Int) -> Double {";
    Indent();
    code_ += "guard let ctx = encryptionCtx, ctx.count >= 32 else { return value }";
    code_ += "let bits = value.bitPattern";
    code_ += "let bytes = withUnsafeBytes(of: bits.littleEndian) { Array($0) }";
    code_ += "let decrypted = decryptBytes(bytes, ctx: ctx, fieldId: fieldId)";
    code_ += "let decryptedBits = decrypted.withUnsafeBytes { $0.load(as: UInt64.self) }.littleEndian";
    code_ += "return Double(bitPattern: decryptedBits)";
    Outdent();
    code_ += "}";
    code_ += "";
    code_ += "public static func decryptString(_ value: String?, encryptionCtx: [UInt8]?, fieldId: Int) -> String? {";
    Indent();
    code_ += "guard let str = value, let ctx = encryptionCtx, ctx.count >= 32 else { return value }";
    code_ += "let bytes = Array(str.utf8)";
    code_ += "let decrypted = decryptBytes(bytes, ctx: ctx, fieldId: fieldId)";
    code_ += "return String(bytes: decrypted, encoding: .utf8)";
    Outdent();
    code_ += "}";
    Outdent();
    code_ += "}";
    code_ += "";
  }

  bool generate() {
    code_.Clear();
    code_.SetValue("ACCESS", "_accessor");
    code_.SetValue("TABLEOFFSET", "VT");
    code_ += "// " + std::string(FlatBuffersGeneratedWarning());
    code_ += "// swiftlint:disable all";
    code_ += "// swiftformat:disable all\n";

    if (parser_.opts.include_dependence_headers || parser_.opts.generate_all) {
      code_.SetValue("IMPLEMENTONLY", parser_.opts.swift_implementation_only
                                          ? "@_implementationOnly "
                                          : "");
      code_ += "#if canImport(Common)";
      code_ += "{{IMPLEMENTONLY}}import Common";
      code_ += "#endif";
      code_ += "";
      code_ += "{{IMPLEMENTONLY}}import FlatBuffers\n";
    }

    if (parser_.advanced_features_ == reflection::AdvancedArrayFeatures) {
      code_ += "#if compiler(>=6.2)";
    }

    GenerateCode();

    if (parser_.advanced_features_ == reflection::AdvancedArrayFeatures) {
      code_ += "#endif";
    }

    const auto filename = GeneratedFileName(path_, file_name_, parser_.opts);
    const auto final_code = code_.ToString();
    return parser_.opts.file_saver->SaveFile(filename.c_str(), final_code,
                                             false);
  }

  void GenerateCode() {
    // Generate code for all the enum declarations.
    for (auto it = parser_.enums_.vec.begin(); it != parser_.enums_.vec.end();
         ++it) {
      const auto& enum_def = **it;
      if (!enum_def.generated) {
        GenEnum(enum_def);
      }
    }

    for (auto it = parser_.structs_.vec.begin();
         it != parser_.structs_.vec.end(); ++it) {
      const auto& struct_def = **it;
      if (struct_def.fixed && !struct_def.generated) {
        GenStructReader(struct_def);
        GenMutableStructReader(struct_def);
      }
    }

    for (auto it = parser_.structs_.vec.begin();
         it != parser_.structs_.vec.end(); ++it) {
      const auto& struct_def = **it;
      if (!struct_def.fixed && !struct_def.generated) {
        GenTable(struct_def);
        if (parser_.opts.generate_object_based_api) {
          GenObjectAPI(struct_def);
        }
      }
    }

    // Generate encryption class if any struct has encrypted fields
    bool needs_encryption = false;
    for (auto it = parser_.structs_.vec.begin();
         it != parser_.structs_.vec.end(); ++it) {
      if (HasEncryptedFields(**it)) {
        needs_encryption = true;
        break;
      }
    }
    if (needs_encryption) {
      GenerateEncryptionClass();
    }
  }

  void mark(const std::string& str) {
    code_.SetValue("MARKVALUE", str);
    code_ += "\n// MARK: - {{MARKVALUE}}\n";
  }

  // MARK: - Generating structs

  // Generates the reader for swift
  void GenStructReader(const StructDef& struct_def) {
    const bool is_private_access =
        parser_.opts.swift_implementation_only ||
        struct_def.attributes.Lookup("private") != nullptr;
    code_.SetValue("ACCESS_TYPE", is_private_access ? "internal" : "public");
    GenComment(struct_def.doc_comment);
    code_.SetValue("STRUCTNAME", namer_.NamespacedType(struct_def));
    GenOSVersionChecks();
    code_ +=
        "{{ACCESS_TYPE}} struct {{STRUCTNAME}}: NativeStruct, "
        "FlatbuffersVectorInitializable, Verifiable, "
        "FlatbuffersInitializable\\";
    if (parser_.opts.generate_object_based_api) code_ += ", NativeObject\\";
    code_ += " {";
    code_ += "";
    Indent();
    code_ += ValidateFunc();
    code_ += "";
    int padding_id = 0;
    std::string constructor = "";
    std::vector<std::string> base_constructor;
    std::vector<std::string> main_constructor;

    for (auto it = struct_def.fields.vec.begin();
         it != struct_def.fields.vec.end(); ++it) {
      const auto& field = **it;
      if (field.deprecated) continue;

      if (!constructor.empty()) constructor += ", ";

      const auto field_var = namer_.Variable(field);
      code_.SetValue("FIELDVAR", field_var);
      const auto type = GenType(field.value.type);
      if (IsEnum(field.value.type)) {
        code_.SetValue("BASEVALUE", GenTypeBasic(field.value.type, false));
      }
      code_.SetValue("VALUETYPE", type);
      GenComment(field.doc_comment);

      if (IsArray(field.value.type)) {
        std::string valueType = IsEnum(field.value.type.VectorType())
                                    ? "{{BASEVALUE}}"
                                    : "{{VALUETYPE}}";
        const auto fixed_length =
            NumToString(field.value.type.VectorType().fixed_length);
        code_.SetValue("FIXEDLENGTH", fixed_length);

        const auto vector_base_type = IsStruct(field.value.type.VectorType())
                                          ? (type + "()")
                                          : SwiftConstant(field);
        code_ += "private var _{{FIELDVAR}}: InlineArray<{{FIXEDLENGTH}}, " +
                 valueType + ">";

        main_constructor.push_back("_" + field_var + " = " + field_var);
        base_constructor.push_back(
            "_" + field_var + " = InlineArray(repeating: " + vector_base_type +
            ")");

        if (field.padding) {
          GenPadding(field, &padding_id);
        }
        constructor += field_var + ": " + "InlineArray<" + fixed_length + ", ";
        if (IsEnum(field.value.type.VectorType())) {
          constructor +=
              GenTypeBasic(field.value.type.VectorType(), false) + ">";
        } else {
          constructor += type + ">";
        }
      } else {
        const auto accessing_value = IsEnum(field.value.type) ? ".value" : "";
        const auto base_value =
            IsStruct(field.value.type) ? (type + "()") : SwiftConstant(field);

        std::string valueType =
            IsEnum(field.value.type) ? "{{BASEVALUE}}" : "{{VALUETYPE}}";
        code_ += "private var _{{FIELDVAR}}: " + valueType;

        main_constructor.push_back("_" + field_var + " = " + field_var +
                                   accessing_value);
        base_constructor.push_back("_" + field_var + " = " + base_value);

        if (field.padding) {
          GenPadding(field, &padding_id);
        }
        constructor += field_var + ": " + type;
      }
    }
    code_ += "";
    code_ += "{{ACCESS_TYPE}} init(_ bb: ByteBuffer, o: Int32) {";
    Indent();
    code_ += "self = bb.read(def: Self.self, position: Int(o))";
    Outdent();
    code_ += "}\n";

    BuildObjectConstructor(main_constructor, constructor);
    BuildObjectConstructor(base_constructor, "");

    if (parser_.opts.generate_object_based_api)
      GenerateObjectAPIStructConstructor(struct_def);

    for (auto it = struct_def.fields.vec.begin();
         it != struct_def.fields.vec.end(); ++it) {
      const auto& field = **it;
      if (field.deprecated) continue;
      code_.SetValue("FIELDVAR", namer_.Variable(field));
      code_.SetValue("VALUETYPE", GenType(field.value.type));
      GenComment(field.doc_comment);
      if (IsArray(field.value.type)) {
        const auto fixed_length =
            NumToString(field.value.type.VectorType().fixed_length);
        code_.SetValue("FIXEDLENGTH", fixed_length);
        if (IsEnum(field.value.type.VectorType())) {
          code_ +=
              "{{ACCESS_TYPE}} var {{FIELDVAR}}: InlineArray<{{FIXEDLENGTH}}, "
              "{{VALUETYPE}}> { InlineArray { {{VALUETYPE}}(rawValue: "
              "_{{FIELDVAR}}[$0])! } }";
        } else {
          code_ +=
              "{{ACCESS_TYPE}} var {{FIELDVAR}}: InlineArray<{{FIXEDLENGTH}}, "
              "{{VALUETYPE}}> { _{{FIELDVAR}} }";
        }
      } else if (!IsEnum(field.value.type)) {
        code_ += GenReaderMainBody() + "_{{FIELDVAR}} }";
      } else if (IsEnum(field.value.type)) {
        code_ +=
            GenReaderMainBody() + "{{VALUETYPE}}(rawValue: _{{FIELDVAR}})! }";
      }
    }
    code_ += "";
    code_ +=
        "{{ACCESS_TYPE}} static func verify<T>(_ verifier: inout Verifier, at "
        "position: "
        "Int, of type: T.Type) throws where T: Verifiable {";
    Indent();
    code_ +=
        "try verifier.inBuffer(position: position, of: {{STRUCTNAME}}.self)";
    Outdent();
    code_ += "}";
    Outdent();
    code_ += "}\n";
    if (parser_.opts.gen_json_coders) GenerateJSONEncodingAPIs(struct_def);
  }

  void GenMutableStructReader(const StructDef& struct_def) {
    GenObjectHeader(struct_def);

    for (auto it = struct_def.fields.vec.begin();
         it != struct_def.fields.vec.end(); ++it) {
      const auto& field = **it;
      if (field.deprecated) continue;
      const auto offset = NumToString(field.value.offset);
      const auto type = GenType(field.value.type);
      code_.SetValue("FIELDVAR", namer_.Variable(field));
      if (IsEnum(field.value.type)) {
        code_.SetValue("BASEVALUE", GenTypeBasic(field.value.type, false));
      }
      code_.SetValue("VALUETYPE", type);
      code_.SetValue("OFFSET", offset);

      if (IsArray(field.value.type)) {
        code_.SetValue("OFFSET_VALUE", NumToString(field.value.offset));
        code_.SetValue("SIZE",
                       NumToString(InlineSize(field.value.type.VectorType())));
        code_.SetValue("MUTABLE", IsStruct(field.value.type.VectorType())
                                      ? Mutable()
                                      : "");
        const auto fixed_length =
            NumToString(field.value.type.VectorType().fixed_length);
        code_.SetValue("FIXEDLENGTH", fixed_length);

        code_ +=
            "{{ACCESS_TYPE}} var {{FIELDVAR}}: "
            "FlatbufferVector<{{VALUETYPE}}{{MUTABLE}}> "
            "{ return {{ACCESS}}.vector(at: {{OFFSET_VALUE}}, count: "
            "{{FIXEDLENGTH}}, size: {{SIZE}}) "
            "}";
      } else if (IsScalar(field.value.type.base_type) &&
                 !IsEnum(field.value.type)) {
        code_ +=
            GenReaderMainBody() + "return " + GenReader("VALUETYPE") + " }";
      } else if (IsEnum(field.value.type)) {
        code_.SetValue("BASEVALUE", GenTypeBasic(field.value.type, false));
        code_ += GenReaderMainBody() + "return " +
                 GenEnumConstructor("{{OFFSET}}") + "?? " +
                 GenEnumDefaultValue(field) + " }";
      } else if (IsStruct(field.value.type)) {
        code_.SetValue("VALUETYPE", GenType(field.value.type) + Mutable());
        code_ += GenReaderMainBody() + "return " +
                 GenConstructor("{{ACCESS}}.position + {{OFFSET}}");
      } else if (IsVector(field.value.type.base_type)) {
        code_.SetValue("VALUETYPE", GenType(field.value.type) + Mutable());
        code_ += GenReaderMainBody() + "return " +
                 GenConstructor("{{ACCESS}}.position + {{OFFSET}}");
      }

      if (parser_.opts.mutable_buffer) {
        if (!IsStruct(field.value.type) && !IsArray(field.value.type)) {
          code_ += GenMutate("{{OFFSET}}", "", IsEnum(field.value.type));
        } else if (IsArray(field.value.type) &&
                   !IsStruct(field.value.type.VectorType())) {
          code_.SetValue("IS_RAW", IsEnum(field.value.type.VectorType())
                                       ? ".rawValue"
                                       : "");
          code_ +=
              "@discardableResult {{ACCESS_TYPE}} func mutate({{FIELDVAR}}: "
              "{{VALUETYPE}}, at index: Int32) -> Bool { "
              "return {{ACCESS}}.mutate({{FIELDVAR}}{{IS_RAW}}, index: "
              "{{OFFSET_VALUE}} + (index * {{SIZE}})) }";
        }
      }
    }

    if (parser_.opts.generate_object_based_api) {
      GenerateObjectAPIExtensionHeader(namer_.NamespacedType(struct_def),
                                       struct_def.fixed);
      code_ += "return builder.create(struct: obj)";
      Outdent();
      code_ += "}";
    }
    Outdent();
    code_ += "}\n";
  }

  void GenerateStructArgs(const StructDef& struct_def, std::string* code_ptr,
                          const std::string& nameprefix,
                          const std::string& object_name,
                          const std::string& obj_api_named = "",
                          bool is_obj_api = false) {
    auto& code = *code_ptr;
    for (auto it = struct_def.fields.vec.begin();
         it != struct_def.fields.vec.end(); ++it) {
      const auto& field = **it;
      if (field.deprecated) continue;
      const auto& field_type = field.value.type;
      if (IsStruct(field.value.type)) {
        GenerateStructArgs(
            *field_type.struct_def, code_ptr, (nameprefix + field.name),
            (object_name + "." + field.name), obj_api_named, is_obj_api);
      } else {
        const auto field_var = namer_.Variable(field);
        const auto field_field = namer_.Field(field);
        const auto type = GenType(field.value.type);
        if (!is_obj_api) {
          code += nameprefix + field_var + ": " + type;
          if (!IsEnum(field.value.type)) {
            code += " = ";
            code += SwiftConstant(field);
          }
          code += ", ";
          continue;
        }
        code += nameprefix + field_var + ": " + obj_api_named + object_name +
                "." + field_field;
        code += ", ";
      }
    }
  }

  // MARK: - Table Generator

  // Generates the reader for swift
  void GenTable(const StructDef& struct_def) {
    const bool is_private_access =
        parser_.opts.swift_implementation_only ||
        struct_def.attributes.Lookup("private") != nullptr;
    code_.SetValue("ACCESS_TYPE", is_private_access ? "internal" : "public");
    GenObjectHeader(struct_def);
    GenTableAccessors(struct_def);
    GenTableReader(struct_def);
    GenTableWriter(struct_def);
    if (parser_.opts.generate_object_based_api)
      GenerateObjectAPITableExtension(struct_def);
    code_ += "";
    GenerateVerifier(struct_def);
    Outdent();
    code_ += "}\n";
    if (parser_.opts.gen_json_coders) GenerateJSONEncodingAPIs(struct_def);
  }

  // Generates the reader for swift
  void GenTableAccessors(const StructDef& struct_def) {
    // Generate field id constants.
    if (struct_def.fields.vec.size() > 0) {
      code_ += "private struct {{TABLEOFFSET}} {";
      Indent();
      for (auto it = struct_def.fields.vec.begin();
           it != struct_def.fields.vec.end(); ++it) {
        const auto& field = **it;
        if (field.deprecated) {
          continue;
        }
        code_.SetValue("OFFSET_NAME", namer_.Variable(field));
        code_.SetValue("OFFSET_VALUE", NumToString(field.value.offset));
        code_ += "static let {{OFFSET_NAME}}: VOffset = {{OFFSET_VALUE}}";
      }
      Outdent();
      code_ += "}";
      code_ += "";
    }
  }

  void GenObjectHeader(const StructDef& struct_def) {
    GenComment(struct_def.doc_comment);

    code_.SetValue("SHORT_STRUCTNAME", namer_.Type(struct_def));
    code_.SetValue("STRUCTNAME", namer_.NamespacedType(struct_def));
    code_.SetValue("OBJECTTYPE", struct_def.fixed ? "Struct" : "Table");
    code_.SetValue("MUTABLE", struct_def.fixed ? Mutable() : "");

    bool has_encrypted = HasEncryptedFields(struct_def);

    GenOSVersionChecks();
    code_ +=
        "{{ACCESS_TYPE}} struct {{STRUCTNAME}}{{MUTABLE}}: "
        "FlatBuffer{{OBJECTTYPE}}, FlatbuffersVectorInitializable\\";
    if (!struct_def.fixed) code_ += ", Verifiable\\";
    if (!struct_def.fixed && parser_.opts.generate_object_based_api)
      code_ += ", ObjectAPIPacker\\";
    code_ += " {\n";
    Indent();
    code_ += ValidateFunc();
    code_ +=
        "{{ACCESS_TYPE}} var __buffer: ByteBuffer! { return {{ACCESS}}.bb }";
    code_ += "private var {{ACCESS}}: {{OBJECTTYPE}}\n";
    if (has_encrypted) {
      code_ += "/// Encryption context for decrypting encrypted fields";
      code_ += "{{ACCESS_TYPE}} var encryptionCtx: [UInt8]?\n";
    }
    if (!struct_def.fixed) {
      if (parser_.file_identifier_.length()) {
        code_.SetValue("FILENAME", parser_.file_identifier_);
        code_ += "{{ACCESS_TYPE}} static var id: String { \"{{FILENAME}}\" } ";
        code_ +=
            "{{ACCESS_TYPE}} static func finish(_ fbb: inout "
            "FlatBufferBuilder, end: "
            "Offset, prefix: Bool = false) { fbb.finish(offset: end, "
            "fileId: "
            "{{STRUCTNAME}}.id, addPrefix: prefix) }";
      }
      if (has_encrypted) {
        code_ += "private init(_ t: Table, encryptionCtx: [UInt8]? = nil) { {{ACCESS}} = t; self.encryptionCtx = encryptionCtx }";
      } else {
        code_ += "private init(_ t: Table) { {{ACCESS}} = t }";
      }
    }
    if (has_encrypted) {
      code_ +=
          "{{ACCESS_TYPE}} init(_ bb: ByteBuffer, o: Int32, encryptionCtx: [UInt8]? = nil) { {{ACCESS}} = "
          "{{OBJECTTYPE}}(bb: "
          "bb, position: o); self.encryptionCtx = encryptionCtx }";
    } else {
      code_ +=
          "{{ACCESS_TYPE}} init(_ bb: ByteBuffer, o: Int32) { {{ACCESS}} = "
          "{{OBJECTTYPE}}(bb: "
          "bb, position: o) }";
    }
    code_ += "";
  }

  void GenTableWriter(const StructDef& struct_def) {
    flatbuffers::FieldDef* key_field = nullptr;
    std::vector<std::string> require_fields;
    std::vector<std::string> create_func_body;
    std::vector<std::string> create_func_header;
    const auto should_generate_create = struct_def.fields.vec.size() != 0;

    code_.SetValue("NUMBEROFFIELDS", NumToString(struct_def.fields.vec.size()));
    code_ +=
        "{{ACCESS_TYPE}} static func start{{SHORT_STRUCTNAME}}(_ fbb: inout "
        "FlatBufferBuilder) -> "
        "UOffset { fbb.startTable(with: {{NUMBEROFFIELDS}}) }";

    for (auto it = struct_def.fields.vec.begin();
         it != struct_def.fields.vec.end(); ++it) {
      auto& field = **it;
      if (field.deprecated) continue;
      if (field.key) key_field = &field;
      if (field.IsRequired())
        require_fields.push_back(NumToString(field.value.offset));

      GenTableWriterFields(field, &create_func_body, &create_func_header);
    }
    code_ +=
        "{{ACCESS_TYPE}} static func end{{SHORT_STRUCTNAME}}(_ fbb: inout "
        "FlatBufferBuilder, "
        "start: "
        "UOffset) -> Offset { let end = Offset(offset: "
        "fbb.endTable(at: start))\\";
    if (require_fields.capacity() != 0) {
      std::string fields = "";
      for (auto it = require_fields.begin(); it != require_fields.end(); ++it)
        fields += *it + ", ";
      code_.SetValue("FIELDS", fields.substr(0, fields.size() - 2));
      code_ += "; fbb.require(table: end, fields: [{{FIELDS}}])\\";
    }
    code_ += "; return end }";

    if (should_generate_create) {
      code_ += "{{ACCESS_TYPE}} static func create{{SHORT_STRUCTNAME}}(";
      Indent();
      code_ += "_ fbb: inout FlatBufferBuilder\\";
      if (create_func_header.empty() == false) code_ += ",";
      for (auto it = create_func_header.begin(); it < create_func_header.end();
           ++it) {
        code_ += *it + "\\";
        if (it < create_func_header.end() - 1) code_ += ",";
      }
      code_ += "";
      Outdent();
      code_ += ") -> Offset {";
      Indent();
      code_ += "let __start = {{STRUCTNAME}}.start{{SHORT_STRUCTNAME}}(&fbb)";
      for (auto it = create_func_body.begin(); it < create_func_body.end();
           ++it) {
        code_ += *it;
      }
      code_ +=
          "return {{STRUCTNAME}}.end{{SHORT_STRUCTNAME}}(&fbb, start: __start)";
      Outdent();
      code_ += "}";
    }

    std::string spacing = "";

    if (key_field != nullptr && !struct_def.fixed && struct_def.has_key) {
      code_.SetValue("VOFFSET", NumToString(key_field->value.offset));

      code_ += "{{ACCESS_TYPE}} static func " +
               namer_.Method("sort_vector_of", struct_def) +
               "(offsets:[Offset], "
               "_ fbb: inout FlatBufferBuilder) -> Offset {";
      Indent();
      code_ += spacing + "var off = offsets";
      code_ += spacing +
               "off.sort { Table.compare(Table.offset(Int32($1.o), vOffset: "
               "{{VOFFSET}}, fbb: &fbb), Table.offset(Int32($0.o), vOffset: "
               "{{VOFFSET}}, fbb: &fbb), fbb: &fbb) < 0 } ";
      code_ += spacing + "return fbb.createVector(ofOffsets: off)";
      Outdent();
      code_ += "}";
      GenLookup(*key_field, namer_.NamespacedType(struct_def));
    }
  }

  void GenTableWriterFields(const FieldDef& field,
                            std::vector<std::string>* create_body,
                            std::vector<std::string>* create_header) {
    std::string builder_string = ", _ fbb: inout FlatBufferBuilder) { ";
    auto& create_func_body = *create_body;
    auto& create_func_header = *create_header;
    const auto field_field = namer_.Field(field);
    const auto field_var = namer_.Variable(field);
    const auto type = GenType(field.value.type);
    const auto opt_scalar =
        field.IsOptional() && IsScalar(field.value.type.base_type);
    const auto nullable_type = opt_scalar ? type + "?" : type;
    code_.SetValue("FIELDVAR", namer_.Variable(field));
    code_.SetValue("VALUETYPE", nullable_type);
    code_.SetValue("OFFSET", namer_.Field(field));
    code_.SetValue("CONSTANT", SwiftConstant(field));
    std::string check_if_vector =
        (IsVector(field.value.type) || IsArray(field.value.type)) ? "VectorOf("
                                                                  : "(";
    const auto body = "add" + check_if_vector + field_field + ": ";
    code_ += "{{ACCESS_TYPE}} static func " + body + "\\";

    create_func_body.push_back("{{STRUCTNAME}}." + body + field_field +
                               ", &fbb)");

    if (IsScalar(field.value.type.base_type) &&
        !IsBool(field.value.type.base_type)) {
      const std::string is_enum = IsEnum(field.value.type) ? ".rawValue" : "";
      const std::string optional_enum =
          IsEnum(field.value.type) ? ("?" + is_enum) : "";
      code_ +=
          "{{VALUETYPE}}" + builder_string + "fbb.add(element: {{FIELDVAR}}\\";

      code_ += field.IsOptional() ? (optional_enum + "\\")
                                  : (is_enum + ", def: {{CONSTANT}}\\");

      code_ += ", at: {{TABLEOFFSET}}.{{OFFSET}}) }";

      const auto default_value =
          IsEnum(field.value.type)
              ? (field.IsOptional() ? "nil" : GenEnumDefaultValue(field))
              : SwiftConstant(field);
      create_func_header.push_back(
          "" + field_field + ": " + nullable_type + " = " +
          (field.IsOptional() ? "nil" : default_value));
      return;
    }

    if (IsBool(field.value.type.base_type)) {
      std::string default_value = SwiftConstant(field);

      code_.SetValue("CONSTANT", default_value);
      code_.SetValue("VALUETYPE", field.IsOptional() ? "Bool?" : "Bool");
      code_ +=
          "{{VALUETYPE}}" + builder_string + "fbb.add(element: {{FIELDVAR}},\\";
      code_ += field.IsOptional() ? "\\" : " def: {{CONSTANT}},";
      code_ += " at: {{TABLEOFFSET}}.{{OFFSET}}) }";
      create_func_header.push_back(
          field_var + ": " + nullable_type + " = " +
          (field.IsOptional() ? "nil" : default_value));
      return;
    }

    if (IsStruct(field.value.type)) {
      const auto create_struct =
          "guard let {{FIELDVAR}} = {{FIELDVAR}} else { return };"
          " fbb.create(struct: {{FIELDVAR}}, position: "
          "{{TABLEOFFSET}}.{{OFFSET}}) }";
      code_ += type + "?" + builder_string + create_struct;
      /// Optional hard coded since structs are always optional
      create_func_header.push_back(field_var + ": " + type +
                                   (field.IsOptional() ? "? = nil" : ""));
      return;
    }

    const auto arg_label =
        namer_.Variable(field) +
        (IsVector(field.value.type) || IsArray(field.value.type)
             ? "VectorOffset"
             : "Offset");
    create_func_header.push_back(arg_label + " " + field_var + ": " + "Offset" +
                                 (field.IsRequired() ? "" : " = Offset()"));
    const auto reader_type =
        IsStruct(field.value.type) && field.value.type.struct_def->fixed
            ? "structOffset: {{TABLEOFFSET}}.{{OFFSET}}) }"
            : "offset: {{FIELDVAR}}, at: {{TABLEOFFSET}}.{{OFFSET}}) "
              "}";
    code_ += "Offset" + builder_string + "fbb.add(" + reader_type;

    const auto vectortype = field.value.type.VectorType();

    if ((vectortype.base_type == BASE_TYPE_STRUCT &&
         field.value.type.struct_def->fixed) &&
        (IsVector(field.value.type) || IsArray(field.value.type))) {
      const auto field_name = namer_.NamespacedType(*vectortype.struct_def);
      code_ += "{{ACCESS_TYPE}} static func " +
               namer_.Method("start_vector_of", field_var) +
               "(_ size: Int, in builder: inout "
               "FlatBufferBuilder) {";
      Indent();
      code_ += "builder.startVector(size * MemoryLayout<" + field_name +
               ">.size, elementSize: MemoryLayout<" + field_name +
               ">.alignment)";
      Outdent();
      code_ += "}";
    }
  }

  void GenTableReader(const StructDef& struct_def) {
    for (auto it = struct_def.fields.vec.begin();
         it != struct_def.fields.vec.end(); ++it) {
      const auto& field = **it;
      if (field.deprecated) continue;
      GenTableReaderFields(field);
    }
  }

  void GenTableReaderFields(const FieldDef& field) {
    const auto offset = NumToString(field.value.offset);
    const auto field_field = namer_.Field(field);
    const auto type = GenType(field.value.type);
    code_.SetValue("FIELDVAR", namer_.Variable(field));
    code_.SetValue("FIELDMETHOD", namer_.Method(field));
    code_.SetValue("VALUETYPE", type);
    code_.SetValue("OFFSET", namer_.Constant(field.name));
    code_.SetValue("CONSTANT", SwiftConstant(field));
    bool opt_scalar =
        field.IsOptional() && IsScalar(field.value.type.base_type);
    std::string def_Val = opt_scalar ? "nil" : "{{CONSTANT}}";
    std::string optional = opt_scalar ? "?" : "";
    const auto const_string = "return o == 0 ? " + def_Val + " : ";
    GenComment(field.doc_comment);
    if (IsScalar(field.value.type.base_type) && !IsEnum(field.value.type) &&
        !IsBool(field.value.type.base_type)) {
      if (field.attributes.Lookup("encrypted") != nullptr) {
        const auto field_id = NumToString(field.value.offset);
        code_ += GenReaderMainBody(optional) + GenOffset() + const_string +
                 "FlatbuffersEncryption.decryptScalar(" +
                 GenReader("VALUETYPE", "o") +
                 ", encryptionCtx: self.encryptionCtx, fieldId: " + field_id + ") }";
      } else {
        code_ += GenReaderMainBody(optional) + GenOffset() + const_string +
                 GenReader("VALUETYPE", "o") + " }";
      }
      if (parser_.opts.mutable_buffer) code_ += GenMutate("o", GenOffset());
      return;
    }

    if (IsBool(field.value.type.base_type)) {
      std::string default_value =
          field.IsOptional() ? "nil" : SwiftConstant(field);
      code_.SetValue("CONSTANT", default_value);
      code_.SetValue("VALUETYPE", "Bool");
      code_ += GenReaderMainBody(optional) + "\\";
      code_ += GenOffset() +
               "return o == 0 ? {{CONSTANT}} : " + GenReader("VALUETYPE", "o") +
               " }";
      if (parser_.opts.mutable_buffer) code_ += GenMutate("o", GenOffset());
      return;
    }

    if (IsEnum(field.value.type)) {
      const auto default_value =
          field.IsOptional() ? "nil" : GenEnumDefaultValue(field);
      code_.SetValue("BASEVALUE", GenTypeBasic(field.value.type, false));
      code_ += GenReaderMainBody(optional) + "\\";
      code_ += GenOffset() + "return o == 0 ? " + default_value + " : " +
               GenEnumConstructor("o") + "?? " + default_value + " }";
      if (parser_.opts.mutable_buffer && !IsUnion(field.value.type))
        code_ += GenMutate("o", GenOffset(), true);
      return;
    }

    const std::string is_required = field.IsRequired() ? "!" : "?";
    const auto required_reader = field.IsRequired() ? "return " : const_string;

    if (IsStruct(field.value.type) && field.value.type.struct_def->fixed) {
      code_.SetValue("VALUETYPE", GenType(field.value.type));
      code_.SetValue("CONSTANT", "nil");
      code_ += GenReaderMainBody(is_required) + GenOffset() + required_reader +
               "{{ACCESS}}.readBuffer(of: {{VALUETYPE}}.self, at: o) }";
      code_.SetValue("FIELDVAR", namer_.Variable("mutable", field_field));
      code_.SetValue("VALUETYPE", GenType(field.value.type) + Mutable());
      code_.SetValue("CONSTANT", "nil");
      code_ += GenReaderMainBody(is_required) + GenOffset() + required_reader +
               GenConstructor("o + {{ACCESS}}.position");
      return;
    }
    switch (field.value.type.base_type) {
      case BASE_TYPE_STRUCT:
        code_.SetValue("VALUETYPE", GenType(field.value.type));
        code_.SetValue("CONSTANT", "nil");
        code_ += GenReaderMainBody(is_required) + GenOffset() +
                 required_reader +
                 GenConstructor(GenIndirect("o + {{ACCESS}}.position"));
        break;

      case BASE_TYPE_STRING: {
        const auto default_string = "\"" + SwiftConstant(field) + "\"";
        code_.SetValue("VALUETYPE", GenType(field.value.type));
        code_.SetValue("CONSTANT", field.IsDefault() ? default_string : "nil");
        if (field.attributes.Lookup("encrypted") != nullptr) {
          const auto field_id = NumToString(field.value.offset);
          code_ += GenReaderMainBody(is_required) + GenOffset() +
                   required_reader + "FlatbuffersEncryption.decryptString(" +
                   "{{ACCESS}}.string(at: o), encryptionCtx: self.encryptionCtx, fieldId: " +
                   field_id + ") }";
        } else {
          code_ += GenReaderMainBody(is_required) + GenOffset() +
                   required_reader + "{{ACCESS}}.string(at: o) }";
        }
        code_ += "{{ACCESS_TYPE}} var {{FIELDVAR}}SegmentArray: [UInt8]" +
                 is_required +
                 " { return "
                 "{{ACCESS}}.getVector(at: {{TABLEOFFSET}}.{{OFFSET}}) }";
        break;
      }
      case BASE_TYPE_ARRAY:
        FLATBUFFERS_FALLTHROUGH();  // fall thru
      case BASE_TYPE_VECTOR:
        GenTableReaderVectorFields(field);
        break;
      case BASE_TYPE_UNION:
        code_.SetValue("CONSTANT", "nil");
        code_ +=
            "{{ACCESS_TYPE}} func {{FIELDVAR}}<T: "
            "FlatbuffersInitializable>(type: "
            "T.Type) -> T" +
            is_required + " { " + GenOffset() + required_reader +
            "{{ACCESS}}.union(o) }";
        break;
      default:
        FLATBUFFERS_ASSERT(0);
    }
  }

  void GenTableReaderVectorFields(const FieldDef& field) {
    const auto vectortype = field.value.type.VectorType();
    code_.SetValue("SIZE", NumToString(InlineSize(vectortype)));

    if (vectortype.base_type == BASE_TYPE_STRING) {
      code_.SetValue("VALUETYPE", "String?");
    }

    if (vectortype.base_type != BASE_TYPE_UNION) {
      code_ +=
          "{{ACCESS_TYPE}} var {{FIELDVAR}}: "
          "FlatbufferVector<{{VALUETYPE}}> "
          "{ return {{ACCESS}}.vector(at: {{TABLEOFFSET}}.{{OFFSET}}, "
          "byteSize: {{SIZE}}) }";
    }

    if (IsScalar(vectortype.base_type) && !IsEnum(vectortype) &&
        !IsBool(field.value.type.base_type)) {
      if (parser_.opts.mutable_buffer) code_ += GenMutateArray();
      GenUnsafeBufferPointer(field);
      return;
    }

    if (vectortype.base_type == BASE_TYPE_STRUCT &&
        field.value.type.struct_def->fixed) {
      code_.SetValue("FIELDVAR", namer_.Method("mutable", field));
      code_ +=
          "{{ACCESS_TYPE}} var {{FIELDVAR}}: "
          "FlatbufferVector<{{VALUETYPE}}_Mutable> "
          "{ return {{ACCESS}}.vector(at: {{TABLEOFFSET}}.{{OFFSET}}, "
          "byteSize: {{SIZE}}) }";
      GenUnsafeBufferPointer(field);
      return;
    }

    if (vectortype.base_type == BASE_TYPE_UNION) {
      code_ +=
          "{{ACCESS_TYPE}} var {{FIELDVAR}}: UnionFlatbufferVector "
          "{ return {{ACCESS}}.unionVector(at: "
          "{{TABLEOFFSET}}.{{OFFSET}}, "
          "byteSize: {{SIZE}}) }";
      code_ +=
          "{{ACCESS_TYPE}} func {{FIELDVAR}}<T: FlatbuffersInitializable>(at "
          "index: "
          "Int32, type: T.Type) -> T? { " +
          GenOffset() + "return o == 0 ? nil : \\";
      code_ +=
          "{{ACCESS}}.directUnion({{ACCESS}}.vector(at: o) + "
          "index * {{SIZE}}) }";
      return;
    }

    if (vectortype.base_type == BASE_TYPE_STRUCT &&
        !field.value.type.struct_def->fixed) {
      const auto& sd = *field.value.type.struct_def;
      const auto& fields = sd.fields.vec;
      for (auto kit = fields.begin(); kit != fields.end(); ++kit) {
        const auto& key_field = **kit;
        if (key_field.key) {
          GenByKeyFunctions(key_field);
          break;
        }
      }
    }
  }

  void GenUnsafeBufferPointer(const FieldDef& field) {
    code_.SetValue("functionName",
                   namer_.Variable("withUnsafePointerTo", field));
    code_ +=
        "{{ACCESS_TYPE}} func {{functionName}}<T>(_ body: "
        "(UnsafeRawBufferPointer, Int) throws -> T) rethrows -> T? { return "
        "try "
        "{{ACCESS}}.withUnsafePointerToSlice(at: "
        "{{TABLEOFFSET}}.{{OFFSET}}, "
        "body: body) }";
  }

  std::vector<std::string> GenerateCodingKeys(const StructDef& struct_def) {
    std::vector<std::string> coding_keys;
    for (auto it = struct_def.fields.vec.begin();
         it != struct_def.fields.vec.end(); ++it) {
      const auto& field = **it;
      if (field.deprecated) continue;
      coding_keys.push_back("case " + namer_.Variable(field) + " = \"" +
                            field.name + "\"");
    }
    return coding_keys;
  }

  void GenerateEncoderUnionBody(const FieldDef& field) {
    EnumDef& union_def = *field.value.type.enum_def;
    const auto is_vector = field.value.type.base_type == BASE_TYPE_VECTOR ||
                           field.value.type.base_type == BASE_TYPE_ARRAY;
    if (field.value.type.base_type == BASE_TYPE_UTYPE ||
        (is_vector &&
         field.value.type.VectorType().base_type == BASE_TYPE_UTYPE))
      return;
    if (is_vector) {
      code_ +=
          "try container.encode({{FIELDVAR}}Type, forKey: .charactersType)";
      code_ +=
          "var contentEncoder = container.nestedUnkeyedContainer(forKey: "
          ".{{FIELDVAR}})";
      code_ += "let _{{FIELDVAR}} = {{FIELDVAR}}Type";
      code_ +=
          "for index in _{{FIELDVAR}}.startIndex..<_{{FIELDVAR}}.endIndex {";
      Indent();
      code_ += "switch _{{FIELDVAR}}[index] {";
      for (auto it = union_def.Vals().begin(); it != union_def.Vals().end();
           ++it) {
        const auto& ev = **it;
        const auto type = GenType(ev.union_type);
        code_.SetValue("KEY", namer_.LegacySwiftVariant(ev));
        code_.SetValue("VALUETYPE", type);
        if (ev.union_type.base_type == BASE_TYPE_NONE) {
          continue;
        }
        code_ += "case .{{KEY}}:";
        Indent();
        code_ +=
            "let _v = {{FIELDVAR}}(at: Int32(index), type: {{VALUETYPE}}.self)";
        code_ += "try contentEncoder.encode(_v)";
        Outdent();
      }
      code_ += "default: break;";
      code_ += "}";
      Outdent();
      code_ += "}";
      return;
    }

    code_ += "switch {{FIELDVAR}}Type {";
    for (auto it = union_def.Vals().begin(); it != union_def.Vals().end();
         ++it) {
      const auto& ev = **it;
      const auto type = GenType(ev.union_type);
      code_.SetValue("KEY", namer_.LegacySwiftVariant(ev));
      code_.SetValue("VALUETYPE", type);
      if (ev.union_type.base_type == BASE_TYPE_NONE) {
        continue;
      }
      code_ += "case .{{KEY}}:";
      Indent();
      code_ += "let _v = {{FIELDVAR}}(type: {{VALUETYPE}}.self)";
      code_ += "try container.encodeIfPresent(_v, forKey: .{{FIELDVAR}})";
      Outdent();
    }
    code_ += "default: break;";
    code_ += "}";
  }

  void GenerateEncoderBody(const StructDef& struct_def) {
    code_ += "var container = encoder.container(keyedBy: CodingKeys.self)";
    for (auto it = struct_def.fields.vec.begin();
         it != struct_def.fields.vec.end(); ++it) {
      const auto& field = **it;
      if (field.deprecated) continue;
      const auto type = field.value.type;

      code_.SetValue("FIELDVAR", namer_.Variable(field));
      code_.SetValue("CONSTANT", SwiftConstant(field));
      bool should_indent = true;
      if (IsEnum(type) && !field.IsOptional()) {
        code_.SetValue("CONSTANT", GenEnumDefaultValue(field));
        code_ += "if {{FIELDVAR}} != {{CONSTANT}} {";
      } else if (IsFloat(type.base_type) &&
                 StringIsFlatbufferNan(field.value.constant)) {
        code_ += "if !{{FIELDVAR}}.isNaN {";
      } else if (IsScalar(type.base_type) && !IsEnum(type) &&
                 !IsBool(type.base_type) && !field.IsOptional()) {
        code_ += "if {{FIELDVAR}} != {{CONSTANT}} {";
      } else if (IsBool(type.base_type) && !field.IsOptional()) {
        code_.SetValue("CONSTANT", SwiftConstant(field));
        code_ += "if {{FIELDVAR}} != {{CONSTANT}} {";
      } else {
        should_indent = false;
      }
      if (should_indent) Indent();

      if (IsUnion(type) && !IsEnum(type)) {
        GenerateEncoderUnionBody(field);
      } else if (IsArray(type)) {
        code_ +=
            "var {{FIELDVAR}}Container = "
            "container.nestedUnkeyedContainer(forKey: .{{FIELDVAR}})";
        code_ +=
            "for index in {{FIELDVAR}}.startIndex..<{{FIELDVAR}}.endIndex {";
        Indent();
        code_ += "try {{FIELDVAR}}Container.encode({{FIELDVAR}}[index])";
        Outdent();
        code_ += "}";
      } else {
        code_ +=
            "try container.encodeIfPresent({{FIELDVAR}}, forKey: "
            ".{{FIELDVAR}})";
      }
      if (should_indent) Outdent();

      if ((IsScalar(type.base_type) && !field.IsOptional())) {
        code_ += "}";
      }
    }
  }

  void GenerateJSONEncodingAPIs(const StructDef& struct_def) {
    GenOSVersionChecks();
    code_ += "extension {{STRUCTNAME}}: Encodable {";
    Indent();
    auto coding_keys = GenerateCodingKeys(struct_def);

    if (coding_keys.empty() == false) {
      code_ += "enum CodingKeys: String, CodingKey {";
      Indent();
      for (auto it = coding_keys.begin(); it != coding_keys.end(); ++it) {
        const auto& field = *it;
        code_ += field;
      }
      Outdent();
      code_ += "}";

      code_ += "";
    }

    code_ += "{{ACCESS_TYPE}} func encode(to encoder: Encoder) throws {";

    if (coding_keys.empty() == false) {
      Indent();
      GenerateEncoderBody(struct_def);
      Outdent();
    }

    code_ += "}";

    Outdent();
    code_ += "}";
    code_ += "";
  }

  void GenerateVerifier(const StructDef& struct_def) {
    code_ +=
        "{{ACCESS_TYPE}} static func verify<T>(_ verifier: inout Verifier, at "
        "position: "
        "Int, of type: T.Type) throws where T: Verifiable {";
    Indent();
    code_ += "var _v = try verifier.visitTable(at: position)";
    for (auto it = struct_def.fields.vec.begin();
         it != struct_def.fields.vec.end(); ++it) {
      const auto& field = **it;
      if (field.deprecated) continue;
      const auto offset = NumToString(field.value.offset);

      code_.SetValue("FIELDVAR", namer_.Variable(field));
      code_.SetValue("VALUETYPE", GenerateVerifierType(field));
      code_.SetValue("OFFSET", namer_.Field(field));
      code_.SetValue("ISREQUIRED", field.IsRequired() ? "true" : "false");

      if (IsUnion(field.value.type)) {
        GenerateUnionTypeVerifier(field);
        continue;
      }

      code_ +=
          "try _v.visit(field: {{TABLEOFFSET}}.{{OFFSET}}, fieldName: "
          "\"{{FIELDVAR}}\", required: {{ISREQUIRED}}, type: "
          "{{VALUETYPE}}.self)";
    }
    code_ += "_v.finish()";
    Outdent();
    code_ += "}";
  }

  void GenerateUnionTypeVerifier(const FieldDef& field) {
    const auto is_vector =
        IsVector(field.value.type) || IsArray(field.value.type);
    if (field.value.type.base_type == BASE_TYPE_UTYPE ||
        (is_vector &&
         field.value.type.VectorType().base_type == BASE_TYPE_UTYPE))
      return;
    EnumDef& union_def = *field.value.type.enum_def;
    code_.SetValue("VALUETYPE", namer_.NamespacedType(union_def));
    code_.SetValue("FUNCTION_NAME", is_vector ? "visitUnionVector" : "visit");
    code_ +=
        "try _v.{{FUNCTION_NAME}}(unionKey: "
        "{{TABLEOFFSET}}.{{OFFSET}}Type, "
        "unionField: {{TABLEOFFSET}}.{{OFFSET}}, unionKeyName: "
        "\"{{FIELDVAR}}Type\", fieldName: \"{{FIELDVAR}}\", required: "
        "{{ISREQUIRED}}, completion: { (verifier, key: {{VALUETYPE}}, pos) in";
    Indent();
    code_ += "switch key {";
    for (auto it = union_def.Vals().begin(); it != union_def.Vals().end();
         ++it) {
      const auto& ev = **it;
      const auto type = GenType(ev.union_type);
      code_.SetValue("KEY", namer_.LegacySwiftVariant(ev));
      code_.SetValue("VALUETYPE", type);
      code_ += "case .{{KEY}}:";
      Indent();
      if (ev.union_type.base_type == BASE_TYPE_NONE) {
        code_ += "break // NOTE - SWIFT doesnt support none";
      } else if (ev.union_type.base_type == BASE_TYPE_STRING) {
        code_ +=
            "try ForwardOffset<String>.verify(&verifier, at: pos, of: "
            "String.self)";
      } else {
        code_.SetValue("MAINTYPE", ev.union_type.struct_def->fixed
                                       ? type
                                       : "ForwardOffset<" + type + ">");
        code_ +=
            "try {{MAINTYPE}}.verify(&verifier, at: pos, of: "
            "{{VALUETYPE}}.self)";
      }
      Outdent();
    }
    code_ += "}";
    Outdent();
    code_ += "})";
  }

  std::string GenerateVerifierType(const FieldDef& field) {
    const auto type = field.value.type;
    const auto is_vector = IsVector(type) || IsArray(type);

    if (is_vector) {
      const auto vector_type = field.value.type.VectorType();
      return "ForwardOffset<Vector<" +
             GenerateNestedVerifierTypes(vector_type) + ", " +
             GenType(vector_type) + ">>";
    }

    return GenerateNestedVerifierTypes(field.value.type);
  }

  std::string GenerateNestedVerifierTypes(const Type& type) {
    const auto string_type = GenType(type);

    if (IsScalar(type.base_type)) {
      return string_type;
    }

    if (IsString(type)) {
      return "ForwardOffset<" + string_type + ">";
    }

    if (type.struct_def && type.struct_def->fixed) {
      return string_type;
    }

    return "ForwardOffset<" + string_type + ">";
  }

  void GenByKeyFunctions(const FieldDef& key_field) {
    code_.SetValue("TYPE", GenType(key_field.value.type));
    code_ +=
        "{{ACCESS_TYPE}} func {{FIELDVAR}}By(key: {{TYPE}}) -> {{VALUETYPE}}? "
        "{ \\";
    code_ += GenOffset() +
             "return o == 0 ? nil : {{VALUETYPE}}.lookupByKey(vector: "
             "{{ACCESS}}.vector(at: o), key: key, fbb: {{ACCESS}}.bb) }";
  }

  void GenEnum(const EnumDef& enum_def) {
    if (enum_def.generated) return;
    const bool is_private_access =
        parser_.opts.swift_implementation_only ||
        enum_def.attributes.Lookup("private") != nullptr;
    code_.SetValue("ENUM_TYPE",
                   enum_def.is_union ? "UnionEnum" : "Enum, Verifiable");
    code_.SetValue("ACCESS_TYPE", is_private_access ? "internal" : "public");
    code_.SetValue("ENUM_NAME", namer_.NamespacedType(enum_def));
    code_.SetValue("BASE_TYPE", GenTypeBasic(enum_def.underlying_type, false));
    GenComment(enum_def.doc_comment);
    code_ +=
        "{{ACCESS_TYPE}} enum {{ENUM_NAME}}: "
        "{{BASE_TYPE}}, FlatbuffersVectorInitializable, {{ENUM_TYPE}} {";
    Indent();
    code_ += "{{ACCESS_TYPE}} typealias T = {{BASE_TYPE}}";
    if (enum_def.is_union) {
      code_ += "";
      code_ += "{{ACCESS_TYPE}} init?(value: T) {";
      Indent();
      code_ += "self.init(rawValue: value)";
      Outdent();
      code_ += "}\n";
    }
    code_ +=
        "{{ACCESS_TYPE}} static var byteSize: Int { return "
        "MemoryLayout<{{BASE_TYPE}}>.size "
        "}";
    code_ +=
        "{{ACCESS_TYPE}} var value: {{BASE_TYPE}} { return self.rawValue }";
    for (auto it = enum_def.Vals().begin(); it != enum_def.Vals().end(); ++it) {
      const auto& ev = **it;
      code_.SetValue("KEY", namer_.LegacySwiftVariant(ev));
      code_.SetValue("VALUE", enum_def.ToString(ev));
      GenComment(ev.doc_comment);
      code_ += "case {{KEY}} = {{VALUE}}";
    }
    code_ += "";
    AddMinOrMaxEnumValue(namer_.LegacySwiftVariant(*enum_def.MaxValue()),
                         "max");
    AddMinOrMaxEnumValue(namer_.LegacySwiftVariant(*enum_def.MinValue()),
                         "min");
    Outdent();
    code_ += "}\n";
    if (parser_.opts.gen_json_coders) EnumEncoder(enum_def);
    code_ += "";
    if (parser_.opts.generate_object_based_api && enum_def.is_union) {
      code_ += "{{ACCESS_TYPE}} struct {{ENUM_NAME}}Union {";
      Indent();
      code_ += "{{ACCESS_TYPE}} var type: {{ENUM_NAME}}";
      code_ += "{{ACCESS_TYPE}} var value: NativeObject?";
      code_ +=
          "{{ACCESS_TYPE}} init(_ v: NativeObject?, type: {{ENUM_NAME}}) {";
      Indent();
      code_ += "self.type = type";
      code_ += "self.value = v";
      Outdent();
      code_ += "}";
      code_ +=
          "{{ACCESS_TYPE}} func pack(builder: inout FlatBufferBuilder) -> "
          "Offset {";
      Indent();
      BuildUnionEnumSwitchCaseWritter(enum_def);
      Outdent();
      code_ += "}";
      Outdent();
      code_ += "}";
    }
  }

  void EnumEncoder(const EnumDef& enum_def) {
    code_ += "extension {{ENUM_NAME}}: Encodable {";
    Indent();
    code_ += "{{ACCESS_TYPE}} func encode(to encoder: Encoder) throws {";
    Indent();
    code_ += "var container = encoder.singleValueContainer()";
    code_ += "switch self {";
    for (auto it = enum_def.Vals().begin(); it != enum_def.Vals().end(); ++it) {
      const auto& ev = **it;
      code_.SetValue("KEY", namer_.LegacySwiftVariant(ev));
      code_.SetValue("RAWKEY", ev.name);
      code_ += "case .{{KEY}}: try container.encode(\"{{RAWKEY}}\")";
    }
    code_ += "}";
    Outdent();
    code_ += "}";
    Outdent();
    code_ += "}";
  }

  // MARK: - Object API

  void GenerateObjectAPIExtensionHeader(std::string type_name,
                                        const bool is_fixed_struct) {
    //    code_.SetValue("MUTATING", is_fixed_struct ? "" : " mutating");
    code_ += "";
    code_ += "{{ACCESS_TYPE}} func unpack() -> " + type_name + " {";
    Indent();
    code_ += "return " + type_name + (is_fixed_struct ? "(self)" : "(self)");
    Outdent();
    code_ += "}";
    code_ +=
        "{{ACCESS_TYPE}} static func pack(_ builder: inout FlatBufferBuilder, "
        "obj: "
        "inout " +
        type_name + "?) -> Offset {";
    Indent();
    code_ += "guard var obj = obj else { return Offset() }";
    code_ += "return pack(&builder, obj: &obj)";
    Outdent();
    code_ += "}";
    code_ += "";
    code_ +=
        "{{ACCESS_TYPE}} static func pack(_ builder: inout FlatBufferBuilder, "
        "obj: "
        "inout " +
        type_name + ") -> Offset {";
    Indent();
  }

  void GenerateObjectAPIStructConstructor(const StructDef& struct_def) {
    code_ += "{{ACCESS_TYPE}} init(_ _t: borrowing {{STRUCTNAME}}" + Mutable() +
             ") {";
    Indent();
    for (auto it = struct_def.fields.vec.begin();
         it != struct_def.fields.vec.end(); ++it) {
      const auto& field = **it;
      if (field.deprecated) continue;

      const auto type = GenType(field.value.type);
      code_.SetValue("FIELDVAR", namer_.Variable(field));
      if (IsArray(field.value.type)) {
        code_.SetValue(
            "RAW_VALUE",
            IsStruct(field.value.type.VectorType())
                ? ".unpack()"
                : (IsEnum(field.value.type.VectorType()) ? ".rawValue" : ""));
        code_ += "let _v{{FIELDVAR}} = _t.{{FIELDVAR}}";
        code_ +=
            "_{{FIELDVAR}} = InlineArray { _v{{FIELDVAR}}[$0]{{RAW_VALUE}} }";
        continue;
      } else if (IsStruct(field.value.type)) {
        code_ += "let _v{{FIELDVAR}} = _t.{{FIELDVAR}}";
        code_ += "_{{FIELDVAR}} = _v{{FIELDVAR}}.unpack()";
        continue;
      }
      std::string is_enum = IsEnum(field.value.type) ? ".value" : "";
      code_ += "_{{FIELDVAR}} = _t.{{FIELDVAR}}" + is_enum;
    }
    Outdent();
    code_ += "}\n";
  }

  void GenObjectAPI(const StructDef& struct_def) {
    GenOSVersionChecks();
    code_ += "{{ACCESS_TYPE}} class " +
             namer_.NamespacedObjectType(struct_def) + ": NativeObject {\n";
    std::vector<std::string> buffer_constructor;
    std::vector<std::string> base_constructor;
    Indent();
    for (auto it = struct_def.fields.vec.begin();
         it != struct_def.fields.vec.end(); ++it) {
      const auto& field = **it;
      if (field.deprecated) continue;
      BuildObjectAPIConstructorBody(field, struct_def.fixed, buffer_constructor,
                                    base_constructor);
    }
    code_ += "";
    BuildObjectConstructor(
        buffer_constructor,
        "_ _t: borrowing " + namer_.NamespacedType(struct_def));
    BuildObjectConstructor(base_constructor);
    if (!struct_def.fixed)
      code_ +=
          "{{ACCESS_TYPE}} func serialize() -> ByteBuffer { return "
          "serialize(type: "
          "{{STRUCTNAME}}.self) }\n";
    Outdent();
    code_ += "}";
  }

  void GenerateObjectAPITableExtension(const StructDef& struct_def) {
    GenerateObjectAPIExtensionHeader(namer_.NamespacedObjectType(struct_def),
                                     struct_def.fixed);
    std::vector<std::string> unpack_body;
    std::string builder = ", &builder)";
    for (auto it = struct_def.fields.vec.begin();
         it != struct_def.fields.vec.end(); ++it) {
      const auto& field = **it;
      if (field.deprecated) continue;
      const auto field_var = namer_.Variable(field);
      const auto field_field = namer_.Field(field);
      const auto field_method = namer_.Method(field);
      const auto type = GenType(field.value.type);
      std::string check_if_vector =
          (IsVector(field.value.type) || IsArray(field.value.type))
              ? "VectorOf("
              : "(";
      std::string body = "add" + check_if_vector + field_method + ": ";
      switch (field.value.type.base_type) {
        case BASE_TYPE_ARRAY:
          FLATBUFFERS_FALLTHROUGH();
        case BASE_TYPE_VECTOR: {
          GenerateVectorObjectAPITableExtension(field);
          unpack_body.push_back("{{STRUCTNAME}}." + body + "__" + field_var +
                                builder);
          break;
        }
        case BASE_TYPE_UNION: {
          code_ += "let __" + field_var + " = obj." + field_var +
                   "?.pack(builder: &builder) ?? Offset()";
          unpack_body.push_back("if let o = obj." + field_var + "?.type {");
          unpack_body.push_back("  {{STRUCTNAME}}.add(" + field_var +
                                "Type: o" + builder);
          unpack_body.push_back("  {{STRUCTNAME}}." + body + "__" + field_var +
                                builder);
          unpack_body.push_back("}\n");
          break;
        }
        case BASE_TYPE_STRUCT: {
          if (field.value.type.struct_def &&
              field.value.type.struct_def->fixed) {
            // This is a Struct (IsStruct), not a table. We create
            // a native swift object in this case.
            std::string code;
            GenerateStructArgs(*field.value.type.struct_def, &code, "", "",
                               "$0", true);
            code = code.substr(0, code.size() - 2);
            unpack_body.push_back("{{STRUCTNAME}}." + body + "obj." +
                                  field_field + builder);
          } else {
            code_ += "let __" + field_var + " = " + type +
                     ".pack(&builder, obj: &obj." + field_field + ")";
            unpack_body.push_back("{{STRUCTNAME}}." + body + "__" + field_var +
                                  builder);
          }
          break;
        }
        case BASE_TYPE_STRING: {
          unpack_body.push_back("{{STRUCTNAME}}." + body + "__" + field_var +
                                builder);
          if (field.IsRequired()) {
            code_ += "let __" + field_var + " = builder.create(string: obj." +
                     field_field + ")";
          } else {
            BuildingOptionalObjects(field_field, "builder.create(string: s)");
          }
          break;
        }
        case BASE_TYPE_UTYPE:
          break;
        default:
          unpack_body.push_back("{{STRUCTNAME}}." + body + "obj." +
                                field_field + builder);
      }
    }
    code_ += "let __root = {{STRUCTNAME}}.start{{SHORT_STRUCTNAME}}(&builder)";
    for (auto it = unpack_body.begin(); it < unpack_body.end(); it++)
      code_ += *it;
    code_ +=
        "return {{STRUCTNAME}}.end{{SHORT_STRUCTNAME}}(&builder, start: "
        "__root)";
    Outdent();
    code_ += "}";
  }

  void GenerateVectorObjectAPITableExtension(const FieldDef& field_def) {
    const Type& field_type = field_def.value.type;
    const auto type = GenType(field_type);
    const auto var = namer_.Variable(field_def);
    const auto field = namer_.Field(field_def);

    const auto vectortype = field_type.VectorType();
    switch (vectortype.base_type) {
      case BASE_TYPE_UNION: {
        code_ += "var __" + var + "__: [Offset] = []";
        code_ += "for i in obj." + var + " {";
        Indent();
        code_ += "guard let off = i?.pack(builder: &builder) else { continue }";
        code_ += "__" + var + "__.append(off)";
        Outdent();
        code_ += "}";
        code_ += "let __" + var + " = builder.createVector(ofOffsets: __" +
                 var + "__)";
        code_ += "let __" + var + "Type = builder.createVector(obj." + field +
                 ".compactMap { $0?.type })";
        break;
      }
      case BASE_TYPE_UTYPE:
        break;
      case BASE_TYPE_STRUCT: {
        if (field_type.struct_def && !field_type.struct_def->fixed) {
          code_ += "var __" + var + "__: [Offset] = []";
          code_ += "for var i in obj." + var + " {";
          Indent();
          code_ +=
              "__" + var + "__.append(" + type + ".pack(&builder, obj: &i))";
          Outdent();
          code_ += "}";
          code_ += "let __" + var + " = builder.createVector(ofOffsets: __" +
                   var + "__)";
        } else {
          code_ += "{{STRUCTNAME}}." + namer_.Method("start_vector_of", var) +
                   "(obj." + field + ".count, in: &builder)";
          std::string code;
          GenerateStructArgs(*field_type.struct_def, &code, "", "", "_o", true);
          code = code.substr(0, code.size() - 2);
          code_ += "for val in obj." + field + " {";
          Indent();
          code_ += "builder.create(struct: val)";
          Outdent();
          code_ += "}";
          code_ += "let __" + var + " = builder.endVector(len: obj." + field +
                   ".count)";
        }
        break;
      }
      case BASE_TYPE_STRING: {
        code_ += "let __" + var + " = builder.createVector(ofStrings: obj." +
                 var + ".compactMap({ $0 }) )";
        break;
      }
      default: {
        code_ += "let __" + var + " = builder.createVector(obj." + field + ")";
        break;
      }
    }
  }

  void BuildingOptionalObjects(const std::string& var,
                               const std::string& body_front) {
    code_ += "let __" + var + ": Offset";
    code_ += "if let s = obj." + var + " {";
    Indent();
    code_ += "__" + var + " = " + body_front;
    Outdent();
    code_ += "} else {";
    Indent();
    code_ += "__" + var + " = Offset()";
    Outdent();
    code_ += "}";
    code_ += "";
  }

  void BuildObjectConstructor(const std::vector<std::string>& body,
                              const std::string& header = "") {
    code_.SetValue("HEADER", header);
    code_ += "{{ACCESS_TYPE}} init({{HEADER}}) {";
    Indent();
    for (auto it = body.begin(); it < body.end(); ++it) code_ += *it;
    Outdent();
    code_ += "}\n";
  }

  void BuildObjectAPIConstructorBody(
      const FieldDef& field, bool is_fixed,
      std::vector<std::string>& buffer_constructor,
      std::vector<std::string>& base_constructor) {
    const auto field_field = namer_.Field(field);
    const auto field_var = namer_.Variable(field);
    const auto type = GenType(field.value.type);
    code_.SetValue("FIELDVAR", field_field);
    code_.SetValue("VALUETYPE", type);
    std::string is_required = field.IsRequired() ? "" : "?";

    switch (field.value.type.base_type) {
      case BASE_TYPE_STRUCT: {
        const auto objtype = GenType(field.value.type, true);
        code_.SetValue("VALUETYPE", objtype);
        const auto optional =
            (field.value.type.struct_def && field.value.type.struct_def->fixed);
        std::string question_mark =
            (field.IsRequired() || (optional && is_fixed) ? "" : "?");

        code_ +=
            "{{ACCESS_TYPE}} var {{FIELDVAR}}: {{VALUETYPE}}" + question_mark;
        base_constructor.push_back("" + field_var + " = " + objtype + "()");

        if (field.value.type.struct_def->fixed) {
          buffer_constructor.push_back("" + field_var + " = _t." + field_field);
        } else {
          buffer_constructor.push_back(
              "" + field_var + " = _t." + field_var +
              (field.IsRequired() ? "!" : question_mark) + ".unpack()");
        }
        break;
      }
      case BASE_TYPE_ARRAY:
        FLATBUFFERS_FALLTHROUGH();
      case BASE_TYPE_VECTOR: {
        BuildObjectAPIConstructorBodyVectors(field, buffer_constructor,
                                             base_constructor, "    ");
        break;
      }
      case BASE_TYPE_STRING: {
        code_ += "{{ACCESS_TYPE}} var {{FIELDVAR}}: String" + is_required;
        buffer_constructor.push_back(field_var + " = _t." + field_field);

        if (field.IsRequired()) {
          std::string default_value =
              field.IsDefault() ? SwiftConstant(field) : "";
          base_constructor.push_back(field_var + " = \"" + default_value +
                                     "\"");
          break;
        }
        if (field.IsDefault() && !field.IsRequired()) {
          std::string value = field.IsDefault() ? SwiftConstant(field) : "nil";
          base_constructor.push_back(field_var + " = \"" + value + "\"");
        }
        break;
      }
      case BASE_TYPE_UTYPE:
        break;
      case BASE_TYPE_UNION: {
        BuildUnionEnumSwitchCase(*field.value.type.enum_def, field_var,
                                 buffer_constructor);
        break;
      }
      default: {
        buffer_constructor.push_back(field_var + " = _t." + field_field);
        std::string nullable = field.IsOptional() ? "?" : "";
        if (IsScalar(field.value.type.base_type) &&
            !IsBool(field.value.type.base_type) && !IsEnum(field.value.type)) {
          code_ += "{{ACCESS_TYPE}} var {{FIELDVAR}}: {{VALUETYPE}}" + nullable;
          if (!field.IsOptional())
            base_constructor.push_back(field_var + " = " +
                                       SwiftConstant(field));
          break;
        }

        if (IsEnum(field.value.type)) {
          const auto default_value = IsEnum(field.value.type)
                                         ? GenEnumDefaultValue(field)
                                         : SwiftConstant(field);
          code_ += "{{ACCESS_TYPE}} var {{FIELDVAR}}: {{VALUETYPE}}";
          base_constructor.push_back(field_var + " = " + default_value);
          break;
        }

        if (IsBool(field.value.type.base_type)) {
          code_ += "{{ACCESS_TYPE}} var {{FIELDVAR}}: Bool" + nullable;
          if (!field.IsOptional())
            base_constructor.push_back(field_var + " = " +
                                       SwiftConstant(field));
        }
      }
    }
  }

  void BuildObjectAPIConstructorBodyVectors(
      const FieldDef& field, std::vector<std::string>& buffer_constructor,
      std::vector<std::string>& base_constructor,
      const std::string& indentation) {
    const auto vectortype = field.value.type.VectorType();
    const auto field_var = namer_.Field(field);
    const auto field_field = namer_.Field(field);

    if (vectortype.base_type != BASE_TYPE_UTYPE) {
      buffer_constructor.push_back(field_var + " = []");
      base_constructor.push_back(field_var + " = []");
    }

    switch (vectortype.base_type) {
      case BASE_TYPE_STRUCT: {
        code_.SetValue("VALUETYPE", GenType(vectortype, true));
        code_.SetValue("OPTIONAL", !vectortype.struct_def->fixed ? "?" : "");
        code_ +=
            "{{ACCESS_TYPE}} var {{FIELDVAR}}: [{{VALUETYPE}}{{OPTIONAL}}]";
        if (!vectortype.struct_def->fixed) {
          buffer_constructor.push_back("for val in _t." + field_field + "{");
          buffer_constructor.push_back(indentation + field_var +
                                       ".append(val.unpack())");
          buffer_constructor.push_back("}");
        } else {
          buffer_constructor.push_back(field_var + ".append(contentsOf: _t." +
                                       field_field + ")");
        }
        break;
      }
      case BASE_TYPE_ARRAY:
        FLATBUFFERS_FALLTHROUGH();
      case BASE_TYPE_VECTOR: {
        break;
      }
      case BASE_TYPE_UNION: {
        BuildUnionEnumSwitchCase(*field.value.type.enum_def, field_var,
                                 buffer_constructor, indentation, true);
        break;
      }
      case BASE_TYPE_UTYPE:
        break;
      default: {
        code_.SetValue(
            "VALUETYPE",
            (IsString(vectortype) ? "String?" : GenType(vectortype)));
        code_ += "{{ACCESS_TYPE}} var {{FIELDVAR}}: [{{VALUETYPE}}]";

        buffer_constructor.push_back(field_var + ".append(contentsOf: _t." +
                                     field_field + ")");
        break;
      }
    }
  }

  void BuildUnionEnumSwitchCaseWritter(const EnumDef& ed) {
    code_ += "switch type {";
    for (auto it = ed.Vals().begin(); it < ed.Vals().end(); ++it) {
      const auto ev = **it;
      const auto variant = namer_.LegacySwiftVariant(ev);
      const auto type = GenType(ev.union_type);
      const auto is_struct = IsStruct(ev.union_type) ? type + Mutable() : type;
      if (ev.union_type.base_type == BASE_TYPE_NONE) {
        continue;
      }
      code_ += "case ." + variant + ":";
      Indent();
      code_ += "var __obj = value as? " + GenType(ev.union_type, true);
      code_ += "return " + is_struct + ".pack(&builder, obj: &__obj)";
      Outdent();
    }
    code_ += "default: return Offset()";
    code_ += "}";
  }

  void BuildUnionEnumSwitchCase(const EnumDef& ed, const std::string& field,
                                std::vector<std::string>& buffer_constructor,
                                const std::string& indentation = "",
                                const bool is_vector = false) {
    const auto ns_type = namer_.NamespacedType(ed);
    code_.SetValue("VALUETYPE", ns_type);
    code_ += "{{ACCESS_TYPE}} var {{FIELDVAR}}: \\";
    code_ += is_vector ? "[{{VALUETYPE}}Union?]" : "{{VALUETYPE}}Union?";

    const auto vector_reader = is_vector ? "[index]" : "";
    if (is_vector) {
      buffer_constructor.push_back("let _" + field + "Type = _t." + field +
                                   "Type");
      buffer_constructor.push_back("for index in _" + field +
                                   "Type.startIndex..<_" + field +
                                   "Type.endIndex {");
    }

    buffer_constructor.push_back(indentation + "switch _t." + field + "Type" +
                                 vector_reader + " {");

    for (auto it = ed.Vals().begin(); it < ed.Vals().end(); ++it) {
      const auto ev = **it;
      const auto variant = namer_.LegacySwiftVariant(ev);
      if (ev.union_type.base_type == BASE_TYPE_NONE) {
        continue;
      }
      const auto type = IsStruct(ev.union_type)
                            ? GenType(ev.union_type) + Mutable()
                            : GenType(ev.union_type);

      buffer_constructor.push_back(indentation + "case ." + variant + ":");
      const auto constructor =
          ns_type + "Union(_v?.unpack(), type: ." + variant + ")";
      if (is_vector) {
        buffer_constructor.push_back(indentation + "  let _v = _t." + field +
                                     "(at: Int32(index), type: " + type +
                                     ".self)");
        buffer_constructor.push_back(indentation + "  " + field + ".append(" +
                                     constructor + ")");
      } else {
        buffer_constructor.push_back(indentation + "  let _v = _t." + field +
                                     "(" + "type: " + type + ".self)");
        buffer_constructor.push_back(indentation + "  " + field + " = " +
                                     constructor);
      }
    }
    buffer_constructor.push_back(indentation + "default: break");
    buffer_constructor.push_back(indentation + "}");
    if (is_vector) {
      buffer_constructor.push_back("}");
    }
  }

  void AddMinOrMaxEnumValue(const std::string& str, const std::string& type) {
    const auto current_value = str;
    code_.SetValue(type, current_value);
    code_ += "{{ACCESS_TYPE}} static var " + type +
             ": {{ENUM_NAME}} { return .{{" + type + "}} }";
  }

  void GenLookup(const FieldDef& key_field, const std::string& struct_type) {
    code_.SetValue("STRUCTTYPE", struct_type);
    code_.SetValue("OFFSET", NumToString(key_field.value.offset));
    std::string offset_reader =
        "Table.offset(Int32(fbb.capacity) - tableOffset, vOffset: {{OFFSET}}, "
        "fbb: fbb)";

    code_.SetValue("TYPE", GenType(key_field.value.type));
    code_ +=
        "fileprivate static func lookupByKey(vector: Int32, key: {{TYPE}}, "
        "fbb: "
        "ByteBuffer) -> {{STRUCTTYPE}}? {";
    Indent();
    if (IsString(key_field.value.type))
      code_ += "let key = key.utf8.map { $0 }";
    code_ += "var span = fbb.read(def: Int32.self, position: Int(vector - 4))";
    code_ += "var start: Int32 = 0";
    code_ += "while span != 0 {";
    Indent();
    code_ += "var middle = span / 2";
    code_ +=
        "let tableOffset = Table.indirect(vector + 4 * (start + middle), fbb)";
    if (IsString(key_field.value.type)) {
      code_ += "let comp = Table.compare(" + offset_reader + ", key, fbb: fbb)";
    } else {
      code_ += "let comp = fbb.read(def: {{TYPE}}.self, position: Int(" +
               offset_reader + "))";
    }

    code_ += "if comp > 0 {";
    Indent();
    code_ += "span = middle";
    Outdent();
    code_ += "} else if comp < 0 {";
    Indent();
    code_ += "middle += 1";
    code_ += "start += middle";
    code_ += "span -= middle";
    Outdent();
    code_ += "} else {";
    Indent();
    code_ += "return {{STRUCTTYPE}}(fbb, o: tableOffset)";
    Outdent();
    code_ += "}";
    Outdent();
    code_ += "}";
    code_ += "return nil";
    Outdent();
    code_ += "}";
  }

  inline void GenPadding(const FieldDef& field, int* id) {
    if (field.padding) {
      for (int i = 0; i < 4; i++) {
        if (static_cast<int>(field.padding) & (1 << i)) {
          const auto bits = (1 << i) * 8;
          code_ += "private var padding" + NumToString((*id)++) + "__: UInt" +
                   NumToString(bits) + " = 0";
        }
      }
      FLATBUFFERS_ASSERT(!(field.padding & ~0xF));
    }
  }

  void GenComment(const std::vector<std::string>& dc) {
    if (dc.begin() == dc.end()) {
      // Don't output empty comment blocks with 0 lines of comment content.
      return;
    }
    for (auto it = dc.begin(); it != dc.end(); ++it) {
      code_ += "/// " + *it;
    }
  }

  void GenOSVersionChecks() {
    if (parser_.advanced_features_ == reflection::AdvancedArrayFeatures) {
      code_ += "@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, *)";
    }
  }

  std::string GenOffset() {
    return "let o = {{ACCESS}}.offset({{TABLEOFFSET}}.{{OFFSET}}); ";
  }

  std::string GenReaderMainBody(const std::string& optional = "") {
    return "{{ACCESS_TYPE}} var {{FIELDVAR}}: {{VALUETYPE}}" + optional + " { ";
  }

  std::string GenReader(const std::string& type,
                        const std::string& at = "{{OFFSET}}") {
    return "{{ACCESS}}.readBuffer(of: {{" + type + "}}.self, at: " + at + ")";
  }

  std::string GenConstructor(const std::string& offset) {
    return "{{VALUETYPE}}({{ACCESS}}.bb, o: " + offset + ") }";
  }

  std::string GenMutate(const std::string& offset,
                        const std::string& get_offset, bool isRaw = false) {
    return "@discardableResult {{ACCESS_TYPE}} func mutate({{FIELDVAR}}: "
           "{{VALUETYPE}}) -> Bool {" +
           get_offset + " return {{ACCESS}}.mutate({{FIELDVAR}}" +
           (isRaw ? ".rawValue" : "") + ", index: " + offset + ") }";
  }

  std::string GenMutateArray() {
    return "{{ACCESS_TYPE}} func mutate({{FIELDVAR}}: {{VALUETYPE}}, at "
           "index: Int32) -> Bool { " +
           GenOffset() +
           "return {{ACCESS}}.directMutate({{FIELDVAR}}, index: "
           "{{ACCESS}}.vector(at: o) + index * {{SIZE}}) }";
  }

  std::string GenEnumDefaultValue(const FieldDef& field) {
    const auto& value = field.value;
    FLATBUFFERS_ASSERT(value.type.enum_def);
    const auto& enum_def = *value.type.enum_def;
    // Vector of enum defaults are always "[]" which never works.
    const std::string constant = IsVector(value.type) ? "0" : value.constant;
    const auto enum_val = enum_def.FindByValue(constant);
    if (enum_val) {
      return "." + namer_.LegacySwiftVariant(*enum_val);
    } else {
      const auto& ev = **enum_def.Vals().begin();
      return "." + namer_.LegacySwiftVariant(ev);
    }
  }

  std::string SwiftConstant(const FieldDef& field) {
    const auto default_value =
        StringIsFlatbufferNan(field.value.constant)                ? ".nan"
        : StringIsFlatbufferPositiveInfinity(field.value.constant) ? ".infinity"
        : StringIsFlatbufferNegativeInfinity(field.value.constant)
            ? "-.infinity"
        : IsBool(field.value.type.base_type)
            ? ("0" == field.value.constant ? "false" : "true")
            : field.value.constant;
    return default_value;
  }

  std::string GenEnumConstructor(const std::string& at) {
    return "{{VALUETYPE}}(rawValue: " + GenReader("BASEVALUE", at) + ") ";
  }

  std::string ValidateFunc() {
    return "static func validateVersion() { FlatBuffersVersion_25_12_19() }";
  }

  std::string GenType(const Type& type,
                      const bool should_consider_suffix = false) const {
    return IsScalar(type.base_type) ? GenTypeBasic(type)
           : IsArray(type)          ? GenType(type.VectorType())
                           : GenTypePointer(type, should_consider_suffix);
  }

  std::string GenTypePointer(const Type& type,
                             const bool should_consider_suffix) const {
    switch (type.base_type) {
      case BASE_TYPE_STRING:
        return "String";
      case BASE_TYPE_VECTOR:
        return GenType(type.VectorType());
      case BASE_TYPE_STRUCT: {
        const auto& sd = *type.struct_def;
        if (should_consider_suffix && !sd.fixed) {
          return namer_.NamespacedObjectType(sd);
        }
        return namer_.NamespacedType(sd);
      }
      case BASE_TYPE_UNION:
      default:
        return "FlatbuffersInitializable";
    }
  }

  std::string GenTypeBasic(const Type& type) const {
    return GenTypeBasic(type, true);
  }

  void Indent() { code_.IncrementIdentLevel(); }

  void Outdent() { code_.DecrementIdentLevel(); }

  std::string GenTypeBasic(const Type& type, bool can_override) const {
    // clang-format off
    static const char * const swift_type[] = {
      #define FLATBUFFERS_TD(ENUM, IDLTYPE, \
              CTYPE, JTYPE, GTYPE, NTYPE, PTYPE, RTYPE, KTYPE, STYPE, ...) \
        #STYPE,
        FLATBUFFERS_GEN_TYPES(FLATBUFFERS_TD)
      #undef FLATBUFFERS_TD
    };
    // clang-format on
    if (can_override) {
      if (type.enum_def) return namer_.NamespacedType(*type.enum_def);
      if (type.base_type == BASE_TYPE_BOOL) return "Bool";
    }
    return swift_type[static_cast<int>(type.base_type)];
  }

  std::string Mutable() const { return "_Mutable"; }

  IdlNamer namer_;
};
}  // namespace swift

static bool GenerateSwift(const Parser& parser, const std::string& path,
                          const std::string& file_name) {
  swift::SwiftGenerator generator(parser, path, file_name);
  return generator.generate();
}

namespace {

class SwiftCodeGenerator : public CodeGenerator {
 public:
  Status GenerateCode(const Parser& parser, const std::string& path,
                      const std::string& filename) override {
    if (!GenerateSwift(parser, path, filename)) {
      return Status::ERROR;
    }
    return Status::OK;
  }

  Status GenerateCode(const uint8_t*, int64_t, const CodeGenOptions&) override {
    return Status::NOT_IMPLEMENTED;
  }

  Status GenerateGrpcCode(const Parser& parser, const std::string& path,
                          const std::string& filename) override {
    if (!GenerateSwiftGRPC(parser, path, filename)) {
      return Status::ERROR;
    }
    return Status::OK;
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

  Status GenerateRootFile(const Parser& parser,
                          const std::string& path) override {
    (void)parser;
    (void)path;
    return Status::NOT_IMPLEMENTED;
  }

  bool IsSchemaOnly() const override { return true; }

  bool SupportsBfbsGeneration() const override { return false; }

  bool SupportsRootFileGeneration() const override { return false; }

  IDLOptions::Language Language() const override { return IDLOptions::kSwift; }

  std::string LanguageName() const override { return "Swift"; }
};
}  // namespace

std::unique_ptr<CodeGenerator> NewSwiftCodeGenerator() {
  return std::unique_ptr<SwiftCodeGenerator>(new SwiftCodeGenerator());
}

}  // namespace flatbuffers
