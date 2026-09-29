/*
 * Copyright 2014 Google Inc. All rights reserved.
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

// independent from idl_parser, since this code is not needed for most clients

#include "idl_gen_php.h"

#include <set>
#include <string>

#include "flatbuffers/code_generators.h"
#include "flatbuffers/flatbuffers.h"
#include "flatbuffers/idl.h"
#include "flatbuffers/util.h"
#include "idl_gen_encryption.h"

namespace flatbuffers {
namespace php {
// Hardcode spaces per indentation.
const std::string Indent = "    ";
class PhpGenerator : public BaseGenerator {
 public:
  PhpGenerator(const Parser& parser, const std::string& path,
               const std::string& file_name)
      : BaseGenerator(parser, path, file_name, "\\", "\\", "php"),
        encryption_plan_(parser) {}
  bool generate() {
    if (!GenerateEnums()) return false;
    if (!GenerateStructs()) return false;
    return true;
  }

 private:
  bool GenerateEnums() {
    for (auto it = parser_.enums_.vec.begin(); it != parser_.enums_.vec.end();
         ++it) {
      auto& enum_def = **it;
      std::string enumcode;
      GenEnum(enum_def, &enumcode);
      if (!SaveType(enum_def, enumcode, false)) return false;
    }
    return true;
  }

  bool GenerateStructs() {
    // Namespaces that got a FlatbuffersEncryption class.
    std::set<std::string> encryption_namespaces;
    for (auto it = parser_.structs_.vec.begin();
         it != parser_.structs_.vec.end(); ++it) {
      auto& struct_def = **it;
      std::string declcode;
      GenStruct(struct_def, &declcode);
      if (!SaveType(struct_def, declcode, true)) return false;
      if (!struct_def.generated && encryption_plan_.NeedsWalk(struct_def) &&
          encryption_namespaces
              .insert(FullNamespace("\\", *struct_def.defined_namespace))
              .second &&
          !GenerateEncryptionClass(*struct_def.defined_namespace)) {
        return false;
      }
    }
    return true;
  }

  // The FlatbuffersEncryption helper (field-encryption format 3) of a
  // namespace: the openssl and hash extensions.
  bool GenerateEncryptionClass(const Namespace& ns) {
    std::string code;
    BeginFile(FullNamespace("\\", ns), false, &code);
    code += R"PHP(/**
 * Field-encryption format 3: encrypts or decrypts every (encrypted) field
 * instance of a buffer exactly as the C++ walker
 * (flatbuffers::EncryptBuffer/DecryptBuffer, version 3) and flatc-wasm do.
 * The record's key is
 * K = HKDF-SHA256(key, no salt, "flatbuffers-buffer-v3" || BE32(recordIndex)),
 * and each instance is AES-256-CTR encrypted with K and the IV
 * BE32(position of its first byte in the buffer) || 12 zero bytes, so no two
 * instances share a key stream. (key, recordIndex) must be unique per buffer.
 * Generated tables call it with their walk program.
 */
class FlatbuffersEncryption
{
    private $buf;
    private $size;
    private $program;
    private $key; // null: a dry run that only checks the buffer
    private $tables = array();
    private $regions = array();

    private function __construct($buf, array $program, $key)
    {
        $this->buf = $buf;
        $this->size = strlen($buf);
        $this->program = $program;
        $this->key = $key;
    }

    /**
     * HKDF-SHA256(key, no salt, "flatbuffers-buffer-v3" || BE32(recordIndex)).
     */
    public static function bufferKey($key, $recordIndex)
    {
        $prk = hash_hmac('sha256', $key, str_repeat("\0", 32), true);
        $info = 'flatbuffers-buffer-v3' . pack('N', $recordIndex) . "\1";
        return hash_hmac('sha256', $info, $prk, true);
    }

    /**
     * Returns a copy of $bytes with every (encrypted) field instance
     * encrypted, or decrypted (the same operation), by a table's walk
     * program.
     * @throws \InvalidArgumentException for a bad key or a malformed buffer
     */
    public static function cryptBuffer($bytes, $key, $recordIndex, array $program)
    {
        if (!is_string($key) || strlen($key) !== 32) {
            throw new \InvalidArgumentException('FlatbuffersEncryption: the key must be 32 bytes');
        }
        if (!is_int($recordIndex) || $recordIndex < 0 || $recordIndex > 0xFFFFFFFF) {
            throw new \InvalidArgumentException('FlatbuffersEncryption: recordIndex must fit in 32 bits');
        }
        if (!is_string($bytes) || strlen($bytes) < 4 || strlen($bytes) > 0x7FFFFFFF) {
            throw new \InvalidArgumentException('FlatbuffersEncryption: invalid buffer');
        }
        $dry = new FlatbuffersEncryption($bytes, $program, null);
        $root = $dry->u32(0);
        $dry->check($root, 4);
        $dry->walk(0, $root, 0);
        $walk = new FlatbuffersEncryption($bytes, $program, self::bufferKey($key, $recordIndex));
        $walk->walk(0, $root, 0);
        return $walk->buf;
    }

    private static function fail($what)
    {
        throw new \InvalidArgumentException('FlatbuffersEncryption: ' . $what);
    }

    private function check($pos, $length)
    {
        if ($pos < 0 || $length < 0 || $pos > $this->size || $length > $this->size - $pos) {
            self::fail('the buffer is malformed (offset ' . $pos . ' out of bounds)');
        }
    }

    private function u8($pos)
    {
        $this->check($pos, 1);
        return ord($this->buf[$pos]);
    }

    private function u16($pos)
    {
        $this->check($pos, 2);
        $value = unpack('v', substr($this->buf, $pos, 2));
        return $value[1];
    }

    private function u32($pos)
    {
        $this->check($pos, 4);
        $value = unpack('V', substr($this->buf, $pos, 4));
        return $value[1];
    }

    private function follow($pos)
    {
        $target = $pos + $this->u32($pos);
        $this->check($target, 4);
        return $target;
    }

    private function count($pos, $elementSize)
    {
        $n = $this->u32($pos);
        $this->check($pos + 4, $n * $elementSize);
        return $n;
    }

    private function crypt($start, $length)
    {
        if ($length === 0 || isset($this->regions[$start])) {
            return;
        }
        $this->regions[$start] = true;
        if ($this->key === null) {
            return;
        }
        $iv = pack('N', $start) . str_repeat("\0", 12);
        $out = openssl_encrypt(substr($this->buf, $start, $length), 'aes-256-ctr',
            $this->key, OPENSSL_RAW_DATA, $iv);
        $this->buf = substr_replace($this->buf, $out, $start, $length);
    }

    private function str($pos)
    {
        $s = $this->follow($pos);
        $n = $this->u32($s);
        $this->check($s + 4, $n + 1);
        $this->crypt($s + 4, $n);
    }

    private function vtable($table)
    {
        $soffset = $this->u32($table);
        if ($soffset >= 0x80000000) {
            $soffset -= 0x100000000;
        }
        return $table - $soffset;
    }

    private function field($table, $slot)
    {
        $vtable = $this->vtable($table);
        if ($slot + 2 > $this->u16($vtable)) {
            return 0;
        }
        $offset = $this->u16($vtable + $slot);
        return $offset === 0 ? 0 : $table + $offset;
    }

    private function enter($table, $depth)
    {
        if ($depth > 64) {
            self::fail('tables nested deeper than 64 levels');
        }
        if (isset($this->tables[$table])) {
            return false;
        }
        $this->tables[$table] = true;
        $vtable = $this->vtable($table);
        $this->check($vtable, 4);
        $vtableSize = $this->u16($vtable);
        $tableSize = $this->u16($vtable + 2);
        if ($vtableSize < 4 || ($vtableSize & 1) !== 0) {
            self::fail('the buffer is malformed (bad vtable)');
        }
        $this->check($vtable, $vtableSize);
        $this->check($table, $tableSize);
        for ($slot = 4; $slot < $vtableSize; $slot += 2) {
            $offset = $this->u16($vtable + $slot);
            if ($offset !== 0 && $offset >= $tableSize) {
                self::fail('the buffer is malformed (bad field offset)');
            }
        }
        return true;
    }

    private function member($at, $n, $unionType)
    {
        for ($i = 0; $i < $n; $i++) {
            if ($this->program[$at + 2 * $i] === $unionType) {
                return $this->program[$at + 2 * $i + 1];
            }
        }
        return -1;
    }

)PHP";
    code += R"PHP(    private function walk($index, $table, $depth)
    {
        if (!$this->enter($table, $depth)) {
            return;
        }
        $p = $this->program;
        $at = $p[1 + $index];
        $ops = $p[$at++];
        for ($op = 0; $op < $ops; $op++) {
            $kind = $p[$at];
            $slot = $p[$at + 1];
            $at += 2;
            $arg = 0;
            $typeSlot = 0;
            $members = 0;
            $n = 0;
            if ($kind === 0 || $kind === 2 || $kind === 4 || $kind === 5) {
                $arg = $p[$at++];
            } elseif ($kind === 6 || $kind === 7) {
                $typeSlot = $p[$at];
                $n = $p[$at + 1];
                $members = $at + 2;
                $at += 2 + 2 * $n;
            }
            $loc = $this->field($table, $slot);
            if ($loc === 0) {
                continue;
            }
            switch ($kind) {
                case 0:
                    $this->check($loc, $arg);
                    $this->crypt($loc, $arg);
                    break;
                case 1:
                    $this->str($loc);
                    break;
                case 2:
                    $v = $this->follow($loc);
                    $this->crypt($v + 4, $this->count($v, $arg) * $arg);
                    break;
                case 3:
                    $v = $this->follow($loc);
                    $c = $this->count($v, 4);
                    for ($i = 0; $i < $c; $i++) {
                        $this->str($v + 4 + 4 * $i);
                    }
                    break;
                case 4:
                    $this->walk($arg, $this->follow($loc), $depth + 1);
                    break;
                case 5:
                    $v = $this->follow($loc);
                    $c = $this->count($v, 4);
                    for ($i = 0; $i < $c; $i++) {
                        $this->walk($arg, $this->follow($v + 4 + 4 * $i), $depth + 1);
                    }
                    break;
                case 6:
                    $typeLoc = $this->field($table, $typeSlot);
                    if ($typeLoc === 0) {
                        break;
                    }
                    $member = $this->member($members, $n, $this->u8($typeLoc));
                    if ($member >= 0) {
                        $this->walk($member, $this->follow($loc), $depth + 1);
                    }
                    break;
                case 7:
                    $typeLoc = $this->field($table, $typeSlot);
                    if ($typeLoc === 0) {
                        break;
                    }
                    $types = $this->follow($typeLoc);
                    $c = $this->count($types, 1);
                    $values = $this->follow($loc);
                    if ($this->count($values, 4) !== $c) {
                        self::fail('the buffer is malformed (union vectors differ)');
                    }
                    for ($i = 0; $i < $c; $i++) {
                        $member = $this->member($members, $n, $this->u8($types + 4 + $i));
                        if ($member >= 0) {
                            $this->walk($member, $this->follow($values + 4 + 4 * $i), $depth + 1);
                        }
                    }
                    break;
                default:
                    self::fail('unknown walk program op ' . $kind);
            }
        }
    }
}
)PHP";
    const std::string filename = NamespaceDir(ns) + "FlatbuffersEncryption.php";
    return parser_.opts.file_saver->SaveFile(filename.c_str(), code, false);
  }

  // encryptBuffer/decryptBuffer of a table that reaches an (encrypted) field.
  void GenEncryptionMethods(const StructDef& struct_def,
                            std::string* code_ptr) const {
    std::string& code = *code_ptr;
    code += Indent + "// Field-encryption format 3 walk program of " +
            struct_def.name + " (see FlatbuffersEncryption).\n";
    code += Indent + "const FLATBUFFERS_ENCRYPTION_PROGRAM = array(\n";
    for (const auto& line : encryption_plan_.ProgramLines(struct_def)) {
      code += Indent + Indent + line + "\n";
    }
    code += Indent + ");\n\n";
    const char* kVerbs[] = { "encrypt", "decrypt" };
    const char* kParticiples[] = { "encrypted", "decrypted" };
    for (int i = 0; i < 2; i++) {
      code += Indent + "/**\n";
      code += Indent + " * Returns a copy of a " + struct_def.name +
              " buffer (a string) with its (encrypted) fields\n";
      code += Indent + " * " + std::string(kParticiples[i]) +
              " with field-encryption format 3 ($key: 32 bytes; "
              "$recordIndex:\n";
      code += Indent + " * unique per buffer under the key).\n";
      code += Indent + " * @throws \\InvalidArgumentException for a bad key "
              "or a malformed buffer\n";
      code += Indent + " */\n";
      code += Indent + "public static function " + std::string(kVerbs[i]) +
              "Buffer($bytes, $key, $recordIndex = 0)\n";
      code += Indent + "{\n";
      code += Indent + Indent +
              "return FlatbuffersEncryption::cryptBuffer($bytes, $key, "
              "$recordIndex, self::FLATBUFFERS_ENCRYPTION_PROGRAM);\n";
      code += Indent + "}\n\n";
    }
  }

  // Begin by declaring namespace and imports.
  void BeginFile(const std::string& name_space_name, const bool needs_imports,
                 std::string* code_ptr) {
    auto& code = *code_ptr;
    code += "<?php\n";
    code = code + "// " + FlatBuffersGeneratedWarning() + "\n\n";

    if (!name_space_name.empty()) {
      code += "namespace " + name_space_name + ";\n\n";
    }

    if (needs_imports) {
      code += "use \\Google\\FlatBuffers\\Struct;\n";
      code += "use \\Google\\FlatBuffers\\Table;\n";
      code += "use \\Google\\FlatBuffers\\ByteBuffer;\n";
      code += "use \\Google\\FlatBuffers\\FlatBufferBuilder;\n";
      code += "\n";
    }
  }

  // Save out the generated code for a Php Table type.
  bool SaveType(const Definition& def, const std::string& classcode,
                bool needs_imports) {
    if (!classcode.length()) return true;

    std::string code = "";
    BeginFile(FullNamespace("\\", *def.defined_namespace), needs_imports,
              &code);
    code += classcode;

    std::string filename =
        NamespaceDir(*def.defined_namespace) + def.name + ".php";
    return parser_.opts.file_saver->SaveFile(filename.c_str(), code, false);
  }

  // Begin a class declaration.
  static void BeginClass(const StructDef& struct_def, std::string* code_ptr) {
    std::string& code = *code_ptr;
    if (struct_def.fixed) {
      code += "class " + struct_def.name + " extends Struct\n";
    } else {
      code += "class " + struct_def.name + " extends Table\n";
    }
    code += "{\n";
  }

  static void EndClass(std::string* code_ptr) {
    std::string& code = *code_ptr;
    code += "}\n";
  }

  // Begin enum code with a class declaration.
  static void BeginEnum(const std::string& class_name, std::string* code_ptr) {
    std::string& code = *code_ptr;
    code += "class " + class_name + "\n{\n";
  }

  // A single enum member.
  static void EnumMember(const EnumDef& enum_def, const EnumVal& ev,
                         std::string* code_ptr) {
    std::string& code = *code_ptr;
    code += Indent + "const ";
    code += ev.name;
    code += " = ";
    code += enum_def.ToString(ev) + ";\n";
  }

  // End enum code.
  static void EndEnum(std::string* code_ptr) {
    std::string& code = *code_ptr;
    code += "}\n";
  }

  // Initialize a new struct or table from existing data.
  static void NewRootTypeFromBuffer(const StructDef& struct_def,
                                    std::string* code_ptr) {
    std::string& code = *code_ptr;

    code += Indent + "/**\n";
    code += Indent + " * @param ByteBuffer $bb\n";
    code += Indent + " * @return " + struct_def.name + "\n";
    code += Indent + " */\n";
    code += Indent + "public static function getRootAs";
    code += struct_def.name;
    code += "(ByteBuffer $bb)\n";
    code += Indent + "{\n";

    code += Indent + Indent + "$obj = new " + struct_def.name + "();\n";
    code += Indent + Indent;
    code += "return ($obj->init($bb->getInt($bb->getPosition())";
    code += " + $bb->getPosition(), $bb));\n";
    code += Indent + "}\n\n";
  }

  // Initialize an existing object with other data, to avoid an allocation.
  static void InitializeExisting(const StructDef& struct_def,
                                 std::string* code_ptr) {
    std::string& code = *code_ptr;

    code += Indent + "/**\n";
    code += Indent + " * @param int $_i offset\n";
    code += Indent + " * @param ByteBuffer $_bb\n";
    code += Indent + " * @return " + struct_def.name + "\n";
    code += Indent + " **/\n";
    code += Indent + "public function init($_i, ByteBuffer $_bb)\n";
    code += Indent + "{\n";
    code += Indent + Indent + "$this->bb_pos = $_i;\n";
    code += Indent + Indent + "$this->bb = $_bb;\n";
    code += Indent + Indent + "return $this;\n";
    code += Indent + "}\n\n";
  }

  // Get the length of a vector.
  static void GetVectorLen(const FieldDef& field, std::string* code_ptr) {
    std::string& code = *code_ptr;

    code += Indent + "/**\n";
    code += Indent + " * @return int\n";
    code += Indent + " */\n";
    code += Indent + "public function get";
    code += ConvertCase(field.name, Case::kUpperCamel) + "Length()\n";
    code += Indent + "{\n";
    code += Indent + Indent + "$o = $this->__offset(";
    code += NumToString(field.value.offset) + ");\n";
    code += Indent + Indent;
    code += "return $o != 0 ? $this->__vector_len($o) : 0;\n";
    code += Indent + "}\n\n";
  }

  // Get a [ubyte] vector as a byte array.
  static void GetUByte(const FieldDef& field, std::string* code_ptr) {
    std::string& code = *code_ptr;

    code += Indent + "/**\n";
    code += Indent + " * @return string\n";
    code += Indent + " */\n";
    code += Indent + "public function get";
    code += ConvertCase(field.name, Case::kUpperCamel) + "Bytes()\n";
    code += Indent + "{\n";
    code += Indent + Indent + "return $this->__vector_as_bytes(";
    code += NumToString(field.value.offset) + ");\n";
    code += Indent + "}\n\n";
  }

  // Get the value of a struct's scalar.
  static void GetScalarFieldOfStruct(const FieldDef& field,
                                     std::string* code_ptr) {
    std::string& code = *code_ptr;
    std::string getter = GenGetter(field.value.type);

    code += Indent + "/**\n";
    code += Indent + " * @return ";
    code += GenTypeGet(field.value.type) + "\n";
    code += Indent + " */\n";
    code += Indent + "public function " + getter;
    code += ConvertCase(field.name, Case::kUpperCamel) + "()\n";
    code += Indent + "{\n";
    code += Indent + Indent + "return ";

    code += "$this->bb->get";
    code += ConvertCase(GenTypeGet(field.value.type), Case::kUpperCamel);
    code += "($this->bb_pos + ";
    code += NumToString(field.value.offset) + ")";
    code += ";\n";

    code += Indent + "}\n\n";
  }

  // Get the value of a table's scalar.
  void GetScalarFieldOfTable(const FieldDef& field, std::string* code_ptr) {
    std::string& code = *code_ptr;

    code += Indent + "/**\n";
    code += Indent + " * @return " + GenTypeGet(field.value.type) + "\n";
    code += Indent + " */\n";
    code += Indent + "public function get";
    code += ConvertCase(field.name, Case::kUpperCamel);
    code += "()\n";
    code += Indent + "{\n";
    code += Indent + Indent + "$o = $this->__offset(" +
            NumToString(field.value.offset) + ");\n" + Indent + Indent +
            "return $o != 0 ? ";
    code += "$this->bb->get";
    code += ConvertCase(GenTypeGet(field.value.type), Case::kUpperCamel) +
            "($o + $this->bb_pos)";
    code += " : " + GenDefaultValue(field.value) + ";\n";
    code += Indent + "}\n\n";
  }

  // Get a struct by initializing an existing struct.
  // Specific to Struct.
  void GetStructFieldOfStruct(const FieldDef& field, std::string* code_ptr) {
    std::string& code = *code_ptr;

    code += Indent + "/**\n";
    code += Indent + " * @return " + GenTypeGet(field.value.type) + "\n";
    code += Indent + " */\n";
    code += Indent + "public function get";
    code += ConvertCase(field.name, Case::kUpperCamel) + "()\n";
    code += Indent + "{\n";
    code += Indent + Indent + "$obj = new ";
    code += GenTypeGet(field.value.type) + "();\n";
    code += Indent + Indent + "$obj->init($this->bb_pos + ";
    code += NumToString(field.value.offset) + ", $this->bb);";
    code += "\n" + Indent + Indent + "return $obj;\n";
    code += Indent + "}\n\n";
  }

  // Get a struct by initializing an existing struct.
  // Specific to Table.
  void GetStructFieldOfTable(const FieldDef& field, std::string* code_ptr) {
    std::string& code = *code_ptr;

    code += Indent + "public function get";
    code += ConvertCase(field.name, Case::kUpperCamel);
    code += "()\n";
    code += Indent + "{\n";
    code += Indent + Indent + "$obj = new ";
    code +=
        ConvertCase(GenTypeGet(field.value.type), Case::kUpperCamel) + "();\n";
    code += Indent + Indent + "$o = $this->__offset(" +
            NumToString(field.value.offset) + ");\n";
    code += Indent + Indent;
    code += "return $o != 0 ? $obj->init(";
    if (field.value.type.struct_def->fixed) {
      code += "$o + $this->bb_pos, $this->bb) : ";
    } else {
      code += "$this->__indirect($o + $this->bb_pos), $this->bb) : ";
    }
    code += GenDefaultValue(field.value) + ";\n";
    code += Indent + "}\n\n";
  }

  // Get the value of a string.
  void GetStringField(const FieldDef& field, std::string* code_ptr) {
    std::string& code = *code_ptr;
    code += Indent + "public function get";
    code += ConvertCase(field.name, Case::kUpperCamel);
    code += "()\n";
    code += Indent + "{\n";
    code += Indent + Indent + "$o = $this->__offset(" +
            NumToString(field.value.offset) + ");\n";
    code += Indent + Indent;
    code += "return $o != 0 ? $this->__string($o + $this->bb_pos) : ";
    code += GenDefaultValue(field.value) + ";\n";
    code += Indent + "}\n\n";
  }

  // Get the value of a union from an object.
  void GetUnionField(const FieldDef& field, std::string* code_ptr) {
    std::string& code = *code_ptr;

    code += Indent + "/**\n";
    code += Indent + " * @return" + GenTypeBasic(field.value.type) + "\n";
    code += Indent + " */\n";
    code += Indent + "public function get";
    code += ConvertCase(field.name, Case::kUpperCamel) + "($obj)\n";
    code += Indent + "{\n";
    code += Indent + Indent + "$o = $this->__offset(" +
            NumToString(field.value.offset) + ");\n";
    code += Indent + Indent;
    code += "return $o != 0 ? $this->__union($obj, $o) : null;\n";
    code += Indent + "}\n\n";
  }

  // Get the value of a vector's struct member.
  void GetMemberOfVectorOfStruct(const StructDef& struct_def,
                                 const FieldDef& field, std::string* code_ptr) {
    std::string& code = *code_ptr;
    auto vectortype = field.value.type.VectorType();

    code += Indent + "/**\n";
    code += Indent + " * @return" + GenTypeBasic(field.value.type) + "\n";
    code += Indent + " */\n";
    code += Indent + "public function get";
    code += ConvertCase(field.name, Case::kUpperCamel);
    code += "($j)\n";
    code += Indent + "{\n";
    code += Indent + Indent + "$o = $this->__offset(" +
            NumToString(field.value.offset) + ");\n";
    code += Indent + Indent + "$obj = new ";
    code +=
        ConvertCase(GenTypeGet(field.value.type), Case::kUpperCamel) + "();\n";

    switch (field.value.type.base_type) {
      case BASE_TYPE_STRUCT:
        if (struct_def.fixed) {
          code += Indent + Indent;
          code += "return $o != 0 ? $obj->init($this->bb_pos +" +
                  NumToString(field.value.offset) + ", $this->bb) : null;\n";
        } else {
          code += Indent + Indent + "return $o != 0 ? $obj->init(";
          code += field.value.type.struct_def->fixed
                      ? "$o + $this->bb_pos"
                      : "$this->__indirect($o + $this->bb_pos)";
          code += ", $this->bb) : null;\n";
        }
        break;
      case BASE_TYPE_STRING:
        code += "// base_type_string\n";
        // TODO(chobie): do we need this?
        break;
      case BASE_TYPE_VECTOR:
        if (vectortype.base_type == BASE_TYPE_STRUCT) {
          code += Indent + Indent + "return $o != 0 ? $obj->init(";
          if (vectortype.struct_def->fixed) {
            code += "$this->__vector($o) + $j *";
            code += NumToString(InlineSize(vectortype));
          } else {
            code += "$this->__indirect($this->__vector($o) + $j * ";
            code += NumToString(InlineSize(vectortype)) + ")";
          }
          code += ", $this->bb) : null;\n";
        }
        break;
      case BASE_TYPE_UNION:
        code += Indent + Indent + "return $o != 0 ? $this->";
        code += GenGetter(field.value.type) + "($obj, $o); null;\n";
        break;
      default:
        break;
    }

    code += Indent + "}\n\n";
  }

  // Get the value of a vector's non-struct member. Uses a named return
  // argument to conveniently set the zero value for the result.
  void GetMemberOfVectorOfNonStruct(const FieldDef& field,
                                    std::string* code_ptr) {
    std::string& code = *code_ptr;
    auto vectortype = field.value.type.VectorType();

    code += Indent + "/**\n";
    code += Indent + " * @param int offset\n";
    code += Indent + " * @return " + GenTypeGet(field.value.type) + "\n";
    code += Indent + " */\n";
    code += Indent + "public function get";
    code += ConvertCase(field.name, Case::kUpperCamel);
    code += "($j)\n";
    code += Indent + "{\n";
    code += Indent + Indent + "$o = $this->__offset(" +
            NumToString(field.value.offset) + ");\n";

    if (IsString(field.value.type.VectorType())) {
      code += Indent + Indent;
      code += "return $o != 0 ? $this->__string($this->__vector($o) + $j * ";
      code += NumToString(InlineSize(vectortype)) + ") : ";
      code += GenDefaultValue(field.value) + ";\n";
    } else {
      code += Indent + Indent + "return $o != 0 ? $this->bb->get";
      code += ConvertCase(GenTypeGet(field.value.type), Case::kUpperCamel);
      code += "($this->__vector($o) + $j * ";
      code += NumToString(InlineSize(vectortype)) + ") : ";
      code += GenDefaultValue(field.value) + ";\n";
    }
    code += Indent + "}\n\n";
  }

  // Get the value of a vector's union member. Uses a named return
  // argument to conveniently set the zero value for the result.
  void GetMemberOfVectorOfUnion(const FieldDef& field, std::string* code_ptr) {
    std::string& code = *code_ptr;
    auto vectortype = field.value.type.VectorType();

    code += Indent + "/**\n";
    code += Indent + " * @param int offset\n";
    code += Indent + " * @return " + GenTypeGet(field.value.type) + "\n";
    code += Indent + " */\n";
    code += Indent + "public function get";
    code += ConvertCase(field.name, Case::kUpperCamel);
    code += "($j, $obj)\n";
    code += Indent + "{\n";
    code += Indent + Indent + "$o = $this->__offset(" +
            NumToString(field.value.offset) + ");\n";
    code += Indent + Indent + "return $o != 0 ? ";
    code += "$this->__union($obj, $this->__vector($o) + $j * ";
    code += NumToString(InlineSize(vectortype)) + " - $this->bb_pos) : null;\n";
    code += Indent + "}\n\n";
  }

  // Recursively generate arguments for a constructor, to deal with nested
  // structs.
  static void StructBuilderArgs(const StructDef& struct_def,
                                const char* nameprefix, std::string* code_ptr) {
    for (auto it = struct_def.fields.vec.begin();
         it != struct_def.fields.vec.end(); ++it) {
      auto& field = **it;
      if (IsStruct(field.value.type)) {
        // Generate arguments for a struct inside a struct. To ensure names
        // don't clash, and to make it obvious
        // these arguments are constructing
        // a nested struct, prefix the name with the field name.
        StructBuilderArgs(*field.value.type.struct_def,
                          (nameprefix + (field.name + "_")).c_str(), code_ptr);
      } else {
        std::string& code = *code_ptr;
        code += std::string(", $") + nameprefix;
        code += ConvertCase(field.name, Case::kLowerCamel);
      }
    }
  }

  // Recursively generate struct construction statements and instert manual
  // padding.
  static void StructBuilderBody(const StructDef& struct_def,
                                const char* nameprefix, std::string* code_ptr) {
    std::string& code = *code_ptr;
    code += Indent + Indent + "$builder->prep(";
    code += NumToString(struct_def.minalign) + ", ";
    code += NumToString(struct_def.bytesize) + ");\n";
    for (auto it = struct_def.fields.vec.rbegin();
         it != struct_def.fields.vec.rend(); ++it) {
      auto& field = **it;
      if (field.padding) {
        code += Indent + Indent + "$builder->pad(";
        code += NumToString(field.padding) + ");\n";
      }
      if (IsStruct(field.value.type)) {
        StructBuilderBody(*field.value.type.struct_def,
                          (nameprefix + (field.name + "_")).c_str(), code_ptr);
      } else {
        code += Indent + Indent + "$builder->put" + GenMethod(field) + "($";
        code +=
            nameprefix + ConvertCase(field.name, Case::kLowerCamel) + ");\n";
      }
    }
  }

  // Get the value of a table's starting offset.
  static void GetStartOfTable(const StructDef& struct_def,
                              std::string* code_ptr) {
    std::string& code = *code_ptr;

    code += Indent + "/**\n";
    code += Indent + " * @param FlatBufferBuilder $builder\n";
    code += Indent + " * @return void\n";
    code += Indent + " */\n";
    code += Indent + "public static function start" + struct_def.name;
    code += "(FlatBufferBuilder $builder)\n";
    code += Indent + "{\n";
    code += Indent + Indent + "$builder->StartObject(";
    code += NumToString(struct_def.fields.vec.size());
    code += ");\n";
    code += Indent + "}\n\n";

    code += Indent + "/**\n";
    code += Indent + " * @param FlatBufferBuilder $builder\n";
    code += Indent + " * @return " + struct_def.name + "\n";
    code += Indent + " */\n";
    code += Indent + "public static function create" + struct_def.name;
    code += "(FlatBufferBuilder $builder, ";

    for (auto it = struct_def.fields.vec.begin();
         it != struct_def.fields.vec.end(); ++it) {
      auto& field = **it;

      if (field.deprecated) continue;
      if (it != struct_def.fields.vec.begin()) {
        code += ", ";
      }
      code += "$" + field.name;
    }
    code += ")\n";
    code += Indent + "{\n";
    code += Indent + Indent + "$builder->startObject(";
    code += NumToString(struct_def.fields.vec.size());
    code += ");\n";
    for (auto it = struct_def.fields.vec.begin();
         it != struct_def.fields.vec.end(); ++it) {
      auto& field = **it;
      if (field.deprecated) continue;

      code += Indent + Indent + "self::add";
      code += ConvertCase(field.name, Case::kUpperCamel) + "($builder, $" +
              field.name + ");\n";
    }

    code += Indent + Indent + "$o = $builder->endObject();\n";

    for (auto it = struct_def.fields.vec.begin();
         it != struct_def.fields.vec.end(); ++it) {
      auto& field = **it;
      if (!field.deprecated && field.IsRequired()) {
        code += Indent + Indent + "$builder->required($o, ";
        code += NumToString(field.value.offset);
        code += ");  // " + field.name + "\n";
      }
    }
    code += Indent + Indent + "return $o;\n";
    code += Indent + "}\n\n";
  }

  // Set the value of a table's field.
  static void BuildFieldOfTable(const FieldDef& field, const size_t offset,
                                std::string* code_ptr) {
    std::string& code = *code_ptr;

    code += Indent + "/**\n";
    code += Indent + " * @param FlatBufferBuilder $builder\n";
    code += Indent + " * @param " + GenTypeBasic(field.value.type) + "\n";
    code += Indent + " * @return void\n";
    code += Indent + " */\n";
    code += Indent + "public static function ";
    code += "add" + ConvertCase(field.name, Case::kUpperCamel);
    code += "(FlatBufferBuilder $builder, ";
    code += "$" + ConvertCase(field.name, Case::kLowerCamel);
    code += ")\n";
    code += Indent + "{\n";
    code += Indent + Indent + "$builder->add";
    code += GenMethod(field) + "X(";
    code += NumToString(offset) + ", ";

    code += "$" + ConvertCase(field.name, Case::kLowerCamel);
    code += ", ";

    if (field.value.type.base_type == BASE_TYPE_BOOL) {
      code += "false";
    } else {
      code += field.value.constant;
    }
    code += ");\n";
    code += Indent + "}\n\n";
  }

  // Set the value of one of the members of a table's vector.
  static void BuildVectorOfTable(const FieldDef& field, std::string* code_ptr) {
    std::string& code = *code_ptr;

    auto vector_type = field.value.type.VectorType();
    auto alignment = InlineAlignment(vector_type);
    auto elem_size = InlineSize(vector_type);
    code += Indent + "/**\n";
    code += Indent + " * @param FlatBufferBuilder $builder\n";
    code += Indent + " * @param array offset array\n";
    code += Indent + " * @return int vector offset\n";
    code += Indent + " */\n";
    code += Indent + "public static function create";
    code += ConvertCase(field.name, Case::kUpperCamel);
    code += "Vector(FlatBufferBuilder $builder, array $data)\n";
    code += Indent + "{\n";
    code += Indent + Indent + "$builder->startVector(";
    code += NumToString(elem_size);
    code += ", count($data), " + NumToString(alignment);
    code += ");\n";
    code += Indent + Indent;
    code += "for ($i = count($data) - 1; $i >= 0; $i--) {\n";
    if (IsScalar(field.value.type.VectorType().base_type)) {
      code += Indent + Indent + Indent;
      code += "$builder->put";
      code += ConvertCase(GenTypeBasic(field.value.type.VectorType()),
                          Case::kUpperCamel);
      code += "($data[$i]);\n";
    } else {
      code += Indent + Indent + Indent;
      code += "$builder->putOffset($data[$i]);\n";
    }
    code += Indent + Indent + "}\n";
    code += Indent + Indent + "return $builder->endVector();\n";
    code += Indent + "}\n\n";

    code += Indent + "/**\n";
    code += Indent + " * @param FlatBufferBuilder $builder\n";
    code += Indent + " * @param int $numElems\n";
    code += Indent + " * @return void\n";
    code += Indent + " */\n";
    code += Indent + "public static function start";
    code += ConvertCase(field.name, Case::kUpperCamel);
    code += "Vector(FlatBufferBuilder $builder, $numElems)\n";
    code += Indent + "{\n";
    code += Indent + Indent + "$builder->startVector(";
    code += NumToString(elem_size);
    code += ", $numElems, " + NumToString(alignment);
    code += ");\n";
    code += Indent + "}\n\n";
  }

  // Get the offset of the end of a table.
  void GetEndOffsetOnTable(const StructDef& struct_def, std::string* code_ptr) {
    std::string& code = *code_ptr;

    code += Indent + "/**\n";
    code += Indent + " * @param FlatBufferBuilder $builder\n";
    code += Indent + " * @return int table offset\n";
    code += Indent + " */\n";
    code += Indent + "public static function end" + struct_def.name;
    code += "(FlatBufferBuilder $builder)\n";
    code += Indent + "{\n";
    code += Indent + Indent + "$o = $builder->endObject();\n";

    for (auto it = struct_def.fields.vec.begin();
         it != struct_def.fields.vec.end(); ++it) {
      auto& field = **it;
      if (!field.deprecated && field.IsRequired()) {
        code += Indent + Indent + "$builder->required($o, ";
        code += NumToString(field.value.offset);
        code += ");  // " + field.name + "\n";
      }
    }
    code += Indent + Indent + "return $o;\n";
    code += Indent + "}\n";

    if (parser_.root_struct_def_ == &struct_def) {
      code += "\n";
      code += Indent + "public static function finish";
      code += struct_def.name;
      code += "Buffer(FlatBufferBuilder $builder, $offset)\n";
      code += Indent + "{\n";
      code += Indent + Indent + "$builder->finish($offset";

      if (parser_.file_identifier_.length())
        code += ", \"" + parser_.file_identifier_ + "\"";
      code += ");\n";
      code += Indent + "}\n";
    }
  }

  // Generate a struct field, conditioned on its child type(s).
  void GenStructAccessor(const StructDef& struct_def, const FieldDef& field,
                         std::string* code_ptr) {
    GenComment(field.doc_comment, code_ptr, nullptr, Indent.c_str());

    if (IsScalar(field.value.type.base_type)) {
      if (struct_def.fixed) {
        GetScalarFieldOfStruct(field, code_ptr);
      } else {
        GetScalarFieldOfTable(field, code_ptr);
      }
    } else {
      switch (field.value.type.base_type) {
        case BASE_TYPE_STRUCT:
          if (struct_def.fixed) {
            GetStructFieldOfStruct(field, code_ptr);
          } else {
            GetStructFieldOfTable(field, code_ptr);
          }
          break;
        case BASE_TYPE_STRING:
          GetStringField(field, code_ptr);
          break;
        case BASE_TYPE_VECTOR: {
          auto vectortype = field.value.type.VectorType();
          if (vectortype.base_type == BASE_TYPE_UNION) {
            GetMemberOfVectorOfUnion(field, code_ptr);
          } else if (vectortype.base_type == BASE_TYPE_STRUCT) {
            GetMemberOfVectorOfStruct(struct_def, field, code_ptr);
          } else {
            GetMemberOfVectorOfNonStruct(field, code_ptr);
          }
          break;
        }
        case BASE_TYPE_UNION:
          GetUnionField(field, code_ptr);
          break;
        default:
          FLATBUFFERS_ASSERT(0);
      }
    }
    if (IsVector(field.value.type)) {
      GetVectorLen(field, code_ptr);
      if (field.value.type.element == BASE_TYPE_UCHAR) {
        GetUByte(field, code_ptr);
      }
    }
  }

  // Generate table constructors, conditioned on its members' types.
  void GenTableBuilders(const StructDef& struct_def, std::string* code_ptr) {
    GetStartOfTable(struct_def, code_ptr);

    for (auto it = struct_def.fields.vec.begin();
         it != struct_def.fields.vec.end(); ++it) {
      auto& field = **it;
      if (field.deprecated) continue;

      auto offset = it - struct_def.fields.vec.begin();
      if (field.value.type.base_type == BASE_TYPE_UNION) {
        std::string& code = *code_ptr;
        code += Indent + "public static function add";
        code += ConvertCase(field.name, Case::kUpperCamel);
        code += "(FlatBufferBuilder $builder, $offset)\n";
        code += Indent + "{\n";
        code += Indent + Indent + "$builder->addOffsetX(";
        code += NumToString(offset) + ", $offset, 0);\n";
        code += Indent + "}\n\n";
      } else {
        BuildFieldOfTable(field, offset, code_ptr);
      }
      if (IsVector(field.value.type)) {
        BuildVectorOfTable(field, code_ptr);
      }
    }

    GetEndOffsetOnTable(struct_def, code_ptr);
  }

  // Generate struct or table methods.
  void GenStruct(const StructDef& struct_def, std::string* code_ptr) {
    if (struct_def.generated) return;

    GenComment(struct_def.doc_comment, code_ptr, nullptr);
    BeginClass(struct_def, code_ptr);

    if (!struct_def.fixed) {
      // Generate a special accessor for the table that has been declared as
      // the root type.
      NewRootTypeFromBuffer(struct_def, code_ptr);
      if (encryption_plan_.NeedsWalk(struct_def)) {
        GenEncryptionMethods(struct_def, code_ptr);
      }
    }

    std::string& code = *code_ptr;
    if (!struct_def.fixed) {
      if (parser_.file_identifier_.length()) {
        // Return the identifier
        code += Indent + "public static function " + struct_def.name;
        code += "Identifier()\n";
        code += Indent + "{\n";
        code += Indent + Indent + "return \"";
        code += parser_.file_identifier_ + "\";\n";
        code += Indent + "}\n\n";

        // Check if a buffer has the identifier.
        code += Indent + "public static function " + struct_def.name;
        code += "BufferHasIdentifier(ByteBuffer $buf)\n";
        code += Indent + "{\n";
        code += Indent + Indent + "return self::";
        code += "__has_identifier($buf, self::";
        code += struct_def.name + "Identifier());\n";
        code += Indent + "}\n\n";
      }

      if (parser_.file_extension_.length()) {
        // Return the extension
        code += Indent + "public static function " + struct_def.name;
        code += "Extension()\n";
        code += Indent + "{\n";
        code += Indent + Indent + "return \"" + parser_.file_extension_;
        code += "\";\n";
        code += Indent + "}\n\n";
      }
    }

    // Generate the Init method that sets the field in a pre-existing
    // accessor object. This is to allow object reuse.
    InitializeExisting(struct_def, code_ptr);
    for (auto it = struct_def.fields.vec.begin();
         it != struct_def.fields.vec.end(); ++it) {
      auto& field = **it;
      if (field.deprecated) continue;

      GenStructAccessor(struct_def, field, code_ptr);
    }

    if (struct_def.fixed) {
      // create a struct constructor function
      GenStructBuilder(struct_def, code_ptr);
    } else {
      // Create a set of functions that allow table construction.
      GenTableBuilders(struct_def, code_ptr);
    }
    EndClass(code_ptr);
  }

  // Generate enum declarations.
  static void GenEnum(const EnumDef& enum_def, std::string* code_ptr) {
    if (enum_def.generated) return;

    GenComment(enum_def.doc_comment, code_ptr, nullptr);
    BeginEnum(enum_def.name, code_ptr);
    for (auto it = enum_def.Vals().begin(); it != enum_def.Vals().end(); ++it) {
      auto& ev = **it;
      GenComment(ev.doc_comment, code_ptr, nullptr, Indent.c_str());
      EnumMember(enum_def, ev, code_ptr);
    }

    std::string& code = *code_ptr;
    code += "\n";
    code += Indent + "private static $names = array(\n";
    for (auto it = enum_def.Vals().begin(); it != enum_def.Vals().end(); ++it) {
      auto& ev = **it;
      code += Indent + Indent + enum_def.name + "::" + ev.name + "=>" + "\"" +
              ev.name + "\",\n";
    }

    code += Indent + ");\n\n";
    code += Indent + "public static function Name($e)\n";
    code += Indent + "{\n";
    code += Indent + Indent + "if (!isset(self::$names[$e])) {\n";
    code += Indent + Indent + Indent + "throw new \\Exception();\n";
    code += Indent + Indent + "}\n";
    code += Indent + Indent + "return self::$names[$e];\n";
    code += Indent + "}\n";
    EndEnum(code_ptr);
  }

  // Returns the function name that is able to read a value of the given type.
  static std::string GenGetter(const Type& type) {
    switch (type.base_type) {
      case BASE_TYPE_STRING:
        return "__string";
      case BASE_TYPE_STRUCT:
        return "__struct";
      case BASE_TYPE_UNION:
        return "__union";
      case BASE_TYPE_VECTOR:
        return GenGetter(type.VectorType());
      default:
        return "Get";
    }
  }

  // Returns the method name for use with add/put calls.
  static std::string GenMethod(const FieldDef& field) {
    return IsScalar(field.value.type.base_type)
               ? ConvertCase(GenTypeBasic(field.value.type), Case::kUpperCamel)
               : (IsStruct(field.value.type) ? "Struct" : "Offset");
  }

  static std::string GenTypeBasic(const Type& type) {
    // clang-format off
    static const char *ctypename[] = {
      #define FLATBUFFERS_TD(ENUM, IDLTYPE, \
              CTYPE, JTYPE, GTYPE, NTYPE, ...) \
        #NTYPE,
        FLATBUFFERS_GEN_TYPES(FLATBUFFERS_TD)
      #undef FLATBUFFERS_TD
    };
    // clang-format on
    return ctypename[type.base_type];
  }

  std::string GenDefaultValue(const Value& value) {
    if (value.type.enum_def) {
      if (auto val = value.type.enum_def->FindByValue(value.constant)) {
        return WrapInNameSpace(*value.type.enum_def) + "::" + val->name;
      }
    }

    switch (value.type.base_type) {
      case BASE_TYPE_BOOL:
        return value.constant == "0" ? "false" : "true";

      case BASE_TYPE_STRING:
        return "null";

      case BASE_TYPE_LONG:
      case BASE_TYPE_ULONG:
        if (value.constant != "0") {
          int64_t constant = StringToInt(value.constant.c_str());
          return NumToString(constant);
        }
        return "0";

      default:
        return value.constant;
    }
  }

  static std::string GenTypePointer(const Type& type) {
    switch (type.base_type) {
      case BASE_TYPE_STRING:
        return "string";
      case BASE_TYPE_VECTOR:
        return GenTypeGet(type.VectorType());
      case BASE_TYPE_STRUCT:
        return type.struct_def->name;
      case BASE_TYPE_UNION:
        // fall through
      default:
        return "Table";
    }
  }

  static std::string GenTypeGet(const Type& type) {
    return IsScalar(type.base_type) ? GenTypeBasic(type) : GenTypePointer(type);
  }

  // Create a struct with a builder and the struct's arguments.
  static void GenStructBuilder(const StructDef& struct_def,
                               std::string* code_ptr) {
    std::string& code = *code_ptr;
    code += "\n";
    code += Indent + "/**\n";
    code += Indent + " * @return int offset\n";
    code += Indent + " */\n";
    code += Indent + "public static function create" + struct_def.name;
    code += "(FlatBufferBuilder $builder";
    StructBuilderArgs(struct_def, "", code_ptr);
    code += ")\n";
    code += Indent + "{\n";

    StructBuilderBody(struct_def, "", code_ptr);

    code += Indent + Indent + "return $builder->offset();\n";
    code += Indent + "}\n";
  }

  const encryption_codegen::Plan encryption_plan_;
};
}  // namespace php

static bool GeneratePhp(const Parser& parser, const std::string& path,
                        const std::string& file_name) {
  php::PhpGenerator generator(parser, path, file_name);
  return generator.generate();
}

namespace {

class PhpCodeGenerator : public CodeGenerator {
 public:
  Status GenerateCode(const Parser& parser, const std::string& path,
                      const std::string& filename) override {
    const encryption_codegen::Plan plan(parser);
    if (!plan.ok()) {
      status_detail = ": " + plan.error();
      return Status::ERROR;
    }
    if (!GeneratePhp(parser, path, filename)) {
      return Status::ERROR;
    }
    return Status::OK;
  }

  Status GenerateCode(const uint8_t*, int64_t, const CodeGenOptions&) override {
    return Status::NOT_IMPLEMENTED;
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

  Status GenerateGrpcCode(const Parser& parser, const std::string& path,
                          const std::string& filename) override {
    (void)parser;
    (void)path;
    (void)filename;
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

  IDLOptions::Language Language() const override { return IDLOptions::kPhp; }

  std::string LanguageName() const override { return "Php"; }
};
}  // namespace

std::unique_ptr<CodeGenerator> NewPhpCodeGenerator() {
  return std::unique_ptr<PhpCodeGenerator>(new PhpCodeGenerator());
}

}  // namespace flatbuffers
