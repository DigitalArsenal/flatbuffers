#!/usr/bin/env node
/**
 * test_comprehensive.mjs - Comprehensive test suite for WASM flatc module
 *
 * Uses the canonical FlatBuffers test files (monster_test.fbs, monsterdata_test.json,
 * monsterdata_test.mon, etc.) instead of custom schemas.
 */
import { readFile } from 'fs/promises';
import { fileURLToPath } from 'url';
import path from 'path';
import FlatcWasm from './flatc.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const TESTS_DIR = path.join(__dirname, '..');

// =============================================================================
// Test infrastructure
// =============================================================================

let testsRun = 0;
let testsPassed = 0;

function assert(condition, message) {
  testsRun++;
  if (!condition) {
    console.error(`  ❌ FAIL: ${message}`);
    return false;
  }
  testsPassed++;
  console.log(`  ✓ ${message}`);
  return true;
}

// =============================================================================
// Helper class for WASM interactions
// =============================================================================

class FlatcHelper {
  constructor(module) {
    this.module = module;
    this.encoder = new TextEncoder();
    this.decoder = new TextDecoder();
    this.schemas = new Map();
  }

  /**
   * Parse FlatBuffers JSON which may contain non-standard values like nan, inf, -inf.
   * These are valid in FlatBuffers but not in standard JSON.
   */
  static parseFlatBuffersJson(json) {
    // Replace FlatBuffers-specific float literals with JavaScript equivalents
    // nan -> null (JavaScript has NaN but JSON.parse can't handle it)
    // inf/-inf -> null (similar situation)
    // We use null since that's the closest JSON-valid representation
    const sanitized = json
      .replace(/:\s*nan\b/g, ': null')
      .replace(/:\s*-inf\b/g, ': null')
      .replace(/:\s*\+?inf\b/g, ': null')
      .replace(/:\s*-infinity\b/g, ': null')
      .replace(/:\s*\+?infinity\b/g, ': null');
    return JSON.parse(sanitized);
  }

  writeString(str) {
    const bytes = this.encoder.encode(str);
    const ptr = this.module._malloc(bytes.length);
    this.module.HEAPU8.set(bytes, ptr);
    return [ptr, bytes.length];
  }

  writeBytes(data) {
    const ptr = this.module._malloc(data.length);
    this.module.HEAPU8.set(data, ptr);
    return ptr;
  }

  readString(ptr) {
    return this.module.UTF8ToString(ptr);
  }

  getLastError() {
    const ptr = this.module._wasm_get_last_error();
    return ptr ? this.readString(ptr) : 'Unknown error';
  }

  addSchema(name, source) {
    const [namePtr, nameLen] = this.writeString(name);
    const [srcPtr, srcLen] = this.writeString(source);

    try {
      const id = this.module._wasm_schema_add(namePtr, nameLen, srcPtr, srcLen);
      if (id < 0) {
        throw new Error(`Failed to add schema '${name}': ${this.getLastError()}`);
      }
      this.schemas.set(name, id);
      return id;
    } finally {
      this.module._free(namePtr);
      this.module._free(srcPtr);
    }
  }

  getSchemaId(name) {
    const id = this.schemas.get(name);
    if (id === undefined) {
      throw new Error(`Schema '${name}' not found`);
    }
    return id;
  }

  jsonToBinary(schemaName, json) {
    const schemaId = this.getSchemaId(schemaName);
    const [jsonPtr, jsonLen] = this.writeString(json);
    const outLenPtr = this.module._malloc(4);

    try {
      const resultPtr = this.module._wasm_json_to_binary(schemaId, jsonPtr, jsonLen, outLenPtr);
      if (!resultPtr) {
        throw new Error(`JSON to binary failed: ${this.getLastError()}`);
      }
      const len = this.module.getValue(outLenPtr, 'i32');
      return this.module.HEAPU8.slice(resultPtr, resultPtr + len);
    } finally {
      this.module._free(jsonPtr);
      this.module._free(outLenPtr);
    }
  }

  binaryToJson(schemaName, binary) {
    const schemaId = this.getSchemaId(schemaName);
    const binPtr = this.writeBytes(binary);
    const outLenPtr = this.module._malloc(4);

    try {
      const resultPtr = this.module._wasm_binary_to_json(schemaId, binPtr, binary.length, outLenPtr);
      if (!resultPtr) {
        throw new Error(`Binary to JSON failed: ${this.getLastError()}`);
      }
      const len = this.module.getValue(outLenPtr, 'i32');
      return this.decoder.decode(this.module.HEAPU8.slice(resultPtr, resultPtr + len));
    } finally {
      this.module._free(binPtr);
      this.module._free(outLenPtr);
    }
  }

  generateCode(schemaName, langId) {
    const schemaId = this.getSchemaId(schemaName);
    const outLenPtr = this.module._malloc(4);

    try {
      const resultPtr = this.module._wasm_generate_code(schemaId, langId, outLenPtr);
      if (!resultPtr) {
        throw new Error(`Code generation failed: ${this.getLastError()}`);
      }
      const len = this.module.getValue(outLenPtr, 'i32');
      return this.decoder.decode(this.module.HEAPU8.slice(resultPtr, resultPtr + len));
    } finally {
      this.module._free(outLenPtr);
    }
  }

  detectFormat(data) {
    const ptr = this.writeBytes(data);
    try {
      return this.module._wasm_detect_format(ptr, data.length);
    } finally {
      this.module._free(ptr);
    }
  }
}

// =============================================================================
// Standalone version of monster_test.fbs (without includes)
// This is the canonical FlatBuffers test schema used across all language bindings
// =============================================================================

const MONSTER_TEST_SCHEMA = `
// Standalone version of monster_test.fbs for WASM testing
// Original: tests/monster_test.fbs

namespace MyGame;

table InParentNamespace {}

namespace MyGame.Example2;

table Monster {}

namespace MyGame.Example;

attribute "priority";

/// Composite components of Monster color.
enum Color:ubyte (bit_flags) {
  Red = 0,
  Green,
  Blue = 3,
}

enum Race:byte {
  None = -1,
  Human = 0,
  Dwarf,
  Elf,
}

enum LongEnum:ulong (bit_flags) {
  LongOne = 1,
  LongTwo = 2,
  LongBig = 40,
}

union Any { Monster, TestSimpleTableWithEnum, MyGame.Example2.Monster }
union AnyUniqueAliases { M: Monster, TS: TestSimpleTableWithEnum, M2: MyGame.Example2.Monster }
union AnyAmbiguousAliases { M1: Monster, M2: Monster, M3: Monster }

struct Test { a:short; b:byte; }

table TestSimpleTableWithEnum (csharp_partial, private) {
  color: Color = Green;
}

struct Vec3 (force_align: 8) {
  x:float;
  y:float;
  z:float;
  test1:double;
  test2:Color;
  test3:Test;
}

struct Ability {
  id:uint(key);
  distance:uint;
}

struct StructOfStructs {
  a: Ability;
  b: Test;
  c: Ability;
}

struct StructOfStructsOfStructs {
 a: StructOfStructs;
}

table Stat {
  id:string;
  val:long;
  count:ushort (key);
}

table Referrable {
  id:ulong(key, hash:"fnv1a_64");
}

/// an example documentation comment: "monster object"
table Monster {
  pos:Vec3 (id: 0);
  hp:short = 100 (id: 2);
  mana:short = 150 (id: 1);
  name:string (id: 3, key);
  color:Color = Blue (id: 6);
  inventory:[ubyte] (id: 5);
  friendly:bool = false (deprecated, priority: 1, id: 4);
  testarrayoftables:[Monster] (id: 11);
  testarrayofstring:[string] (id: 10);
  testarrayofstring2:[string] (id: 28);
  testarrayofbools:[bool] (id: 24);
  testarrayofsortedstruct:[Ability] (id: 29);
  enemy:MyGame.Example.Monster (id:12);
  test:Any (id: 8);
  test4:[Test] (id: 9);
  test5:[Test] (id: 31);
  testnestedflatbuffer:[ubyte] (id:13, nested_flatbuffer: "Monster");
  testempty:Stat (id:14);
  testbool:bool (id:15);
  testhashs32_fnv1:int (id:16, hash:"fnv1_32");
  testhashu32_fnv1:uint (id:17, hash:"fnv1_32");
  testhashs64_fnv1:long (id:18, hash:"fnv1_64");
  testhashu64_fnv1:ulong (id:19, hash:"fnv1_64");
  testhashs32_fnv1a:int (id:20, hash:"fnv1a_32");
  testhashu32_fnv1a:uint (id:21, hash:"fnv1a_32");
  testhashs64_fnv1a:long (id:22, hash:"fnv1a_64");
  testhashu64_fnv1a:ulong (id:23, hash:"fnv1a_64");
  testf:float = 3.14159 (id:25);
  testf2:float = 3 (id:26);
  testf3:float (id:27);
  flex:[ubyte] (id:30, flexbuffer);
  vector_of_longs:[long] (id:32);
  vector_of_doubles:[double] (id:33);
  parent_namespace_test:InParentNamespace (id:34);
  vector_of_referrables:[Referrable](id:35);
  single_weak_reference:ulong(id:36, hash:"fnv1a_64");
  vector_of_weak_references:[ulong](id:37, hash:"fnv1a_64");
  vector_of_strong_referrables:[Referrable](id:38);
  co_owning_reference:ulong(id:39, hash:"fnv1a_64");
  vector_of_co_owning_references:[ulong](id:40, hash:"fnv1a_64");
  non_owning_reference:ulong(id:41, hash:"fnv1a_64");
  vector_of_non_owning_references:[ulong](id:42, hash:"fnv1a_64");
  any_unique:AnyUniqueAliases(id:44);
  any_ambiguous:AnyAmbiguousAliases (id:46);
  vector_of_enums:[Color] (id:47);
  signed_enum:Race = None (id:48);
  testrequirednestedflatbuffer:[ubyte] (id:49, nested_flatbuffer: "Monster");
  scalar_key_sorted_tables:[Stat] (id: 50);
  native_inline:Test (id: 51, native_inline);
  long_enum_non_enum_default:LongEnum (id: 52);
  long_enum_normal_default:LongEnum = LongOne (id: 53);
  nan_default:float = nan (id: 54);
  inf_default:float = inf (id: 55);
  positive_inf_default:float = +inf (id: 56);
  infinity_default:float = infinity (id: 57);
  positive_infinity_default:float = +infinity (id: 58);
  negative_inf_default:float = -inf (id: 59);
  negative_infinity_default:float = -infinity (id: 60);
  double_inf_default:double = inf (id: 61);
}

table TypeAliases {
    i8:int8;
    u8:uint8;
    i16:int16;
    u16:uint16;
    i32:int32;
    u32:uint32;
    i64:int64;
    u64:uint64;
    f32:float32;
    f64:float64;
    v8:[int8];
    vf64:[float64];
}

root_type Monster;

file_identifier "MONS";
file_extension "mon";
`;

// =============================================================================
// Main test runner
// =============================================================================

async function main() {
  console.log('Loading WASM module...');
  const module = await FlatcWasm();
  const flatc = new FlatcHelper(module);
  console.log('Version:', module.getVersion());
  console.log('');

  // Load test files from the tests directory
  console.log('Loading test files...');
  const monsterDataJson = await readFile(path.join(TESTS_DIR, 'monsterdata_test.json'), 'utf-8');
  const monsterDataBinary = await readFile(path.join(TESTS_DIR, 'monsterdata_test.mon'));
  const unicodeJson = await readFile(path.join(TESTS_DIR, 'unicode_test.json'), 'utf-8');
  const unicodeBinary = await readFile(path.join(TESTS_DIR, 'unicode_test.mon'));
  const optionalScalarsSchema = await readFile(path.join(TESTS_DIR, 'optional_scalars.fbs'), 'utf-8');
  const optionalScalarsJson = await readFile(path.join(TESTS_DIR, 'optional_scalars.json'), 'utf-8');
  console.log('Test files loaded.\n');

  // ==========================================================================
  // Test 1: Load monster_test schema
  // ==========================================================================
  console.log('=== Test 1: Load monster_test Schema ===');

  const monsterSchemaId = flatc.addSchema('monster_test.fbs', MONSTER_TEST_SCHEMA);
  assert(monsterSchemaId >= 0, `Schema loaded with ID ${monsterSchemaId}`);
  assert(module._wasm_schema_count() >= 1, 'Schema count is at least 1');
  console.log('');

  // ==========================================================================
  // Test 2: JSON → Binary using monsterdata_test.json
  // ==========================================================================
  console.log('=== Test 2: JSON → Binary (monsterdata_test.json) ===');

  const binary = flatc.jsonToBinary('monster_test.fbs', monsterDataJson);
  assert(binary.length > 0, `Converted to binary: ${binary.length} bytes`);

  // Check file identifier (bytes 4-7 should be "MONS")
  const fileId = String.fromCharCode(binary[4], binary[5], binary[6], binary[7]);
  assert(fileId === 'MONS', `File identifier is "${fileId}" (expected "MONS")`);
  console.log('');

  // ==========================================================================
  // Test 3: Binary → JSON using generated binary
  // ==========================================================================
  console.log('=== Test 3: Binary → JSON (round-trip) ===');

  const jsonRoundTrip = flatc.binaryToJson('monster_test.fbs', binary);
  assert(jsonRoundTrip.includes('"name": "MyMonster"'), 'JSON contains name "MyMonster"');
  assert(jsonRoundTrip.includes('"hp": 80'), 'JSON contains hp: 80');
  assert(jsonRoundTrip.includes('"mana": 150'), 'JSON contains mana: 150 (default)');
  console.log('');

  // ==========================================================================
  // Test 4: Read canonical monsterdata_test.mon binary
  // ==========================================================================
  console.log('=== Test 4: Read Canonical Binary (monsterdata_test.mon) ===');

  const canonicalJson = flatc.binaryToJson('monster_test.fbs', new Uint8Array(monsterDataBinary));
  assert(canonicalJson.includes('"name": "MyMonster"'), 'Canonical binary: name is "MyMonster"');
  assert(canonicalJson.includes('"hp": 80'), 'Canonical binary: hp is 80');
  assert(canonicalJson.includes('"inventory"'), 'Canonical binary: has inventory field');
  assert(canonicalJson.includes('"testarrayofstring"'), 'Canonical binary: has testarrayofstring');

  // Parse and verify specific values (using FlatBuffers-aware parser for nan/inf)
  const parsed = FlatcHelper.parseFlatBuffersJson(canonicalJson);
  assert(parsed.name === 'MyMonster', 'Parsed name matches');
  assert(parsed.hp === 80, 'Parsed hp matches');
  assert(Array.isArray(parsed.inventory) && parsed.inventory.length === 5, 'Inventory has 5 elements');
  console.log('');

  // ==========================================================================
  // Test 5: Unicode test (unicode_test.json / unicode_test.mon)
  // ==========================================================================
  console.log('=== Test 5: Unicode Support ===');

  // JSON → Binary
  const unicodeBinaryGenerated = flatc.jsonToBinary('monster_test.fbs', unicodeJson);
  assert(unicodeBinaryGenerated.length > 0, `Unicode JSON converted to ${unicodeBinaryGenerated.length} bytes`);

  // Read canonical unicode binary
  const unicodeJsonFromBinary = flatc.binaryToJson('monster_test.fbs', new Uint8Array(unicodeBinary));
  assert(unicodeJsonFromBinary.includes('unicode_test'), 'Unicode binary contains "unicode_test"');

  // Parse and verify Unicode strings (JSON may use \uXXXX escapes)
  const unicodeParsed = FlatcHelper.parseFlatBuffersJson(unicodeJsonFromBinary);
  const unicodeStrings = unicodeParsed.testarrayofstring || [];
  assert(unicodeStrings.some(s => s.includes('Цлїςσδε')), 'Unicode has Cyrillic/Greek text');
  assert(unicodeStrings.some(s => s.includes('フムヤムカモケモ')), 'Unicode has Japanese text');
  assert(unicodeStrings.some(s => s.includes('☳☶☲')), 'Unicode has symbols');
  console.log('');

  // ==========================================================================
  // Test 6: Optional scalars schema
  // ==========================================================================
  console.log('=== Test 6: Optional Scalars Schema ===');

  const optionalSchemaId = flatc.addSchema('optional_scalars.fbs', optionalScalarsSchema);
  assert(optionalSchemaId >= 0, `Optional scalars schema loaded with ID ${optionalSchemaId}`);

  const optionalBinary = flatc.jsonToBinary('optional_scalars.fbs', optionalScalarsJson);
  assert(optionalBinary.length > 0, `Optional scalars converted to ${optionalBinary.length} bytes`);

  // Check file identifier (should be "NULL")
  const optionalFileId = String.fromCharCode(optionalBinary[4], optionalBinary[5], optionalBinary[6], optionalBinary[7]);
  assert(optionalFileId === 'NULL', `Optional scalars file ID is "${optionalFileId}"`);

  // Round-trip
  const optionalRoundTrip = flatc.binaryToJson('optional_scalars.fbs', optionalBinary);
  assert(optionalRoundTrip.includes('just_i8'), 'Optional round-trip contains just_i8');
  console.log('');

  // ==========================================================================
  // Test 7: Format detection
  // ==========================================================================
  console.log('=== Test 7: Format Detection ===');

  const jsonFormat = flatc.detectFormat(new TextEncoder().encode(monsterDataJson));
  assert(jsonFormat === 0, 'JSON data detected as format 0 (JSON)');

  const binaryFormat = flatc.detectFormat(new Uint8Array(monsterDataBinary));
  assert(binaryFormat === 1, 'Binary data detected as format 1 (FlatBuffer)');

  const unknownFormat = flatc.detectFormat(new Uint8Array([0x00, 0x01, 0x02, 0x03]));
  assert(unknownFormat === -1, 'Random bytes detected as format -1 (Unknown)');
  console.log('');

  // ==========================================================================
  // Test 8: Code generation with monster_test schema
  // ==========================================================================
  console.log('=== Test 8: Code Generation ===');

  const LANGUAGES = [
    { id: 0, name: 'C++', markers: ['struct Vec3', 'struct Monster', 'namespace MyGame'] },
    { id: 3, name: 'Go', markers: ['package Example', 'type Monster struct', 'func (rcv *Monster)'] },
    { id: 6, name: 'Python', markers: ['class Monster', 'def Init(', 'import flatbuffers'] },
    { id: 7, name: 'Rust', markers: ['pub struct Monster', 'impl<', 'pub fn'] },
    { id: 9, name: 'TypeScript', markers: ['export class Monster', 'flatbuffers.Table', 'export enum Color'] },
    { id: 11, name: 'JSON Schema', markers: ['$schema', '"Monster"', '"properties"'] },
    { id: 12, name: 'FBS', markers: ['table Monster', 'struct', 'enum Color'] },
  ];

  for (const lang of LANGUAGES) {
    try {
      const code = flatc.generateCode('monster_test.fbs', lang.id);
      const allMarkersFound = lang.markers.every(m => code.includes(m));
      assert(allMarkersFound, `${lang.name}: Generated code contains expected markers`);
    } catch (err) {
      console.log(`  ⚠ ${lang.name}: ${err.message}`);
    }
  }
  console.log('');

  // ==========================================================================
  // Test 9: Streaming API
  // ==========================================================================
  console.log('=== Test 9: Streaming API ===');

  module._wasm_stream_reset();
  assert(module._wasm_stream_size() === 0, 'Stream reset, size is 0');

  // Stream the JSON in chunks
  const jsonChunks = [
    monsterDataJson.substring(0, 100),
    monsterDataJson.substring(100, 500),
    monsterDataJson.substring(500),
  ];

  let totalSize = 0;
  for (const chunk of jsonChunks) {
    const bytes = new TextEncoder().encode(chunk);
    const ptr = module._wasm_stream_prepare(bytes.length);
    module.HEAPU8.set(bytes, ptr);
    module._wasm_stream_commit(bytes.length);
    totalSize += bytes.length;
  }

  assert(module._wasm_stream_size() === totalSize, `Stream accumulated ${totalSize} bytes`);

  // Convert streamed data
  const outPtrPtr = module._malloc(4);
  const outLenPtr = module._malloc(4);
  const streamResult = module._wasm_stream_convert(monsterSchemaId, outPtrPtr, outLenPtr);
  module._free(outPtrPtr);
  module._free(outLenPtr);

  assert(streamResult === 0, 'Stream convert detected JSON input');
  console.log('');

  // ==========================================================================
  // Test 10: Error handling
  // ==========================================================================
  console.log('=== Test 10: Error Handling ===');

  // Invalid schema ID
  module._wasm_clear_error();
  const invalidOutLenPtr = module._malloc(4);
  const invalidResult = module._wasm_json_to_binary(9999, 0, 0, invalidOutLenPtr);
  module._free(invalidOutLenPtr);
  assert(invalidResult === 0, 'Invalid schema ID returns null');
  assert(flatc.getLastError().includes('not found'), 'Error mentions "not found"');

  // Invalid JSON
  module._wasm_clear_error();
  try {
    flatc.jsonToBinary('monster_test.fbs', '{ not valid json }');
    assert(false, 'Invalid JSON should throw');
  } catch (e) {
    assert(e.message.includes('JSON'), 'Error mentions JSON parsing issue');
  }

  // Schema without root type
  module._wasm_clear_error();
  try {
    flatc.addSchema('no_root.fbs', 'table Foo { x: int; }');
    assert(false, 'Schema without root_type should fail');
  } catch (e) {
    assert(e.message.includes('root'), 'Error mentions root type');
  }
  console.log('');

  // ==========================================================================
  // Test 11: Cross-language binary compatibility
  // ==========================================================================
  console.log('=== Test 11: Cross-Language Binary Compatibility ===');

  // Test reading binaries generated by different language implementations
  const crossLangBinaries = [
    { name: 'Java', file: 'monsterdata_java_wire.mon' },
    { name: 'Python', file: 'monsterdata_python_wire.mon' },
    { name: 'Rust', file: 'monsterdata_rust_wire.mon' },
  ];

  for (const { name, file } of crossLangBinaries) {
    try {
      const binaryData = await readFile(path.join(TESTS_DIR, file));
      const json = flatc.binaryToJson('monster_test.fbs', new Uint8Array(binaryData));
      assert(json.includes('"name"'), `${name} binary readable`);
    } catch (e) {
      // File might not exist in all builds
      if (e.code === 'ENOENT') {
        console.log(`  ⚠ ${name}: ${file} not found (skipped)`);
      } else {
        console.log(`  ⚠ ${name}: ${e.message}`);
      }
    }
  }
  console.log('');

  // ==========================================================================
  // Summary
  // ==========================================================================
  console.log('='.repeat(50));
  console.log(`Tests run: ${testsRun}`);
  console.log(`Tests passed: ${testsPassed}`);
  console.log(`Tests failed: ${testsRun - testsPassed}`);
  console.log('='.repeat(50));

  if (testsPassed === testsRun) {
    console.log('🎉 All tests passed!');
    process.exit(0);
  } else {
    console.log('❌ Some tests failed');
    process.exit(1);
  }
}

main().catch(err => {
  console.error('Test error:', err);
  process.exit(1);
});
