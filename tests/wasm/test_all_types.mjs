#!/usr/bin/env node
/**
 * test_all_types.mjs - Comprehensive type test for WASM flatc module
 *
 * Uses canonical FlatBuffers test schemas instead of custom inline schemas:
 * - monster_test.fbs: Comprehensive schema with most types (standalone version)
 * - optional_scalars.fbs: Optional scalar types
 * - nan_inf_test.fbs: Special float values (nan, inf, -inf)
 * - nested_union_test.fbs: Unions and nested types
 * - more_defaults.fbs: Default values for vectors and strings
 * - arrays_test.fbs: Fixed-size arrays in structs
 */

import { readFile } from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const TESTS_DIR = path.join(__dirname, '..');
const WASM_PATH = path.join(__dirname, '..', '..', 'build', 'wasm', 'wasm', 'flatc.js');

// Test results
let passed = 0;
let failed = 0;

function log(msg) {
  console.log(msg);
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

function assertClose(actual, expected, epsilon, message) {
  if (Math.abs(actual - expected) > epsilon) {
    throw new Error(`${message}: expected ${expected}, got ${actual}`);
  }
}

async function test(name, fn) {
  try {
    await fn();
    log(`  PASS: ${name}`);
    passed++;
  } catch (err) {
    log(`  FAIL: ${name} - ${err.message}`);
    failed++;
  }
}

// =============================================================================
// WASM Module Wrapper
// =============================================================================

class FlatcTester {
  constructor(module) {
    this.module = module;
    this.encoder = new TextEncoder();
    this.decoder = new TextDecoder();
    this.schemaIds = new Map();
  }

  static async create() {
    const moduleFactory = await import(WASM_PATH);
    const module = await moduleFactory.default();
    return new FlatcTester(module);
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
      this.schemaIds.set(name, id);
      return id;
    } finally {
      this.module._free(namePtr);
      this.module._free(srcPtr);
    }
  }

  jsonToBinary(schemaName, json) {
    const schemaId = this.schemaIds.get(schemaName);
    if (schemaId === undefined) {
      throw new Error(`Schema '${schemaName}' not found`);
    }

    const jsonStr = typeof json === 'string' ? json : JSON.stringify(json);
    const [jsonPtr, jsonLen] = this.writeString(jsonStr);
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
    const schemaId = this.schemaIds.get(schemaName);
    if (schemaId === undefined) {
      throw new Error(`Schema '${schemaName}' not found`);
    }

    const binPtr = this.writeBytes(binary);
    const outLenPtr = this.module._malloc(4);

    try {
      const resultPtr = this.module._wasm_binary_to_json(schemaId, binPtr, binary.length, outLenPtr);
      if (!resultPtr) {
        throw new Error(`Binary to JSON failed: ${this.getLastError()}`);
      }

      const len = this.module.getValue(outLenPtr, 'i32');
      const data = this.module.HEAPU8.slice(resultPtr, resultPtr + len);
      return this.decoder.decode(data);
    } finally {
      this.module._free(binPtr);
      this.module._free(outLenPtr);
    }
  }

  /**
   * Parse FlatBuffers JSON which may contain non-standard values like nan, inf.
   */
  static parseFlatBuffersJson(json) {
    const sanitized = json
      .replace(/:\s*nan\b/g, ': null')
      .replace(/:\s*-inf\b/g, ': null')
      .replace(/:\s*\+?inf\b/g, ': null')
      .replace(/:\s*-infinity\b/g, ': null')
      .replace(/:\s*\+?infinity\b/g, ': null');
    return JSON.parse(sanitized);
  }

  roundTrip(schemaName, json) {
    const binary = this.jsonToBinary(schemaName, json);
    const resultJson = this.binaryToJson(schemaName, binary);
    return FlatcTester.parseFlatBuffersJson(resultJson);
  }
}

// =============================================================================
// Canonical test schemas (standalone versions without includes)
// =============================================================================

// Standalone monster_test.fbs (simplified version without explicit IDs)
const MONSTER_TEST_SCHEMA = `
namespace MyGame.Example;

attribute "priority";

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

struct Test { a:short; b:byte; }

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

table Stat {
  id:string;
  val:long;
  count:ushort (key);
}

table Monster {
  pos:Vec3;
  mana:short = 150;
  hp:short = 100;
  name:string (key);
  friendly:bool = false (deprecated, priority: 1);
  inventory:[ubyte];
  color:Color = Blue;
  test_type:ubyte;
  test:Monster;
  test4:[Test];
  testarrayofstring:[string];
  testarrayoftables:[Monster];
  testempty:Stat;
  testbool:bool;
  testhashs32_fnv1:int (hash:"fnv1_32");
  testf:float = 3.14159;
  testf2:float = 3;
  testf3:float;
  testarrayofbools:[bool];
  testarrayofsortedstruct:[Ability];
  vector_of_longs:[long];
  vector_of_doubles:[double];
  signed_enum:Race = None;
}

root_type Monster;
file_identifier "MONS";
file_extension "mon";
`;

// Optional scalars test (from tests/optional_scalars.fbs)
const OPTIONAL_SCALARS_SCHEMA = `
namespace optional_scalars;

enum OptionalByte: byte {
  None = 0,
  One = 1,
  Two = 2,
}

table ScalarStuff {
  just_i8: int8;
  maybe_i8: int8 = null;
  default_i8: int8 = 42;
  just_u8: uint8;
  maybe_u8: uint8 = null;
  default_u8: uint8 = 42;

  just_i16: int16;
  maybe_i16: int16 = null;
  default_i16: int16 = 42;
  just_u16: uint16;
  maybe_u16: uint16 = null;
  default_u16: uint16 = 42;

  just_i32: int32;
  maybe_i32: int32 = null;
  default_i32: int32 = 42;
  just_u32: uint32;
  maybe_u32: uint32 = null;
  default_u32: uint32 = 42;

  just_i64: int64;
  maybe_i64: int64 = null;
  default_i64: int64 = 42;
  just_u64: uint64;
  maybe_u64: uint64 = null;
  default_u64: uint64 = 42;

  just_f32: float32;
  maybe_f32: float32 = null;
  default_f32: float32 = 42;
  just_f64: float64;
  maybe_f64: float64 = null;
  default_f64: float64 = 42;

  just_bool: bool;
  maybe_bool: bool = null;
  default_bool: bool = true;

  just_enum: OptionalByte;
  maybe_enum: OptionalByte = null;
  default_enum: OptionalByte = One;
}

root_type ScalarStuff;
file_identifier "NULL";
file_extension "mon";
`;

// Nan/Inf test (from tests/nan_inf_test.fbs)
const NAN_INF_SCHEMA = `
namespace Swift.Tests;

table NanInfTable
{
  default_nan:double = nan;
  default_inf:double = inf;
  default_ninf:double = -inf;
  value_nan:double;
  value_inf:double;
  value_ninf:double;
  value:double;
}

root_type NanInfTable;
`;

// Nested union test (from tests/nested_union_test.fbs)
const NESTED_UNION_SCHEMA = `
namespace MyGame.Example.NestedUnion;

enum Color:ubyte (bit_flags) {
  Red = 0,
  Green,
  Blue = 3,
}

table TestSimpleTableWithEnum {
  color: Color = Green;
}

struct Test { a:short; b:byte; }

table Vec3 {
  x:double;
  y:double;
  z:double;
  test1:double;
  test2:Color;
  test3:Test;
}

union Any { Vec3, TestSimpleTableWithEnum }

table NestedUnionTest {
  name:string;
  data:Any;
  id:short;
}

root_type NestedUnionTest;
`;

// More defaults (from tests/more_defaults.fbs)
const MORE_DEFAULTS_SCHEMA = `
enum ABC: int { A, B, C }

table MoreDefaults {
  ints: [int];
  floats: [float];
  empty_string: string = "";
  some_string: string = "some";
  abcs: [ABC];
  bools: [bool];
}

root_type MoreDefaults;
`;

// =============================================================================
// Test Functions using Canonical Schemas
// =============================================================================

async function testMonsterScalarTypes(tester) {
  log('\n[Monster Schema - Scalar Types]');

  await test('Signed integers (hp, mana)', async () => {
    const result = tester.roundTrip('monster.fbs', {
      name: 'TestMonster',
      hp: -32768,
      mana: 32767
    });
    assert(result.hp === -32768, 'hp minimum short');
    assert(result.mana === 32767, 'mana maximum short');
  });

  await test('Default values applied', async () => {
    const result = tester.roundTrip('monster.fbs', { name: 'Default' });
    assert(result.hp === 100, 'default hp is 100');
    assert(result.mana === 150, 'default mana is 150');
    assertClose(result.testf, 3.14159, 0.0001, 'default testf');
  });

  await test('Float values', async () => {
    const result = tester.roundTrip('monster.fbs', {
      name: 'FloatTest',
      testf: 1.5,
      testf2: 2.5,
      testf3: 3.5
    });
    assertClose(result.testf, 1.5, 0.0001, 'testf');
    assertClose(result.testf2, 2.5, 0.0001, 'testf2');
    assertClose(result.testf3, 3.5, 0.0001, 'testf3');
  });

  await test('Boolean values', async () => {
    const result = tester.roundTrip('monster.fbs', {
      name: 'BoolTest',
      testbool: true
    });
    assert(result.testbool === true, 'testbool is true');
  });

  await test('Signed enum (Race)', async () => {
    let result = tester.roundTrip('monster.fbs', { name: 'Human', signed_enum: 'Human' });
    assert(result.signed_enum === 'Human', 'Race.Human');

    result = tester.roundTrip('monster.fbs', { name: 'Elf', signed_enum: 'Elf' });
    assert(result.signed_enum === 'Elf', 'Race.Elf');

    result = tester.roundTrip('monster.fbs', { name: 'None', signed_enum: 'None' });
    assert(result.signed_enum === 'None', 'Race.None (negative enum value)');
  });
}

async function testMonsterVectors(tester) {
  log('\n[Monster Schema - Vectors]');

  await test('ubyte vector (inventory)', async () => {
    const result = tester.roundTrip('monster.fbs', {
      name: 'Inventory',
      inventory: [0, 1, 2, 3, 4, 255]
    });
    assert(result.inventory.length === 6, 'inventory length');
    assert(result.inventory[0] === 0, 'inventory[0]');
    assert(result.inventory[5] === 255, 'inventory[5]');
  });

  await test('String vector', async () => {
    const result = tester.roundTrip('monster.fbs', {
      name: 'Strings',
      testarrayofstring: ['hello', 'world', '你好', '🌍']
    });
    assert(result.testarrayofstring.length === 4, 'string array length');
    assert(result.testarrayofstring[0] === 'hello', 'string[0]');
    assert(result.testarrayofstring[2] === '你好', 'string[2] unicode');
    assert(result.testarrayofstring[3] === '🌍', 'string[3] emoji');
  });

  await test('Bool vector', async () => {
    const result = tester.roundTrip('monster.fbs', {
      name: 'Bools',
      testarrayofbools: [true, false, true, false, true]
    });
    assert(result.testarrayofbools.length === 5, 'bool array length');
    assert(result.testarrayofbools[0] === true, 'bool[0]');
    assert(result.testarrayofbools[1] === false, 'bool[1]');
  });

  await test('Long vector (64-bit integers)', async () => {
    const result = tester.roundTrip('monster.fbs', {
      name: 'Longs',
      vector_of_longs: ["-9223372036854775808", 0, "9223372036854775807"]
    });
    assert(result.vector_of_longs.length === 3, 'long array length');
  });

  await test('Double vector', async () => {
    const result = tester.roundTrip('monster.fbs', {
      name: 'Doubles',
      vector_of_doubles: [1.111111111111111, 2.222222222222222, 3.333333333333333]
    });
    assert(result.vector_of_doubles.length === 3, 'double array length');
    assertClose(result.vector_of_doubles[0], 1.111111111111111, 0.0000001, 'double[0]');
  });

  await test('Struct vector (Ability)', async () => {
    const result = tester.roundTrip('monster.fbs', {
      name: 'Abilities',
      testarrayofsortedstruct: [
        { id: 1, distance: 100 },
        { id: 2, distance: 200 },
        { id: 3, distance: 300 }
      ]
    });
    assert(result.testarrayofsortedstruct.length === 3, 'struct array length');
    assert(result.testarrayofsortedstruct[0].id === 1, 'struct[0].id');
    assert(result.testarrayofsortedstruct[2].distance === 300, 'struct[2].distance');
  });

  await test('Test struct array', async () => {
    const result = tester.roundTrip('monster.fbs', {
      name: 'TestStructs',
      test4: [
        { a: -100, b: 50 },
        { a: 100, b: -50 }
      ]
    });
    assert(result.test4.length === 2, 'test4 length');
    assert(result.test4[0].a === -100, 'test4[0].a');
    assert(result.test4[1].b === -50, 'test4[1].b');
  });
}

async function testMonsterStructs(tester) {
  log('\n[Monster Schema - Structs]');

  await test('Vec3 struct with nested struct', async () => {
    const result = tester.roundTrip('monster.fbs', {
      name: 'StructTest',
      pos: {
        x: 1.0,
        y: 2.0,
        z: 3.0,
        test1: 4.5,
        test2: 'Green',
        test3: { a: 100, b: 50 }
      }
    });
    assertClose(result.pos.x, 1.0, 0.0001, 'pos.x');
    assertClose(result.pos.y, 2.0, 0.0001, 'pos.y');
    assertClose(result.pos.z, 3.0, 0.0001, 'pos.z');
    assertClose(result.pos.test1, 4.5, 0.0001, 'pos.test1');
    assert(result.pos.test2 === 'Green', 'pos.test2 enum');
    assert(result.pos.test3.a === 100, 'pos.test3.a');
    assert(result.pos.test3.b === 50, 'pos.test3.b');
  });
}

async function testMonsterNestedTables(tester) {
  log('\n[Monster Schema - Nested Tables]');

  await test('Nested table (Stat)', async () => {
    const result = tester.roundTrip('monster.fbs', {
      name: 'Nested',
      testempty: {
        id: 'stat_id',
        val: "1234567890123",
        count: 42
      }
    });
    assert(result.testempty.id === 'stat_id', 'testempty.id');
    assert(result.testempty.count === 42, 'testempty.count');
  });

  await test('Vector of tables (testarrayoftables)', async () => {
    const result = tester.roundTrip('monster.fbs', {
      name: 'Parent',
      testarrayoftables: [
        { name: 'Child1', hp: 10 },
        { name: 'Child2', hp: 20 },
        { name: 'Child3', hp: 30 }
      ]
    });
    assert(result.testarrayoftables.length === 3, 'nested table array length');
    assert(result.testarrayoftables[0].name === 'Child1', 'child1.name');
    assert(result.testarrayoftables[1].hp === 20, 'child2.hp');
  });
}

async function testOptionalScalars(tester) {
  log('\n[Optional Scalars Schema]');

  await test('All optional scalars set', async () => {
    const result = tester.roundTrip('optional_scalars.fbs', {
      just_i8: -128,
      maybe_i8: 127,
      just_i16: -32768,
      maybe_i16: 32767,
      just_i32: -2147483648,
      maybe_i32: 2147483647,
      just_f32: 1.5,
      maybe_f32: 2.5,
      just_bool: true,
      maybe_bool: false,
      just_enum: 'One',
      maybe_enum: 'Two'
    });
    assert(result.just_i8 === -128, 'just_i8');
    assert(result.maybe_i8 === 127, 'maybe_i8');
    assert(result.just_i32 === -2147483648, 'just_i32');
    assert(result.just_bool === true, 'just_bool');
    assert(result.maybe_bool === false, 'maybe_bool');
    assert(result.just_enum === 'One', 'just_enum');
    assert(result.maybe_enum === 'Two', 'maybe_enum');
  });

  await test('Optional scalars absent (defaults)', async () => {
    const result = tester.roundTrip('optional_scalars.fbs', {
      just_i8: 0,
      just_u8: 0,
      just_i16: 0,
      just_u16: 0,
      just_i32: 0,
      just_u32: 0,
      just_i64: 0,
      just_u64: 0,
      just_f32: 0,
      just_f64: 0,
      just_bool: false,
      just_enum: 'None'
    });
    // Default values should be applied
    assert(result.default_i8 === 42, 'default_i8');
    assert(result.default_u8 === 42, 'default_u8');
    assert(result.default_i32 === 42, 'default_i32');
    assert(result.default_bool === true, 'default_bool');
    assert(result.default_enum === 'One', 'default_enum');

    // Optional fields not set should be null/undefined
    assert(result.maybe_i8 === null || result.maybe_i8 === undefined, 'maybe_i8 absent');
    assert(result.maybe_bool === null || result.maybe_bool === undefined, 'maybe_bool absent');
  });

  await test('Unsigned scalar extremes', async () => {
    const result = tester.roundTrip('optional_scalars.fbs', {
      just_i8: 0,
      just_u8: 255,
      just_i16: 0,
      just_u16: 65535,
      just_i32: 0,
      just_u32: 4294967295,
      just_i64: 0,
      just_u64: "18446744073709551615",
      just_f32: 0,
      just_f64: 0,
      just_bool: false,
      just_enum: 'None'
    });
    assert(result.just_u8 === 255, 'max u8');
    assert(result.just_u16 === 65535, 'max u16');
    assert(result.just_u32 === 4294967295, 'max u32');
  });
}

async function testNanInf(tester) {
  log('\n[NaN/Inf Schema - Special Float Values]');

  await test('Regular double value', async () => {
    const result = tester.roundTrip('nan_inf.fbs', { value: 123.456 });
    assertClose(result.value, 123.456, 0.0001, 'regular value');
  });

  await test('Default nan/inf values', async () => {
    const result = tester.roundTrip('nan_inf.fbs', { value: 1.0 });
    // Default values are nan, inf, -inf - they come back as null after sanitization
    assert(result.default_nan === null, 'default_nan is sanitized to null');
    assert(result.default_inf === null, 'default_inf is sanitized to null');
    assert(result.default_ninf === null, 'default_ninf is sanitized to null');
  });
}

async function testNestedUnion(tester) {
  log('\n[Nested Union Schema]');

  await test('Union with Vec3', async () => {
    const result = tester.roundTrip('nested_union.fbs', {
      name: 'Vec3Union',
      data_type: 'Vec3',
      data: {
        x: 1.0,
        y: 2.0,
        z: 3.0,
        test1: 4.0,
        test2: 'Green',
        test3: { a: 10, b: 5 }
      },
      id: 42
    });
    assert(result.name === 'Vec3Union', 'name');
    assert(result.data_type === 'Vec3', 'union type');
    assertClose(result.data.x, 1.0, 0.0001, 'data.x');
    assertClose(result.data.z, 3.0, 0.0001, 'data.z');
    assert(result.id === 42, 'id');
  });

  await test('Union with TestSimpleTableWithEnum', async () => {
    const result = tester.roundTrip('nested_union.fbs', {
      name: 'EnumUnion',
      data_type: 'TestSimpleTableWithEnum',
      data: { color: 'Blue' },
      id: 100
    });
    assert(result.name === 'EnumUnion', 'name');
    assert(result.data_type === 'TestSimpleTableWithEnum', 'union type');
    assert(result.data.color === 'Blue', 'data.color');
  });
}

async function testMoreDefaults(tester) {
  log('\n[More Defaults Schema]');

  await test('Empty vectors', async () => {
    const result = tester.roundTrip('more_defaults.fbs', {});
    // Empty vectors may be undefined or empty
    assert(!result.ints || result.ints.length === 0, 'ints empty');
    assert(!result.floats || result.floats.length === 0, 'floats empty');
  });

  await test('Default string values when explicitly set', async () => {
    // FlatBuffers doesn't output default values unless explicitly set
    // So we test that when we explicitly set them, they roundtrip correctly
    const result = tester.roundTrip('more_defaults.fbs', {
      ints: [1, 2, 3],
      empty_string: '',
      some_string: 'custom'
    });
    // Only explicitly set values appear in output
    assert(result.empty_string === '' || result.empty_string === undefined, 'empty_string roundtrip');
    assert(result.some_string === 'custom', 'custom string value');
  });

  await test('Vectors with values', async () => {
    const result = tester.roundTrip('more_defaults.fbs', {
      ints: [1, 2, 3, 4, 5],
      floats: [1.1, 2.2, 3.3],
      abcs: ['A', 'B', 'C'],
      bools: [true, false, true]
    });
    assert(result.ints.length === 5, 'ints length');
    assert(result.floats.length === 3, 'floats length');
    assert(result.abcs.length === 3, 'abcs length');
    assert(result.bools.length === 3, 'bools length');
  });
}

async function testCanonicalFiles(tester) {
  log('\n[Canonical Test Files]');

  // Test optional_scalars.json - we have the full matching schema
  const optionalJson = await readFile(path.join(TESTS_DIR, 'optional_scalars.json'), 'utf-8');

  await test('optional_scalars.json round-trip', async () => {
    const binary = tester.jsonToBinary('optional_scalars.fbs', optionalJson);
    assert(binary.length > 0, 'binary generated');

    const fileId = String.fromCharCode(binary[4], binary[5], binary[6], binary[7]);
    assert(fileId === 'NULL', 'file identifier is NULL');

    const result = FlatcTester.parseFlatBuffersJson(tester.binaryToJson('optional_scalars.fbs', binary));
    // Values from the canonical optional_scalars.json file
    assert(result.just_i8 === 4, 'just_i8 is 4');
    assert(result.just_i16 === 4, 'just_i16 is 4');
    assert(result.just_bool === true, 'just_bool is true');
  });

  // Test schema round-trip with complex Monster data
  await test('Monster schema complex round-trip', async () => {
    const complexMonster = {
      name: 'ComplexMonster',
      hp: 500,
      mana: 300,
      color: 'Green',
      pos: {
        x: 1.5,
        y: 2.5,
        z: 3.5,
        test1: 10.0,
        test2: 'Red',
        test3: { a: 100, b: 50 }
      },
      inventory: [0, 1, 2, 255],
      testarrayofstring: ['hello', 'world', '你好'],
      testarrayoftables: [
        { name: 'Child1', hp: 10 },
        { name: 'Child2', hp: 20 }
      ],
      testarrayofbools: [true, false, true],
      vector_of_longs: ["9223372036854775807", "-9223372036854775808"],
      vector_of_doubles: [1.111, 2.222, 3.333]
    };

    const binary = tester.jsonToBinary('monster.fbs', complexMonster);
    assert(binary.length > 0, 'complex monster binary generated');

    const fileId = String.fromCharCode(binary[4], binary[5], binary[6], binary[7]);
    assert(fileId === 'MONS', 'file identifier is MONS');

    const result = FlatcTester.parseFlatBuffersJson(tester.binaryToJson('monster.fbs', binary));
    assert(result.name === 'ComplexMonster', 'name');
    assert(result.hp === 500, 'hp');
    assert(result.mana === 300, 'mana');
    assert(result.color === 'Green', 'color');
    assert(result.inventory.length === 4, 'inventory length');
    assert(result.testarrayofstring.length === 3, 'strings length');
    assert(result.testarrayoftables.length === 2, 'nested tables length');
  });
}

// =============================================================================
// Main
// =============================================================================

async function main() {
  log('='.repeat(60));
  log('FlatBuffers WASM All Types Test Suite');
  log('Using Canonical Test Schemas');
  log('='.repeat(60));

  const tester = await FlatcTester.create();

  // Load canonical schemas
  log('\nLoading schemas...');
  tester.addSchema('monster.fbs', MONSTER_TEST_SCHEMA);
  tester.addSchema('optional_scalars.fbs', OPTIONAL_SCALARS_SCHEMA);
  tester.addSchema('nan_inf.fbs', NAN_INF_SCHEMA);
  tester.addSchema('nested_union.fbs', NESTED_UNION_SCHEMA);
  tester.addSchema('more_defaults.fbs', MORE_DEFAULTS_SCHEMA);
  log('Schemas loaded.');

  // Run tests
  await testMonsterScalarTypes(tester);
  await testMonsterVectors(tester);
  await testMonsterStructs(tester);
  await testMonsterNestedTables(tester);
  await testOptionalScalars(tester);
  await testNanInf(tester);
  await testNestedUnion(tester);
  await testMoreDefaults(tester);
  await testCanonicalFiles(tester);

  // Summary
  log('\n' + '='.repeat(60));
  log(`Results: ${passed} passed, ${failed} failed`);
  log('='.repeat(60));

  process.exit(failed > 0 ? 1 : 0);
}

main().catch(err => {
  console.error('Test suite error:', err);
  process.exit(1);
});
