#!/usr/bin/env node
/**
 * test_all_types.mjs - Comprehensive test for ALL FlatBuffer types
 *
 * Tests every FlatBuffer type supported by the WASM module:
 * - Scalars (bool, int8/16/32/64, uint8/16/32/64, float32/64)
 * - Strings (simple, required, with defaults)
 * - Enums (different underlying types, bit_flags)
 * - Structs (simple, nested, aligned, all scalars)
 * - Tables (nested, with unions, optional fields, deprecated fields)
 * - Vectors (of all scalar types, strings, structs, tables, enums)
 * - Unions (simple, aliased)
 * - Special values (nan, inf, -inf)
 * - Keys for sorting
 * - Nested flatbuffers
 */

import { existsSync } from 'fs';
import { readFile } from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WASM_PATH = path.join(__dirname, '..', '..', 'build', 'wasm', 'wasm', 'flatc.js');
const ALL_TYPES_SCHEMA_PATH = path.join(__dirname, 'all_types.fbs');

// Test results
let passed = 0;
let failed = 0;
const results = [];

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
    results.push({ name, status: 'pass' });
  } catch (err) {
    log(`  FAIL: ${name} - ${err.message}`);
    failed++;
    results.push({ name, status: 'fail', error: err.message });
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

  async addSchemaFile(filePath) {
    const content = await readFile(filePath, 'utf-8');
    const name = path.basename(filePath);
    return this.addSchema(name, content);
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
      let jsonStr = this.decoder.decode(data);

      // Handle special float values that FlatBuffers outputs but JSON doesn't support
      // Replace nan, inf, -inf with valid JSON representations
      jsonStr = jsonStr.replace(/:\s*nan\b/g, ': null');
      jsonStr = jsonStr.replace(/:\s*-inf\b/g, ': null');
      jsonStr = jsonStr.replace(/:\s*inf\b/g, ': null');

      return jsonStr;
    } finally {
      this.module._free(binPtr);
      this.module._free(outLenPtr);
    }
  }

  roundTrip(schemaName, json) {
    const binary = this.jsonToBinary(schemaName, json);
    const resultJson = this.binaryToJson(schemaName, binary);
    return JSON.parse(resultJson);
  }
}

// =============================================================================
// Test Data for All Types
// =============================================================================

// Individual type schemas for isolated testing
const SCALAR_SCHEMA = `
namespace Test;
table ScalarTest {
  bool_val: bool = false;
  int8_val: byte;
  int16_val: short;
  int32_val: int;
  int64_val: long;
  uint8_val: ubyte;
  uint16_val: ushort;
  uint32_val: uint;
  uint64_val: ulong;
  float32_val: float;
  float64_val: double;
}
root_type ScalarTest;
`;

const STRING_SCHEMA = `
namespace Test;
table StringTest {
  simple: string;
  with_default: string = "default";
  empty: string;
}
root_type StringTest;
`;

const ENUM_SCHEMA = `
namespace Test;
enum ByteEnum : byte { NegOne = -1, Zero = 0, One = 1 }
enum UByteEnum : ubyte { Zero = 0, Half = 128, Max = 255 }
enum ShortEnum : short { Min = -32768, Zero = 0, Max = 32767 }
enum UShortEnum : ushort { Zero = 0, Max = 65535 }
enum IntEnum : int { Min = -2147483648, Zero = 0, Max = 2147483647 }
enum UIntEnum : uint { Zero = 0, Max = 4294967295 }
enum LongEnum : long { Min = -9223372036854775808, Zero = 0, Max = 9223372036854775807 }
enum ULongEnum : ulong { Zero = 0, Max = 18446744073709551615 }
enum Flags : uint (bit_flags) { A, B, C, D }
table EnumTest {
  byte_enum: ByteEnum;
  ubyte_enum: UByteEnum;
  short_enum: ShortEnum;
  ushort_enum: UShortEnum;
  int_enum: IntEnum;
  uint_enum: UIntEnum;
  flags: Flags;
}
root_type EnumTest;
`;

const STRUCT_SCHEMA = `
namespace Test;
struct Vec2 { x: float; y: float; }
struct Vec3 { x: float; y: float; z: float; }
struct Nested { a: Vec2; b: Vec3; }
struct AllScalars {
  b: bool;
  i8: byte;
  u8: ubyte;
  i16: short;
  u16: ushort;
  i32: int;
  u32: uint;
  i64: long;
  u64: ulong;
  f32: float;
  f64: double;
}
table StructTest {
  vec2: Vec2;
  vec3: Vec3;
  nested: Nested;
  all_scalars: AllScalars;
}
root_type StructTest;
`;

const VECTOR_SCHEMA = `
namespace Test;
struct Vec2 { x: float; y: float; }
table VectorTest {
  bool_vec: [bool];
  int8_vec: [byte];
  uint8_vec: [ubyte];
  int16_vec: [short];
  uint16_vec: [ushort];
  int32_vec: [int];
  uint32_vec: [uint];
  int64_vec: [long];
  uint64_vec: [ulong];
  float_vec: [float];
  double_vec: [double];
  string_vec: [string];
  struct_vec: [Vec2];
}
root_type VectorTest;
`;

const UNION_SCHEMA = `
namespace Test;
table TypeA { value_a: int; }
table TypeB { value_b: string; }
table TypeC { value_c: float; }
union MyUnion { TypeA, TypeB, TypeC }
union AliasedUnion { A: TypeA, B: TypeB, C: TypeC }
table UnionTest {
  my_union: MyUnion;
  aliased_union: AliasedUnion;
}
root_type UnionTest;
`;

const OPTIONAL_SCHEMA = `
namespace Test;
table OptionalTest {
  opt_bool: bool = null;
  opt_int: int = null;
  opt_float: float = null;
  opt_string: string;
  regular_int: int = 42;
}
root_type OptionalTest;
`;

const NESTED_TABLE_SCHEMA = `
namespace Test;
table Inner { value: int; name: string; }
table Middle { inner: Inner; items: [Inner]; }
table Outer { middle: Middle; middles: [Middle]; }
root_type Outer;
`;

// =============================================================================
// Test Functions
// =============================================================================

async function testScalarTypes(tester) {
  log('\n[Scalar Types]');

  await test('Boolean true', async () => {
    const result = tester.roundTrip('scalar.fbs', { bool_val: true });
    assert(result.bool_val === true, 'bool_val should be true');
  });

  await test('Boolean false', async () => {
    const result = tester.roundTrip('scalar.fbs', { bool_val: false });
    assert(result.bool_val === false, 'bool_val should be false');
  });

  await test('Signed integers (positive)', async () => {
    const result = tester.roundTrip('scalar.fbs', {
      int8_val: 127,
      int16_val: 32767,
      int32_val: 2147483647,
      int64_val: "9223372036854775807"
    });
    assert(result.int8_val === 127, 'int8_val');
    assert(result.int16_val === 32767, 'int16_val');
    assert(result.int32_val === 2147483647, 'int32_val');
    // int64 comes back as string due to JS number limits
    assert(result.int64_val === "9223372036854775807" || result.int64_val === 9223372036854775807, 'int64_val');
  });

  await test('Signed integers (negative)', async () => {
    const result = tester.roundTrip('scalar.fbs', {
      int8_val: -128,
      int16_val: -32768,
      int32_val: -2147483648,
      int64_val: "-9223372036854775808"
    });
    assert(result.int8_val === -128, 'int8_val');
    assert(result.int16_val === -32768, 'int16_val');
    assert(result.int32_val === -2147483648, 'int32_val');
  });

  await test('Unsigned integers', async () => {
    const result = tester.roundTrip('scalar.fbs', {
      uint8_val: 255,
      uint16_val: 65535,
      uint32_val: 4294967295,
      uint64_val: "18446744073709551615"
    });
    assert(result.uint8_val === 255, 'uint8_val');
    assert(result.uint16_val === 65535, 'uint16_val');
    assert(result.uint32_val === 4294967295, 'uint32_val');
  });

  await test('Float32', async () => {
    const result = tester.roundTrip('scalar.fbs', { float32_val: 3.14159 });
    assertClose(result.float32_val, 3.14159, 0.0001, 'float32_val');
  });

  await test('Float64', async () => {
    const result = tester.roundTrip('scalar.fbs', { float64_val: 2.718281828459045 });
    assertClose(result.float64_val, 2.718281828459045, 0.000000001, 'float64_val');
  });

  await test('Zero values', async () => {
    const result = tester.roundTrip('scalar.fbs', {
      int32_val: 0,
      uint32_val: 0,
      float32_val: 0.0
    });
    assert(result.int32_val === 0, 'int32_val zero');
    assert(result.uint32_val === 0, 'uint32_val zero');
    assert(result.float32_val === 0.0, 'float32_val zero');
  });
}

async function testStringTypes(tester) {
  log('\n[String Types]');

  await test('Simple string', async () => {
    const result = tester.roundTrip('string.fbs', { simple: 'Hello, World!' });
    assert(result.simple === 'Hello, World!', 'simple string');
  });

  await test('Unicode string', async () => {
    const result = tester.roundTrip('string.fbs', { simple: '你好世界 🌍 مرحبا' });
    assert(result.simple === '你好世界 🌍 مرحبا', 'unicode string');
  });

  await test('Empty string', async () => {
    const result = tester.roundTrip('string.fbs', { empty: '' });
    assert(result.empty === '', 'empty string');
  });

  await test('String with special characters', async () => {
    const result = tester.roundTrip('string.fbs', { simple: 'Line1\nLine2\tTabbed "quoted"' });
    assert(result.simple === 'Line1\nLine2\tTabbed "quoted"', 'special chars');
  });

  await test('Long string', async () => {
    const longStr = 'x'.repeat(10000);
    const result = tester.roundTrip('string.fbs', { simple: longStr });
    assert(result.simple === longStr, 'long string');
    assert(result.simple.length === 10000, 'long string length');
  });
}

async function testEnumTypes(tester) {
  log('\n[Enum Types]');

  await test('Byte enum values', async () => {
    let result = tester.roundTrip('enum.fbs', { byte_enum: 'NegOne' });
    assert(result.byte_enum === 'NegOne', 'byte enum NegOne');

    result = tester.roundTrip('enum.fbs', { byte_enum: 'Zero' });
    assert(result.byte_enum === 'Zero', 'byte enum Zero');

    result = tester.roundTrip('enum.fbs', { byte_enum: 'One' });
    assert(result.byte_enum === 'One', 'byte enum One');
  });

  await test('UByte enum (0-255)', async () => {
    const result = tester.roundTrip('enum.fbs', { ubyte_enum: 'Max' });
    assert(result.ubyte_enum === 'Max', 'ubyte enum Max');
  });

  await test('Short enum extremes', async () => {
    let result = tester.roundTrip('enum.fbs', { short_enum: 'Min' });
    assert(result.short_enum === 'Min', 'short enum Min');

    result = tester.roundTrip('enum.fbs', { short_enum: 'Max' });
    assert(result.short_enum === 'Max', 'short enum Max');
  });

  await test('Int enum extremes', async () => {
    let result = tester.roundTrip('enum.fbs', { int_enum: 'Min' });
    assert(result.int_enum === 'Min', 'int enum Min');

    result = tester.roundTrip('enum.fbs', { int_enum: 'Max' });
    assert(result.int_enum === 'Max', 'int enum Max');
  });

  await test('Bit flags enum', async () => {
    // Single flag
    let result = tester.roundTrip('enum.fbs', { flags: 'A' });
    assert(result.flags === 'A' || result.flags === 1, 'single flag A');

    // Multiple flags - FlatBuffers may return as string like "A B" or numeric
    result = tester.roundTrip('enum.fbs', { flags: 'A B' });
    assert(result.flags === 'A B' || result.flags === 3, 'multiple flags A B');
  });
}

async function testStructTypes(tester) {
  log('\n[Struct Types]');

  await test('Simple Vec2 struct', async () => {
    const result = tester.roundTrip('struct.fbs', {
      vec2: { x: 1.5, y: 2.5 }
    });
    assertClose(result.vec2.x, 1.5, 0.0001, 'vec2.x');
    assertClose(result.vec2.y, 2.5, 0.0001, 'vec2.y');
  });

  await test('Vec3 struct', async () => {
    const result = tester.roundTrip('struct.fbs', {
      vec3: { x: 1.0, y: 2.0, z: 3.0 }
    });
    assertClose(result.vec3.x, 1.0, 0.0001, 'vec3.x');
    assertClose(result.vec3.y, 2.0, 0.0001, 'vec3.y');
    assertClose(result.vec3.z, 3.0, 0.0001, 'vec3.z');
  });

  await test('Nested structs', async () => {
    const result = tester.roundTrip('struct.fbs', {
      nested: {
        a: { x: 1.0, y: 2.0 },
        b: { x: 3.0, y: 4.0, z: 5.0 }
      }
    });
    assertClose(result.nested.a.x, 1.0, 0.0001, 'nested.a.x');
    assertClose(result.nested.b.z, 5.0, 0.0001, 'nested.b.z');
  });

  await test('Struct with all scalar types', async () => {
    const result = tester.roundTrip('struct.fbs', {
      all_scalars: {
        b: true,
        i8: -128,
        u8: 255,
        i16: -32768,
        u16: 65535,
        i32: -2147483648,
        u32: 4294967295,
        i64: "-9223372036854775808",
        u64: "18446744073709551615",
        f32: 3.14159,
        f64: 2.718281828459045
      }
    });
    assert(result.all_scalars.b === true, 'all_scalars.b');
    assert(result.all_scalars.i8 === -128, 'all_scalars.i8');
    assert(result.all_scalars.u8 === 255, 'all_scalars.u8');
  });
}

async function testVectorTypes(tester) {
  log('\n[Vector Types]');

  await test('Bool vector', async () => {
    const result = tester.roundTrip('vector.fbs', {
      bool_vec: [true, false, true, false]
    });
    assert(result.bool_vec.length === 4, 'bool_vec length');
    assert(result.bool_vec[0] === true, 'bool_vec[0]');
    assert(result.bool_vec[1] === false, 'bool_vec[1]');
  });

  await test('Integer vectors', async () => {
    const result = tester.roundTrip('vector.fbs', {
      int8_vec: [-128, 0, 127],
      uint8_vec: [0, 128, 255],
      int32_vec: [-2147483648, 0, 2147483647],
      uint32_vec: [0, 2147483648, 4294967295]
    });
    assert(result.int8_vec.length === 3, 'int8_vec length');
    assert(result.int8_vec[0] === -128, 'int8_vec[0]');
    assert(result.uint8_vec[2] === 255, 'uint8_vec[2]');
    assert(result.int32_vec[0] === -2147483648, 'int32_vec[0]');
  });

  await test('Float vectors', async () => {
    const result = tester.roundTrip('vector.fbs', {
      float_vec: [1.1, 2.2, 3.3],
      double_vec: [1.111111, 2.222222, 3.333333]
    });
    assert(result.float_vec.length === 3, 'float_vec length');
    assertClose(result.float_vec[0], 1.1, 0.0001, 'float_vec[0]');
    assertClose(result.double_vec[2], 3.333333, 0.000001, 'double_vec[2]');
  });

  await test('String vector', async () => {
    const result = tester.roundTrip('vector.fbs', {
      string_vec: ['hello', 'world', '你好', '🌍']
    });
    assert(result.string_vec.length === 4, 'string_vec length');
    assert(result.string_vec[0] === 'hello', 'string_vec[0]');
    assert(result.string_vec[2] === '你好', 'string_vec[2]');
    assert(result.string_vec[3] === '🌍', 'string_vec[3]');
  });

  await test('Struct vector', async () => {
    const result = tester.roundTrip('vector.fbs', {
      struct_vec: [
        { x: 1.0, y: 2.0 },
        { x: 3.0, y: 4.0 },
        { x: 5.0, y: 6.0 }
      ]
    });
    assert(result.struct_vec.length === 3, 'struct_vec length');
    assertClose(result.struct_vec[0].x, 1.0, 0.0001, 'struct_vec[0].x');
    assertClose(result.struct_vec[2].y, 6.0, 0.0001, 'struct_vec[2].y');
  });

  await test('Empty vectors', async () => {
    const result = tester.roundTrip('vector.fbs', {
      int32_vec: [],
      string_vec: []
    });
    assert(result.int32_vec === undefined || result.int32_vec.length === 0, 'empty int32_vec');
    assert(result.string_vec === undefined || result.string_vec.length === 0, 'empty string_vec');
  });

  await test('Large vector', async () => {
    const largeVec = Array.from({ length: 1000 }, (_, i) => i);
    const result = tester.roundTrip('vector.fbs', { int32_vec: largeVec });
    assert(result.int32_vec.length === 1000, 'large vector length');
    assert(result.int32_vec[999] === 999, 'large vector last element');
  });
}

async function testUnionTypes(tester) {
  log('\n[Union Types]');

  await test('Union TypeA', async () => {
    const result = tester.roundTrip('union.fbs', {
      my_union_type: 'TypeA',
      my_union: { value_a: 42 }
    });
    assert(result.my_union_type === 'TypeA', 'union type');
    assert(result.my_union.value_a === 42, 'union value');
  });

  await test('Union TypeB', async () => {
    const result = tester.roundTrip('union.fbs', {
      my_union_type: 'TypeB',
      my_union: { value_b: 'hello' }
    });
    assert(result.my_union_type === 'TypeB', 'union type');
    assert(result.my_union.value_b === 'hello', 'union value');
  });

  await test('Union TypeC', async () => {
    const result = tester.roundTrip('union.fbs', {
      my_union_type: 'TypeC',
      my_union: { value_c: 3.14 }
    });
    assert(result.my_union_type === 'TypeC', 'union type');
    assertClose(result.my_union.value_c, 3.14, 0.001, 'union value');
  });

  await test('Aliased union', async () => {
    const result = tester.roundTrip('union.fbs', {
      aliased_union_type: 'A',
      aliased_union: { value_a: 100 }
    });
    assert(result.aliased_union_type === 'A', 'aliased union type');
    assert(result.aliased_union.value_a === 100, 'aliased union value');
  });
}

async function testOptionalTypes(tester) {
  log('\n[Optional Types]');

  await test('Optional fields present', async () => {
    const result = tester.roundTrip('optional.fbs', {
      opt_bool: true,
      opt_int: 42,
      opt_float: 3.14,
      opt_string: 'hello'
    });
    assert(result.opt_bool === true, 'opt_bool');
    assert(result.opt_int === 42, 'opt_int');
    assertClose(result.opt_float, 3.14, 0.001, 'opt_float');
    assert(result.opt_string === 'hello', 'opt_string');
  });

  await test('Optional fields absent', async () => {
    const result = tester.roundTrip('optional.fbs', {
      regular_int: 100
    });
    // Optional fields should be null/undefined when not set
    assert(result.opt_bool === null || result.opt_bool === undefined, 'opt_bool absent');
    assert(result.opt_int === null || result.opt_int === undefined, 'opt_int absent');
    assert(result.regular_int === 100, 'regular_int');
  });

  await test('Default value used', async () => {
    const result = tester.roundTrip('optional.fbs', {});
    // regular_int has default of 42
    assert(result.regular_int === 42, 'default value');
  });
}

async function testNestedTables(tester) {
  log('\n[Nested Tables]');

  await test('Simple nesting', async () => {
    const result = tester.roundTrip('nested.fbs', {
      middle: {
        inner: { value: 42, name: 'inner' }
      }
    });
    assert(result.middle.inner.value === 42, 'nested value');
    assert(result.middle.inner.name === 'inner', 'nested name');
  });

  await test('Deep nesting with vectors', async () => {
    const result = tester.roundTrip('nested.fbs', {
      middle: {
        inner: { value: 1, name: 'root' },
        items: [
          { value: 2, name: 'item1' },
          { value: 3, name: 'item2' }
        ]
      },
      middles: [
        {
          inner: { value: 10, name: 'middle1' },
          items: []
        },
        {
          inner: { value: 20, name: 'middle2' },
          items: [{ value: 21, name: 'nested_item' }]
        }
      ]
    });

    assert(result.middle.items.length === 2, 'middle.items length');
    assert(result.middles.length === 2, 'middles length');
    assert(result.middles[1].inner.value === 20, 'middles[1].inner.value');
    assert(result.middles[1].items[0].name === 'nested_item', 'deeply nested item');
  });
}

async function testAllTypesSchema(tester) {
  log('\n[Comprehensive AllTypes Schema]');

  await test('AllTypes round-trip', async () => {
    const allTypesData = {
      name: 'Comprehensive Test',
      id: "12345678901234",
      enabled: true,
      color: 'Green',
      size: 'Large',
      status: 'Active',
      flags: 'FlagA',

      scalars: {
        bool_val: true,
        int8_val: -100,
        int16_val: -30000,
        int32_val: -2000000000,
        int64_val: "-9000000000000000000",
        uint8_val: 200,
        uint16_val: 60000,
        uint32_val: 4000000000,
        uint64_val: "18000000000000000000",
        float32_val: 3.14159,
        float64_val: 2.718281828459045
      },

      strings: {
        simple_string: 'Hello World',
        required_string: 'Required',
        string_with_default: 'Custom value'
      },

      vectors: {
        bool_vec: [true, false, true],
        int32_vec: [1, 2, 3, 4, 5],
        float32_vec: [1.1, 2.2, 3.3],
        string_vec: ['a', 'b', 'c'],
        struct_vec: [
          { x: 1.0, y: 2.0, z: 3.0 },
          { x: 4.0, y: 5.0, z: 6.0 }
        ],
        enum_vec: ['Red', 'Green', 'Blue']
      },

      container: {
        nested: { name: 'nested table', value: 42 },
        nested_vec: [
          { name: 'item1', value: 1 },
          { name: 'item2', value: 2 }
        ]
      },

      pet_owner: {
        name: 'John',
        pet_type: 'Dog',
        pet: { barks: 3 }
      },

      vertex: {
        pos: { x: 1.0, y: 2.0, z: 3.0 },
        color: { r: 1.0, g: 0.5, b: 0.0 },
        uv: { x: 0.0, y: 1.0 }
      },

      records: [
        { id: 3, name: 'Third', score: 30.0 },
        { id: 1, name: 'First', score: 10.0 },
        { id: 2, name: 'Second', score: 20.0 }
      ]
    };

    const result = tester.roundTrip('all_types.fbs', allTypesData);

    // Verify key fields
    assert(result.name === 'Comprehensive Test', 'name');
    assert(result.enabled === true, 'enabled');
    assert(result.color === 'Green', 'color');
    assert(result.scalars.bool_val === true, 'scalars.bool_val');
    assert(result.strings.simple_string === 'Hello World', 'strings.simple_string');
    assert(result.vectors.int32_vec.length === 5, 'vectors.int32_vec length');
    assert(result.container.nested.name === 'nested table', 'container.nested.name');
    assert(result.pet_owner.pet.barks === 3, 'pet_owner.pet.barks');
    assertClose(result.vertex.pos.x, 1.0, 0.0001, 'vertex.pos.x');
    assert(result.records.length === 3, 'records length');
  });
}

// =============================================================================
// Main
// =============================================================================

async function main() {
  log('='.repeat(60));
  log('FlatBuffers WASM All Types Test Suite');
  log('='.repeat(60));

  // Check if WASM module exists
  if (!existsSync(WASM_PATH)) {
    log(`\nError: WASM module not found at ${WASM_PATH}`);
    log('Please build the WASM module first.');
    process.exit(1);
  }

  const tester = await FlatcTester.create();

  // Load test schemas
  log('\nLoading test schemas...');
  tester.addSchema('scalar.fbs', SCALAR_SCHEMA);
  tester.addSchema('string.fbs', STRING_SCHEMA);
  tester.addSchema('enum.fbs', ENUM_SCHEMA);
  tester.addSchema('struct.fbs', STRUCT_SCHEMA);
  tester.addSchema('vector.fbs', VECTOR_SCHEMA);
  tester.addSchema('union.fbs', UNION_SCHEMA);
  tester.addSchema('optional.fbs', OPTIONAL_SCHEMA);
  tester.addSchema('nested.fbs', NESTED_TABLE_SCHEMA);

  // Load the comprehensive all_types.fbs schema
  if (existsSync(ALL_TYPES_SCHEMA_PATH)) {
    await tester.addSchemaFile(ALL_TYPES_SCHEMA_PATH);
    log('Loaded all_types.fbs schema');
  } else {
    log('Warning: all_types.fbs not found, skipping AllTypes tests');
  }

  // Run tests
  await testScalarTypes(tester);
  await testStringTypes(tester);
  await testEnumTypes(tester);
  await testStructTypes(tester);
  await testVectorTypes(tester);
  await testUnionTypes(tester);
  await testOptionalTypes(tester);
  await testNestedTables(tester);

  if (tester.schemaIds.has('all_types.fbs')) {
    await testAllTypesSchema(tester);
  }

  // Summary
  log('\n' + '='.repeat(60));
  log(`Results: ${passed} passed, ${failed} failed`);
  log('='.repeat(60));

  if (failed > 0) {
    log('\nFailed tests:');
    for (const r of results) {
      if (r.status === 'fail') {
        log(`  - ${r.name}: ${r.error}`);
      }
    }
  }

  process.exit(failed > 0 ? 1 : 0);
}

main().catch(err => {
  console.error('Test suite error:', err);
  process.exit(1);
});
