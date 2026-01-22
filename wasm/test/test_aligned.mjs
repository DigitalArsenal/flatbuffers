#!/usr/bin/env node
/**
 * test_aligned.mjs - Test suite for aligned code generation
 *
 * Tests the zero-copy WASM interop code generation from FlatBuffers schemas.
 */

import {
  parseSchema,
  computeLayout,
  generateCppHeader,
  generateTypeScript,
  generateAlignedCode,
} from '../src/aligned-codegen.mjs';

// =============================================================================
// Test Utilities
// =============================================================================

let passed = 0;
let failed = 0;

function log(msg) {
  console.log(msg);
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || 'Assertion failed');
  }
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(`${message || 'Assertion failed'}: expected ${expected}, got ${actual}`);
  }
}

async function test(name, fn) {
  try {
    await fn();
    passed++;
    log(`  ✓ ${name}`);
  } catch (err) {
    failed++;
    log(`  ✗ ${name}`);
    log(`    Error: ${err.message}`);
  }
}

// =============================================================================
// Test Schemas
// =============================================================================

const SIMPLE_STRUCT_SCHEMA = `
namespace Game;

struct Vec3 {
  x: float;
  y: float;
  z: float;
}
`;

const MIXED_TYPES_SCHEMA = `
namespace Test;

struct MixedTypes {
  a: byte;
  b: uint32;
  c: ushort;
  d: double;
  e: bool;
}
`;

const NESTED_STRUCT_SCHEMA = `
namespace Game;

struct Vec3 {
  x: float;
  y: float;
  z: float;
}

table Player {
  id: uint32;
  position: Vec3;
  health: ushort;
  flags: ubyte;
}
`;

const ENUM_SCHEMA = `
namespace Game;

enum Color : ubyte {
  Red = 0,
  Green = 1,
  Blue = 2
}

struct Pixel {
  x: ushort;
  y: ushort;
  color: Color;
}
`;

const FIXED_ARRAY_SCHEMA = `
namespace Math;

struct Matrix4x4 {
  data: [float:16];
}

struct Transform {
  position: [float:3];
  rotation: [float:4];
  scale: [float:3];
}
`;

const STRING_SCHEMA = `
namespace Game;

table Player {
  id: uint32;
  name: string;
  guild: string;
  health: ushort;
}
`;

const MIXED_STRING_SCHEMA = `
namespace App;

struct Vec2 {
  x: float;
  y: float;
}

table Entity {
  position: Vec2;
  name: string;
  tag: string;
  active: bool;
}
`;

// =============================================================================
// Schema Parsing Tests
// =============================================================================

async function runParsingTests() {
  log('\n[Schema Parsing]');

  await test('parses simple struct', async () => {
    const schema = parseSchema(SIMPLE_STRUCT_SCHEMA);
    assertEqual(schema.namespace, 'Game', 'namespace');
    assertEqual(schema.structs.length, 1, 'struct count');
    assertEqual(schema.structs[0].name, 'Vec3', 'struct name');
    assertEqual(schema.structs[0].fields.length, 3, 'field count');
  });

  await test('parses field types correctly', async () => {
    const schema = parseSchema(SIMPLE_STRUCT_SCHEMA);
    const vec3 = schema.structs[0];
    assertEqual(vec3.fields[0].name, 'x', 'field 0 name');
    assertEqual(vec3.fields[0].type, 'float', 'field 0 type');
    assertEqual(vec3.fields[0].size, 4, 'field 0 size');
  });

  await test('parses mixed types', async () => {
    const schema = parseSchema(MIXED_TYPES_SCHEMA);
    const mixed = schema.structs[0];
    assertEqual(mixed.fields.length, 5, 'field count');
    assertEqual(mixed.fields[0].size, 1, 'byte size');
    assertEqual(mixed.fields[1].size, 4, 'uint32 size');
    assertEqual(mixed.fields[2].size, 2, 'ushort size');
    assertEqual(mixed.fields[3].size, 8, 'double size');
    assertEqual(mixed.fields[4].size, 1, 'bool size');
  });

  await test('parses enums', async () => {
    const schema = parseSchema(ENUM_SCHEMA);
    assertEqual(schema.enums.length, 1, 'enum count');
    assertEqual(schema.enums[0].name, 'Color', 'enum name');
    assertEqual(schema.enums[0].baseType, 'ubyte', 'enum base type');
    assertEqual(schema.enums[0].values.length, 3, 'enum value count');
  });

  await test('parses tables', async () => {
    const schema = parseSchema(NESTED_STRUCT_SCHEMA);
    assertEqual(schema.tables.length, 1, 'table count');
    assertEqual(schema.tables[0].name, 'Player', 'table name');
  });

  await test('parses fixed-size arrays', async () => {
    const schema = parseSchema(FIXED_ARRAY_SCHEMA);
    assertEqual(schema.structs.length, 2, 'struct count');

    const matrix = schema.structs[0];
    assertEqual(matrix.fields[0].isArray, true, 'is array');
    assertEqual(matrix.fields[0].arraySize, 16, 'array size');
    assertEqual(matrix.fields[0].size, 64, 'total size'); // 16 * 4

    const transform = schema.structs[1];
    assertEqual(transform.fields[0].arraySize, 3, 'position size');
    assertEqual(transform.fields[1].arraySize, 4, 'rotation size');
    assertEqual(transform.fields[2].arraySize, 3, 'scale size');
  });
}

// =============================================================================
// Layout Calculation Tests
// =============================================================================

async function runLayoutTests() {
  log('\n[Layout Calculation]');

  await test('computes Vec3 layout', async () => {
    const schema = parseSchema(SIMPLE_STRUCT_SCHEMA);
    const layout = computeLayout(schema.structs[0], {});

    assertEqual(layout.size, 12, 'Vec3 size'); // 3 * 4 bytes
    assertEqual(layout.align, 4, 'Vec3 alignment');
    assertEqual(layout.fields[0].offset, 0, 'x offset');
    assertEqual(layout.fields[1].offset, 4, 'y offset');
    assertEqual(layout.fields[2].offset, 8, 'z offset');
  });

  await test('handles alignment padding', async () => {
    const schema = parseSchema(MIXED_TYPES_SCHEMA);
    const layout = computeLayout(schema.structs[0], {});

    // byte (1) + padding (3) + uint32 (4) + ushort (2) + padding (6) + double (8) + bool (1) + padding (7)
    // Actually: align to largest (8)
    // byte at 0, padding to 4, uint32 at 4, ushort at 8, padding to 16, double at 16, bool at 24, padding to 32
    // Let's verify actual layout:
    assertEqual(layout.fields[0].offset, 0, 'byte offset');
    assertEqual(layout.fields[1].offset, 4, 'uint32 offset'); // aligned to 4
    assertEqual(layout.fields[2].offset, 8, 'ushort offset');
    assertEqual(layout.fields[3].offset, 16, 'double offset'); // aligned to 8
    assertEqual(layout.fields[4].offset, 24, 'bool offset');
    assertEqual(layout.align, 8, 'struct alignment');
  });

  await test('computes nested struct layout', async () => {
    const schema = parseSchema(NESTED_STRUCT_SCHEMA);
    const allStructs = {
      Vec3: schema.structs[0],
      Player: schema.tables[0],
    };

    const layout = computeLayout(schema.tables[0], allStructs);

    // uint32 (4) + Vec3 (12) + ushort (2) + ubyte (1) + padding (1) = 20 bytes
    assertEqual(layout.fields[0].offset, 0, 'id offset');
    assertEqual(layout.fields[1].offset, 4, 'position offset');
    assertEqual(layout.fields[2].offset, 16, 'health offset');
    assertEqual(layout.fields[3].offset, 18, 'flags offset');
    assertEqual(layout.size, 20, 'Player size');
    assertEqual(layout.align, 4, 'Player alignment');
  });

  await test('computes fixed array layout', async () => {
    const schema = parseSchema(FIXED_ARRAY_SCHEMA);
    const layout = computeLayout(schema.structs[0], {});

    assertEqual(layout.size, 64, 'Matrix4x4 size'); // 16 * 4
    assertEqual(layout.fields[0].offset, 0, 'data offset');
  });
}

// =============================================================================
// C++ Generation Tests
// =============================================================================

async function runCppTests() {
  log('\n[C++ Header Generation]');

  await test('generates pragma once', async () => {
    const schema = parseSchema(SIMPLE_STRUCT_SCHEMA);
    const cpp = generateCppHeader(schema);
    assert(cpp.includes('#pragma once'), 'should have pragma once');
  });

  await test('generates namespace', async () => {
    const schema = parseSchema(SIMPLE_STRUCT_SCHEMA);
    const cpp = generateCppHeader(schema);
    assert(cpp.includes('namespace Game {'), 'should have Game namespace');
    assert(cpp.includes('namespace Aligned {'), 'should have Aligned namespace');
  });

  await test('generates struct with offsets', async () => {
    const schema = parseSchema(SIMPLE_STRUCT_SCHEMA);
    const cpp = generateCppHeader(schema);
    assert(cpp.includes('struct Vec3 {'), 'should have struct');
    assert(cpp.includes('float x;'), 'should have x field');
    assert(cpp.includes('// offset 0'), 'should have offset comment');
  });

  await test('generates static_assert for size', async () => {
    const schema = parseSchema(SIMPLE_STRUCT_SCHEMA);
    const cpp = generateCppHeader(schema);
    assert(cpp.includes('static_assert(sizeof(Vec3) == 12'), 'should have size assert');
    assert(cpp.includes('static_assert(alignof(Vec3) == 4'), 'should have align assert');
  });

  await test('generates size constants', async () => {
    const schema = parseSchema(SIMPLE_STRUCT_SCHEMA);
    const cpp = generateCppHeader(schema);
    assert(cpp.includes('constexpr size_t VEC3_SIZE = 12'), 'should have size constant');
    assert(cpp.includes('constexpr size_t VEC3_ALIGN = 4'), 'should have align constant');
  });

  await test('generates enum class', async () => {
    const schema = parseSchema(ENUM_SCHEMA);
    const cpp = generateCppHeader(schema);
    assert(cpp.includes('enum class Color : uint8_t'), 'should have enum class');
    assert(cpp.includes('Red = 0'), 'should have Red');
    assert(cpp.includes('Green = 1'), 'should have Green');
    assert(cpp.includes('Blue = 2'), 'should have Blue');
  });

  await test('generates fixed array', async () => {
    const schema = parseSchema(FIXED_ARRAY_SCHEMA);
    const cpp = generateCppHeader(schema);
    assert(cpp.includes('float data[16]'), 'should have array');
  });
}

// =============================================================================
// TypeScript Generation Tests
// =============================================================================

async function runTypeScriptTests() {
  log('\n[TypeScript Generation]');

  await test('generates size constants', async () => {
    const schema = parseSchema(SIMPLE_STRUCT_SCHEMA);
    const ts = generateTypeScript(schema);
    assert(ts.includes('export const VEC3_SIZE = 12'), 'should have size');
    assert(ts.includes('export const VEC3_ALIGN = 4'), 'should have align');
  });

  await test('generates offset object', async () => {
    const schema = parseSchema(SIMPLE_STRUCT_SCHEMA);
    const ts = generateTypeScript(schema);
    assert(ts.includes('export const Vec3Offsets = {'), 'should have offsets');
    assert(ts.includes('x: 0'), 'should have x offset');
    assert(ts.includes('y: 4'), 'should have y offset');
    assert(ts.includes('z: 8'), 'should have z offset');
  });

  await test('generates view class', async () => {
    const schema = parseSchema(SIMPLE_STRUCT_SCHEMA);
    const ts = generateTypeScript(schema);
    assert(ts.includes('export class Vec3View {'), 'should have view class');
    assert(ts.includes('private readonly view: DataView'), 'should have DataView');
  });

  await test('generates fromMemory factory', async () => {
    const schema = parseSchema(SIMPLE_STRUCT_SCHEMA);
    const ts = generateTypeScript(schema);
    assert(ts.includes('static fromMemory(memory: WebAssembly.Memory'), 'should have fromMemory');
  });

  await test('generates getters/setters', async () => {
    const schema = parseSchema(SIMPLE_STRUCT_SCHEMA);
    const ts = generateTypeScript(schema);
    assert(ts.includes('get x(): number'), 'should have getter');
    assert(ts.includes('set x(v: number)'), 'should have setter');
    assert(ts.includes('getFloat32(0, true)'), 'should use little-endian');
  });

  await test('generates array view class', async () => {
    const schema = parseSchema(SIMPLE_STRUCT_SCHEMA);
    const ts = generateTypeScript(schema);
    assert(ts.includes('export class Vec3ArrayView {'), 'should have array view');
    assert(ts.includes('at(index: number): Vec3View'), 'should have at method');
    assert(ts.includes('[Symbol.iterator]'), 'should be iterable');
  });

  await test('generates enum as const object', async () => {
    const schema = parseSchema(ENUM_SCHEMA);
    const ts = generateTypeScript(schema);
    assert(ts.includes('export const Color = {'), 'should have enum object');
    assert(ts.includes('Red: 0'), 'should have Red');
    assert(ts.includes('} as const'), 'should be const');
    assert(ts.includes('export type Color = typeof Color'), 'should have type');
  });

  await test('generates fixed array accessor', async () => {
    const schema = parseSchema(FIXED_ARRAY_SCHEMA);
    const ts = generateTypeScript(schema);
    assert(ts.includes('get data(): Float32Array'), 'should have typed array getter');
  });

  await test('generates bigint accessors for 64-bit', async () => {
    const schema = parseSchema(`
      namespace Test;
      struct Big {
        a: long;
        b: ulong;
      }
    `);
    const ts = generateTypeScript(schema);
    assert(ts.includes('get a(): bigint'), 'should have bigint type');
    assert(ts.includes('getBigInt64'), 'should use BigInt64');
    assert(ts.includes('getBigUint64'), 'should use BigUint64');
  });

  await test('generates bool accessor', async () => {
    const schema = parseSchema(`
      namespace Test;
      struct Flags {
        active: bool;
      }
    `);
    const ts = generateTypeScript(schema);
    assert(ts.includes('get active(): boolean'), 'should have boolean type');
    assert(ts.includes('!== 0'), 'should convert to boolean');
    assert(ts.includes('? 1 : 0'), 'should convert from boolean');
  });
}

// =============================================================================
// String Support Tests
// =============================================================================

async function runStringTests() {
  log('\n[Fixed-Length String Support]');

  await test('parses string fields with defaultStringLength', async () => {
    const schema = parseSchema(STRING_SCHEMA, { defaultStringLength: 255 });
    const player = schema.tables[0];

    const nameField = player.fields.find(f => f.name === 'name');
    assert(nameField, 'should have name field');
    assert(nameField.isString, 'name should be marked as string');
    assertEqual(nameField.maxStringLength, 255, 'max length should be 255');
    assertEqual(nameField.arraySize, 256, 'array size should be 256 (255 + null)');
    assertEqual(nameField.size, 256, 'total size should be 256');
  });

  await test('rejects strings without defaultStringLength', async () => {
    const schema = parseSchema(STRING_SCHEMA);
    const player = schema.tables[0];

    // Without defaultStringLength, string fields should be null (rejected)
    const nameField = player.fields.find(f => f.name === 'name');
    assertEqual(nameField, undefined, 'name field should be rejected');
  });

  await test('computes layout with string fields', async () => {
    const schema = parseSchema(STRING_SCHEMA, { defaultStringLength: 31 });
    const allStructs = { Player: schema.tables[0] };
    const layout = computeLayout(schema.tables[0], allStructs);

    // uint32 (4) + name (32) + guild (32) + ushort (2) + padding (2) = 72
    assertEqual(layout.fields[0].offset, 0, 'id offset');
    assertEqual(layout.fields[1].offset, 4, 'name offset');
    assertEqual(layout.fields[1].size, 32, 'name size (31 + null)');
    assertEqual(layout.fields[2].offset, 36, 'guild offset');
    assertEqual(layout.fields[3].offset, 68, 'health offset');
  });

  await test('generates C++ char arrays for strings', async () => {
    const { cpp } = generateAlignedCode(STRING_SCHEMA, { defaultStringLength: 63 });

    assert(cpp.includes('char name[64]'), 'should have name char array');
    assert(cpp.includes('char guild[64]'), 'should have guild char array');
    assert(cpp.includes('max 63 chars + null'), 'should have comment about max length');
  });

  await test('generates C++ string helper methods', async () => {
    const { cpp } = generateAlignedCode(STRING_SCHEMA, { defaultStringLength: 63 });

    assert(cpp.includes('const char* get_name()'), 'should have name getter');
    assert(cpp.includes('void set_name(const char* value)'), 'should have name setter');
    assert(cpp.includes('std::strncpy'), 'should use strncpy for safety');
    assert(cpp.includes('Ensure null termination'), 'should ensure null termination');
  });

  await test('generates TypeScript string accessors', async () => {
    const { ts } = generateAlignedCode(STRING_SCHEMA, { defaultStringLength: 127 });

    assert(ts.includes('get name(): string'), 'should have name getter returning string');
    assert(ts.includes('set name(v: string)'), 'should have name setter accepting string');
    assert(ts.includes('TextDecoder'), 'should use TextDecoder for reading');
    assert(ts.includes('TextEncoder'), 'should use TextEncoder for writing');
    assert(ts.includes('get nameBytes(): Uint8Array'), 'should have raw bytes accessor');
  });

  await test('generates JavaScript string accessors', async () => {
    const { js } = generateAlignedCode(STRING_SCHEMA, { defaultStringLength: 127 });

    assert(js.includes('get name()'), 'should have name getter');
    assert(js.includes('set name(v)'), 'should have name setter');
    assert(js.includes('TextDecoder'), 'should use TextDecoder');
    assert(js.includes('TextEncoder'), 'should use TextEncoder');
    assert(js.includes('get nameBytes()'), 'should have raw bytes accessor');
  });

  await test('string accessors handle null termination', async () => {
    const { ts } = generateAlignedCode(STRING_SCHEMA, { defaultStringLength: 31 });

    // Verify getter finds null terminator
    assert(ts.includes('while (len < 31 && bytes[len] !== 0)'), 'getter should scan for null');

    // Verify setter null-terminates
    assert(ts.includes('for (let i = copyLen; i < 32; i++) bytes[i] = 0'), 'setter should null-terminate');
  });

  await test('mixed struct and string table generates correctly', async () => {
    const { cpp, ts, layouts } = generateAlignedCode(MIXED_STRING_SCHEMA, { defaultStringLength: 63 });

    // Verify C++ output
    assert(cpp.includes('struct Vec2'), 'C++ should have Vec2 struct');
    assert(cpp.includes('struct Entity'), 'C++ should have Entity struct');
    assert(cpp.includes('char name[64]'), 'C++ should have name string');
    assert(cpp.includes('float position_x'), 'C++ should flatten Vec2');

    // Verify TypeScript output
    assert(ts.includes('class Vec2View'), 'TS should have Vec2View');
    assert(ts.includes('class EntityView'), 'TS should have EntityView');
    assert(ts.includes('get name(): string'), 'TS should have string getter');
    assert(ts.includes('get position_x(): number'), 'TS should flatten position');

    // Verify layout
    assert(layouts.Entity, 'should have Entity layout');
    // Vec2 (8) + name (64) + tag (64) + bool (1) + padding (3) to align to 4 = 140
    assertEqual(layouts.Entity.size, 140, 'Entity size with strings');
  });

  await test('string field appears in toObject output', async () => {
    const { ts, js } = generateAlignedCode(STRING_SCHEMA, { defaultStringLength: 31 });

    // TypeScript toObject should include string fields
    assert(ts.includes('name: this.name,'), 'TS toObject should include name');

    // JavaScript toObject should include string fields
    assert(js.includes('name: this.name,'), 'JS toObject should include name');
  });

  await test('string field works with copyFrom', async () => {
    const { ts, js } = generateAlignedCode(STRING_SCHEMA, { defaultStringLength: 31 });

    // TypeScript copyFrom should handle strings
    assert(ts.includes('if (obj.name !== undefined) this.name = obj.name as string'), 'TS copyFrom should handle name');

    // JavaScript copyFrom should handle strings
    assert(js.includes('if (obj.name !== undefined) this.name = obj.name'), 'JS copyFrom should handle name');
  });
}

// =============================================================================
// Integration Tests
// =============================================================================

async function runIntegrationTests() {
  log('\n[Integration Tests]');

  await test('generateAlignedCode returns all outputs', async () => {
    const result = generateAlignedCode(SIMPLE_STRUCT_SCHEMA);

    assert(typeof result.cpp === 'string', 'should have cpp');
    assert(typeof result.ts === 'string', 'should have ts');
    assert(typeof result.schema === 'object', 'should have schema');
    assert(typeof result.layouts === 'object', 'should have layouts');
    assert(result.layouts.Vec3, 'should have Vec3 layout');
  });

  await test('complex schema generates valid code', async () => {
    const complexSchema = `
      namespace App;

      enum Status : ubyte { Idle, Active, Done }

      struct Point { x: float; y: float; }

      struct Rect {
        topLeft: Point;
        bottomRight: Point;
      }
    `;

    const result = generateAlignedCode(complexSchema);

    // Verify C++ has all types
    assert(result.cpp.includes('enum class Status'), 'cpp should have enum');
    assert(result.cpp.includes('struct Point'), 'cpp should have Point');
    assert(result.cpp.includes('struct Rect'), 'cpp should have Rect');

    // Verify TypeScript has all types
    assert(result.ts.includes('export const Status'), 'ts should have enum');
    assert(result.ts.includes('export class PointView'), 'ts should have PointView');
    assert(result.ts.includes('export class RectView'), 'ts should have RectView');

    // Verify layouts
    assert(result.layouts.Point.size === 8, 'Point should be 8 bytes');
    assert(result.layouts.Rect.size === 16, 'Rect should be 16 bytes');
  });

  await test('generated TypeScript has valid structure', async () => {
    const result = generateAlignedCode(SIMPLE_STRUCT_SCHEMA);

    // Verify the generated code has all expected components
    assert(result.ts.includes('class Vec3View'), 'should have Vec3View class');
    assert(result.ts.includes('class Vec3ArrayView'), 'should have array view');
    assert(result.ts.includes('get x()'), 'should have x getter');
    assert(result.ts.includes('set x('), 'should have x setter');
    assert(result.ts.includes('getFloat32'), 'should use DataView');
    assert(result.ts.includes('setFloat32'), 'should use DataView for writing');
    assert(result.ts.includes('fromMemory'), 'should have WASM factory');
    assert(result.ts.includes('fromBytes'), 'should have bytes factory');
    assert(result.ts.includes('toObject()'), 'should have debug helper');
    assert(result.ts.includes('Symbol.iterator'), 'array view should be iterable');
  });

  await test('generated TypeScript has conversion helpers', async () => {
    const result = generateAlignedCode(SIMPLE_STRUCT_SCHEMA);

    // Verify conversion methods
    assert(result.ts.includes('copyFrom('), 'should have copyFrom method');
    assert(result.ts.includes('copyTo('), 'should have copyTo method');
    assert(result.ts.includes('getBytes()'), 'should have getBytes method');
    assert(result.ts.includes('static allocate()'), 'should have allocate factory');
  });

  await test('generated JavaScript has conversion helpers', async () => {
    const result = generateAlignedCode(SIMPLE_STRUCT_SCHEMA);

    // Verify JS output has same conversion methods
    assert(result.js.includes('copyFrom('), 'JS should have copyFrom method');
    assert(result.js.includes('copyTo('), 'JS should have copyTo method');
    assert(result.js.includes('getBytes()'), 'JS should have getBytes method');
    assert(result.js.includes('static allocate()'), 'JS should have allocate factory');
  });

  await test('generated C++ has helper methods', async () => {
    const result = generateAlignedCode(SIMPLE_STRUCT_SCHEMA);

    // Verify C++ helper methods
    assert(result.cpp.includes('#include <cstring>'), 'should include cstring');
    assert(result.cpp.includes('static Vec3* fromBytes('), 'should have fromBytes');
    assert(result.cpp.includes('void copyTo(void* dest)'), 'should have copyTo');
    assert(result.cpp.includes('void copyFrom(const Vec3& src)'), 'should have copyFrom');
    assert(result.cpp.includes('std::memcpy'), 'should use memcpy');
  });
}

// =============================================================================
// Main
// =============================================================================

async function main() {
  log('============================================================');
  log('Aligned Code Generation Test Suite');
  log('============================================================');

  await runParsingTests();
  await runLayoutTests();
  await runCppTests();
  await runTypeScriptTests();
  await runStringTests();
  await runIntegrationTests();

  log('\n============================================================');
  log(`Results: ${passed} passed, ${failed} failed`);
  log('============================================================');

  process.exit(failed > 0 ? 1 : 0);
}

main().catch(err => {
  console.error('Test suite failed:', err);
  process.exit(1);
});
