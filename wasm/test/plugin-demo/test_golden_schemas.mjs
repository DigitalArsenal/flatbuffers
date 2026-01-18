#!/usr/bin/env node
/**
 * Golden Schema Test Suite
 *
 * Tests the Aligned Buffer ABI using the actual FlatBuffers test schemas
 * from the tests/ directory. These are the canonical "golden" schemas used
 * to validate FlatBuffers implementations.
 *
 * Schemas tested:
 * - monster_test.fbs: Complex nested structs (Vec3, Test, Ability, StructOfStructs)
 * - arrays_test.fbs: Fixed-size arrays with nested structs (NestedStruct, ArrayStruct)
 * - alignment_test.fbs: Various alignment scenarios (BadAlignmentSmall/Large)
 * - native_type_test.fbs: Vector3D geometry types
 */

import { fileURLToPath } from 'url';
import path from 'path';
import fs from 'fs';
import { execSync, spawnSync } from 'child_process';
import { generateAlignedCode } from '../../src/aligned-codegen.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.join(__dirname, '..', '..', '..');
const TESTS_DIR = path.join(REPO_ROOT, 'tests');
const BUILD_DIR = path.join(__dirname, 'build-golden');

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

function assertClose(actual, expected, epsilon = 0.0001, message) {
  if (Math.abs(actual - expected) > epsilon) {
    throw new Error(`${message || 'Assertion failed'}: expected ${expected} ± ${epsilon}, got ${actual}`);
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
    if (process.env.DEBUG) {
      console.error(err.stack);
    }
  }
}

function checkEmcc() {
  try {
    execSync('emcc --version', { stdio: 'pipe' });
    return true;
  } catch {
    const emsdkRoot = path.join(REPO_ROOT, 'build', 'wasm', '_deps', 'emsdk-src');
    const emsdkEnv = path.join(emsdkRoot, 'emsdk_env.sh');
    if (fs.existsSync(emsdkEnv)) {
      try {
        const pathResult = execSync(`source "${emsdkEnv}" 2>/dev/null && echo "$PATH"`, {
          shell: '/bin/bash', stdio: 'pipe', encoding: 'utf8'
        });
        process.env.PATH = pathResult.trim();
        execSync('emcc --version', { stdio: 'pipe' });
        return true;
      } catch { return false; }
    }
    return false;
  }
}

function evalJsModule(jsCode) {
  const wrappedCode = `
    const exports = {};
    ${jsCode}
    return { ${jsCode.match(/^(?:const|class)\s+(\w+)/gm)?.map(m => m.split(/\s+/)[1]).join(', ') || ''} };
  `;
  return new Function(wrappedCode)();
}

// =============================================================================
// Monster Test Schema - Complex nested structs
// =============================================================================

async function runMonsterTests() {
  log('\n[monster_test.fbs - Core Game Types]');

  // Extract just the struct definitions we can use (no includes, no tables with strings)
  const monsterStructs = `
namespace MyGame.Example;

// Enums from monster_test.fbs
enum Color : ubyte { Red = 0, Green = 1, Blue = 3 }
enum Race : byte { None = -1, Human = 0, Dwarf = 1, Elf = 2 }

// Core structs from monster_test.fbs
struct Test {
  a: short;
  b: byte;
}

struct Vec3 {
  x: float;
  y: float;
  z: float;
  test1: double;
  test2: Color;
  test3: Test;
}

struct Ability {
  id: uint;
  distance: uint;
}

struct StructOfStructs {
  a: Ability;
  b: Test;
  c: Ability;
}

struct StructOfStructsOfStructs {
  a: StructOfStructs;
}
`;

  const result = generateAlignedCode(monsterStructs);

  await test('Test struct: 4 bytes (short + byte + padding)', async () => {
    const layout = result.layouts.Test;
    assertEqual(layout.size, 4, 'Test should be 4 bytes');
    assertEqual(layout.align, 2, 'Test should be 2-byte aligned');
    assertEqual(layout.fields[0].offset, 0, 'Test.a offset should be 0');
    assertEqual(layout.fields[1].offset, 2, 'Test.b offset should be 2');
  });

  await test('Vec3 struct: 32 bytes with nested Test', async () => {
    const layout = result.layouts.Vec3;
    // x(4) + y(4) + z(4) + test1(8) + test2(1) + pad(1) + test3(4) + pad(6) = 32
    // Actually: needs to be 8-byte aligned due to double
    assertEqual(layout.align, 8, 'Vec3 should be 8-byte aligned (has double)');
    assert(layout.size >= 28, 'Vec3 should be at least 28 bytes');
  });

  await test('Ability struct: 8 bytes', async () => {
    const layout = result.layouts.Ability;
    assertEqual(layout.size, 8, 'Ability should be 8 bytes');
    assertEqual(layout.align, 4, 'Ability should be 4-byte aligned');
  });

  await test('StructOfStructs: nested structs flattened', async () => {
    const layout = result.layouts.StructOfStructs;
    // Ability(8) + Test(4) + Ability(8) = 20
    assertEqual(layout.size, 20, 'StructOfStructs should be 20 bytes');

    // Check flattened field names in generated code
    assert(result.ts.includes('a_id'), 'TS should have a_id');
    assert(result.ts.includes('a_distance'), 'TS should have a_distance');
    assert(result.ts.includes('b_a'), 'TS should have b_a (Test.a)');
    assert(result.ts.includes('b_b'), 'TS should have b_b (Test.b)');
    assert(result.ts.includes('c_id'), 'TS should have c_id');
  });

  await test('StructOfStructsOfStructs: deep nesting', async () => {
    const layout = result.layouts.StructOfStructsOfStructs;
    assertEqual(layout.size, 20, 'StructOfStructsOfStructs should be 20 bytes');

    // Check deeply flattened names
    assert(result.ts.includes('a_a_id'), 'TS should have a_a_id');
    assert(result.ts.includes('a_b_a'), 'TS should have a_b_a');
    assert(result.ts.includes('a_c_distance'), 'TS should have a_c_distance');
  });

  await test('Color enum generation', async () => {
    assert(result.cpp.includes('enum class Color'), 'C++ should have Color enum');
    assert(result.cpp.includes('Red = 0'), 'C++ should have Red = 0');
    assert(result.cpp.includes('Green = 1'), 'C++ should have Green = 1');
    assert(result.cpp.includes('Blue = 3'), 'C++ should have Blue = 3');

    assert(result.ts.includes('export const Color'), 'TS should have Color');
  });

  await test('Race enum with negative value', async () => {
    assert(result.cpp.includes('enum class Race'), 'C++ should have Race enum');
    assert(result.cpp.includes('None = -1'), 'C++ should have None = -1');
  });

  await test('Vec3 JS view operations', async () => {
    const mod = evalJsModule(result.js);

    const vec = mod.Vec3View.allocate();

    // Set position
    vec.x = 1.0;
    vec.y = 2.0;
    vec.z = 3.0;

    // Set double field
    vec.test1 = 3.14159265358979;

    // Set enum field
    vec.test2 = 3;  // Blue

    // Set nested Test struct
    vec.test3_a = 100;
    vec.test3_b = 42;

    // Verify
    assertClose(vec.x, 1.0);
    assertClose(vec.y, 2.0);
    assertClose(vec.z, 3.0);
    assertClose(vec.test1, 3.14159265358979, 0.0000001);
    assertEqual(vec.test2, 3);
    assertEqual(vec.test3_a, 100);
    assertEqual(vec.test3_b, 42);

    // Test toObject
    const obj = vec.toObject();
    assertClose(obj.x, 1.0);
    assertEqual(obj.test3_b, 42);
  });

  await test('StructOfStructs JS operations', async () => {
    const mod = evalJsModule(result.js);

    const sos = mod.StructOfStructsView.allocate();

    // Set first Ability
    sos.a_id = 1;
    sos.a_distance = 100;

    // Set Test
    sos.b_a = 50;
    sos.b_b = 25;

    // Set second Ability
    sos.c_id = 2;
    sos.c_distance = 200;

    // Verify
    assertEqual(sos.a_id, 1);
    assertEqual(sos.a_distance, 100);
    assertEqual(sos.b_a, 50);
    assertEqual(sos.b_b, 25);
    assertEqual(sos.c_id, 2);
    assertEqual(sos.c_distance, 200);

    // Test copyFrom
    sos.copyFrom({ a_id: 999, c_distance: 500 });
    assertEqual(sos.a_id, 999);
    assertEqual(sos.c_distance, 500);
    // Others unchanged
    assertEqual(sos.b_a, 50);
  });
}

// =============================================================================
// Arrays Test Schema - Fixed arrays with nested structs
// =============================================================================

async function runArraysTests() {
  log('\n[arrays_test.fbs - Fixed Arrays]');

  const schema = fs.readFileSync(path.join(TESTS_DIR, 'arrays_test.fbs'), 'utf8');
  const result = generateAlignedCode(schema);

  await test('TestEnum generation', async () => {
    assert(result.cpp.includes('enum class TestEnum'), 'C++ should have TestEnum');
    assert(result.cpp.includes('A = 0'), 'C++ should have A = 0');
    assert(result.cpp.includes('B = 1'), 'C++ should have B = 1');
    assert(result.cpp.includes('C = 2'), 'C++ should have C = 2');
  });

  await test('NestedStruct layout', async () => {
    const layout = result.layouts.NestedStruct;
    // a:[int:2] = 8 bytes
    // b:TestEnum (byte) = 1 byte
    // c:[TestEnum:2] = 2 bytes
    // d:[int64:2] = 16 bytes
    // Total with alignment: 8 + 1 + 2 + padding(5) + 16 = 32? Let's check
    assert(layout.size >= 27, 'NestedStruct should be at least 27 bytes');
    assertEqual(layout.align, 8, 'NestedStruct should be 8-byte aligned (has int64)');
  });

  await test('ArrayStruct layout with nested array', async () => {
    const layout = result.layouts.ArrayStruct;
    // Complex layout with d:[NestedStruct:2]
    // This is a challenging case - array of nested structs
    assert(layout.size > 0, 'ArrayStruct should have valid size');
    assert(result.cpp.includes('float a'), 'C++ should have float a');
    assert(result.cpp.includes('int32_t b[15]'), 'C++ should have b[15] (0xF = 15)');
  });

  await test('NestedStruct JS array operations', async () => {
    const mod = evalJsModule(result.js);

    const nested = mod.NestedStructView.allocate();

    // Set int array
    nested.a[0] = 100;
    nested.a[1] = 200;

    // Set enum
    nested.b = 1;  // B

    // Set enum array
    nested.c[0] = 0;  // A
    nested.c[1] = 2;  // C

    // Set int64 array (bigint)
    nested.d[0] = 0x123456789ABCDEFn;
    nested.d[1] = 0xFEDCBA987654321n;

    // Verify
    assertEqual(nested.a[0], 100);
    assertEqual(nested.a[1], 200);
    assertEqual(nested.b, 1);
    assertEqual(nested.c[0], 0);
    assertEqual(nested.c[1], 2);
    assertEqual(nested.d[0], 0x123456789ABCDEFn);
    assertEqual(nested.d[1], 0xFEDCBA987654321n);
  });
}

// =============================================================================
// Alignment Test Schema - Various alignment scenarios
// =============================================================================

async function runAlignmentTests() {
  log('\n[alignment_test.fbs - Alignment Scenarios]');

  const schema = fs.readFileSync(path.join(TESTS_DIR, 'alignment_test.fbs'), 'utf8');
  const result = generateAlignedCode(schema);

  await test('BadAlignmentSmall: 12 bytes, 4-byte aligned', async () => {
    const layout = result.layouts.BadAlignmentSmall;
    assertEqual(layout.size, 12, 'BadAlignmentSmall should be 12 bytes (per schema comment)');
    assertEqual(layout.align, 4, 'BadAlignmentSmall should be 4-byte aligned (per schema comment)');
  });

  await test('BadAlignmentLarge: 8 bytes, 8-byte aligned', async () => {
    const layout = result.layouts.BadAlignmentLarge;
    assertEqual(layout.size, 8, 'BadAlignmentLarge should be 8 bytes (per schema comment)');
    assertEqual(layout.align, 8, 'BadAlignmentLarge should be 8-byte aligned (per schema comment)');
  });

  await test('EvenSmallStruct: 2 bytes, 1-byte aligned', async () => {
    const layout = result.layouts.EvenSmallStruct;
    assertEqual(layout.size, 2, 'EvenSmallStruct should be 2 bytes (per schema comment)');
    assertEqual(layout.align, 1, 'EvenSmallStruct should be 1-byte aligned (per schema comment)');
  });

  await test('OddSmallStruct: 3 bytes, 1-byte aligned', async () => {
    const layout = result.layouts.OddSmallStruct;
    assertEqual(layout.size, 3, 'OddSmallStruct should be 3 bytes (per schema comment)');
    assertEqual(layout.align, 1, 'OddSmallStruct should be 1-byte aligned (per schema comment)');
  });

  await test('BadAlignmentSmall JS operations', async () => {
    const mod = evalJsModule(result.js);

    const small = mod.BadAlignmentSmallView.allocate();
    small.var_0 = 0xDEADBEEF;
    small.var_1 = 0xCAFEBABE;
    small.var_2 = 0x12345678;

    assertEqual(small.var_0, 0xDEADBEEF >>> 0);
    assertEqual(small.var_1, 0xCAFEBABE >>> 0);
    assertEqual(small.var_2, 0x12345678);
  });

  await test('BadAlignmentLarge JS with 64-bit', async () => {
    const mod = evalJsModule(result.js);

    const large = mod.BadAlignmentLargeView.allocate();
    large.var_0 = 0x123456789ABCDEF0n;

    assertEqual(large.var_0, 0x123456789ABCDEF0n);
  });

  await test('Small structs byte precision', async () => {
    const mod = evalJsModule(result.js);

    // Test even struct
    const even = mod.EvenSmallStructView.allocate();
    even.var_0 = 0xAB;
    even.var_1 = 0xCD;
    assertEqual(even.var_0, 0xAB);
    assertEqual(even.var_1, 0xCD);

    // Test odd struct
    const odd = mod.OddSmallStructView.allocate();
    odd.var_0 = 0x11;
    odd.var_1 = 0x22;
    odd.var_2 = 0x33;
    assertEqual(odd.var_0, 0x11);
    assertEqual(odd.var_1, 0x22);
    assertEqual(odd.var_2, 0x33);
  });
}

// =============================================================================
// Native Type Test Schema - Geometry types
// =============================================================================

async function runNativeTypeTests() {
  log('\n[native_type_test.fbs - Geometry Types]');

  // Extract just the structs (no native_include)
  const geometrySchema = `
namespace Geometry;

struct Vector3D {
  x: float;
  y: float;
  z: float;
}

struct Vector3DAlt {
  a: float;
  b: float;
  c: float;
}
`;

  const result = generateAlignedCode(geometrySchema);

  await test('Vector3D: 12 bytes, 4-byte aligned', async () => {
    const layout = result.layouts.Vector3D;
    assertEqual(layout.size, 12, 'Vector3D should be 12 bytes');
    assertEqual(layout.align, 4, 'Vector3D should be 4-byte aligned');
  });

  await test('Vector3DAlt identical layout', async () => {
    const v3d = result.layouts.Vector3D;
    const v3da = result.layouts.Vector3DAlt;
    assertEqual(v3d.size, v3da.size, 'Both Vector3D variants should have same size');
    assertEqual(v3d.align, v3da.align, 'Both Vector3D variants should have same alignment');
  });

  await test('Vector3D JS operations', async () => {
    const mod = evalJsModule(result.js);

    const v = mod.Vector3DView.allocate();
    v.x = 1.0;
    v.y = 2.0;
    v.z = 3.0;

    assertClose(v.x, 1.0);
    assertClose(v.y, 2.0);
    assertClose(v.z, 3.0);

    // Test magnitude calculation pattern
    const mag = Math.sqrt(v.x * v.x + v.y * v.y + v.z * v.z);
    assertClose(mag, Math.sqrt(14), 0.0001);
  });

  await test('Vector3D array view', async () => {
    const mod = evalJsModule(result.js);

    // Allocate array of 4 vectors
    const buffer = new ArrayBuffer(mod.VECTOR3D_SIZE * 4);
    const arr = new mod.Vector3DArrayView(buffer, 0, 4);

    // Set values
    for (let i = 0; i < 4; i++) {
      const v = arr.at(i);
      v.x = i * 10;
      v.y = i * 10 + 1;
      v.z = i * 10 + 2;
    }

    // Verify
    for (let i = 0; i < 4; i++) {
      const v = arr.at(i);
      assertClose(v.x, i * 10);
      assertClose(v.y, i * 10 + 1);
      assertClose(v.z, i * 10 + 2);
    }

    // Test iteration
    let count = 0;
    for (const v of arr) {
      assertClose(v.x, count * 10);
      count++;
    }
    assertEqual(count, 4);
  });
}

// =============================================================================
// WASM Integration with Golden Schemas
// =============================================================================

async function runWasmGoldenTests() {
  if (!checkEmcc()) {
    log('\n[WASM Golden Schema Tests - SKIPPED]');
    log('  emcc not found');
    return;
  }

  log('\n[WASM Golden Schema Integration]');

  // Setup
  if (fs.existsSync(BUILD_DIR)) {
    fs.rmSync(BUILD_DIR, { recursive: true });
  }
  fs.mkdirSync(BUILD_DIR, { recursive: true });

  // Generate aligned code for monster structs
  const monsterStructs = `
namespace MyGame.Example;

enum Color : ubyte { Red = 0, Green = 1, Blue = 3 }

struct Test {
  a: short;
  b: byte;
}

struct Vec3 {
  x: float;
  y: float;
  z: float;
  test1: double;
  test2: Color;
  test3: Test;
}

struct Ability {
  id: uint;
  distance: uint;
}
`;

  const result = generateAlignedCode(monsterStructs);
  fs.writeFileSync(path.join(BUILD_DIR, 'monster_aligned.h'), result.cpp);

  // Create plugin that processes Vec3 (normalize) and Ability (scale distance)
  const pluginCpp = `
#include "monster_aligned.h"
#include <cmath>

using namespace MyGame::Example::Aligned;

// Input/Output buffers
static Vec3 g_vec3_in;
static Vec3 g_vec3_out;
static Ability g_ability_in;
static Ability g_ability_out;

extern "C" {

// Vec3 operations
__attribute__((export_name("get_vec3_in")))
Vec3* get_vec3_in() { return &g_vec3_in; }

__attribute__((export_name("get_vec3_out")))
Vec3* get_vec3_out() { return &g_vec3_out; }

__attribute__((export_name("vec3_size")))
size_t vec3_size() { return sizeof(Vec3); }

__attribute__((export_name("normalize_vec3")))
int normalize_vec3() {
  float len = std::sqrt(
    g_vec3_in.x * g_vec3_in.x +
    g_vec3_in.y * g_vec3_in.y +
    g_vec3_in.z * g_vec3_in.z
  );
  if (len < 0.0001f) return -1;  // Error: zero length

  g_vec3_out.x = g_vec3_in.x / len;
  g_vec3_out.y = g_vec3_in.y / len;
  g_vec3_out.z = g_vec3_in.z / len;
  g_vec3_out.test1 = static_cast<double>(len);  // Store original length
  g_vec3_out.test2 = g_vec3_in.test2;  // Copy color
  g_vec3_out.test3_a = g_vec3_in.test3_a;
  g_vec3_out.test3_b = g_vec3_in.test3_b;
  return 0;
}

// Ability operations
__attribute__((export_name("get_ability_in")))
Ability* get_ability_in() { return &g_ability_in; }

__attribute__((export_name("get_ability_out")))
Ability* get_ability_out() { return &g_ability_out; }

__attribute__((export_name("ability_size")))
size_t ability_size() { return sizeof(Ability); }

__attribute__((export_name("scale_ability")))
int scale_ability(uint32_t multiplier) {
  g_ability_out.id = g_ability_in.id;
  g_ability_out.distance = g_ability_in.distance * multiplier;
  return 0;
}

// Combined operation: process Vec3 and Ability together
__attribute__((export_name("process_monster_data")))
int process_monster_data() {
  // Normalize Vec3
  int result = normalize_vec3();
  if (result != 0) return result;

  // Scale ability by 2
  g_ability_out.id = g_ability_in.id;
  g_ability_out.distance = g_ability_in.distance * 2;

  return 0;
}

}
`;

  fs.writeFileSync(path.join(BUILD_DIR, 'monster_plugin.cpp'), pluginCpp);

  await test('compiles monster plugin', async () => {
    const result = spawnSync('emcc', [
      path.join(BUILD_DIR, 'monster_plugin.cpp'),
      '-o', path.join(BUILD_DIR, 'monster_plugin.mjs'),
      '-I', BUILD_DIR,
      '-s', 'EXPORTED_FUNCTIONS=["_get_vec3_in","_get_vec3_out","_vec3_size","_normalize_vec3","_get_ability_in","_get_ability_out","_ability_size","_scale_ability","_process_monster_data"]',
      '-s', 'EXPORTED_RUNTIME_METHODS=["HEAPU8"]',
      '-s', 'MODULARIZE=1',
      '-s', 'EXPORT_ES6=1',
      '-O2'
    ], { stdio: 'pipe' });

    if (result.status !== 0) {
      throw new Error(`Compile failed: ${result.stderr?.toString()}`);
    }
  });

  await test('Vec3 normalize operation', async () => {
    const createModule = (await import(path.join(BUILD_DIR, 'monster_plugin.mjs'))).default;
    const plugin = await createModule();

    const inPtr = plugin._get_vec3_in();
    const outPtr = plugin._get_vec3_out();
    const size = plugin._vec3_size();

    // Verify size matches our generated code
    assertEqual(size, result.layouts.Vec3.size, 'Vec3 size should match');

    // Get field offsets from computed layout (respects alignment)
    const layout = result.layouts.Vec3;
    const getOffset = (name) => {
      // Find field (may be nested like test3_a)
      for (const f of layout.fields) {
        if (f.name === name) return f.offset;
        // Handle nested fields
        if (name.startsWith(f.name + '_') && f.nestedLayout) {
          const nestedName = name.slice(f.name.length + 1);
          for (const nf of f.nestedLayout.fields) {
            if (nf.name === nestedName) return f.offset + nf.offset;
          }
        }
      }
      throw new Error(`Field not found: ${name}`);
    };

    // Create views
    const inView = new DataView(plugin.HEAPU8.buffer, inPtr, size);
    const outView = new DataView(plugin.HEAPU8.buffer, outPtr, size);

    // Set input: (3, 4, 0) - length = 5, using computed offsets
    inView.setFloat32(getOffset('x'), 3.0, true);
    inView.setFloat32(getOffset('y'), 4.0, true);
    inView.setFloat32(getOffset('z'), 0.0, true);
    inView.setFloat64(getOffset('test1'), 0.0, true);
    inView.setUint8(getOffset('test2'), 3);  // Blue
    inView.setInt16(getOffset('test3_a'), 100, true);
    inView.setInt8(getOffset('test3_b'), 42);

    // Normalize
    const err = plugin._normalize_vec3();
    assertEqual(err, 0, 'normalize should succeed');

    // Check output: (0.6, 0.8, 0), length stored in test1
    assertClose(outView.getFloat32(getOffset('x'), true), 0.6, 0.0001, 'normalized x');
    assertClose(outView.getFloat32(getOffset('y'), true), 0.8, 0.0001, 'normalized y');
    assertClose(outView.getFloat32(getOffset('z'), true), 0.0, 0.0001, 'normalized z');
    assertClose(outView.getFloat64(getOffset('test1'), true), 5.0, 0.0001, 'original length');
    assertEqual(outView.getUint8(getOffset('test2')), 3, 'color preserved');
    assertEqual(outView.getInt16(getOffset('test3_a'), true), 100, 'test3.a preserved');
    assertEqual(outView.getInt8(getOffset('test3_b')), 42, 'test3.b preserved');
  });

  await test('Ability scale operation', async () => {
    const createModule = (await import(path.join(BUILD_DIR, 'monster_plugin.mjs'))).default;
    const plugin = await createModule();

    const inPtr = plugin._get_ability_in();
    const outPtr = plugin._get_ability_out();
    const size = plugin._ability_size();

    assertEqual(size, 8, 'Ability size should be 8');

    const inView = new DataView(plugin.HEAPU8.buffer, inPtr, size);
    const outView = new DataView(plugin.HEAPU8.buffer, outPtr, size);

    // Set input
    inView.setUint32(0, 42, true);     // id
    inView.setUint32(4, 100, true);    // distance

    // Scale by 5
    plugin._scale_ability(5);

    // Check output
    assertEqual(outView.getUint32(0, true), 42, 'id preserved');
    assertEqual(outView.getUint32(4, true), 500, 'distance scaled');
  });

  await test('Combined monster data processing', async () => {
    const createModule = (await import(path.join(BUILD_DIR, 'monster_plugin.mjs'))).default;
    const plugin = await createModule();

    // Set up Vec3 input
    const vec3InPtr = plugin._get_vec3_in();
    const vec3In = new DataView(plugin.HEAPU8.buffer, vec3InPtr, plugin._vec3_size());
    vec3In.setFloat32(0, 1.0, true);
    vec3In.setFloat32(4, 0.0, true);
    vec3In.setFloat32(8, 0.0, true);

    // Set up Ability input
    const abilityInPtr = plugin._get_ability_in();
    const abilityIn = new DataView(plugin.HEAPU8.buffer, abilityInPtr, 8);
    abilityIn.setUint32(0, 1, true);      // id
    abilityIn.setUint32(4, 50, true);     // distance

    // Process
    const err = plugin._process_monster_data();
    assertEqual(err, 0, 'processing should succeed');

    // Check Vec3 output (normalized unit vector)
    const vec3OutPtr = plugin._get_vec3_out();
    const vec3Out = new DataView(plugin.HEAPU8.buffer, vec3OutPtr, plugin._vec3_size());
    assertClose(vec3Out.getFloat32(0, true), 1.0, 0.0001, 'unit x');
    assertClose(vec3Out.getFloat32(4, true), 0.0, 0.0001, 'unit y');
    assertClose(vec3Out.getFloat32(8, true), 0.0, 0.0001, 'unit z');

    // Check Ability output (distance * 2)
    const abilityOutPtr = plugin._get_ability_out();
    const abilityOut = new DataView(plugin.HEAPU8.buffer, abilityOutPtr, 8);
    assertEqual(abilityOut.getUint32(0, true), 1, 'ability id');
    assertEqual(abilityOut.getUint32(4, true), 100, 'ability distance doubled');
  });

  // Cleanup
  if (!process.env.KEEP_BUILD) {
    fs.rmSync(BUILD_DIR, { recursive: true });
  }
}

// =============================================================================
// Main
// =============================================================================

async function main() {
  log('============================================================');
  log('Golden Schema Test Suite');
  log('============================================================');
  log('');
  log('Testing Aligned Buffer ABI with official FlatBuffers test schemas');

  await runMonsterTests();
  await runArraysTests();
  await runAlignmentTests();
  await runNativeTypeTests();
  await runWasmGoldenTests();

  log('\n============================================================');
  log(`Results: ${passed} passed, ${failed} failed`);
  log('============================================================');

  process.exit(failed > 0 ? 1 : 0);
}

main().catch(err => {
  console.error('Test failed:', err);
  process.exit(1);
});
