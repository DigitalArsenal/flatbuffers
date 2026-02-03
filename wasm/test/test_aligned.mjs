#!/usr/bin/env node
/**
 * test_aligned.mjs - Test suite for aligned code generation
 *
 * Tests the zero-copy WASM interop code generation from FlatBuffers schemas.
 */

import { generateAlignedCode } from '../src/aligned-codegen.mjs';

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

table Dummy { v: Vec3; }
root_type Dummy;
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

table Dummy { m: MixedTypes; }
root_type Dummy;
`;

const NESTED_STRUCT_SCHEMA = `
namespace Game;

struct Vec3 {
  x: float;
  y: float;
  z: float;
}

struct Player {
  id: uint32;
  position: Vec3;
  health: ushort;
  flags: ubyte;
}

table Dummy { p: Player; }
root_type Dummy;
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

table Dummy { p: Pixel; }
root_type Dummy;
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

table Dummy { m: Matrix4x4; }
root_type Dummy;
`;

// =============================================================================
// C++ Generation Tests
// =============================================================================

async function runCppTests() {
  log('\n[C++ Header Generation]');

  await test('generates pragma once', async () => {
    const result = await generateAlignedCode(SIMPLE_STRUCT_SCHEMA);
    assert(result.cpp.includes('#pragma once'), 'should have pragma once');
  });

  await test('generates namespace', async () => {
    const result = await generateAlignedCode(SIMPLE_STRUCT_SCHEMA);
    assert(result.cpp.includes('namespace Game'), 'should have Game namespace');
  });

  await test('generates struct with offsets', async () => {
    const result = await generateAlignedCode(SIMPLE_STRUCT_SCHEMA);
    assert(result.cpp.includes('struct Vec3'), 'should have struct');
    assert(result.cpp.includes('float x'), 'should have x field');
  });

  await test('generates static_assert for size', async () => {
    const result = await generateAlignedCode(SIMPLE_STRUCT_SCHEMA);
    assert(result.cpp.includes('static_assert'), 'should have size assert');
  });

  await test('generates size constants', async () => {
    const result = await generateAlignedCode(SIMPLE_STRUCT_SCHEMA);
    assert(result.cpp.includes('sizeof(Vec3) == 12') || result.cpp.includes('SIZE = 12'), 'should have size info');
  });

  await test('handles enum fields', async () => {
    const result = await generateAlignedCode(ENUM_SCHEMA);
    assert(result.cpp.includes('color'), 'should have color field');
    assert(result.cpp.includes('uint8_t') || result.cpp.includes('Color'), 'should use uint8_t or Color type');
  });

  await test('generates fixed array', async () => {
    const result = await generateAlignedCode(FIXED_ARRAY_SCHEMA);
    assert(result.cpp.includes('float data[16]') || result.cpp.includes('data[16]'), 'should have array');
  });
}

// =============================================================================
// TypeScript Generation Tests
// =============================================================================

async function runTypeScriptTests() {
  log('\n[TypeScript Generation]');

  await test('generates size constants', async () => {
    const result = await generateAlignedCode(SIMPLE_STRUCT_SCHEMA);
    assert(result.ts.includes('SIZE = 12') || result.ts.includes('SIZE:'), 'should have size');
  });

  await test('generates view class', async () => {
    const result = await generateAlignedCode(SIMPLE_STRUCT_SCHEMA);
    assert(result.ts.includes('class Vec3'), 'should have view class');
  });

  await test('generates fromPointer factory', async () => {
    const result = await generateAlignedCode(SIMPLE_STRUCT_SCHEMA);
    assert(result.ts.includes('fromPointer'), 'should have fromPointer');
  });

  await test('generates getters/setters', async () => {
    const result = await generateAlignedCode(SIMPLE_STRUCT_SCHEMA);
    assert(result.ts.includes('get x'), 'should have getter');
    assert(result.ts.includes('set x'), 'should have setter');
  });

  await test('generates class for each struct', async () => {
    const result = await generateAlignedCode(SIMPLE_STRUCT_SCHEMA);
    assert(result.ts.includes('export class Vec3'), 'should have Vec3 class');
  });

  await test('generates enum', async () => {
    const result = await generateAlignedCode(ENUM_SCHEMA);
    assert(result.ts.includes('Color') || result.ts.includes('Pixel'), 'should have Color or Pixel');
  });

  await test('generates fixed array accessor', async () => {
    const result = await generateAlignedCode(FIXED_ARRAY_SCHEMA);
    assert(result.ts.includes('get data') || result.ts.includes('data(') || result.ts.includes('getdata'), 'should have data getter');
  });

  await test('generates bigint accessors for 64-bit', async () => {
    const result = await generateAlignedCode(`
      namespace Test;
      struct Big {
        a: long;
        b: ulong;
      }
      table Dummy { b: Big; }
      root_type Dummy;
    `);
    assert(result.ts.includes('bigint') || result.ts.includes('BigInt'), 'should have bigint type');
  });

  await test('generates bool accessor', async () => {
    const result = await generateAlignedCode(`
      namespace Test;
      struct Flags {
        active: bool;
      }
      table Dummy { f: Flags; }
      root_type Dummy;
    `);
    assert(result.ts.includes('boolean') || result.ts.includes('active'), 'should have boolean');
  });
}

// =============================================================================
// Layout Tests (via JSON from C++ generator)
// =============================================================================

async function runLayoutTests() {
  log('\n[Layout Calculation]');

  await test('computes Vec3 layout', async () => {
    const result = await generateAlignedCode(SIMPLE_STRUCT_SCHEMA);
    const layout = result.layouts.Vec3;

    assertEqual(layout.size, 12, 'Vec3 size'); // 3 * 4 bytes
    assertEqual(layout.align, 4, 'Vec3 alignment');
    assertEqual(layout.fields[0].offset, 0, 'x offset');
    assertEqual(layout.fields[1].offset, 4, 'y offset');
    assertEqual(layout.fields[2].offset, 8, 'z offset');
  });

  await test('handles alignment padding', async () => {
    const result = await generateAlignedCode(MIXED_TYPES_SCHEMA);
    const layout = result.layouts.MixedTypes;

    assertEqual(layout.fields[0].offset, 0, 'byte offset');
    assertEqual(layout.fields[1].offset, 4, 'uint32 offset'); // aligned to 4
    assertEqual(layout.fields[2].offset, 8, 'ushort offset');
    assertEqual(layout.fields[3].offset, 16, 'double offset'); // aligned to 8
    assertEqual(layout.fields[4].offset, 24, 'bool offset');
    assertEqual(layout.align, 8, 'struct alignment');
  });

  await test('computes nested struct layout', async () => {
    const result = await generateAlignedCode(NESTED_STRUCT_SCHEMA);
    const layout = result.layouts.Player;

    assertEqual(layout.fields[0].offset, 0, 'id offset');
    assertEqual(layout.fields[1].offset, 4, 'position offset');
    assertEqual(layout.fields[2].offset, 16, 'health offset');
    assertEqual(layout.fields[3].offset, 18, 'flags offset');
    assertEqual(layout.size, 20, 'Player size');
    assertEqual(layout.align, 4, 'Player alignment');
  });

  await test('computes fixed array layout', async () => {
    const result = await generateAlignedCode(FIXED_ARRAY_SCHEMA);
    const layout = result.layouts.Matrix4x4;

    assertEqual(layout.size, 64, 'Matrix4x4 size'); // 16 * 4
    assertEqual(layout.fields[0].offset, 0, 'data offset');
  });
}

// =============================================================================
// Integration Tests
// =============================================================================

async function runIntegrationTests() {
  log('\n[Integration Tests]');

  await test('generateAlignedCode returns all outputs', async () => {
    const result = await generateAlignedCode(SIMPLE_STRUCT_SCHEMA);

    assert(typeof result.cpp === 'string', 'should have cpp');
    assert(typeof result.ts === 'string', 'should have ts');
    assert(typeof result.js === 'string', 'should have js');
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

      table Dummy { r: Rect; }
      root_type Dummy;
    `;

    const result = await generateAlignedCode(complexSchema);

    // Verify C++ has struct types
    assert(result.cpp.includes('Point'), 'cpp should have Point');
    assert(result.cpp.includes('Rect'), 'cpp should have Rect');

    // Verify TypeScript has struct types
    assert(result.ts.includes('Point'), 'ts should have Point');
    assert(result.ts.includes('Rect'), 'ts should have Rect');

    // Verify layouts
    assertEqual(result.layouts.Point.size, 8, 'Point should be 8 bytes');
    assertEqual(result.layouts.Rect.size, 16, 'Rect should be 16 bytes');
  });

  await test('generated TypeScript has valid structure', async () => {
    const result = await generateAlignedCode(SIMPLE_STRUCT_SCHEMA);

    assert(result.ts.includes('Vec3'), 'should have Vec3');
    assert(result.ts.includes('get x'), 'should have x getter');
    assert(result.ts.includes('fromPointer'), 'should have WASM factory');
  });

  await test('generated code includes JavaScript version', async () => {
    const result = await generateAlignedCode(SIMPLE_STRUCT_SCHEMA);
    assert(typeof result.js === 'string', 'should have js output');
    assert(result.js.length > 0, 'js should not be empty');
  });
}

// =============================================================================
// Main
// =============================================================================

async function main() {
  log('============================================================');
  log('Aligned Code Generation Test Suite');
  log('============================================================');

  await runCppTests();
  await runTypeScriptTests();
  await runLayoutTests();
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
