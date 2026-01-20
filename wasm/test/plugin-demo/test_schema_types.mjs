#!/usr/bin/env node
/**
 * Schema Types Test Suite
 *
 * Tests various data types and patterns with generated aligned code:
 * - Basic numeric types (int, float, double)
 * - 64-bit integers (bigint)
 * - Fixed-size arrays
 * - Nested structs
 * - Enums
 * - Complex real-world schemas
 */

import { fileURLToPath } from 'url';
import path from 'path';
import fs from 'fs';
import { execSync, spawnSync } from 'child_process';
import { generateAlignedCode } from '../../src/aligned-codegen.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCHEMAS_DIR = path.join(__dirname, 'schemas');
const BUILD_DIR = path.join(__dirname, 'build-types');

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
    const emsdkRoot = path.join(__dirname, '..', '..', '..', 'build', 'wasm', '_deps', 'emsdk-src');
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
  // Create module from JS code by wrapping it
  const wrappedCode = `
    const exports = {};
    ${jsCode}
    return { ${jsCode.match(/^(?:const|class)\s+(\w+)/gm)?.map(m => m.split(/\s+/)[1]).join(', ') || ''} };
  `;
  return new Function(wrappedCode)();
}

// =============================================================================
// Math Operations Tests
// =============================================================================

async function runMathOpsTests() {
  log('\n[Math Operations Schema]');

  const schema = fs.readFileSync(path.join(SCHEMAS_DIR, 'math_ops.fbs'), 'utf8');
  const result = generateAlignedCode(schema);

  await test('Vec2 layout is correct', async () => {
    assertEqual(result.layouts.Vec2Input.size, 16, 'Vec2Input should be 16 bytes');
    assertEqual(result.layouts.Vec2Output.size, 12, 'Vec2Output should be 12 bytes');
  });

  await test('Matrix2x2 with arrays', async () => {
    const layout = result.layouts.Matrix2x2Input;
    assertEqual(layout.size, 24, 'Matrix2x2Input should be 24 bytes (4*4 + 2*4)');
    assert(result.cpp.includes('float m[4]'), 'C++ should have m[4] array');
    assert(result.cpp.includes('float v[2]'), 'C++ should have v[2] array');
  });

  await test('IntArith with bool and uint8', async () => {
    const layout = result.layouts.IntArithOutput;
    // int32 (4) + bool (1) + uint8 (1) + padding (2) = 8? Let's check
    assert(layout.size >= 6, 'IntArithOutput should be at least 6 bytes');
    assert(result.ts.includes('get overflow(): boolean'), 'TS should have bool accessor');
  });

  await test('BigInt 64-bit operations', async () => {
    const layout = result.layouts.BigIntInput;
    assertEqual(layout.size, 16, 'BigIntInput should be 16 bytes (2 * int64)');
    assertEqual(layout.align, 8, 'BigIntInput should be 8-byte aligned');

    const outputLayout = result.layouts.BigIntOutput;
    assertEqual(outputLayout.size, 32, 'BigIntOutput should be 32 bytes (4 * int64)');

    assert(result.ts.includes('bigint'), 'TS should use bigint type');
    assert(result.ts.includes('getBigInt64'), 'TS should use getBigInt64');
  });

  await test('Vec2 JS view works correctly', async () => {
    const mod = evalJsModule(result.js);

    // Test Vec2Input
    const input = mod.Vec2InputView.allocate();
    input.a_x = 1.0;
    input.a_y = 2.0;
    input.b_x = 3.0;
    input.b_y = 4.0;

    assertClose(input.a_x, 1.0);
    assertClose(input.a_y, 2.0);
    assertClose(input.b_x, 3.0);
    assertClose(input.b_y, 4.0);

    // Test toObject
    const obj = input.toObject();
    assertClose(obj.a_x, 1.0);
    assertClose(obj.b_y, 4.0);
  });

  await test('Matrix array accessors work', async () => {
    const mod = evalJsModule(result.js);

    const input = mod.Matrix2x2InputView.allocate();

    // Set matrix values
    const m = input.m;
    m[0] = 1.0; m[1] = 2.0;
    m[2] = 3.0; m[3] = 4.0;

    // Set vector
    const v = input.v;
    v[0] = 5.0;
    v[1] = 6.0;

    // Read back
    assertClose(input.m[0], 1.0);
    assertClose(input.m[3], 4.0);
    assertClose(input.v[0], 5.0);
    assertClose(input.v[1], 6.0);
  });
}

// =============================================================================
// Signal Processing Tests
// =============================================================================

async function runSignalProcTests() {
  log('\n[Signal Processing Schema]');

  const schema = fs.readFileSync(path.join(SCHEMAS_DIR, 'signal_processing.fbs'), 'utf8');
  const result = generateAlignedCode(schema);

  await test('SampleBuffer with 64-element array', async () => {
    const layout = result.layouts.SampleBuffer;
    // 64 floats (256) + uint32 (4) + uint8 (1) + padding = 264 rounded up
    assertEqual(layout.size, 264, 'SampleBuffer should be 264 bytes');
    assert(result.cpp.includes('float samples[64]'), 'C++ should have samples[64]');
  });

  await test('FFT input/output structures', async () => {
    const inputLayout = result.layouts.FFTInput;
    assertEqual(inputLayout.size, 128, 'FFTInput should be 128 bytes (2 * 16 * 4)');

    const outputLayout = result.layouts.FFTOutput;
    // 16*4 + 16*4 + 1 + 4 + padding = 133 -> 136 (aligned to 4)
    assert(outputLayout.size >= 133, 'FFTOutput should be at least 133 bytes');
  });

  await test('Large array read/write performance', async () => {
    const mod = evalJsModule(result.js);

    const buffer = mod.SampleBufferView.allocate();
    const samples = buffer.samples;

    // Fill with test pattern
    const start = performance.now();
    for (let i = 0; i < 64; i++) {
      samples[i] = Math.sin(i * 0.1);
    }
    const writeTime = performance.now() - start;

    // Read back and verify
    const readStart = performance.now();
    let sum = 0;
    for (let i = 0; i < 64; i++) {
      sum += samples[i];
    }
    const readTime = performance.now() - readStart;

    assertClose(samples[0], 0.0, 0.0001);
    assertClose(samples[10], Math.sin(1.0), 0.0001);

    // Just verify it doesn't take too long
    assert(writeTime < 10, 'Write should be fast');
    assert(readTime < 10, 'Read should be fast');
  });

  await test('FilterCoeffs array operations', async () => {
    const mod = evalJsModule(result.js);

    const coeffs = mod.FilterCoeffsView.allocate();

    // Set filter coefficients (simple lowpass)
    coeffs.b[0] = 0.25;
    coeffs.b[1] = 0.5;
    coeffs.b[2] = 0.25;
    coeffs.b[3] = 0.0;
    coeffs.b[4] = 0.0;

    coeffs.a[0] = 1.0;
    coeffs.a[1] = 0.0;
    coeffs.a[2] = 0.0;
    coeffs.a[3] = 0.0;
    coeffs.a[4] = 0.0;

    coeffs.gain = 1.0;

    assertClose(coeffs.b[0], 0.25);
    assertClose(coeffs.b[1], 0.5);
    assertClose(coeffs.a[0], 1.0);
    assertClose(coeffs.gain, 1.0);
  });
}

// =============================================================================
// Game State Tests
// =============================================================================

async function runGameStateTests() {
  log('\n[Game State Schema]');

  const schema = fs.readFileSync(path.join(SCHEMAS_DIR, 'game_state.fbs'), 'utf8');
  const result = generateAlignedCode(schema);

  await test('Enum generation', async () => {
    assert(result.cpp.includes('enum class EntityState'), 'C++ should have EntityState enum');
    assert(result.cpp.includes('Idle = 0'), 'C++ should have Idle = 0');
    assert(result.cpp.includes('Dead = 4'), 'C++ should have Dead = 4');

    assert(result.ts.includes('export const EntityState'), 'TS should have EntityState');
    assert(result.ts.includes('Idle: 0'), 'TS should have Idle: 0');
  });

  await test('Position struct layout', async () => {
    const layout = result.layouts.Position;
    assertEqual(layout.size, 12, 'Position should be 12 bytes (3 floats)');
    assertEqual(layout.align, 4, 'Position should be 4-byte aligned');
  });

  await test('Nested Transform struct', async () => {
    const layout = result.layouts.Transform;
    // Position (12) + Velocity (12) + rotation (4) + scale (4) = 32
    assertEqual(layout.size, 32, 'Transform should be 32 bytes');

    // Check flattened field names in TS
    assert(result.ts.includes('pos_x'), 'TS should have flattened pos_x');
    assert(result.ts.includes('vel_dx'), 'TS should have flattened vel_dx');
  });

  await test('Deep nesting - EntityInput', async () => {
    const layout = result.layouts.EntityInput;
    // Transform (32) + Stats (16) + state (1) + direction (1) + entity_id (4) = 54 -> 56 aligned
    assert(layout.size >= 52, 'EntityInput should be at least 52 bytes');

    // Check deeply nested fields are flattened
    assert(result.ts.includes('transform_pos_x'), 'TS should have transform_pos_x');
    assert(result.ts.includes('transform_vel_dy'), 'TS should have transform_vel_dy');
    assert(result.ts.includes('stats_health'), 'TS should have stats_health');
  });

  await test('EntityInput JS operations', async () => {
    const mod = evalJsModule(result.js);

    const entity = mod.EntityInputView.allocate();

    // Set nested transform values
    entity.transform_pos_x = 100.0;
    entity.transform_pos_y = 200.0;
    entity.transform_pos_z = 0.0;
    entity.transform_vel_dx = 5.0;
    entity.transform_vel_dy = -3.0;
    entity.transform_vel_dz = 0.0;
    entity.transform_rotation = 1.57;
    entity.transform_scale = 1.0;

    // Set stats
    entity.stats_health = 100;
    entity.stats_max_health = 100;
    entity.stats_mana = 50;
    entity.stats_max_mana = 100;
    entity.stats_attack = 25;
    entity.stats_defense = 10;
    entity.stats_speed = 15;
    entity.stats_level = 5;

    // Set enums
    entity.state = 1;  // Moving
    entity.direction = 2;  // South
    entity.entity_id = 12345;

    // Verify
    assertClose(entity.transform_pos_x, 100.0);
    assertClose(entity.transform_vel_dx, 5.0);
    assertEqual(entity.stats_health, 100);
    assertEqual(entity.stats_level, 5);
    assertEqual(entity.state, 1);
    assertEqual(entity.direction, 2);
    assertEqual(entity.entity_id, 12345);
  });

  await test('Collision detection struct', async () => {
    const mod = evalJsModule(result.js);

    const collision = mod.CollisionInputView.allocate();

    // Entity A at origin
    collision.entity_a_pos_x = 0.0;
    collision.entity_a_pos_y = 0.0;
    collision.entity_a_pos_z = 0.0;
    collision.radius_a = 1.0;

    // Entity B at (1.5, 0, 0)
    collision.entity_b_pos_x = 1.5;
    collision.entity_b_pos_y = 0.0;
    collision.entity_b_pos_z = 0.0;
    collision.radius_b = 1.0;

    // Read back and verify
    assertClose(collision.entity_a_pos_x, 0.0);
    assertClose(collision.entity_b_pos_x, 1.5);
    assertClose(collision.radius_a, 1.0);
    assertClose(collision.radius_b, 1.0);

    // Test copyFrom with object
    collision.copyFrom({
      entity_a_pos_x: 5.0,
      radius_a: 2.0
    });
    assertClose(collision.entity_a_pos_x, 5.0);
    assertClose(collision.radius_a, 2.0);
    // Other values should be unchanged
    assertClose(collision.entity_b_pos_x, 1.5);
  });

  await test('CollisionOutput with bool', async () => {
    const mod = evalJsModule(result.js);

    const output = mod.CollisionOutputView.allocate();

    output.collides = true;
    output.penetration_depth = 0.5;
    output.normal_x = 1.0;
    output.normal_y = 0.0;
    output.normal_z = 0.0;

    assertEqual(output.collides, true);
    assertClose(output.penetration_depth, 0.5);
    assertClose(output.normal_x, 1.0);

    output.collides = false;
    assertEqual(output.collides, false);
  });
}

// =============================================================================
// WASM Integration Tests (if emcc available)
// =============================================================================

async function runWasmTests() {
  if (!checkEmcc()) {
    log('\n[WASM Integration Tests - SKIPPED]');
    log('  emcc not found');
    return;
  }

  log('\n[WASM Integration Tests]');

  // Setup build directory
  if (fs.existsSync(BUILD_DIR)) {
    fs.rmSync(BUILD_DIR, { recursive: true });
  }
  fs.mkdirSync(BUILD_DIR, { recursive: true });

  // Generate code for math_ops
  const mathSchema = fs.readFileSync(path.join(SCHEMAS_DIR, 'math_ops.fbs'), 'utf8');
  const mathResult = generateAlignedCode(mathSchema);
  fs.writeFileSync(path.join(BUILD_DIR, 'math_ops_aligned.h'), mathResult.cpp);

  // Create a vector dot product plugin
  const dotProductCpp = `
#include "math_ops_aligned.h"
#include <cmath>

using namespace MathOps::Aligned;

static Vec2Input g_input;
static Vec2Output g_output;

extern "C" {

__attribute__((export_name("get_input")))
Vec2Input* get_input() { return &g_input; }

__attribute__((export_name("get_output")))
Vec2Output* get_output() { return &g_output; }

__attribute__((export_name("get_input_size")))
size_t get_input_size() { return sizeof(Vec2Input); }

__attribute__((export_name("get_output_size")))
size_t get_output_size() { return sizeof(Vec2Output); }

// Compute: output = a + b, magnitude = |a + b|
__attribute__((export_name("vec_add")))
int vec_add() {
  g_output.x = g_input.a_x + g_input.b_x;
  g_output.y = g_input.a_y + g_input.b_y;
  g_output.magnitude = std::sqrt(g_output.x * g_output.x + g_output.y * g_output.y);
  return 0;
}

// Compute dot product, store in x
__attribute__((export_name("vec_dot")))
int vec_dot() {
  g_output.x = g_input.a_x * g_input.b_x + g_input.a_y * g_input.b_y;
  g_output.y = 0;
  g_output.magnitude = std::abs(g_output.x);
  return 0;
}

}
`;

  fs.writeFileSync(path.join(BUILD_DIR, 'vec_plugin.cpp'), dotProductCpp);

  await test('compiles vector plugin', async () => {
    const result = spawnSync('emcc', [
      path.join(BUILD_DIR, 'vec_plugin.cpp'),
      '-o', path.join(BUILD_DIR, 'vec_plugin.mjs'),
      '-I', BUILD_DIR,
      '-s', 'EXPORTED_FUNCTIONS=["_get_input","_get_output","_get_input_size","_get_output_size","_vec_add","_vec_dot"]',
      '-s', 'EXPORTED_RUNTIME_METHODS=["HEAPU8"]',
      '-s', 'MODULARIZE=1',
      '-s', 'EXPORT_ES6=1',
      '-O2'
    ], { stdio: 'pipe' });

    if (result.status !== 0) {
      throw new Error(`Compile failed: ${result.stderr?.toString()}`);
    }
  });

  await test('vector add operation', async () => {
    const createModule = (await import(path.join(BUILD_DIR, 'vec_plugin.mjs'))).default;
    const plugin = await createModule();

    const inputPtr = plugin._get_input();
    const outputPtr = plugin._get_output();

    assertEqual(plugin._get_input_size(), 16, 'Input size should be 16');
    assertEqual(plugin._get_output_size(), 12, 'Output size should be 12');

    // Create views
    const inputView = new DataView(plugin.HEAPU8.buffer, inputPtr, 16);
    const outputView = new DataView(plugin.HEAPU8.buffer, outputPtr, 12);

    // Set input: a=(3,4), b=(1,2)
    inputView.setFloat32(0, 3.0, true);   // a_x
    inputView.setFloat32(4, 4.0, true);   // a_y
    inputView.setFloat32(8, 1.0, true);   // b_x
    inputView.setFloat32(12, 2.0, true);  // b_y

    // Call vec_add
    plugin._vec_add();

    // Check output: (4, 6), magnitude = sqrt(52) ≈ 7.21
    assertClose(outputView.getFloat32(0, true), 4.0, 0.0001, 'x should be 4');
    assertClose(outputView.getFloat32(4, true), 6.0, 0.0001, 'y should be 6');
    assertClose(outputView.getFloat32(8, true), 7.211, 0.01, 'magnitude should be ~7.21');
  });

  await test('vector dot product operation', async () => {
    const createModule = (await import(path.join(BUILD_DIR, 'vec_plugin.mjs'))).default;
    const plugin = await createModule();

    const inputPtr = plugin._get_input();
    const outputPtr = plugin._get_output();

    const inputView = new DataView(plugin.HEAPU8.buffer, inputPtr, 16);
    const outputView = new DataView(plugin.HEAPU8.buffer, outputPtr, 12);

    // Set input: a=(3,4), b=(2,1)
    inputView.setFloat32(0, 3.0, true);   // a_x
    inputView.setFloat32(4, 4.0, true);   // a_y
    inputView.setFloat32(8, 2.0, true);   // b_x
    inputView.setFloat32(12, 1.0, true);  // b_y

    // Call vec_dot: 3*2 + 4*1 = 10
    plugin._vec_dot();

    assertClose(outputView.getFloat32(0, true), 10.0, 0.0001, 'dot product should be 10');
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
  log('Schema Types Test Suite');
  log('============================================================');
  log('');
  log('Testing various FlatBuffers schema patterns with aligned code');

  await runMathOpsTests();
  await runSignalProcTests();
  await runGameStateTests();
  await runWasmTests();

  log('\n============================================================');
  log(`Results: ${passed} passed, ${failed} failed`);
  log('============================================================');

  process.exit(failed > 0 ? 1 : 0);
}

main().catch(err => {
  console.error('Test failed:', err);
  process.exit(1);
});
