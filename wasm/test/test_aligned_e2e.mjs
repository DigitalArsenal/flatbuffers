#!/usr/bin/env node
/**
 * test_aligned_e2e.mjs - End-to-end test for aligned code generation
 *
 * This test:
 * 1. Uses existing .fbs schemas from the tests/ folder
 * 2. Generates C++ header and TypeScript view classes
 * 3. Compiles C++ to WASM using emcc
 * 4. Verifies data can be written in C++/WASM and read correctly in JS
 * 5. Verifies data can be written in JS and read correctly in C++/WASM
 */

import { fileURLToPath } from 'url';
import path from 'path';
import fs from 'fs';
import { execSync, spawnSync } from 'child_process';
import { generateAlignedCode } from '../src/aligned-codegen.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.join(__dirname, '..', '..');
const TEST_DIR = path.join(__dirname, 'e2e-aligned-temp');

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

function assertClose(actual, expected, epsilon, message) {
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

function getEmsdkEnv() {
  // Check for emsdk in the build directory
  const emsdkRoot = path.join(REPO_ROOT, 'build', 'wasm', '_deps', 'emsdk-src');
  const emsdkEnvScript = path.join(emsdkRoot, 'emsdk_env.sh');

  if (fs.existsSync(emsdkEnvScript)) {
    try {
      // Source the emsdk environment and extract PATH
      const result = execSync(`source "${emsdkEnvScript}" 2>/dev/null && echo "$PATH"`, {
        shell: '/bin/bash',
        stdio: 'pipe',
        encoding: 'utf8'
      });
      return { PATH: result.trim(), EMSDK: emsdkRoot };
    } catch {
      // Fall through to system check
    }
  }

  return null;
}

function checkEmcc() {
  // First check if emcc is in PATH
  try {
    execSync('emcc --version', { stdio: 'pipe' });
    return { env: process.env };
  } catch {
    // Try to find emsdk in build directory
    const emsdkEnv = getEmsdkEnv();
    if (emsdkEnv) {
      try {
        execSync('emcc --version', {
          stdio: 'pipe',
          env: { ...process.env, ...emsdkEnv }
        });
        return { env: { ...process.env, ...emsdkEnv } };
      } catch {
        return null;
      }
    }
    return null;
  }
}

function cleanup() {
  if (fs.existsSync(TEST_DIR)) {
    fs.rmSync(TEST_DIR, { recursive: true });
  }
}

// =============================================================================
// Test Schemas (from tests/ folder)
// =============================================================================

const ALIGNMENT_SCHEMA = fs.readFileSync(
  path.join(REPO_ROOT, 'tests', 'alignment_test.fbs'),
  'utf8'
);

const ARRAYS_SCHEMA = fs.readFileSync(
  path.join(REPO_ROOT, 'tests', 'arrays_test.fbs'),
  'utf8'
);

// =============================================================================
// E2E Tests
// =============================================================================

async function runE2ETests() {
  const emccResult = checkEmcc();

  if (!emccResult) {
    log('\n[E2E Tests - SKIPPED]');
    log('  emcc (Emscripten) not found in PATH or build/wasm/_deps/emsdk-src');
    log('  Install Emscripten to run E2E tests: https://emscripten.org/docs/getting_started/');
    return;
  }

  const emccEnv = emccResult.env;
  log('\n[E2E Tests]');

  // Setup test directory
  cleanup();
  fs.mkdirSync(TEST_DIR, { recursive: true });

  await test('generates code from alignment_test.fbs', async () => {
    const result = generateAlignedCode(ALIGNMENT_SCHEMA);

    assert(result.cpp.length > 0, 'should generate C++ code');
    assert(result.ts.length > 0, 'should generate TypeScript code');

    // Verify structs were found
    assert(result.layouts.BadAlignmentSmall, 'should have BadAlignmentSmall');
    assert(result.layouts.BadAlignmentLarge, 'should have BadAlignmentLarge');
    assert(result.layouts.EvenSmallStruct, 'should have EvenSmallStruct');
    assert(result.layouts.OddSmallStruct, 'should have OddSmallStruct');

    // Verify sizes match comments in schema
    assertEqual(result.layouts.BadAlignmentSmall.size, 12, 'BadAlignmentSmall size');
    assertEqual(result.layouts.BadAlignmentSmall.align, 4, 'BadAlignmentSmall align');
    assertEqual(result.layouts.BadAlignmentLarge.size, 8, 'BadAlignmentLarge size');
    assertEqual(result.layouts.BadAlignmentLarge.align, 8, 'BadAlignmentLarge align');
    assertEqual(result.layouts.EvenSmallStruct.size, 2, 'EvenSmallStruct size');
    assertEqual(result.layouts.OddSmallStruct.size, 3, 'OddSmallStruct size');
  });

  await test('generates code from arrays_test.fbs', async () => {
    const result = generateAlignedCode(ARRAYS_SCHEMA);

    assert(result.cpp.length > 0, 'should generate C++ code');
    assert(result.ts.length > 0, 'should generate TypeScript code');
    assert(result.layouts.NestedStruct, 'should have NestedStruct');
    assert(result.layouts.ArrayStruct, 'should have ArrayStruct');
  });

  await test('compiles C++ to WASM and verifies round-trip', async () => {
    // Generate code for a simple schema
    const simpleSchema = `
      namespace Test;

      struct Vec3 {
        x: float;
        y: float;
        z: float;
      }

      struct TestData {
        id: uint32;
        pos: Vec3;
        value: double;
        flags: ubyte;
      }
    `;

    const result = generateAlignedCode(simpleSchema);

    // Write generated header
    const headerPath = path.join(TEST_DIR, 'aligned.h');
    fs.writeFileSync(headerPath, result.cpp);

    // Write C++ test code that populates structs
    const cppCode = `
#include "aligned.h"
#include <emscripten.h>
#include <cstring>

using namespace Test::Aligned;

// Exported buffer for JS to read
static TestData g_testData;
static Vec3 g_vec3Array[4];

extern "C" {

EMSCRIPTEN_KEEPALIVE
TestData* get_test_data() {
  return &g_testData;
}

EMSCRIPTEN_KEEPALIVE
size_t get_test_data_size() {
  return sizeof(TestData);
}

EMSCRIPTEN_KEEPALIVE
Vec3* get_vec3_array() {
  return g_vec3Array;
}

EMSCRIPTEN_KEEPALIVE
size_t get_vec3_size() {
  return sizeof(Vec3);
}

// C++ writes data for JS to read
EMSCRIPTEN_KEEPALIVE
void populate_test_data() {
  g_testData.id = 12345;
  g_testData.pos_x = 1.5f;
  g_testData.pos_y = 2.5f;
  g_testData.pos_z = 3.5f;
  g_testData.value = 3.14159265358979;
  g_testData.flags = 0xAB;
}

// C++ reads data written by JS and returns checksum
EMSCRIPTEN_KEEPALIVE
uint32_t verify_test_data(uint32_t expected_id, float expected_x, float expected_y, float expected_z) {
  uint32_t errors = 0;
  if (g_testData.id != expected_id) errors |= 1;
  if (g_testData.pos_x != expected_x) errors |= 2;
  if (g_testData.pos_y != expected_y) errors |= 4;
  if (g_testData.pos_z != expected_z) errors |= 8;
  return errors;
}

// Populate array for JS to read
EMSCRIPTEN_KEEPALIVE
void populate_vec3_array() {
  for (int i = 0; i < 4; i++) {
    g_vec3Array[i].x = (float)(i * 10);
    g_vec3Array[i].y = (float)(i * 10 + 1);
    g_vec3Array[i].z = (float)(i * 10 + 2);
  }
}

// Verify array written by JS
EMSCRIPTEN_KEEPALIVE
uint32_t verify_vec3_array() {
  uint32_t errors = 0;
  for (int i = 0; i < 4; i++) {
    if (g_vec3Array[i].x != (float)(i * 100)) errors |= (1 << (i * 3));
    if (g_vec3Array[i].y != (float)(i * 100 + 10)) errors |= (1 << (i * 3 + 1));
    if (g_vec3Array[i].z != (float)(i * 100 + 20)) errors |= (1 << (i * 3 + 2));
  }
  return errors;
}

}
`;

    const cppPath = path.join(TEST_DIR, 'test.cpp');
    fs.writeFileSync(cppPath, cppCode);

    // Compile to WASM
    const wasmPath = path.join(TEST_DIR, 'test.mjs');
    const compileResult = spawnSync('emcc', [
      cppPath,
      '-o', wasmPath,
      '-s', 'EXPORTED_FUNCTIONS=["_get_test_data","_get_test_data_size","_get_vec3_array","_get_vec3_size","_populate_test_data","_verify_test_data","_populate_vec3_array","_verify_vec3_array","_malloc","_free"]',
      '-s', 'EXPORTED_RUNTIME_METHODS=["ccall","cwrap","HEAPU8","HEAPF32","HEAPF64","HEAP32","HEAPU32"]',
      '-s', 'MODULARIZE=1',
      '-s', 'EXPORT_ES6=1',
      '-O2',
    ], { cwd: TEST_DIR, stdio: 'pipe', env: emccEnv });

    if (compileResult.status !== 0) {
      throw new Error(`emcc failed: ${compileResult.stderr?.toString() || 'unknown error'}`);
    }

    // Use the plain JavaScript output (no TypeScript types to strip)
    const jsViewCode = result.js;

    // Create test runner
    const testRunner = `
import createModule from './test.mjs';

${jsViewCode}

async function runTest() {
  const Module = await createModule();

  // Test 1: C++ writes, JS reads
  Module._populate_test_data();

  const dataPtr = Module._get_test_data();
  const dataSize = Module._get_test_data_size();

  // Verify size matches
  if (dataSize !== TESTDATA_SIZE) {
    throw new Error(\`Size mismatch: C++=$\{dataSize}, JS=$\{TESTDATA_SIZE}\`);
  }

  // Read using our generated view
  const view = TestDataView.fromMemory({ buffer: Module.HEAPU8.buffer }, dataPtr);

  if (view.id !== 12345) throw new Error(\`id mismatch: \${view.id}\`);
  if (Math.abs(view.pos_x - 1.5) > 0.0001) throw new Error(\`pos_x mismatch: \${view.pos_x}\`);
  if (Math.abs(view.pos_y - 2.5) > 0.0001) throw new Error(\`pos_y mismatch: \${view.pos_y}\`);
  if (Math.abs(view.pos_z - 3.5) > 0.0001) throw new Error(\`pos_z mismatch: \${view.pos_z}\`);
  if (Math.abs(view.value - 3.14159265358979) > 0.0000001) throw new Error(\`value mismatch: \${view.value}\`);
  if (view.flags !== 0xAB) throw new Error(\`flags mismatch: \${view.flags}\`);

  console.log('  [C++ -> JS] Data read correctly');

  // Test 2: JS writes, C++ reads
  view.id = 99999;
  view.pos_x = 100.5;
  view.pos_y = 200.5;
  view.pos_z = 300.5;

  const errors = Module._verify_test_data(99999, 100.5, 200.5, 300.5);
  if (errors !== 0) {
    throw new Error(\`C++ verification failed with error code: \${errors}\`);
  }

  console.log('  [JS -> C++] Data verified correctly');

  // Test 3: Array round-trip (C++ writes, JS reads)
  Module._populate_vec3_array();

  const arrayPtr = Module._get_vec3_array();
  const vec3Size = Module._get_vec3_size();

  if (vec3Size !== VEC3_SIZE) {
    throw new Error(\`Vec3 size mismatch: C++=$\{vec3Size}, JS=$\{VEC3_SIZE}\`);
  }

  const arrayView = Vec3ArrayView.fromMemory({ buffer: Module.HEAPU8.buffer }, arrayPtr, 4);

  for (let i = 0; i < 4; i++) {
    const v = arrayView.at(i);
    if (Math.abs(v.x - (i * 10)) > 0.0001) throw new Error(\`array[\${i}].x mismatch\`);
    if (Math.abs(v.y - (i * 10 + 1)) > 0.0001) throw new Error(\`array[\${i}].y mismatch\`);
    if (Math.abs(v.z - (i * 10 + 2)) > 0.0001) throw new Error(\`array[\${i}].z mismatch\`);
  }

  console.log('  [C++ -> JS] Array read correctly');

  // Test 4: JS writes array, C++ reads
  for (let i = 0; i < 4; i++) {
    const v = arrayView.at(i);
    v.x = i * 100;
    v.y = i * 100 + 10;
    v.z = i * 100 + 20;
  }

  const arrayErrors = Module._verify_vec3_array();
  if (arrayErrors !== 0) {
    throw new Error(\`C++ array verification failed with error code: \${arrayErrors}\`);
  }

  console.log('  [JS -> C++] Array verified correctly');

  console.log('  All round-trip tests passed!');
}

runTest().catch(err => {
  console.error('Test failed:', err.message);
  process.exit(1);
});
`;

    const runnerPath = path.join(TEST_DIR, 'run_test.mjs');
    fs.writeFileSync(runnerPath, testRunner);

    // Run the test
    const testResult = spawnSync('node', [runnerPath], {
      cwd: TEST_DIR,
      stdio: 'pipe',
      env: { ...process.env }
    });

    if (testResult.status !== 0) {
      const stderr = testResult.stderr?.toString() || '';
      const stdout = testResult.stdout?.toString() || '';
      throw new Error(`Round-trip test failed:\n${stderr}\n${stdout}`);
    }

    log(testResult.stdout?.toString().trim().split('\n').map(l => '    ' + l).join('\n'));
  });

  // Cleanup
  cleanup();
}

// =============================================================================
// Main
// =============================================================================

async function main() {
  log('============================================================');
  log('Aligned Code Generation E2E Test Suite');
  log('============================================================');

  await runE2ETests();

  log('\n============================================================');
  log(`Results: ${passed} passed, ${failed} failed`);
  log('============================================================');

  process.exit(failed > 0 ? 1 : 0);
}

main().catch(err => {
  console.error('Test suite failed:', err);
  process.exit(1);
});
