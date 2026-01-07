#!/usr/bin/env node
/**
 * test_all.mjs - Test suite for flatc-wasm npm package
 *
 * Tests the npm package to ensure it works correctly after build.
 * Uses canonical test schemas from the FlatBuffers repository.
 */

import { readFile } from 'fs/promises';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const TESTS_DIR = path.join(__dirname, '..', '..', 'tests');

// Import from the dist directory (built package)
const distPath = path.join(__dirname, '..', 'dist', 'flatc-wasm.js');

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

// Standalone Monster schema (based on tests/monster_test.fbs without includes)
const MONSTER_SCHEMA = `
namespace MyGame.Example;

enum Color:ubyte (bit_flags) { Red = 0, Green, Blue = 3 }
enum Race:byte { None = -1, Human = 0, Dwarf, Elf }

struct Test { a:short; b:byte; }

struct Vec3 (force_align: 8) {
  x:float;
  y:float;
  z:float;
}

struct Ability {
  id:uint(key);
  distance:uint;
}

table Stat {
  id:string;
  val:long;
  count:ushort;
}

table Monster {
  pos:Vec3;
  mana:short = 150;
  hp:short = 100;
  name:string (key);
  inventory:[ubyte];
  color:Color = Blue;
  testarrayofstring:[string];
  testarrayoftables:[Monster];
  testempty:Stat;
  testbool:bool;
  testf:float = 3.14159;
  vector_of_doubles:[double];
  signed_enum:Race = None;
}

root_type Monster;
file_identifier "MONS";
file_extension "mon";
`;

// Test data mimicking monsterdata_test.json
const MONSTER_JSON = `{
  "name": "MyMonster",
  "hp": 80,
  "mana": 150,
  "color": "Blue",
  "inventory": [0, 1, 2, 3, 4],
  "testarrayofstring": ["test1", "test2"]
}`;

async function main() {
  log('============================================================');
  log('flatc-wasm NPM Package Test Suite');
  log('Using Canonical Test Patterns');
  log('============================================================');

  // Load the module
  log('\nLoading WASM module...');
  let FlatcWasm;
  try {
    const module = await import(distPath);
    FlatcWasm = module.default;
  } catch (err) {
    log(`ERROR: Failed to import flatc-wasm: ${err.message}`);
    log(`Expected path: ${distPath}`);
    log('\nMake sure you have built the npm package:');
    log('  cmake --build build/wasm --target flatc_wasm_npm');
    process.exit(1);
  }

  const flatc = await FlatcWasm();
  log(`Version: ${flatc.getVersion()}`);

  // Helper functions
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  function writeString(str) {
    const bytes = encoder.encode(str);
    const ptr = flatc._malloc(bytes.length);
    flatc.HEAPU8.set(bytes, ptr);
    return [ptr, bytes.length];
  }

  function writeBytes(data) {
    const ptr = flatc._malloc(data.length);
    flatc.HEAPU8.set(data, ptr);
    return ptr;
  }

  function getLastError() {
    const ptr = flatc._wasm_get_last_error();
    return ptr ? flatc.UTF8ToString(ptr) : 'Unknown error';
  }

  /**
   * Parse FlatBuffers JSON which may contain non-standard values like nan, inf.
   */
  function parseFlatBuffersJson(json) {
    const sanitized = json
      .replace(/:\s*nan\b/g, ': null')
      .replace(/:\s*-inf\b/g, ': null')
      .replace(/:\s*\+?inf\b/g, ': null')
      .replace(/:\s*-infinity\b/g, ': null')
      .replace(/:\s*\+?infinity\b/g, ': null');
    return JSON.parse(sanitized);
  }

  // ==========================================================================
  // Tests
  // ==========================================================================

  log('\n[Module Loading]');
  await test('Module loaded successfully', async () => {
    assert(flatc, 'Module should be loaded');
    assert(typeof flatc.getVersion === 'function', 'Should have getVersion');
  });

  await test('Version is valid', async () => {
    const version = flatc.getVersion();
    assert(typeof version === 'string', 'Version should be string');
    assert(version.length > 0, 'Version should not be empty');
    assert(/^\d+\.\d+\.\d+/.test(version), 'Version should be semantic');
  });

  log('\n[Schema Management]');
  let monsterSchemaId;

  await test('Add monster schema', async () => {
    const [namePtr, nameLen] = writeString('monster.fbs');
    const [srcPtr, srcLen] = writeString(MONSTER_SCHEMA);
    monsterSchemaId = flatc._wasm_schema_add(namePtr, nameLen, srcPtr, srcLen);
    flatc._free(namePtr);
    flatc._free(srcPtr);
    assert(monsterSchemaId >= 0, `Schema should be added, got id ${monsterSchemaId}`);
  });

  await test('Schema count is correct', async () => {
    const count = flatc._wasm_schema_count();
    assert(count >= 1, `Should have at least 1 schema, got ${count}`);
  });

  await test('Get schema name', async () => {
    const namePtr = flatc._wasm_schema_get_name(monsterSchemaId);
    assert(namePtr !== 0, 'Should return name pointer');
    const name = flatc.UTF8ToString(namePtr);
    assert(name === 'monster.fbs', `Name should be monster.fbs, got ${name}`);
  });

  log('\n[JSON to Binary Conversion]');
  let binaryData;

  await test('Convert JSON to binary', async () => {
    const [jsonPtr, jsonLen] = writeString(MONSTER_JSON);
    const outLenPtr = flatc._malloc(4);

    const resultPtr = flatc._wasm_json_to_binary(monsterSchemaId, jsonPtr, jsonLen, outLenPtr);
    flatc._free(jsonPtr);

    if (resultPtr === 0) {
      throw new Error(`Conversion failed: ${getLastError()}`);
    }

    const len = flatc.getValue(outLenPtr, 'i32');
    flatc._free(outLenPtr);

    assert(len > 0, `Should have output length, got ${len}`);
    binaryData = flatc.HEAPU8.slice(resultPtr, resultPtr + len);
    assert(binaryData.length === len, 'Binary data length should match');
  });

  await test('File identifier is correct', async () => {
    const fileId = String.fromCharCode(binaryData[4], binaryData[5], binaryData[6], binaryData[7]);
    assert(fileId === 'MONS', `File ID should be MONS, got ${fileId}`);
  });

  log('\n[Binary to JSON Conversion]');
  await test('Convert binary to JSON', async () => {
    const binPtr = writeBytes(binaryData);
    const outLenPtr = flatc._malloc(4);

    const resultPtr = flatc._wasm_binary_to_json(monsterSchemaId, binPtr, binaryData.length, outLenPtr);
    flatc._free(binPtr);

    if (resultPtr === 0) {
      throw new Error(`Conversion failed: ${getLastError()}`);
    }

    const len = flatc.getValue(outLenPtr, 'i32');
    flatc._free(outLenPtr);

    const jsonBytes = flatc.HEAPU8.slice(resultPtr, resultPtr + len);
    const json = decoder.decode(jsonBytes);
    const parsed = parseFlatBuffersJson(json);

    assert(parsed.name === 'MyMonster', 'Name should match');
    assert(parsed.hp === 80, 'HP should match');
    assert(Array.isArray(parsed.inventory), 'Should have inventory array');
    assert(parsed.inventory.length === 5, 'Inventory should have 5 items');
  });

  log('\n[Format Detection]');
  await test('Detect JSON format', async () => {
    const jsonBytes = encoder.encode(MONSTER_JSON);
    const ptr = writeBytes(jsonBytes);
    const format = flatc._wasm_detect_format(ptr, jsonBytes.length);
    flatc._free(ptr);
    assert(format === 0, `Should detect JSON (0), got ${format}`);
  });

  await test('Detect binary format', async () => {
    const ptr = writeBytes(binaryData);
    const format = flatc._wasm_detect_format(ptr, binaryData.length);
    flatc._free(ptr);
    assert(format === 1, `Should detect binary (1), got ${format}`);
  });

  log('\n[Code Generation]');

  const languageTests = [
    { id: 0, name: 'C++', marker: 'struct Monster' },
    { id: 6, name: 'Python', marker: 'class Monster' },
    { id: 7, name: 'Rust', marker: 'pub struct Monster' },
    { id: 9, name: 'TypeScript', marker: 'export class Monster' },
    { id: 11, name: 'JSON Schema', marker: '"$schema"' },
  ];

  for (const lang of languageTests) {
    await test(`Generate ${lang.name}`, async () => {
      const outLenPtr = flatc._malloc(4);
      const resultPtr = flatc._wasm_generate_code(monsterSchemaId, lang.id, outLenPtr);

      if (resultPtr === 0) {
        throw new Error(`Code generation failed: ${getLastError()}`);
      }

      const len = flatc.getValue(outLenPtr, 'i32');
      flatc._free(outLenPtr);

      const codeBytes = flatc.HEAPU8.slice(resultPtr, resultPtr + len);
      const code = decoder.decode(codeBytes);

      assert(code.includes(lang.marker), `Should contain ${lang.marker}`);
      assert(code.length > 50, 'Code should be substantial');
    });
  }

  log('\n[Streaming API]');
  await test('Stream accumulation', async () => {
    flatc._wasm_stream_reset();
    assert(flatc._wasm_stream_size() === 0, 'Stream should be empty after reset');

    const chunks = [
      MONSTER_JSON.substring(0, 50),
      MONSTER_JSON.substring(50, 100),
      MONSTER_JSON.substring(100)
    ];

    let totalSize = 0;
    for (const chunk of chunks) {
      const bytes = encoder.encode(chunk);
      const ptr = flatc._wasm_stream_prepare(bytes.length);
      flatc.HEAPU8.set(bytes, ptr);
      flatc._wasm_stream_commit(bytes.length);
      totalSize += bytes.length;
    }

    assert(flatc._wasm_stream_size() === totalSize, 'Stream should have accumulated data');
  });

  log('\n[Optional Scalars Schema]');
  await test('Load optional_scalars schema', async () => {
    const optionalSchema = await readFile(path.join(TESTS_DIR, 'optional_scalars.fbs'), 'utf-8');
    const [namePtr, nameLen] = writeString('optional_scalars.fbs');
    const [srcPtr, srcLen] = writeString(optionalSchema);
    const schemaId = flatc._wasm_schema_add(namePtr, nameLen, srcPtr, srcLen);
    flatc._free(namePtr);
    flatc._free(srcPtr);
    assert(schemaId >= 0, 'Optional scalars schema should load');

    // Round-trip test
    const testData = JSON.stringify({
      just_i8: 42,
      just_bool: true,
      just_enum: 'One'
    });

    const [jsonPtr, jsonLen] = writeString(testData);
    const outLenPtr = flatc._malloc(4);
    const resultPtr = flatc._wasm_json_to_binary(schemaId, jsonPtr, jsonLen, outLenPtr);
    flatc._free(jsonPtr);

    assert(resultPtr !== 0, 'Should convert to binary');

    const binLen = flatc.getValue(outLenPtr, 'i32');
    const binary = flatc.HEAPU8.slice(resultPtr, resultPtr + binLen);

    // Check file identifier
    const fileId = String.fromCharCode(binary[4], binary[5], binary[6], binary[7]);
    assert(fileId === 'NULL', 'File ID should be NULL');

    flatc._free(outLenPtr);
  });

  log('\n[Embind API]');
  await test('Embind getVersion', async () => {
    const version = flatc.getVersion();
    assert(typeof version === 'string', 'Should return string');
    assert(version.length > 0, 'Version should not be empty');
  });

  await test('Embind createSchema', async () => {
    const handle = flatc.createSchema('test.fbs', MONSTER_SCHEMA);
    assert(handle, 'Should return handle object');

    // Try to access methods - they may be on the prototype
    const proto = Object.getPrototypeOf(handle);
    const hasIsValid = proto && typeof proto.isValid === 'function';

    if (hasIsValid) {
      assert(handle.isValid(), 'Handle should be valid');
      handle.release();
    } else {
      log('    (Embind methods use C API internally)');
    }
  });

  log('\n[Cleanup]');
  await test('Remove schemas', async () => {
    flatc._wasm_schema_remove(monsterSchemaId);
    // Just verify it doesn't crash
  });

  // ==========================================================================
  // Summary
  // ==========================================================================

  log('\n============================================================');
  log(`Results: ${passed} passed, ${failed} failed`);
  log('============================================================');

  if (passed > 0 && failed === 0) {
    log('🎉 All tests passed!');
  } else if (failed > 0) {
    log('❌ Some tests failed');
  }

  process.exit(failed > 0 ? 1 : 0);
}

main().catch(err => {
  console.error('Test error:', err);
  process.exit(1);
});
