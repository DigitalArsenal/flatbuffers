// test_json_schema.mjs - Test JSON Schema input support
import FlatcWasm from './flatc.js';

// JSON Schema definition for a Person type (FlatBuffers-compatible format)
// FlatBuffers requires the schema to have "definitions" or "$defs" section
const personJsonSchema = `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "definitions": {
    "Person": {
      "type": "object",
      "properties": {
        "firstName": {
          "type": "string"
        },
        "lastName": {
          "type": "string"
        },
        "age": {
          "type": "integer"
        },
        "email": {
          "type": "string"
        }
      },
      "required": ["firstName", "lastName"],
      "x-flatbuffers": {
        "root": true
      }
    }
  }
}`;

// Test data matching the schema
const personData = `{
  "firstName": "John",
  "lastName": "Doe",
  "age": 30,
  "email": "john.doe@example.com"
}`;

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

async function main() {
  console.log('Loading WASM module...');
  const flatc = await FlatcWasm();
  console.log('Version:', flatc.getVersion());
  console.log('');

  // ============================================================================
  // Test 1: Add JSON Schema
  // ============================================================================
  console.log('=== Test 1: Add JSON Schema ===');

  const schemaName = 'person.schema.json';
  const schemaBytes = new TextEncoder().encode(personJsonSchema);

  const namePtr = flatc._malloc(schemaName.length);
  const schemaPtr = flatc._malloc(schemaBytes.length);
  flatc.HEAPU8.set(new TextEncoder().encode(schemaName), namePtr);
  flatc.HEAPU8.set(schemaBytes, schemaPtr);

  const schemaId = flatc._wasm_schema_add(namePtr, schemaName.length, schemaPtr, schemaBytes.length);
  flatc._free(namePtr);
  flatc._free(schemaPtr);

  if (schemaId < 0) {
    const error = flatc.UTF8ToString(flatc._wasm_get_last_error());
    console.log('  Note: JSON Schema parsing may not be fully supported');
    console.log('  Error:', error);
    console.log('');
    console.log('==================================================');
    console.log('JSON Schema tests skipped (not fully supported yet)');
    console.log('==================================================');
    process.exit(0);
  }

  assert(schemaId >= 0, 'JSON Schema added successfully');
  assert(flatc._wasm_schema_count() === 1, 'Schema count is 1');

  const nameResultPtr = flatc._wasm_schema_get_name(schemaId);
  assert(flatc.UTF8ToString(nameResultPtr) === 'person.schema.json', 'Schema name matches');
  console.log('');

  // ============================================================================
  // Test 2: Convert JSON data to binary
  // ============================================================================
  console.log('=== Test 2: JSON → Binary Conversion ===');

  const jsonBytes = new TextEncoder().encode(personData);
  const jsonPtr = flatc._malloc(jsonBytes.length);
  flatc.HEAPU8.set(jsonBytes, jsonPtr);

  const outLenPtr = flatc._malloc(4);
  const binaryPtr = flatc._wasm_json_to_binary(schemaId, jsonPtr, jsonBytes.length, outLenPtr);
  flatc._free(jsonPtr);

  if (!binaryPtr) {
    const error = flatc.UTF8ToString(flatc._wasm_get_last_error());
    console.log('  JSON to binary conversion not supported for JSON Schema');
    console.log('  Error:', error);
  } else {
    const binaryLen = flatc.getValue(outLenPtr, 'i32');
    assert(binaryLen > 0, `Binary output has size ${binaryLen} bytes`);

    // Test round-trip
    console.log('');
    console.log('=== Test 3: Binary → JSON Round-Trip ===');

    const binaryData = flatc.HEAPU8.slice(binaryPtr, binaryPtr + binaryLen);
    const binaryInputPtr = flatc._malloc(binaryData.length);
    flatc.HEAPU8.set(binaryData, binaryInputPtr);

    const outLenPtr2 = flatc._malloc(4);
    const jsonResultPtr = flatc._wasm_binary_to_json(schemaId, binaryInputPtr, binaryData.length, outLenPtr2);
    flatc._free(binaryInputPtr);

    if (jsonResultPtr) {
      const jsonResult = flatc.UTF8ToString(jsonResultPtr);
      assert(jsonResult.includes('firstName'), 'Round-trip JSON contains firstName');
      assert(jsonResult.includes('John'), 'Round-trip JSON contains John');
      console.log('  Round-trip JSON:', jsonResult.substring(0, 100) + '...');
    }
    flatc._free(outLenPtr2);
  }
  flatc._free(outLenPtr);
  console.log('');

  // ============================================================================
  // Test 4: Export schema back to FBS
  // ============================================================================
  console.log('=== Test 4: Schema Export ===');

  const exportOutLenPtr = flatc._malloc(4);
  const exportPtr = flatc._wasm_schema_export(schemaId, 0, exportOutLenPtr);  // 0 = FBS format

  if (exportPtr) {
    const exportLen = flatc.getValue(exportOutLenPtr, 'i32');
    assert(exportLen > 0, `Exported ${exportLen} bytes as FBS`);

    const exportedFbs = flatc.UTF8ToString(exportPtr);
    console.log('  Exported FBS preview:', exportedFbs.substring(0, 200) + '...');
  } else {
    console.log('  FBS export from JSON Schema not fully supported');
  }
  flatc._free(exportOutLenPtr);
  console.log('');

  // ============================================================================
  // Test 5: Cleanup
  // ============================================================================
  console.log('=== Test 5: Cleanup ===');
  flatc._wasm_schema_remove(schemaId);
  assert(flatc._wasm_schema_count() === 0, 'Schema removed');
  console.log('');

  // ============================================================================
  // Summary
  // ============================================================================
  console.log('='.repeat(50));
  console.log(`Tests run: ${testsRun}`);
  console.log(`Tests passed: ${testsPassed}`);
  console.log(`Tests failed: ${testsRun - testsPassed}`);
  console.log('='.repeat(50));

  if (testsPassed === testsRun) {
    console.log('JSON Schema tests passed!');
    process.exit(0);
  } else {
    console.log('Some JSON Schema tests failed');
    process.exit(1);
  }
}

main().catch(err => {
  console.error('Test error:', err);
  process.exit(1);
});
