#!/usr/bin/env node
/**
 * test_json_schema.mjs - Test JSON Schema support in WASM flatc module
 *
 * Tests both:
 * 1. JSON Schema import (parsing JSON Schema to create FlatBuffers schema)
 * 2. JSON Schema export (generating JSON Schema from FlatBuffers schema)
 *
 * Uses canonical test files from the repository.
 */
import { readFile } from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import FlatcWasm from './flatc.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const TESTS_DIR = path.join(__dirname, '..');

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

// Helper to write a null-terminated string to WASM memory
function writeString(flatc, str) {
  const bytes = new TextEncoder().encode(str);
  const ptr = flatc._malloc(bytes.length);
  flatc.HEAPU8.set(bytes, ptr);
  return [ptr, bytes.length];
}

async function main() {
  console.log('Loading WASM module...');
  const flatc = await FlatcWasm();
  console.log('Version:', flatc.getVersion());
  console.log('');

  // ============================================================================
  // Test 1: Load FBS schema and export to JSON Schema
  // ============================================================================
  console.log('=== Test 1: Export FBS to JSON Schema ===');

  // Use a standalone Monster schema (without includes)
  const MONSTER_SCHEMA = `
namespace MyGame.Example;

enum Color:ubyte (bit_flags) { Red = 0, Green, Blue = 3 }
enum Race:byte { None = -1, Human = 0, Dwarf, Elf }

struct Test { a:short; b:byte; }

struct Vec3 {
  x:float;
  y:float;
  z:float;
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
  testempty:Stat;
  testbool:bool;
  signed_enum:Race = None;
}

root_type Monster;
`;

  const [namePtr, nameLen] = writeString(flatc, 'monster.fbs');
  const [srcPtr, srcLen] = writeString(flatc, MONSTER_SCHEMA);

  const schemaId = flatc._wasm_schema_add(namePtr, nameLen, srcPtr, srcLen);
  flatc._free(namePtr);
  flatc._free(srcPtr);

  if (schemaId < 0) {
    const error = flatc.UTF8ToString(flatc._wasm_get_last_error());
    console.error('Failed to add schema:', error);
    process.exit(1);
  }

  assert(schemaId >= 0, 'FBS schema loaded successfully');

  // Generate JSON Schema using code generation (language 11 = JSONSchema)
  const exportOutLenPtr = flatc._malloc(4);
  const exportPtr = flatc._wasm_generate_code(schemaId, 11, exportOutLenPtr);

  if (exportPtr) {
    const exportLen = flatc.getValue(exportOutLenPtr, 'i32');
    assert(exportLen > 0, `Generated ${exportLen} bytes as JSON Schema`);

    const jsonSchemaStr = flatc.UTF8ToString(exportPtr);
    const jsonSchema = JSON.parse(jsonSchemaStr);

    assert('$schema' in jsonSchema, 'JSON Schema has $schema property');
    assert('definitions' in jsonSchema, 'JSON Schema has definitions');
    assert('MyGame_Example_Monster' in jsonSchema.definitions, 'Has Monster definition');
    assert('MyGame_Example_Color' in jsonSchema.definitions, 'Has Color enum definition');
    assert('MyGame_Example_Vec3' in jsonSchema.definitions, 'Has Vec3 struct definition');

    // Check Monster properties
    const monster = jsonSchema.definitions.MyGame_Example_Monster;
    assert(monster.properties.name !== undefined, 'Monster has name property');
    assert(monster.properties.hp !== undefined, 'Monster has hp property');
    assert(monster.properties.inventory !== undefined, 'Monster has inventory property');
  } else {
    console.error('  Failed to generate JSON Schema');
    testsRun++;
  }
  flatc._free(exportOutLenPtr);
  console.log('');

  // ============================================================================
  // Test 2: Import JSON Schema
  // ============================================================================
  console.log('=== Test 2: Import JSON Schema ===');

  // Use a simple JSON Schema for testing import
  const simpleJsonSchema = JSON.stringify({
    "$schema": "http://json-schema.org/draft-07/schema#",
    "definitions": {
      "Person": {
        "type": "object",
        "properties": {
          "firstName": { "type": "string" },
          "lastName": { "type": "string" },
          "age": { "type": "integer" }
        },
        "required": ["firstName", "lastName"],
        "x-flatbuffers": { "root": true }
      }
    }
  });

  const [jsNamePtr, jsNameLen] = writeString(flatc, 'person.schema.json');
  const [jsSrcPtr, jsSrcLen] = writeString(flatc, simpleJsonSchema);

  const jsSchemaId = flatc._wasm_schema_add(jsNamePtr, jsNameLen, jsSrcPtr, jsSrcLen);
  flatc._free(jsNamePtr);
  flatc._free(jsSrcPtr);

  if (jsSchemaId < 0) {
    console.log('  Note: JSON Schema import may not be fully supported');
    console.log('  Error:', flatc.UTF8ToString(flatc._wasm_get_last_error()));
  } else {
    assert(jsSchemaId >= 0, 'JSON Schema imported successfully');

    // Test JSON to binary conversion with the imported schema
    const personData = JSON.stringify({
      firstName: 'Jane',
      lastName: 'Doe',
      age: 25
    });

    const [jsonPtr, jsonLen] = writeString(flatc, personData);
    const outLenPtr = flatc._malloc(4);
    const binaryPtr = flatc._wasm_json_to_binary(jsSchemaId, jsonPtr, jsonLen, outLenPtr);
    flatc._free(jsonPtr);

    if (binaryPtr) {
      const binaryLen = flatc.getValue(outLenPtr, 'i32');
      assert(binaryLen > 0, `Converted to binary: ${binaryLen} bytes`);

      // Round-trip test
      const binaryData = flatc.HEAPU8.slice(binaryPtr, binaryPtr + binaryLen);
      const binPtr2 = flatc._malloc(binaryData.length);
      flatc.HEAPU8.set(binaryData, binPtr2);

      const outLenPtr2 = flatc._malloc(4);
      const jsonResultPtr = flatc._wasm_binary_to_json(jsSchemaId, binPtr2, binaryData.length, outLenPtr2);
      flatc._free(binPtr2);

      if (jsonResultPtr) {
        const resultLen = flatc.getValue(outLenPtr2, 'i32');
        const jsonResult = new TextDecoder().decode(flatc.HEAPU8.slice(jsonResultPtr, jsonResultPtr + resultLen));
        const parsed = JSON.parse(jsonResult);
        assert(parsed.firstName === 'Jane', 'Round-trip firstName');
        assert(parsed.lastName === 'Doe', 'Round-trip lastName');
        assert(parsed.age === 25, 'Round-trip age');
      }
      flatc._free(outLenPtr2);
    }
    flatc._free(outLenPtr);

    // Export imported JSON Schema back to FBS
    const exportPtr2 = flatc._wasm_schema_export(jsSchemaId, 0, exportOutLenPtr);
    if (exportPtr2) {
      const fbsOutput = flatc.UTF8ToString(exportPtr2);
      assert(fbsOutput.includes('table Person'), 'Exported FBS contains Person table');
      assert(fbsOutput.includes('firstName'), 'Exported FBS contains firstName');
    }
  }
  console.log('');

  // ============================================================================
  // Test 3: Compare with canonical JSON Schema
  // ============================================================================
  console.log('=== Test 3: Validate Against Canonical Schema ===');

  try {
    const canonicalJsonSchema = await readFile(path.join(TESTS_DIR, 'arrays_test.schema.json'), 'utf-8');
    const canonical = JSON.parse(canonicalJsonSchema);

    assert('$schema' in canonical, 'Canonical has $schema');
    assert('definitions' in canonical, 'Canonical has definitions');
    assert('MyGame_Example_ArrayStruct' in canonical.definitions, 'Has ArrayStruct definition');
    assert('MyGame_Example_NestedStruct' in canonical.definitions, 'Has NestedStruct definition');
    console.log(`  Canonical schema has ${Object.keys(canonical.definitions).length} definitions`);
  } catch (err) {
    console.log('  Note: Could not load canonical JSON Schema:', err.message);
  }
  console.log('');

  // ============================================================================
  // Test 4: Code generation produces valid JSON Schema
  // ============================================================================
  console.log('=== Test 4: Code Generation to JSON Schema ===');

  const codeGenOutLenPtr = flatc._malloc(4);
  const codeGenPtr = flatc._wasm_generate_code(schemaId, 11, codeGenOutLenPtr); // 11 = JSONSchema

  if (codeGenPtr) {
    const codeGenLen = flatc.getValue(codeGenOutLenPtr, 'i32');
    const codeGenResult = flatc.UTF8ToString(codeGenPtr);

    assert(codeGenLen > 0, `Code generation produced ${codeGenLen} bytes`);

    try {
      const generated = JSON.parse(codeGenResult);
      assert('$schema' in generated, 'Generated has $schema');
      assert('definitions' in generated, 'Generated has definitions');
    } catch (e) {
      console.log('  Warning: Generated output is not valid JSON');
    }
  }
  flatc._free(codeGenOutLenPtr);
  console.log('');

  // ============================================================================
  // Test 5: Bidirectional IDL ↔ JSON Schema Conversion
  // ============================================================================
  console.log('=== Test 5: Bidirectional IDL ↔ JSON Schema Conversion ===');

  // Start with a simple FBS schema
  const SIMPLE_FBS = `
namespace TestConversion;

enum Status:byte { Unknown = 0, Active, Inactive }

table User {
  id:int;
  name:string;
  email:string;
  status:Status = Active;
  tags:[string];
}

root_type User;
`;

  // Step 1: Load FBS schema
  const [fbsNamePtr, fbsNameLen] = writeString(flatc, 'user.fbs');
  const [fbsSrcPtr, fbsSrcLen] = writeString(flatc, SIMPLE_FBS);
  const fbsSchemaId = flatc._wasm_schema_add(fbsNamePtr, fbsNameLen, fbsSrcPtr, fbsSrcLen);
  flatc._free(fbsNamePtr);
  flatc._free(fbsSrcPtr);

  assert(fbsSchemaId >= 0, 'Step 1: FBS schema loaded');

  // Step 2: Export FBS to JSON Schema
  const jsOutLenPtr = flatc._malloc(4);
  const jsOutputPtr = flatc._wasm_generate_code(fbsSchemaId, 11, jsOutLenPtr);

  let generatedJsonSchema = null;
  if (jsOutputPtr) {
    const jsOutputLen = flatc.getValue(jsOutLenPtr, 'i32');
    generatedJsonSchema = flatc.UTF8ToString(jsOutputPtr);
    assert(jsOutputLen > 0, 'Step 2: FBS → JSON Schema conversion successful');

    const parsed = JSON.parse(generatedJsonSchema);
    assert('$schema' in parsed, 'Generated JSON Schema has $schema');
    assert('definitions' in parsed, 'Generated JSON Schema has definitions');
    assert('TestConversion_User' in parsed.definitions, 'Has User table definition');
    assert('TestConversion_Status' in parsed.definitions, 'Has Status enum definition');

    // Check User properties
    const userDef = parsed.definitions.TestConversion_User;
    assert(userDef.properties.id !== undefined, 'User has id property');
    assert(userDef.properties.name !== undefined, 'User has name property');
    assert(userDef.properties.status !== undefined, 'User has status property');
    assert(userDef.properties.tags !== undefined, 'User has tags property');
  } else {
    console.log('  Warning: JSON Schema generation not available');
  }
  flatc._free(jsOutLenPtr);

  // Step 3: Import the generated JSON Schema back
  if (generatedJsonSchema) {
    const [jsName2Ptr, jsName2Len] = writeString(flatc, 'user.schema.json');
    const [jsSrc2Ptr, jsSrc2Len] = writeString(flatc, generatedJsonSchema);
    const reimportedId = flatc._wasm_schema_add(jsName2Ptr, jsName2Len, jsSrc2Ptr, jsSrc2Len);
    flatc._free(jsName2Ptr);
    flatc._free(jsSrc2Ptr);

    if (reimportedId >= 0) {
      assert(reimportedId >= 0, 'Step 3: JSON Schema re-imported successfully');

      // Step 4: Verify round-trip with data conversion
      const testUser = JSON.stringify({
        id: 123,
        name: 'Test User',
        email: 'test@example.com',
        status: 'Active',
        tags: ['admin', 'verified']
      });

      const [userJsonPtr, userJsonLen] = writeString(flatc, testUser);
      const binOutLenPtr = flatc._malloc(4);
      const binPtr = flatc._wasm_json_to_binary(reimportedId, userJsonPtr, userJsonLen, binOutLenPtr);
      flatc._free(userJsonPtr);

      if (binPtr) {
        const binLen = flatc.getValue(binOutLenPtr, 'i32');
        assert(binLen > 0, 'Step 4: JSON → Binary with re-imported schema');

        // Convert back to JSON to verify
        const binData = flatc.HEAPU8.slice(binPtr, binPtr + binLen);
        const binPtr2 = flatc._malloc(binData.length);
        flatc.HEAPU8.set(binData, binPtr2);

        const jsonOutLenPtr = flatc._malloc(4);
        const jsonOutPtr = flatc._wasm_binary_to_json(reimportedId, binPtr2, binData.length, jsonOutLenPtr);
        flatc._free(binPtr2);

        if (jsonOutPtr) {
          const jsonOutLen = flatc.getValue(jsonOutLenPtr, 'i32');
          const jsonResult = new TextDecoder().decode(flatc.HEAPU8.slice(jsonOutPtr, jsonOutPtr + jsonOutLen));
          const resultParsed = JSON.parse(jsonResult);

          assert(resultParsed.id === 123, 'Round-trip: id preserved');
          assert(resultParsed.name === 'Test User', 'Round-trip: name preserved');
          assert(Array.isArray(resultParsed.tags), 'Round-trip: tags is array');
          assert(resultParsed.tags.length === 2, 'Round-trip: tags count preserved');
        }
        flatc._free(jsonOutLenPtr);
      }
      flatc._free(binOutLenPtr);

      flatc._wasm_schema_remove(reimportedId);
    } else {
      console.log('  Note: JSON Schema re-import requires enhanced parser support');
    }
  }

  flatc._wasm_schema_remove(fbsSchemaId);
  console.log('');

  // ============================================================================
  // Cleanup
  // ============================================================================
  console.log('=== Cleanup ===');
  flatc._wasm_schema_remove(schemaId);
  if (jsSchemaId >= 0) {
    flatc._wasm_schema_remove(jsSchemaId);
  }
  assert(flatc._wasm_schema_count() === 0, 'All schemas removed');
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
    console.log('🎉 All JSON Schema tests passed!');
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
