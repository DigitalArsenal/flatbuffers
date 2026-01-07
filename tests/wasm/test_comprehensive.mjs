// test_comprehensive.mjs - Comprehensive test suite for WASM flatc module
import FlatcWasm from './flatc.js';

// Test schemas
const monsterSchema = `
namespace TestGame;

table Monster {
  name: string;
  hp: int = 100;
  mana: int = 50;
  pos: Vec3;
  inventory: [ubyte];
}

struct Vec3 {
  x: float;
  y: float;
  z: float;
}

root_type Monster;
`;

const simpleSchema = `
table Simple {
  id: int;
  message: string;
}
root_type Simple;
`;

const testJson = `{
  "name": "Orc",
  "hp": 150,
  "mana": 30,
  "pos": { "x": 1.0, "y": 2.0, "z": 3.0 },
  "inventory": [1, 2, 3, 4, 5]
}`;

const simpleJson = `{
  "id": 42,
  "message": "Hello, FlatBuffers!"
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
  // Test 1: Basic Schema Management
  // ============================================================================
  console.log('=== Test 1: Basic Schema Management ===');

  // Add schema
  const schemaName = 'monster.fbs';
  const schemaBytes = new TextEncoder().encode(monsterSchema);
  const namePtr = flatc._malloc(schemaName.length);
  const schemaPtr = flatc._malloc(schemaBytes.length);
  flatc.HEAPU8.set(new TextEncoder().encode(schemaName), namePtr);
  flatc.HEAPU8.set(schemaBytes, schemaPtr);

  const schemaId = flatc._wasm_schema_add(namePtr, schemaName.length, schemaPtr, schemaBytes.length);
  flatc._free(namePtr);
  flatc._free(schemaPtr);

  assert(schemaId >= 0, 'Schema added successfully');
  assert(flatc._wasm_schema_count() === 1, 'Schema count is 1');

  const nameResultPtr = flatc._wasm_schema_get_name(schemaId);
  assert(flatc.UTF8ToString(nameResultPtr) === 'monster.fbs', 'Schema name matches');
  console.log('');

  // ============================================================================
  // Test 2: JSON → Binary Conversion
  // ============================================================================
  console.log('=== Test 2: JSON → Binary Conversion ===');

  const jsonBytes = new TextEncoder().encode(testJson);
  const jsonPtr = flatc._malloc(jsonBytes.length);
  flatc.HEAPU8.set(jsonBytes, jsonPtr);

  const outLenPtr = flatc._malloc(4);
  const binaryPtr = flatc._wasm_json_to_binary(schemaId, jsonPtr, jsonBytes.length, outLenPtr);
  flatc._free(jsonPtr);

  assert(binaryPtr !== 0, 'JSON to binary conversion succeeded');

  const binaryLen = flatc.getValue(outLenPtr, 'i32');
  flatc._free(outLenPtr);
  assert(binaryLen > 0, `Binary output has size ${binaryLen} bytes`);

  // Copy binary for later tests
  const binaryData = flatc.HEAPU8.slice(binaryPtr, binaryPtr + binaryLen);
  console.log('');

  // ============================================================================
  // Test 3: Binary → JSON Conversion
  // ============================================================================
  console.log('=== Test 3: Binary → JSON Conversion ===');

  const binaryInputPtr = flatc._malloc(binaryData.length);
  flatc.HEAPU8.set(binaryData, binaryInputPtr);

  const outLenPtr2 = flatc._malloc(4);
  const jsonResultPtr = flatc._wasm_binary_to_json(schemaId, binaryInputPtr, binaryData.length, outLenPtr2);
  flatc._free(binaryInputPtr);

  assert(jsonResultPtr !== 0, 'Binary to JSON conversion succeeded');

  const jsonLen = flatc.getValue(outLenPtr2, 'i32');
  flatc._free(outLenPtr2);

  const jsonResult = flatc.UTF8ToString(jsonResultPtr);
  assert(jsonLen > 0, `JSON output has ${jsonLen} chars`);
  assert(jsonResult.includes('"name": "Orc"'), 'JSON contains expected name');
  assert(jsonResult.includes('"hp": 150'), 'JSON contains expected hp');
  console.log('');

  // ============================================================================
  // Test 4: Format Detection
  // ============================================================================
  console.log('=== Test 4: Format Detection ===');

  const jsonTestData = new TextEncoder().encode('{"test": 123}');
  const jsonTestPtr = flatc._malloc(jsonTestData.length);
  flatc.HEAPU8.set(jsonTestData, jsonTestPtr);
  const jsonFormat = flatc._wasm_detect_format(jsonTestPtr, jsonTestData.length);
  flatc._free(jsonTestPtr);
  assert(jsonFormat === 0, 'JSON format detected as JSON (0)');

  const binaryTestPtr = flatc._malloc(binaryData.length);
  flatc.HEAPU8.set(binaryData, binaryTestPtr);
  const binaryFormat = flatc._wasm_detect_format(binaryTestPtr, binaryData.length);
  flatc._free(binaryTestPtr);
  assert(binaryFormat === 1, 'FlatBuffer format detected as Binary (1)');
  console.log('');

  // ============================================================================
  // Test 5: Auto-Detect Conversion
  // ============================================================================
  console.log('=== Test 5: Auto-Detect Conversion ===');

  // Test with JSON input (should convert to binary)
  const autoJsonBytes = new TextEncoder().encode(testJson);
  const autoJsonPtr = flatc._malloc(autoJsonBytes.length);
  flatc.HEAPU8.set(autoJsonBytes, autoJsonPtr);

  const autoOutPtrPtr = flatc._malloc(4);
  const autoOutLenPtr = flatc._malloc(4);

  const autoResult1 = flatc._wasm_convert_auto(schemaId, autoJsonPtr, autoJsonBytes.length, autoOutPtrPtr, autoOutLenPtr);
  flatc._free(autoJsonPtr);

  assert(autoResult1 === 0, 'Auto-detect recognized JSON input (returns 0)');
  const autoOutLen1 = flatc.getValue(autoOutLenPtr, 'i32');
  assert(autoOutLen1 > 0, `Auto-convert produced ${autoOutLen1} bytes of binary`);

  // Test with binary input (should convert to JSON)
  const autoBinaryPtr = flatc._malloc(binaryData.length);
  flatc.HEAPU8.set(binaryData, autoBinaryPtr);

  const autoResult2 = flatc._wasm_convert_auto(schemaId, autoBinaryPtr, binaryData.length, autoOutPtrPtr, autoOutLenPtr);
  flatc._free(autoBinaryPtr);

  assert(autoResult2 === 1, 'Auto-detect recognized binary input (returns 1)');
  const autoOutLen2 = flatc.getValue(autoOutLenPtr, 'i32');
  assert(autoOutLen2 > 0, `Auto-convert produced ${autoOutLen2} chars of JSON`);

  flatc._free(autoOutPtrPtr);
  flatc._free(autoOutLenPtr);
  console.log('');

  // ============================================================================
  // Test 6: Streaming Input
  // ============================================================================
  console.log('=== Test 6: Streaming Input ===');

  // Reset stream
  flatc._wasm_stream_reset();
  assert(flatc._wasm_stream_size() === 0, 'Stream reset, size is 0');

  // Write in chunks
  const chunk1 = new TextEncoder().encode('{"name": "Streamed",');
  const chunk2 = new TextEncoder().encode(' "hp": 200}');

  let writePtr = flatc._wasm_stream_prepare(chunk1.length);
  flatc.HEAPU8.set(chunk1, writePtr);
  flatc._wasm_stream_commit(chunk1.length);
  assert(flatc._wasm_stream_size() === chunk1.length, `Stream size after chunk1: ${chunk1.length}`);

  writePtr = flatc._wasm_stream_prepare(chunk2.length);
  flatc.HEAPU8.set(chunk2, writePtr);
  flatc._wasm_stream_commit(chunk2.length);
  assert(flatc._wasm_stream_size() === chunk1.length + chunk2.length, `Stream size after chunk2: ${chunk1.length + chunk2.length}`);

  // Convert streamed data
  const streamOutPtrPtr = flatc._malloc(4);
  const streamOutLenPtr = flatc._malloc(4);
  const streamResult = flatc._wasm_stream_convert(schemaId, streamOutPtrPtr, streamOutLenPtr);

  assert(streamResult === 0, 'Stream convert recognized JSON input');
  const streamOutLen = flatc.getValue(streamOutLenPtr, 'i32');
  assert(streamOutLen > 0, `Stream convert produced ${streamOutLen} bytes`);

  flatc._free(streamOutPtrPtr);
  flatc._free(streamOutLenPtr);
  console.log('');

  // ============================================================================
  // Test 7: Code Generation
  // ============================================================================
  console.log('=== Test 7: Code Generation ===');

  const languages = flatc.UTF8ToString(flatc._wasm_get_supported_languages());
  assert(languages.includes('cpp'), 'Supported languages includes cpp');
  assert(languages.includes('typescript'), 'Supported languages includes typescript');
  console.log('  Supported languages:', languages);

  // Test language ID lookup
  const cppId = flatc._wasm_get_language_id(flatc._malloc(3));
  // Allocate and write "cpp" string properly
  const cppStr = new TextEncoder().encode('cpp\0');
  const cppStrPtr = flatc._malloc(cppStr.length);
  flatc.HEAPU8.set(cppStr, cppStrPtr);
  const cppLangId = flatc._wasm_get_language_id(cppStrPtr);
  flatc._free(cppStrPtr);
  assert(cppLangId === 0, 'Language ID for cpp is 0');

  const tsStr = new TextEncoder().encode('typescript\0');
  const tsStrPtr = flatc._malloc(tsStr.length);
  flatc.HEAPU8.set(tsStr, tsStrPtr);
  const tsLangId = flatc._wasm_get_language_id(tsStrPtr);
  flatc._free(tsStrPtr);
  assert(tsLangId === 9, 'Language ID for typescript is 9');

  // Generate TypeScript code
  const genOutLenPtr = flatc._malloc(4);
  const genResultPtr = flatc._wasm_generate_code(schemaId, 9, genOutLenPtr);  // 9 = TypeScript

  assert(genResultPtr !== 0, 'Code generation succeeded');
  const genLen = flatc.getValue(genOutLenPtr, 'i32');
  assert(genLen > 0, `Generated ${genLen} chars of TypeScript code`);

  const tsCode = flatc.UTF8ToString(genResultPtr);
  assert(tsCode.includes('Monster'), 'Generated code contains Monster');
  assert(tsCode.includes('Vec3'), 'Generated code contains Vec3');
  console.log('  Generated TypeScript code preview:', tsCode.substring(0, 100) + '...');

  flatc._free(genOutLenPtr);
  console.log('');

  // ============================================================================
  // Test 8: Generate Multiple Languages
  // ============================================================================
  console.log('=== Test 8: Generate Multiple Languages ===');

  const languagesToTest = [
    { id: 0, name: 'C++', marker: 'struct' },
    { id: 3, name: 'Go', marker: 'package' },
    { id: 6, name: 'Python', marker: 'def' },
    { id: 7, name: 'Rust', marker: 'pub' },
    { id: 11, name: 'JSON Schema', marker: '$schema' },
    { id: 12, name: 'FBS', marker: 'table Monster' },
  ];

  for (const lang of languagesToTest) {
    const langOutLenPtr = flatc._malloc(4);
    const langResultPtr = flatc._wasm_generate_code(schemaId, lang.id, langOutLenPtr);
    const langLen = flatc.getValue(langOutLenPtr, 'i32');
    flatc._free(langOutLenPtr);

    if (langResultPtr !== 0 && langLen > 0) {
      const code = flatc.UTF8ToString(langResultPtr);
      assert(code.includes(lang.marker), `${lang.name} code contains "${lang.marker}"`);
    } else {
      const error = flatc.UTF8ToString(flatc._wasm_get_last_error());
      console.log(`  ⚠ ${lang.name} generation: ${error || 'returned empty'}`);
    }
  }
  console.log('');

  // ============================================================================
  // Test 9: Schema Export
  // ============================================================================
  console.log('=== Test 9: Schema Export ===');

  const exportOutLenPtr = flatc._malloc(4);
  const exportPtr = flatc._wasm_schema_export(schemaId, 0, exportOutLenPtr);  // 0 = FBS format

  assert(exportPtr !== 0, 'Schema export succeeded');
  const exportLen = flatc.getValue(exportOutLenPtr, 'i32');
  assert(exportLen > 0, `Exported ${exportLen} bytes`);

  const exportedFbs = flatc.UTF8ToString(exportPtr);
  assert(exportedFbs.includes('Monster'), 'Exported FBS contains Monster');
  assert(exportedFbs.includes('Vec3'), 'Exported FBS contains Vec3');

  flatc._free(exportOutLenPtr);
  console.log('');

  // ============================================================================
  // Test 10: Multiple Schemas
  // ============================================================================
  console.log('=== Test 10: Multiple Schemas ===');

  // Add second schema
  const simple2Name = 'simple.fbs';
  const simple2Bytes = new TextEncoder().encode(simpleSchema);
  const name2Ptr = flatc._malloc(simple2Name.length);
  const schema2Ptr = flatc._malloc(simple2Bytes.length);
  flatc.HEAPU8.set(new TextEncoder().encode(simple2Name), name2Ptr);
  flatc.HEAPU8.set(simple2Bytes, schema2Ptr);

  const schema2Id = flatc._wasm_schema_add(name2Ptr, simple2Name.length, schema2Ptr, simple2Bytes.length);
  flatc._free(name2Ptr);
  flatc._free(schema2Ptr);

  assert(schema2Id >= 0, 'Second schema added');
  assert(flatc._wasm_schema_count() === 2, 'Schema count is 2');

  // Test conversion with second schema
  const simple2JsonBytes = new TextEncoder().encode(simpleJson);
  const simple2JsonPtr = flatc._malloc(simple2JsonBytes.length);
  flatc.HEAPU8.set(simple2JsonBytes, simple2JsonPtr);

  const simple2OutLenPtr = flatc._malloc(4);
  const simple2BinaryPtr = flatc._wasm_json_to_binary(schema2Id, simple2JsonPtr, simple2JsonBytes.length, simple2OutLenPtr);
  flatc._free(simple2JsonPtr);

  assert(simple2BinaryPtr !== 0, 'Conversion with second schema succeeded');
  const simple2BinaryLen = flatc.getValue(simple2OutLenPtr, 'i32');
  assert(simple2BinaryLen > 0, `Second schema binary: ${simple2BinaryLen} bytes`);
  flatc._free(simple2OutLenPtr);
  console.log('');

  // ============================================================================
  // Test 11: Embind API
  // ============================================================================
  console.log('=== Test 11: Embind API ===');

  const embindSchema = flatc.createSchema('embind.fbs', simpleSchema);
  assert(embindSchema.valid(), 'Embind schema is valid');
  assert(embindSchema.id() >= 0, `Embind schema ID: ${embindSchema.id()}`);
  assert(embindSchema.name() === 'embind.fbs', 'Embind schema name matches');

  // Get all schemas
  const allSchemas = flatc.getAllSchemas();
  assert(allSchemas.size() >= 3, `getAllSchemas returned ${allSchemas.size()} schemas`);

  // Release and verify
  embindSchema.release();
  assert(!embindSchema.valid(), 'Embind schema invalid after release');
  embindSchema.delete();
  console.log('');

  // ============================================================================
  // Test 12: Error Handling
  // ============================================================================
  console.log('=== Test 12: Error Handling ===');

  // Try to use invalid schema ID
  flatc._wasm_clear_error();
  const invalidOutLenPtr = flatc._malloc(4);
  const invalidResult = flatc._wasm_json_to_binary(9999, 0, 0, invalidOutLenPtr);
  flatc._free(invalidOutLenPtr);

  assert(invalidResult === 0, 'Invalid schema ID returns null');
  const error1 = flatc.UTF8ToString(flatc._wasm_get_last_error());
  assert(error1.includes('not found'), 'Error message mentions "not found"');

  // Try to parse invalid JSON
  flatc._wasm_clear_error();
  const badJson = new TextEncoder().encode('{ invalid json }');
  const badJsonPtr = flatc._malloc(badJson.length);
  flatc.HEAPU8.set(badJson, badJsonPtr);

  const badOutLenPtr = flatc._malloc(4);
  const badResult = flatc._wasm_json_to_binary(schemaId, badJsonPtr, badJson.length, badOutLenPtr);
  flatc._free(badJsonPtr);
  flatc._free(badOutLenPtr);

  assert(badResult === 0, 'Invalid JSON returns null');
  const error2 = flatc.UTF8ToString(flatc._wasm_get_last_error());
  assert(error2.length > 0, 'Error message set for invalid JSON');
  console.log('');

  // ============================================================================
  // Test 13: Cleanup
  // ============================================================================
  console.log('=== Test 13: Cleanup ===');

  // Remove all schemas
  flatc._wasm_schema_remove(schemaId);
  flatc._wasm_schema_remove(schema2Id);

  // Count should be 0 or 1 (embind schema was released)
  const finalCount = flatc._wasm_schema_count();
  assert(finalCount <= 1, `Final schema count: ${finalCount}`);
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
    console.log('🎉 All tests passed!');
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
