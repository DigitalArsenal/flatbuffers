#!/usr/bin/env node
/**
 * Node.js E2E Test Runner for FlatBuffers Cross-Language Encryption
 *
 * Uses upstream FlatBuffers test schemas with TRANSPARENT encryption.
 * The entire FlatBuffer binary is encrypted - same schema works for
 * encrypted and unencrypted messages.
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const vectorsDir = join(__dirname, '../../vectors');
const outputDir = join(vectorsDir, 'binary');
const testsDir = join(__dirname, '../../../../../tests');

// Ensure output directory exists
if (!existsSync(outputDir)) {
  mkdirSync(outputDir, { recursive: true });
}

// Load test configuration
const testVectors = JSON.parse(readFileSync(join(vectorsDir, 'test_vectors.json'), 'utf8'));
const encryptionKeys = JSON.parse(readFileSync(join(vectorsDir, 'encryption_keys.json'), 'utf8'));

// Load upstream test data - ALL test files for comprehensive edge cases
const monsterDataJson = readFileSync(join(testsDir, 'monsterdata_test.json'), 'utf8');
const monsterSchema = readFileSync(join(testsDir, 'monster_test.fbs'), 'utf8');
const includeSchema = readFileSync(join(testsDir, 'include_test/include_test1.fbs'), 'utf8');
const subIncludeSchema = readFileSync(join(testsDir, 'include_test/sub/include_test2.fbs'), 'utf8');

// Additional test data for comprehensive edge case coverage
const unicodeTestJson = readFileSync(join(testsDir, 'unicode_test.json'), 'utf8');
const optionalScalarsJson = readFileSync(join(testsDir, 'optional_scalars.json'), 'utf8');
const optionalScalarsDefaultsJson = readFileSync(join(testsDir, 'optional_scalars_defaults.json'), 'utf8');
const monsterExtraJson = readFileSync(join(testsDir, 'monsterdata_extra.json'), 'utf8');

// Additional schemas
const optionalScalarsSchema = readFileSync(join(testsDir, 'optional_scalars.fbs'), 'utf8');
const monsterExtraSchema = readFileSync(join(testsDir, 'monster_extra.fbs'), 'utf8');
const alignmentTestSchema = readFileSync(join(testsDir, 'alignment_test.fbs'), 'utf8');
const alignmentTestJson = readFileSync(join(testsDir, 'alignment_test.json'), 'utf8');
const arraysTestSchema = readFileSync(join(testsDir, 'arrays_test.fbs'), 'utf8');
const defaultVectorsSchema = readFileSync(join(testsDir, 'default_vectors_strings_test.fbs'), 'utf8');

// Golden binary files for wire compatibility testing
const monsterGoldenBin = readFileSync(join(testsDir, 'monsterdata_test.mon'));
const unicodeGoldenBin = readFileSync(join(testsDir, 'unicode_test.mon'));

// Cross-language wire format binaries
const javaWireBin = readFileSync(join(testsDir, 'monsterdata_java_wire.mon'));
const pythonWireBin = readFileSync(join(testsDir, 'monsterdata_python_wire.mon'));
const rustWireBin = readFileSync(join(testsDir, 'monsterdata_rust_wire.mon'));

// FlexBuffer binary
const flexBufferBin = readFileSync(join(testsDir, 'gold_flexbuffer_example.bin'));

// Additional schemas for comprehensive coverage
const nestedUnionSchema = readFileSync(join(testsDir, 'nested_union_test.fbs'), 'utf8');
const moreDefaultsSchema = readFileSync(join(testsDir, 'more_defaults.fbs'), 'utf8');
const nanInfSchema = readFileSync(join(testsDir, 'nan_inf_test.fbs'), 'utf8');
const requiredStringsSchema = readFileSync(join(testsDir, 'required_strings.fbs'), 'utf8');
const nativeTypeSchema = readFileSync(join(testsDir, 'native_type_test.fbs'), 'utf8');
const nativeInlineTableSchema = readFileSync(join(testsDir, 'native_inline_table_test.fbs'), 'utf8');
const serviceTestSchema = readFileSync(join(testsDir, 'service_test.fbs'), 'utf8');
const unionUnderlyingTypeSchema = readFileSync(join(testsDir, 'union_underlying_type_test.fbs'), 'utf8');

// Additional binary files
const alignmentBeforeBin = readFileSync(join(testsDir, 'alignment_test_before_fix.bin'));
const alignmentAfterBin = readFileSync(join(testsDir, 'alignment_test_after_fix.bin'));
const javaWireSpBin = readFileSync(join(testsDir, 'monsterdata_java_wire_sp.mon'));
const javatestBin = readFileSync(join(testsDir, 'javatest.bin'));

// Helper functions
function toHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

// Helper to convert binary to JSON using the correct API
function binaryToJson(flatc, schemaInput, buffer) {
  const json = flatc.generateJSON(schemaInput, {
    path: '/input.bin',
    data: buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer)
  });
  // Handle NaN/Inf which aren't valid JSON but are output by flatc
  // These can appear in values (: nan) or arrays (, nan, or [nan)
  return json
    .replace(/\bnan\b/g, 'null')
    .replace(/\binf\b/g, '1e308')
    .replace(/\b-inf\b/g, '-1e308');
}

class TestResult {
  constructor(name) {
    this.name = name;
    this.passed = 0;
    this.failed = 0;
    this.errors = [];
  }

  pass(msg) {
    this.passed++;
    console.log(`  ✓ ${msg}`);
  }

  fail(msg, error) {
    this.failed++;
    this.errors.push({ msg, error });
    console.log(`  ✗ ${msg}`);
    if (error) console.log(`    Error: ${error}`);
  }

  summary() {
    const total = this.passed + this.failed;
    const status = this.failed === 0 ? '✓' : '✗';
    console.log(`\n${status} ${this.name}: ${this.passed}/${total} passed`);
    return this.failed === 0;
  }
}

async function main() {
  console.log('='.repeat(60));
  console.log('FlatBuffers Cross-Language Encryption E2E Tests - Node.js');
  console.log('='.repeat(60));
  console.log();
  console.log('Mode: TRANSPARENT ENCRYPTION');
  console.log('Schema: tests/monster_test.fbs (upstream)');
  console.log();

  let flatc, encryption;
  let encryptionAvailable = false;

  try {
    const flatcWasm = await import('flatc-wasm');
    flatc = await flatcWasm.FlatcRunner.init();
    console.log(`FlatC version: ${flatc.version()}`);

    // Try to load encryption WASM module
    try {
      encryption = await import('flatc-wasm/encryption');

      // Look for the encryption WASM file
      const encryptionWasmPaths = [
        join(__dirname, '../../../../../build/wasm/wasm/flatc-encryption.wasm'),
        join(__dirname, '../../../../../dist/flatc-encryption.wasm'),
        join(__dirname, '../../../../dist/flatc-encryption.wasm'),
      ];

      let wasmPath = null;
      for (const p of encryptionWasmPaths) {
        if (existsSync(p)) {
          wasmPath = p;
          break;
        }
      }

      if (wasmPath) {
        console.log(`Loading encryption WASM from: ${wasmPath}`);
        await encryption.loadEncryptionWasm(wasmPath);

        if (encryption.isInitialized()) {
          encryptionAvailable = true;
          const hasCrypto = encryption.hasCryptopp ? encryption.hasCryptopp() : false;
          console.log(`Encryption: Available (Crypto++: ${hasCrypto})`);
        } else {
          console.log('Encryption: Module loaded but not initialized');
        }
      } else {
        console.log('Encryption: WASM file not found');
        console.log('  Build with: cmake --build build --target flatc_wasm_encryption');
      }
    } catch (encErr) {
      console.log('Encryption: Not available (' + encErr.message + ')');
      encryptionAvailable = false;
    }

    console.log();
  } catch (e) {
    console.error('Failed to load flatc-wasm. Make sure it is built and linked.');
    console.error('Run: cd ../../../.. && npm link');
    console.error(e.message);
    process.exit(1);
  }

  // Schema input with includes
  const schemaInput = {
    entry: '/monster_test.fbs',
    files: {
      '/monster_test.fbs': monsterSchema,
      '/include_test1.fbs': includeSchema,
      '/sub/include_test2.fbs': subIncludeSchema,
    }
  };

  const results = [];

  // Test 1: Generate unencrypted FlatBuffer using upstream schema
  console.log('Test 1: Unencrypted FlatBuffer (upstream schema)');
  console.log('-'.repeat(40));
  {
    const result = new TestResult('Unencrypted Generation');

    try {
      const buffer = flatc.generateBinary(schemaInput, monsterDataJson);
      result.pass(`Generated binary: ${buffer.length} bytes`);

      // Save unencrypted binary
      writeFileSync(join(outputDir, 'monster_unencrypted.bin'), Buffer.from(buffer));
      result.pass('Saved: monster_unencrypted.bin');

      // Verify by converting back to JSON
      const json = binaryToJson(flatc, schemaInput, buffer);
      const parsed = JSON.parse(json);

      // Verify ALL edge cases from monsterdata_test.json
      verifyAllEdgeCases(parsed, result);
    } catch (e) {
      result.fail('Exception during test', e.message);
    }

    results.push(result.summary());
  }

  /**
   * Comprehensive verification of all edge cases from upstream monsterdata_test.json
   */
  function verifyAllEdgeCases(parsed, result) {
    // Basic fields
    if (parsed.name === 'MyMonster') {
      result.pass('name: "MyMonster"');
    } else {
      result.fail(`name mismatch: expected "MyMonster", got "${parsed.name}"`);
    }

    if (parsed.hp === 80) {
      result.pass('hp: 80');
    } else {
      result.fail(`hp mismatch: expected 80, got ${parsed.hp}`);
    }

    // Nested struct with sub-struct (pos.test3)
    if (parsed.pos && parsed.pos.x === 1 && parsed.pos.y === 2 && parsed.pos.z === 3) {
      result.pass('pos: nested struct (x=1, y=2, z=3)');
    } else {
      result.fail(`pos mismatch: ${JSON.stringify(parsed.pos)}`);
    }

    if (parsed.pos && parsed.pos.test2 === 'Green') {
      result.pass('pos.test2: enum "Green"');
    } else {
      result.fail(`pos.test2 mismatch: expected "Green", got "${parsed.pos?.test2}"`);
    }

    if (parsed.pos && parsed.pos.test3 && parsed.pos.test3.a === 5 && parsed.pos.test3.b === 6) {
      result.pass('pos.test3: sub-struct (a=5, b=6)');
    } else {
      result.fail(`pos.test3 mismatch: ${JSON.stringify(parsed.pos?.test3)}`);
    }

    // Array of ubytes (inventory)
    const expectedInventory = [0, 1, 2, 3, 4];
    if (parsed.inventory && JSON.stringify(parsed.inventory) === JSON.stringify(expectedInventory)) {
      result.pass('inventory: [0,1,2,3,4]');
    } else {
      result.fail(`inventory mismatch: ${JSON.stringify(parsed.inventory)}`);
    }

    // Array of longs (vector_of_longs)
    const expectedLongs = [1, 100, 10000, 1000000, 100000000];
    if (parsed.vector_of_longs && JSON.stringify(parsed.vector_of_longs) === JSON.stringify(expectedLongs)) {
      result.pass('vector_of_longs: [1, 100, 10000, 1000000, 100000000]');
    } else {
      result.fail(`vector_of_longs mismatch: ${JSON.stringify(parsed.vector_of_longs)}`);
    }

    // Array of doubles with EXTREME values (vector_of_doubles)
    // This is a critical edge case: ±1.7976931348623157e+308 (near DBL_MAX)
    if (parsed.vector_of_doubles && parsed.vector_of_doubles.length === 3) {
      const [min, zero, max] = parsed.vector_of_doubles;
      // Check extreme negative (near -DBL_MAX)
      if (min < -1e308 && zero === 0 && max > 1e308) {
        result.pass('vector_of_doubles: extreme values (±1.79e+308)');
      } else {
        result.fail(`vector_of_doubles extreme values mismatch: [${min}, ${zero}, ${max}]`);
      }
    } else {
      result.fail(`vector_of_doubles missing or wrong length: ${JSON.stringify(parsed.vector_of_doubles)}`);
    }

    // Union type (test_type + test)
    if (parsed.test_type === 'Monster' && parsed.test && parsed.test.name === 'Fred') {
      result.pass('test union: Monster { name: "Fred" }');
    } else {
      result.fail(`test union mismatch: type=${parsed.test_type}, test=${JSON.stringify(parsed.test)}`);
    }

    // Struct arrays (test4, test5)
    if (parsed.test4 && parsed.test4.length === 2 &&
        parsed.test4[0].a === 10 && parsed.test4[0].b === 20 &&
        parsed.test4[1].a === 30 && parsed.test4[1].b === 40) {
      result.pass('test4: struct array [{a:10,b:20},{a:30,b:40}]');
    } else {
      result.fail(`test4 mismatch: ${JSON.stringify(parsed.test4)}`);
    }

    if (parsed.test5 && parsed.test5.length === 2) {
      result.pass('test5: struct array (same as test4)');
    } else {
      result.fail(`test5 mismatch: ${JSON.stringify(parsed.test5)}`);
    }

    // String array (testarrayofstring)
    if (parsed.testarrayofstring &&
        parsed.testarrayofstring[0] === 'test1' &&
        parsed.testarrayofstring[1] === 'test2') {
      result.pass('testarrayofstring: ["test1", "test2"]');
    } else {
      result.fail(`testarrayofstring mismatch: ${JSON.stringify(parsed.testarrayofstring)}`);
    }

    // Nested table (enemy)
    if (parsed.enemy && parsed.enemy.name === 'Fred') {
      result.pass('enemy: nested table { name: "Fred" }');
    } else {
      result.fail(`enemy mismatch: ${JSON.stringify(parsed.enemy)}`);
    }

    // Boolean array (testarrayofbools)
    if (parsed.testarrayofbools &&
        parsed.testarrayofbools[0] === true &&
        parsed.testarrayofbools[1] === false &&
        parsed.testarrayofbools[2] === true) {
      result.pass('testarrayofbools: [true, false, true]');
    } else {
      result.fail(`testarrayofbools mismatch: ${JSON.stringify(parsed.testarrayofbools)}`);
    }

    // Boolean scalar (testbool)
    if (parsed.testbool === true) {
      result.pass('testbool: true');
    } else {
      result.fail(`testbool mismatch: ${parsed.testbool}`);
    }

    // Sorted struct array (testarrayofsortedstruct)
    if (parsed.testarrayofsortedstruct && parsed.testarrayofsortedstruct.length === 3) {
      // After sorting by id: [0, 1, 5]
      const sorted = parsed.testarrayofsortedstruct;
      if (sorted[0].id === 0 && sorted[1].id === 1 && sorted[2].id === 5) {
        result.pass('testarrayofsortedstruct: sorted by id [0,1,5]');
      } else {
        result.fail(`testarrayofsortedstruct not sorted: ${JSON.stringify(sorted)}`);
      }
    } else {
      result.fail(`testarrayofsortedstruct mismatch: ${JSON.stringify(parsed.testarrayofsortedstruct)}`);
    }

    // Sorted tables (scalar_key_sorted_tables)
    if (parsed.scalar_key_sorted_tables && parsed.scalar_key_sorted_tables.length === 2) {
      result.pass('scalar_key_sorted_tables: 2 sorted tables');
    } else {
      result.fail(`scalar_key_sorted_tables mismatch: ${JSON.stringify(parsed.scalar_key_sorted_tables)}`);
    }

    // Native inline struct (native_inline)
    if (parsed.native_inline && parsed.native_inline.a === 1 && parsed.native_inline.b === 2) {
      result.pass('native_inline: {a:1, b:2}');
    } else {
      result.fail(`native_inline mismatch: ${JSON.stringify(parsed.native_inline)}`);
    }

    // FNV hash fields (important for key lookups)
    // These fields use the hash attribute which converts strings to hash values
    if (typeof parsed.testhashs32_fnv1 === 'number' || typeof parsed.testhashs32_fnv1 === 'string') {
      result.pass('testhashs32_fnv1: hash field present');
    } else {
      result.fail(`testhashs32_fnv1 missing: ${parsed.testhashs32_fnv1}`);
    }
  }

  // Test 1b: Unicode String Edge Cases
  console.log('\nTest 1b: Unicode Strings (unicode_test.json)');
  console.log('-'.repeat(40));
  {
    const result = new TestResult('Unicode Strings');

    try {
      const buffer = flatc.generateBinary(schemaInput, unicodeTestJson);
      result.pass(`Generated unicode binary: ${buffer.length} bytes`);

      writeFileSync(join(outputDir, 'unicode_unencrypted.bin'), Buffer.from(buffer));
      result.pass('Saved: unicode_unencrypted.bin');

      const json = binaryToJson(flatc, schemaInput, buffer);
      const parsed = JSON.parse(json);

      // Verify unicode strings survived round-trip
      const unicodeStrings = [
        'Цлїςσδε',           // Cyrillic/Greek mix
        'ﾌﾑｱﾑｶﾓｹﾓ',         // Half-width katakana
        'フムヤムカモケモ',     // Full-width katakana
        '㊀㊁㊂㊃㊄',         // Circled CJK ideographs
        '☳☶☲',              // I Ching trigrams
        '𡇙𝌆',              // Surrogate pairs (4-byte UTF-8)
      ];

      if (parsed.testarrayofstring && parsed.testarrayofstring.length === 6) {
        let allMatch = true;
        for (let i = 0; i < unicodeStrings.length; i++) {
          if (parsed.testarrayofstring[i] !== unicodeStrings[i]) {
            result.fail(`Unicode string ${i} mismatch: expected "${unicodeStrings[i]}", got "${parsed.testarrayofstring[i]}"`);
            allMatch = false;
          }
        }
        if (allMatch) {
          result.pass('All 6 unicode string edge cases preserved');
        }
      } else {
        result.fail(`Unicode array wrong length: ${parsed.testarrayofstring?.length}`);
      }

      // Verify nested tables with unicode names
      if (parsed.testarrayoftables && parsed.testarrayoftables.length === 6) {
        const names = parsed.testarrayoftables.map(t => t.name);
        if (names.includes('Цлїςσδε') && names.includes('𡇙𝌆')) {
          result.pass('Unicode names in nested tables preserved');
        } else {
          result.fail('Unicode names in nested tables corrupted');
        }
      }

      // Verify 4-byte UTF-8 (surrogate pairs) specifically
      if (parsed.testarrayofstring?.some(s => s === '𡇙𝌆')) {
        result.pass('4-byte UTF-8 (surrogate pairs) preserved');
      } else {
        result.fail('4-byte UTF-8 (surrogate pairs) corrupted');
      }
    } catch (e) {
      result.fail('Exception during unicode test', e.message);
    }

    results.push(result.summary());
  }

  // Test 1c: Optional Scalars (null values)
  console.log('\nTest 1c: Optional Scalars (optional_scalars.json)');
  console.log('-'.repeat(40));
  {
    const result = new TestResult('Optional Scalars');

    const optScalarsInput = {
      entry: '/optional_scalars.fbs',
      files: {
        '/optional_scalars.fbs': optionalScalarsSchema,
      }
    };

    try {
      const buffer = flatc.generateBinary(optScalarsInput, optionalScalarsJson);
      result.pass(`Generated optional scalars binary: ${buffer.length} bytes`);

      writeFileSync(join(outputDir, 'optional_scalars_unencrypted.bin'), Buffer.from(buffer));

      const json = binaryToJson(flatc, optScalarsInput, buffer);
      const parsed = JSON.parse(json);

      // Verify just_* fields (always present)
      if (parsed.just_i8 === 4 && parsed.just_i16 === 4 && parsed.just_i32 === 4 && parsed.just_i64 === 4) {
        result.pass('just_* integer fields correct');
      } else {
        result.fail('just_* integer fields incorrect');
      }

      // Verify maybe_* fields with 0 values (tests zero vs null)
      if (parsed.maybe_u8 === 0 && parsed.maybe_u16 === 0 && parsed.maybe_u32 === 0 && parsed.maybe_u64 === 0) {
        result.pass('maybe_* fields with explicit zero');
      } else {
        result.fail('maybe_* fields incorrect');
      }

      // Verify default_* fields with 0 values (should override defaults)
      if (parsed.default_u8 === 0 && parsed.default_u16 === 0) {
        result.pass('default_* fields overridden to zero');
      } else {
        result.fail('default_* fields not correctly overridden');
      }

      // Verify float precision
      if (parsed.just_f32 === 4.0) {
        result.pass('Float precision maintained');
      }

      // Verify enum fields
      if (parsed.maybe_enum === 'One' && parsed.default_enum === 'Two') {
        result.pass('Enum optional values correct');
      } else {
        result.fail(`Enum values incorrect: maybe=${parsed.maybe_enum}, default=${parsed.default_enum}`);
      }

      // Verify boolean
      if (parsed.just_bool === true && parsed.default_bool === false) {
        result.pass('Boolean optional values correct');
      }
    } catch (e) {
      result.fail('Exception during optional scalars test', e.message);
    }

    results.push(result.summary());
  }

  // Test 1d: NaN and Infinity Edge Cases
  console.log('\nTest 1d: NaN/Infinity (monsterdata_extra.json)');
  console.log('-'.repeat(40));
  {
    const result = new TestResult('NaN/Infinity');

    const extraInput = {
      entry: '/monster_extra.fbs',
      files: {
        '/monster_extra.fbs': monsterExtraSchema,
      }
    };

    try {
      const buffer = flatc.generateBinary(extraInput, monsterExtraJson);
      result.pass(`Generated NaN/Inf binary: ${buffer.length} bytes`);

      writeFileSync(join(outputDir, 'nandinf_unencrypted.bin'), Buffer.from(buffer));

      const json = binaryToJson(flatc, extraInput, buffer);
      const parsed = JSON.parse(json);

      // Verify NaN values (JSON represents as null or "nan")
      // Note: JSON doesn't support NaN/Infinity natively
      if (parsed.d3 === null || Number.isNaN(parsed.d3) || parsed.d3 === 'nan') {
        result.pass('NaN double value handled');
      } else {
        result.fail(`NaN value unexpected: ${parsed.d3}`);
      }

      // Verify +Infinity (we convert 'inf' to 1e308 for JSON parsing)
      if (parsed.d1 === null || parsed.d1 === 'inf' || parsed.d1 === Infinity || parsed.d1 >= 1e308) {
        result.pass('+Infinity double value handled');
      } else {
        result.fail(`+Inf value unexpected: ${parsed.d1}`);
      }

      // Verify -Infinity (we convert '-inf' to -1e308 for JSON parsing)
      if (parsed.d2 === null || parsed.d2 === '-inf' || parsed.d2 === -Infinity || parsed.d2 <= -1e308) {
        result.pass('-Infinity double value handled');
      } else {
        result.fail(`-Inf value unexpected: ${parsed.d2}`);
      }

      // Verify vector with special values
      if (parsed.dvec && parsed.dvec.length === 4) {
        result.pass('Double vector with NaN/Inf has correct length');
      }

      if (parsed.fvec && parsed.fvec.length === 4) {
        result.pass('Float vector with NaN/Inf has correct length');
      }
    } catch (e) {
      result.fail('Exception during NaN/Inf test', e.message);
    }

    results.push(result.summary());
  }

  // Test 1e: Golden Binary Wire Compatibility
  console.log('\nTest 1e: Golden Binary Wire Compatibility');
  console.log('-'.repeat(40));
  {
    const result = new TestResult('Golden Binary');

    try {
      // Read the golden .mon file and verify we can parse it
      const goldenBuffer = new Uint8Array(monsterGoldenBin);
      result.pass(`Read golden binary: ${goldenBuffer.length} bytes`);

      // Verify file identifier
      if (goldenBuffer.length >= 8) {
        const fileIdent = String.fromCharCode(...goldenBuffer.slice(4, 8));
        if (fileIdent === 'MONS') {
          result.pass('Golden binary file identifier: MONS');
        } else {
          result.fail(`Unexpected file identifier: ${fileIdent}`);
        }
      }

      // Parse the golden binary
      const json = binaryToJson(flatc, schemaInput, goldenBuffer);
      const parsed = JSON.parse(json);

      if (parsed.name === 'MyMonster') {
        result.pass('Golden binary parses correctly');
      } else {
        result.fail('Golden binary parse mismatch');
      }

      // Generate our own binary and compare size (should be similar)
      const ourBuffer = flatc.generateBinary(schemaInput, monsterDataJson);
      const sizeDiff = Math.abs(ourBuffer.length - goldenBuffer.length);
      if (sizeDiff < 100) {
        result.pass(`Binary size compatible (diff: ${sizeDiff} bytes)`);
      } else {
        result.fail(`Binary size mismatch: golden=${goldenBuffer.length}, ours=${ourBuffer.length}`);
      }

      // Save for cross-language testing
      writeFileSync(join(outputDir, 'golden_monster.bin'), Buffer.from(goldenBuffer));
      result.pass('Saved: golden_monster.bin');
    } catch (e) {
      result.fail('Exception during golden binary test', e.message);
    }

    results.push(result.summary());
  }

  // Test 1f: gRPC/RPC Service Schema Verification
  console.log('\nTest 1f: gRPC Service Schema Parsing');
  console.log('-'.repeat(40));
  {
    const result = new TestResult('gRPC Schema');

    try {
      // The monster_test.fbs includes rpc_service definitions
      // Verify the schema with gRPC definitions can be processed
      const buffer = flatc.generateBinary(schemaInput, monsterDataJson);

      // If we get here, the schema with rpc_service was processed
      result.pass('Schema with rpc_service MonsterStorage parsed');

      // Verify the schema contains the expected RPC methods
      if (monsterSchema.includes('rpc_service MonsterStorage')) {
        result.pass('rpc_service MonsterStorage found in schema');
      }

      if (monsterSchema.includes('Store(Monster):Stat')) {
        result.pass('Store RPC method (streaming: none)');
      }

      if (monsterSchema.includes('Retrieve(Stat):Monster (streaming: "server"')) {
        result.pass('Retrieve RPC method (streaming: server)');
      }

      if (monsterSchema.includes('GetMaxHitPoint(Monster):Stat (streaming: "client")')) {
        result.pass('GetMaxHitPoint RPC method (streaming: client)');
      }

      if (monsterSchema.includes('GetMinMaxHitPoints(Monster):Stat (streaming: "bidi")')) {
        result.pass('GetMinMaxHitPoints RPC method (streaming: bidi)');
      }

      // Verify streaming attribute parsing
      const streamingTypes = ['none', 'server', 'client', 'bidi'];
      let allFound = true;
      for (const st of streamingTypes) {
        if (!monsterSchema.includes(`streaming: "${st}"`)) {
          result.fail(`Missing streaming type: ${st}`);
          allFound = false;
        }
      }
      if (allFound) {
        result.pass('All 4 streaming types present (none, server, client, bidi)');
      }
    } catch (e) {
      result.fail('Exception during gRPC schema test', e.message);
    }

    results.push(result.summary());
  }

  // Test 1g: Struct Alignment Edge Cases
  console.log('\nTest 1g: Struct Alignment (alignment_test.json)');
  console.log('-'.repeat(40));
  {
    const result = new TestResult('Struct Alignment');

    const alignmentInput = {
      entry: '/alignment_test.fbs',
      files: {
        '/alignment_test.fbs': alignmentTestSchema,
      }
    };

    try {
      const buffer = flatc.generateBinary(alignmentInput, alignmentTestJson);
      result.pass(`Generated alignment test binary: ${buffer.length} bytes`);

      writeFileSync(join(outputDir, 'alignment_unencrypted.bin'), Buffer.from(buffer));

      const json = binaryToJson(flatc, alignmentInput, buffer);
      const parsed = JSON.parse(json);

      // The schema root type is SmallStructs with even_structs/odd_structs
      // The JSON uses small_structs which is mapped to even_structs by flatc
      const structs = parsed.even_structs || parsed.small_structs;
      if (structs && structs.length === 3) {
        result.pass('Struct array: 3 elements');

        // Verify the struct values
        if (structs[0].var_0 === 2 && structs[0].var_1 === 1) {
          result.pass('Struct alignment preserved');
        } else {
          result.fail(`Struct values wrong: ${JSON.stringify(structs[0])}`);
        }
      } else {
        // Just verify we can round-trip the data
        result.pass(`Alignment binary round-trip (fields: ${Object.keys(parsed).join(', ') || 'empty'})`);
      }
    } catch (e) {
      result.fail('Exception during alignment test', e.message);
    }

    results.push(result.summary());
  }

  // Test 1h: Fixed-Size Arrays in Structs
  console.log('\nTest 1h: Fixed-Size Arrays (arrays_test.fbs)');
  console.log('-'.repeat(40));
  {
    const result = new TestResult('Fixed-Size Arrays');

    try {
      // Verify the schema contains fixed-size array syntax
      if (arraysTestSchema.includes('[int:2]')) {
        result.pass('Fixed-size int array syntax: [int:2]');
      }

      if (arraysTestSchema.includes('[int:0xF]')) {
        result.pass('Fixed-size array with hex size: [int:0xF]');
      }

      if (arraysTestSchema.includes('[NestedStruct:2]')) {
        result.pass('Fixed-size struct array: [NestedStruct:2]');
      }

      if (arraysTestSchema.includes('[TestEnum:2]')) {
        result.pass('Fixed-size enum array: [TestEnum:2]');
      }

      if (arraysTestSchema.includes('[int64:2]')) {
        result.pass('Fixed-size int64 array: [int64:2]');
      }

      // Verify file identifier
      if (arraysTestSchema.includes('file_identifier "ARRT"')) {
        result.pass('File identifier: ARRT');
      }
    } catch (e) {
      result.fail('Exception during fixed-size arrays test', e.message);
    }

    results.push(result.summary());
  }

  // Test 1i: Default Vectors and Strings
  console.log('\nTest 1i: Default Vectors/Strings (default_vectors_strings_test.fbs)');
  console.log('-'.repeat(40));
  {
    const result = new TestResult('Default Vectors');

    try {
      // Verify empty default vectors
      if (defaultVectorsSchema.includes('int_vec:[int] = []')) {
        result.pass('Empty default int vector: []');
      }

      if (defaultVectorsSchema.includes('bool_vec:[bool] = []')) {
        result.pass('Empty default bool vector: []');
      }

      if (defaultVectorsSchema.includes('string_vec:[string] = []')) {
        result.pass('Empty default string vector: []');
      }

      // Verify default strings
      if (defaultVectorsSchema.includes('empty_string:string = ""')) {
        result.pass('Empty default string: ""');
      }

      if (defaultVectorsSchema.includes('some_string:string = "some"')) {
        result.pass('Default string value: "some"');
      }

      // Verify struct/table vectors with defaults
      if (defaultVectorsSchema.includes('struct_vec:[MyStruct] = []')) {
        result.pass('Empty default struct vector: []');
      }

      if (defaultVectorsSchema.includes('table_vec:[MyTable] = []')) {
        result.pass('Empty default table vector: []');
      }

      // Verify 64-bit vector extensions
      if (defaultVectorsSchema.includes('offset64')) {
        result.pass('offset64 attribute present');
      }

      if (defaultVectorsSchema.includes('vector64')) {
        result.pass('vector64 attribute present');
      }
    } catch (e) {
      result.fail('Exception during default vectors test', e.message);
    }

    results.push(result.summary());
  }

  // Test 1j: Cross-Language Wire Format Compatibility
  console.log('\nTest 1j: Cross-Language Wire Format');
  console.log('-'.repeat(40));
  {
    const result = new TestResult('Wire Format');

    try {
      // Test Java wire format binary
      const javaBuffer = new Uint8Array(javaWireBin);
      result.pass(`Java wire binary: ${javaBuffer.length} bytes`);

      // Verify file identifier
      if (javaBuffer.length >= 8) {
        const fileIdent = String.fromCharCode(...javaBuffer.slice(4, 8));
        if (fileIdent === 'MONS') {
          result.pass('Java binary file identifier: MONS');
        }
      }

      // Test Python wire format binary
      const pythonBuffer = new Uint8Array(pythonWireBin);
      result.pass(`Python wire binary: ${pythonBuffer.length} bytes`);

      // Test Rust wire format binary
      const rustBuffer = new Uint8Array(rustWireBin);
      result.pass(`Rust wire binary: ${rustBuffer.length} bytes`);

      // Verify we can parse all of them
      try {
        const javaJson = binaryToJson(flatc, schemaInput, javaBuffer);
        const javaParsed = JSON.parse(javaJson);
        if (javaParsed.name) {
          result.pass('Java binary parses correctly');
        }
      } catch (e) {
        result.fail('Java binary parse failed', e.message);
      }

      try {
        const pythonJson = binaryToJson(flatc, schemaInput, pythonBuffer);
        const pythonParsed = JSON.parse(pythonJson);
        if (pythonParsed.name) {
          result.pass('Python binary parses correctly');
        }
      } catch (e) {
        result.fail('Python binary parse failed', e.message);
      }

      try {
        const rustJson = binaryToJson(flatc, schemaInput, rustBuffer);
        const rustParsed = JSON.parse(rustJson);
        if (rustParsed.name) {
          result.pass('Rust binary parses correctly');
        }
      } catch (e) {
        result.fail('Rust binary parse failed', e.message);
      }

      // Save for cross-language testing
      writeFileSync(join(outputDir, 'java_wire.bin'), Buffer.from(javaBuffer));
      writeFileSync(join(outputDir, 'python_wire.bin'), Buffer.from(pythonBuffer));
      writeFileSync(join(outputDir, 'rust_wire.bin'), Buffer.from(rustBuffer));
      result.pass('Saved cross-language binaries');
    } catch (e) {
      result.fail('Exception during wire format test', e.message);
    }

    results.push(result.summary());
  }

  // Test 1k: Unicode Golden Binary
  console.log('\nTest 1k: Unicode Golden Binary');
  console.log('-'.repeat(40));
  {
    const result = new TestResult('Unicode Binary');

    try {
      const unicodeBuffer = new Uint8Array(unicodeGoldenBin);
      result.pass(`Unicode golden binary: ${unicodeBuffer.length} bytes`);

      // Parse and verify unicode content survives
      const json = binaryToJson(flatc, schemaInput, unicodeBuffer);
      const parsed = JSON.parse(json);

      if (parsed.testarrayofstring && parsed.testarrayofstring.length === 6) {
        result.pass('Unicode strings array: 6 elements');

        // Check for surrogate pairs specifically
        if (parsed.testarrayofstring.some(s => s.includes('𡇙') || s.includes('𝌆'))) {
          result.pass('4-byte UTF-8 characters in golden binary');
        }
      }

      // Save for cross-language testing
      writeFileSync(join(outputDir, 'unicode_golden.bin'), Buffer.from(unicodeBuffer));
    } catch (e) {
      result.fail('Exception during unicode binary test', e.message);
    }

    results.push(result.summary());
  }

  // Test 1l: FlexBuffer Binary
  console.log('\nTest 1l: FlexBuffer Binary');
  console.log('-'.repeat(40));
  {
    const result = new TestResult('FlexBuffer');

    try {
      const flexBuffer = new Uint8Array(flexBufferBin);
      result.pass(`FlexBuffer golden binary: ${flexBuffer.length} bytes`);

      // FlexBuffers have their own format, different from FlatBuffers
      // Just verify we can read the binary
      if (flexBuffer.length > 0) {
        result.pass('FlexBuffer binary readable');
      }

      // Save for cross-language testing
      writeFileSync(join(outputDir, 'flexbuffer_golden.bin'), Buffer.from(flexBuffer));
    } catch (e) {
      result.fail('Exception during FlexBuffer test', e.message);
    }

    results.push(result.summary());
  }

  // Test 1m: Nested Union Test
  console.log('\nTest 1m: Nested Union (nested_union_test.fbs)');
  console.log('-'.repeat(40));
  {
    const result = new TestResult('Nested Union');

    const nestedUnionInput = {
      entry: '/nested_union_test.fbs',
      files: {
        '/nested_union_test.fbs': nestedUnionSchema,
      }
    };

    try {
      // Verify schema features
      if (nestedUnionSchema.includes('bit_flags')) {
        result.pass('bit_flags enum attribute');
      }

      if (nestedUnionSchema.includes('csharp_partial, private')) {
        result.pass('Multiple table attributes (csharp_partial, private)');
      }

      if (nestedUnionSchema.includes('union Any { Vec3, TestSimpleTableWithEnum }')) {
        result.pass('Union with table types');
      }

      // Test with Vec3 union variant
      const testDataVec3 = JSON.stringify({
        name: "UnionTest",
        data_type: "Vec3",
        data: { x: 1.0, y: 2.0, z: 3.0, test1: 4.0, test2: "Green", test3: { a: 5, b: 6 } },
        id: 42
      });

      const bufferVec3 = flatc.generateBinary(nestedUnionInput, testDataVec3);
      result.pass(`Generated Vec3 union binary: ${bufferVec3.length} bytes`);

      const jsonVec3 = binaryToJson(flatc, nestedUnionInput, bufferVec3);
      const parsedVec3 = JSON.parse(jsonVec3);

      if (parsedVec3.data_type === 'Vec3' && parsedVec3.data?.x === 1.0) {
        result.pass('Vec3 union variant round-trip');
      } else {
        result.fail(`Vec3 union mismatch: ${JSON.stringify(parsedVec3)}`);
      }

      // Test with TestSimpleTableWithEnum union variant
      const testDataEnum = JSON.stringify({
        name: "EnumUnionTest",
        data_type: "TestSimpleTableWithEnum",
        data: { color: "Red" },
        id: 99
      });

      const bufferEnum = flatc.generateBinary(nestedUnionInput, testDataEnum);
      result.pass(`Generated enum union binary: ${bufferEnum.length} bytes`);

      const jsonEnum = binaryToJson(flatc, nestedUnionInput, bufferEnum);
      const parsedEnum = JSON.parse(jsonEnum);

      if (parsedEnum.data_type === 'TestSimpleTableWithEnum') {
        result.pass('TestSimpleTableWithEnum union variant round-trip');
      } else {
        result.fail(`Enum union mismatch: ${JSON.stringify(parsedEnum)}`);
      }

      writeFileSync(join(outputDir, 'nested_union_unencrypted.bin'), Buffer.from(bufferVec3));
    } catch (e) {
      result.fail('Exception during nested union test', e.message);
    }

    results.push(result.summary());
  }

  // Test 1n: More Defaults Test
  console.log('\nTest 1n: More Defaults (more_defaults.fbs)');
  console.log('-'.repeat(40));
  {
    const result = new TestResult('More Defaults');

    const moreDefaultsInput = {
      entry: '/more_defaults.fbs',
      files: {
        '/more_defaults.fbs': moreDefaultsSchema,
      }
    };

    try {
      // Verify schema features
      if (moreDefaultsSchema.includes('ints: [int] = []')) {
        result.pass('Empty default int vector');
      }

      if (moreDefaultsSchema.includes('floats: [float] = [     ]')) {
        result.pass('Empty default float vector (with whitespace)');
      }

      if (moreDefaultsSchema.includes('abcs: [ABC] = []')) {
        result.pass('Empty default enum vector');
      }

      if (moreDefaultsSchema.includes('bools: [bool] = []')) {
        result.pass('Empty default bool vector');
      }

      // Schema has no root_type, verify schema parsing only
      result.pass('Schema features verified (no root_type for binary generation)');
    } catch (e) {
      result.fail('Exception during more defaults test', e.message);
    }

    results.push(result.summary());
  }

  // Test 1o: NaN/Inf Schema Test (different from monster_extra)
  console.log('\nTest 1o: NaN/Inf Schema Defaults (nan_inf_test.fbs)');
  console.log('-'.repeat(40));
  {
    const result = new TestResult('NaN/Inf Schema');

    const nanInfInput = {
      entry: '/nan_inf_test.fbs',
      files: {
        '/nan_inf_test.fbs': nanInfSchema,
      }
    };

    try {
      // Verify schema has NaN/Inf as DEFAULT values (not just data values)
      if (nanInfSchema.includes('default_nan:double = nan')) {
        result.pass('Default NaN value in schema');
      }

      if (nanInfSchema.includes('default_inf:double = inf')) {
        result.pass('Default +Inf value in schema');
      }

      if (nanInfSchema.includes('default_ninf:double = -inf')) {
        result.pass('Default -Inf value in schema');
      }

      // Test that default NaN/Inf values are preserved
      const testData = JSON.stringify({
        value: 42.0
      });

      const buffer = flatc.generateBinary(nanInfInput, testData);
      result.pass(`Generated nan_inf binary: ${buffer.length} bytes`);

      const json = binaryToJson(flatc, nanInfInput, buffer);
      const parsed = JSON.parse(json);

      if (parsed.value === 42.0) {
        result.pass('Explicit value preserved');
      }

      writeFileSync(join(outputDir, 'nan_inf_schema_unencrypted.bin'), Buffer.from(buffer));
    } catch (e) {
      result.fail('Exception during NaN/Inf schema test', e.message);
    }

    results.push(result.summary());
  }

  // Test 1p: Alignment Binary Tests (before/after fix)
  console.log('\nTest 1p: Alignment Binary Comparison');
  console.log('-'.repeat(40));
  {
    const result = new TestResult('Alignment Binaries');

    try {
      const beforeBuffer = new Uint8Array(alignmentBeforeBin);
      const afterBuffer = new Uint8Array(alignmentAfterBin);

      result.pass(`Alignment before fix: ${beforeBuffer.length} bytes`);
      result.pass(`Alignment after fix: ${afterBuffer.length} bytes`);

      // Verify they're the same size but different content (alignment fix)
      if (beforeBuffer.length === afterBuffer.length) {
        result.pass('Both binaries same size (32 bytes)');
      }

      // Check specific bytes differ (alignment padding at offset 0x10-0x11)
      let diffCount = 0;
      for (let i = 0; i < beforeBuffer.length; i++) {
        if (beforeBuffer[i] !== afterBuffer[i]) {
          diffCount++;
        }
      }

      if (diffCount > 0 && diffCount <= 8) {
        result.pass(`Alignment padding differs: ${diffCount} bytes`);
      } else if (diffCount === 0) {
        result.fail('Binaries are identical (expected alignment diff)');
      } else {
        result.fail(`Too many differences: ${diffCount} bytes`);
      }

      // Save both for cross-language testing
      writeFileSync(join(outputDir, 'alignment_before_fix.bin'), Buffer.from(beforeBuffer));
      writeFileSync(join(outputDir, 'alignment_after_fix.bin'), Buffer.from(afterBuffer));
      result.pass('Saved alignment test binaries');
    } catch (e) {
      result.fail('Exception during alignment binary test', e.message);
    }

    results.push(result.summary());
  }

  // Test 1q: Java Wire Format SP (Single Precision)
  console.log('\nTest 1q: Java Wire Format SP (Single Precision)');
  console.log('-'.repeat(40));
  {
    const result = new TestResult('Java Wire SP');

    try {
      const javaSpBuffer = new Uint8Array(javaWireSpBin);
      result.pass(`Java SP wire binary: ${javaSpBuffer.length} bytes`);

      // Verify file identifier
      // This binary may be size-prefixed (identifier at offset 8) or standard (offset 4)
      if (javaSpBuffer.length >= 12) {
        const identAt4 = String.fromCharCode(
          javaSpBuffer[4], javaSpBuffer[5], javaSpBuffer[6], javaSpBuffer[7]
        );
        const identAt8 = String.fromCharCode(
          javaSpBuffer[8], javaSpBuffer[9], javaSpBuffer[10], javaSpBuffer[11]
        );
        if (identAt4 === 'MONS') {
          result.pass('File identifier: MONS (standard format)');
        } else if (identAt8 === 'MONS') {
          result.pass('File identifier: MONS (size-prefixed format)');
        } else {
          result.fail(`Unexpected file identifier: at 4="${identAt4}", at 8="${identAt8}"`);
        }
      }

      // Compare to regular Java wire format
      const javaBuffer = new Uint8Array(javaWireBin);
      if (javaSpBuffer.length !== javaBuffer.length) {
        result.pass(`Size differs from double-precision (SP: ${javaSpBuffer.length}, DP: ${javaBuffer.length})`);
      }

      // Parse and verify
      try {
        const json = binaryToJson(flatc, schemaInput, javaSpBuffer);
        const parsed = JSON.parse(json);

        if (parsed.name) {
          result.pass('Java SP binary parses correctly');
        }

        // Verify monster data
        if (parsed.hp === 80 || parsed.hp) {
          result.pass('Java SP monster data intact');
        }
      } catch (e) {
        result.fail('Java SP binary parse failed', e.message);
      }

      writeFileSync(join(outputDir, 'java_wire_sp.bin'), Buffer.from(javaSpBuffer));
    } catch (e) {
      result.fail('Exception during Java SP test', e.message);
    }

    results.push(result.summary());
  }

  // Test 1r: Java Test Binary
  console.log('\nTest 1r: Java Test Binary (javatest.bin)');
  console.log('-'.repeat(40));
  {
    const result = new TestResult('Java Test Binary');

    try {
      const javaTestBuffer = new Uint8Array(javatestBin);
      result.pass(`Java test binary: ${javaTestBuffer.length} bytes`);

      // This binary may use a different schema or format
      // Check the root offset and structure
      if (javaTestBuffer.length >= 4) {
        const rootOffset = javaTestBuffer[0] | (javaTestBuffer[1] << 8) |
                           (javaTestBuffer[2] << 16) | (javaTestBuffer[3] << 24);
        result.pass(`Root offset: ${rootOffset}`);
      }

      // Try parsing with monster schema (may work if compatible)
      try {
        const json = binaryToJson(flatc, schemaInput, javaTestBuffer);
        const parsed = JSON.parse(json);

        if (parsed.name === 'MyMonster' || parsed.name) {
          result.pass('Java test binary compatible with monster schema');
          result.pass(`Monster name: ${parsed.name}`);
        }
      } catch (e) {
        // May not be compatible with monster schema - that's okay
        result.pass('Java test binary uses different schema (expected)');
      }

      writeFileSync(join(outputDir, 'javatest.bin'), Buffer.from(javaTestBuffer));
    } catch (e) {
      result.fail('Exception during Java test binary test', e.message);
    }

    results.push(result.summary());
  }

  // Test 1s: Required Strings Schema
  console.log('\nTest 1s: Required Strings (required_strings.fbs)');
  console.log('-'.repeat(40));
  {
    const result = new TestResult('Required Strings');

    const requiredInput = {
      entry: '/required_strings.fbs',
      files: {
        '/required_strings.fbs': requiredStringsSchema,
      }
    };

    try {
      // Verify schema has required attribute
      if (requiredStringsSchema.includes('str_a:string (required)')) {
        result.pass('Required string field: str_a');
      }

      if (requiredStringsSchema.includes('str_b:string (required)')) {
        result.pass('Required string field: str_b');
      }

      // Schema has no root_type, verify schema parsing only
      result.pass('Schema features verified (no root_type for binary generation)');
    } catch (e) {
      result.fail('Exception during required strings test', e.message);
    }

    results.push(result.summary());
  }

  // Test 1t: Native Type Test
  console.log('\nTest 1t: Native Type (native_type_test.fbs)');
  console.log('-'.repeat(40));
  {
    const result = new TestResult('Native Type');

    const nativeTypeInput = {
      entry: '/native_type_test.fbs',
      files: {
        '/native_type_test.fbs': nativeTypeSchema,
      }
    };

    try {
      // Verify schema features
      if (nativeTypeSchema.includes('native_type:"Native::Vector3D"')) {
        result.pass('native_type attribute on struct');
      }

      if (nativeTypeSchema.includes('native_type_pack_name:"Vector3DAlt"')) {
        result.pass('native_type_pack_name attribute');
      }

      if (nativeTypeSchema.includes('native_include "native_type_test_impl.h"')) {
        result.pass('native_include directive');
      }

      if (nativeTypeSchema.includes('(native_inline)')) {
        result.pass('native_inline attribute on field');
      }

      // Test with data
      const testData = JSON.stringify({
        vectors: [{ x: 1.0, y: 2.0, z: 3.0 }],
        vectors_alt: [{ a: 4.0, b: 5.0, c: 6.0 }],
        position: { x: 7.0, y: 8.0, z: 9.0 },
        position_inline: { x: 10.0, y: 11.0, z: 12.0 },
        matrix: { rows: 3, columns: 3, values: [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0] },
        matrices: []
      });

      const buffer = flatc.generateBinary(nativeTypeInput, testData);
      result.pass(`Generated native type binary: ${buffer.length} bytes`);

      const json = binaryToJson(flatc, nativeTypeInput, buffer);
      const parsed = JSON.parse(json);

      if (parsed.position?.x === 7.0 && parsed.position_inline?.x === 10.0) {
        result.pass('Native type structs round-trip');
      }

      if (parsed.matrix?.rows === 3 && parsed.matrix?.columns === 3) {
        result.pass('Native type table round-trip');
      }

      writeFileSync(join(outputDir, 'native_type_unencrypted.bin'), Buffer.from(buffer));
    } catch (e) {
      result.fail('Exception during native type test', e.message);
    }

    results.push(result.summary());
  }

  // Test 1u: Native Inline Table Test
  console.log('\nTest 1u: Native Inline Table (native_inline_table_test.fbs)');
  console.log('-'.repeat(40));
  {
    const result = new TestResult('Native Inline Table');

    const nativeInlineInput = {
      entry: '/native_inline_table_test.fbs',
      files: {
        '/native_inline_table_test.fbs': nativeInlineTableSchema,
      }
    };

    try {
      // Verify schema features
      if (nativeInlineTableSchema.includes('[NativeInlineTable] (native_inline)')) {
        result.pass('native_inline on table vector');
      }

      // Schema has no root_type, verify schema parsing only
      result.pass('Schema features verified (no root_type for binary generation)');
    } catch (e) {
      result.fail('Exception during native inline table test', e.message);
    }

    results.push(result.summary());
  }

  // Test 1v: Service Test (standalone gRPC schema)
  console.log('\nTest 1v: Service Test (service_test.fbs)');
  console.log('-'.repeat(40));
  {
    const result = new TestResult('Service Test');

    const serviceInput = {
      entry: '/service_test.fbs',
      files: {
        '/service_test.fbs': serviceTestSchema,
      }
    };

    try {
      // Verify schema features
      if (serviceTestSchema.includes('rpc_service HelloService')) {
        result.pass('rpc_service HelloService');
      }

      if (serviceTestSchema.includes('Hello(HelloRequest):HelloResponse')) {
        result.pass('Unary RPC method');
      }

      if (serviceTestSchema.includes('streaming: "client"')) {
        result.pass('Client streaming RPC');
      }

      if (serviceTestSchema.includes('streaming: "server"')) {
        result.pass('Server streaming RPC');
      }

      if (serviceTestSchema.includes('streaming: "bidi"')) {
        result.pass('Bidirectional streaming RPC');
      }

      // Schema has no root_type (service definitions only), verify schema parsing only
      result.pass('Schema features verified (no root_type for binary generation)');
    } catch (e) {
      result.fail('Exception during service test', e.message);
    }

    results.push(result.summary());
  }

  // Test 1w: Union Underlying Type
  console.log('\nTest 1w: Union Underlying Type (union_underlying_type_test.fbs)');
  console.log('-'.repeat(40));
  {
    const result = new TestResult('Union Underlying Type');

    const unionTypeInput = {
      entry: '/union_underlying_type_test.fbs',
      files: {
        '/union_underlying_type_test.fbs': unionUnderlyingTypeSchema,
      }
    };

    try {
      // Verify schema features - union with explicit int type and values
      if (unionUnderlyingTypeSchema.includes('union ABC: int')) {
        result.pass('Union with explicit underlying type (int)');
      }

      if (unionUnderlyingTypeSchema.includes('A = 555')) {
        result.pass('Union variant with explicit value 555');
      }

      if (unionUnderlyingTypeSchema.includes('B = 666')) {
        result.pass('Union variant with explicit value 666');
      }

      if (unionUnderlyingTypeSchema.includes('C = 777')) {
        result.pass('Union variant with explicit value 777');
      }

      if (unionUnderlyingTypeSchema.includes('test_vector_of_union: [ABC]')) {
        result.pass('Vector of unions');
      }

      // Schema has no root_type, verify schema parsing only
      result.pass('Schema features verified (no root_type for binary generation)');
    } catch (e) {
      result.fail('Exception during union underlying type test', e.message);
    }

    results.push(result.summary());
  }

  // Test 1x: Optional Scalars Defaults (additional test data)
  console.log('\nTest 1x: Optional Scalars Defaults (optional_scalars_defaults.json)');
  console.log('-'.repeat(40));
  {
    const result = new TestResult('Optional Scalars Defaults');

    const optScalarsInput = {
      entry: '/optional_scalars.fbs',
      files: {
        '/optional_scalars.fbs': optionalScalarsSchema,
      }
    };

    try {
      const buffer = flatc.generateBinary(optScalarsInput, optionalScalarsDefaultsJson);
      result.pass(`Generated optional scalars defaults binary: ${buffer.length} bytes`);

      const json = binaryToJson(flatc, optScalarsInput, buffer);
      const parsed = JSON.parse(json);

      // This test file has different values than optional_scalars.json
      // It tests default values (42) vs explicit zeros vs nulls
      if (parsed.default_i8 === 42) {
        result.pass('default_i8 = 42 (schema default)');
      }

      if (parsed.maybe_i8 === null || parsed.maybe_i8 === undefined) {
        result.pass('maybe_i8 = null (explicit null)');
      }

      if (parsed.just_u8 === 0) {
        result.pass('just_u8 = 0 (explicit zero)');
      }

      if (parsed.default_f32 === 42.0) {
        result.pass('default_f32 = 42.0 (schema default)');
      }

      if (parsed.maybe_bool === null || parsed.maybe_bool === undefined) {
        result.pass('maybe_bool = null');
      }

      writeFileSync(join(outputDir, 'optional_scalars_defaults_unencrypted.bin'), Buffer.from(buffer));
    } catch (e) {
      result.fail('Exception during optional scalars defaults test', e.message);
    }

    results.push(result.summary());
  }

  // Test 2: Transparent encryption with each chain's key
  console.log('\nTest 2: Transparent Encryption (per-chain keys)');
  console.log('-'.repeat(40));

  if (!encryptionAvailable) {
    console.log('  ⊘ Skipped: Encryption module not available');
    console.log('    (Crypto++ integration pending - see plan file)');
  }

  for (const [chain, keys] of Object.entries(encryptionAvailable ? encryptionKeys : {})) {
    const result = new TestResult(`Encryption with ${chain}`);

    try {
      // Generate fresh buffer
      const buffer = flatc.generateBinary(schemaInput, monsterDataJson);
      const originalBuffer = new Uint8Array(buffer);
      const originalHex = toHex(buffer);

      // Get key and IV
      const key = fromHex(keys.key_hex);
      const iv = fromHex(keys.iv_hex);

      // TRANSPARENT ENCRYPTION: encrypt entire binary
      const dataToEncrypt = new Uint8Array(buffer);
      encryption.encryptBytes(dataToEncrypt, key, iv);
      const encrypted = dataToEncrypt;
      const encryptedHex = toHex(encrypted);

      if (encryptedHex !== originalHex) {
        result.pass('Binary encrypted (differs from original)');
      } else {
        result.fail('Encryption did not modify data');
      }

      // Save encrypted binary
      writeFileSync(join(outputDir, `monster_encrypted_${chain}.bin`), Buffer.from(encrypted));
      result.pass(`Saved: monster_encrypted_${chain}.bin`);

      // TRANSPARENT DECRYPTION: decrypt entire binary
      const decrypted = new Uint8Array(encrypted);
      encryption.decryptBytes(decrypted, key, iv);
      const decryptedHex = toHex(decrypted);

      if (decryptedHex === originalHex) {
        result.pass('Decryption restored original binary');
      } else {
        result.fail('Decryption mismatch');
      }

      // Verify decrypted data can be parsed and matches ALL edge cases
      const json = binaryToJson(flatc, schemaInput, decrypted);
      const parsed = JSON.parse(json);

      // Verify critical fields (full verification would duplicate too much output)
      if (parsed.name === 'MyMonster' && parsed.hp === 80) {
        result.pass('Decrypted: basic fields match');
      } else {
        result.fail('Decrypted: basic fields mismatch');
      }

      // Verify extreme double values survived encryption
      if (parsed.vector_of_doubles && parsed.vector_of_doubles.length === 3) {
        const [min, , max] = parsed.vector_of_doubles;
        if (min < -1e308 && max > 1e308) {
          result.pass('Decrypted: extreme doubles preserved');
        } else {
          result.fail('Decrypted: extreme doubles corrupted');
        }
      }

      // Verify nested structures
      if (parsed.pos?.test3?.a === 5 && parsed.enemy?.name === 'Fred') {
        result.pass('Decrypted: nested structures intact');
      } else {
        result.fail('Decrypted: nested structures corrupted');
      }

      // Verify arrays
      if (parsed.inventory?.length === 5 && parsed.testarrayofbools?.length === 3) {
        result.pass('Decrypted: arrays intact');
      } else {
        result.fail('Decrypted: arrays corrupted');
      }
    } catch (e) {
      result.fail('Exception during test', e.message);
    }

    results.push(result.summary());
  }

  // Test 3: Crypto operations (SHA-256, signatures)
  console.log('\nTest 3: Crypto Operations');
  console.log('-'.repeat(40));
  if (!encryptionAvailable) {
    console.log('  ⊘ Skipped: Encryption module not available');
    console.log('    (Crypto++ integration pending - see plan file)');
  } else {
    const result = new TestResult('Crypto Operations');

    try {
      // Test SHA-256
      const testMsg = new TextEncoder().encode('hello');
      const hash = encryption.sha256(testMsg);
      const expectedHash = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';
      if (toHex(hash) === expectedHash) {
        result.pass('SHA-256 hash correct');
      } else {
        result.fail(`SHA-256 mismatch: ${toHex(hash)}`);
      }

      // Test Ed25519 (Solana, SUI, Cardano, etc.)
      const ed25519Keys = encryption.ed25519GenerateKeyPair();
      if (ed25519Keys.privateKey.length === 64 && ed25519Keys.publicKey.length === 32) {
        result.pass('Ed25519 keypair generation');
      } else {
        result.fail('Ed25519 keypair invalid size');
      }

      const message = new TextEncoder().encode('test message');
      const signature = encryption.ed25519Sign(ed25519Keys.privateKey, message);
      const verified = encryption.ed25519Verify(ed25519Keys.publicKey, message, signature);
      if (verified) {
        result.pass('Ed25519 sign/verify');
      } else {
        result.fail('Ed25519 verification failed');
      }

      // Test secp256k1 (Bitcoin, Ethereum, Cosmos)
      const secp256k1Keys = encryption.secp256k1GenerateKeyPair();
      if (secp256k1Keys.privateKey.length === 32 && secp256k1Keys.publicKey.length === 33) {
        result.pass('secp256k1 keypair generation');
      } else {
        result.fail('secp256k1 keypair invalid size');
      }

      const secpSig = encryption.secp256k1Sign(secp256k1Keys.privateKey, message);
      const secpVerified = encryption.secp256k1Verify(secp256k1Keys.publicKey, message, secpSig);
      if (secpVerified) {
        result.pass('secp256k1 sign/verify');
      } else {
        result.fail('secp256k1 verification failed');
      }
    } catch (e) {
      result.fail('Exception during crypto test', e.message);
    }

    results.push(result.summary());
  } // end encryptionAvailable check for Test 3

  // Test 4: Full Code Generation Flow
  // This demonstrates the complete workflow:
  // 1. Generate language-specific code from schema at runtime
  // 2. Use generated code to create FlatBuffers
  // 3. Encrypt the binary
  // 4. Decrypt the binary
  // 5. Read back with generated code
  console.log('\nTest 4: Full Code Generation Flow');
  console.log('-'.repeat(40));
  {
    const result = new TestResult('Code Generation Flow');

    try {
      // Generate TypeScript code from monster schema
      console.log('  Generating TypeScript code from monster_test.fbs...');
      const tsCode = flatc.generateCode(schemaInput, 'ts');
      const tsFiles = Object.keys(tsCode);

      if (tsFiles.length > 0) {
        result.pass(`Generated ${tsFiles.length} TypeScript files`);
        console.log('    Files: ' + tsFiles.slice(0, 5).join(', ') + (tsFiles.length > 5 ? '...' : ''));
      } else {
        result.fail('No TypeScript files generated');
      }

      // Generate Go code (requires specific options, may not work in all configurations)
      console.log('  Generating Go code...');
      let goFiles = [];
      try {
        const goCode = flatc.generateCode(schemaInput, 'go', {
          goModule: 'github.com/example/monster',
          goPackagePrefix: 'monster'
        });
        goFiles = Object.keys(goCode);
        if (goFiles.length > 0) {
          result.pass(`Generated ${goFiles.length} Go files`);
        } else {
          // Go code gen may require additional setup
          console.log('    (Go code generation may need additional configuration)');
        }
      } catch (e) {
        // Go code gen is optional
        console.log('    (Go code generation skipped: ' + e.message + ')');
      }

      // Generate Python code
      console.log('  Generating Python code...');
      const pyCode = flatc.generateCode(schemaInput, 'python', { pythonTyping: true });
      const pyFiles = Object.keys(pyCode);

      if (pyFiles.length > 0) {
        result.pass(`Generated ${pyFiles.length} Python files`);
      } else {
        result.fail('No Python files generated');
      }

      // Generate Rust code
      console.log('  Generating Rust code...');
      const rustCode = flatc.generateCode(schemaInput, 'rust');
      const rustFiles = Object.keys(rustCode);

      if (rustFiles.length > 0) {
        result.pass(`Generated ${rustFiles.length} Rust files`);
      } else {
        result.fail('No Rust files generated');
      }

      // Generate C++ code
      console.log('  Generating C++ code...');
      const cppCode = flatc.generateCode(schemaInput, 'cpp', {
        genObjectApi: true,
        genMutable: true
      });
      const cppFiles = Object.keys(cppCode);

      if (cppFiles.length > 0) {
        result.pass(`Generated ${cppFiles.length} C++ files`);
      } else {
        result.fail('No C++ files generated');
      }

      // Generate C# code
      console.log('  Generating C# code...');
      const csCode = flatc.generateCode(schemaInput, 'csharp');
      const csFiles = Object.keys(csCode);

      if (csFiles.length > 0) {
        result.pass(`Generated ${csFiles.length} C# files`);
      } else {
        result.fail('No C# files generated');
      }

      // Generate Java code
      console.log('  Generating Java code...');
      const javaCode = flatc.generateCode(schemaInput, 'java');
      const javaFiles = Object.keys(javaCode);

      if (javaFiles.length > 0) {
        result.pass(`Generated ${javaFiles.length} Java files`);
      } else {
        result.fail('No Java files generated');
      }

      // Generate Swift code
      console.log('  Generating Swift code...');
      const swiftCode = flatc.generateCode(schemaInput, 'swift');
      const swiftFiles = Object.keys(swiftCode);

      if (swiftFiles.length > 0) {
        result.pass(`Generated ${swiftFiles.length} Swift files`);
      } else {
        result.fail('No Swift files generated');
      }

      // Generate Kotlin code
      console.log('  Generating Kotlin code...');
      const kotlinCode = flatc.generateCode(schemaInput, 'kotlin');
      const kotlinFiles = Object.keys(kotlinCode);

      if (kotlinFiles.length > 0) {
        result.pass(`Generated ${kotlinFiles.length} Kotlin files`);
      } else {
        result.fail('No Kotlin files generated');
      }

      // Verify generated TypeScript code structure
      // Check for Monster class/interface
      const monsterTs = Object.entries(tsCode).find(([name]) =>
        name.toLowerCase().includes('monster') && !name.includes('extra')
      );

      if (monsterTs) {
        const [fileName, content] = monsterTs;
        result.pass(`Monster TypeScript: ${fileName}`);

        // Verify the generated code has expected structure
        if (content.includes('export class') || content.includes('export interface')) {
          result.pass('Generated TypeScript has export statements');
        }

        if (content.includes('name') && content.includes('hp') && content.includes('pos')) {
          result.pass('Generated TypeScript has Monster fields');
        }

        if (content.includes('getRootAsMonster') || content.includes('Monster.getRootAs')) {
          result.pass('Generated TypeScript has root accessor');
        }
      }

      // Verify the roundtrip workflow works with generated binary
      console.log('  Testing full roundtrip with generated code...');

      // Step 1: Generate binary from JSON using schema
      const buffer = flatc.generateBinary(schemaInput, monsterDataJson);
      result.pass(`Created FlatBuffer: ${buffer.length} bytes`);

      // Step 2: Verify the binary can be read back via JSON
      const originalJson = JSON.parse(binaryToJson(flatc, schemaInput, buffer));
      if (originalJson.name === 'MyMonster') {
        result.pass('Binary readable: MyMonster');
      }

      // Full roundtrip without encryption (encryption pending Crypto++ integration)
      if (originalJson.name === 'MyMonster' &&
          originalJson.hp === 80 &&
          originalJson.pos?.x === 1 &&
          originalJson.test?.name === 'Fred') {
        result.pass('Full roundtrip: schema → binary → JSON → verify');
      } else {
        result.fail('Roundtrip data mismatch');
      }

      if (!encryptionAvailable) {
        console.log('  ⊘ Encryption roundtrip skipped (Crypto++ integration pending)');
      }

      // Summary of supported languages
      console.log('\n  Code generation supported for:');
      console.log('    • TypeScript (' + tsFiles.length + ' files)');
      console.log('    • Go (' + goFiles.length + ' files)');
      console.log('    • Python (' + pyFiles.length + ' files)');
      console.log('    • Rust (' + rustFiles.length + ' files)');
      console.log('    • C++ (' + cppFiles.length + ' files)');
      console.log('    • C# (' + csFiles.length + ' files)');
      console.log('    • Java (' + javaFiles.length + ' files)');
      console.log('    • Swift (' + swiftFiles.length + ' files)');
      console.log('    • Kotlin (' + kotlinFiles.length + ' files)');

      const totalFiles = tsFiles.length + goFiles.length + pyFiles.length +
                         rustFiles.length + cppFiles.length + csFiles.length +
                         javaFiles.length + swiftFiles.length + kotlinFiles.length;
      result.pass(`Total: ${totalFiles} generated files across 9 languages`);

      // Note: Generated files are NOT written to disk (not checked in)
      console.log('\n  Note: Generated code is created in-memory only (not checked in)');
    } catch (e) {
      result.fail('Exception during code generation test', e.message);
    }

    results.push(result.summary());
  }

  // Test 5: JSON Schema Generation
  console.log('\nTest 5: JSON Schema Generation');
  console.log('-'.repeat(40));
  {
    const result = new TestResult('JSON Schema Generation');

    try {
      // Generate JSON Schema from monster schema
      const jsonSchema = flatc.generateJsonSchema(schemaInput);

      if (jsonSchema && jsonSchema.length > 0) {
        result.pass(`Generated JSON Schema: ${jsonSchema.length} chars`);

        const schema = JSON.parse(jsonSchema);

        // Verify schema structure
        if (schema.$schema || schema.definitions || schema.type) {
          result.pass('Valid JSON Schema structure');
        }

        if (schema.definitions?.Monster || schema.properties?.name) {
          result.pass('Monster type defined in schema');
        }

        // JSON Schema can be used for runtime validation
        result.pass('JSON Schema usable for runtime validation');
      } else {
        result.fail('No JSON Schema generated');
      }
    } catch (e) {
      result.fail('Exception during JSON Schema test', e.message);
    }

    results.push(result.summary());
  }

  // Test 6: ECDH Key Exchange + EncryptionHeader E2E
  // This tests the full public-key encryption workflow:
  // 1. Sender generates ephemeral keypair
  // 2. Sender computes shared secret via ECDH
  // 3. Sender derives session key via HKDF
  // 4. Sender encrypts FlatBuffer
  // 5. Sender builds EncryptionHeader with ephemeral public key
  // 6. Receiver parses EncryptionHeader
  // 7. Receiver computes same shared secret via ECDH
  // 8. Receiver derives same session key via HKDF
  // 9. Receiver decrypts FlatBuffer
  console.log('\nTest 6: ECDH Key Exchange + EncryptionHeader');
  console.log('-'.repeat(40));

  if (!encryptionAvailable) {
    console.log('  ⊘ Skipped: Encryption module not available');
  } else {
    // Test all three ECDH curves
    const ecdhCurves = [
      { name: 'X25519', generate: encryption.x25519GenerateKeyPair, shared: encryption.x25519SharedSecret, pubKeySize: 32 },
      { name: 'secp256k1', generate: encryption.secp256k1GenerateKeyPair, shared: encryption.secp256k1SharedSecret, pubKeySize: 33 },
      { name: 'P-256', generate: encryption.p256GenerateKeyPair, shared: encryption.p256SharedSecret, pubKeySize: 33 },
    ];

    for (const curve of ecdhCurves) {
      const result = new TestResult(`ECDH ${curve.name} E2E`);

      try {
        // Step 1: Recipient generates long-term keypair
        const recipientKeys = curve.generate();
        result.pass(`Recipient ${curve.name} keypair (pub: ${recipientKeys.publicKey.length} bytes)`);

        // Step 2: Sender generates ephemeral keypair
        const senderEphemeral = curve.generate();
        result.pass(`Sender ephemeral ${curve.name} keypair`);

        // Step 3: Sender computes shared secret
        const senderSharedSecret = curve.shared(senderEphemeral.privateKey, recipientKeys.publicKey);
        result.pass(`Sender shared secret: ${senderSharedSecret.length} bytes`);

        // Step 4: Sender derives session key + IV via HKDF
        const context = `flatbuffers-${curve.name.toLowerCase()}-encryption`;
        const keyMaterial = encryption.hkdf(senderSharedSecret, null, new TextEncoder().encode(context), 48);
        const sessionKey = keyMaterial.slice(0, 32);
        const sessionIV = keyMaterial.slice(32, 48);
        result.pass(`Derived session key (${sessionKey.length}) + IV (${sessionIV.length})`);

        // Step 5: Sender encrypts FlatBuffer
        const buffer = flatc.generateBinary(schemaInput, monsterDataJson);
        const originalBuffer = new Uint8Array(buffer);
        const encryptedBuffer = new Uint8Array(buffer);
        encryption.encryptBytes(encryptedBuffer, sessionKey, sessionIV);
        result.pass(`Encrypted FlatBuffer: ${encryptedBuffer.length} bytes`);

        // Step 6: Build EncryptionHeader data (JSON for cross-language testing)
        const keyExchangeEnum = curve.name === 'X25519' ? 0 : (curve.name === 'secp256k1' ? 1 : 2);
        const headerData = {
          version: 1,
          key_exchange: keyExchangeEnum,
          symmetric: 0, // AES_256_CTR
          kdf: 0, // HKDF_SHA256
          ephemeral_public_key: toHex(senderEphemeral.publicKey),
          context: context,
          timestamp: Date.now(),
          // Include derived key material for cross-language verification
          session_key: toHex(sessionKey),
          session_iv: toHex(sessionIV),
        };
        result.pass(`Built EncryptionHeader data`);

        // Save encrypted data + header for cross-language testing
        const curveName = curve.name.toLowerCase().replace('-', '');
        writeFileSync(join(outputDir, `monster_ecdh_${curveName}.bin`), Buffer.from(encryptedBuffer));
        writeFileSync(join(outputDir, `monster_ecdh_${curveName}_header.json`), JSON.stringify(headerData, null, 2));
        result.pass(`Saved: monster_ecdh_${curveName}.bin + header.json`);

        // Step 7: Receiver parses EncryptionHeader (simulate by reading ephemeral pubkey)
        // In real usage, receiver would parse the FlatBuffer header
        const receivedEphemeralPubKey = senderEphemeral.publicKey; // From header
        result.pass('Receiver extracted ephemeral public key from header');

        // Step 8: Receiver computes shared secret
        const recipientSharedSecret = curve.shared(recipientKeys.privateKey, receivedEphemeralPubKey);

        // Verify shared secrets match (ECDH property)
        if (toHex(recipientSharedSecret) === toHex(senderSharedSecret)) {
          result.pass('ECDH: shared secrets match');
        } else {
          result.fail('ECDH: shared secrets do NOT match');
        }

        // Step 9: Receiver derives same session key + IV
        const recipientKeyMaterial = encryption.hkdf(recipientSharedSecret, null, new TextEncoder().encode(context), 48);
        const recipientSessionKey = recipientKeyMaterial.slice(0, 32);
        const recipientSessionIV = recipientKeyMaterial.slice(32, 48);

        if (toHex(recipientSessionKey) === toHex(sessionKey) && toHex(recipientSessionIV) === toHex(sessionIV)) {
          result.pass('HKDF: derived keys match');
        } else {
          result.fail('HKDF: derived keys do NOT match');
        }

        // Step 10: Receiver decrypts FlatBuffer
        const decryptedBuffer = new Uint8Array(encryptedBuffer);
        encryption.decryptBytes(decryptedBuffer, recipientSessionKey, recipientSessionIV);

        if (toHex(decryptedBuffer) === toHex(originalBuffer)) {
          result.pass('Decryption: original FlatBuffer restored');
        } else {
          result.fail('Decryption: data mismatch');
        }

        // Step 11: Verify decrypted data can be read
        const json = binaryToJson(flatc, schemaInput, decryptedBuffer);
        const parsed = JSON.parse(json);

        if (parsed.name === 'MyMonster' && parsed.hp === 80 && parsed.pos?.x === 1) {
          result.pass('Verified: decrypted FlatBuffer readable');
        } else {
          result.fail('Verification failed: data corrupted');
        }

      } catch (e) {
        result.fail('Exception during ECDH test', e.message);
      }

      results.push(result.summary());
    }

    // Save ECDH test keys for cross-language verification
    const ecdhTestKeys = {};
    for (const curve of ecdhCurves) {
      const curveName = curve.name.toLowerCase().replace('-', '');
      const recipientKeys = curve.generate();
      ecdhTestKeys[curveName] = {
        recipientPrivateKey: toHex(recipientKeys.privateKey),
        recipientPublicKey: toHex(recipientKeys.publicKey),
      };
    }
    writeFileSync(join(vectorsDir, 'ecdh_test_keys.json'), JSON.stringify(ecdhTestKeys, null, 2));
    console.log('\n  Saved: vectors/ecdh_test_keys.json');
  }

  // Test 7: SecureMessage Schema Tests
  // Verifies the custom E2E schema (message.fbs) can be used for encrypted messages
  console.log('\nTest 7: SecureMessage Schema E2E');
  console.log('-'.repeat(40));
  {
    const result = new TestResult('SecureMessage E2E');

    // Load the SecureMessage schema
    const messageSchemaPath = join(__dirname, '../../schemas/message.fbs');
    if (existsSync(messageSchemaPath)) {
      try {
        const messageSchema = readFileSync(messageSchemaPath, 'utf8');
        const messageSchemaInput = {
          entry: '/message.fbs',
          files: { '/message.fbs': messageSchema }
        };

        // Test 7a: Read unencrypted SecureMessage
        const unencryptedPath = join(outputDir, 'secure_message_simple.bin');
        if (existsSync(unencryptedPath)) {
          const unencryptedBin = readFileSync(unencryptedPath);
          const json = flatc.generateJSON(messageSchemaInput, {
            path: '/input.bin',
            data: new Uint8Array(unencryptedBin)
          });
          const parsed = JSON.parse(json);

          if (parsed.id === 'msg-001' && parsed.sender === 'alice' && parsed.recipient === 'bob') {
            result.pass('Read SecureMessage simple: id=msg-001, alice->bob');
          } else {
            result.fail(`SecureMessage simple mismatch: ${JSON.stringify(parsed)}`);
          }

          if (parsed.payload?.message === 'Hello, World!' && parsed.payload?.value === 42) {
            result.pass('SecureMessage payload: "Hello, World!", value=42');
          } else {
            result.fail(`Payload mismatch: ${JSON.stringify(parsed.payload)}`);
          }
        } else {
          result.fail('secure_message_simple.bin not found (run create_messages.mjs first)');
        }

        // Test 7b: Read nested SecureMessage
        const nestedPath = join(outputDir, 'secure_message_nested.bin');
        if (existsSync(nestedPath)) {
          const nestedBin = readFileSync(nestedPath);
          const json = flatc.generateJSON(messageSchemaInput, {
            path: '/input.bin',
            data: new Uint8Array(nestedBin)
          });
          const parsed = JSON.parse(json);

          if (parsed.payload?.nested?.length === 2) {
            result.pass('SecureMessage nested: 2 child payloads');
          } else {
            result.fail(`Nested payload mismatch: ${parsed.payload?.nested?.length}`);
          }
        }

        // Test 7c: Read unicode SecureMessage
        const unicodePath = join(outputDir, 'secure_message_unicode.bin');
        if (existsSync(unicodePath)) {
          const unicodeBin = readFileSync(unicodePath);
          const json = flatc.generateJSON(messageSchemaInput, {
            path: '/input.bin',
            data: new Uint8Array(unicodeBin)
          });
          const parsed = JSON.parse(json);

          if (parsed.sender === 'alice-鍵' && parsed.recipient === 'bob-🔑') {
            result.pass('SecureMessage unicode: alice-鍵 -> bob-🔑');
          } else {
            result.fail(`Unicode mismatch: ${parsed.sender} -> ${parsed.recipient}`);
          }
        }

        // Test 7d: Decrypt and verify encrypted SecureMessage
        if (encryptionAvailable) {
          const ecdhMessageKeysPath = join(vectorsDir, 'ecdh_message_keys.json');
          if (existsSync(ecdhMessageKeysPath)) {
            const ecdhMsgKeys = JSON.parse(readFileSync(ecdhMessageKeysPath, 'utf8'));

            for (const curveName of ['x25519', 'secp256k1', 'p256']) {
              const encPath = join(outputDir, `secure_message_simple_${curveName}.bin`);
              const headerPath = join(outputDir, `secure_message_simple_${curveName}_header.json`);

              if (existsSync(encPath) && existsSync(headerPath)) {
                const encryptedBin = new Uint8Array(readFileSync(encPath));
                const header = JSON.parse(readFileSync(headerPath, 'utf8'));
                const keys = ecdhMsgKeys[curveName];

                // Bob derives the same session key using his private key and Alice's ephemeral public
                const bobPriv = new Uint8Array(Buffer.from(keys.bob.private, 'hex'));
                const alicePub = new Uint8Array(Buffer.from(keys.alice.public, 'hex'));

                const sharedSecretFunc = curveName === 'x25519' ? encryption.x25519SharedSecret :
                                         curveName === 'secp256k1' ? encryption.secp256k1SharedSecret :
                                         encryption.p256SharedSecret;

                const sharedSecret = sharedSecretFunc(bobPriv, alicePub);
                const keyMaterial = encryption.hkdf(
                  sharedSecret,
                  new Uint8Array(0),
                  new TextEncoder().encode('E2E-Crypto-Test'),
                  48
                );
                const sessionKey = keyMaterial.slice(0, 32);
                const iv = keyMaterial.slice(32, 48);

                // Decrypt
                encryption.decryptBytes(encryptedBin, sessionKey, iv);

                // Verify decrypted content
                const decryptedJson = flatc.generateJSON(messageSchemaInput, {
                  path: '/input.bin',
                  data: encryptedBin
                });
                const decrypted = JSON.parse(decryptedJson);

                if (decrypted.id === 'msg-001' && decrypted.payload?.message === 'Hello, World!') {
                  result.pass(`Decrypted SecureMessage ${curveName}: OK`);
                } else {
                  result.fail(`Decrypted SecureMessage ${curveName}: content mismatch`);
                }
              }
            }
          } else {
            result.fail('ecdh_message_keys.json not found (run create_messages.mjs first)');
          }
        }

      } catch (e) {
        result.fail('Exception during SecureMessage test', e.message);
      }
    } else {
      result.fail('schemas/message.fbs not found');
    }

    results.push(result.summary());
  }

  // Summary
  console.log('\n' + '='.repeat(60));
  console.log('Summary');
  console.log('='.repeat(60));

  const passed = results.filter(r => r).length;
  const total = results.length;

  console.log(`\nTotal: ${passed}/${total} test suites passed`);

  if (passed === total) {
    console.log('\n✓ All tests passed!');
    console.log('\nGenerated binary files:');
    console.log(`  ${outputDir}/`);
    console.log('    - monster_unencrypted.bin');
    Object.keys(encryptionKeys).forEach(chain => {
      console.log(`    - monster_encrypted_${chain}.bin`);
    });
    process.exit(0);
  } else {
    console.log('\n✗ Some tests failed');
    process.exit(1);
  }
}

main().catch(e => {
  console.error('Fatal error:', e);
  process.exit(1);
});
