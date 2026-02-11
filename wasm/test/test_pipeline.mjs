/**
 * Tests for FlatBufferPipeline - the unified API
 *
 * Tests format detection integration, schema management, format conversion,
 * streaming, code generation, and HE encryption (with mocks where HE WASM
 * is not available).
 */

import { FlatBufferPipeline } from "../src/pipeline.mjs";
import { detectFormat, detectStringFormat } from "../src/format-detector.mjs";
import {
  identifyHEFields,
  generateCompanionSchema,
} from "../src/he-field-encryptor.mjs";

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${name}`);
    console.log(`    Error: ${e.message}`);
    failed++;
  }
}

async function testAsync(name, fn) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${name}`);
    console.log(`    Error: ${e.message}`);
    failed++;
  }
}

function assertEqual(actual, expected, msg) {
  if (actual !== expected) {
    throw new Error(`${msg}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

function assertContains(str, substr, msg) {
  if (!str.includes(substr)) {
    throw new Error(`${msg}: expected to contain "${substr}"`);
  }
}

function assertInstanceOf(obj, cls, msg) {
  if (!(obj instanceof cls)) {
    throw new Error(`${msg}: expected instance of ${cls.name}`);
  }
}

function assertTrue(val, msg) {
  if (!val) {
    throw new Error(`${msg}: expected truthy value`);
  }
}

// Test schemas
const monsterSchema = `
namespace MyGame.Sample;

enum Color:byte { Red = 0, Green, Blue = 2 }

union Equipment { Weapon }

struct Vec3 {
  x:float;
  y:float;
  z:float;
}

table Monster {
  pos:Vec3;
  mana:short = 150;
  hp:short = 100;
  name:string;
  friendly:bool = false (deprecated);
  inventory:[ubyte];
  color:Color = Blue;
  weapons:[Weapon];
  equipped:Equipment;
  path:[Vec3];
}

table Weapon {
  name:string;
  damage:short;
}

root_type Monster;
`;

const monsterJson = JSON.stringify({
  pos: { x: 1.0, y: 2.0, z: 3.0 },
  mana: 200,
  hp: 300,
  name: "Orc",
  inventory: [0, 1, 2, 3, 4],
  color: "Red",
  weapons: [
    { name: "Sword", damage: 50 },
    { name: "Axe", damage: 60 },
  ],
  equipped_type: "Weapon",
  equipped: { name: "Sword", damage: 50 },
  path: [
    { x: 0.0, y: 0.0, z: 0.0 },
    { x: 1.0, y: 1.0, z: 1.0 },
  ],
});

const sensorSchema = `
table SensorReading {
  timestamp:long;
  temperature:double;
  humidity:float;
  pressure:int;
  name:string;
}

root_type SensorReading;
`;

const sensorJson = JSON.stringify({
  timestamp: 1000000,
  temperature: 22.5,
  humidity: 0.65,
  pressure: 1013,
  name: "sensor-1",
});

const schemaInput = { contents: monsterSchema };
const sensorSchemaInput = { contents: sensorSchema };

console.log("\n=== FlatBufferPipeline Tests ===\n");

// =========================================================================
// Pipeline creation
// =========================================================================
console.log("1. Pipeline creation and initialization:");

let pipeline;

await testAsync("create() initializes pipeline", async () => {
  pipeline = await FlatBufferPipeline.create();
  assertTrue(pipeline !== null, "pipeline created");
  assertTrue(pipeline.getRunner() !== null, "runner available");
});

await testAsync("create() with schema option", async () => {
  const p = await FlatBufferPipeline.create({ schema: schemaInput });
  assertEqual(p.getSchemaSource(), monsterSchema, "schema set");
  p.destroy();
});

await testAsync("create() with streaming option (graceful if no WASM dispatcher)", async () => {
  const p = await FlatBufferPipeline.create({ streaming: true });
  // Dispatcher may be null if WASM module doesn't have dispatcher exports
  // This is expected in builds without streaming support compiled in
  assertTrue(p !== null, "pipeline created");
  p.destroy();
});

// =========================================================================
// Schema management
// =========================================================================
console.log("\n2. Schema management:");

test("setSchema sets schema", () => {
  pipeline.setSchema(schemaInput);
  assertEqual(pipeline.getSchemaSource(), monsterSchema, "schema source matches");
});

test("setSchema returns pipeline for chaining", () => {
  const result = pipeline.setSchema(schemaInput);
  assertEqual(result, pipeline, "returns this");
});

test("setSchema throws on null", () => {
  let threw = false;
  try {
    pipeline.setSchema(null);
  } catch (e) {
    threw = true;
    assertContains(e.message, 'required', "error message");
  }
  assertEqual(threw, true, "threw on null schema");
});

// =========================================================================
// Format conversion: toBinary
// =========================================================================
console.log("\n3. toBinary:");

test("toBinary converts JSON string to binary", () => {
  pipeline.setSchema(schemaInput);
  const binary = pipeline.toBinary(monsterJson);
  assertInstanceOf(binary, Uint8Array, "returns Uint8Array");
  assertTrue(binary.length > 0, "binary has content");
});

test("toBinary converts JSON object to binary", () => {
  pipeline.setSchema(schemaInput);
  const binary = pipeline.toBinary(JSON.parse(monsterJson));
  assertInstanceOf(binary, Uint8Array, "returns Uint8Array");
  assertTrue(binary.length > 0, "binary has content");
});

test("toBinary passes through FlatBuffer binary", () => {
  pipeline.setSchema(schemaInput);
  const binary = pipeline.toBinary(monsterJson);
  const result = pipeline.toBinary(binary);
  // Should return the same binary since it's already in FlatBuffer format
  assertInstanceOf(result, Uint8Array, "returns Uint8Array");
  assertEqual(result.length, binary.length, "same length");
});

test("toBinary converts JSON bytes", () => {
  pipeline.setSchema(schemaInput);
  const jsonBytes = new TextEncoder().encode(monsterJson);
  const binary = pipeline.toBinary(jsonBytes);
  assertInstanceOf(binary, Uint8Array, "returns Uint8Array");
  assertTrue(binary.length > 0, "binary has content");
});

test("toBinary throws without schema", () => {
  const p = new FlatBufferPipeline(pipeline.getRunner());
  let threw = false;
  try {
    p.toBinary(monsterJson);
  } catch (e) {
    threw = true;
    assertContains(e.message, 'Schema required', "error message");
  }
  assertEqual(threw, true, "threw without schema");
});

// =========================================================================
// Format conversion: toJSON
// =========================================================================
console.log("\n4. toJSON:");

test("toJSON converts binary to JSON string", () => {
  pipeline.setSchema(schemaInput);
  const binary = pipeline.toBinary(monsterJson);
  const json = pipeline.toJSON(binary);
  assertEqual(typeof json, 'string', "returns string");
  assertContains(json, 'Orc', "contains monster name");
});

test("toJSON passes through JSON string", () => {
  pipeline.setSchema(schemaInput);
  const result = pipeline.toJSON(monsterJson);
  assertEqual(result, monsterJson, "passes through JSON");
});

test("toJSON roundtrip preserves data", () => {
  pipeline.setSchema(schemaInput);
  const binary = pipeline.toBinary(monsterJson);
  const json = pipeline.toJSON(binary);
  const parsed = JSON.parse(json);
  assertEqual(parsed.name, 'Orc', "name preserved");
  assertEqual(parsed.hp, 300, "hp preserved");
  assertEqual(parsed.mana, 200, "mana preserved");
});

// =========================================================================
// Streaming
// =========================================================================
console.log("\n5. Streaming:");

test("pushStream creates dispatcher on demand or throws if no WASM support", () => {
  const p = new FlatBufferPipeline(pipeline.getRunner());
  p.setSchema(schemaInput);
  assertEqual(p.getDispatcher(), null, "no dispatcher initially");

  // Push some binary data - may throw if WASM dispatcher not compiled in
  const binary = pipeline.toBinary(monsterJson);
  try {
    p.pushStream(binary);
    assertTrue(p.getDispatcher() !== null, "dispatcher created on demand");
  } catch (e) {
    // Expected if WASM module doesn't have dispatcher exports
    assertTrue(e.message.includes('dispatcher'), "error mentions dispatcher");
  }
  p.destroy();
});

// =========================================================================
// Code generation
// =========================================================================
console.log("\n6. Code generation:");

test("generateCode generates TypeScript", () => {
  pipeline.setSchema(schemaInput);
  const code = pipeline.generateCode('ts');
  assertEqual(typeof code, 'object', "returns object");
  const files = Object.keys(code);
  assertTrue(files.length > 0, "has output files");
  const content = Object.values(code).join('\n');
  assertContains(content, 'Monster', "has Monster");
});

test("generateCode generates Python", () => {
  pipeline.setSchema(schemaInput);
  const code = pipeline.generateCode('python');
  const content = Object.values(code).join('\n');
  assertContains(content, 'Monster', "has Monster");
});

test("generateCode generates C++", () => {
  pipeline.setSchema(schemaInput);
  const code = pipeline.generateCode('cpp');
  const content = Object.values(code).join('\n');
  assertContains(content, 'Monster', "has Monster");
});

test("generateCode throws without schema", () => {
  const p = new FlatBufferPipeline(pipeline.getRunner());
  let threw = false;
  try {
    p.generateCode('ts');
  } catch (e) {
    threw = true;
  }
  assertEqual(threw, true, "threw without schema");
});

// =========================================================================
// Key management
// =========================================================================
console.log("\n7. Key management:");

test("setKeyManager returns pipeline for chaining", () => {
  const mockManager = { deriveEncryptionKey: () => {} };
  const result = pipeline.setKeyManager(mockManager);
  assertEqual(result, pipeline, "returns this");
});

test("setHEContext returns pipeline for chaining", () => {
  const mockCtx = { canDecrypt: () => true };
  const result = pipeline.setHEContext(mockCtx);
  assertEqual(result, pipeline, "returns this");
  assertEqual(pipeline.getHEContext(), mockCtx, "context stored");
});

test("deriveHEContext throws without key manager", async () => {
  const p = new FlatBufferPipeline(pipeline.getRunner());
  let threw = false;
  try {
    await p.deriveHEContext();
  } catch (e) {
    threw = true;
    assertContains(e.message, 'key manager', "error message");
  }
  assertEqual(threw, true, "threw without key manager");
});

// =========================================================================
// HE encryption (validation only, requires HE WASM for full test)
// =========================================================================
console.log("\n8. HE encryption (validation):");

test("encryptHE throws without schema", () => {
  const p = new FlatBufferPipeline(pipeline.getRunner());
  p.setHEContext({ canDecrypt: () => true });
  let threw = false;
  try {
    p.encryptHE('{"hp":100}');
  } catch (e) {
    threw = true;
    assertContains(e.message, 'Schema required', "error message");
  }
  assertEqual(threw, true, "threw without schema");
});

test("encryptHE throws without HE context", () => {
  pipeline.setSchema(sensorSchemaInput);
  pipeline.setHEContext(null);
  let threw = false;
  try {
    pipeline.encryptHE(sensorJson, { fields: ['temperature'] });
  } catch (e) {
    threw = true;
    assertContains(e.message, 'HE context', "error message");
  }
  assertEqual(threw, true, "threw without HE context");
});

test("decryptHE throws with server context", () => {
  pipeline.setSchema(sensorSchemaInput);
  pipeline.setHEContext({ canDecrypt: () => false });
  let threw = false;
  try {
    pipeline.decryptHE(new Uint8Array(8));
  } catch (e) {
    threw = true;
    assertContains(e.message, 'client', "error message");
  }
  assertEqual(threw, true, "threw with server context");
});

// =========================================================================
// Companion schema
// =========================================================================
console.log("\n9. Companion schema:");

test("getCompanionSchema generates companion for sensor schema", () => {
  pipeline.setSchema(sensorSchemaInput);
  const companion = pipeline.getCompanionSchema({ fields: ['temperature', 'pressure'] });
  assertEqual(typeof companion, 'string', "returns string");
  assertContains(companion, 'temperature:[ubyte]', "temperature replaced");
  assertContains(companion, 'pressure:[ubyte]', "pressure replaced");
  assertContains(companion, 'name:string', "name unchanged");
  assertContains(companion, 'timestamp:long', "timestamp unchanged");
});

test("getCompanionSchema preserves schema structure", () => {
  pipeline.setSchema(sensorSchemaInput);
  const companion = pipeline.getCompanionSchema({ fields: ['temperature'] });
  assertContains(companion, 'table SensorReading', "table preserved");
  assertContains(companion, 'root_type SensorReading', "root_type preserved");
});

// =========================================================================
// Multi-schema workflow
// =========================================================================
console.log("\n10. Multi-schema workflow:");

test("switching schemas clears cached companion schema", () => {
  pipeline.setSchema(sensorSchemaInput);
  const comp1 = pipeline.getCompanionSchema({ fields: ['temperature'] });
  assertContains(comp1, 'temperature:[ubyte]', "first companion");

  pipeline.setSchema(schemaInput);
  // Getting companion for different schema should work
  const comp2 = pipeline.getCompanionSchema({ fields: ['hp', 'mana'] });
  assertContains(comp2, 'hp:[ubyte]', "second companion");
  assertContains(comp2, 'mana:[ubyte]', "second companion");
});

test("full JSON→binary→JSON roundtrip via pipeline", () => {
  pipeline.setSchema(sensorSchemaInput);
  const binary = pipeline.toBinary(sensorJson);
  assertInstanceOf(binary, Uint8Array, "binary created");
  assertTrue(binary.length > 0, "binary has content");

  const json = pipeline.toJSON(binary);
  const parsed = JSON.parse(json);
  assertEqual(parsed.name, 'sensor-1', "name roundtripped");
  assertEqual(parsed.pressure, 1013, "pressure roundtripped");
});

// =========================================================================
// Destroy
// =========================================================================
console.log("\n11. Cleanup:");

test("destroy clears all state", () => {
  pipeline.setSchema(sensorSchemaInput);
  pipeline.setHEContext({ canDecrypt: () => true, destroy: () => {} });
  pipeline.destroy();

  assertEqual(pipeline.getSchemaSource(), null, "schema cleared");
  assertEqual(pipeline.getHEContext(), null, "HE context cleared");
  assertEqual(pipeline.getKeyManager(), null, "key manager cleared");
});

// =========================================================================
// Integration: format detector + pipeline
// =========================================================================
console.log("\n12. Format detection integration:");

await testAsync("pipeline handles format detection end-to-end", async () => {
  const p = await FlatBufferPipeline.create({ schema: sensorSchemaInput });

  // JSON string → binary
  const binary = p.toBinary(sensorJson);
  assertEqual(detectFormat(binary), 'flatbuffer', "binary detected as flatbuffer");

  // Binary → JSON
  const jsonResult = p.toJSON(binary);
  const jsonBytes = new TextEncoder().encode(jsonResult);
  assertEqual(detectFormat(jsonBytes), 'json', "JSON bytes detected as json");

  // JSON bytes → binary (auto-detected)
  const binary2 = p.toBinary(jsonBytes);
  assertInstanceOf(binary2, Uint8Array, "converted from JSON bytes");
  assertTrue(binary2.length > 0, "has content");

  p.destroy();
});

// =========================================================================
// Summary
// =========================================================================
console.log("\n=== Test Summary ===");
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log(`Total:  ${passed + failed}`);

if (failed > 0) {
  process.exit(1);
}

process.exit(0);
