/**
 * Tests for FlatcRunner - the CLI wrapper functionality
 */

import { FlatcRunner } from "../src/runner.mjs";

let runner;
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

function assertEqual(actual, expected, msg) {
  if (actual !== expected) {
    throw new Error(`${msg}: expected ${expected}, got ${actual}`);
  }
}

function assertContains(str, substr, msg) {
  if (!str.includes(substr)) {
    throw new Error(`${msg}: expected to contain "${substr}" but got "${str}"`);
  }
}

function assertInstanceOf(obj, cls, msg) {
  if (!(obj instanceof cls)) {
    throw new Error(`${msg}: expected instance of ${cls.name}`);
  }
}

// Test schema
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

const monsterJson = `{
  "pos": { "x": 1.0, "y": 2.0, "z": 3.0 },
  "mana": 200,
  "hp": 300,
  "name": "Orc",
  "inventory": [0, 1, 2, 3, 4],
  "color": "Red",
  "weapons": [
    { "name": "Sword", "damage": 50 },
    { "name": "Axe", "damage": 60 }
  ],
  "equipped_type": "Weapon",
  "equipped": { "name": "Sword", "damage": 50 },
  "path": [
    { "x": 0.0, "y": 0.0, "z": 0.0 },
    { "x": 1.0, "y": 1.0, "z": 1.0 }
  ]
}`;

console.log("\n=== FlatcRunner Tests ===\n");

// Initialize the runner
console.log("Initializing FlatcRunner...");
runner = await FlatcRunner.init();
console.log("FlatcRunner initialized successfully.\n");

// Test: Basic functionality
console.log("1. Basic CLI functionality:");

test("runCommand returns result object", () => {
  const result = runner.runCommand(["--version"]);
  assertEqual(typeof result.code, "number", "code type");
  assertEqual(typeof result.stdout, "string", "stdout type");
  assertEqual(typeof result.stderr, "string", "stderr type");
});

test("version() returns version string", () => {
  const version = runner.version();
  assertContains(version, "flatc version", "version output");
});

test("help() returns help text", () => {
  const help = runner.help();
  assertContains(help, "--binary", "help contains --binary");
  assertContains(help, "--json", "help contains --json");
  assertContains(help, "--cpp", "help contains --cpp");
});

// Test: File system operations
console.log("\n2. Virtual filesystem operations:");

test("mountFile creates file", () => {
  runner.mountFile("/test/hello.txt", "Hello, World!");
  const content = runner.readFile("/test/hello.txt", { encoding: "utf8" });
  assertEqual(content, "Hello, World!", "file content");
});

test("mountFiles creates multiple files", () => {
  runner.mountFiles([
    { path: "/multi/a.txt", data: "File A" },
    { path: "/multi/b.txt", data: "File B" },
  ]);
  const a = runner.readFile("/multi/a.txt", { encoding: "utf8" });
  const b = runner.readFile("/multi/b.txt", { encoding: "utf8" });
  assertEqual(a, "File A", "file a content");
  assertEqual(b, "File B", "file b content");
});

test("readdir lists files", () => {
  const files = runner.readdir("/multi");
  assertEqual(files.includes("a.txt"), true, "has a.txt");
  assertEqual(files.includes("b.txt"), true, "has b.txt");
});

test("listAllFiles recursively lists files", () => {
  runner.mountFile("/deep/level1/level2/file.txt", "deep file");
  const files = runner.listAllFiles("/deep");
  assertEqual(files.length >= 1, true, "has files");
  assertEqual(files.some(f => f.includes("file.txt")), true, "found deep file");
});

// Test: Schema operations
console.log("\n3. Schema compilation:");

const schemaInput = {
  entry: "/schemas/monster.fbs",
  files: {
    "/schemas/monster.fbs": monsterSchema,
  },
};

test("generateBinary converts JSON to binary", () => {
  const binary = runner.generateBinary(schemaInput, monsterJson);
  assertInstanceOf(binary, Uint8Array, "binary type");
  assertEqual(binary.length > 0, true, "binary has content");
});

test("generateJSON converts binary to JSON", () => {
  const binary = runner.generateBinary(schemaInput, monsterJson);
  const json = runner.generateJSON(schemaInput, {
    path: "/test/monster.bin",
    data: binary,
  });
  assertEqual(typeof json, "string", "json type");
  assertContains(json, "Orc", "json contains monster name");
  assertContains(json, "Sword", "json contains weapon name");
});

test("generateJSON roundtrip preserves data", () => {
  const binary = runner.generateBinary(schemaInput, monsterJson);
  const json = runner.generateJSON(schemaInput, {
    path: "/test/monster.bin",
    data: binary,
  });
  const parsed = JSON.parse(json);
  assertEqual(parsed.name, "Orc", "name preserved");
  assertEqual(parsed.mana, 200, "mana preserved");
  assertEqual(parsed.hp, 300, "hp preserved");
  assertEqual(parsed.weapons.length, 2, "weapons preserved");
});

// Test: Code generation
console.log("\n4. Code generation:");

test("generateCode generates TypeScript", () => {
  const code = runner.generateCode(schemaInput, "ts");
  assertEqual(typeof code, "object", "code is object");
  const files = Object.keys(code);
  assertEqual(files.length > 0, true, "has output files");
  const content = Object.values(code).join("\n");
  assertContains(content, "Monster", "has Monster class");
});

test("generateCode generates Python", () => {
  const code = runner.generateCode(schemaInput, "python");
  const files = Object.keys(code);
  assertEqual(files.length > 0, true, "has output files");
  const content = Object.values(code).join("\n");
  assertContains(content, "Monster", "has Monster class");
});

test("generateCode generates Go", () => {
  const code = runner.generateCode(schemaInput, "go");
  const files = Object.keys(code);
  assertEqual(files.length > 0, true, "has output files");
  const content = Object.values(code).join("\n");
  assertContains(content, "Monster", "has Monster type");
});

test("generateCode generates Rust", () => {
  const code = runner.generateCode(schemaInput, "rust");
  const files = Object.keys(code);
  assertEqual(files.length > 0, true, "has output files");
  const content = Object.values(code).join("\n");
  assertContains(content, "Monster", "has Monster struct");
});

test("generateJsonSchema exports schema", () => {
  const jsonSchema = runner.generateJsonSchema(schemaInput);
  assertEqual(typeof jsonSchema, "string", "jsonschema is string");
  assertContains(jsonSchema, "Monster", "has Monster");
  const parsed = JSON.parse(jsonSchema);
  assertEqual(typeof parsed.$schema, "string", "has $schema");
});

test("generateJsonSchema with includeXFlatbuffers adds metadata", () => {
  const jsonSchema = runner.generateJsonSchema(schemaInput, { includeXFlatbuffers: true });
  assertEqual(typeof jsonSchema, "string", "jsonschema is string");
  const parsed = JSON.parse(jsonSchema);
  assertEqual(typeof parsed["x-flatbuffers"], "object", "has x-flatbuffers root metadata");
  assertEqual(typeof parsed["x-flatbuffers"].root_type, "string", "has root_type in x-flatbuffers");
  // Check that definitions also have x-flatbuffers metadata
  const monsterDef = parsed.definitions?.MyGame_Sample_Monster;
  assertEqual(typeof monsterDef?.["x-flatbuffers"], "object", "Monster has x-flatbuffers metadata");
});

// Test: Code generation options
console.log("\n5. Code generation options:");

test("generateCode with genObjectApi", () => {
  const code = runner.generateCode(schemaInput, "cpp", { genObjectApi: true });
  const content = Object.values(code).join("\n");
  assertContains(content, "UnPack", "has UnPack method");
});

test("generateCode with genOnefile (cpp)", () => {
  const code = runner.generateCode(schemaInput, "cpp", { genOnefile: true });
  const files = Object.keys(code);
  // genOnefile combines all output into fewer files
  assertEqual(files.length >= 1, true, "has output files");
});

// Test: Error handling
console.log("\n6. Error handling:");

test("generateBinary throws on invalid JSON", () => {
  let threw = false;
  try {
    runner.generateBinary(schemaInput, "{ invalid json }");
  } catch (e) {
    threw = true;
    assertEqual(e instanceof Error, true, "threw Error");
  }
  assertEqual(threw, true, "threw error on invalid JSON");
});

test("runCommand returns non-zero code on invalid args", () => {
  const result = runner.runCommand(["--invalid-flag-xyz"]);
  assertEqual(result.code !== 0 || result.stderr.length > 0, true, "error on invalid flag");
});

// ==========================================================================
// Security Tests - Schema Validation (VULN-002)
// ==========================================================================
console.log("\n7. Security: Schema validation:");

test("rejects schema input exceeding file count limit", () => {
  const files = {};
  // Create more than MAX_SCHEMA_FILES (1000)
  for (let i = 0; i < 1001; i++) {
    files[`file${i}.fbs`] = 'table Test { x: int; }';
  }
  let threw = false;
  let errorMsg = '';
  try {
    runner.generateCode({ entry: 'file0.fbs', files }, 'ts');
  } catch (e) {
    threw = true;
    errorMsg = e.message;
  }
  assertEqual(threw, true, "threw error on too many files");
  assertContains(errorMsg, "maximum file count", "mentions file count limit");
});

test("rejects schema input exceeding total size limit", () => {
  // Create a single large file (> 10 MB)
  const largeContent = 'x'.repeat(11 * 1024 * 1024);
  let threw = false;
  let errorMsg = '';
  try {
    runner.generateCode({ entry: 'large.fbs', files: { 'large.fbs': largeContent } }, 'ts');
  } catch (e) {
    threw = true;
    errorMsg = e.message;
  }
  assertEqual(threw, true, "threw error on large schema");
  assertContains(errorMsg, "maximum total size", "mentions size limit");
});

test("rejects circular includes", () => {
  const files = {
    'a.fbs': 'include "b.fbs";\ntable A { x: int; }',
    'b.fbs': 'include "a.fbs";\ntable B { y: int; }',
  };
  let threw = false;
  let errorMsg = '';
  try {
    runner.generateCode({ entry: 'a.fbs', files }, 'ts');
  } catch (e) {
    threw = true;
    errorMsg = e.message;
  }
  assertEqual(threw, true, "threw error on circular include");
  assertContains(errorMsg, "Circular include", "mentions circular include");
});

test("rejects deeply nested includes", () => {
  const files = {};
  // Create a chain of 60 includes (exceeds MAX_INCLUDE_DEPTH of 50)
  for (let i = 0; i < 60; i++) {
    if (i < 59) {
      files[`level${i}.fbs`] = `include "level${i + 1}.fbs";\ntable Level${i} { x: int; }`;
    } else {
      files[`level${i}.fbs`] = `table Level${i} { x: int; }`;
    }
  }
  let threw = false;
  let errorMsg = '';
  try {
    runner.generateCode({ entry: 'level0.fbs', files }, 'ts');
  } catch (e) {
    threw = true;
    errorMsg = e.message;
  }
  assertEqual(threw, true, "threw error on deep nesting");
  assertContains(errorMsg, "include depth exceeds", "mentions depth limit");
});

test("accepts valid nested includes within limit", () => {
  const files = {};
  // Create a chain of 10 includes (within limit)
  for (let i = 0; i < 10; i++) {
    if (i < 9) {
      files[`level${i}.fbs`] = `include "level${i + 1}.fbs";\ntable Level${i} { x: int; }`;
    } else {
      files[`level${i}.fbs`] = `table Level${i} { x: int; }\nroot_type Level${i};`;
    }
  }
  // Should not throw
  const code = runner.generateCode({ entry: 'level0.fbs', files }, 'ts');
  assertEqual(typeof code, 'object', 'returns code object');
});

// ==========================================================================
// Security Tests - Binary Validation (VULN-003)
// ==========================================================================
console.log("\n8. Security: Binary validation:");

test("rejects binary input that is too small", () => {
  let threw = false;
  let errorMsg = '';
  try {
    runner.generateJSON(schemaInput, { path: 'test.bin', data: new Uint8Array([1, 2]) });
  } catch (e) {
    threw = true;
    errorMsg = e.message;
  }
  assertEqual(threw, true, "threw error on small binary");
  assertContains(errorMsg, "too small", "mentions size");
});

test("rejects binary with invalid root offset", () => {
  // Create binary with root offset pointing outside buffer
  const binary = new Uint8Array(8);
  const view = new DataView(binary.buffer);
  view.setUint32(0, 1000, true); // Root offset way outside buffer

  let threw = false;
  let errorMsg = '';
  try {
    runner.generateJSON(schemaInput, { path: 'test.bin', data: binary });
  } catch (e) {
    threw = true;
    errorMsg = e.message;
  }
  assertEqual(threw, true, "threw error on invalid root offset");
  assertContains(errorMsg, "root offset", "mentions root offset");
});

test("rejects non-Uint8Array binary input", () => {
  let threw = false;
  let errorMsg = '';
  try {
    runner.generateJSON(schemaInput, { path: 'test.bin', data: [1, 2, 3, 4, 5, 6, 7, 8] });
  } catch (e) {
    threw = true;
    errorMsg = e.message;
  }
  assertEqual(threw, true, "threw error on non-Uint8Array");
  assertContains(errorMsg, "Uint8Array", "mentions Uint8Array");
});

test("skipValidation option bypasses binary validation", () => {
  // Create invalid binary
  const binary = new Uint8Array(8);
  const view = new DataView(binary.buffer);
  view.setUint32(0, 1000, true); // Invalid root offset

  let threw = false;
  try {
    // This should skip validation and fail later in flatc
    runner.generateJSON(schemaInput, { path: 'test.bin', data: binary }, { skipValidation: true });
  } catch (e) {
    threw = true;
    // Should throw from flatc, not from validation
    assertEqual(e.message.includes('root offset') === false, true, 'error not from validation');
  }
  // It will throw eventually from flatc, but not from our validation
  assertEqual(threw, true, "flatc still fails on invalid binary");
});

test("accepts valid FlatBuffer binary", () => {
  // First generate a valid binary
  const binary = runner.generateBinary(schemaInput, monsterJson);
  assertInstanceOf(binary, Uint8Array, "binary is Uint8Array");

  // Then convert back to JSON (should pass validation)
  const json = runner.generateJSON(schemaInput, { path: 'monster.bin', data: binary });
  assertEqual(typeof json, 'string', 'returns JSON string');
  assertContains(json, 'Orc', 'contains monster name');
});

// Summary
console.log("\n=== Test Summary ===");
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log(`Total:  ${passed + failed}`);

if (failed > 0) {
  process.exit(1);
}

process.exit(0);
