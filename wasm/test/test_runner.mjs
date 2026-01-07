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

// Summary
console.log("\n=== Test Summary ===");
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log(`Total:  ${passed + failed}`);

if (failed > 0) {
  process.exit(1);
}

process.exit(0);
