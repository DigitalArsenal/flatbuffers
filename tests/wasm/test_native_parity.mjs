/**
 * Test: WASM vs Native flatc Parity
 *
 * This test ensures that the WASM version of flatc produces identical output
 * to the native flatc binary for code generation and binary/JSON conversions.
 */

import { execSync } from "node:child_process";
import { mkdirSync, writeFileSync, readFileSync, rmSync, readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { FlatcRunner } from "../../wasm/src/runner.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = join(__dirname, "../..");
const NATIVE_FLATC = join(ROOT_DIR, "build/flatc");
const TEMP_DIR = join(ROOT_DIR, "build/wasm-parity-test");

let passed = 0;
let failed = 0;
let skipped = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    if (e.message?.includes("SKIP:")) {
      console.log(`  ⊘ ${name} (skipped: ${e.message.replace("SKIP: ", "")})`);
      skipped++;
    } else {
      console.log(`  ✗ ${name}`);
      console.log(`    Error: ${e.message}`);
      if (e.details) console.log(`    Details: ${e.details}`);
      failed++;
    }
  }
}

function assertEqual(actual, expected, msg) {
  if (actual !== expected) {
    const error = new Error(`${msg}: values differ`);
    error.details = `Expected length ${expected?.length}, got ${actual?.length}`;
    throw error;
  }
}

function assertDeepEqual(actual, expected, msg) {
  const actualStr = JSON.stringify(actual, null, 2);
  const expectedStr = JSON.stringify(expected, null, 2);
  if (actualStr !== expectedStr) {
    const error = new Error(`${msg}: objects differ`);
    error.details = `Expected: ${expectedStr.slice(0, 200)}...\nGot: ${actualStr.slice(0, 200)}...`;
    throw error;
  }
}

function normalizeCode(code) {
  // Normalize line endings and trailing whitespace
  return code
    .replace(/\r\n/g, "\n")
    .replace(/[ \t]+$/gm, "")
    .replace(/\n+$/g, "\n");
}

function cleanup() {
  try {
    rmSync(TEMP_DIR, { recursive: true, force: true });
  } catch {}
}

function ensureDir(dir) {
  mkdirSync(dir, { recursive: true });
}

// Check if native flatc exists
if (!existsSync(NATIVE_FLATC)) {
  console.error(`Native flatc not found at ${NATIVE_FLATC}`);
  console.error("Please build flatc first: cmake --build build --target flatc");
  process.exit(1);
}

// Test schemas
const schemas = {
  simple: `
    namespace Test;
    table SimpleMessage {
      id: int;
      name: string;
      active: bool = true;
    }
    root_type SimpleMessage;
  `,

  withEnum: `
    namespace Test;
    enum Color : byte { Red = 0, Green = 1, Blue = 2 }
    table ColoredItem {
      name: string;
      color: Color = Green;
    }
    root_type ColoredItem;
  `,

  withStruct: `
    namespace Test;
    struct Vec3 {
      x: float;
      y: float;
      z: float;
    }
    table Position {
      location: Vec3;
      label: string;
    }
    root_type Position;
  `,

  withUnion: `
    namespace Test;
    table Sword { damage: int; }
    table Shield { defense: int; }
    union Equipment { Sword, Shield }
    table Character {
      name: string;
      gear: Equipment;
    }
    root_type Character;
  `,

  withVector: `
    namespace Test;
    table Item { value: int; }
    table Container {
      items: [Item];
      tags: [string];
      data: [ubyte];
    }
    root_type Container;
  `,

  complex: `
    namespace Game.RPG;

    enum ItemRarity : byte { Common, Uncommon, Rare, Epic, Legendary }

    struct Stats {
      strength: short;
      agility: short;
      intelligence: short;
    }

    table Weapon {
      name: string (required);
      damage: int;
      rarity: ItemRarity = Common;
    }

    table Armor {
      name: string (required);
      defense: int;
      rarity: ItemRarity = Common;
    }

    union Equipment { Weapon, Armor }

    table Character {
      id: ulong;
      name: string (required);
      level: int = 1;
      stats: Stats;
      inventory: [Equipment];
      gold: int;
    }

    root_type Character;
  `,
};

// Languages to test
const languages = [
  { flag: "cpp", ext: ".h" },
  { flag: "ts", ext: ".ts" },
  { flag: "python", ext: ".py" },
  { flag: "go", ext: ".go" },
  { flag: "rust", ext: ".rs" },
  { flag: "java", ext: ".java" },
  { flag: "csharp", ext: ".cs" },
  { flag: "kotlin", ext: ".kt" },
  { flag: "swift", ext: ".swift" },
  { flag: "jsonschema", ext: ".schema.json" },
];

console.log("\n=== WASM vs Native flatc Parity Tests ===\n");

// Initialize
cleanup();
ensureDir(TEMP_DIR);

let runner;

console.log("Initializing FlatcRunner...");
runner = await FlatcRunner.init();
console.log("FlatcRunner initialized.\n");

// Helper: Run native flatc
function runNativeFlatc(args, cwd = TEMP_DIR) {
  try {
    execSync(`"${NATIVE_FLATC}" ${args.join(" ")}`, {
      cwd,
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    });
    return { success: true };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

// Helper: Get all files in directory recursively
function getAllFiles(dir, base = "") {
  const result = {};
  if (!existsSync(dir)) return result;

  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const relPath = base ? `${base}/${entry.name}` : entry.name;
    const fullPath = join(dir, entry.name);

    if (entry.isDirectory()) {
      Object.assign(result, getAllFiles(fullPath, relPath));
    } else {
      result[relPath] = readFileSync(fullPath, "utf8");
    }
  }
  return result;
}

// Test 1: Code Generation Parity
console.log("1. Code Generation Parity:");

for (const [schemaName, schemaContent] of Object.entries(schemas)) {
  for (const lang of languages) {
    test(`${schemaName} → ${lang.flag}`, () => {
      const schemaFile = `${schemaName}.fbs`;
      const nativeOutDir = join(TEMP_DIR, `native_${schemaName}_${lang.flag}`);
      const schemaPath = join(TEMP_DIR, schemaFile);

      // Write schema for native flatc
      writeFileSync(schemaPath, schemaContent);
      ensureDir(nativeOutDir);

      // Run native flatc
      const nativeResult = runNativeFlatc([
        `--${lang.flag}`,
        "-o", nativeOutDir,
        schemaPath,
      ]);

      if (!nativeResult.success) {
        throw new Error(`SKIP: Native flatc failed: ${nativeResult.error}`);
      }

      // Get native output
      const nativeFiles = getAllFiles(nativeOutDir);

      if (Object.keys(nativeFiles).length === 0) {
        throw new Error(`SKIP: Native flatc produced no output`);
      }

      // Run WASM flatc
      const schemaInput = {
        entry: `/${schemaFile}`,
        files: { [`/${schemaFile}`]: schemaContent },
      };

      const wasmFiles = runner.generateCode(schemaInput, lang.flag);

      // Compare file count
      const nativeFileNames = Object.keys(nativeFiles).sort();
      const wasmFileNames = Object.keys(wasmFiles).sort();

      if (nativeFileNames.length !== wasmFileNames.length) {
        const error = new Error("File count mismatch");
        error.details = `Native: ${nativeFileNames.join(", ")}\nWASM: ${wasmFileNames.join(", ")}`;
        throw error;
      }

      // Compare each file's content
      for (const nativeFile of nativeFileNames) {
        // Find matching WASM file (may have different path structure)
        const wasmFile = wasmFileNames.find(
          (f) => f === nativeFile || f.endsWith(nativeFile) || nativeFile.endsWith(f)
        );

        if (!wasmFile) {
          throw new Error(`Missing WASM file for: ${nativeFile}`);
        }

        const nativeContent = normalizeCode(nativeFiles[nativeFile]);
        const wasmContent = normalizeCode(wasmFiles[wasmFile]);

        if (nativeContent !== wasmContent) {
          // Find first difference
          const lines1 = nativeContent.split("\n");
          const lines2 = wasmContent.split("\n");
          let diffLine = -1;
          for (let i = 0; i < Math.max(lines1.length, lines2.length); i++) {
            if (lines1[i] !== lines2[i]) {
              diffLine = i + 1;
              break;
            }
          }
          const error = new Error(`Content mismatch in ${nativeFile}`);
          error.details = `First difference at line ${diffLine}\nNative: "${lines1[diffLine - 1]?.slice(0, 80)}"\nWASM: "${lines2[diffLine - 1]?.slice(0, 80)}"`;
          throw error;
        }
      }
    });
  }
}

// Test 2: Binary Conversion Parity
console.log("\n2. Binary Conversion Parity:");

const binaryTestCases = [
  {
    name: "simple",
    schema: schemas.simple,
    json: '{"id": 42, "name": "test", "active": true}',
  },
  {
    name: "withEnum",
    schema: schemas.withEnum,
    json: '{"name": "item1", "color": "Blue"}',
  },
  {
    name: "withStruct",
    schema: schemas.withStruct,
    json: '{"location": {"x": 1.5, "y": 2.5, "z": 3.5}, "label": "point"}',
  },
  {
    name: "withVector",
    schema: schemas.withVector,
    json: '{"items": [{"value": 1}, {"value": 2}], "tags": ["a", "b"], "data": [1, 2, 3]}',
  },
];

for (const tc of binaryTestCases) {
  test(`JSON→Binary→JSON: ${tc.name}`, () => {
    const schemaFile = `${tc.name}.fbs`;
    const jsonFile = `${tc.name}.json`;
    const schemaPath = join(TEMP_DIR, schemaFile);
    const jsonPath = join(TEMP_DIR, jsonFile);
    const nativeBinDir = join(TEMP_DIR, `native_bin_${tc.name}`);
    const nativeJsonDir = join(TEMP_DIR, `native_json_${tc.name}`);

    // Write files for native flatc
    writeFileSync(schemaPath, tc.schema);
    writeFileSync(jsonPath, tc.json);
    ensureDir(nativeBinDir);
    ensureDir(nativeJsonDir);

    // Native: JSON → Binary
    const nativeToBin = runNativeFlatc([
      "--binary",
      "--unknown-json",
      "-o", nativeBinDir,
      schemaPath,
      jsonPath,
    ]);

    if (!nativeToBin.success) {
      throw new Error(`SKIP: Native JSON→Binary failed`);
    }

    // Get native binary
    const nativeBinFiles = readdirSync(nativeBinDir);
    const nativeBinFile = nativeBinFiles.find((f) => f.endsWith(".bin"));
    if (!nativeBinFile) {
      throw new Error(`SKIP: Native flatc produced no binary`);
    }
    const nativeBinary = readFileSync(join(nativeBinDir, nativeBinFile));

    // WASM: JSON → Binary
    const schemaInput = {
      entry: `/${schemaFile}`,
      files: { [`/${schemaFile}`]: tc.schema },
    };
    const wasmBinary = runner.generateBinary(schemaInput, tc.json);

    // Compare binaries
    if (nativeBinary.length !== wasmBinary.length) {
      const error = new Error("Binary size mismatch");
      error.details = `Native: ${nativeBinary.length} bytes, WASM: ${wasmBinary.length} bytes`;
      throw error;
    }

    // Compare byte-by-byte
    for (let i = 0; i < nativeBinary.length; i++) {
      if (nativeBinary[i] !== wasmBinary[i]) {
        const error = new Error("Binary content mismatch");
        error.details = `First difference at byte ${i}: native=0x${nativeBinary[i].toString(16)}, wasm=0x${wasmBinary[i].toString(16)}`;
        throw error;
      }
    }

    // Native: Binary → JSON
    const binForNative = join(nativeBinDir, "test.bin");
    writeFileSync(binForNative, nativeBinary);

    const nativeToJson = runNativeFlatc([
      "--json",
      "--strict-json",
      "--raw-binary",
      "-o", nativeJsonDir,
      schemaPath,
      "--",
      binForNative,
    ]);

    if (!nativeToJson.success) {
      throw new Error(`SKIP: Native Binary→JSON failed`);
    }

    // Get native JSON output
    const nativeJsonFiles = readdirSync(nativeJsonDir);
    const nativeJsonFile = nativeJsonFiles.find((f) => f.endsWith(".json"));
    if (!nativeJsonFile) {
      throw new Error(`SKIP: Native flatc produced no JSON`);
    }
    const nativeJsonOutput = readFileSync(join(nativeJsonDir, nativeJsonFile), "utf8");

    // WASM: Binary → JSON
    const wasmJsonOutput = runner.generateJSON(schemaInput, {
      path: "/test.bin",
      data: wasmBinary,
    });

    // Compare JSON (parse and re-stringify to normalize)
    const nativeParsed = JSON.parse(nativeJsonOutput);
    const wasmParsed = JSON.parse(wasmJsonOutput);

    assertDeepEqual(wasmParsed, nativeParsed, "JSON output");
  });
}

// Test 3: Code Generation Options Parity
console.log("\n3. Code Generation Options Parity:");

const optionTests = [
  { lang: "cpp", options: { genObjectApi: true }, flag: "--gen-object-api" },
  { lang: "cpp", options: { genMutable: true }, flag: "--gen-mutable" },
  { lang: "cpp", options: { genCompare: true }, flag: "--gen-compare" },
  { lang: "python", options: { pythonTyping: true }, flag: "--python-typing" },
];

for (const optTest of optionTests) {
  test(`${optTest.lang} with ${optTest.flag}`, () => {
    const schemaContent = schemas.simple;
    const schemaFile = "options_test.fbs";
    const schemaPath = join(TEMP_DIR, schemaFile);
    const nativeOutDir = join(TEMP_DIR, `native_opt_${optTest.lang}_${optTest.flag.replace(/--/g, "")}`);

    writeFileSync(schemaPath, schemaContent);
    ensureDir(nativeOutDir);

    // Run native flatc with option
    const nativeResult = runNativeFlatc([
      `--${optTest.lang}`,
      optTest.flag,
      "-o", nativeOutDir,
      schemaPath,
    ]);

    if (!nativeResult.success) {
      throw new Error(`SKIP: Native flatc failed with ${optTest.flag}`);
    }

    const nativeFiles = getAllFiles(nativeOutDir);

    if (Object.keys(nativeFiles).length === 0) {
      throw new Error(`SKIP: Native flatc produced no output`);
    }

    // Run WASM flatc with option
    const schemaInput = {
      entry: `/${schemaFile}`,
      files: { [`/${schemaFile}`]: schemaContent },
    };

    const wasmFiles = runner.generateCode(schemaInput, optTest.lang, optTest.options);

    // Compare
    for (const [nativeFile, nativeContent] of Object.entries(nativeFiles)) {
      const wasmFile = Object.keys(wasmFiles).find(
        (f) => f === nativeFile || f.endsWith(nativeFile) || nativeFile.endsWith(f)
      );

      if (!wasmFile) {
        throw new Error(`Missing WASM file for: ${nativeFile}`);
      }

      const normalizedNative = normalizeCode(nativeContent);
      const normalizedWasm = normalizeCode(wasmFiles[wasmFile]);

      if (normalizedNative !== normalizedWasm) {
        const error = new Error(`Content mismatch with ${optTest.flag}`);
        throw error;
      }
    }
  });
}

// Test 4: JSON Schema Export Parity
console.log("\n4. JSON Schema Export Parity:");

for (const [schemaName, schemaContent] of Object.entries(schemas)) {
  test(`JSON Schema: ${schemaName}`, () => {
    const schemaFile = `${schemaName}.fbs`;
    const schemaPath = join(TEMP_DIR, schemaFile);
    const nativeOutDir = join(TEMP_DIR, `native_jsonschema_${schemaName}`);

    writeFileSync(schemaPath, schemaContent);
    ensureDir(nativeOutDir);

    // Run native flatc
    const nativeResult = runNativeFlatc([
      "--jsonschema",
      "-o", nativeOutDir,
      schemaPath,
    ]);

    if (!nativeResult.success) {
      throw new Error(`SKIP: Native flatc failed`);
    }

    const nativeFiles = getAllFiles(nativeOutDir);
    const nativeSchemaFile = Object.keys(nativeFiles).find((f) => f.endsWith(".schema.json"));

    if (!nativeSchemaFile) {
      throw new Error(`SKIP: Native flatc produced no JSON Schema`);
    }

    // Run WASM flatc
    const schemaInput = {
      entry: `/${schemaFile}`,
      files: { [`/${schemaFile}`]: schemaContent },
    };

    const wasmJsonSchema = runner.generateJsonSchema(schemaInput);

    // Parse and compare
    const nativeParsed = JSON.parse(nativeFiles[nativeSchemaFile]);
    const wasmParsed = JSON.parse(wasmJsonSchema);

    assertDeepEqual(wasmParsed, nativeParsed, "JSON Schema content");
  });
}

// Cleanup
cleanup();

// Summary
console.log("\n=== Test Summary ===");
console.log(`Passed:  ${passed}`);
console.log(`Failed:  ${failed}`);
console.log(`Skipped: ${skipped}`);
console.log(`Total:   ${passed + failed + skipped}`);

if (failed > 0) {
  console.log("\n❌ Some tests failed!");
  process.exit(1);
} else {
  console.log("\n✅ All tests passed!");
}
