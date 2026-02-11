/**
 * Tests for format-detector.mjs
 */

import { detectFormat, detectStringFormat } from "../src/format-detector.mjs";

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

console.log("\n=== Format Detector Tests ===\n");

// =========================================================================
// detectFormat - JSON detection
// =========================================================================
console.log("1. detectFormat - JSON detection:");

test("detects JSON object from Uint8Array", () => {
  const data = new TextEncoder().encode('{"name":"test"}');
  assertEqual(detectFormat(data), 'json', "JSON object detected");
});

test("detects JSON array from Uint8Array", () => {
  const data = new TextEncoder().encode('[1, 2, 3]');
  assertEqual(detectFormat(data), 'json', "JSON array detected");
});

test("detects JSON with leading whitespace", () => {
  const data = new TextEncoder().encode('  \n\t {"name":"test"}');
  assertEqual(detectFormat(data), 'json', "JSON with whitespace detected");
});

test("detects JSON with UTF-8 BOM", () => {
  const bom = new Uint8Array([0xEF, 0xBB, 0xBF]);
  const json = new TextEncoder().encode('{"x":1}');
  const data = new Uint8Array(bom.length + json.length);
  data.set(bom);
  data.set(json, bom.length);
  assertEqual(detectFormat(data), 'json', "JSON with BOM detected");
});

test("detects JSON array with leading spaces", () => {
  const data = new TextEncoder().encode('   [{"a":1}]');
  assertEqual(detectFormat(data), 'json', "JSON array with spaces");
});

// =========================================================================
// detectFormat - FlatBuffer detection
// =========================================================================
console.log("\n2. detectFormat - FlatBuffer detection:");

test("detects valid FlatBuffer binary", () => {
  // Create a minimal valid FlatBuffer-like structure
  // Root offset at byte 0 points to position 8 within a 16-byte buffer
  const data = new Uint8Array(16);
  const view = new DataView(data.buffer);
  view.setUint32(0, 8, true); // Root offset = 8 (little-endian)
  // Fill rest with some data
  view.setUint32(8, 4, true); // vtable offset at root
  assertEqual(detectFormat(data), 'flatbuffer', "FlatBuffer detected");
});

test("detects FlatBuffer with root offset at beginning of valid range", () => {
  const data = new Uint8Array(32);
  const view = new DataView(data.buffer);
  view.setUint32(0, 4, true); // Minimum valid root offset
  assertEqual(detectFormat(data), 'flatbuffer', "FlatBuffer with min offset");
});

// =========================================================================
// detectFormat - Unknown / edge cases
// =========================================================================
console.log("\n3. detectFormat - Unknown and edge cases:");

test("returns unknown for null input", () => {
  assertEqual(detectFormat(null), 'unknown', "null input");
});

test("returns unknown for empty Uint8Array", () => {
  assertEqual(detectFormat(new Uint8Array(0)), 'unknown', "empty array");
});

test("returns unknown for very small data", () => {
  assertEqual(detectFormat(new Uint8Array([0x41, 0x42])), 'unknown', "2 bytes");
});

test("returns unknown for plain text", () => {
  const data = new TextEncoder().encode('Hello, World!');
  assertEqual(detectFormat(data), 'unknown', "plain text");
});

test("returns unknown for all whitespace", () => {
  const data = new TextEncoder().encode('   \n\t\r  ');
  assertEqual(detectFormat(data), 'unknown', "whitespace only");
});

test("returns unknown for data starting with non-JSON non-FB bytes", () => {
  const data = new Uint8Array([0xFF, 0xFE, 0x00, 0x01]);
  assertEqual(detectFormat(data), 'unknown', "non-JSON non-FB");
});

test("returns unknown when root offset is 0", () => {
  const data = new Uint8Array(8);
  // Root offset = 0, which is < MIN_FLATBUFFER_SIZE (4)
  assertEqual(detectFormat(data), 'unknown', "zero root offset");
});

test("returns unknown when root offset exceeds buffer", () => {
  const data = new Uint8Array(8);
  const view = new DataView(data.buffer);
  view.setUint32(0, 100, true); // Root offset beyond buffer
  assertEqual(detectFormat(data), 'unknown', "root offset out of bounds");
});

// =========================================================================
// detectStringFormat
// =========================================================================
console.log("\n4. detectStringFormat:");

test("detects JSON object string", () => {
  assertEqual(detectStringFormat('{"name":"test"}'), 'json', "JSON object string");
});

test("detects JSON array string", () => {
  assertEqual(detectStringFormat('[1, 2, 3]'), 'json', "JSON array string");
});

test("detects JSON with leading whitespace", () => {
  assertEqual(detectStringFormat('  \n  {"x":1}'), 'json', "JSON with whitespace");
});

test("returns unknown for plain text", () => {
  assertEqual(detectStringFormat('Hello'), 'unknown', "plain text");
});

test("returns unknown for null", () => {
  assertEqual(detectStringFormat(null), 'unknown', "null");
});

test("returns unknown for empty string", () => {
  assertEqual(detectStringFormat(''), 'unknown', "empty string");
});

test("returns unknown for number", () => {
  assertEqual(detectStringFormat(42), 'unknown', "number input");
});

test("returns unknown for whitespace-only string", () => {
  assertEqual(detectStringFormat('   \t\n  '), 'unknown', "whitespace only");
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
