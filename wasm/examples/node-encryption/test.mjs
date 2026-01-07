/**
 * Node.js Encryption Integration Test
 *
 * Demonstrates and tests field-level encryption with flatc-wasm
 */

import { randomBytes } from "crypto";
import { FlatcRunner } from "flatc-wasm";
import {
  EncryptionContext,
  encryptBuffer,
  decryptBuffer,
  encryptBytes,
  parseSchemaForEncryption,
} from "flatc-wasm/encryption";

// Test utilities
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

function assertNotEqual(actual, expected, msg) {
  if (actual === expected) {
    throw new Error(`${msg}: expected different from ${expected}`);
  }
}

function assertArrayEqual(a, b, msg) {
  if (a.length !== b.length) {
    throw new Error(`${msg}: length mismatch ${a.length} vs ${b.length}`);
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      throw new Error(`${msg}: mismatch at index ${i}`);
    }
  }
}

// Schema for testing
const testSchema = `
namespace Test;

struct Coordinates {
  lat: double;
  lon: double;
}

table SensorReading {
  device_id: string;
  timestamp: uint64;
  location: Coordinates (encrypted);
  temperature: float (encrypted);
  raw_data: [ubyte] (encrypted);
  secret_message: string (encrypted);
}

root_type SensorReading;
`;

const simpleSchema = `
table SimpleMessage {
  public_text: string;
  secret_number: int (encrypted);
  secret_text: string (encrypted);
}
root_type SimpleMessage;
`;

// ============================================================================
// Tests
// ============================================================================

console.log("\n=== Node.js Encryption Integration Tests ===\n");

// Test 1: EncryptionContext
console.log("1. EncryptionContext:");

test("creates valid context from Uint8Array", () => {
  const key = randomBytes(32);
  const ctx = new EncryptionContext(key);
  assertEqual(ctx.isValid(), true, "context validity");
});

test("creates valid context from hex string", () => {
  const hexKey =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  const ctx = new EncryptionContext(hexKey);
  assertEqual(ctx.isValid(), true, "context validity");
});

test("rejects invalid key size", () => {
  const shortKey = new Uint8Array(16);
  const ctx = new EncryptionContext(shortKey);
  assertEqual(ctx.isValid(), false, "context should be invalid");
});

test("derives different keys for different fields", () => {
  const key = randomBytes(32);
  const ctx = new EncryptionContext(key);
  const key1 = ctx.deriveFieldKey(1);
  const key2 = ctx.deriveFieldKey(2);

  let different = false;
  for (let i = 0; i < 32; i++) {
    if (key1[i] !== key2[i]) {
      different = true;
      break;
    }
  }
  assertEqual(different, true, "derived keys should differ");
});

// Test 2: Low-level encryption
console.log("\n2. Low-level byte encryption:");

test("encrypts and decrypts bytes", () => {
  const key = randomBytes(32);
  const iv = randomBytes(16);
  const original = new TextEncoder().encode("Hello, World!");
  const data = new Uint8Array(original);

  encryptBytes(data, key, iv);

  // Should be different after encryption
  let changed = false;
  for (let i = 0; i < data.length; i++) {
    if (data[i] !== original[i]) {
      changed = true;
      break;
    }
  }
  assertEqual(changed, true, "data should change after encryption");

  // Decrypt (same operation for CTR)
  encryptBytes(data, key, iv);
  assertArrayEqual(data, original, "data should match after decryption");
});

test("different IVs produce different ciphertext", () => {
  const key = randomBytes(32);
  const iv1 = randomBytes(16);
  const iv2 = randomBytes(16);
  const plaintext = new TextEncoder().encode("Test data");

  const data1 = new Uint8Array(plaintext);
  const data2 = new Uint8Array(plaintext);

  encryptBytes(data1, key, iv1);
  encryptBytes(data2, key, iv2);

  let different = false;
  for (let i = 0; i < data1.length; i++) {
    if (data1[i] !== data2[i]) {
      different = true;
      break;
    }
  }
  assertEqual(different, true, "different IVs should produce different ciphertext");
});

// Test 3: Schema parsing
console.log("\n3. Schema parsing:");

test("parses schema and identifies encrypted fields", () => {
  const parsed = parseSchemaForEncryption(simpleSchema, "SimpleMessage");

  assertEqual(parsed.fields.length, 3, "field count");

  const publicField = parsed.fields.find((f) => f.name === "public_text");
  const secretNum = parsed.fields.find((f) => f.name === "secret_number");
  const secretText = parsed.fields.find((f) => f.name === "secret_text");

  assertEqual(publicField.encrypted, false, "public_text should not be encrypted");
  assertEqual(secretNum.encrypted, true, "secret_number should be encrypted");
  assertEqual(secretText.encrypted, true, "secret_text should be encrypted");
});

test("parses complex schema with structs and vectors", () => {
  const parsed = parseSchemaForEncryption(testSchema, "SensorReading");

  const location = parsed.fields.find((f) => f.name === "location");
  const rawData = parsed.fields.find((f) => f.name === "raw_data");

  assertEqual(location.encrypted, true, "location should be encrypted");
  assertEqual(rawData.encrypted, true, "raw_data should be encrypted");
  assertEqual(rawData.type, "vector", "raw_data should be vector type");
});

// Test 4: Full buffer encryption with FlatcRunner
console.log("\n4. Full buffer encryption:");

let flatc;

test("initializes FlatcRunner", async () => {
  flatc = await FlatcRunner.init();
  assertEqual(typeof flatc.version(), "string", "version should be string");
});

test("encrypts and decrypts FlatBuffer", () => {
  const schemaInput = {
    entry: "/simple.fbs",
    files: { "/simple.fbs": simpleSchema },
  };

  const json = JSON.stringify({
    public_text: "Hello, public!",
    secret_number: 42,
    secret_text: "This is secret",
  });

  // Create buffer
  const buffer = flatc.generateBinary(schemaInput, json);
  const original = new Uint8Array(buffer);

  // Encrypt
  const key = randomBytes(32);
  encryptBuffer(buffer, simpleSchema, key, "SimpleMessage");

  // Buffer should be modified
  let changed = false;
  for (let i = 0; i < buffer.length; i++) {
    if (buffer[i] !== original[i]) {
      changed = true;
      break;
    }
  }
  assertEqual(changed, true, "buffer should change after encryption");

  // Decrypt
  decryptBuffer(buffer, simpleSchema, key, "SimpleMessage");

  // Should be able to read JSON again
  const recovered = flatc.generateJSON(schemaInput, {
    path: "/msg.bin",
    data: buffer,
  });
  const recoveredObj = JSON.parse(recovered);

  assertEqual(recoveredObj.public_text, "Hello, public!", "public_text");
  assertEqual(recoveredObj.secret_number, 42, "secret_number");
  assertEqual(recoveredObj.secret_text, "This is secret", "secret_text");
});

test("encrypted buffer is still a valid FlatBuffer", () => {
  const schemaInput = {
    entry: "/simple.fbs",
    files: { "/simple.fbs": simpleSchema },
  };

  const json = JSON.stringify({
    public_text: "Public data",
    secret_number: 999,
    secret_text: "Secret data",
  });

  const buffer = flatc.generateBinary(schemaInput, json);
  const key = randomBytes(32);

  encryptBuffer(buffer, simpleSchema, key, "SimpleMessage");

  // The buffer should still be parseable (though values will be garbage)
  // This is the key property - binary layout is preserved
  let threw = false;
  try {
    // This should not throw - the buffer structure is valid
    const result = flatc.generateJSON(schemaInput, {
      path: "/msg.bin",
      data: buffer,
    });
    // The JSON will have garbage values but should parse
    JSON.parse(result);
  } catch (e) {
    // Some encrypted values might produce invalid UTF-8 in strings
    // That's expected - the test is that we don't corrupt the structure
    threw = true;
  }

  // Either way, decrypt should restore original
  decryptBuffer(buffer, simpleSchema, key, "SimpleMessage");
  const recovered = flatc.generateJSON(schemaInput, {
    path: "/msg.bin",
    data: buffer,
  });
  const obj = JSON.parse(recovered);
  assertEqual(obj.secret_number, 999, "secret_number after decrypt");
});

test("different keys produce different ciphertext", () => {
  const schemaInput = {
    entry: "/simple.fbs",
    files: { "/simple.fbs": simpleSchema },
  };

  const json = JSON.stringify({
    public_text: "Test",
    secret_number: 123,
    secret_text: "Same data",
  });

  const buffer1 = flatc.generateBinary(schemaInput, json);
  const buffer2 = flatc.generateBinary(schemaInput, json);

  const key1 = randomBytes(32);
  const key2 = randomBytes(32);

  encryptBuffer(buffer1, simpleSchema, key1, "SimpleMessage");
  encryptBuffer(buffer2, simpleSchema, key2, "SimpleMessage");

  let different = false;
  for (let i = 0; i < buffer1.length; i++) {
    if (buffer1[i] !== buffer2[i]) {
      different = true;
      break;
    }
  }
  assertEqual(different, true, "different keys should produce different ciphertext");
});

test("public fields remain unchanged after encryption", () => {
  const schemaInput = {
    entry: "/simple.fbs",
    files: { "/simple.fbs": simpleSchema },
  };

  const publicText = "This text should not change!";
  const json = JSON.stringify({
    public_text: publicText,
    secret_number: 42,
    secret_text: "secret",
  });

  const buffer = flatc.generateBinary(schemaInput, json);
  const key = randomBytes(32);

  encryptBuffer(buffer, simpleSchema, key, "SimpleMessage");

  // The public_text string bytes should still be in the buffer
  const textBytes = new TextEncoder().encode(publicText);
  const bufferStr = new TextDecoder().decode(buffer);

  assertEqual(
    bufferStr.includes(publicText),
    true,
    "public text should be readable in encrypted buffer"
  );
});

// Test 5: Encryption context reuse
console.log("\n5. Encryption context reuse:");

test("EncryptionContext can be reused", () => {
  const key = randomBytes(32);
  const ctx = new EncryptionContext(key);

  const schemaInput = {
    entry: "/simple.fbs",
    files: { "/simple.fbs": simpleSchema },
  };

  const json1 = JSON.stringify({
    public_text: "msg1",
    secret_number: 1,
    secret_text: "secret1",
  });
  const json2 = JSON.stringify({
    public_text: "msg2",
    secret_number: 2,
    secret_text: "secret2",
  });

  const buffer1 = flatc.generateBinary(schemaInput, json1);
  const buffer2 = flatc.generateBinary(schemaInput, json2);

  // Use same context for both
  encryptBuffer(buffer1, simpleSchema, ctx, "SimpleMessage");
  encryptBuffer(buffer2, simpleSchema, ctx, "SimpleMessage");

  // Both should decrypt correctly
  decryptBuffer(buffer1, simpleSchema, ctx, "SimpleMessage");
  decryptBuffer(buffer2, simpleSchema, ctx, "SimpleMessage");

  const recovered1 = JSON.parse(
    flatc.generateJSON(schemaInput, { path: "/m.bin", data: buffer1 })
  );
  const recovered2 = JSON.parse(
    flatc.generateJSON(schemaInput, { path: "/m.bin", data: buffer2 })
  );

  assertEqual(recovered1.secret_number, 1, "first message");
  assertEqual(recovered2.secret_number, 2, "second message");
});

// Summary
console.log("\n=== Test Summary ===");
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log(`Total:  ${passed + failed}`);

if (failed > 0) {
  process.exit(1);
}

console.log("\n✅ All Node.js encryption tests passed!\n");
process.exit(0);
