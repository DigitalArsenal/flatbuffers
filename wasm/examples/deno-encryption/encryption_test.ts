/**
 * Deno Encryption Integration Tests
 *
 * Run with: deno test --allow-read
 */

import {
  assertEquals,
  assertNotEquals,
  assertThrows,
} from "https://deno.land/std@0.208.0/assert/mod.ts";

import {
  EncryptionContext,
  encryptBytes,
  decryptBytes,
  encryptBuffer,
  decryptBuffer,
  parseSchemaForEncryption,
} from "./encryption.ts";

const SIMPLE_SCHEMA = `
table SimpleMessage {
  public_text: string;
  secret_number: int (encrypted);
  secret_text: string (encrypted);
}
root_type SimpleMessage;
`;

const SENSOR_SCHEMA = `
table SensorReading {
  device_id: string;
  timestamp: uint64;
  temperature: float (encrypted);
  raw_data: [ubyte] (encrypted);
  secret_message: string (encrypted);
}
root_type SensorReading;
`;

function createSimpleFlatBuffer(): Uint8Array {
  const buf = new Uint8Array(64);
  const view = new DataView(buf.buffer);

  // Root offset points to table at offset 16
  view.setUint32(0, 16, true);

  // VTable at offset 4
  view.setUint16(4, 10, true); // vtable size
  view.setUint16(6, 12, true); // table size
  view.setUint16(8, 4, true); // field 0 offset
  view.setUint16(10, 8, true); // field 1 offset
  view.setUint16(12, 0, true); // field 2 not present

  // Table at offset 16: soffset to vtable
  view.setUint32(16, 12, true); // 16 - 4 = 12

  // Field 0 (string offset) at table+4 = offset 20
  view.setUint32(20, 12, true); // points to string at 32

  // Field 1 (int32) at table+8 = offset 24
  view.setUint32(24, 42, true); // secret_number = 42

  // String at offset 32
  view.setUint32(32, 5, true); // length
  const hello = new TextEncoder().encode("hello");
  buf.set(hello, 36);

  return buf;
}

// Test 1: EncryptionContext
Deno.test("EncryptionContext - creates valid context from bytes", () => {
  const key = crypto.getRandomValues(new Uint8Array(32));
  const ctx = new EncryptionContext(key);
  assertEquals(ctx.isValid(), true);
});

Deno.test("EncryptionContext - creates valid context from hex", () => {
  const hexKey = "0123456789abcdef".repeat(4);
  const ctx = new EncryptionContext(hexKey);
  assertEquals(ctx.isValid(), true);
});

Deno.test("EncryptionContext - rejects invalid key size", () => {
  const key = crypto.getRandomValues(new Uint8Array(16));
  const ctx = new EncryptionContext(key);
  assertEquals(ctx.isValid(), false);
});

Deno.test("EncryptionContext - derives different keys for different fields", () => {
  const key = crypto.getRandomValues(new Uint8Array(32));
  const ctx = new EncryptionContext(key);
  const key1 = ctx.deriveFieldKey(1);
  const key2 = ctx.deriveFieldKey(2);
  assertNotEquals(Array.from(key1), Array.from(key2));
});

// Test 2: Low-level byte encryption
Deno.test("encryptBytes - encrypts and decrypts bytes", () => {
  const key = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const original = new TextEncoder().encode("Hello, World!");
  const data = new Uint8Array(original);

  encryptBytes(data, key, iv);
  assertNotEquals(Array.from(data), Array.from(original));

  decryptBytes(data, key, iv);
  assertEquals(Array.from(data), Array.from(original));
});

Deno.test("encryptBytes - different IVs produce different ciphertext", () => {
  const key = crypto.getRandomValues(new Uint8Array(32));
  const iv1 = crypto.getRandomValues(new Uint8Array(16));
  const iv2 = crypto.getRandomValues(new Uint8Array(16));
  const plaintext = new TextEncoder().encode("Test data");

  const data1 = new Uint8Array(plaintext);
  const data2 = new Uint8Array(plaintext);

  encryptBytes(data1, key, iv1);
  encryptBytes(data2, key, iv2);

  assertNotEquals(Array.from(data1), Array.from(data2));
});

// Test 3: Schema parsing
Deno.test("parseSchemaForEncryption - parses simple schema", () => {
  const fields = parseSchemaForEncryption(SIMPLE_SCHEMA, "SimpleMessage");
  assertEquals(fields.length, 3);

  const publicField = fields.find((f) => f.name === "public_text");
  const secretNum = fields.find((f) => f.name === "secret_number");
  const secretText = fields.find((f) => f.name === "secret_text");

  assertEquals(publicField?.encrypted, false);
  assertEquals(secretNum?.encrypted, true);
  assertEquals(secretText?.encrypted, true);
});

Deno.test("parseSchemaForEncryption - parses vector fields", () => {
  const fields = parseSchemaForEncryption(SENSOR_SCHEMA, "SensorReading");
  const rawData = fields.find((f) => f.name === "raw_data");

  assertEquals(rawData?.encrypted, true);
  assertEquals(rawData?.type, "vector");
});

// Test 4: Buffer encryption
Deno.test("encryptBuffer - changes data", () => {
  const buf = createSimpleFlatBuffer();
  const original = new Uint8Array(buf);
  const key = crypto.getRandomValues(new Uint8Array(32));

  encryptBuffer(buf, SIMPLE_SCHEMA, key, "SimpleMessage");

  assertNotEquals(Array.from(buf), Array.from(original));
});

Deno.test("encryptBuffer - roundtrip", () => {
  const buf = createSimpleFlatBuffer();
  const original = new Uint8Array(buf);
  const key = crypto.getRandomValues(new Uint8Array(32));

  encryptBuffer(buf, SIMPLE_SCHEMA, key, "SimpleMessage");
  decryptBuffer(buf, SIMPLE_SCHEMA, key, "SimpleMessage");

  assertEquals(Array.from(buf), Array.from(original));
});

Deno.test("encryptBuffer - different keys produce different ciphertext", () => {
  const buf1 = createSimpleFlatBuffer();
  const buf2 = createSimpleFlatBuffer();
  const key1 = crypto.getRandomValues(new Uint8Array(32));
  const key2 = crypto.getRandomValues(new Uint8Array(32));

  encryptBuffer(buf1, SIMPLE_SCHEMA, key1, "SimpleMessage");
  encryptBuffer(buf2, SIMPLE_SCHEMA, key2, "SimpleMessage");

  assertNotEquals(Array.from(buf1), Array.from(buf2));
});

Deno.test("encryptBuffer - wrong key produces wrong result", () => {
  const buf = createSimpleFlatBuffer();
  const original = new Uint8Array(buf);
  const key1 = crypto.getRandomValues(new Uint8Array(32));
  const key2 = crypto.getRandomValues(new Uint8Array(32));

  encryptBuffer(buf, SIMPLE_SCHEMA, key1, "SimpleMessage");
  decryptBuffer(buf, SIMPLE_SCHEMA, key2, "SimpleMessage");

  assertNotEquals(Array.from(buf), Array.from(original));
});

// Test 5: Context reuse
Deno.test("EncryptionContext - can be reused", () => {
  const key = crypto.getRandomValues(new Uint8Array(32));
  const ctx = new EncryptionContext(key);

  const buf1 = createSimpleFlatBuffer();
  const buf2 = createSimpleFlatBuffer();
  const orig1 = new Uint8Array(buf1);
  const orig2 = new Uint8Array(buf2);

  encryptBuffer(buf1, SIMPLE_SCHEMA, ctx, "SimpleMessage");
  encryptBuffer(buf2, SIMPLE_SCHEMA, ctx, "SimpleMessage");

  decryptBuffer(buf1, SIMPLE_SCHEMA, ctx, "SimpleMessage");
  decryptBuffer(buf2, SIMPLE_SCHEMA, ctx, "SimpleMessage");

  assertEquals(Array.from(buf1), Array.from(orig1));
  assertEquals(Array.from(buf2), Array.from(orig2));
});

// Test 6: Interoperability
Deno.test("key derivation is deterministic", () => {
  const key = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    key[i] = parseInt("0123456789abcdef"[i % 16], 16);
  }

  const ctx1 = new EncryptionContext(key);
  const ctx2 = new EncryptionContext(key);

  const derived1 = ctx1.deriveFieldKey(5);
  const derived2 = ctx2.deriveFieldKey(5);

  assertEquals(Array.from(derived1), Array.from(derived2));
});

Deno.test("encryption is deterministic", () => {
  const key = crypto.getRandomValues(new Uint8Array(32));
  const ctx = new EncryptionContext(key);

  const buf1 = createSimpleFlatBuffer();
  const buf2 = createSimpleFlatBuffer();

  encryptBuffer(buf1, SIMPLE_SCHEMA, ctx, "SimpleMessage");
  encryptBuffer(buf2, SIMPLE_SCHEMA, ctx, "SimpleMessage");

  assertEquals(Array.from(buf1), Array.from(buf2));
});

Deno.test("hex key same as bytes key", () => {
  const hexKey = "0123456789abcdef".repeat(4);
  const bytesKey = new Uint8Array(32);
  for (let i = 0; i < 64; i += 2) {
    bytesKey[i / 2] = parseInt(hexKey.substring(i, i + 2), 16);
  }

  const ctxHex = new EncryptionContext(hexKey);
  const ctxBytes = new EncryptionContext(bytesKey);

  const buf1 = createSimpleFlatBuffer();
  const buf2 = createSimpleFlatBuffer();

  encryptBuffer(buf1, SIMPLE_SCHEMA, ctxHex, "SimpleMessage");
  encryptBuffer(buf2, SIMPLE_SCHEMA, ctxBytes, "SimpleMessage");

  assertEquals(Array.from(buf1), Array.from(buf2));
});

// Test 7: Error handling
Deno.test("encryptBuffer - throws on invalid key", () => {
  const buf = createSimpleFlatBuffer();
  const key = crypto.getRandomValues(new Uint8Array(16)); // Invalid size

  assertThrows(
    () => encryptBuffer(buf, SIMPLE_SCHEMA, key, "SimpleMessage"),
    Error,
    "Invalid encryption key"
  );
});
