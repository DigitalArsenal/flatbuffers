#!/usr/bin/env node
/**
 * Generate test vectors for cross-language encryption testing.
 *
 * This script creates FlatBuffers with various complex field types,
 * encrypts them with known keys, and outputs test vectors that can
 * be verified in Python, Go, Rust, and Deno.
 *
 * Usage: node generate_test_vectors.mjs > test_vectors.json
 */

import { FlatcRunner } from "flatc-wasm";
import {
  EncryptionContext,
  encryptBuffer,
  decryptBuffer,
} from "flatc-wasm/encryption";

// Deterministic key for reproducible tests
const TEST_KEY = new Uint8Array([
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
  0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
]);

// Comprehensive test schema
const FULL_SCHEMA = `
attribute "encrypted";
namespace EncryptionTest;

struct Coordinates {
  lat: double;
  lon: double;
}

table SensorReading {
  // Public fields
  device_id: string;
  timestamp: uint64;

  // Encrypted fields of various types
  location: Coordinates (encrypted);
  temperature: float (encrypted);
  raw_data: [ubyte] (encrypted);
  secret_message: string (encrypted);
  readings: [float] (encrypted);
}

root_type SensorReading;
`;

// Schema with all scalar types
const SCALAR_SCHEMA = `
attribute "encrypted";
namespace ScalarTest;

table AllScalars {
  // All scalar types encrypted
  bool_val: bool (encrypted);
  byte_val: byte (encrypted);
  ubyte_val: ubyte (encrypted);
  short_val: short (encrypted);
  ushort_val: ushort (encrypted);
  int_val: int (encrypted);
  uint_val: uint (encrypted);
  long_val: long (encrypted);
  ulong_val: ulong (encrypted);
  float_val: float (encrypted);
  double_val: double (encrypted);
}

root_type AllScalars;
`;

// Simple schema
const SIMPLE_SCHEMA = `
attribute "encrypted";
table SimpleMessage {
  public_text: string;
  secret_number: int (encrypted);
  secret_text: string (encrypted);
}
root_type SimpleMessage;
`;

function toHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function fromHex(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

async function main() {
  const flatc = await FlatcRunner.init();
  const ctx = new EncryptionContext(TEST_KEY);

  const testVectors = {
    key_hex: toHex(TEST_KEY),
    flatc_version: flatc.version(),
    vectors: [],
  };

  // Test 1: Simple message
  {
    const schemaInput = {
      entry: "/simple.fbs",
      files: { "/simple.fbs": SIMPLE_SCHEMA },
    };

    const data = {
      public_text: "Hello, World!",
      secret_number: 42,
      secret_text: "This is secret",
    };

    const buffer = flatc.generateBinary(schemaInput, JSON.stringify(data));
    const originalHex = toHex(buffer);

    encryptBuffer(buffer, SIMPLE_SCHEMA, ctx, "SimpleMessage");
    const encryptedHex = toHex(buffer);

    testVectors.vectors.push({
      name: "simple_message",
      schema: SIMPLE_SCHEMA,
      root_type: "SimpleMessage",
      original_json: data,
      original_hex: originalHex,
      encrypted_hex: encryptedHex,
    });
  }

  // Test 2: Sensor reading with struct and vectors
  {
    const schemaInput = {
      entry: "/sensor.fbs",
      files: { "/sensor.fbs": FULL_SCHEMA },
    };

    const data = {
      device_id: "sensor-001",
      timestamp: 1699900000,
      location: { lat: 37.7749, lon: -122.4194 },
      temperature: 23.5,
      raw_data: [0x01, 0x02, 0x03, 0x04, 0x05],
      secret_message: "Encrypted sensor data",
      readings: [1.1, 2.2, 3.3, 4.4, 5.5],
    };

    const buffer = flatc.generateBinary(schemaInput, JSON.stringify(data));
    const originalHex = toHex(buffer);

    encryptBuffer(buffer, FULL_SCHEMA, ctx, "SensorReading");
    const encryptedHex = toHex(buffer);

    testVectors.vectors.push({
      name: "sensor_reading",
      schema: FULL_SCHEMA,
      root_type: "SensorReading",
      original_json: data,
      original_hex: originalHex,
      encrypted_hex: encryptedHex,
    });
  }

  // Test 3: All scalar types
  {
    const schemaInput = {
      entry: "/scalar.fbs",
      files: { "/scalar.fbs": SCALAR_SCHEMA },
    };

    const data = {
      bool_val: true,
      byte_val: -42,
      ubyte_val: 200,
      short_val: -1000,
      ushort_val: 50000,
      int_val: -123456789,
      uint_val: 3000000000,
      long_val: -9223372036854775807n,
      ulong_val: 18446744073709551615n,
      float_val: 3.14159,
      double_val: 2.718281828459045,
    };

    // Manually serialize bigints for JSON
    const jsonData = {
      bool_val: data.bool_val,
      byte_val: data.byte_val,
      ubyte_val: data.ubyte_val,
      short_val: data.short_val,
      ushort_val: data.ushort_val,
      int_val: data.int_val,
      uint_val: data.uint_val,
      long_val: String(data.long_val),
      ulong_val: String(data.ulong_val),
      float_val: data.float_val,
      double_val: data.double_val,
    };

    const buffer = flatc.generateBinary(schemaInput, JSON.stringify(jsonData));
    const originalHex = toHex(buffer);

    encryptBuffer(buffer, SCALAR_SCHEMA, ctx, "AllScalars");
    const encryptedHex = toHex(buffer);

    testVectors.vectors.push({
      name: "all_scalars",
      schema: SCALAR_SCHEMA,
      root_type: "AllScalars",
      original_json: jsonData,
      original_hex: originalHex,
      encrypted_hex: encryptedHex,
    });
  }

  // Test 4: Edge cases - empty strings, zero values
  {
    const schemaInput = {
      entry: "/simple.fbs",
      files: { "/simple.fbs": SIMPLE_SCHEMA },
    };

    const data = {
      public_text: "",
      secret_number: 0,
      secret_text: "",
    };

    const buffer = flatc.generateBinary(schemaInput, JSON.stringify(data));
    const originalHex = toHex(buffer);

    encryptBuffer(buffer, SIMPLE_SCHEMA, ctx, "SimpleMessage");
    const encryptedHex = toHex(buffer);

    testVectors.vectors.push({
      name: "edge_cases_empty",
      schema: SIMPLE_SCHEMA,
      root_type: "SimpleMessage",
      original_json: data,
      original_hex: originalHex,
      encrypted_hex: encryptedHex,
    });
  }

  // Test 5: Large values
  {
    const schemaInput = {
      entry: "/simple.fbs",
      files: { "/simple.fbs": SIMPLE_SCHEMA },
    };

    const data = {
      public_text: "A".repeat(1000),
      secret_number: 2147483647, // MAX_INT32
      secret_text: "B".repeat(500),
    };

    const buffer = flatc.generateBinary(schemaInput, JSON.stringify(data));
    const originalHex = toHex(buffer);

    encryptBuffer(buffer, SIMPLE_SCHEMA, ctx, "SimpleMessage");
    const encryptedHex = toHex(buffer);

    testVectors.vectors.push({
      name: "large_values",
      schema: SIMPLE_SCHEMA,
      root_type: "SimpleMessage",
      original_json: data,
      original_hex: originalHex,
      encrypted_hex: encryptedHex,
    });
  }

  console.log(JSON.stringify(testVectors, null, 2));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
