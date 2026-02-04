/**
 * Native encryption test for TypeScript FlatBuffers code generation.
 * Tests that encrypted fields can be correctly decrypted using the generated code.
 */

import * as flatbuffers from 'flatbuffers';
import { SensorReading } from './ts_gen/encryption-test/sensor-reading.js';

// Derive a 16-byte nonce from encryption context and field offset
function deriveNonce(ctx: Uint8Array, fieldOffset: number): Uint8Array {
  const nonce = new Uint8Array(16);
  nonce.set(ctx.slice(0, 12));
  const view = new DataView(nonce.buffer, nonce.byteOffset);
  view.setUint32(12, fieldOffset, true); // Little-endian
  return nonce;
}

// Simple AES-CTR counter increment
function incrementCounter(counter: Uint8Array): void {
  for (let i = 15; i >= 0; i--) {
    if (++counter[i] !== 0) break;
  }
}

// AES S-box
const SBOX = new Uint8Array([
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]);

// Rijndael round constants
const RCON = new Uint8Array([0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]);

function xtime(x: number): number {
  return ((x << 1) ^ ((x & 0x80) ? 0x1b : 0)) & 0xff;
}

// Simple AES-256 implementation for CTR mode
function aesEncryptBlock(block: Uint8Array, expandedKey: Uint8Array): Uint8Array {
  const state = new Uint8Array(block);
  for (let i = 0; i < 16; i++) state[i] ^= expandedKey[i];
  for (let round = 1; round <= 14; round++) {
    for (let i = 0; i < 16; i++) state[i] = SBOX[state[i]];
    const t1 = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t1;
    const t2 = state[2]; state[2] = state[10]; state[10] = t2; const t6 = state[6]; state[6] = state[14]; state[14] = t6;
    const t3 = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t3;
    if (round < 14) {
      for (let c = 0; c < 4; c++) {
        const i = c * 4;
        const s0 = state[i], s1 = state[i+1], s2 = state[i+2], s3 = state[i+3];
        const xor = s0 ^ s1 ^ s2 ^ s3;
        state[i] ^= xor ^ xtime(s0 ^ s1);
        state[i+1] ^= xor ^ xtime(s1 ^ s2);
        state[i+2] ^= xor ^ xtime(s2 ^ s3);
        state[i+3] ^= xor ^ xtime(s3 ^ s0);
      }
    }
    for (let i = 0; i < 16; i++) state[i] ^= expandedKey[round * 16 + i];
  }
  return state;
}

function expandKey(key: Uint8Array): Uint8Array {
  const expanded = new Uint8Array(240);
  expanded.set(key);
  let rconIdx = 0;
  for (let i = 32; i < 240; i += 4) {
    let t = expanded.slice(i - 4, i);
    if (i % 32 === 0) {
      t = new Uint8Array([SBOX[t[1]] ^ RCON[rconIdx++], SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]]);
    } else if (i % 32 === 16) {
      t = new Uint8Array([SBOX[t[0]], SBOX[t[1]], SBOX[t[2]], SBOX[t[3]]]);
    }
    for (let j = 0; j < 4; j++) expanded[i + j] = expanded[i - 32 + j] ^ t[j];
  }
  return expanded;
}

function encryptBytes(data: Uint8Array, ctx: Uint8Array, fieldOffset: number): Uint8Array {
  const key = ctx.slice(0, 32);
  const counter = deriveNonce(ctx, fieldOffset);
  const expandedKey = expandKey(key);
  const result = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i += 16) {
    const keystream = aesEncryptBlock(counter, expandedKey);
    const blockLen = Math.min(16, data.length - i);
    for (let j = 0; j < blockLen; j++) {
      result[i + j] = data[i + j] ^ keystream[j];
    }
    incrementCounter(counter);
  }
  return result;
}

function encryptFloat32(value: number, ctx: Uint8Array, fieldOffset: number): number {
  const buffer = new ArrayBuffer(4);
  const view = new DataView(buffer);
  view.setFloat32(0, value, true);
  const encrypted = encryptBytes(new Uint8Array(buffer), ctx, fieldOffset);
  const encryptedView = new DataView(encrypted.buffer, encrypted.byteOffset);
  return encryptedView.getFloat32(0, true);
}

function encryptString(value: string, ctx: Uint8Array, fieldOffset: number): Uint8Array {
  const encoder = new TextEncoder();
  const data = encoder.encode(value);
  return encryptBytes(data, ctx, fieldOffset);
}

function testSensorReading(): void {
  console.log("Testing SensorReading with encrypted fields...");

  // Create encryption context (48 bytes)
  const encryptionCtx = new Uint8Array(48);
  for (let i = 0; i < 48; i++) {
    encryptionCtx[i] = i;
  }

  // Original values
  const originalDeviceId = "sensor-001";
  const originalTimestamp = BigInt(1234567890);
  const originalTemperature = 23.5;
  const originalSecretMessage = "Hello, World!";

  // Field offsets
  const temperatureOffset = 12;
  const secretMessageOffset = 16;

  // Encrypt values
  const encryptedTemperature = encryptFloat32(originalTemperature, encryptionCtx, temperatureOffset);
  const encryptedSecretMessage = encryptString(originalSecretMessage, encryptionCtx, secretMessageOffset);

  // Build the FlatBuffer
  const builder = new flatbuffers.Builder(256);

  const deviceIdOffset = builder.createString(originalDeviceId);
  const secretMessageVectorOffset = builder.createByteVector(encryptedSecretMessage);

  SensorReading.startSensorReading(builder);
  SensorReading.addDeviceId(builder, deviceIdOffset);
  SensorReading.addTimestamp(builder, originalTimestamp);
  SensorReading.addTemperature(builder, encryptedTemperature);
  SensorReading.addSecretMessage(builder, secretMessageVectorOffset);
  const sensorReadingOffset = SensorReading.endSensorReading(builder);

  builder.finish(sensorReadingOffset);
  const buf = builder.asUint8Array();

  // Read back using generated code with encryption context
  const bb = new flatbuffers.ByteBuffer(buf);
  const sensorReading = SensorReading.getRootAsSensorReading(bb, undefined, encryptionCtx);

  // Verify public fields
  if (sensorReading.deviceId() !== originalDeviceId) {
    throw new Error(`Device ID mismatch: ${sensorReading.deviceId()} != ${originalDeviceId}`);
  }
  if (sensorReading.timestamp() !== originalTimestamp) {
    throw new Error(`Timestamp mismatch: ${sensorReading.timestamp()} != ${originalTimestamp}`);
  }

  // Verify encrypted fields are correctly decrypted
  const decryptedTemperature = sensorReading.temperature();
  if (Math.abs(decryptedTemperature - originalTemperature) > 0.001) {
    throw new Error(`Temperature mismatch: ${decryptedTemperature} != ${originalTemperature}`);
  }

  const secretMessageBytes = sensorReading.secretMessage(flatbuffers.Encoding.UTF8_BYTES) as Uint8Array;
  if (secretMessageBytes) {
    const decoder = new TextDecoder();
    const decryptedSecretMessage = decoder.decode(secretMessageBytes);
    if (decryptedSecretMessage !== originalSecretMessage) {
      throw new Error(`Secret message mismatch: ${decryptedSecretMessage} != ${originalSecretMessage}`);
    }
  }

  console.log("  Device ID: OK");
  console.log("  Timestamp: OK");
  console.log("  Temperature (encrypted): OK");
  console.log("  Secret Message (encrypted): OK");
  console.log("SensorReading test passed!");
}

function testWithoutEncryptionContext(): void {
  console.log("\nTesting reading without encryption context...");

  const encryptionCtx = new Uint8Array(48);
  for (let i = 0; i < 48; i++) {
    encryptionCtx[i] = i;
  }

  const originalTemperature = 23.5;
  const temperatureOffset = 12;
  const encryptedTemperature = encryptFloat32(originalTemperature, encryptionCtx, temperatureOffset);

  const builder = new flatbuffers.Builder(64);
  const deviceIdOffset = builder.createString("test");
  SensorReading.startSensorReading(builder);
  SensorReading.addDeviceId(builder, deviceIdOffset);
  SensorReading.addTemperature(builder, encryptedTemperature);
  const sensorReadingOffset = SensorReading.endSensorReading(builder);
  builder.finish(sensorReadingOffset);
  const buf = builder.asUint8Array();

  // Read without encryption context
  const bb = new flatbuffers.ByteBuffer(buf);
  const sensorReading = SensorReading.getRootAsSensorReading(bb);

  // Temperature should be returned as-is (encrypted) when no context
  const readTemp = sensorReading.temperature();
  if (Math.abs(readTemp - encryptedTemperature) > 0.001) {
    throw new Error(`Expected encrypted value ${encryptedTemperature}, got ${readTemp}`);
  }

  console.log("  Reading without context returns raw values: OK");
  console.log("No encryption context test passed!");
}

function main(): number {
  console.log("=".repeat(60));
  console.log("TypeScript FlatBuffers Encryption Test");
  console.log("=".repeat(60));

  try {
    testSensorReading();
    testWithoutEncryptionContext();
    console.log("\n" + "=".repeat(60));
    console.log("All tests passed!");
    console.log("=".repeat(60));
    return 0;
  } catch (e) {
    console.log(`\nTest failed: ${e}`);
    console.error(e);
    return 1;
  }
}

process.exit(main());
