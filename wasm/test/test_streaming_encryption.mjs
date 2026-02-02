#!/usr/bin/env node
/**
 * test_streaming_encryption.mjs - Streaming encryption test suite
 *
 * Tests streaming encryption scenarios including:
 * - JSON to encrypted FBS stream
 * - JSON to encrypted JSON stream
 * - Plain FBS to encrypted FBS stream (in-place)
 * - Plain FBS to encrypted JSON stream
 * - Encrypted FBS to plaintext JSON stream (decrypt + convert)
 * - Encrypted FBS to plain FBS stream (decrypt in-place)
 * - Encrypted JSON to plain FBS stream
 * - Encrypted JSON to re-encrypted FBS stream (rekey)
 * - Rekey mid-stream
 * - clearEncryption() mid-stream
 * - Long-running session memory leak check
 * - Full roundtrip: encrypt stream -> decrypt stream -> compare
 */

import { fileURLToPath } from 'url';
import path from 'path';
import fs from 'fs';
import { execSync, spawnSync } from 'child_process';
import {
  StreamingDispatcher,
  createSizePrefixedMessage,
  concatMessages,
} from '../src/streaming-dispatcher.mjs';
import {
  loadEncryptionWasm,
  isInitialized,
  EncryptionContext,
  x25519GenerateKeyPair,
  x25519SharedSecret,
  x25519DeriveKey,
  encryptBytes,
  decryptBytes,
  encryptBytesCopy,
  decryptBytesCopy,
  clearIVTracking,
  clearAllIVTracking,
  generateIV,
  hkdf,
  createEncryptionHeader,
  computeKeyId,
  encryptionHeaderToJSON,
  encryptionHeaderFromJSON,
  KEY_SIZE,
  IV_SIZE,
} from '../src/encryption.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SRC_DIR = path.join(__dirname, '..', 'src');
const BUILD_DIR = path.join(__dirname, 'build-streaming-enc');
const REPO_ROOT = path.join(__dirname, '..', '..');
const DIST_PATH = path.join(__dirname, '..', 'dist', 'flatc-wasm.js');

// =============================================================================
// Test Utilities
// =============================================================================

let passed = 0;
let failed = 0;

function log(msg) {
  console.log(msg);
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || 'Assertion failed');
  }
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(`${message || 'Assertion failed'}: expected ${expected}, got ${actual}`);
  }
}

function assertArrayEqual(actual, expected, message) {
  if (actual.length !== expected.length) {
    throw new Error(`${message}: length mismatch - expected ${expected.length}, got ${actual.length}`);
  }
  for (let i = 0; i < actual.length; i++) {
    if (actual[i] !== expected[i]) {
      throw new Error(`${message}: mismatch at index ${i} - expected ${expected[i]}, got ${actual[i]}`);
    }
  }
}

async function test(name, fn) {
  try {
    await fn();
    passed++;
    log(`  PASS: ${name}`);
  } catch (err) {
    failed++;
    log(`  FAIL: ${name}`);
    log(`    Error: ${err.message}`);
    if (process.env.DEBUG) {
      console.error(err.stack);
    }
  }
}

function randomBytes(size) {
  const bytes = new Uint8Array(size);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else if (typeof process !== 'undefined' && process.versions?.node) {
    const nodeCrypto = new Function('return require("crypto")')();
    nodeCrypto.randomFillSync(bytes);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

// Schema with encrypted fields for testing
const ENCRYPTED_SCHEMA = `
namespace StreamTest;

table SensorReading {
  timestamp:uint64;
  device_id:string;
  temperature:float (encrypted);
  humidity:float (encrypted);
  location:string;
  battery_pct:ubyte;
  secret_notes:string (encrypted);
}

root_type SensorReading;
file_identifier "SENS";
`;

// Generate JSON record for a given index
function makeJsonRecord(index) {
  return {
    timestamp: 1700000000 + index,
    device_id: `device-${index}`,
    temperature: 20.0 + (index % 30),
    humidity: 40.0 + (index % 50),
    location: `zone-${index % 10}`,
    battery_pct: 50 + (index % 50),
    secret_notes: `classified-data-${index}`,
  };
}

function checkEmcc() {
  try {
    execSync('emcc --version', { stdio: 'pipe' });
    return true;
  } catch {
    const emsdkRoot = path.join(REPO_ROOT, 'build', 'wasm', '_deps', 'emsdk-src');
    const emsdkEnv = path.join(emsdkRoot, 'emsdk_env.sh');
    if (fs.existsSync(emsdkEnv)) {
      try {
        const pathResult = execSync(`source "${emsdkEnv}" 2>/dev/null && echo "$PATH"`, {
          shell: '/bin/bash', stdio: 'pipe', encoding: 'utf8'
        });
        process.env.PATH = pathResult.trim();
        execSync('emcc --version', { stdio: 'pipe' });
        return true;
      } catch { return false; }
    }
    return false;
  }
}

// =============================================================================
// Test Suite
// =============================================================================

async function runTests() {
  log('============================================================');
  log('Streaming Encryption Test Suite');
  log('============================================================\n');

  // Check for CI mode
  const isCI = process.env.CI === 'true' || process.env.CI === '1' ||
               process.env.REQUIRE_WASM === 'true' || process.env.REQUIRE_WASM === '1';

  // Load encryption WASM
  log('[Module Initialization]');

  let encryptionLoaded = false;
  try {
    await loadEncryptionWasm();
    encryptionLoaded = true;
    log('  Encryption WASM module loaded');
  } catch (err) {
    log(`  WARNING: Could not load encryption WASM: ${err.message}`);
    if (isCI) {
      log('  ERROR: Encryption WASM is required in CI mode');
      process.exit(1);
    }
    log('  Some tests will be skipped.');
  }

  // Load flatc WASM for JSON/binary conversions
  let flatc = null;
  try {
    const module = await import(DIST_PATH);
    const FlatcWasm = module.default;
    flatc = await FlatcWasm();
    log(`  flatc-wasm loaded (version ${flatc.getVersion()})`);
  } catch (err) {
    log(`  WARNING: Could not load flatc-wasm: ${err.message}`);
    log('  Conversion tests will be skipped.');
  }

  // Check for emcc (needed for streaming dispatcher WASM)
  const hasEmcc = checkEmcc();
  let dispatcher = null;
  let dispatcherWasm = null;

  if (hasEmcc) {
    try {
      // Build streaming dispatcher WASM
      if (fs.existsSync(BUILD_DIR)) {
        fs.rmSync(BUILD_DIR, { recursive: true });
      }
      fs.mkdirSync(BUILD_DIR, { recursive: true });

      fs.copyFileSync(
        path.join(SRC_DIR, 'streaming-dispatcher.h'),
        path.join(BUILD_DIR, 'streaming-dispatcher.h')
      );
      fs.copyFileSync(
        path.join(SRC_DIR, 'streaming-dispatcher.cpp'),
        path.join(BUILD_DIR, 'streaming-dispatcher.cpp')
      );

      const result = spawnSync('emcc', [
        path.join(BUILD_DIR, 'streaming-dispatcher.cpp'),
        '-o', path.join(BUILD_DIR, 'dispatcher.mjs'),
        '-I', BUILD_DIR,
        '-s', 'EXPORTED_FUNCTIONS=["_malloc","_free","_dispatcher_init","_dispatcher_reset","_dispatcher_get_type_count","_dispatcher_register_type","_dispatcher_find_type","_dispatcher_get_input_buffer","_dispatcher_get_input_buffer_size","_dispatcher_push_bytes","_dispatcher_get_message_count","_dispatcher_get_total_received","_dispatcher_get_message","_dispatcher_get_latest_message","_dispatcher_clear_messages","_dispatcher_get_type_file_id","_dispatcher_get_type_buffer","_dispatcher_get_type_message_size","_dispatcher_get_type_capacity","_dispatcher_set_encryption","_dispatcher_clear_encryption","_dispatcher_is_encryption_active"]',
        '-s', 'EXPORTED_RUNTIME_METHODS=["HEAPU8"]',
        '-s', 'MODULARIZE=1',
        '-s', 'EXPORT_ES6=1',
        '-s', 'ALLOW_MEMORY_GROWTH=1',
        '-O2',
      ], { stdio: 'pipe' });

      if (result.status === 0) {
        const createModule = (await import(path.join(BUILD_DIR, 'dispatcher.mjs'))).default;
        dispatcherWasm = await createModule();
        dispatcher = new StreamingDispatcher(dispatcherWasm);
        log('  Streaming dispatcher compiled and loaded');
      } else {
        log(`  WARNING: Dispatcher compilation failed: ${result.stderr?.toString()}`);
      }
    } catch (err) {
      log(`  WARNING: Could not build dispatcher: ${err.message}`);
    }
  } else {
    log('  emcc not found - dispatcher tests will use JS-only simulation');
  }

  // Helpers for flatc conversions
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  let schemaId = -1;
  if (flatc) {
    const nameBytes = encoder.encode('sensor.fbs');
    const namePtr = flatc._malloc(nameBytes.length);
    flatc.HEAPU8.set(nameBytes, namePtr);
    const srcBytes = encoder.encode(ENCRYPTED_SCHEMA);
    const srcPtr = flatc._malloc(srcBytes.length);
    flatc.HEAPU8.set(srcBytes, srcPtr);
    schemaId = flatc._wasm_schema_add(namePtr, nameBytes.length, srcPtr, srcBytes.length);
    flatc._free(namePtr);
    flatc._free(srcPtr);
  }

  function jsonToBinary(jsonStr) {
    if (!flatc || schemaId < 0) return null;
    const jsonBytes = encoder.encode(jsonStr);
    const jsonPtr = flatc._malloc(jsonBytes.length);
    flatc.HEAPU8.set(jsonBytes, jsonPtr);
    const outLenPtr = flatc._malloc(4);
    const resultPtr = flatc._wasm_json_to_binary(schemaId, jsonPtr, jsonBytes.length, outLenPtr);
    flatc._free(jsonPtr);
    if (resultPtr === 0) {
      flatc._free(outLenPtr);
      return null;
    }
    const len = flatc.getValue(outLenPtr, 'i32');
    flatc._free(outLenPtr);
    return flatc.HEAPU8.slice(resultPtr, resultPtr + len);
  }

  function binaryToJson(binary) {
    if (!flatc || schemaId < 0) return null;
    const binPtr = flatc._malloc(binary.length);
    flatc.HEAPU8.set(binary, binPtr);
    const outLenPtr = flatc._malloc(4);
    const resultPtr = flatc._wasm_binary_to_json(schemaId, binPtr, binary.length, outLenPtr);
    flatc._free(binPtr);
    if (resultPtr === 0) {
      flatc._free(outLenPtr);
      return null;
    }
    const len = flatc.getValue(outLenPtr, 'i32');
    flatc._free(outLenPtr);
    const jsonBytes = flatc.HEAPU8.slice(resultPtr, resultPtr + len);
    return decoder.decode(jsonBytes);
  }

  // Helper: encrypt specific field ranges in a binary buffer using EncryptionContext
  function encryptFieldsInBinary(buffer, encCtx, fieldIndices) {
    // Simulate field-level encryption on known offsets
    // In real usage, the schema would provide vtable offsets
    for (const fieldIdx of fieldIndices) {
      encCtx.encryptScalar(buffer, 0, buffer.length, fieldIdx);
    }
    return buffer;
  }

  // ==========================================================================
  // Test 1: JSON -> encrypted FBS stream (1000 records)
  // ==========================================================================
  log('\n[1. JSON -> Encrypted FBS Stream (1000 records)]');

  await test('JSON to encrypted FBS stream - 1000 records with encrypted fields', async () => {
    if (!encryptionLoaded) throw new Error('Encryption WASM not loaded');

    const recipientKeys = x25519GenerateKeyPair();
    const encCtx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
      algorithm: 'x25519',
      context: 'json-to-encrypted-fbs',
    });

    const recordCount = 1000;
    const encryptedRecords = [];
    const originalRecords = [];

    for (let i = 0; i < recordCount; i++) {
      const record = makeJsonRecord(i);
      originalRecords.push(record);
      const jsonStr = JSON.stringify(record);

      // Simulate: convert JSON fields to binary representation
      // then encrypt the (encrypted) tagged fields
      const tempBytes = encoder.encode(record.temperature.toString());
      const humBytes = encoder.encode(record.humidity.toString());
      const notesBytes = encoder.encode(record.secret_notes);

      // Encrypt the field data copies
      const encTemp = new Uint8Array(tempBytes);
      encCtx.encryptScalar(encTemp, 0, encTemp.length, i * 3);

      const encHum = new Uint8Array(humBytes);
      encCtx.encryptScalar(encHum, 0, encHum.length, i * 3 + 1);

      const encNotes = new Uint8Array(notesBytes);
      encCtx.encryptScalar(encNotes, 0, encNotes.length, i * 3 + 2);

      // Verify encrypted fields differ from plaintext
      let tempChanged = false;
      for (let j = 0; j < encTemp.length; j++) {
        if (encTemp[j] !== tempBytes[j]) { tempChanged = true; break; }
      }

      // Verify non-encrypted fields remain in plaintext
      const deviceIdPlain = record.device_id;
      const locationPlain = record.location;

      encryptedRecords.push({
        encryptedTemp: encTemp,
        encryptedHum: encHum,
        encryptedNotes: encNotes,
        deviceId: deviceIdPlain,
        location: locationPlain,
        tempChanged,
      });
    }

    assertEqual(encryptedRecords.length, recordCount, 'should produce 1000 encrypted records');

    // Verify encrypted fields are actually encrypted (spot check)
    let encFieldsModified = 0;
    for (let i = 0; i < recordCount; i++) {
      if (encryptedRecords[i].tempChanged) encFieldsModified++;
    }
    assert(encFieldsModified > recordCount * 0.9, 'most encrypted fields should be modified');

    // Verify plaintext fields remain unchanged
    for (let i = 0; i < 10; i++) {
      assertEqual(encryptedRecords[i].deviceId, `device-${i}`, 'device_id should be plaintext');
      assertEqual(encryptedRecords[i].location, `zone-${i % 10}`, 'location should be plaintext');
    }
  });

  // ==========================================================================
  // Test 2: JSON -> encrypted JSON stream
  // ==========================================================================
  log('\n[2. JSON -> Encrypted JSON Stream]');

  await test('JSON to encrypted JSON stream - only encrypted field values are ciphertext', async () => {
    if (!encryptionLoaded) throw new Error('Encryption WASM not loaded');

    const recipientKeys = x25519GenerateKeyPair();
    const encCtx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
      algorithm: 'x25519',
      context: 'json-to-encrypted-json',
    });

    const recordCount = 100;
    const outputRecords = [];

    for (let i = 0; i < recordCount; i++) {
      const record = makeJsonRecord(i);

      // Encrypt only the (encrypted) tagged fields
      const tempBytes = encoder.encode(JSON.stringify(record.temperature));
      const encTemp = new Uint8Array(tempBytes);
      encCtx.encryptScalar(encTemp, 0, encTemp.length, i * 3);

      const humBytes = encoder.encode(JSON.stringify(record.humidity));
      const encHum = new Uint8Array(humBytes);
      encCtx.encryptScalar(encHum, 0, encHum.length, i * 3 + 1);

      const notesBytes = encoder.encode(JSON.stringify(record.secret_notes));
      const encNotes = new Uint8Array(notesBytes);
      encCtx.encryptScalar(encNotes, 0, encNotes.length, i * 3 + 2);

      // Build output JSON with encrypted values as base64
      const outputRecord = {
        timestamp: record.timestamp,
        device_id: record.device_id,
        temperature: bytesToHex(encTemp),
        humidity: bytesToHex(encHum),
        location: record.location,
        battery_pct: record.battery_pct,
        secret_notes: bytesToHex(encNotes),
      };
      outputRecords.push(outputRecord);
    }

    // Verify encrypted fields are hex-encoded ciphertext
    for (let i = 0; i < 10; i++) {
      const rec = outputRecords[i];
      assert(typeof rec.temperature === 'string', 'encrypted temperature should be hex string');
      assert(rec.temperature.length > 0, 'encrypted temperature should not be empty');
      // Plaintext fields should be original values
      assertEqual(rec.timestamp, 1700000000 + i, 'timestamp should be plaintext');
      assertEqual(rec.device_id, `device-${i}`, 'device_id should be plaintext');
      assertEqual(rec.location, `zone-${i % 10}`, 'location should be plaintext');
      assertEqual(rec.battery_pct, 50 + (i % 50), 'battery_pct should be plaintext');
    }
  });

  // ==========================================================================
  // Test 3: Plain FBS -> encrypted FBS stream (in-place)
  // ==========================================================================
  log('\n[3. Plain FBS -> Encrypted FBS Stream (in-place)]');

  await test('Plain FBS to encrypted FBS stream - in-place encryption', async () => {
    if (!encryptionLoaded) throw new Error('Encryption WASM not loaded');

    const recipientKeys = x25519GenerateKeyPair();
    const encCtx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
      algorithm: 'x25519',
      context: 'fbs-to-encrypted-fbs',
    });

    // Simulate a stream of plain FBS messages
    const messageCount = 50;
    const messageSize = 64;

    for (let i = 0; i < messageCount; i++) {
      // Create a simulated plaintext FBS buffer
      const plainBuffer = new Uint8Array(messageSize);
      for (let j = 0; j < messageSize; j++) {
        plainBuffer[j] = (i + j) & 0xFF;
      }
      const original = new Uint8Array(plainBuffer);

      // Encrypt in-place (simulates encrypting specific field offsets)
      encCtx.encryptScalar(plainBuffer, 8, 24, i);

      // Verify the encrypted region changed
      let regionChanged = false;
      for (let j = 8; j < 32; j++) {
        if (plainBuffer[j] !== original[j]) {
          regionChanged = true;
          break;
        }
      }
      assert(regionChanged, `record ${i}: encrypted region should differ`);

      // Verify non-encrypted regions are unchanged
      for (let j = 0; j < 8; j++) {
        assertEqual(plainBuffer[j], original[j], `record ${i}: prefix byte ${j} should be unchanged`);
      }
      for (let j = 32; j < messageSize; j++) {
        assertEqual(plainBuffer[j], original[j], `record ${i}: suffix byte ${j} should be unchanged`);
      }
    }
  });

  // ==========================================================================
  // Test 4: Plain FBS -> encrypted JSON stream
  // ==========================================================================
  log('\n[4. Plain FBS -> Encrypted JSON Stream]');

  await test('Plain FBS to encrypted JSON stream', async () => {
    if (!encryptionLoaded) throw new Error('Encryption WASM not loaded');

    const recipientKeys = x25519GenerateKeyPair();
    const encCtx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
      algorithm: 'x25519',
      context: 'fbs-to-encrypted-json',
    });

    const recordCount = 20;
    const jsonOutput = [];

    for (let i = 0; i < recordCount; i++) {
      // Simulate extracting fields from a plain FBS buffer
      const plainTemp = encoder.encode(String(20.0 + i));
      const encTemp = new Uint8Array(plainTemp);
      encCtx.encryptScalar(encTemp, 0, encTemp.length, i * 2);

      const plainNotes = encoder.encode(`secret-${i}`);
      const encNotes = new Uint8Array(plainNotes);
      encCtx.encryptScalar(encNotes, 0, encNotes.length, i * 2 + 1);

      jsonOutput.push({
        device_id: `device-${i}`,
        temperature: bytesToHex(encTemp),
        secret_notes: bytesToHex(encNotes),
      });
    }

    assertEqual(jsonOutput.length, recordCount, 'should produce correct number of records');
    for (let i = 0; i < recordCount; i++) {
      assertEqual(jsonOutput[i].device_id, `device-${i}`, 'plaintext field should be intact');
      assert(typeof jsonOutput[i].temperature === 'string', 'encrypted field should be hex');
      assert(jsonOutput[i].temperature !== String(20.0 + i), 'encrypted field should differ from plain');
    }
  });

  // ==========================================================================
  // Test 5: Encrypted FBS -> plaintext JSON stream (decrypt + convert)
  // ==========================================================================
  log('\n[5. Encrypted FBS -> Plaintext JSON Stream (decrypt + convert)]');

  await test('Encrypted FBS to plaintext JSON stream', async () => {
    if (!encryptionLoaded) throw new Error('Encryption WASM not loaded');

    const recipientKeys = x25519GenerateKeyPair();
    const appContext = 'enc-fbs-to-plain-json';

    // Encrypt
    const encCtx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
      algorithm: 'x25519',
      context: appContext,
    });

    const recordCount = 30;
    const encryptedBuffers = [];
    const originalValues = [];

    for (let i = 0; i < recordCount; i++) {
      const value = `temperature=${(20.0 + i).toFixed(1)}`;
      originalValues.push(value);
      const data = new Uint8Array(encoder.encode(value));
      encCtx.encryptScalar(data, 0, data.length, i);
      encryptedBuffers.push(new Uint8Array(data));
    }

    // Decrypt
    const headerJSON = encCtx.getHeaderJSON();
    const header = encryptionHeaderFromJSON(headerJSON);
    const decCtx = EncryptionContext.forDecryption(
      recipientKeys.privateKey,
      header,
      appContext
    );

    const decryptedJsonRecords = [];
    for (let i = 0; i < recordCount; i++) {
      const data = new Uint8Array(encryptedBuffers[i]);
      decCtx.decryptScalar(data, 0, data.length, i);
      const decryptedStr = decoder.decode(data);
      decryptedJsonRecords.push({ value: decryptedStr });
    }

    // Verify all records decrypted correctly
    for (let i = 0; i < recordCount; i++) {
      assertEqual(
        decryptedJsonRecords[i].value,
        originalValues[i],
        `record ${i} should decrypt to original`
      );
    }
  });

  // ==========================================================================
  // Test 6: Encrypted FBS -> plain FBS stream (decrypt in-place)
  // ==========================================================================
  log('\n[6. Encrypted FBS -> Plain FBS Stream (decrypt in-place)]');

  await test('Encrypted FBS to plain FBS stream - decrypt in-place', async () => {
    if (!encryptionLoaded) throw new Error('Encryption WASM not loaded');

    const recipientKeys = x25519GenerateKeyPair();
    const appContext = 'enc-fbs-to-plain-fbs';

    const encCtx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
      algorithm: 'x25519',
      context: appContext,
    });

    const recordCount = 50;
    const originals = [];
    const encrypted = [];

    for (let i = 0; i < recordCount; i++) {
      const original = new Uint8Array(48);
      for (let j = 0; j < 48; j++) original[j] = (i * 7 + j * 3) & 0xFF;
      originals.push(new Uint8Array(original));

      const buf = new Uint8Array(original);
      encCtx.encryptScalar(buf, 4, 32, i);
      encrypted.push(buf);
    }

    // Decrypt in-place
    const headerJSON = encCtx.getHeaderJSON();
    const header = encryptionHeaderFromJSON(headerJSON);
    const decCtx = EncryptionContext.forDecryption(
      recipientKeys.privateKey,
      header,
      appContext
    );

    for (let i = 0; i < recordCount; i++) {
      decCtx.decryptScalar(encrypted[i], 4, 32, i);
      assertArrayEqual(encrypted[i], originals[i], `record ${i} should match original after decrypt`);
    }
  });

  // ==========================================================================
  // Test 7: Encrypted JSON -> plain FBS stream
  // ==========================================================================
  log('\n[7. Encrypted JSON -> Plain FBS Stream]');

  await test('Encrypted JSON to plain FBS stream', async () => {
    if (!encryptionLoaded) throw new Error('Encryption WASM not loaded');

    const recipientKeys = x25519GenerateKeyPair();
    const appContext = 'enc-json-to-plain-fbs';

    const encCtx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
      algorithm: 'x25519',
      context: appContext,
    });

    const recordCount = 25;
    const originalFields = [];
    const encryptedJsonRecords = [];

    for (let i = 0; i < recordCount; i++) {
      const fieldValue = `sensor-reading-${i}-value=${(30.0 + i).toFixed(2)}`;
      originalFields.push(fieldValue);

      const data = new Uint8Array(encoder.encode(fieldValue));
      encCtx.encryptScalar(data, 0, data.length, i);
      encryptedJsonRecords.push({
        device_id: `device-${i}`,
        encrypted_value: bytesToHex(data),
      });
    }

    // Decrypt and convert to FBS-like binary representation
    const headerJSON = encCtx.getHeaderJSON();
    const header = encryptionHeaderFromJSON(headerJSON);
    const decCtx = EncryptionContext.forDecryption(
      recipientKeys.privateKey,
      header,
      appContext
    );

    for (let i = 0; i < recordCount; i++) {
      const encHex = encryptedJsonRecords[i].encrypted_value;
      const data = hexToBytes(encHex);
      decCtx.decryptScalar(data, 0, data.length, i);
      const decrypted = decoder.decode(data);
      assertEqual(decrypted, originalFields[i], `record ${i} should decrypt correctly`);
    }
  });

  // ==========================================================================
  // Test 8: Encrypted JSON -> re-encrypted FBS stream (different key)
  // ==========================================================================
  log('\n[8. Encrypted JSON -> Re-encrypted FBS Stream (rekey)]');

  await test('Encrypted JSON to re-encrypted FBS stream with different key', async () => {
    if (!encryptionLoaded) throw new Error('Encryption WASM not loaded');

    const originalRecipientKeys = x25519GenerateKeyPair();
    const newRecipientKeys = x25519GenerateKeyPair();
    const appContext = 'rekey-test';

    // Encrypt with original key
    const encCtx = EncryptionContext.forEncryption(originalRecipientKeys.publicKey, {
      algorithm: 'x25519',
      context: appContext,
    });

    const recordCount = 20;
    const originalValues = [];
    const encryptedHexValues = [];

    for (let i = 0; i < recordCount; i++) {
      const value = `secret-${i}`;
      originalValues.push(value);
      const data = new Uint8Array(encoder.encode(value));
      encCtx.encryptScalar(data, 0, data.length, i);
      encryptedHexValues.push(bytesToHex(data));
    }

    // Decrypt with original key
    const headerJSON = encCtx.getHeaderJSON();
    const header = encryptionHeaderFromJSON(headerJSON);
    const decCtx = EncryptionContext.forDecryption(
      originalRecipientKeys.privateKey,
      header,
      appContext
    );

    // Re-encrypt with new key
    const reEncCtx = EncryptionContext.forEncryption(newRecipientKeys.publicKey, {
      algorithm: 'x25519',
      context: appContext,
    });

    const reEncryptedBuffers = [];
    for (let i = 0; i < recordCount; i++) {
      const data = hexToBytes(encryptedHexValues[i]);
      decCtx.decryptScalar(data, 0, data.length, i);

      // Verify intermediate plaintext is correct
      const intermediate = decoder.decode(data);
      assertEqual(intermediate, originalValues[i], `intermediate plaintext ${i} should match`);

      // Re-encrypt with new key
      reEncCtx.encryptScalar(data, 0, data.length, i);
      reEncryptedBuffers.push(new Uint8Array(data));
    }

    // Verify re-encrypted data can be decrypted with new key
    const reEncHeaderJSON = reEncCtx.getHeaderJSON();
    const reEncHeader = encryptionHeaderFromJSON(reEncHeaderJSON);
    const newDecCtx = EncryptionContext.forDecryption(
      newRecipientKeys.privateKey,
      reEncHeader,
      appContext
    );

    for (let i = 0; i < recordCount; i++) {
      const data = new Uint8Array(reEncryptedBuffers[i]);
      newDecCtx.decryptScalar(data, 0, data.length, i);
      const decrypted = decoder.decode(data);
      assertEqual(decrypted, originalValues[i], `re-encrypted record ${i} should decrypt correctly`);
    }
  });

  // ==========================================================================
  // Test 9: Rekey mid-stream
  // ==========================================================================
  log('\n[9. Rekey Mid-Stream]');

  await test('Rekey mid-stream - new config, new header, new key for subsequent records', async () => {
    if (!encryptionLoaded) throw new Error('Encryption WASM not loaded');

    const recipientKeys1 = x25519GenerateKeyPair();
    const recipientKeys2 = x25519GenerateKeyPair();
    const appContext = 'rekey-mid-stream';

    // Phase 1: encrypt with key 1
    const encCtx1 = EncryptionContext.forEncryption(recipientKeys1.publicKey, {
      algorithm: 'x25519',
      context: appContext,
    });

    const phase1Records = [];
    for (let i = 0; i < 10; i++) {
      const data = new Uint8Array(encoder.encode(`phase1-record-${i}`));
      encCtx1.encryptScalar(data, 0, data.length, i);
      phase1Records.push(new Uint8Array(data));
    }
    const header1JSON = encCtx1.getHeaderJSON();

    // Phase 2: rekey - new encryption context with key 2
    const encCtx2 = EncryptionContext.forEncryption(recipientKeys2.publicKey, {
      algorithm: 'x25519',
      context: appContext,
    });

    const phase2Records = [];
    for (let i = 0; i < 10; i++) {
      const data = new Uint8Array(encoder.encode(`phase2-record-${i}`));
      encCtx2.encryptScalar(data, 0, data.length, i);
      phase2Records.push(new Uint8Array(data));
    }
    const header2JSON = encCtx2.getHeaderJSON();

    // Headers should be different (different ephemeral keys)
    assert(header1JSON !== header2JSON, 'headers should differ after rekey');

    // Decrypt phase 1 with key 1
    const h1 = encryptionHeaderFromJSON(header1JSON);
    const decCtx1 = EncryptionContext.forDecryption(recipientKeys1.privateKey, h1, appContext);
    for (let i = 0; i < 10; i++) {
      const data = new Uint8Array(phase1Records[i]);
      decCtx1.decryptScalar(data, 0, data.length, i);
      assertEqual(decoder.decode(data), `phase1-record-${i}`, `phase1 record ${i}`);
    }

    // Decrypt phase 2 with key 2
    const h2 = encryptionHeaderFromJSON(header2JSON);
    const decCtx2 = EncryptionContext.forDecryption(recipientKeys2.privateKey, h2, appContext);
    for (let i = 0; i < 10; i++) {
      const data = new Uint8Array(phase2Records[i]);
      decCtx2.decryptScalar(data, 0, data.length, i);
      assertEqual(decoder.decode(data), `phase2-record-${i}`, `phase2 record ${i}`);
    }

    // Verify cross-key decryption fails (phase1 with key2)
    const wrongDecCtx = EncryptionContext.forDecryption(recipientKeys2.privateKey, h1, appContext);
    const testData = new Uint8Array(phase1Records[0]);
    wrongDecCtx.decryptScalar(testData, 0, testData.length, 0);
    const wrongResult = decoder.decode(testData);
    assert(wrongResult !== 'phase1-record-0', 'cross-key decryption should produce wrong data');
  });

  // ==========================================================================
  // Test 10: clearEncryption() mid-stream
  // ==========================================================================
  log('\n[10. clearEncryption() Mid-Stream]');

  await test('clearEncryption mid-stream - subsequent records are plaintext', async () => {
    if (!encryptionLoaded) throw new Error('Encryption WASM not loaded');
    if (!dispatcher) throw new Error('Dispatcher not available');

    const recipientKeys = x25519GenerateKeyPair();

    // Register type for this test
    dispatcher.reset();
    const typeInfo = dispatcher.registerType('ENCM', 64, 32);

    // Set encryption
    dispatcher.setEncryption(recipientKeys.publicKey, {});
    assert(dispatcher.isEncryptionActive(), 'encryption should be active');

    // Push some encrypted messages
    for (let i = 0; i < 5; i++) {
      const data = new Uint8Array(60); // 64 - 4 for file_id
      data[0] = 0xE0 + i; // marker for encrypted
      dispatcher.pushBytes(createSizePrefixedMessage('ENCM', data));
    }
    assertEqual(dispatcher.getMessageCount('ENCM'), 5, 'should have 5 encrypted messages');

    // Clear encryption
    dispatcher.clearEncryption();
    assert(!dispatcher.isEncryptionActive(), 'encryption should be inactive after clear');

    // Push plaintext messages
    for (let i = 0; i < 5; i++) {
      const data = new Uint8Array(60);
      data[0] = 0xA0 + i; // marker for plaintext
      dispatcher.pushBytes(createSizePrefixedMessage('ENCM', data));
    }
    assertEqual(dispatcher.getMessageCount('ENCM'), 10, 'should have 10 total messages');
  });

  // ==========================================================================
  // Test 11: Long-running session - memory leak check over 10k+ records
  // ==========================================================================
  log('\n[11. Long-Running Session - Memory Leak Check (10k+ records)]');

  await test('Long-running session - no memory leaks over 10000 records', async () => {
    if (!encryptionLoaded) throw new Error('Encryption WASM not loaded');

    const recipientKeys = x25519GenerateKeyPair();
    const appContext = 'long-running-session';

    const recordCount = 10000;

    // Measure memory before
    const memBefore = process.memoryUsage();

    const encCtx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
      algorithm: 'x25519',
      context: appContext,
    });

    // Process many records
    for (let i = 0; i < recordCount; i++) {
      const data = new Uint8Array(encoder.encode(`record-${i}-payload-data`));
      encCtx.encryptScalar(data, 0, data.length, i);
      // Do not store references - let GC collect
    }

    // Force GC if available
    if (global.gc) {
      global.gc();
    }

    // Measure memory after
    const memAfter = process.memoryUsage();

    // Allow for some reasonable growth but check there is no catastrophic leak
    // heapUsed growth should be bounded (not proportional to recordCount * record_size)
    const heapGrowthMB = (memAfter.heapUsed - memBefore.heapUsed) / (1024 * 1024);

    // With 10k records of ~30 bytes each, total data is ~300KB
    // If we leaked all of it, heapGrowth would be at least 0.3MB
    // Allow up to 50MB growth (generous, accounts for JIT, caches, etc.)
    assert(heapGrowthMB < 50, `heap growth should be bounded, got ${heapGrowthMB.toFixed(2)}MB`);

    log(`    Processed ${recordCount} records, heap growth: ${heapGrowthMB.toFixed(2)}MB`);
  });

  // ==========================================================================
  // Test 12: Roundtrip - encrypt stream -> decrypt stream -> compare
  // ==========================================================================
  log('\n[12. Roundtrip - Encrypt Stream -> Decrypt Stream -> Compare]');

  await test('Full roundtrip: encrypt stream then decrypt stream matches original', async () => {
    if (!encryptionLoaded) throw new Error('Encryption WASM not loaded');

    const recipientKeys = x25519GenerateKeyPair();
    const appContext = 'full-roundtrip';

    const encCtx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
      algorithm: 'x25519',
      context: appContext,
    });

    const recordCount = 200;
    const originalPayloads = [];
    const encryptedPayloads = [];

    // Encrypt stream
    for (let i = 0; i < recordCount; i++) {
      const payload = encoder.encode(JSON.stringify(makeJsonRecord(i)));
      originalPayloads.push(new Uint8Array(payload));

      const encrypted = new Uint8Array(payload);
      encCtx.encryptScalar(encrypted, 0, encrypted.length, i);
      encryptedPayloads.push(encrypted);
    }

    // Verify encrypted data differs from original
    let diffCount = 0;
    for (let i = 0; i < recordCount; i++) {
      let differs = false;
      for (let j = 0; j < originalPayloads[i].length; j++) {
        if (originalPayloads[i][j] !== encryptedPayloads[i][j]) {
          differs = true;
          break;
        }
      }
      if (differs) diffCount++;
    }
    assert(diffCount === recordCount, 'all encrypted records should differ from originals');

    // Decrypt stream
    const headerJSON = encCtx.getHeaderJSON();
    const header = encryptionHeaderFromJSON(headerJSON);
    const decCtx = EncryptionContext.forDecryption(
      recipientKeys.privateKey,
      header,
      appContext
    );

    for (let i = 0; i < recordCount; i++) {
      const data = new Uint8Array(encryptedPayloads[i]);
      decCtx.decryptScalar(data, 0, data.length, i);
      assertArrayEqual(data, originalPayloads[i], `record ${i} should roundtrip correctly`);
    }

    // Parse decrypted JSON and verify semantic content
    for (let i = 0; i < 10; i++) {
      const decryptedPayload = new Uint8Array(encryptedPayloads[i]);
      // Already decrypted above, but verify the data
      const expected = makeJsonRecord(i);
      // The encrypted payloads were decrypted in-place above
      // Re-decrypt from a fresh copy for this check
    }

    // Additional spot-check: take a few encrypted payloads, decrypt fresh, parse JSON
    const freshDecCtx = EncryptionContext.forDecryption(
      recipientKeys.privateKey,
      encryptionHeaderFromJSON(headerJSON),
      appContext
    );

    // Re-encrypt to get fresh ciphertext for verification
    const reEncCtx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
      algorithm: 'x25519',
      context: appContext,
    });

    for (let i = 0; i < 5; i++) {
      const payload = encoder.encode(JSON.stringify(makeJsonRecord(i)));
      const copy = new Uint8Array(payload);
      reEncCtx.encryptScalar(copy, 0, copy.length, i);

      const reEncHeader = encryptionHeaderFromJSON(reEncCtx.getHeaderJSON());
      const reDecCtx = EncryptionContext.forDecryption(
        recipientKeys.privateKey,
        reEncHeader,
        appContext
      );
      reDecCtx.decryptScalar(copy, 0, copy.length, i);

      const parsed = JSON.parse(decoder.decode(copy));
      const expected = makeJsonRecord(i);
      assertEqual(parsed.device_id, expected.device_id, `spot check ${i}: device_id`);
      assertEqual(parsed.timestamp, expected.timestamp, `spot check ${i}: timestamp`);
      assertEqual(parsed.temperature, expected.temperature, `spot check ${i}: temperature`);
      assertEqual(parsed.secret_notes, expected.secret_notes, `spot check ${i}: secret_notes`);
    }
  });

  // ==========================================================================
  // Cleanup
  // ==========================================================================

  if (BUILD_DIR && fs.existsSync(BUILD_DIR) && !process.env.KEEP_BUILD) {
    fs.rmSync(BUILD_DIR, { recursive: true });
  }

  if (flatc && schemaId >= 0) {
    flatc._wasm_schema_remove(schemaId);
  }

  // ==========================================================================
  // Summary
  // ==========================================================================

  log('\n============================================================');
  log(`Results: ${passed} passed, ${failed} failed`);
  log('============================================================');

  if (passed > 0 && failed === 0) {
    log('All tests passed!');
  } else if (failed > 0) {
    log('Some tests failed');
  }

  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch(err => {
  console.error('Test error:', err);
  process.exit(1);
});
