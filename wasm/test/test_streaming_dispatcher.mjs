#!/usr/bin/env node
/**
 * Tests for the Streaming Message Dispatcher
 *
 * This test compiles the dispatcher to WASM and validates:
 * - Type registration
 * - Message parsing from wire format
 * - Ring buffer behavior
 * - Statistics tracking
 * - Multi-type routing
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

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SRC_DIR = path.join(__dirname, '..', 'src');
const BUILD_DIR = path.join(__dirname, 'build-streaming');
const REPO_ROOT = path.join(__dirname, '..', '..');

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

async function test(name, fn) {
  try {
    await fn();
    passed++;
    log(`  ✓ ${name}`);
  } catch (err) {
    failed++;
    log(`  ✗ ${name}`);
    log(`    Error: ${err.message}`);
    if (process.env.DEBUG) {
      console.error(err.stack);
    }
  }
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
  log('Streaming Message Dispatcher Tests');
  log('============================================================\n');

  if (!checkEmcc()) {
    log('emcc not found - skipping WASM tests');
    process.exit(0);
  }

  // Setup
  if (fs.existsSync(BUILD_DIR)) {
    fs.rmSync(BUILD_DIR, { recursive: true });
  }
  fs.mkdirSync(BUILD_DIR, { recursive: true });

  // Copy source files
  fs.copyFileSync(
    path.join(SRC_DIR, 'streaming-dispatcher.h'),
    path.join(BUILD_DIR, 'streaming-dispatcher.h')
  );
  fs.copyFileSync(
    path.join(SRC_DIR, 'streaming-dispatcher.cpp'),
    path.join(BUILD_DIR, 'streaming-dispatcher.cpp')
  );

  log('[Compilation]');

  await test('compiles dispatcher to WASM', async () => {
    const result = spawnSync('emcc', [
      path.join(BUILD_DIR, 'streaming-dispatcher.cpp'),
      '-o', path.join(BUILD_DIR, 'dispatcher.mjs'),
      '-I', BUILD_DIR,
      '-s', 'EXPORTED_FUNCTIONS=["_malloc","_free","_dispatcher_init","_dispatcher_reset","_dispatcher_get_type_count","_dispatcher_register_type","_dispatcher_find_type","_dispatcher_get_input_buffer","_dispatcher_get_input_buffer_size","_dispatcher_push_bytes","_dispatcher_get_message_count","_dispatcher_get_total_received","_dispatcher_get_message","_dispatcher_get_latest_message","_dispatcher_clear_messages","_dispatcher_get_type_file_id","_dispatcher_get_type_buffer","_dispatcher_get_type_message_size","_dispatcher_get_type_capacity"]',
      '-s', 'EXPORTED_RUNTIME_METHODS=["HEAPU8"]',
      '-s', 'MODULARIZE=1',
      '-s', 'EXPORT_ES6=1',
      '-s', 'ALLOW_MEMORY_GROWTH=1',
      '-O2',
    ], { stdio: 'pipe' });

    if (result.status !== 0) {
      throw new Error(`Compile failed: ${result.stderr?.toString()}`);
    }
  });

  log('\n[Type Registration]');

  let dispatcher;
  let wasm;

  await test('creates dispatcher instance', async () => {
    const createModule = (await import(path.join(BUILD_DIR, 'dispatcher.mjs'))).default;
    wasm = await createModule();
    dispatcher = new StreamingDispatcher(wasm);
    assert(dispatcher !== null, 'Dispatcher should be created');
  });

  await test('registers message type "MON1"', async () => {
    const info = dispatcher.registerType('MON1', 32, 16);
    assertEqual(info.fileId, 'MON1');
    assertEqual(info.messageSize, 32);
    assertEqual(info.capacity, 16);
    assertEqual(info.typeIndex, 0);
  });

  await test('registers message type "WEAP"', async () => {
    const info = dispatcher.registerType('WEAP', 24, 8);
    assertEqual(info.fileId, 'WEAP');
    assertEqual(info.messageSize, 24);
    assertEqual(info.capacity, 8);
    assertEqual(info.typeIndex, 1);
  });

  await test('returns existing info for duplicate registration', async () => {
    const info = dispatcher.registerType('MON1', 32, 16);
    assertEqual(info.typeIndex, 0, 'Should return existing type index');
  });

  await test('rejects invalid file ID', async () => {
    let threw = false;
    try {
      dispatcher.registerType('TOOLONG', 32, 16);
    } catch (e) {
      threw = true;
    }
    assert(threw, 'Should throw for invalid file ID');
  });

  log('\n[Message Parsing]');

  await test('parses single message', async () => {
    // Create a 32-byte message with MON1 identifier
    const data = new Uint8Array(28); // 32 - 4 (file_id is included in size)
    data[0] = 0x42; // some marker byte
    const msg = createSizePrefixedMessage('MON1', data);

    const parsed = dispatcher.pushBytes(msg);
    assertEqual(parsed, 1, 'Should parse 1 message');
    assertEqual(dispatcher.getMessageCount('MON1'), 1);
  });

  await test('parses multiple messages of same type', async () => {
    dispatcher.clearMessages('MON1');

    const data1 = new Uint8Array(28);
    data1[0] = 0x01;
    const data2 = new Uint8Array(28);
    data2[0] = 0x02;
    const data3 = new Uint8Array(28);
    data3[0] = 0x03;

    const stream = concatMessages(
      createSizePrefixedMessage('MON1', data1),
      createSizePrefixedMessage('MON1', data2),
      createSizePrefixedMessage('MON1', data3)
    );

    const parsed = dispatcher.pushBytes(stream);
    assertEqual(parsed, 3, 'Should parse 3 messages');
    assertEqual(dispatcher.getMessageCount('MON1'), 3);
  });

  await test('parses messages of different types', async () => {
    dispatcher.reset();

    const mon = new Uint8Array(28);
    mon[0] = 0xAA;
    const weap = new Uint8Array(20); // 24 - 4
    weap[0] = 0xBB;

    const stream = concatMessages(
      createSizePrefixedMessage('MON1', mon),
      createSizePrefixedMessage('WEAP', weap),
      createSizePrefixedMessage('MON1', mon)
    );

    const parsed = dispatcher.pushBytes(stream);
    assertEqual(parsed, 3, 'Should parse 3 messages');
    assertEqual(dispatcher.getMessageCount('MON1'), 2);
    assertEqual(dispatcher.getMessageCount('WEAP'), 1);
  });

  await test('handles partial messages (streaming)', async () => {
    dispatcher.reset();

    const data = new Uint8Array(28);
    data[0] = 0xFF;
    const fullMsg = createSizePrefixedMessage('MON1', data);

    // Send first half
    const half1 = fullMsg.slice(0, 20);
    let parsed = dispatcher.pushBytes(half1);
    assertEqual(parsed, 0, 'Should not parse incomplete message');
    assertEqual(dispatcher.getMessageCount('MON1'), 0);

    // Send second half
    const half2 = fullMsg.slice(20);
    parsed = dispatcher.pushBytes(half2);
    assertEqual(parsed, 1, 'Should parse completed message');
    assertEqual(dispatcher.getMessageCount('MON1'), 1);
  });

  await test('ignores unknown message types', async () => {
    dispatcher.reset();

    const unknown = new Uint8Array(16);
    const stream = concatMessages(
      createSizePrefixedMessage('UNKN', unknown),
      createSizePrefixedMessage('MON1', new Uint8Array(28))
    );

    const parsed = dispatcher.pushBytes(stream);
    assertEqual(parsed, 1, 'Should only parse known type');
    assertEqual(dispatcher.getMessageCount('MON1'), 1);
  });

  log('\n[Message Access]');

  await test('retrieves message by index', async () => {
    dispatcher.reset();

    const data1 = new Uint8Array(28);
    data1[0] = 0x11;
    data1[1] = 0x22;
    const data2 = new Uint8Array(28);
    data2[0] = 0x33;
    data2[1] = 0x44;

    dispatcher.pushBytes(concatMessages(
      createSizePrefixedMessage('MON1', data1),
      createSizePrefixedMessage('MON1', data2)
    ));

    const msg0 = dispatcher.getMessage('MON1', 0);
    assertEqual(msg0[4], 0x11, 'First message byte 0'); // offset 4 for file_id
    assertEqual(msg0[5], 0x22, 'First message byte 1');

    const msg1 = dispatcher.getMessage('MON1', 1);
    assertEqual(msg1[4], 0x33, 'Second message byte 0');
    assertEqual(msg1[5], 0x44, 'Second message byte 1');
  });

  await test('retrieves latest message', async () => {
    const latest = dispatcher.getLatestMessage('MON1');
    assertEqual(latest[4], 0x33, 'Latest should be second message');
  });

  await test('returns null for out-of-bounds index', async () => {
    const msg = dispatcher.getMessage('MON1', 999);
    assertEqual(msg, null, 'Should return null');
  });

  await test('returns null for unknown type', async () => {
    const msg = dispatcher.getMessage('NOPE', 0);
    assertEqual(msg, null, 'Should return null');
  });

  log('\n[Ring Buffer Behavior]');

  await test('ring buffer wraps around', async () => {
    dispatcher.reset();

    // Register type with capacity 4
    dispatcher.registerType('RING', 16, 4);

    // Push 6 messages (should keep last 4)
    for (let i = 0; i < 6; i++) {
      const data = new Uint8Array(12); // 16 - 4
      data[0] = i + 1; // 1, 2, 3, 4, 5, 6
      dispatcher.pushBytes(createSizePrefixedMessage('RING', data));
    }

    assertEqual(dispatcher.getMessageCount('RING'), 4, 'Should have 4 messages');

    // Should have messages 3, 4, 5, 6 (oldest to newest)
    const msg0 = dispatcher.getMessage('RING', 0);
    assertEqual(msg0[4], 3, 'Oldest should be 3');

    const msg3 = dispatcher.getMessage('RING', 3);
    assertEqual(msg3[4], 6, 'Newest should be 6');
  });

  log('\n[Statistics]');

  await test('tracks total received count', async () => {
    dispatcher.reset();
    dispatcher.registerType('STAT', 16, 4);

    for (let i = 0; i < 10; i++) {
      dispatcher.pushBytes(createSizePrefixedMessage('STAT', new Uint8Array(12)));
    }

    const stats = dispatcher.getStats('STAT');
    assertEqual(stats.count, 4, 'Should have 4 stored');
    assertEqual(stats.totalReceived, 10, 'Should have received 10');
  });

  log('\n[Iterator]');

  await test('iterates over messages', async () => {
    dispatcher.reset();

    for (let i = 0; i < 3; i++) {
      const data = new Uint8Array(28);
      data[0] = i * 10;
      dispatcher.pushBytes(createSizePrefixedMessage('MON1', data));
    }

    let count = 0;
    const values = [];
    for (const msg of dispatcher.iterMessages('MON1')) {
      values.push(msg[4]); // byte 4 has our marker
      count++;
    }

    assertEqual(count, 3);
    assertEqual(values[0], 0);
    assertEqual(values[1], 10);
    assertEqual(values[2], 20);
  });

  log('\n[Input Buffer]');

  await test('provides input buffer for direct writes', async () => {
    const buf = dispatcher.getInputBuffer();
    assert(buf.ptr > 0, 'Should have valid pointer');
    assert(buf.size >= 1024, 'Should have reasonable size');
    assert(buf.view instanceof Uint8Array, 'Should provide Uint8Array view');
    assertEqual(buf.view.length, buf.size, 'View length should match size');
  });

  // Cleanup
  if (!process.env.KEEP_BUILD) {
    fs.rmSync(BUILD_DIR, { recursive: true });
  }

  log('\n============================================================');
  log(`Results: ${passed} passed, ${failed} failed`);
  log('============================================================');

  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch(err => {
  console.error('Test failed:', err);
  process.exit(1);
});
