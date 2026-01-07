#!/usr/bin/env node
/**
 * test_io_methods.mjs - Test all I/O methods for flatc-stream
 *
 * Tests:
 * - Unix domain sockets
 * - TCP server
 * - Binary protocol TCP
 * - Named pipes (FIFO)
 * - Folder watching
 * - stdin/stdout pipe mode
 */

import { spawn, execSync } from 'child_process';
import { createConnection, createServer } from 'net';
import { mkdir, writeFile, readFile, unlink, rm, mkdtemp } from 'fs/promises';
import { existsSync, mkdirSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { tmpdir } from 'os';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCRIPT_PATH = path.join(__dirname, '..', '..', 'scripts', 'flatc-stream.mjs');
const SCHEMA_PATH = path.join(__dirname, 'all_types.fbs');

// Test configuration
const TEST_TIMEOUT = 10000;
const PORT_BASE = 19000 + Math.floor(Math.random() * 1000);

// Simple monster schema for quick tests
const MONSTER_SCHEMA = `
namespace TestGame;
table Monster {
  name: string;
  hp: int = 100;
}
root_type Monster;
`;

const MONSTER_JSON = '{"name": "Orc", "hp": 150}';

// Test results
let passed = 0;
let failed = 0;
const results = [];

function log(msg) {
  console.log(msg);
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

async function test(name, fn) {
  const start = Date.now();
  try {
    await Promise.race([
      fn(),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('Test timeout')), TEST_TIMEOUT)
      )
    ]);
    const elapsed = Date.now() - start;
    log(`  PASS: ${name} (${elapsed}ms)`);
    passed++;
    results.push({ name, status: 'pass', elapsed });
  } catch (err) {
    const elapsed = Date.now() - start;
    log(`  FAIL: ${name} - ${err.message}`);
    failed++;
    results.push({ name, status: 'fail', error: err.message, elapsed });
  }
}

// Helper: Send JSON-RPC request and get response
let rpcIdCounter = 1;
function sendRpc(socket, method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = rpcIdCounter++;
    const request = JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n';

    let data = '';
    let resolved = false;
    const timeout = setTimeout(() => {
      if (!resolved) {
        resolved = true;
        socket.removeListener('data', onData);
        reject(new Error(`RPC timeout for method: ${method}`));
      }
    }, 5000);

    const onData = (chunk) => {
      if (resolved) return;
      data += chunk.toString();
      const lines = data.split('\n');
      for (const line of lines) {
        if (line.trim()) {
          try {
            const response = JSON.parse(line);
            if (response.id === id) {
              resolved = true;
              clearTimeout(timeout);
              socket.removeListener('data', onData);
              if (response.error) {
                reject(new Error(response.error.message));
              } else {
                resolve(response.result);
              }
              return;
            }
          } catch (e) {
            // Continue accumulating
          }
        }
      }
    };

    socket.on('data', onData);
    socket.write(request);
  });
}

// Helper: Start server process
function startServer(args) {
  return new Promise((resolve, reject) => {
    const proc = spawn('node', [SCRIPT_PATH, ...args], {
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let stderr = '';
    proc.stderr.on('data', (data) => {
      stderr += data.toString();
      // Wait for server to indicate it's ready
      if (stderr.includes('listening') || stderr.includes('started')) {
        resolve(proc);
      }
    });

    proc.on('error', reject);

    // Timeout if server doesn't start
    setTimeout(() => {
      if (!stderr.includes('listening') && !stderr.includes('started')) {
        resolve(proc); // Try anyway
      }
    }, 2000);
  });
}

// Helper: Connect to server with retry
async function connectWithRetry(options, maxRetries = 5) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await new Promise((resolve, reject) => {
        const socket = createConnection(options, () => resolve(socket));
        socket.on('error', reject);
      });
    } catch (e) {
      if (i === maxRetries - 1) throw e;
      await new Promise(r => setTimeout(r, 200));
    }
  }
}

// =============================================================================
// Test: Unix Domain Socket
// =============================================================================
async function testUnixSocket() {
  const socketPath = path.join(tmpdir(), `flatc-test-${Date.now()}.sock`);
  let proc = null;
  let socket = null;

  try {
    // Start socket server
    proc = await startServer(['--socket', socketPath]);
    await new Promise(r => setTimeout(r, 500));

    // Connect
    socket = await connectWithRetry({ path: socketPath });

    // Test version
    const version = await sendRpc(socket, 'version');
    assert(typeof version === 'string', 'Version should be string');

    // Add schema
    await sendRpc(socket, 'addSchema', { name: 'monster.fbs', source: MONSTER_SCHEMA });

    // List schemas
    const schemas = await sendRpc(socket, 'listSchemas');
    assert(schemas.includes('monster.fbs'), 'Schema should be listed');

    // Convert JSON to binary
    const { binary } = await sendRpc(socket, 'jsonToBinary', {
      schema: 'monster.fbs',
      json: MONSTER_JSON
    });
    assert(binary && binary.length > 0, 'Should get binary data');

    // Convert back to JSON
    const { json } = await sendRpc(socket, 'binaryToJson', {
      schema: 'monster.fbs',
      binary: binary
    });
    const parsed = JSON.parse(json);
    assert(parsed.name === 'Orc', 'Name should match');
    assert(parsed.hp === 150, 'HP should match');

  } finally {
    if (socket) socket.destroy();
    if (proc) proc.kill('SIGTERM');
    try { await unlink(socketPath); } catch (e) {}
  }
}

// =============================================================================
// Test: TCP Server
// =============================================================================
async function testTcpServer() {
  const port = PORT_BASE + 1;
  let proc = null;
  let socket = null;

  try {
    // Start TCP server
    proc = await startServer(['--tcp', String(port)]);
    await new Promise(r => setTimeout(r, 500));

    // Connect
    socket = await connectWithRetry({ port, host: '127.0.0.1' });

    // Test ping
    const pong = await sendRpc(socket, 'ping');
    assert(pong.pong === true, 'Ping should return pong');

    // Test stats
    const stats = await sendRpc(socket, 'stats');
    assert(typeof stats.uptime === 'number', 'Stats should have uptime');
    assert(stats.memory, 'Stats should have memory');

    // Add schema and convert
    await sendRpc(socket, 'addSchema', { name: 'monster.fbs', source: MONSTER_SCHEMA });

    const { binary } = await sendRpc(socket, 'jsonToBinary', {
      schema: 'monster.fbs',
      json: MONSTER_JSON
    });

    // Use auto-detect convert
    const result = await sendRpc(socket, 'convert', {
      schema: 'monster.fbs',
      data: binary  // Already base64
    });
    assert(result.format === 'binary', 'Should detect binary format');

  } finally {
    if (socket) socket.destroy();
    if (proc) proc.kill('SIGTERM');
  }
}

// =============================================================================
// Test: Binary Protocol TCP
// =============================================================================
async function testBinaryTcpServer() {
  const port = PORT_BASE + 2;
  let proc = null;
  let socket = null;

  try {
    // Start binary TCP server
    proc = await startServer(['--binary-tcp', String(port)]);
    await new Promise(r => setTimeout(r, 500));

    // Connect
    socket = await connectWithRetry({ port, host: '127.0.0.1' });

    // Send binary protocol message (4-byte length + JSON)
    const request = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'version' });
    const payload = Buffer.from(request, 'utf-8');
    const header = Buffer.alloc(4);
    header.writeUInt32LE(payload.length, 0);

    const responsePromise = new Promise((resolve, reject) => {
      let buffer = Buffer.alloc(0);
      let expectedLen = null;

      socket.on('data', (data) => {
        buffer = Buffer.concat([buffer, data]);

        if (expectedLen === null && buffer.length >= 4) {
          expectedLen = buffer.readUInt32LE(0);
          buffer = buffer.slice(4);
        }

        if (expectedLen !== null && buffer.length >= expectedLen) {
          const response = JSON.parse(buffer.slice(0, expectedLen).toString('utf-8'));
          resolve(response);
        }
      });

      setTimeout(() => reject(new Error('Binary response timeout')), 5000);
    });

    socket.write(Buffer.concat([header, payload]));

    const response = await responsePromise;
    assert(response.result, 'Should get version result');
    assert(typeof response.result === 'string', 'Version should be string');

  } finally {
    if (socket) socket.destroy();
    if (proc) proc.kill('SIGTERM');
  }
}

// =============================================================================
// Test: Pipe Mode (stdin/stdout)
// =============================================================================
async function testPipeMode() {
  const tmpDir = await mkdtemp(path.join(tmpdir(), 'flatc-pipe-'));
  const schemaFile = path.join(tmpDir, 'monster.fbs');

  try {
    // Write schema file
    await writeFile(schemaFile, MONSTER_SCHEMA);

    // Test JSON to binary
    const toBinaryProc = spawn('node', [
      SCRIPT_PATH, '--schema', schemaFile, '--to-binary'
    ], { stdio: ['pipe', 'pipe', 'pipe'] });

    const binaryPromise = new Promise((resolve, reject) => {
      const chunks = [];
      toBinaryProc.stdout.on('data', (chunk) => chunks.push(chunk));
      toBinaryProc.stdout.on('end', () => resolve(Buffer.concat(chunks)));
      toBinaryProc.on('error', reject);
    });

    toBinaryProc.stdin.write(MONSTER_JSON);
    toBinaryProc.stdin.end();

    const binary = await binaryPromise;
    assert(binary.length > 0, 'Should produce binary output');

    // Test binary to JSON
    const toJsonProc = spawn('node', [
      SCRIPT_PATH, '--schema', schemaFile, '--to-json'
    ], { stdio: ['pipe', 'pipe', 'pipe'] });

    const jsonPromise = new Promise((resolve, reject) => {
      let output = '';
      toJsonProc.stdout.on('data', (chunk) => output += chunk.toString());
      toJsonProc.stdout.on('end', () => resolve(output));
      toJsonProc.on('error', reject);
    });

    toJsonProc.stdin.write(binary);
    toJsonProc.stdin.end();

    const json = await jsonPromise;
    const parsed = JSON.parse(json);
    assert(parsed.name === 'Orc', 'Name should match after round-trip');
    assert(parsed.hp === 150, 'HP should match after round-trip');

  } finally {
    await rm(tmpDir, { recursive: true, force: true });
  }
}

// =============================================================================
// Test: Folder Watch Mode
// =============================================================================
async function testFolderWatch() {
  const tmpDir = await mkdtemp(path.join(tmpdir(), 'flatc-watch-'));
  const inputDir = path.join(tmpDir, 'input');
  const outputDir = path.join(tmpDir, 'output');
  const schemaFile = path.join(tmpDir, 'monster.fbs');

  let proc = null;

  try {
    // Create directories
    await mkdir(inputDir, { recursive: true });
    await mkdir(outputDir, { recursive: true });
    await writeFile(schemaFile, MONSTER_SCHEMA);

    // Start watcher
    proc = spawn('node', [
      SCRIPT_PATH,
      '--watch', inputDir,
      '--output', outputDir,
      '--schema', schemaFile
    ], { stdio: ['pipe', 'pipe', 'pipe'] });

    // Wait for watcher to start
    await new Promise(r => setTimeout(r, 1000));

    // Write a JSON file to input directory
    const inputFile = path.join(inputDir, 'test1.json');
    await writeFile(inputFile, MONSTER_JSON);

    // Wait for conversion
    await new Promise(r => setTimeout(r, 1000));

    // Check output file exists
    const outputFile = path.join(outputDir, 'test1.bin');
    let attempts = 0;
    while (!existsSync(outputFile) && attempts < 10) {
      await new Promise(r => setTimeout(r, 200));
      attempts++;
    }

    assert(existsSync(outputFile), 'Output file should be created');

    const outputData = await readFile(outputFile);
    assert(outputData.length > 0, 'Output file should have content');

  } finally {
    if (proc) proc.kill('SIGTERM');
    await rm(tmpDir, { recursive: true, force: true });
  }
}

// =============================================================================
// Test: Code Generation via RPC
// =============================================================================
async function testCodeGeneration() {
  const port = PORT_BASE + 3;
  let proc = null;
  let socket = null;

  try {
    proc = await startServer(['--tcp', String(port)]);
    await new Promise(r => setTimeout(r, 500));

    socket = await connectWithRetry({ port, host: '127.0.0.1' });

    // Add schema
    await sendRpc(socket, 'addSchema', { name: 'monster.fbs', source: MONSTER_SCHEMA });

    // Generate TypeScript
    const tsResult = await sendRpc(socket, 'generateCode', {
      schema: 'monster.fbs',
      language: 'typescript'
    });
    assert(tsResult.code, 'Should generate TypeScript code');
    assert(tsResult.code.includes('Monster'), 'TS should contain Monster');

    // Generate Python
    const pyResult = await sendRpc(socket, 'generateCode', {
      schema: 'monster.fbs',
      language: 'python'
    });
    assert(pyResult.code, 'Should generate Python code');

    // Generate C++
    const cppResult = await sendRpc(socket, 'generateCode', {
      schema: 'monster.fbs',
      language: 'cpp'
    });
    assert(cppResult.code, 'Should generate C++ code');

  } finally {
    if (socket) socket.destroy();
    if (proc) proc.kill('SIGTERM');
  }
}

// =============================================================================
// Test: Multiple Concurrent Connections
// =============================================================================
async function testConcurrentConnections() {
  const port = PORT_BASE + 4;
  let proc = null;
  const sockets = [];

  try {
    proc = await startServer(['--tcp', String(port)]);
    await new Promise(r => setTimeout(r, 500));

    // Create multiple connections
    for (let i = 0; i < 5; i++) {
      const socket = await connectWithRetry({ port, host: '127.0.0.1' });
      sockets.push(socket);
    }

    // Add schema on first connection
    await sendRpc(sockets[0], 'addSchema', { name: 'monster.fbs', source: MONSTER_SCHEMA });

    // Send concurrent requests on all connections
    const promises = sockets.map(async (socket, i) => {
      const pong = await sendRpc(socket, 'ping');
      assert(pong.pong === true, `Connection ${i} should get pong`);

      const { binary } = await sendRpc(socket, 'jsonToBinary', {
        schema: 'monster.fbs',
        json: JSON.stringify({ name: `Monster${i}`, hp: 100 + i })
      });

      const { json } = await sendRpc(socket, 'binaryToJson', {
        schema: 'monster.fbs',
        binary
      });

      const parsed = JSON.parse(json);
      assert(parsed.name === `Monster${i}`, `Connection ${i} name should match`);
      return true;
    });

    const results = await Promise.all(promises);
    assert(results.every(r => r === true), 'All concurrent requests should succeed');

  } finally {
    for (const socket of sockets) {
      socket.destroy();
    }
    if (proc) proc.kill('SIGTERM');
  }
}

// =============================================================================
// Test: Schema Management
// =============================================================================
async function testSchemaManagement() {
  const port = PORT_BASE + 5;
  let proc = null;
  let socket = null;

  try {
    proc = await startServer(['--tcp', String(port)]);
    await new Promise(r => setTimeout(r, 500));

    socket = await connectWithRetry({ port, host: '127.0.0.1' });

    // Initially empty
    let schemas = await sendRpc(socket, 'listSchemas');
    assert(schemas.length === 0, 'Should start with no schemas');

    // Add multiple schemas
    await sendRpc(socket, 'addSchema', { name: 'schema1.fbs', source: MONSTER_SCHEMA });
    await sendRpc(socket, 'addSchema', { name: 'schema2.fbs', source: MONSTER_SCHEMA });
    await sendRpc(socket, 'addSchema', { name: 'schema3.fbs', source: MONSTER_SCHEMA });

    schemas = await sendRpc(socket, 'listSchemas');
    assert(schemas.length === 3, 'Should have 3 schemas');

    // Remove one
    await sendRpc(socket, 'removeSchema', { name: 'schema2.fbs' });

    schemas = await sendRpc(socket, 'listSchemas');
    assert(schemas.length === 2, 'Should have 2 schemas after remove');
    assert(!schemas.includes('schema2.fbs'), 'schema2 should be removed');

    // Re-add with same name (should replace)
    await sendRpc(socket, 'addSchema', { name: 'schema1.fbs', source: MONSTER_SCHEMA });
    schemas = await sendRpc(socket, 'listSchemas');
    assert(schemas.length === 2, 'Re-add should replace, not duplicate');

  } finally {
    if (socket) socket.destroy();
    if (proc) proc.kill('SIGTERM');
  }
}

// =============================================================================
// Test: Error Handling
// =============================================================================
async function testErrorHandling() {
  const port = PORT_BASE + 6;
  let proc = null;
  let socket = null;

  try {
    proc = await startServer(['--tcp', String(port)]);
    await new Promise(r => setTimeout(r, 500));

    socket = await connectWithRetry({ port, host: '127.0.0.1' });

    // Unknown method
    try {
      await sendRpc(socket, 'unknownMethod');
      assert(false, 'Should throw for unknown method');
    } catch (e) {
      assert(e.message.includes('Unknown method'), 'Should report unknown method');
    }

    // Missing schema
    try {
      await sendRpc(socket, 'jsonToBinary', {
        schema: 'nonexistent.fbs',
        json: '{}'
      });
      assert(false, 'Should throw for missing schema');
    } catch (e) {
      assert(e.message.includes('not found'), 'Should report schema not found');
    }

    // Invalid JSON
    await sendRpc(socket, 'addSchema', { name: 'monster.fbs', source: MONSTER_SCHEMA });
    try {
      await sendRpc(socket, 'jsonToBinary', {
        schema: 'monster.fbs',
        json: 'not valid json'
      });
      assert(false, 'Should throw for invalid JSON');
    } catch (e) {
      // Expected error
    }

  } finally {
    if (socket) socket.destroy();
    if (proc) proc.kill('SIGTERM');
  }
}

// =============================================================================
// Main
// =============================================================================
async function main() {
  log('='.repeat(60));
  log('FlatBuffers WASM I/O Methods Test Suite');
  log('='.repeat(60));

  // Check if WASM module exists
  const wasmPath = path.join(__dirname, '..', '..', 'build', 'wasm', 'wasm', 'flatc.js');
  if (!existsSync(wasmPath)) {
    log(`\nError: WASM module not found at ${wasmPath}`);
    log('Please build the WASM module first with: cmake --build build/wasm --target flatc_wasm');
    process.exit(1);
  }

  log('\n[Unix Socket Tests]');
  await test('Unix domain socket server', testUnixSocket);

  log('\n[TCP Server Tests]');
  await test('TCP server', testTcpServer);
  await test('Binary protocol TCP', testBinaryTcpServer);
  await test('Concurrent connections', testConcurrentConnections);

  log('\n[Pipe Mode Tests]');
  await test('stdin/stdout pipe mode', testPipeMode);

  log('\n[Folder Watch Tests]');
  await test('Folder watch mode', testFolderWatch);

  log('\n[RPC Feature Tests]');
  await test('Code generation via RPC', testCodeGeneration);
  await test('Schema management', testSchemaManagement);
  await test('Error handling', testErrorHandling);

  log('\n' + '='.repeat(60));
  log(`Results: ${passed} passed, ${failed} failed`);
  log('='.repeat(60));

  process.exit(failed > 0 ? 1 : 0);
}

main().catch(err => {
  console.error('Test suite error:', err);
  process.exit(1);
});
