#!/usr/bin/env node
/**
 * test_benchmark.mjs - Benchmark test for flatc-stream throughput
 *
 * Measures:
 * - JSON to Binary conversions per second
 * - Binary to JSON conversions per second
 * - Round-trip conversions per second
 * - Code generation throughput
 * - I/O overhead for different transport methods
 */

import { spawn } from 'child_process';
import { createConnection } from 'net';
import { mkdir, writeFile, rm, mkdtemp, unlink } from 'fs/promises';
import { existsSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { tmpdir } from 'os';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCRIPT_PATH = path.join(__dirname, '..', '..', 'scripts', 'flatc-stream.mjs');

// Import the FlatcService directly for in-process benchmarks
const WASM_PATH = path.join(__dirname, '..', '..', 'build', 'wasm', 'wasm', 'flatc.js');

// Test schemas of varying complexity
const SIMPLE_SCHEMA = `
namespace Test;
table Simple {
  name: string;
  value: int;
}
root_type Simple;
`;

const MEDIUM_SCHEMA = `
namespace Test;
struct Vec3 { x: float; y: float; z: float; }
table Item { id: int; name: string; price: float; }
table Medium {
  id: ulong;
  name: string;
  position: Vec3;
  items: [Item];
  tags: [string];
  active: bool = true;
}
root_type Medium;
`;

const COMPLEX_SCHEMA = `
namespace Test;
enum Status : byte { Pending, Active, Complete, Failed }
struct Vec3 { x: float; y: float; z: float; }
struct Color { r: ubyte; g: ubyte; b: ubyte; a: ubyte; }
table Attribute { key: string; value: string; }
table Component { type: string; data: [ubyte]; }
table Entity {
  id: ulong;
  name: string;
  description: string;
  status: Status;
  position: Vec3;
  rotation: Vec3;
  scale: Vec3;
  color: Color;
  attributes: [Attribute];
  components: [Component];
  children: [ulong];
  tags: [string];
  created: long;
  modified: long;
}
table Complex {
  version: uint;
  entities: [Entity];
  metadata: [Attribute];
}
root_type Complex;
`;

// Test data
const SIMPLE_JSON = { name: "Test", value: 42 };

const MEDIUM_JSON = {
  id: 12345678901234,
  name: "Test Entity",
  position: { x: 1.5, y: 2.5, z: 3.5 },
  items: [
    { id: 1, name: "Item 1", price: 9.99 },
    { id: 2, name: "Item 2", price: 19.99 },
    { id: 3, name: "Item 3", price: 29.99 }
  ],
  tags: ["tag1", "tag2", "tag3"],
  active: true
};

const COMPLEX_JSON = {
  version: 1,
  entities: Array.from({ length: 10 }, (_, i) => ({
    id: BigInt(i + 1).toString(),
    name: `Entity ${i}`,
    description: `This is entity number ${i} with a longer description`,
    status: i % 4,
    position: { x: i * 1.0, y: i * 2.0, z: i * 3.0 },
    rotation: { x: 0.0, y: i * 45.0, z: 0.0 },
    scale: { x: 1.0, y: 1.0, z: 1.0 },
    color: { r: i * 25, g: 255 - i * 25, b: 128, a: 255 },
    attributes: [
      { key: "type", value: "entity" },
      { key: "layer", value: String(i % 5) }
    ],
    components: [],
    children: [],
    tags: [`group${i % 3}`, "entity"],
    created: Date.now(),
    modified: Date.now()
  })),
  metadata: [
    { key: "author", value: "benchmark" },
    { key: "version", value: "1.0.0" }
  ]
};

// Benchmark configuration
const WARMUP_ITERATIONS = 100;
const BENCHMARK_DURATION_MS = 3000; // 3 seconds per benchmark

// Results storage
const benchmarkResults = [];

function log(msg) {
  console.log(msg);
}

function formatNumber(n) {
  return n.toLocaleString('en-US', { maximumFractionDigits: 0 });
}

function formatRate(rate) {
  if (rate >= 1000000) {
    return `${(rate / 1000000).toFixed(2)}M`;
  } else if (rate >= 1000) {
    return `${(rate / 1000).toFixed(2)}K`;
  }
  return rate.toFixed(2);
}

// =============================================================================
// In-Process Benchmarks (Direct WASM calls)
// =============================================================================

async function loadWasmModule() {
  const moduleFactory = await import(WASM_PATH);
  return await moduleFactory.default();
}

async function benchmarkInProcess(module, schemaName, schema, jsonData) {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const jsonStr = JSON.stringify(jsonData);

  // Helper functions
  function writeString(str) {
    const bytes = encoder.encode(str);
    const ptr = module._malloc(bytes.length);
    module.HEAPU8.set(bytes, ptr);
    return [ptr, bytes.length];
  }

  function writeBytes(data) {
    const ptr = module._malloc(data.length);
    module.HEAPU8.set(data, ptr);
    return ptr;
  }

  // Add schema
  const [namePtr, nameLen] = writeString(schemaName);
  const [srcPtr, srcLen] = writeString(schema);
  const schemaId = module._wasm_schema_add(namePtr, nameLen, srcPtr, srcLen);
  module._free(namePtr);
  module._free(srcPtr);

  if (schemaId < 0) {
    throw new Error('Failed to add schema');
  }

  // Warmup
  for (let i = 0; i < WARMUP_ITERATIONS; i++) {
    const [jsonPtr, jsonLen] = writeString(jsonStr);
    const outLenPtr = module._malloc(4);
    const resultPtr = module._wasm_json_to_binary(schemaId, jsonPtr, jsonLen, outLenPtr);
    module._free(jsonPtr);
    module._free(outLenPtr);
  }

  // Benchmark JSON to Binary
  let count = 0;
  const startJ2B = performance.now();
  while (performance.now() - startJ2B < BENCHMARK_DURATION_MS) {
    const [jsonPtr, jsonLen] = writeString(jsonStr);
    const outLenPtr = module._malloc(4);
    const resultPtr = module._wasm_json_to_binary(schemaId, jsonPtr, jsonLen, outLenPtr);
    module._free(jsonPtr);
    module._free(outLenPtr);
    count++;
  }
  const j2bElapsed = performance.now() - startJ2B;
  const j2bRate = (count / j2bElapsed) * 1000;

  // Get a binary buffer for B2J test
  const [jsonPtr, jsonLen] = writeString(jsonStr);
  const outLenPtrTemp = module._malloc(4);
  const binResultPtr = module._wasm_json_to_binary(schemaId, jsonPtr, jsonLen, outLenPtrTemp);
  const binLen = module.getValue(outLenPtrTemp, 'i32');
  const binaryData = module.HEAPU8.slice(binResultPtr, binResultPtr + binLen);
  module._free(jsonPtr);
  module._free(outLenPtrTemp);

  // Warmup B2J
  for (let i = 0; i < WARMUP_ITERATIONS; i++) {
    const binPtr = writeBytes(binaryData);
    const outLenPtr = module._malloc(4);
    module._wasm_binary_to_json(schemaId, binPtr, binaryData.length, outLenPtr);
    module._free(binPtr);
    module._free(outLenPtr);
  }

  // Benchmark Binary to JSON
  count = 0;
  const startB2J = performance.now();
  while (performance.now() - startB2J < BENCHMARK_DURATION_MS) {
    const binPtr = writeBytes(binaryData);
    const outLenPtr = module._malloc(4);
    module._wasm_binary_to_json(schemaId, binPtr, binaryData.length, outLenPtr);
    module._free(binPtr);
    module._free(outLenPtr);
    count++;
  }
  const b2jElapsed = performance.now() - startB2J;
  const b2jRate = (count / b2jElapsed) * 1000;

  // Benchmark Round-trip
  count = 0;
  const startRT = performance.now();
  while (performance.now() - startRT < BENCHMARK_DURATION_MS) {
    // JSON to Binary
    const [jPtr, jLen] = writeString(jsonStr);
    const oLenPtr1 = module._malloc(4);
    const binPtr1 = module._wasm_json_to_binary(schemaId, jPtr, jLen, oLenPtr1);
    const bLen = module.getValue(oLenPtr1, 'i32');

    // Binary to JSON
    const oLenPtr2 = module._malloc(4);
    module._wasm_binary_to_json(schemaId, binPtr1, bLen, oLenPtr2);

    module._free(jPtr);
    module._free(oLenPtr1);
    module._free(oLenPtr2);
    count++;
  }
  const rtElapsed = performance.now() - startRT;
  const rtRate = (count / rtElapsed) * 1000;

  // Cleanup
  module._wasm_schema_remove(schemaId);

  return {
    jsonSize: jsonStr.length,
    binarySize: binaryData.length,
    j2bRate,
    b2jRate,
    rtRate
  };
}

// =============================================================================
// RPC Benchmarks (Via TCP server)
// =============================================================================

function sendRpc(socket, method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = Date.now() + Math.random();
    const request = JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n';

    let data = '';
    const onData = (chunk) => {
      data += chunk.toString();
      const lines = data.split('\n');
      for (const line of lines) {
        if (line.trim()) {
          try {
            const response = JSON.parse(line);
            if (response.id === id) {
              socket.removeListener('data', onData);
              if (response.error) {
                reject(new Error(response.error.message));
              } else {
                resolve(response.result);
              }
              return;
            }
          } catch (e) {
            // Continue
          }
        }
      }
    };

    socket.on('data', onData);
    socket.write(request);
  });
}

async function benchmarkRpc(socket, schemaName, jsonData, binaryB64) {
  const jsonStr = JSON.stringify(jsonData);

  // Warmup
  for (let i = 0; i < Math.min(WARMUP_ITERATIONS, 50); i++) {
    await sendRpc(socket, 'jsonToBinary', { schema: schemaName, json: jsonStr });
  }

  // Benchmark JSON to Binary
  let count = 0;
  const startJ2B = performance.now();
  while (performance.now() - startJ2B < BENCHMARK_DURATION_MS) {
    await sendRpc(socket, 'jsonToBinary', { schema: schemaName, json: jsonStr });
    count++;
  }
  const j2bElapsed = performance.now() - startJ2B;
  const j2bRate = (count / j2bElapsed) * 1000;

  // Get binary for B2J test
  const { binary } = await sendRpc(socket, 'jsonToBinary', { schema: schemaName, json: jsonStr });

  // Warmup B2J
  for (let i = 0; i < Math.min(WARMUP_ITERATIONS, 50); i++) {
    await sendRpc(socket, 'binaryToJson', { schema: schemaName, binary });
  }

  // Benchmark Binary to JSON
  count = 0;
  const startB2J = performance.now();
  while (performance.now() - startB2J < BENCHMARK_DURATION_MS) {
    await sendRpc(socket, 'binaryToJson', { schema: schemaName, binary });
    count++;
  }
  const b2jElapsed = performance.now() - startB2J;
  const b2jRate = (count / b2jElapsed) * 1000;

  return { j2bRate, b2jRate };
}

// =============================================================================
// Main Benchmark Suite
// =============================================================================

async function main() {
  log('='.repeat(70));
  log('FlatBuffers WASM Benchmark Suite');
  log('='.repeat(70));

  // Check if WASM module exists
  if (!existsSync(WASM_PATH)) {
    log(`\nError: WASM module not found at ${WASM_PATH}`);
    log('Please build the WASM module first.');
    process.exit(1);
  }

  log(`\nBenchmark duration: ${BENCHMARK_DURATION_MS / 1000}s per test`);
  log(`Warmup iterations: ${WARMUP_ITERATIONS}`);

  // ==========================================================================
  // In-Process Benchmarks (Direct WASM)
  // ==========================================================================
  log('\n' + '='.repeat(70));
  log('IN-PROCESS BENCHMARKS (Direct WASM calls)');
  log('='.repeat(70));

  const module = await loadWasmModule();

  // Simple schema
  log('\n[Simple Schema - Small Payload]');
  const simpleResult = await benchmarkInProcess(module, 'simple.fbs', SIMPLE_SCHEMA, SIMPLE_JSON);
  log(`  JSON size:     ${simpleResult.jsonSize} bytes`);
  log(`  Binary size:   ${simpleResult.binarySize} bytes`);
  log(`  Compression:   ${((1 - simpleResult.binarySize / simpleResult.jsonSize) * 100).toFixed(1)}%`);
  log(`  JSON→Binary:   ${formatRate(simpleResult.j2bRate)} ops/sec`);
  log(`  Binary→JSON:   ${formatRate(simpleResult.b2jRate)} ops/sec`);
  log(`  Round-trip:    ${formatRate(simpleResult.rtRate)} ops/sec`);
  benchmarkResults.push({ name: 'Simple (in-process)', ...simpleResult });

  // Medium schema
  log('\n[Medium Schema - Medium Payload]');
  const mediumResult = await benchmarkInProcess(module, 'medium.fbs', MEDIUM_SCHEMA, MEDIUM_JSON);
  log(`  JSON size:     ${mediumResult.jsonSize} bytes`);
  log(`  Binary size:   ${mediumResult.binarySize} bytes`);
  log(`  Compression:   ${((1 - mediumResult.binarySize / mediumResult.jsonSize) * 100).toFixed(1)}%`);
  log(`  JSON→Binary:   ${formatRate(mediumResult.j2bRate)} ops/sec`);
  log(`  Binary→JSON:   ${formatRate(mediumResult.b2jRate)} ops/sec`);
  log(`  Round-trip:    ${formatRate(mediumResult.rtRate)} ops/sec`);
  benchmarkResults.push({ name: 'Medium (in-process)', ...mediumResult });

  // Complex schema
  log('\n[Complex Schema - Large Payload]');
  const complexResult = await benchmarkInProcess(module, 'complex.fbs', COMPLEX_SCHEMA, COMPLEX_JSON);
  log(`  JSON size:     ${complexResult.jsonSize} bytes`);
  log(`  Binary size:   ${complexResult.binarySize} bytes`);
  log(`  Compression:   ${((1 - complexResult.binarySize / complexResult.jsonSize) * 100).toFixed(1)}%`);
  log(`  JSON→Binary:   ${formatRate(complexResult.j2bRate)} ops/sec`);
  log(`  Binary→JSON:   ${formatRate(complexResult.b2jRate)} ops/sec`);
  log(`  Round-trip:    ${formatRate(complexResult.rtRate)} ops/sec`);
  benchmarkResults.push({ name: 'Complex (in-process)', ...complexResult });

  // ==========================================================================
  // TCP RPC Benchmarks
  // ==========================================================================
  log('\n' + '='.repeat(70));
  log('TCP RPC BENCHMARKS (JSON-RPC over TCP)');
  log('='.repeat(70));

  const port = 19999 + Math.floor(Math.random() * 1000);
  let proc = null;
  let socket = null;

  try {
    // Start TCP server
    proc = spawn('node', [SCRIPT_PATH, '--tcp', String(port)], {
      stdio: ['pipe', 'pipe', 'pipe']
    });

    await new Promise(r => setTimeout(r, 1500));

    // Connect
    socket = await new Promise((resolve, reject) => {
      const s = createConnection({ port, host: '127.0.0.1' }, () => resolve(s));
      s.on('error', reject);
    });

    // Add schemas
    await sendRpc(socket, 'addSchema', { name: 'simple.fbs', source: SIMPLE_SCHEMA });
    await sendRpc(socket, 'addSchema', { name: 'medium.fbs', source: MEDIUM_SCHEMA });
    await sendRpc(socket, 'addSchema', { name: 'complex.fbs', source: COMPLEX_SCHEMA });

    // Simple
    log('\n[Simple Schema - via TCP RPC]');
    const simpleRpc = await benchmarkRpc(socket, 'simple.fbs', SIMPLE_JSON, null);
    log(`  JSON→Binary:   ${formatRate(simpleRpc.j2bRate)} ops/sec`);
    log(`  Binary→JSON:   ${formatRate(simpleRpc.b2jRate)} ops/sec`);
    benchmarkResults.push({ name: 'Simple (TCP RPC)', ...simpleRpc });

    // Medium
    log('\n[Medium Schema - via TCP RPC]');
    const mediumRpc = await benchmarkRpc(socket, 'medium.fbs', MEDIUM_JSON, null);
    log(`  JSON→Binary:   ${formatRate(mediumRpc.j2bRate)} ops/sec`);
    log(`  Binary→JSON:   ${formatRate(mediumRpc.b2jRate)} ops/sec`);
    benchmarkResults.push({ name: 'Medium (TCP RPC)', ...mediumRpc });

    // Complex
    log('\n[Complex Schema - via TCP RPC]');
    const complexRpc = await benchmarkRpc(socket, 'complex.fbs', COMPLEX_JSON, null);
    log(`  JSON→Binary:   ${formatRate(complexRpc.j2bRate)} ops/sec`);
    log(`  Binary→JSON:   ${formatRate(complexRpc.b2jRate)} ops/sec`);
    benchmarkResults.push({ name: 'Complex (TCP RPC)', ...complexRpc });

  } finally {
    if (socket) socket.destroy();
    if (proc) proc.kill('SIGTERM');
  }

  // ==========================================================================
  // Throughput Summary
  // ==========================================================================
  log('\n' + '='.repeat(70));
  log('THROUGHPUT SUMMARY');
  log('='.repeat(70));

  log('\n┌─────────────────────────┬───────────────┬───────────────┬───────────────┐');
  log('│ Benchmark               │ JSON→Binary   │ Binary→JSON   │ Round-trip    │');
  log('├─────────────────────────┼───────────────┼───────────────┼───────────────┤');

  for (const r of benchmarkResults) {
    const name = r.name.padEnd(23);
    const j2b = formatRate(r.j2bRate).padStart(11);
    const b2j = formatRate(r.b2jRate).padStart(11);
    const rt = r.rtRate ? formatRate(r.rtRate).padStart(11) : '      N/A  ';
    log(`│ ${name} │ ${j2b}/s │ ${b2j}/s │ ${rt}/s │`);
  }

  log('└─────────────────────────┴───────────────┴───────────────┴───────────────┘');

  // ==========================================================================
  // I/O Overhead Analysis
  // ==========================================================================
  log('\n' + '='.repeat(70));
  log('I/O OVERHEAD ANALYSIS');
  log('='.repeat(70));

  const inProcessSimple = benchmarkResults.find(r => r.name === 'Simple (in-process)');
  const rpcSimple = benchmarkResults.find(r => r.name === 'Simple (TCP RPC)');

  if (inProcessSimple && rpcSimple) {
    const j2bOverhead = ((inProcessSimple.j2bRate - rpcSimple.j2bRate) / inProcessSimple.j2bRate * 100).toFixed(1);
    const b2jOverhead = ((inProcessSimple.b2jRate - rpcSimple.b2jRate) / inProcessSimple.b2jRate * 100).toFixed(1);
    log(`\nTCP RPC overhead vs in-process (Simple schema):`);
    log(`  JSON→Binary:   ${j2bOverhead}% slower`);
    log(`  Binary→JSON:   ${b2jOverhead}% slower`);
  }

  const inProcessComplex = benchmarkResults.find(r => r.name === 'Complex (in-process)');
  const rpcComplex = benchmarkResults.find(r => r.name === 'Complex (TCP RPC)');

  if (inProcessComplex && rpcComplex) {
    const j2bOverhead = ((inProcessComplex.j2bRate - rpcComplex.j2bRate) / inProcessComplex.j2bRate * 100).toFixed(1);
    const b2jOverhead = ((inProcessComplex.b2jRate - rpcComplex.b2jRate) / inProcessComplex.b2jRate * 100).toFixed(1);
    log(`\nTCP RPC overhead vs in-process (Complex schema):`);
    log(`  JSON→Binary:   ${j2bOverhead}% slower`);
    log(`  Binary→JSON:   ${b2jOverhead}% slower`);
  }

  log('\n' + '='.repeat(70));
  log('Benchmark complete');
  log('='.repeat(70));
}

main().catch(err => {
  console.error('Benchmark error:', err);
  process.exit(1);
});
