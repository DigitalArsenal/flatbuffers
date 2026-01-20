#!/usr/bin/env node
/**
 * flatc-stream.mjs - Node.js streaming FlatBuffers compiler
 *
 * Provides multiple I/O methods for streaming FlatBuffers operations:
 * - stdin/stdout pipes
 * - Unix domain sockets
 * - Named pipes (FIFOs)
 * - TCP server
 * - File/folder watching
 * - JSON-RPC daemon mode
 *
 * Usage:
 *   # Pipe mode (single conversion)
 *   echo '{"name":"test"}' | node flatc-stream.mjs --schema monster.fbs --to-binary > out.bin
 *
 *   # Unix socket daemon
 *   node flatc-stream.mjs --socket /tmp/flatc.sock
 *
 *   # TCP server
 *   node flatc-stream.mjs --tcp 9876
 *
 *   # Named pipe (FIFO)
 *   node flatc-stream.mjs --fifo /tmp/flatc.fifo
 *
 *   # Folder watch mode
 *   node flatc-stream.mjs --watch ./input --output ./output --schema monster.fbs
 *
 *   # JSON-RPC on stdin
 *   node flatc-stream.mjs --daemon
 */

import { createRequire } from 'module';
import { readFile, writeFile, watch, mkdir, stat, unlink } from 'fs/promises';
import { createReadStream, createWriteStream, existsSync, mkdirSync } from 'fs';
import { createInterface } from 'readline';
import { createServer as createNetServer, createConnection } from 'net';
import { EventEmitter } from 'events';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Path to the WASM module
const WASM_PATH = path.join(__dirname, '..', 'build', 'wasm', 'wasm', 'flatc.js');

// Language enum matching the WASM module
export const Language = {
  CPP: 0,
  CSharp: 1,
  Dart: 2,
  Go: 3,
  Java: 4,
  Kotlin: 5,
  Python: 6,
  Rust: 7,
  Swift: 8,
  TypeScript: 9,
  PHP: 10,
  JSONSchema: 11,
  FBS: 12,
};

const LANGUAGE_MAP = {
  cpp: Language.CPP,
  'c++': Language.CPP,
  csharp: Language.CSharp,
  'c#': Language.CSharp,
  dart: Language.Dart,
  go: Language.Go,
  java: Language.Java,
  kotlin: Language.Kotlin,
  python: Language.Python,
  rust: Language.Rust,
  swift: Language.Swift,
  typescript: Language.TypeScript,
  ts: Language.TypeScript,
  php: Language.PHP,
  jsonschema: Language.JSONSchema,
  fbs: Language.FBS,
};

export const DataFormat = {
  JSON: 0,
  Binary: 1,
  Unknown: -1,
};

// =============================================================================
// FlatcService - Core WASM wrapper
// =============================================================================

export class FlatcService {
  constructor(module) {
    this.module = module;
    this.schemaMap = new Map(); // name -> id
    this.encoder = new TextEncoder();
    this.decoder = new TextDecoder();
  }

  static async create(wasmPath = WASM_PATH) {
    const moduleFactory = await import(wasmPath);
    const module = await moduleFactory.default();
    return new FlatcService(module);
  }

  getVersion() {
    return this.module.getVersion();
  }

  writeString(str) {
    const bytes = this.encoder.encode(str);
    const ptr = this.module._malloc(bytes.length);
    this.module.HEAPU8.set(bytes, ptr);
    return [ptr, bytes.length];
  }

  writeBytes(data) {
    const ptr = this.module._malloc(data.length);
    this.module.HEAPU8.set(data, ptr);
    return ptr;
  }

  readString(ptr) {
    return this.module.UTF8ToString(ptr);
  }

  getLastError() {
    const ptr = this.module._wasm_get_last_error();
    return ptr ? this.readString(ptr) : 'Unknown error';
  }

  addSchema(name, source) {
    if (this.schemaMap.has(name)) {
      this.removeSchema(name);
    }

    const [namePtr, nameLen] = this.writeString(name);
    const [srcPtr, srcLen] = this.writeString(source);

    try {
      const id = this.module._wasm_schema_add(namePtr, nameLen, srcPtr, srcLen);
      if (id < 0) {
        throw new Error(`Failed to add schema '${name}': ${this.getLastError()}`);
      }
      this.schemaMap.set(name, id);
      return id;
    } finally {
      this.module._free(namePtr);
      this.module._free(srcPtr);
    }
  }

  async addSchemaFile(filePath) {
    const content = await readFile(filePath, 'utf-8');
    const name = path.basename(filePath);
    return this.addSchema(name, content);
  }

  removeSchema(name) {
    const id = this.schemaMap.get(name);
    if (id === undefined) {
      throw new Error(`Schema '${name}' not found`);
    }
    this.module._wasm_schema_remove(id);
    this.schemaMap.delete(name);
  }

  listSchemas() {
    return Array.from(this.schemaMap.keys());
  }

  getSchemaId(name) {
    const id = this.schemaMap.get(name);
    if (id === undefined) {
      throw new Error(`Schema '${name}' not found. Loaded: ${this.listSchemas().join(', ') || 'none'}`);
    }
    return id;
  }

  jsonToBinary(schemaName, json) {
    const schemaId = this.getSchemaId(schemaName);
    const [jsonPtr, jsonLen] = this.writeString(json);
    const outLenPtr = this.module._malloc(4);

    try {
      const resultPtr = this.module._wasm_json_to_binary(schemaId, jsonPtr, jsonLen, outLenPtr);
      if (!resultPtr) {
        throw new Error(`JSON to binary failed: ${this.getLastError()}`);
      }

      const len = this.module.getValue(outLenPtr, 'i32');
      return this.module.HEAPU8.slice(resultPtr, resultPtr + len);
    } finally {
      this.module._free(jsonPtr);
      this.module._free(outLenPtr);
    }
  }

  binaryToJson(schemaName, binary) {
    const schemaId = this.getSchemaId(schemaName);
    const binPtr = this.writeBytes(binary);
    const outLenPtr = this.module._malloc(4);

    try {
      const resultPtr = this.module._wasm_binary_to_json(schemaId, binPtr, binary.length, outLenPtr);
      if (!resultPtr) {
        throw new Error(`Binary to JSON failed: ${this.getLastError()}`);
      }

      const len = this.module.getValue(outLenPtr, 'i32');
      const data = this.module.HEAPU8.slice(resultPtr, resultPtr + len);
      return this.decoder.decode(data);
    } finally {
      this.module._free(binPtr);
      this.module._free(outLenPtr);
    }
  }

  detectFormat(data) {
    const ptr = this.writeBytes(data);
    try {
      return this.module._wasm_detect_format(ptr, data.length);
    } finally {
      this.module._free(ptr);
    }
  }

  convert(schemaName, data) {
    const format = this.detectFormat(data);
    if (format === DataFormat.JSON) {
      const json = this.decoder.decode(data);
      return { format: 'json', result: this.jsonToBinary(schemaName, json) };
    } else if (format === DataFormat.Binary) {
      return { format: 'binary', result: this.binaryToJson(schemaName, data) };
    } else {
      throw new Error('Unknown data format');
    }
  }

  generateCode(schemaName, language) {
    const schemaId = this.getSchemaId(schemaName);
    const outLenPtr = this.module._malloc(4);

    try {
      const resultPtr = this.module._wasm_generate_code(schemaId, language, outLenPtr);
      if (!resultPtr) {
        throw new Error(`Code generation failed: ${this.getLastError()}`);
      }

      const len = this.module.getValue(outLenPtr, 'i32');
      const data = this.module.HEAPU8.slice(resultPtr, resultPtr + len);
      return this.decoder.decode(data);
    } finally {
      this.module._free(outLenPtr);
    }
  }
}

// =============================================================================
// I/O Handlers
// =============================================================================

/**
 * Handle a single RPC request
 */
async function handleRpcRequest(svc, req) {
  const p = req.params || {};

  switch (req.method) {
    case 'version':
      return svc.getVersion();

    case 'addSchema':
      if (typeof p.name !== 'string' || typeof p.source !== 'string') {
        throw new Error("addSchema requires 'name' and 'source' params");
      }
      svc.addSchema(p.name, p.source);
      return { success: true };

    case 'addSchemaFile':
      if (typeof p.path !== 'string') {
        throw new Error("addSchemaFile requires 'path' param");
      }
      await svc.addSchemaFile(p.path);
      return { success: true };

    case 'removeSchema':
      if (typeof p.name !== 'string') {
        throw new Error("removeSchema requires 'name' param");
      }
      svc.removeSchema(p.name);
      return { success: true };

    case 'listSchemas':
      return svc.listSchemas();

    case 'jsonToBinary': {
      if (typeof p.schema !== 'string' || typeof p.json !== 'string') {
        throw new Error("jsonToBinary requires 'schema' and 'json' params");
      }
      const binary = svc.jsonToBinary(p.schema, p.json);
      return { binary: Buffer.from(binary).toString('base64') };
    }

    case 'binaryToJson': {
      if (typeof p.schema !== 'string' || typeof p.binary !== 'string') {
        throw new Error("binaryToJson requires 'schema' and 'binary' (base64) params");
      }
      const binData = new Uint8Array(Buffer.from(p.binary, 'base64'));
      return { json: svc.binaryToJson(p.schema, binData) };
    }

    case 'convert': {
      if (typeof p.schema !== 'string' || typeof p.data !== 'string') {
        throw new Error("convert requires 'schema' and 'data' (base64) params");
      }
      const data = new Uint8Array(Buffer.from(p.data, 'base64'));
      const result = svc.convert(p.schema, data);
      if (result.result instanceof Uint8Array) {
        return { format: result.format, result: Buffer.from(result.result).toString('base64') };
      }
      return { format: result.format, result: result.result };
    }

    case 'generateCode':
      if (typeof p.schema !== 'string') {
        throw new Error("generateCode requires 'schema' param");
      }
      const lang = typeof p.language === 'number' ? p.language : LANGUAGE_MAP[String(p.language).toLowerCase()];
      if (lang === undefined) {
        throw new Error(`Unknown language: ${p.language}`);
      }
      return { code: svc.generateCode(p.schema, lang) };

    case 'ping':
      return { pong: true, timestamp: Date.now() };

    case 'stats':
      return {
        schemas: svc.listSchemas().length,
        version: svc.getVersion(),
        uptime: process.uptime(),
        memory: process.memoryUsage(),
      };

    default:
      throw new Error(`Unknown method: ${req.method}`);
  }
}

/**
 * Process a line of JSON-RPC input
 */
async function processRpcLine(svc, line) {
  if (!line.trim()) return null;

  let reqId = null;
  try {
    const req = JSON.parse(line);
    reqId = req.id;
    const result = await handleRpcRequest(svc, req);
    return { jsonrpc: '2.0', id: req.id, result };
  } catch (err) {
    return { jsonrpc: '2.0', id: reqId ?? 0, error: { code: -1, message: err.message } };
  }
}

// =============================================================================
// Daemon Modes
// =============================================================================

/**
 * Run as stdin/stdout JSON-RPC daemon
 */
async function runStdinDaemon(svc) {
  console.error(`flatc daemon started (version ${svc.getVersion()})`);
  console.error('Send JSON-RPC requests on stdin, one per line');

  const rl = createInterface({ input: process.stdin, terminal: false });

  for await (const line of rl) {
    const response = await processRpcLine(svc, line);
    if (response) {
      console.log(JSON.stringify(response));
    }
  }
}

/**
 * Run as Unix socket server
 */
async function runSocketServer(svc, socketPath) {
  // Remove existing socket file
  try {
    await unlink(socketPath);
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
  }

  const server = createNetServer((socket) => {
    console.error(`Client connected`);

    const rl = createInterface({ input: socket, crlfDelay: Infinity });

    rl.on('line', async (line) => {
      const response = await processRpcLine(svc, line);
      if (response) {
        socket.write(JSON.stringify(response) + '\n');
      }
    });

    socket.on('close', () => {
      console.error('Client disconnected');
    });

    socket.on('error', (err) => {
      console.error('Socket error:', err.message);
    });
  });

  server.listen(socketPath, () => {
    console.error(`flatc socket server listening on ${socketPath}`);
    console.error(`Connect with: nc -U ${socketPath}`);
  });

  // Cleanup on exit
  process.on('SIGINT', () => {
    server.close();
    unlink(socketPath).catch(() => {});
    process.exit(0);
  });
}

/**
 * Run as TCP server
 */
async function runTcpServer(svc, port, host = '127.0.0.1') {
  const server = createNetServer((socket) => {
    const clientAddr = `${socket.remoteAddress}:${socket.remotePort}`;
    console.error(`Client connected: ${clientAddr}`);

    const rl = createInterface({ input: socket, crlfDelay: Infinity });

    rl.on('line', async (line) => {
      const response = await processRpcLine(svc, line);
      if (response) {
        socket.write(JSON.stringify(response) + '\n');
      }
    });

    socket.on('close', () => {
      console.error(`Client disconnected: ${clientAddr}`);
    });

    socket.on('error', (err) => {
      console.error(`Socket error (${clientAddr}):`, err.message);
    });
  });

  server.listen(port, host, () => {
    console.error(`flatc TCP server listening on ${host}:${port}`);
    console.error(`Connect with: nc ${host} ${port}`);
  });

  process.on('SIGINT', () => {
    server.close();
    process.exit(0);
  });
}

/**
 * Run as named pipe (FIFO) server
 * Note: The FIFO must be created externally with mkfifo
 */
async function runFifoServer(svc, fifoPath, outputPath = null) {
  console.error(`flatc FIFO server`);
  console.error(`Input: ${fifoPath}`);
  console.error(`Output: ${outputPath || 'stdout'}`);
  console.error(`Create the FIFO with: mkfifo ${fifoPath}`);

  // Check if FIFO exists
  try {
    const stats = await stat(fifoPath);
    if (!stats.isFIFO()) {
      console.error(`Warning: ${fifoPath} is not a FIFO`);
    }
  } catch (e) {
    if (e.code === 'ENOENT') {
      console.error(`FIFO does not exist. Create it with: mkfifo ${fifoPath}`);
      process.exit(1);
    }
  }

  // Continuously read from FIFO
  while (true) {
    try {
      const rl = createInterface({
        input: createReadStream(fifoPath),
        crlfDelay: Infinity,
      });

      for await (const line of rl) {
        const response = await processRpcLine(svc, line);
        if (response) {
          const output = JSON.stringify(response) + '\n';
          if (outputPath) {
            await writeFile(outputPath, output, { flag: 'a' });
          } else {
            console.log(output.trim());
          }
        }
      }
    } catch (e) {
      console.error('FIFO error:', e.message);
      await new Promise(r => setTimeout(r, 100));
    }
  }
}

/**
 * Run as folder watcher - converts files as they appear
 */
async function runFolderWatcher(svc, inputDir, outputDir, schemaName, options = {}) {
  const { toBinary = true, extension = toBinary ? '.bin' : '.json' } = options;

  // Ensure output directory exists
  try {
    await mkdir(outputDir, { recursive: true });
  } catch (e) {
    if (e.code !== 'EEXIST') throw e;
  }

  console.error(`flatc folder watcher`);
  console.error(`Input:  ${inputDir}`);
  console.error(`Output: ${outputDir}`);
  console.error(`Schema: ${schemaName}`);
  console.error(`Mode:   ${toBinary ? 'JSON → Binary' : 'Binary → JSON'}`);

  const watcher = watch(inputDir, { persistent: true });

  for await (const event of watcher) {
    if (event.eventType !== 'rename' && event.eventType !== 'change') continue;
    if (!event.filename) continue;

    const inputPath = path.join(inputDir, event.filename);
    const baseName = path.basename(event.filename, path.extname(event.filename));
    const outputPath = path.join(outputDir, baseName + extension);

    try {
      const stats = await stat(inputPath);
      if (!stats.isFile()) continue;

      const inputData = await readFile(inputPath);

      let outputData;
      if (toBinary) {
        const json = inputData.toString('utf-8');
        outputData = Buffer.from(svc.jsonToBinary(schemaName, json));
      } else {
        const binary = new Uint8Array(inputData);
        outputData = svc.binaryToJson(schemaName, binary);
      }

      await writeFile(outputPath, outputData);
      console.error(`Converted: ${event.filename} → ${baseName}${extension}`);
    } catch (e) {
      if (e.code !== 'ENOENT') {
        console.error(`Error processing ${event.filename}: ${e.message}`);
      }
    }
  }
}

// =============================================================================
// Binary Protocol (length-prefixed messages)
// =============================================================================

/**
 * Binary protocol handler for high-performance streaming
 * Message format: 4-byte length (little-endian) + JSON payload
 */
class BinaryProtocolHandler extends EventEmitter {
  constructor(socket, svc) {
    super();
    this.socket = socket;
    this.svc = svc;
    this.buffer = Buffer.alloc(0);
    this.expectedLength = null;

    socket.on('data', (data) => this.onData(data));
    socket.on('close', () => this.emit('close'));
    socket.on('error', (err) => this.emit('error', err));
  }

  onData(data) {
    this.buffer = Buffer.concat([this.buffer, data]);
    this.processBuffer();
  }

  processBuffer() {
    while (true) {
      if (this.expectedLength === null) {
        if (this.buffer.length < 4) return;
        this.expectedLength = this.buffer.readUInt32LE(0);
        this.buffer = this.buffer.slice(4);
      }

      if (this.buffer.length < this.expectedLength) return;

      const message = this.buffer.slice(0, this.expectedLength).toString('utf-8');
      this.buffer = this.buffer.slice(this.expectedLength);
      this.expectedLength = null;

      this.handleMessage(message);
    }
  }

  async handleMessage(message) {
    const response = await processRpcLine(this.svc, message);
    if (response) {
      this.send(response);
    }
  }

  send(obj) {
    const payload = Buffer.from(JSON.stringify(obj), 'utf-8');
    const header = Buffer.alloc(4);
    header.writeUInt32LE(payload.length, 0);
    this.socket.write(Buffer.concat([header, payload]));
  }
}

/**
 * Run as binary protocol TCP server (for high-performance clients)
 */
async function runBinaryTcpServer(svc, port, host = '127.0.0.1') {
  const server = createNetServer((socket) => {
    const handler = new BinaryProtocolHandler(socket, svc);
    handler.on('close', () => console.error('Binary client disconnected'));
    handler.on('error', (err) => console.error('Binary socket error:', err.message));
    console.error('Binary client connected');
  });

  server.listen(port, host, () => {
    console.error(`flatc binary TCP server listening on ${host}:${port}`);
  });

  process.on('SIGINT', () => {
    server.close();
    process.exit(0);
  });
}

// =============================================================================
// CLI
// =============================================================================

function printUsage() {
  console.log(`
flatc-stream.mjs - Streaming FlatBuffers compiler (Node.js/WASM)

I/O MODES:
  --daemon                              JSON-RPC on stdin/stdout
  --socket <path>                       Unix domain socket server
  --tcp <port> [--host <addr>]          TCP server (default host: 127.0.0.1)
  --binary-tcp <port>                   Binary protocol TCP (length-prefixed)
  --fifo <path> [--output <path>]       Named pipe (FIFO) server
  --watch <dir> --output <dir>          Folder watcher mode

SINGLE CONVERSION (pipe mode):
  --schema <file> --to-binary           Convert stdin JSON to binary (stdout)
  --schema <file> --to-json             Convert stdin binary to JSON (stdout)
  --schema <file> --generate <lang>     Generate code for language

OTHER:
  --version                             Show version
  --help                                Show this help

EXAMPLES:
  # Pipe conversion
  echo '{"name":"Orc"}' | node flatc-stream.mjs --schema monster.fbs --to-binary > out.bin

  # Unix socket daemon
  node flatc-stream.mjs --socket /tmp/flatc.sock &
  echo '{"jsonrpc":"2.0","id":1,"method":"version"}' | nc -U /tmp/flatc.sock

  # TCP server
  node flatc-stream.mjs --tcp 9876 &
  echo '{"jsonrpc":"2.0","id":1,"method":"listSchemas"}' | nc localhost 9876

  # Folder watcher (auto-convert JSON files to binary)
  node flatc-stream.mjs --watch ./json_input --output ./bin_output --schema monster.fbs

JSON-RPC METHODS:
  version                               Get flatc version
  addSchema {name, source}              Add schema from string
  addSchemaFile {path}                  Add schema from file
  removeSchema {name}                   Remove schema
  listSchemas                           List loaded schemas
  jsonToBinary {schema, json}           Convert JSON to binary (base64)
  binaryToJson {schema, binary}         Convert binary (base64) to JSON
  convert {schema, data}                Auto-detect and convert
  generateCode {schema, language}       Generate code
  ping                                  Health check
  stats                                 Server statistics

LANGUAGES: cpp, csharp, dart, go, java, kotlin, python, rust, swift, typescript, php, jsonschema, fbs
`);
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

async function main() {
  const args = process.argv.slice(2);

  if (args.includes('--help') || args.includes('-h') || args.length === 0) {
    printUsage();
    process.exit(0);
  }

  if (args.includes('--version') || args.includes('-v')) {
    const svc = await FlatcService.create();
    console.log(`flatc-stream.mjs version ${svc.getVersion()}`);
    process.exit(0);
  }

  const svc = await FlatcService.create();

  // Daemon modes
  if (args.includes('--daemon')) {
    await runStdinDaemon(svc);
    return;
  }

  const socketIdx = args.indexOf('--socket');
  if (socketIdx !== -1) {
    const socketPath = args[socketIdx + 1];
    if (!socketPath) {
      console.error('Error: --socket requires a path');
      process.exit(1);
    }
    await runSocketServer(svc, socketPath);
    return;
  }

  const tcpIdx = args.indexOf('--tcp');
  if (tcpIdx !== -1) {
    const port = parseInt(args[tcpIdx + 1], 10);
    if (isNaN(port)) {
      console.error('Error: --tcp requires a port number');
      process.exit(1);
    }
    const hostIdx = args.indexOf('--host');
    const host = hostIdx !== -1 ? args[hostIdx + 1] : '127.0.0.1';
    await runTcpServer(svc, port, host);
    return;
  }

  const binaryTcpIdx = args.indexOf('--binary-tcp');
  if (binaryTcpIdx !== -1) {
    const port = parseInt(args[binaryTcpIdx + 1], 10);
    if (isNaN(port)) {
      console.error('Error: --binary-tcp requires a port number');
      process.exit(1);
    }
    await runBinaryTcpServer(svc, port);
    return;
  }

  const fifoIdx = args.indexOf('--fifo');
  if (fifoIdx !== -1) {
    const fifoPath = args[fifoIdx + 1];
    if (!fifoPath) {
      console.error('Error: --fifo requires a path');
      process.exit(1);
    }
    const outputIdx = args.indexOf('--output');
    const outputPath = outputIdx !== -1 ? args[outputIdx + 1] : null;
    await runFifoServer(svc, fifoPath, outputPath);
    return;
  }

  const watchIdx = args.indexOf('--watch');
  if (watchIdx !== -1) {
    const inputDir = args[watchIdx + 1];
    const outputIdx = args.indexOf('--output');
    const outputDir = outputIdx !== -1 ? args[outputIdx + 1] : null;
    const schemaIdx = args.indexOf('--schema');
    const schemaPath = schemaIdx !== -1 ? args[schemaIdx + 1] : null;

    if (!inputDir || !outputDir || !schemaPath) {
      console.error('Error: --watch requires --output and --schema');
      process.exit(1);
    }

    await svc.addSchemaFile(schemaPath);
    const schemaName = path.basename(schemaPath);
    const toBinary = !args.includes('--to-json');
    await runFolderWatcher(svc, inputDir, outputDir, schemaName, { toBinary });
    return;
  }

  // Single conversion mode
  const schemaIdx = args.indexOf('--schema');
  if (schemaIdx === -1 || schemaIdx + 1 >= args.length) {
    console.error('Error: --schema <file> required for conversion');
    process.exit(1);
  }

  const schemaPath = args[schemaIdx + 1];
  await svc.addSchemaFile(schemaPath);
  const schemaName = path.basename(schemaPath);

  if (args.includes('--to-binary')) {
    const input = await readStdin();
    const json = input.toString('utf-8');
    const binary = svc.jsonToBinary(schemaName, json);
    process.stdout.write(Buffer.from(binary));
  } else if (args.includes('--to-json')) {
    const binary = await readStdin();
    const json = svc.binaryToJson(schemaName, new Uint8Array(binary));
    console.log(json);
  } else if (args.includes('--generate')) {
    const genIdx = args.indexOf('--generate');
    const langName = args[genIdx + 1]?.toLowerCase();
    const lang = LANGUAGE_MAP[langName];
    if (lang === undefined) {
      console.error(`Unknown language: ${langName}`);
      console.error(`Available: ${Object.keys(LANGUAGE_MAP).join(', ')}`);
      process.exit(1);
    }
    const code = svc.generateCode(schemaName, lang);
    console.log(code);
  } else {
    console.error('Error: specify --to-binary, --to-json, or --generate <lang>');
    process.exit(1);
  }
}

// Export for use as a module
export { FlatcService as default, handleRpcRequest, processRpcLine };

// Run if executed directly
main().catch(err => {
  console.error('Error:', err.message);
  process.exit(1);
});
