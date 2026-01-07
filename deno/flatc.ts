#!/usr/bin/env -S deno run --allow-read --allow-write
/**
 * flatc.ts - Deno CLI wrapper for FlatBuffers WASM compiler
 *
 * This provides a streaming, in-memory FlatBuffers compiler that can:
 * - Load multiple schemas and keep them resident
 * - Convert JSON ↔ FlatBuffer binary via pipes
 * - Run as a daemon accepting commands via stdin
 * - Be imported as a Deno module
 *
 * Usage:
 *   # Single conversion
 *   echo '{"name":"test"}' | deno run flatc.ts --schema monster.fbs --to-binary > out.bin
 *
 *   # Daemon mode (accepts JSON-RPC commands)
 *   deno run flatc.ts --daemon
 *
 *   # As a module
 *   import { FlatcService } from "./flatc.ts";
 *   const svc = await FlatcService.create();
 *   svc.addSchema("monster.fbs", schemaContent);
 *   const binary = svc.jsonToBinary("monster.fbs", jsonData);
 */

// Import the WASM module - in production this would be inlined
// For now, we load it from the build output
const WASM_PATH = new URL("../build/wasm/wasm/flatc.js", import.meta.url);

interface WasmModule {
  _malloc(size: number): number;
  _free(ptr: number): void;
  HEAPU8: Uint8Array;
  getValue(ptr: number, type: string): number;
  setValue(ptr: number, value: number, type: string): void;
  UTF8ToString(ptr: number): string;
  stringToUTF8(str: string, ptr: number, maxLen: number): void;
  lengthBytesUTF8(str: string): number;
  getVersion(): string;

  // Our exported functions
  _wasm_schema_add(namePtr: number, nameLen: number, srcPtr: number, srcLen: number): number;
  _wasm_schema_remove(id: number): number;
  _wasm_schema_count(): number;
  _wasm_schema_get_name(id: number): number;
  _wasm_json_to_binary(schemaId: number, jsonPtr: number, jsonLen: number, outLenPtr: number): number;
  _wasm_binary_to_json(schemaId: number, binPtr: number, binLen: number, outLenPtr: number): number;
  _wasm_detect_format(dataPtr: number, dataLen: number): number;
  _wasm_get_last_error(): number;
  _wasm_generate_code(schemaId: number, language: number, outLenPtr: number): number;
}

export enum Language {
  CPP = 0,
  CSharp = 1,
  Dart = 2,
  Go = 3,
  Java = 4,
  Kotlin = 5,
  Python = 6,
  Rust = 7,
  Swift = 8,
  TypeScript = 9,
  PHP = 10,
  JSONSchema = 11,
  FBS = 12,
}

export enum DataFormat {
  JSON = 0,
  Binary = 1,
  Unknown = -1,
}

/**
 * FlatcService - In-memory FlatBuffers compiler service
 *
 * Keeps schemas resident for repeated conversions.
 */
export class FlatcService {
  private module: WasmModule;
  private schemaMap = new Map<string, number>(); // name -> id
  private encoder = new TextEncoder();
  private decoder = new TextDecoder();

  private constructor(module: WasmModule) {
    this.module = module;
  }

  static async create(wasmPath?: string): Promise<FlatcService> {
    const path = wasmPath || WASM_PATH.pathname;
    const moduleFactory = await import(path);
    const module = await moduleFactory.default() as WasmModule;
    return new FlatcService(module);
  }

  getVersion(): string {
    return this.module.getVersion();
  }

  private writeString(str: string): [number, number] {
    const bytes = this.encoder.encode(str);
    const ptr = this.module._malloc(bytes.length);
    this.module.HEAPU8.set(bytes, ptr);
    return [ptr, bytes.length];
  }

  private writeBytes(data: Uint8Array): number {
    const ptr = this.module._malloc(data.length);
    this.module.HEAPU8.set(data, ptr);
    return ptr;
  }

  private readString(ptr: number): string {
    return this.module.UTF8ToString(ptr);
  }

  private getLastError(): string {
    const ptr = this.module._wasm_get_last_error();
    return ptr ? this.readString(ptr) : "Unknown error";
  }

  /**
   * Add a schema from source content
   */
  addSchema(name: string, source: string): void {
    // Remove existing schema with same name if present
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
    } finally {
      this.module._free(namePtr);
      this.module._free(srcPtr);
    }
  }

  /**
   * Add a schema from a file
   */
  async addSchemaFile(path: string): Promise<void> {
    const content = await Deno.readTextFile(path);
    const name = path.split("/").pop() || path;
    this.addSchema(name, content);
  }

  /**
   * Remove a schema by name
   */
  removeSchema(name: string): void {
    const id = this.schemaMap.get(name);
    if (id === undefined) {
      throw new Error(`Schema '${name}' not found`);
    }
    this.module._wasm_schema_remove(id);
    this.schemaMap.delete(name);
  }

  /**
   * List loaded schema names
   */
  listSchemas(): string[] {
    return Array.from(this.schemaMap.keys());
  }

  /**
   * Get schema ID by name
   */
  private getSchemaId(name: string): number {
    const id = this.schemaMap.get(name);
    if (id === undefined) {
      throw new Error(`Schema '${name}' not found. Loaded schemas: ${this.listSchemas().join(", ") || "none"}`);
    }
    return id;
  }

  /**
   * Convert JSON string to FlatBuffer binary
   */
  jsonToBinary(schemaName: string, json: string): Uint8Array {
    const schemaId = this.getSchemaId(schemaName);
    const [jsonPtr, jsonLen] = this.writeString(json);
    const outLenPtr = this.module._malloc(4);

    try {
      const resultPtr = this.module._wasm_json_to_binary(schemaId, jsonPtr, jsonLen, outLenPtr);
      if (!resultPtr) {
        throw new Error(`JSON to binary failed: ${this.getLastError()}`);
      }

      const len = this.module.getValue(outLenPtr, "i32");
      return this.module.HEAPU8.slice(resultPtr, resultPtr + len);
    } finally {
      this.module._free(jsonPtr);
      this.module._free(outLenPtr);
    }
  }

  /**
   * Convert FlatBuffer binary to JSON string
   */
  binaryToJson(schemaName: string, binary: Uint8Array): string {
    const schemaId = this.getSchemaId(schemaName);
    const binPtr = this.writeBytes(binary);
    const outLenPtr = this.module._malloc(4);

    try {
      const resultPtr = this.module._wasm_binary_to_json(schemaId, binPtr, binary.length, outLenPtr);
      if (!resultPtr) {
        throw new Error(`Binary to JSON failed: ${this.getLastError()}`);
      }

      const len = this.module.getValue(outLenPtr, "i32");
      const data = this.module.HEAPU8.slice(resultPtr, resultPtr + len);
      return this.decoder.decode(data);
    } finally {
      this.module._free(binPtr);
      this.module._free(outLenPtr);
    }
  }

  /**
   * Detect the format of data
   */
  detectFormat(data: Uint8Array): DataFormat {
    const ptr = this.writeBytes(data);
    try {
      return this.module._wasm_detect_format(ptr, data.length) as DataFormat;
    } finally {
      this.module._free(ptr);
    }
  }

  /**
   * Auto-convert: JSON→Binary or Binary→JSON based on detection
   */
  convert(schemaName: string, data: Uint8Array): { format: DataFormat; result: Uint8Array | string } {
    const format = this.detectFormat(data);
    if (format === DataFormat.JSON) {
      const json = this.decoder.decode(data);
      return { format, result: this.jsonToBinary(schemaName, json) };
    } else if (format === DataFormat.Binary) {
      return { format, result: this.binaryToJson(schemaName, data) };
    } else {
      throw new Error("Unknown data format");
    }
  }

  /**
   * Generate code for a schema
   */
  generateCode(schemaName: string, language: Language): string {
    const schemaId = this.getSchemaId(schemaName);
    const outLenPtr = this.module._malloc(4);

    try {
      const resultPtr = this.module._wasm_generate_code(schemaId, language, outLenPtr);
      if (!resultPtr) {
        throw new Error(`Code generation failed: ${this.getLastError()}`);
      }

      const len = this.module.getValue(outLenPtr, "i32");
      const data = this.module.HEAPU8.slice(resultPtr, resultPtr + len);
      return this.decoder.decode(data);
    } finally {
      this.module._free(outLenPtr);
    }
  }
}

// =============================================================================
// JSON-RPC Daemon Protocol
// =============================================================================

interface RpcRequest {
  jsonrpc: "2.0";
  id: number | string;
  method: string;
  params?: Record<string, unknown>;
}

interface RpcResponse {
  jsonrpc: "2.0";
  id: number | string;
  result?: unknown;
  error?: { code: number; message: string };
}

/**
 * Run as a daemon accepting JSON-RPC commands on stdin
 */
async function runDaemon(svc: FlatcService): Promise<void> {
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();

  console.error(`flatc daemon started (version ${svc.getVersion()})`);
  console.error("Send JSON-RPC requests on stdin, one per line");
  console.error("Methods: addSchema, removeSchema, listSchemas, jsonToBinary, binaryToJson, convert, generateCode");

  const stdin = Deno.stdin.readable.getReader();
  let buffer = "";

  while (true) {
    const { value, done } = await stdin.read();
    if (done) break;

    buffer += decoder.decode(value);

    // Process complete lines
    let newlineIdx: number;
    while ((newlineIdx = buffer.indexOf("\n")) !== -1) {
      const line = buffer.slice(0, newlineIdx).trim();
      buffer = buffer.slice(newlineIdx + 1);

      if (!line) continue;

      let response: RpcResponse;
      try {
        const req = JSON.parse(line) as RpcRequest;
        const result = await handleRpcRequest(svc, req);
        response = { jsonrpc: "2.0", id: req.id, result };
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        response = { jsonrpc: "2.0", id: 0, error: { code: -1, message } };
      }

      const output = JSON.stringify(response) + "\n";
      await Deno.stdout.write(encoder.encode(output));
    }
  }
}

async function handleRpcRequest(svc: FlatcService, req: RpcRequest): Promise<unknown> {
  const p = req.params || {};

  switch (req.method) {
    case "version":
      return svc.getVersion();

    case "addSchema":
      if (typeof p.name !== "string" || typeof p.source !== "string") {
        throw new Error("addSchema requires 'name' and 'source' params");
      }
      svc.addSchema(p.name, p.source);
      return { success: true };

    case "addSchemaFile":
      if (typeof p.path !== "string") {
        throw new Error("addSchemaFile requires 'path' param");
      }
      await svc.addSchemaFile(p.path);
      return { success: true };

    case "removeSchema":
      if (typeof p.name !== "string") {
        throw new Error("removeSchema requires 'name' param");
      }
      svc.removeSchema(p.name);
      return { success: true };

    case "listSchemas":
      return svc.listSchemas();

    case "jsonToBinary":
      if (typeof p.schema !== "string" || typeof p.json !== "string") {
        throw new Error("jsonToBinary requires 'schema' and 'json' params");
      }
      const binary = svc.jsonToBinary(p.schema, p.json);
      return { binary: btoa(String.fromCharCode(...binary)) }; // base64

    case "binaryToJson":
      if (typeof p.schema !== "string" || typeof p.binary !== "string") {
        throw new Error("binaryToJson requires 'schema' and 'binary' (base64) params");
      }
      const binData = Uint8Array.from(atob(p.binary), c => c.charCodeAt(0));
      return { json: svc.binaryToJson(p.schema, binData) };

    case "convert":
      if (typeof p.schema !== "string" || typeof p.data !== "string") {
        throw new Error("convert requires 'schema' and 'data' (base64) params");
      }
      const data = Uint8Array.from(atob(p.data), c => c.charCodeAt(0));
      const convResult = svc.convert(p.schema, data);
      if (convResult.result instanceof Uint8Array) {
        return { format: "json", result: btoa(String.fromCharCode(...convResult.result)) };
      }
      return { format: "binary", result: convResult.result };

    case "generateCode":
      if (typeof p.schema !== "string" || typeof p.language !== "number") {
        throw new Error("generateCode requires 'schema' and 'language' params");
      }
      return { code: svc.generateCode(p.schema, p.language as Language) };

    default:
      throw new Error(`Unknown method: ${req.method}`);
  }
}

// =============================================================================
// CLI Mode
// =============================================================================

function printUsage(): void {
  console.log(`
flatc.ts - Streaming FlatBuffers compiler (Deno/WASM)

Usage:
  flatc.ts --daemon                              Run as JSON-RPC daemon
  flatc.ts --schema <file> --to-binary          Convert stdin JSON to binary
  flatc.ts --schema <file> --to-json            Convert stdin binary to JSON
  flatc.ts --schema <file> --generate <lang>    Generate code for language
  flatc.ts --version                            Show version

Daemon mode accepts JSON-RPC 2.0 on stdin, outputs on stdout.

Example daemon commands:
  {"jsonrpc":"2.0","id":1,"method":"addSchema","params":{"name":"monster.fbs","source":"..."}}
  {"jsonrpc":"2.0","id":2,"method":"jsonToBinary","params":{"schema":"monster.fbs","json":"{...}"}}
  {"jsonrpc":"2.0","id":3,"method":"listSchemas"}

Languages for --generate: cpp, csharp, dart, go, java, kotlin, python, rust, swift, typescript, php, jsonschema, fbs
`);
}

async function readStdin(): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  const reader = Deno.stdin.readable.getReader();

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    chunks.push(value);
  }

  const totalLen = chunks.reduce((sum, c) => sum + c.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

const LANGUAGE_MAP: Record<string, Language> = {
  cpp: Language.CPP,
  "c++": Language.CPP,
  csharp: Language.CSharp,
  "c#": Language.CSharp,
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

async function main(): Promise<void> {
  const args = Deno.args;

  if (args.includes("--help") || args.includes("-h") || args.length === 0) {
    printUsage();
    Deno.exit(0);
  }

  if (args.includes("--version") || args.includes("-v")) {
    const svc = await FlatcService.create();
    console.log(`flatc.ts version ${svc.getVersion()}`);
    Deno.exit(0);
  }

  const svc = await FlatcService.create();

  if (args.includes("--daemon")) {
    await runDaemon(svc);
    Deno.exit(0);
  }

  // CLI conversion mode
  const schemaIdx = args.indexOf("--schema");
  if (schemaIdx === -1 || schemaIdx + 1 >= args.length) {
    console.error("Error: --schema <file> required");
    Deno.exit(1);
  }

  const schemaPath = args[schemaIdx + 1];
  await svc.addSchemaFile(schemaPath);
  const schemaName = schemaPath.split("/").pop() || schemaPath;

  if (args.includes("--to-binary")) {
    const input = await readStdin();
    const json = new TextDecoder().decode(input);
    const binary = svc.jsonToBinary(schemaName, json);
    await Deno.stdout.write(binary);
  } else if (args.includes("--to-json")) {
    const binary = await readStdin();
    const json = svc.binaryToJson(schemaName, binary);
    console.log(json);
  } else if (args.includes("--generate")) {
    const genIdx = args.indexOf("--generate");
    const langName = args[genIdx + 1]?.toLowerCase();
    const lang = LANGUAGE_MAP[langName];
    if (lang === undefined) {
      console.error(`Unknown language: ${langName}`);
      console.error(`Available: ${Object.keys(LANGUAGE_MAP).join(", ")}`);
      Deno.exit(1);
    }
    const code = svc.generateCode(schemaName, lang);
    console.log(code);
  } else {
    console.error("Error: specify --to-binary, --to-json, or --generate <lang>");
    Deno.exit(1);
  }
}

// Run if executed directly
if (import.meta.main) {
  main();
}
