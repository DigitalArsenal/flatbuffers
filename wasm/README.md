<p align="center">
  <img src="https://flatbuffers.dev/assets/flatbuffers_logo.svg" alt="FlatBuffers Logo" width="200"/>
</p>

<h1 align="center">flatc-wasm</h1>

<p align="center">
  <a href="https://digitalarsenal.github.io/flatbuffers/">https://digitalarsenal.github.io/flatbuffers/</a>
</p>

<p align="center">
  <strong>FlatBuffers compiler as WebAssembly — run <code>flatc</code> in Node.js or the browser with zero native dependencies</strong>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/flatc-wasm"><img src="https://img.shields.io/npm/v/flatc-wasm.svg" alt="npm"></a>
  <a href="https://github.com/DigitalArsenal/flatbuffers/actions/workflows/build.yml"><img src="https://github.com/DigitalArsenal/flatbuffers/actions/workflows/build.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/DigitalArsenal/flatbuffers/actions/workflows/docs.yml"><img src="https://github.com/DigitalArsenal/flatbuffers/actions/workflows/docs.yml/badge.svg" alt="Docs"></a>
  <a href="https://github.com/DigitalArsenal/flatbuffers/actions/workflows/npm-publish-wasm.yml"><img src="https://github.com/DigitalArsenal/flatbuffers/actions/workflows/npm-publish-wasm.yml/badge.svg" alt="Publish"></a>
  <a href="https://github.com/DigitalArsenal/flatbuffers/blob/master/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License"></a>
</p>

---

## Features

| Category | Features |
|----------|----------|
| **Schema** | Add, remove, list, and export FlatBuffer schemas |
| **Conversion** | JSON ↔ FlatBuffer binary with auto-detection |
| **Code Gen** | 13 languages: C++, TypeScript, Go, Rust, Python, Java, C#, Swift, Kotlin, Dart, PHP, Lua, Nim |
| **JSON Schema** | Import JSON Schema as input, export FlatBuffers to JSON Schema |
| **Encryption** | Per-field AES-256-CTR encryption with `(encrypted)` attribute |
| **Streaming** | Process large data with streaming APIs |
| **Cross-Lang** | Same WASM runs in Node.js, Go, Python, Rust, Java, C#, Swift |
| **Zero Deps** | Self-contained with inlined WASM binaries |

---

## Installation

```bash
npm install flatc-wasm
```

---

## Requirements

| Platform | Minimum Version |
|----------|-----------------|
| Node.js | 18.0.0 or higher |
| Chrome | 57+ |
| Firefox | 52+ |
| Safari | 11+ |
| Edge | 79+ |

**Dependencies:**
- No native dependencies required (self-contained WASM)
- Optional: `hd-wallet-wasm` (included) for HD key derivation

**For building from source:**
- Emscripten SDK (emsdk)
- CMake 3.16+
- Python 3.8+

---

## Table of Contents

- [Quick Start](#quick-start)
- [FlatcRunner API](#flatcrunner-api) (Recommended)
- [Low-Level API Reference](#low-level-api-reference)
  - [Module Initialization](#module-initialization)
  - [Schema Management](#schema-management)
  - [JSON/Binary Conversion](#jsonbinary-conversion)
  - [Code Generation](#code-generation)
  - [Streaming API](#streaming-api)
  - [Low-Level C API](#low-level-c-api)
- [Browser Usage](#browser-usage)
- [Streaming Server](#streaming-server)
- [Examples](#examples)
- [Building from Source](#building-from-source)
- [TypeScript Support](#typescript-support)
- [Aligned Binary Format](#aligned-binary-format)
  - [Why Use Aligned Format?](#why-use-aligned-format)
  - [Basic Usage](#basic-usage)
  - [Fixed-Length Strings](#fixed-length-strings)
  - [Supported Types](#supported-types)
  - [WASM Interop Example](#wasm-interop-example)
- [Encryption](#encryption)
  - [Per-Field Encryption](#per-field-encryption)
  - [FlatcRunner Encryption API](#flatcrunner-encryption-api)
  - [Streaming Encryption](#streaming-encryption)
  - [Encryption Configuration](#encryption-configuration)
  - [FIPS Mode](#fips-mode)
- [Plugin Architecture](#plugin-architecture)
  - [Code Generator Plugins](#code-generator-plugins)
  - [Schema Transformation Plugins](#schema-transformation-plugins)
  - [Custom Language Generator Example](#custom-language-generator-example)
- [License](#license)

---

## Quick Start

The recommended way to use flatc-wasm is through the `FlatcRunner` class, which provides a clean CLI-style interface:

```javascript
import { FlatcRunner } from 'flatc-wasm';

// Initialize the runner
const flatc = await FlatcRunner.init();

// Check version
console.log(flatc.version());  // "flatc version 25.x.x"

// Define schema as a virtual file tree
const schemaInput = {
  entry: '/schemas/monster.fbs',
  files: {
    '/schemas/monster.fbs': `
      namespace Game;
      table Monster {
        name: string;
        hp: short = 100;
      }
      root_type Monster;
    `
  }
};

// Convert JSON to binary
const binary = flatc.generateBinary(schemaInput, '{"name": "Orc", "hp": 150}');
console.log('Binary size:', binary.length, 'bytes');

// Convert binary back to JSON
const json = flatc.generateJSON(schemaInput, {
  path: '/data/monster.bin',
  data: binary
});
console.log('JSON:', json);

// Generate TypeScript code
const code = flatc.generateCode(schemaInput, 'ts');
console.log('Generated files:', Object.keys(code));
```

### Alternative: Low-Level Module API

For advanced use cases, you can also use the raw WASM module directly:

```javascript
import createFlatcWasm from 'flatc-wasm';

const flatc = await createFlatcWasm();
console.log('FlatBuffers version:', flatc.getVersion());

// Add schema using Embind API
const handle = flatc.createSchema('monster.fbs', schema);
console.log('Schema ID:', handle.id());
```

---

## FlatcRunner API

The `FlatcRunner` class provides a high-level, type-safe API for all flatc operations. It wraps the flatc CLI with a virtual filesystem, making it easy to use in Node.js and browser environments.

### Initialization

```javascript
import { FlatcRunner } from 'flatc-wasm';

// Basic initialization
const flatc = await FlatcRunner.init();

// With custom options
const flatc = await FlatcRunner.init({
  print: (text) => console.log('[flatc]', text),
  printErr: (text) => console.error('[flatc]', text),
});

// Check version
console.log(flatc.version());  // "flatc version 25.x.x"

// Get full help text
console.log(flatc.help());
```

### Schema Input Format

All operations use a schema input tree that represents virtual files:

```javascript
// Simple single-file schema
const simpleSchema = {
  entry: '/schema.fbs',
  files: {
    '/schema.fbs': `
      table Message { text: string; }
      root_type Message;
    `
  }
};

// Multi-file schema with includes
const multiFileSchema = {
  entry: '/schemas/game.fbs',
  files: {
    '/schemas/game.fbs': `
      include "common.fbs";
      namespace Game;
      table Player {
        id: uint64;
        position: Common.Vec3;
        name: string;
      }
      root_type Player;
    `,
    '/schemas/common.fbs': `
      namespace Common;
      struct Vec3 {
        x: float;
        y: float;
        z: float;
      }
    `
  }
};
```

### Binary Generation (JSON → FlatBuffer)

Convert JSON data to FlatBuffer binary format:

```javascript
const binary = flatc.generateBinary(schemaInput, jsonData, {
  unknownJson: true,   // Allow unknown fields in JSON (default: true)
  strictJson: false,   // Require strict JSON conformance (default: false)
});

// Example with actual data
const schema = {
  entry: '/player.fbs',
  files: {
    '/player.fbs': `
      table Player { name: string; score: int; }
      root_type Player;
    `
  }
};

const json = JSON.stringify({ name: 'Alice', score: 100 });
const binary = flatc.generateBinary(schema, json);
console.log('Binary size:', binary.length, 'bytes');  // ~32 bytes
```

### JSON Generation (FlatBuffer → JSON)

Convert FlatBuffer binary back to JSON:

```javascript
const json = flatc.generateJSON(schemaInput, {
  path: '/data/input.bin',  // Virtual path (filename used for output naming)
  data: binaryData          // Uint8Array containing FlatBuffer binary
}, {
  strictJson: true,    // Output strict JSON format (default: true)
  rawBinary: true,     // Allow binaries without file_identifier (default: true)
  defaultsJson: false, // Include fields with default values (default: false)
  encoding: 'utf8',    // Return as string; use null for Uint8Array
});

// Round-trip example
const originalJson = '{"name": "Bob", "score": 250}';
const binary = flatc.generateBinary(schema, originalJson);
const recoveredJson = flatc.generateJSON(schema, {
  path: '/player.bin',
  data: binary
});
console.log(JSON.parse(recoveredJson));  // { name: 'Bob', score: 250 }
```

### Code Generation

Generate source code for any supported language:

```javascript
const files = flatc.generateCode(schemaInput, language, options);
```

#### Supported Languages

| Language    | Flag         | File Extension  |
| ----------- | ------------ | --------------- |
| C++         | `cpp`        | `.h`            |
| C#          | `csharp`     | `.cs`           |
| Dart        | `dart`       | `.dart`         |
| Go          | `go`         | `.go`           |
| Java        | `java`       | `.java`         |
| Kotlin      | `kotlin`     | `.kt`           |
| Kotlin KMP  | `kotlin-kmp` | `.kt`           |
| Lobster     | `lobster`    | `.lobster`      |
| Lua         | `lua`        | `.lua`          |
| Nim         | `nim`        | `.nim`          |
| PHP         | `php`        | `.php`          |
| Python      | `python`     | `.py`           |
| Rust        | `rust`       | `.rs`           |
| Swift       | `swift`      | `.swift`        |
| TypeScript  | `ts`         | `.ts`           |
| JSON        | `json`       | `.json`         |
| JSON Schema | `jsonschema` | `.schema.json`  |

#### Code Generation Options

```javascript
const files = flatc.generateCode(schemaInput, 'cpp', {
  // General options
  genObjectApi: true,    // Generate object-based API (Pack/UnPack methods)
  genOnefile: true,      // Generate all output in a single file
  genMutable: true,      // Generate mutable accessors for tables
  genCompare: true,      // Generate comparison operators
  genNameStrings: true,  // Generate type name strings for enums
  reflectNames: true,    // Add minimal reflection with field names
  reflectTypes: true,    // Add full reflection with type info
  genJsonEmit: true,     // Generate JSON emit helpers
  noIncludes: true,      // Don't generate include statements
  keepPrefix: true,      // Keep original prefix/namespace structure
  noWarnings: true,      // Suppress warning messages
  genAll: true,          // Generate code for all schemas (not just root)

  // Language-specific options
  pythonTyping: true,    // Python: Generate type hints (PEP 484)
  tsFlexBuffers: true,   // TypeScript: Include FlexBuffers support
  tsNoImportExt: true,   // TypeScript: Don't add .js to imports
  goModule: 'mymodule',  // Go: Module path for generated code
  goPackagePrefix: 'pkg' // Go: Package prefix for imports
});

// Result is a map of filename → content
for (const [filename, content] of Object.entries(files)) {
  console.log(`Generated: ${filename} (${content.length} bytes)`);
  // Write to disk, upload, etc.
}
```

#### Code Generation Examples

```javascript
// Generate TypeScript with object API
const tsFiles = flatc.generateCode(schema, 'ts', { genObjectApi: true });

// Generate Python with type hints
const pyFiles = flatc.generateCode(schema, 'python', { pythonTyping: true });

// Generate Rust
const rsFiles = flatc.generateCode(schema, 'rust');

// Generate C++ with all features
const cppFiles = flatc.generateCode(schema, 'cpp', {
  genObjectApi: true,
  genMutable: true,
  genCompare: true,
});
```

### JSON Schema Support

#### Export FlatBuffer Schema to JSON Schema

```javascript
const jsonSchema = flatc.generateJsonSchema(schemaInput);
const parsed = JSON.parse(jsonSchema);
console.log(parsed.$schema);  // "http://json-schema.org/draft-04/schema#"
```

#### Import JSON Schema

You can use JSON Schema files as input to FlatcRunner:

```javascript
const jsonSchemaInput = {
  entry: '/person.schema.json',
  files: {
    '/person.schema.json': JSON.stringify({
      "$schema": "http://json-schema.org/draft-07/schema#",
      "type": "object",
      "properties": {
        "name": { "type": "string" },
        "age": { "type": "integer" }
      },
      "required": ["name"]
    })
  }
};

// Generate code from JSON Schema
const code = flatc.generateCode(jsonSchemaInput, 'typescript');
```

### Virtual Filesystem Operations

The FlatcRunner provides direct access to the Emscripten virtual filesystem:

```javascript
// Mount a single file
flatc.mountFile('/schemas/types.fbs', schemaContent);

// Mount multiple files at once
flatc.mountFiles([
  { path: '/schemas/a.fbs', data: 'table A { x: int; }' },
  { path: '/schemas/b.fbs', data: 'table B { y: int; }' },
  { path: '/data/input.json', data: new Uint8Array([...]) },
]);

// Read a file back
const content = flatc.readFile('/schemas/a.fbs', { encoding: 'utf8' });

// Read as binary
const binary = flatc.readFile('/data/output.bin');  // Returns Uint8Array

// List directory contents
const files = flatc.readdir('/schemas');  // ['a.fbs', 'b.fbs']

// Recursively list all files
const allFiles = flatc.listAllFiles('/schemas');

// Delete files
flatc.unlink('/data/input.json');
flatc.rmdir('/data');
```

### Low-Level CLI Access

For advanced use cases, you can run any flatc command directly:

```javascript
// Run arbitrary flatc commands
const result = flatc.runCommand(['--help']);
console.log(result.code);    // Exit code (0 = success)
console.log(result.stdout);  // Standard output
console.log(result.stderr);  // Standard error

// Example: Generate binary schema (.bfbs)
flatc.mountFile('/schema.fbs', schemaContent);
const result = flatc.runCommand([
  '--binary',
  '--schema',
  '-o', '/output',
  '/schema.fbs'
]);

if (result.code === 0) {
  const bfbs = flatc.readFile('/output/schema.bfbs');
}

// Example: Use specific flatc flags
flatc.runCommand([
  '--cpp',
  '--gen-object-api',
  '--gen-mutable',
  '--scoped-enums',
  '-o', '/output',
  '/schema.fbs'
]);
```

### Error Handling

All FlatcRunner methods throw errors with descriptive messages:

```javascript
try {
  const binary = flatc.generateBinary(schema, '{ invalid json }');
} catch (error) {
  console.error('Conversion failed:', error.message);
  // "flatc binary generation failed (exit 0):
  //  error: ... json parse error ..."
}

try {
  const code = flatc.generateCode(schema, 'invalid-language');
} catch (error) {
  console.error('Code generation failed:', error.message);
}

// Check command results manually
const result = flatc.runCommand(['--invalid-flag']);
if (result.code !== 0 || result.stderr.includes('error:')) {
  console.error('Command failed:', result.stderr);
}
```

### Complete Example: Build Pipeline

```javascript
import { FlatcRunner } from 'flatc-wasm';
import { writeFileSync } from 'fs';

async function buildSchemas() {
  const flatc = await FlatcRunner.init();

  // Define your schemas
  const schema = {
    entry: '/schemas/game.fbs',
    files: {
      '/schemas/game.fbs': `
        namespace Game;

        enum ItemType : byte { Weapon, Armor, Potion }

        table Item {
          id: uint32;
          name: string (required);
          type: ItemType;
          value: int = 0;
        }

        table Inventory {
          items: [Item];
          gold: int;
        }

        root_type Inventory;
      `
    }
  };

  // Generate code for multiple languages
  const languages = ['typescript', 'python', 'rust', 'go'];

  for (const lang of languages) {
    const files = flatc.generateCode(schema, lang, {
      genObjectApi: true,
    });

    for (const [filename, content] of Object.entries(files)) {
      const outPath = `./generated/${lang}/${filename}`;
      writeFileSync(outPath, content);
      console.log(`Generated: ${outPath}`);
    }
  }

  // Generate JSON Schema for documentation
  const jsonSchema = flatc.generateJsonSchema(schema);
  writeFileSync('./docs/inventory.schema.json', jsonSchema);

  // Test conversion
  const testData = {
    items: [
      { id: 1, name: 'Sword', type: 'Weapon', value: 100 },
      { id: 2, name: 'Shield', type: 'Armor', value: 50 },
    ],
    gold: 500
  };

  const binary = flatc.generateBinary(schema, JSON.stringify(testData));
  console.log(`Binary size: ${binary.length} bytes`);

  const recovered = flatc.generateJSON(schema, {
    path: '/inventory.bin',
    data: binary
  });
  console.log('Round-trip successful:', JSON.parse(recovered));
}

buildSchemas().catch(console.error);
```

---

## Low-Level API Reference

### Module Initialization

#### ESM (recommended)

```javascript
import createFlatcWasm from 'flatc-wasm';

const flatc = await createFlatcWasm();
```

#### CommonJS

```javascript
const createFlatcWasm = require('flatc-wasm');

const flatc = await createFlatcWasm();
```

#### Embind High-Level API

The module provides a high-level API via Emscripten's Embind:

```javascript
const flatc = await createFlatcWasm();

// Version
flatc.getVersion();        // Returns "25.x.x"
flatc.getLastError();      // Returns last error message

// Schema management (returns SchemaHandle objects)
const handle = flatc.createSchema(name, source);
handle.id();               // Schema ID (number)
handle.name();             // Schema name (string)
handle.valid();            // Is handle valid? (boolean)
handle.release();          // Remove schema and invalidate handle

// Get all schemas
const handles = flatc.getAllSchemas();  // Returns array of SchemaHandle
```

---

### Schema Management

#### Adding Schemas

```javascript
// From string (.fbs format)
const handle = flatc.createSchema('monster.fbs', `
  namespace Game;
  table Monster {
    name: string;
    hp: int = 100;
  }
  root_type Monster;
`);

// Check if valid
if (handle.valid()) {
  console.log('Schema added with ID:', handle.id());
}
```

#### Adding JSON Schema

JSON Schema files are automatically detected and converted:

```javascript
// JSON Schema is auto-detected by content or .schema.json extension
const handle = flatc.createSchema('person.schema.json', `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "name": { "type": "string" },
    "age": { "type": "integer" }
  },
  "required": ["name"]
}`);
```

#### Listing and Removing Schemas

```javascript
// List all schemas
const schemas = flatc.getAllSchemas();
for (const schema of schemas) {
  console.log(`ID: ${schema.id()}, Name: ${schema.name()}`);
}

// Remove a schema
handle.release();
console.log('Valid after release:', handle.valid());  // false
```

---

### JSON/Binary Conversion

For conversions, use the low-level C API which provides direct memory access:

#### Helper Functions

```javascript
const encoder = new TextEncoder();
const decoder = new TextDecoder();

// Write string to WASM memory
function writeString(str) {
  const bytes = encoder.encode(str);
  const ptr = flatc._malloc(bytes.length);
  flatc.HEAPU8.set(bytes, ptr);
  return [ptr, bytes.length];
}

// Write bytes to WASM memory
function writeBytes(data) {
  const ptr = flatc._malloc(data.length);
  flatc.HEAPU8.set(data, ptr);
  return ptr;
}

// Get error message
function getLastError() {
  const ptr = flatc._wasm_get_last_error();
  return ptr ? flatc.UTF8ToString(ptr) : 'Unknown error';
}
```

#### JSON to Binary

```javascript
const schemaId = handle.id();
const json = '{"name": "Goblin", "hp": 50}';

const [jsonPtr, jsonLen] = writeString(json);
const outLenPtr = flatc._malloc(4);

try {
  const resultPtr = flatc._wasm_json_to_binary(schemaId, jsonPtr, jsonLen, outLenPtr);

  if (resultPtr === 0) {
    throw new Error(getLastError());
  }

  const len = flatc.getValue(outLenPtr, 'i32');
  const binary = flatc.HEAPU8.slice(resultPtr, resultPtr + len);

  console.log('Binary size:', binary.length, 'bytes');
  // binary is a Uint8Array containing the FlatBuffer
} finally {
  flatc._free(jsonPtr);
  flatc._free(outLenPtr);
}
```

#### Binary to JSON

```javascript
const binPtr = writeBytes(binary);
const outLenPtr = flatc._malloc(4);

try {
  const resultPtr = flatc._wasm_binary_to_json(schemaId, binPtr, binary.length, outLenPtr);

  if (resultPtr === 0) {
    throw new Error(getLastError());
  }

  const len = flatc.getValue(outLenPtr, 'i32');
  const jsonBytes = flatc.HEAPU8.slice(resultPtr, resultPtr + len);
  const json = decoder.decode(jsonBytes);

  console.log('JSON:', json);
} finally {
  flatc._free(binPtr);
  flatc._free(outLenPtr);
}
```

#### Auto-Detect Format

```javascript
// Detect format without conversion
const dataPtr = writeBytes(data);
const format = flatc._wasm_detect_format(dataPtr, data.length);
flatc._free(dataPtr);

// format: 0 = JSON, 1 = Binary, -1 = Unknown
console.log('Format:', format === 0 ? 'JSON' : format === 1 ? 'Binary' : 'Unknown');
```

#### Auto-Convert

```javascript
const dataPtr = writeBytes(data);
const outPtrPtr = flatc._malloc(4);
const outLenPtr = flatc._malloc(4);

try {
  // Returns: 0 = input was JSON (output is binary)
  //          1 = input was binary (output is JSON)
  //         -1 = error
  const format = flatc._wasm_convert_auto(schemaId, dataPtr, data.length, outPtrPtr, outLenPtr);

  if (format < 0) {
    throw new Error(getLastError());
  }

  const outPtr = flatc.getValue(outPtrPtr, 'i32');
  const outLen = flatc.getValue(outLenPtr, 'i32');
  const result = flatc.HEAPU8.slice(outPtr, outPtr + outLen);

  if (format === 0) {
    console.log('Converted JSON to binary:', result.length, 'bytes');
  } else {
    console.log('Converted binary to JSON:', decoder.decode(result));
  }
} finally {
  flatc._free(dataPtr);
  flatc._free(outPtrPtr);
  flatc._free(outLenPtr);
}
```

---

### Code Generation

Generate code for any supported language:

```javascript
// Language IDs
const Language = {
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
  FBS: 12,  // Re-export as .fbs
};

// Generate TypeScript code
const outLenPtr = flatc._malloc(4);

try {
  const resultPtr = flatc._wasm_generate_code(schemaId, Language.TypeScript, outLenPtr);

  if (resultPtr === 0) {
    throw new Error(getLastError());
  }

  const len = flatc.getValue(outLenPtr, 'i32');
  const codeBytes = flatc.HEAPU8.slice(resultPtr, resultPtr + len);
  const code = decoder.decode(codeBytes);

  console.log(code);
} finally {
  flatc._free(outLenPtr);
}
```

#### Get Language ID by Name

```javascript
// Get language ID from name (case-insensitive)
const [namePtr, nameLen] = writeString('typescript');
const langId = flatc._wasm_get_language_id(namePtr);
flatc._free(namePtr);

console.log('TypeScript ID:', langId);  // 9

// Aliases supported: "ts", "typescript", "c++", "cpp", "c#", "csharp", etc.
```

#### List Supported Languages

```javascript
const languages = flatc._wasm_get_supported_languages();
console.log(flatc.UTF8ToString(languages));
// "cpp,csharp,dart,go,java,kotlin,python,rust,swift,typescript,php,jsonschema,fbs"
```

---

### Streaming API

For processing large data without multiple JavaScript/WASM boundary crossings:

#### Stream Buffer Operations

```javascript
// Reset stream buffer
flatc._wasm_stream_reset();

// Add data in chunks
const chunk1 = encoder.encode('{"name":');
const chunk2 = encoder.encode('"Dragon", "hp": 500}');

// Write chunk 1
let ptr = flatc._wasm_stream_prepare(chunk1.length);
flatc.HEAPU8.set(chunk1, ptr);
flatc._wasm_stream_commit(chunk1.length);

// Write chunk 2
ptr = flatc._wasm_stream_prepare(chunk2.length);
flatc.HEAPU8.set(chunk2, ptr);
flatc._wasm_stream_commit(chunk2.length);

// Check accumulated size
console.log('Stream size:', flatc._wasm_stream_size());  // 31

// Convert accumulated data
const outPtrPtr = flatc._malloc(4);
const outLenPtr = flatc._malloc(4);

const format = flatc._wasm_stream_convert(schemaId, outPtrPtr, outLenPtr);

if (format >= 0) {
  const outPtr = flatc.getValue(outPtrPtr, 'i32');
  const outLen = flatc.getValue(outLenPtr, 'i32');
  const result = flatc.HEAPU8.slice(outPtr, outPtr + outLen);
  console.log('Converted:', result.length, 'bytes');
}

flatc._free(outPtrPtr);
flatc._free(outLenPtr);
```

#### Add Schema via Streaming

```javascript
// Stream a large schema file
flatc._wasm_stream_reset();

for (const chunk of schemaChunks) {
  const ptr = flatc._wasm_stream_prepare(chunk.length);
  flatc.HEAPU8.set(chunk, ptr);
  flatc._wasm_stream_commit(chunk.length);
}

const [namePtr, nameLen] = writeString('large_schema.fbs');
const schemaId = flatc._wasm_stream_add_schema(namePtr, nameLen);
flatc._free(namePtr);

if (schemaId < 0) {
  console.error('Failed:', getLastError());
}
```

---

### Low-Level C API

Complete list of exported C functions:

#### Utility Functions

| Function | Description |
|----------|-------------|
| `_wasm_get_version()` | Get FlatBuffers version string |
| `_wasm_get_last_error()` | Get last error message |
| `_wasm_clear_error()` | Clear error state |

#### Memory Management

| Function | Description |
|----------|-------------|
| `_wasm_malloc(size)` | Allocate memory |
| `_wasm_free(ptr)` | Free memory |
| `_wasm_realloc(ptr, size)` | Reallocate memory |
| `_malloc(size)` | Standard malloc |
| `_free(ptr)` | Standard free |

#### Schema Management

| Function | Description |
|----------|-------------|
| `_wasm_schema_add(name, nameLen, src, srcLen)` | Add schema, returns ID or -1 |
| `_wasm_schema_remove(id)` | Remove schema by ID |
| `_wasm_schema_count()` | Get number of loaded schemas |
| `_wasm_schema_list(outIds, maxCount)` | List schema IDs |
| `_wasm_schema_get_name(id)` | Get schema name by ID |
| `_wasm_schema_export(id, format, outLen)` | Export schema (0=FBS, 1=JSON Schema) |

#### Conversion Functions

| Function | Description |
|----------|-------------|
| `_wasm_json_to_binary(schemaId, json, jsonLen, outLen)` | JSON to FlatBuffer |
| `_wasm_binary_to_json(schemaId, bin, binLen, outLen)` | FlatBuffer to JSON |
| `_wasm_convert_auto(schemaId, data, dataLen, outPtr, outLen)` | Auto-detect and convert |
| `_wasm_detect_format(data, dataLen)` | Detect format (0=JSON, 1=Binary, -1=Unknown) |

#### Output Buffer Management

| Function | Description |
|----------|-------------|
| `_wasm_get_output_ptr()` | Get output buffer pointer |
| `_wasm_get_output_size()` | Get output buffer size |
| `_wasm_reserve_output(capacity)` | Pre-allocate output buffer |
| `_wasm_clear_output()` | Clear output buffer |

#### Stream Buffer Management

| Function | Description |
|----------|-------------|
| `_wasm_stream_reset()` | Clear stream buffer |
| `_wasm_stream_prepare(bytes)` | Prepare buffer for writing, returns pointer |
| `_wasm_stream_commit(bytes)` | Confirm bytes written |
| `_wasm_stream_size()` | Get current stream size |
| `_wasm_stream_data()` | Get stream buffer pointer |
| `_wasm_stream_convert(schemaId, outPtr, outLen)` | Convert stream buffer |
| `_wasm_stream_add_schema(name, nameLen)` | Add schema from stream buffer |

#### Code Generation

| Function | Description |
|----------|-------------|
| `_wasm_generate_code(schemaId, langId, outLen)` | Generate code |
| `_wasm_get_supported_languages()` | Get comma-separated language list |
| `_wasm_get_language_id(name)` | Get language ID from name |

---

## Browser Usage

### ES Module

```html
<script type="module">
import createFlatcWasm from 'https://unpkg.com/flatc-wasm/dist/flatc-wasm.js';

async function main() {
  const flatc = await createFlatcWasm();
  console.log('Version:', flatc.getVersion());

  // Add schema
  const handle = flatc.createSchema('person.fbs', `
    table Person {
      name: string;
      age: int;
    }
    root_type Person;
  `);

  // Convert JSON to binary
  const encoder = new TextEncoder();
  const json = '{"name": "Alice", "age": 30}';
  const jsonBytes = encoder.encode(json);

  const jsonPtr = flatc._malloc(jsonBytes.length);
  flatc.HEAPU8.set(jsonBytes, jsonPtr);
  const outLenPtr = flatc._malloc(4);

  const resultPtr = flatc._wasm_json_to_binary(
    handle.id(), jsonPtr, jsonBytes.length, outLenPtr
  );

  if (resultPtr) {
    const len = flatc.getValue(outLenPtr, 'i32');
    const binary = flatc.HEAPU8.slice(resultPtr, resultPtr + len);
    console.log('Binary size:', binary.length);

    // Download as file
    const blob = new Blob([binary], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'person.bin';
    a.click();
  }

  flatc._free(jsonPtr);
  flatc._free(outLenPtr);
}

main();
</script>
```

### With Bundlers (Webpack, Vite, etc.)

```javascript
// Works out of the box with modern bundlers
import createFlatcWasm from 'flatc-wasm';

const flatc = await createFlatcWasm();
```

---

## Streaming Server

For high-throughput scenarios, use the streaming CLI server:

### Start Server

```bash
# TCP server
npx flatc-wasm --tcp 9876

# Unix socket
npx flatc-wasm --socket /tmp/flatc.sock

# stdin/stdout daemon
npx flatc-wasm --daemon
```

### JSON-RPC Protocol

Send JSON-RPC 2.0 requests (one per line):

```bash
# Get version
echo '{"jsonrpc":"2.0","id":1,"method":"version"}' | nc localhost 9876

# Add schema
echo '{"jsonrpc":"2.0","id":2,"method":"addSchema","params":{"name":"monster.fbs","source":"table Monster { name:string; } root_type Monster;"}}' | nc localhost 9876

# Convert JSON to binary (base64 encoded)
echo '{"jsonrpc":"2.0","id":3,"method":"jsonToBinary","params":{"schema":"monster.fbs","json":"{\"name\":\"Orc\"}"}}' | nc localhost 9876

# Generate code
echo '{"jsonrpc":"2.0","id":4,"method":"generateCode","params":{"schema":"monster.fbs","language":"typescript"}}' | nc localhost 9876
```

### Available RPC Methods

| Method | Parameters | Description |
|--------|------------|-------------|
| `version` | - | Get FlatBuffers version |
| `addSchema` | `name`, `source` | Add schema from string |
| `addSchemaFile` | `path` | Add schema from file path |
| `removeSchema` | `name` | Remove schema by name |
| `listSchemas` | - | List loaded schema names |
| `jsonToBinary` | `schema`, `json` | Convert JSON to binary (base64) |
| `binaryToJson` | `schema`, `binary` | Convert binary (base64) to JSON |
| `convert` | `schema`, `data` | Auto-detect and convert |
| `generateCode` | `schema`, `language` | Generate code for language |
| `ping` | - | Health check |
| `stats` | - | Server statistics |

### Folder Watch Mode

Auto-convert files as they appear:

```bash
# Convert JSON files to binary
npx flatc-wasm --watch ./json_input --output ./bin_output --schema monster.fbs

# Convert binary files to JSON
npx flatc-wasm --watch ./bin_input --output ./json_output --schema monster.fbs --to-json
```

### Pipe Mode

Single-shot conversion via pipes:

```bash
# JSON to binary
echo '{"name":"Orc","hp":100}' | npx flatc-wasm --schema monster.fbs --to-binary > monster.bin

# Binary to JSON
cat monster.bin | npx flatc-wasm --schema monster.fbs --to-json

# Generate code
npx flatc-wasm --schema monster.fbs --generate typescript > monster.ts
```

---

## Examples

### Complete Conversion Example

```javascript
import createFlatcWasm from 'flatc-wasm';

async function example() {
  const flatc = await createFlatcWasm();
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  // Helper to write string to WASM
  function writeString(str) {
    const bytes = encoder.encode(str);
    const ptr = flatc._malloc(bytes.length);
    flatc.HEAPU8.set(bytes, ptr);
    return [ptr, bytes.length];
  }

  // Define schema with multiple types
  const schema = `
    namespace RPG;

    enum Class : byte { Warrior, Mage, Rogue }

    struct Vec3 {
      x: float;
      y: float;
      z: float;
    }

    table Weapon {
      name: string;
      damage: int;
    }

    table Character {
      name: string (required);
      class: Class = Warrior;
      level: int = 1;
      position: Vec3;
      weapons: [Weapon];
    }

    root_type Character;
  `;

  // Add schema
  const [namePtr, nameLen] = writeString('rpg.fbs');
  const [srcPtr, srcLen] = writeString(schema);
  const schemaId = flatc._wasm_schema_add(namePtr, nameLen, srcPtr, srcLen);
  flatc._free(namePtr);
  flatc._free(srcPtr);

  if (schemaId < 0) {
    const errPtr = flatc._wasm_get_last_error();
    throw new Error(flatc.UTF8ToString(errPtr));
  }

  console.log('Schema ID:', schemaId);

  // Create character JSON
  const characterJson = JSON.stringify({
    name: "Aragorn",
    class: "Warrior",  // Can use string name
    level: 87,
    position: { x: 100.5, y: 50.0, z: 25.3 },
    weapons: [
      { name: "Anduril", damage: 150 },
      { name: "Dagger", damage: 30 }
    ]
  });

  // Convert to binary
  const [jsonPtr, jsonLen] = writeString(characterJson);
  const outLenPtr = flatc._malloc(4);

  const binPtr = flatc._wasm_json_to_binary(schemaId, jsonPtr, jsonLen, outLenPtr);
  flatc._free(jsonPtr);

  if (binPtr === 0) {
    flatc._free(outLenPtr);
    const errPtr = flatc._wasm_get_last_error();
    throw new Error(flatc.UTF8ToString(errPtr));
  }

  const binLen = flatc.getValue(outLenPtr, 'i32');
  const binary = flatc.HEAPU8.slice(binPtr, binPtr + binLen);
  flatc._free(outLenPtr);

  console.log('Binary size:', binary.length, 'bytes');
  console.log('Compression ratio:', (characterJson.length / binary.length).toFixed(2) + 'x');

  // Convert back to JSON
  const bin2Ptr = flatc._malloc(binary.length);
  flatc.HEAPU8.set(binary, bin2Ptr);
  const outLen2Ptr = flatc._malloc(4);

  const jsonOutPtr = flatc._wasm_binary_to_json(schemaId, bin2Ptr, binary.length, outLen2Ptr);
  flatc._free(bin2Ptr);

  if (jsonOutPtr === 0) {
    flatc._free(outLen2Ptr);
    const errPtr = flatc._wasm_get_last_error();
    throw new Error(flatc.UTF8ToString(errPtr));
  }

  const jsonOutLen = flatc.getValue(outLen2Ptr, 'i32');
  const jsonBytes = flatc.HEAPU8.slice(jsonOutPtr, jsonOutPtr + jsonOutLen);
  const jsonOut = decoder.decode(jsonBytes);
  flatc._free(outLen2Ptr);

  console.log('Round-trip JSON:', jsonOut);

  // Generate TypeScript code
  const codeLenPtr = flatc._malloc(4);
  const codePtr = flatc._wasm_generate_code(schemaId, 9, codeLenPtr);  // 9 = TypeScript

  if (codePtr) {
    const codeLen = flatc.getValue(codeLenPtr, 'i32');
    const codeBytes = flatc.HEAPU8.slice(codePtr, codePtr + codeLen);
    const code = decoder.decode(codeBytes);
    console.log('Generated TypeScript:\n', code.substring(0, 500) + '...');
  }
  flatc._free(codeLenPtr);

  // Cleanup
  flatc._wasm_schema_remove(schemaId);
}

example().catch(console.error);
```

### Wrapper Class Example

```javascript
import createFlatcWasm from 'flatc-wasm';

class FlatBuffersCompiler {
  constructor(module) {
    this.module = module;
    this.encoder = new TextEncoder();
    this.decoder = new TextDecoder();
    this.schemas = new Map();
  }

  static async create() {
    const module = await createFlatcWasm();
    return new FlatBuffersCompiler(module);
  }

  getVersion() {
    return this.module.getVersion();
  }

  addSchema(name, source) {
    const [namePtr, nameLen] = this._writeString(name);
    const [srcPtr, srcLen] = this._writeString(source);

    try {
      const id = this.module._wasm_schema_add(namePtr, nameLen, srcPtr, srcLen);
      if (id < 0) throw new Error(this._getLastError());
      this.schemas.set(name, id);
      return id;
    } finally {
      this.module._free(namePtr);
      this.module._free(srcPtr);
    }
  }

  removeSchema(name) {
    const id = this.schemas.get(name);
    if (id === undefined) throw new Error(`Schema '${name}' not found`);
    this.module._wasm_schema_remove(id);
    this.schemas.delete(name);
  }

  jsonToBinary(schemaName, json) {
    const id = this._getSchemaId(schemaName);
    const [jsonPtr, jsonLen] = this._writeString(json);
    const outLenPtr = this.module._malloc(4);

    try {
      const ptr = this.module._wasm_json_to_binary(id, jsonPtr, jsonLen, outLenPtr);
      if (!ptr) throw new Error(this._getLastError());
      const len = this.module.getValue(outLenPtr, 'i32');
      return this.module.HEAPU8.slice(ptr, ptr + len);
    } finally {
      this.module._free(jsonPtr);
      this.module._free(outLenPtr);
    }
  }

  binaryToJson(schemaName, binary) {
    const id = this._getSchemaId(schemaName);
    const binPtr = this._writeBytes(binary);
    const outLenPtr = this.module._malloc(4);

    try {
      const ptr = this.module._wasm_binary_to_json(id, binPtr, binary.length, outLenPtr);
      if (!ptr) throw new Error(this._getLastError());
      const len = this.module.getValue(outLenPtr, 'i32');
      return this.decoder.decode(this.module.HEAPU8.slice(ptr, ptr + len));
    } finally {
      this.module._free(binPtr);
      this.module._free(outLenPtr);
    }
  }

  generateCode(schemaName, language) {
    const id = this._getSchemaId(schemaName);
    const langId = typeof language === 'number' ? language : this._getLanguageId(language);
    const outLenPtr = this.module._malloc(4);

    try {
      const ptr = this.module._wasm_generate_code(id, langId, outLenPtr);
      if (!ptr) throw new Error(this._getLastError());
      const len = this.module.getValue(outLenPtr, 'i32');
      return this.decoder.decode(this.module.HEAPU8.slice(ptr, ptr + len));
    } finally {
      this.module._free(outLenPtr);
    }
  }

  _writeString(str) {
    const bytes = this.encoder.encode(str);
    const ptr = this.module._malloc(bytes.length);
    this.module.HEAPU8.set(bytes, ptr);
    return [ptr, bytes.length];
  }

  _writeBytes(data) {
    const ptr = this.module._malloc(data.length);
    this.module.HEAPU8.set(data, ptr);
    return ptr;
  }

  _getSchemaId(name) {
    const id = this.schemas.get(name);
    if (id === undefined) throw new Error(`Schema '${name}' not found`);
    return id;
  }

  _getLastError() {
    const ptr = this.module._wasm_get_last_error();
    return ptr ? this.module.UTF8ToString(ptr) : 'Unknown error';
  }

  _getLanguageId(name) {
    const map = {
      cpp: 0, 'c++': 0, csharp: 1, 'c#': 1, dart: 2, go: 3,
      java: 4, kotlin: 5, python: 6, rust: 7, swift: 8,
      typescript: 9, ts: 9, php: 10, jsonschema: 11, fbs: 12
    };
    const id = map[name.toLowerCase()];
    if (id === undefined) throw new Error(`Unknown language: ${name}`);
    return id;
  }
}

// Usage
const compiler = await FlatBuffersCompiler.create();
compiler.addSchema('game.fbs', 'table Player { name: string; } root_type Player;');

const binary = compiler.jsonToBinary('game.fbs', '{"name": "Hero"}');
const json = compiler.binaryToJson('game.fbs', binary);
const tsCode = compiler.generateCode('game.fbs', 'typescript');
```

---

## Building from Source

```bash
# Clone the repository
git clone https://github.com/google/flatbuffers.git
cd flatbuffers

# Configure CMake (fetches Emscripten automatically)
cmake -B build/wasm -S . -DFLATBUFFERS_BUILD_WASM=ON

# Build the npm package (single file with inlined WASM)
cmake --build build/wasm --target flatc_wasm_npm

# Output is in wasm/dist/
ls wasm/dist/
# flatc-wasm.cjs  flatc-wasm.d.ts  flatc-wasm.js

# Run tests
cd wasm && npm test
```

### CMake Targets

#### Demo/Webserver Targets (no Emscripten required)

These targets run the interactive demo webserver using pre-built WASM modules:

```bash
# Configure without WASM build
cmake -B build -S .

# Start the development webserver (http://localhost:3000)
cmake --build build --target wasm_demo

# Build the demo for production deployment
cmake --build build --target wasm_demo_build
```

| Target            | Description                                            |
|-------------------|--------------------------------------------------------|
| `wasm_demo`       | Start development webserver at `http://localhost:3000` |
| `wasm_demo_build` | Build demo for production (outputs to `wasm/docs/dist/`) |

#### WASM Build Targets (requires Emscripten)

These targets build the WASM modules from source:

```bash
# Configure with WASM build enabled
cmake -B build -S . -DFLATBUFFERS_BUILD_WASM=ON

# Build all WASM modules
cmake --build build --target wasm_build

# Build WASM and start webserver in one command
cmake --build build --target wasm_build_and_serve
```

| Target                 | Description                                             |
|------------------------|---------------------------------------------------------|
| `wasm_build`           | Build all WASM modules (flatc_wasm + flatc_wasm_wasi)   |
| `wasm_build_and_serve` | Build WASM modules then start development webserver     |
| `flatc_wasm`           | Build main WASM module (separate .js and .wasm files)   |
| `flatc_wasm_inline`    | Build single .js file with inlined WASM                 |
| `flatc_wasm_npm`       | Build NPM package (uses inline version)                 |
| `flatc_wasm_wasi`      | Build WASI standalone encryption module                 |

#### Test Targets

| Target                   | Description                      |
|--------------------------|----------------------------------|
| `flatc_wasm_test`        | Run basic WASM tests             |
| `flatc_wasm_test_all`    | Run comprehensive test suite     |
| `flatc_wasm_test_parity` | Run WASM vs native parity tests  |
| `flatc_wasm_benchmark`   | Run performance benchmarks       |

#### Browser Example Targets

| Target                 | Description                          |
|------------------------|--------------------------------------|
| `browser_wallet_serve` | Start crypto wallet demo (port 3000) |
| `browser_wallet_build` | Build wallet demo for production     |
| `browser_examples`     | Start all browser demos              |

---

## TypeScript Support

Full TypeScript definitions are included:

```typescript
import createFlatcWasm from 'flatc-wasm';
import type { FlatcWasm, SchemaFormat, Language, DataFormat } from 'flatc-wasm';

const flatc: FlatcWasm = await createFlatcWasm();

// All APIs are fully typed
const version: string = flatc.getVersion();
const handle = flatc.createSchema('test.fbs', schema);
const isValid: boolean = handle.valid();
```

---

## Aligned Binary Format

The aligned binary format provides zero-overhead, fixed-size structs from FlatBuffers schemas, optimized for WASM/native interop and shared memory scenarios.

### Why Use Aligned Format?

| Standard FlatBuffers | Aligned Format |
|---------------------|----------------|
| Variable-size with vtables | Fixed-size structs |
| Requires deserialization | Zero-copy TypedArray views |
| Schema evolution support | No schema evolution |
| Strings and vectors | Fixed-size arrays and strings |

Use aligned format when you need:
- Direct TypedArray views into WASM linear memory
- Zero deserialization overhead
- Predictable memory layout for arrays of structs
- C++/WASM and JavaScript/TypeScript interop

### Basic Usage

```javascript
import { generateAlignedCode, parseSchema } from 'flatc-wasm/aligned-codegen';

const schema = `
namespace MyGame;

struct Vec3 {
  x:float;
  y:float;
  z:float;
}

table Entity {
  position:Vec3;
  health:int;
  mana:int;
}
`;

// Generate code for all languages
const result = generateAlignedCode(schema);
console.log(result.cpp);  // C++ header
console.log(result.ts);   // TypeScript module
console.log(result.js);   // JavaScript module
```

### Fixed-Length Strings

By default, strings are variable-length and not supported. Enable fixed-length strings by setting `defaultStringLength`:

```javascript
const schema = `
table Player {
  name:string;
  guild:string;
  health:int;
}
`;

// Strings become fixed-size char arrays (255 chars + null = 256 bytes)
const result = generateAlignedCode(schema, { defaultStringLength: 255 });
```

### Supported Types

| Type | Size | Notes |
|------|------|-------|
| `bool` | 1 byte | |
| `byte`, `ubyte`, `int8`, `uint8` | 1 byte | |
| `short`, `ushort`, `int16`, `uint16` | 2 bytes | |
| `int`, `uint`, `int32`, `uint32`, `float` | 4 bytes | |
| `long`, `ulong`, `int64`, `uint64`, `double` | 8 bytes | |
| `[type:N]` | N × size | Fixed-size arrays |
| `[ubyte:0x100]` | 256 bytes | Hex array sizes |
| `string` | configurable | Requires `defaultStringLength` |

### Generated Code Example

**C++ Header:**
```cpp
#pragma once
#include <cstdint>
#include <cstring>

namespace MyGame {

struct Vec3 {
  float x;
  float y;
  float z;
};
static_assert(sizeof(Vec3) == 12, "Vec3 size mismatch");

struct Entity {
  Vec3 position;
  int32_t health;
  int32_t mana;
};
static_assert(sizeof(Entity) == 20, "Entity size mismatch");

} // namespace MyGame
```

**TypeScript:**
```typescript
export const ENTITY_SIZE = 20;
export const ENTITY_ALIGN = 4;

export class EntityView {
  private _view: DataView;
  private _offset: number;

  constructor(view: DataView, offset: number = 0) {
    this._view = view;
    this._offset = offset;
  }

  get position(): Vec3View {
    return new Vec3View(this._view, this._offset + 0);
  }

  get health(): number {
    return this._view.getInt32(this._offset + 12, true);
  }
  set health(value: number) {
    this._view.setInt32(this._offset + 12, value, true);
  }

  get mana(): number {
    return this._view.getInt32(this._offset + 16, true);
  }
  set mana(value: number) {
    this._view.setInt32(this._offset + 16, value, true);
  }
}
```

### WASM Interop Example

```javascript
// JavaScript side
import { EntityView, ENTITY_SIZE } from './aligned_types.mjs';

// Get WASM memory buffer
const memory = wasmInstance.exports.memory;
const entityPtr = wasmInstance.exports.get_entity_array();
const count = wasmInstance.exports.get_entity_count();

// Create views directly into WASM memory
const view = new DataView(memory.buffer, entityPtr);
for (let i = 0; i < count; i++) {
  const entity = new EntityView(view, i * ENTITY_SIZE);
  console.log(`Entity ${i}: health=${entity.health}, mana=${entity.mana}`);
}
```

```cpp
// C++ WASM side
#include "aligned_types.h"

static Entity entities[1000];

extern "C" {
  Entity* get_entity_array() { return entities; }
  int get_entity_count() { return 1000; }

  void update_entities(float dt) {
    for (auto& e : entities) {
      e.position.x += e.velocity.x * dt;
      e.health = std::max(0, e.health - 1);
    }
  }
}
```

### Sharing Arrays Between WASM Modules

Since aligned binary structs have no embedded length metadata (unlike FlatBuffers vectors), you need to communicate array bounds **out-of-band**. This section covers patterns for sharing arrays of aligned structs between WASM modules or across the JS/WASM boundary.

#### Pattern 1: Pointer + Count (Recommended)

The simplest pattern - pass the pointer and count as separate values:

```cpp
// C++ WASM module
static Cartesian3 positions[10000];
static uint32_t position_count = 0;

extern "C" {
  Cartesian3* get_positions() { return positions; }
  uint32_t get_position_count() { return position_count; }
}
```

```typescript
// TypeScript consumer
const ptr = wasm.exports.get_positions();
const count = wasm.exports.get_position_count();
const positions = Cartesian3ArrayView.fromMemory(wasm.exports.memory, ptr, count);

for (const pos of positions) {
  console.log(`(${pos.x}, ${pos.y}, ${pos.z})`);
}
```

#### Pattern 2: Index-Based Lookup (Fixed Offset Known)

When struct size is known at compile time, store **indices** separately and compute offsets on access. This is ideal for sparse access, cross-references between arrays, or when indices are embedded in other structures.

```fbs
// Schema with cross-references via indices
namespace Space;

struct Cartesian3 {
  x: double;
  y: double;
  z: double;
}

// Satellite references positions by index, not pointer
table Satellite {
  norad_id: uint32;
  name: string;
  position_index: uint32;    // Index into positions array
  velocity_index: uint32;    // Index into velocities array
}

// Observation references multiple satellites by index
table Observation {
  timestamp: double;
  satellite_indices: [uint32:64];  // Up to 64 satellite indices
  satellite_count: uint32;
}
```

```cpp
// C++ - Dense arrays with index-based access
#include "space_aligned.h"

// Dense arrays in linear memory
static Cartesian3 positions[10000];
static Cartesian3 velocities[10000];
static Satellite satellites[1000];

extern "C" {
  // Export base pointers
  Cartesian3* get_positions_base() { return positions; }
  Cartesian3* get_velocities_base() { return velocities; }
  Satellite* get_satellites_base() { return satellites; }

  // Get position for a satellite (by satellite index)
  Cartesian3* get_satellite_position(uint32_t sat_idx) {
    uint32_t pos_idx = satellites[sat_idx].position_index;
    return &positions[pos_idx];
  }
}
```

```typescript
// TypeScript - Index-based random access
import { Cartesian3View, SatelliteView, CARTESIAN3_SIZE, SATELLITE_SIZE } from './space_aligned.mjs';

class SpaceDataManager {
  private memory: WebAssembly.Memory;
  private positionsBase: number;
  private velocitiesBase: number;
  private satellitesBase: number;

  constructor(wasm: WasmExports) {
    this.memory = wasm.memory;
    this.positionsBase = wasm.get_positions_base();
    this.velocitiesBase = wasm.get_velocities_base();
    this.satellitesBase = wasm.get_satellites_base();
  }

  // Direct index lookup - O(1) access
  getPositionByIndex(index: number): Cartesian3View {
    const offset = this.positionsBase + index * CARTESIAN3_SIZE;
    return Cartesian3View.fromMemory(this.memory, offset);
  }

  getVelocityByIndex(index: number): Cartesian3View {
    const offset = this.velocitiesBase + index * CARTESIAN3_SIZE;
    return Cartesian3View.fromMemory(this.memory, offset);
  }

  getSatelliteByIndex(index: number): SatelliteView {
    const offset = this.satellitesBase + index * SATELLITE_SIZE;
    return SatelliteView.fromMemory(this.memory, offset);
  }

  // Follow index reference from satellite to its position
  getSatellitePosition(satIndex: number): Cartesian3View {
    const sat = this.getSatelliteByIndex(satIndex);
    const posIndex = sat.position_index;
    return this.getPositionByIndex(posIndex);
  }

  // Batch lookup - get positions for multiple satellites
  getPositionsForSatellites(satIndices: number[]): Cartesian3View[] {
    return satIndices.map(satIdx => {
      const sat = this.getSatelliteByIndex(satIdx);
      return this.getPositionByIndex(sat.position_index);
    });
  }
}

// Usage
const manager = new SpaceDataManager(wasmExports);

// Direct access by known index
const pos = manager.getPositionByIndex(42);
console.log(`Position 42: (${pos.x}, ${pos.y}, ${pos.z})`);

// Follow cross-reference
const satPos = manager.getSatellitePosition(0);
console.log(`Satellite 0 position: (${satPos.x}, ${satPos.y}, ${satPos.z})`);
```

#### Pattern 3: Indices Embedded in Header Struct

Store indices in a metadata structure that references into data arrays:

```fbs
// Manifest with indices into data arrays
table EphemerisManifest {
  // Metadata
  epoch_start: double;
  epoch_end: double;
  step_seconds: double;

  // Indices into the points array (one range per satellite)
  satellite_start_indices: [uint32:100];  // Start index for each satellite
  satellite_point_counts: [uint32:100];   // Point count for each satellite
  satellite_count: uint32;
}

struct EphemerisPoint {
  jd: double;
  x: double;
  y: double;
  z: double;
  vx: double;
  vy: double;
  vz: double;
}
```

```typescript
// TypeScript - Navigate using manifest indices
import {
  EphemerisManifestView,
  EphemerisPointView,
  EphemerisPointArrayView,
  EPHEMERISPOINT_SIZE
} from './ephemeris_aligned.mjs';

class EphemerisReader {
  private manifest: EphemerisManifestView;
  private pointsBase: number;
  private memory: WebAssembly.Memory;

  constructor(memory: WebAssembly.Memory, manifestPtr: number, pointsPtr: number) {
    this.memory = memory;
    this.manifest = EphemerisManifestView.fromMemory(memory, manifestPtr);
    this.pointsBase = pointsPtr;
  }

  // Get all points for a specific satellite
  getSatellitePoints(satIndex: number): EphemerisPointArrayView {
    // Read start index and count from manifest
    const startIdx = this.manifest.satellite_start_indices[satIndex];
    const count = this.manifest.satellite_point_counts[satIndex];

    // Calculate byte offset: base + startIdx * structSize
    const offset = this.pointsBase + startIdx * EPHEMERISPOINT_SIZE;

    return new EphemerisPointArrayView(this.memory.buffer, offset, count);
  }

  // Get specific point by satellite and time index
  getPoint(satIndex: number, timeIndex: number): EphemerisPointView {
    const startIdx = this.manifest.satellite_start_indices[satIndex];
    const globalIdx = startIdx + timeIndex;
    const offset = this.pointsBase + globalIdx * EPHEMERISPOINT_SIZE;
    return EphemerisPointView.fromMemory(this.memory, offset);
  }

  // Iterate all satellites
  *iterateSatellites(): Generator<{index: number, points: EphemerisPointArrayView}> {
    const count = this.manifest.satellite_count;
    for (let i = 0; i < count; i++) {
      yield { index: i, points: this.getSatellitePoints(i) };
    }
  }
}

// Usage
const reader = new EphemerisReader(memory, manifestPtr, pointsPtr);

// Get ISS ephemeris (satellite 0)
const issPoints = reader.getSatellitePoints(0);
console.log(`ISS has ${issPoints.length} ephemeris points`);

// Get specific point
const point = reader.getPoint(0, 100);  // Satellite 0, time index 100
console.log(`Position at t=100: (${point.x}, ${point.y}, ${point.z})`);
```

#### Pattern 4: Pre-computed Offset Table

For variable-sized records or complex layouts, pre-compute byte offsets:

```fbs
// Offset table for complex data
table DataDirectory {
  record_count: uint32;
  byte_offsets: [uint32:10000];  // Byte offset of each record
  byte_sizes: [uint32:10000];    // Size of each record (if variable)
}
```

```typescript
// TypeScript - Use pre-computed offsets
class OffsetTableReader<T> {
  constructor(
    private memory: WebAssembly.Memory,
    private directory: DataDirectoryView,
    private dataBase: number,
    private viewFactory: (buffer: ArrayBuffer, offset: number) => T
  ) {}

  get(index: number): T {
    const byteOffset = this.directory.byte_offsets[index];
    return this.viewFactory(this.memory.buffer, this.dataBase + byteOffset);
  }

  getSize(index: number): number {
    return this.directory.byte_sizes[index];
  }

  get length(): number {
    return this.directory.record_count;
  }
}
```

### Real-World Example: Satellite Ephemeris

Complete example for sharing orbital data between WASM propagation and JS visualization:

```fbs
// satellite_ephemeris.fbs
namespace Astrodynamics;

struct StateVector {
  x: double;   // km (ECI)
  y: double;
  z: double;
  vx: double;  // km/s
  vy: double;
  vz: double;
}

struct EphemerisPoint {
  julian_date: double;
  state: StateVector;
}

// Manifest stores indices, data is in separate dense array
table EphemerisManifest {
  satellite_ids: [uint32:100];
  start_indices: [uint32:100];    // Index into points array
  point_counts: [uint32:100];     // How many points per satellite
  total_satellites: uint32;
  total_points: uint32;
}
```

```cpp
// propagator.cpp
#include "ephemeris_aligned.h"

static EphemerisManifest manifest;
static EphemerisPoint points[1000000];  // 1M points max

extern "C" {
  EphemerisManifest* get_manifest() { return &manifest; }
  EphemerisPoint* get_points_base() { return points; }

  // Add satellite ephemeris
  void add_satellite_ephemeris(uint32_t norad_id, EphemerisPoint* pts, uint32_t count) {
    uint32_t sat_idx = manifest.total_satellites++;
    uint32_t start_idx = manifest.total_points;

    manifest.satellite_ids[sat_idx] = norad_id;
    manifest.start_indices[sat_idx] = start_idx;
    manifest.point_counts[sat_idx] = count;

    // Copy points to dense array
    memcpy(&points[start_idx], pts, count * sizeof(EphemerisPoint));
    manifest.total_points += count;
  }
}
```

```typescript
// visualizer.ts
import {
  EphemerisManifestView,
  EphemerisPointView,
  StateVectorView,
  EPHEMERISPOINT_SIZE
} from './ephemeris_aligned.mjs';

class EphemerisVisualizer {
  private manifest: EphemerisManifestView;
  private pointsBase: number;
  private memory: WebAssembly.Memory;

  constructor(wasm: WasmExports) {
    this.memory = wasm.memory;
    this.manifest = EphemerisManifestView.fromMemory(
      this.memory,
      wasm.get_manifest()
    );
    this.pointsBase = wasm.get_points_base();
  }

  // Get position at specific time for satellite
  getPositionAtIndex(satIndex: number, timeIndex: number): StateVectorView {
    const startIdx = this.manifest.start_indices[satIndex];
    const pointOffset = this.pointsBase + (startIdx + timeIndex) * EPHEMERISPOINT_SIZE;

    // StateVector is at offset 8 within EphemerisPoint (after julian_date)
    const pt = EphemerisPointView.fromMemory(this.memory, pointOffset);
    return pt.state;  // Returns view into the state field
  }

  // Render all satellites at current time
  render(ctx: CanvasRenderingContext2D, timeIndex: number) {
    const satCount = this.manifest.total_satellites;

    for (let i = 0; i < satCount; i++) {
      const pointCount = this.manifest.point_counts[i];
      if (timeIndex >= pointCount) continue;

      const state = this.getPositionAtIndex(i, timeIndex);

      // Simple orthographic projection
      const screenX = ctx.canvas.width/2 + state.x / 100;
      const screenY = ctx.canvas.height/2 - state.y / 100;

      ctx.fillStyle = '#0f0';
      ctx.fillRect(screenX - 2, screenY - 2, 4, 4);
    }
  }
}
```

#### Memory Layout Summary

```
┌─────────────────────────────────────────────────────────────┐
│ EphemerisManifest (at manifest_ptr)                         │
│ ├─ satellite_ids[100]    - NORAD catalog numbers            │
│ ├─ start_indices[100]    - Index into points array          │
│ ├─ point_counts[100]     - Points per satellite             │
│ ├─ total_satellites      - Active satellite count           │
│ └─ total_points          - Total points in array            │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ EphemerisPoint[] (at points_base)                           │
│                                                             │
│ Satellite 0: indices [0, point_counts[0])                   │
│ ├─ points[0]: {jd, x, y, z, vx, vy, vz}                     │
│ ├─ points[1]: ...                                           │
│ └─ points[point_counts[0]-1]                                │
│                                                             │
│ Satellite 1: indices [start_indices[1], ...)                │
│ ├─ points[start_indices[1]]: ...                            │
│ └─ ...                                                      │
│                                                             │
│ Access formula:                                             │
│   offset = points_base + (start_indices[sat] + time) * 56   │
│   where 56 = EPHEMERISPOINT_SIZE                            │
└─────────────────────────────────────────────────────────────┘
```

---

## Encryption

flatc-wasm supports per-field AES-256-CTR encryption for FlatBuffer data. Fields marked with the `(encrypted)` attribute are transparently encrypted and decrypted, with key derivation via HKDF so each field gets a unique key/IV pair.

### Per-Field Encryption

Mark fields in your schema with the `(encrypted)` attribute:

```fbs
table UserRecord {
  id: uint64;
  name: string;
  ssn: string (encrypted);
  credit_card: string (encrypted);
  email: string;
}
root_type UserRecord;
```

When encryption is active, only the `ssn` and `credit_card` fields are encrypted. Other fields remain in plaintext, allowing indexing and queries on non-sensitive data.

**How it works:**
- A shared secret is derived via ECDH (X25519, secp256k1, P-256, or P-384)
- HKDF derives a unique AES-256 key and IV per field using the field name as context
- Each field is encrypted independently with AES-256-CTR
- An `EncryptionHeader` FlatBuffer stores the ephemeral public key and algorithm metadata

### FlatcRunner Encryption API

The `FlatcRunner` class provides high-level encryption methods:

```javascript
import { FlatcRunner } from 'flatc-wasm';

const flatc = await FlatcRunner.init();

const schema = {
  entry: '/user.fbs',
  files: {
    '/user.fbs': `
      table UserRecord {
        id: uint64;
        name: string;
        ssn: string (encrypted);
      }
      root_type UserRecord;
    `
  }
};

const json = JSON.stringify({ id: 1, name: 'Alice', ssn: '123-45-6789' });

// Encrypt: JSON → encrypted FlatBuffer
const { header, data } = flatc.generateBinaryEncrypted(schema, json, {
  publicKey: recipientPublicKey,   // Uint8Array (32 bytes for X25519)
  algorithm: 'x25519',            // Key exchange algorithm
  context: 'user-records',        // Optional HKDF domain separation
});

// Decrypt: encrypted FlatBuffer → JSON
const decryptedJson = flatc.generateJSONDecrypted(schema, { path: '/user.bin', data }, {
  privateKey: recipientPrivateKey, // Uint8Array
  header: header,                  // EncryptionHeader from encrypt step
});

console.log(JSON.parse(decryptedJson));
// { id: 1, name: 'Alice', ssn: '123-45-6789' }
```

#### Encryption Options

```javascript
// GenerateBinaryEncrypted options
{
  publicKey: Uint8Array,            // Recipient's public key (required)
  algorithm: 'x25519' | 'secp256k1' | 'p256' | 'p384',  // Default: 'x25519'
  fields: ['ssn', 'credit_card'],   // Specific fields (default: all (encrypted) fields)
  context: 'my-app',               // HKDF context for domain separation
  fips: false,                      // Use OpenSSL/FIPS backend
}

// GenerateJSONDecrypted options
{
  privateKey: Uint8Array,           // Decryption private key (required)
  header: Uint8Array,               // EncryptionHeader from encryption step
}
```

### Streaming Encryption

The `StreamingDispatcher` supports persistent encryption sessions for processing multiple messages:

```javascript
import { StreamingDispatcher } from 'flatc-wasm';

const dispatcher = new StreamingDispatcher(wasmModule);

// Enable encryption for the session
dispatcher.setEncryption(recipientPublicKey, {
  algorithm: 'x25519',
  context: 'stream-session',
});

// All subsequent messages are encrypted/decrypted automatically
dispatcher.dispatch(messageBuffer);

// Check encryption status
console.log(dispatcher.isEncryptionActive()); // true

// Disable encryption (securely zeros key material)
dispatcher.clearEncryption();
```

### Encryption Configuration

The encryption configuration is defined as a FlatBuffer schema (`encryption_config.fbs`):

```fbs
enum DataFormat : byte { FlatBuffer, JSON }
enum EncryptionDirection : byte { Encrypt, Decrypt }

table EncryptionConfig {
  recipient_public_key: [ubyte];
  algorithm: string;          // "x25519", "secp256k1", "p256", "p384"
  field_names: [string];      // Fields to encrypt (empty = use schema attributes)
  context: string;            // HKDF domain separation
  fips_mode: bool = false;
  direction: EncryptionDirection = Encrypt;
  private_key: [ubyte];       // For decryption
}
```

The `EncryptionHeader` stored with encrypted data:

```fbs
enum KeyExchangeAlgorithm : byte { X25519, Secp256k1, P256, P384 }

table EncryptionHeader {
  version: uint8 = 1;
  algorithm: KeyExchangeAlgorithm;
  ephemeral_public_key: [ubyte];
  encrypted_field_indices: [uint16];
  context: string;
}
```

### FIPS Mode

For environments requiring FIPS 140-2 compliance, build with OpenSSL instead of Crypto++:

```bash
cmake -B build/wasm -S . \
  -DFLATBUFFERS_BUILD_WASM=ON \
  -DFLATBUFFERS_WASM_USE_OPENSSL=ON

cmake --build build/wasm --target flatc_wasm_npm
```

When FIPS mode is enabled:
- All cryptographic operations use OpenSSL EVP APIs
- AES-256-CTR via `EVP_aes_256_ctr()`
- HKDF via `EVP_PKEY_derive()` with `EVP_PKEY_HKDF`
- X25519, P-256, P-384 ECDH via `EVP_PKEY_derive()`
- Ed25519 and ECDSA signatures via `EVP_DigestSign`/`EVP_DigestVerify`

To use FIPS mode at runtime, set `fips: true` in encryption options:

```javascript
const { header, data } = flatc.generateBinaryEncrypted(schema, json, {
  publicKey: recipientPublicKey,
  algorithm: 'p256',
  fips: true,
});
```

### Supported Key Exchange Algorithms

| Algorithm | Key Size | Curve | Use Case |
|-----------|----------|-------|----------|
| `x25519` | 32 bytes | Curve25519 | Default, fast, modern |
| `secp256k1` | 33 bytes (compressed) | secp256k1 | Bitcoin/blockchain compatibility |
| `p256` | 33 bytes (compressed) | NIST P-256 | FIPS compliance, broad support |
| `p384` | 49 bytes (compressed) | NIST P-384 | Higher security margin |

---

## Plugin Architecture

The flatc-wasm package supports an extensible plugin architecture for custom code generators and transformations.

### Code Generator Plugins

Create custom code generators that extend the standard flatc output:

```javascript
import { FlatcRunner } from 'flatc-wasm';
import { parseSchema, generateCppHeader, generateTypeScript } from 'flatc-wasm/aligned-codegen';

// Custom plugin that adds encryption metadata
class EncryptionPlugin {
  constructor(options = {}) {
    this.encryptedFields = options.encryptedFields || [];
  }

  transform(schema, generatedCode) {
    // Add encryption annotations to generated code
    const parsed = parseSchema(schema);
    // ... custom transformation logic
    return generatedCode;
  }
}

// Register and use plugin
const flatc = await FlatcRunner.init();
const plugin = new EncryptionPlugin({
  encryptedFields: ['ssn', 'credit_card']
});

const code = flatc.generateCode(schema, 'ts');
const transformedCode = plugin.transform(schema, code);
```

### Schema Transformation Plugins

Transform schemas before code generation:

```javascript
// Plugin that converts tables to aligned structs
function tableToStructPlugin(schema, options = {}) {
  const parsed = parseSchema(schema, options);

  // Filter tables that can be converted to aligned structs
  const alignableTypes = parsed.tables.filter(table => {
    return table.fields.every(field => {
      // Check if field type is fixed-size
      return field.size !== undefined && field.size > 0;
    });
  });

  return {
    ...parsed,
    alignableTypes,
    canAlign: alignableTypes.length > 0,
  };
}
```

### Available Extension Points

| Extension Point | Description |
|-----------------|-------------|
| `parseSchema()` | Parse FlatBuffers schema to AST |
| `computeLayout()` | Calculate memory layout for types |
| `generateCppHeader()` | Generate C++ header from parsed schema |
| `generateTypeScript()` | Generate TypeScript module from parsed schema |
| `generateJavaScript()` | Generate JavaScript module from parsed schema |
| `generateAlignedCode()` | Generate all languages at once |

### Custom Language Generator Example

```javascript
import { parseSchema, computeLayout } from 'flatc-wasm/aligned-codegen';

function generateRustAligned(schemaContent, options = {}) {
  const schema = parseSchema(schemaContent, options);
  let code = '// Auto-generated Rust aligned types\n\n';

  for (const structDef of schema.structs) {
    const layout = computeLayout(structDef);
    code += `#[repr(C)]\n`;
    code += `pub struct ${structDef.name} {\n`;

    for (const field of layout.fields) {
      const rustType = toRustType(field);
      code += `    pub ${field.name}: ${rustType},\n`;
    }

    code += `}\n\n`;
  }

  return code;
}

function toRustType(field) {
  const typeMap = {
    'int32': 'i32',
    'uint32': 'u32',
    'float': 'f32',
    'double': 'f64',
    // ... add more mappings
  };
  return typeMap[field.type] || field.type;
}
```

---

## Performance Tips

1. **Reuse schemas**: Add schemas once and reuse them for multiple conversions
2. **Use streaming for large data**: The stream API avoids multiple memory copies
3. **Pre-allocate output buffer**: Call `_wasm_reserve_output(size)` for known output sizes
4. **Batch operations**: The WASM module has startup overhead; batch multiple conversions
5. **Use binary protocol**: For high-throughput scenarios, use the length-prefixed binary TCP protocol

---

## License

Apache-2.0

This package a fork of the [FlatBuffers](https://github.com/google/flatbuffers) project by Google.
