# flatc-wasm

FlatBuffers compiler (`flatc`) as a WebAssembly module. Run the FlatBuffers compiler directly in Node.js or the browser without native dependencies.

## Features

- **Schema Management**: Add, remove, list, and export FlatBuffer schemas
- **JSON/Binary Conversion**: Convert between JSON and FlatBuffer binary formats
- **Code Generation**: Generate code for 13 languages (C++, TypeScript, Go, Rust, etc.)
- **JSON Schema Support**: Import JSON Schema and convert to FlatBuffer schemas
- **Streaming Support**: Process large data with streaming APIs
- **Zero Dependencies**: Self-contained WASM module with inlined binary (~2.7MB)

## Installation

```bash
npm install flatc-wasm
```

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

### Build Targets

| Target | Description |
|--------|-------------|
| `flatc_wasm` | Separate .js and .wasm files |
| `flatc_wasm_inline` | Single .js file with inlined WASM |
| `flatc_wasm_npm` | NPM package (uses inline version) |
| `flatc_wasm_test` | Run basic tests |
| `flatc_wasm_test_all` | Run comprehensive tests |
| `flatc_wasm_benchmark` | Run performance benchmarks |

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

## Performance Tips

1. **Reuse schemas**: Add schemas once and reuse them for multiple conversions
2. **Use streaming for large data**: The stream API avoids multiple memory copies
3. **Pre-allocate output buffer**: Call `_wasm_reserve_output(size)` for known output sizes
4. **Batch operations**: The WASM module has startup overhead; batch multiple conversions
5. **Use binary protocol**: For high-throughput scenarios, use the length-prefixed binary TCP protocol

---

## License

Apache-2.0

This package is part of the [FlatBuffers](https://github.com/google/flatbuffers) project by Google.
