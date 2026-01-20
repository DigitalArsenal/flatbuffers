# flatc-wasm

FlatBuffers compiler (`flatc`) as a WebAssembly module. Run the FlatBuffers compiler directly in Node.js or the browser without native dependencies.

## Features

- **Schema Management**: Add, remove, list, and export FlatBuffer schemas
- **JSON/Binary Conversion**: Convert between JSON and FlatBuffer binary formats
- **Code Generation**: Generate code for 13 languages (C++, TypeScript, Go, Rust, etc.)
- **JSON Schema Support**: Import JSON Schema and convert to FlatBuffer schemas
- **Streaming Support**: Process large data with streaming APIs
- **End-to-End Encryption**: AES-256-CTR encryption with ECDH key exchange (X25519, secp256k1, P-256)
- **Digital Signatures**: Ed25519 and ECDSA signing for message authentication
- **Cryptocurrency Compatible**: Keys work with Bitcoin, Ethereum, Solana, and 7 other blockchains
- **Cross-Language**: Encryption works across Node.js, Go, Python, Rust, Java, C#, and Swift
- **Zero Dependencies**: Self-contained WASM modules with inlined binaries

## Installation

```bash
npm install flatc-wasm
```

## Table of Contents

- [Quick Start](#quick-start)
- [FlatcRunner API](#flatcrunner-api) (Recommended)
- [Encryption Module](#encryption-module)
  - [End-to-End Encryption Flow](#end-to-end-encryption-flow)
  - [Cryptographic Operations](#cryptographic-operations)
  - [Key Exchange (ECDH)](#key-exchange-ecdh)
  - [Digital Signatures](#digital-signatures)
  - [Cryptocurrency Compatibility](#cryptocurrency-compatibility)
  - [Cross-Language Support](#cross-language-support)
    - [Go Example](#go-example)
    - [Python Example](#python-example)
    - [Rust Example](#rust-example)
    - [Java Example](#java-example-chicory)
    - [C# Example](#c-example)
    - [Swift Example](#swift-example)
  - [WASM Function Reference](#wasm-function-reference)
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

## Encryption Module

The `flatc-wasm` package includes a separate encryption module powered by Crypto++ compiled to WebAssembly. This enables end-to-end encryption of FlatBuffer data directly in JavaScript/TypeScript with no native dependencies.

```javascript
import {
  loadEncryptionWasm,
  encryptBuffer,
  decryptBuffer,
  x25519GenerateKeyPair,
  x25519SharedSecret,
  ed25519GenerateKeyPair,
  ed25519Sign,
  ed25519Verify,
  hkdf,
  EncryptionContext
} from 'flatc-wasm/encryption';

// Initialize the WASM module (required once before use)
await loadEncryptionWasm('path/to/flatc-encryption.wasm');
```

### End-to-End Encryption Flow

The complete flow for secure FlatBuffer transmission:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        END-TO-END ENCRYPTION FLOW                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  SENDER                                              RECIPIENT              │
│  ──────                                              ─────────              │
│                                                                             │
│  1. Define Schema (.fbs)                                                    │
│         │                                                                   │
│         ▼                                                                   │
│  2. Generate Code (flatc --ts)                                              │
│         │                                                                   │
│         ▼                                                                   │
│  3. Create FlatBuffer ◄──────────────────────────────────────┐              │
│         │                                                    │              │
│         ▼                                                    │              │
│  4. ECDH Key Exchange ◄─────── Public Keys ────────► ECDH Key Exchange      │
│         │                                                    │              │
│         ▼                                                    │              │
│  5. Derive AES Key (HKDF)                           Derive AES Key (HKDF)   │
│         │                                                    │              │
│         ▼                                                    │              │
│  6. Encrypt (AES-256-CTR)                                    │              │
│         │                                                    │              │
│         ▼                                                    │              │
│  7. Sign (Ed25519/ECDSA)                                     │              │
│         │                                                    │              │
│         ▼                                                    │              │
│  8. ════════════════════ TRANSMIT ═══════════════════════════╪══════►       │
│                                                              │              │
│                                                    9. Verify Signature      │
│                                                              │              │
│                                                              ▼              │
│                                                   10. Decrypt (AES-256-CTR) │
│                                                              │              │
│                                                              ▼              │
│                                                   11. Read FlatBuffer       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Complete E2E Example

```typescript
import { FlatcRunner } from 'flatc-wasm';
import {
  loadEncryptionWasm,
  x25519GenerateKeyPair,
  x25519SharedSecret,
  ed25519GenerateKeyPair,
  ed25519Sign,
  ed25519Verify,
  hkdf,
  encryptBytes,
  decryptBytes,
  KEY_SIZE,
  IV_SIZE
} from 'flatc-wasm/encryption';
import { randomBytes } from 'crypto'; // Node.js

// Initialize modules
const flatc = await FlatcRunner.init();
await loadEncryptionWasm('path/to/flatc-encryption.wasm');

// 1. Define schema
const schema = {
  entry: '/message.fbs',
  files: {
    '/message.fbs': `
      namespace Secure;
      table Message {
        id: string;
        sender: string;
        content: string;
        timestamp: int64;
      }
      root_type Message;
    `
  }
};

// 2. Create FlatBuffer from JSON
const messageJson = JSON.stringify({
  id: 'msg-001',
  sender: 'alice',
  content: 'Hello, Bob!',
  timestamp: Date.now()
});
const flatbuffer = flatc.generateBinary(schema, messageJson);

// 3. Generate keypairs for sender and recipient
const senderKeyPair = x25519GenerateKeyPair();
const recipientKeyPair = x25519GenerateKeyPair();
const senderSigningKey = ed25519GenerateKeyPair();

// 4. Compute shared secret (sender side)
const sharedSecret = x25519SharedSecret(
  senderKeyPair.privateKey,
  recipientKeyPair.publicKey
);

// 5. Derive AES key using HKDF
const aesKey = hkdf(
  sharedSecret,
  null,  // salt (optional)
  new TextEncoder().encode('flatbuffer-encryption-v1'),  // context
  KEY_SIZE  // 32 bytes
);

// 6. Generate random IV and encrypt (creates copy)
const iv = new Uint8Array(randomBytes(IV_SIZE));
const ciphertext = new Uint8Array(flatbuffer);  // Copy to avoid modifying original
encryptBytes(ciphertext, aesKey, iv);  // Encrypts in-place

// 7. Sign the ciphertext
const signature = ed25519Sign(senderSigningKey.privateKey, ciphertext);

// 8. Package for transmission
const securePackage = {
  senderPublicKey: senderKeyPair.publicKey,
  senderSigningPublicKey: senderSigningKey.publicKey,
  iv: iv,
  ciphertext: ciphertext,
  signature: signature
};

// === RECIPIENT SIDE ===

// 9. Verify signature
const isValid = ed25519Verify(
  securePackage.senderSigningPublicKey,
  securePackage.ciphertext,
  securePackage.signature
);

if (!isValid) {
  throw new Error('Invalid signature - message tampered or wrong sender');
}

// 10. Derive shared secret (recipient side)
const recipientSharedSecret = x25519SharedSecret(
  recipientKeyPair.privateKey,
  securePackage.senderPublicKey
);

// Derive same AES key
const recipientAesKey = hkdf(
  recipientSharedSecret,
  null,
  new TextEncoder().encode('flatbuffer-encryption-v1'),
  KEY_SIZE
);

// 11. Decrypt (copy to avoid modifying received data)
const decryptedFlatbuffer = new Uint8Array(securePackage.ciphertext);
decryptBytes(decryptedFlatbuffer, recipientAesKey, securePackage.iv);

// 12. Convert back to JSON
const recoveredJson = flatc.generateJSON(schema, {
  path: '/message.bin',
  data: decryptedFlatbuffer
});

console.log('Decrypted message:', JSON.parse(recoveredJson));
```

### Cryptographic Operations

#### SHA-256 Hashing

```javascript
import { sha256 } from 'flatc-wasm/encryption';

const data = new TextEncoder().encode('Hello, World!');
const hash = sha256(data);
console.log('SHA-256:', Buffer.from(hash).toString('hex'));
// e.g., "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
```

#### AES-256-CTR Encryption/Decryption

```javascript
import { encryptBytes, decryptBytes, KEY_SIZE, IV_SIZE } from 'flatc-wasm/encryption';
import { randomBytes } from 'crypto';

// Key: 32 bytes, IV: 16 bytes
const key = new Uint8Array(randomBytes(KEY_SIZE));
const iv = new Uint8Array(randomBytes(IV_SIZE));
const data = new TextEncoder().encode('Secret message');

// Encrypt in-place (make a copy first if you need the original)
const ciphertext = new Uint8Array(data);
encryptBytes(ciphertext, key, iv);

// Decrypt in-place (CTR mode is symmetric)
decryptBytes(ciphertext, key, iv);

console.log(new TextDecoder().decode(ciphertext)); // "Secret message"
```

#### HKDF Key Derivation

Derive cryptographic keys from shared secrets:

```javascript
import { hkdf } from 'flatc-wasm/encryption';

const inputKeyMaterial = sharedSecret;  // e.g., from ECDH
const salt = null;                      // optional, can be null
const info = new TextEncoder().encode('my-app-encryption-key');
const outputLength = 32;                // 256 bits

const derivedKey = hkdf(inputKeyMaterial, salt, info, outputLength);
```

### Key Exchange (ECDH)

Three elliptic curves are supported for key exchange:

#### X25519 (Curve25519)

Best for general-purpose encryption. Used by Signal, WireGuard, etc.

```javascript
import { x25519GenerateKeyPair, x25519SharedSecret } from 'flatc-wasm/encryption';

// Generate keypair
const keypair = x25519GenerateKeyPair();
// keypair.privateKey: 32 bytes
// keypair.publicKey: 32 bytes

// Compute shared secret
const sharedSecret = x25519SharedSecret(
  myPrivateKey,
  theirPublicKey
);
// sharedSecret: 32 bytes
```

#### secp256k1

Used by Bitcoin, Ethereum, and most cryptocurrencies.

```javascript
import { secp256k1GenerateKeyPair, secp256k1SharedSecret } from 'flatc-wasm/encryption';

// Generate keypair
const keypair = secp256k1GenerateKeyPair();
// keypair.privateKey: 32 bytes
// keypair.publicKey: 33 bytes (compressed)

// Compute shared secret
const sharedSecret = secp256k1SharedSecret(
  myPrivateKey,
  theirPublicKey  // 33 or 65 bytes
);
// sharedSecret: 32 bytes
```

#### P-256 (secp256r1/prime256v1)

NIST standard curve, used in TLS and enterprise applications.

```javascript
import { p256GenerateKeyPair, p256SharedSecret } from 'flatc-wasm/encryption';

// Generate keypair
const keypair = p256GenerateKeyPair();
// keypair.privateKey: 32 bytes
// keypair.publicKey: 33 bytes (compressed)

// Compute shared secret
const sharedSecret = p256SharedSecret(
  myPrivateKey,
  theirPublicKey  // 33 or 65 bytes
);
// sharedSecret: 32 bytes
```

### Digital Signatures

Three signature algorithms are supported:

#### Ed25519

Fast, secure, deterministic signatures. Used by Solana, Cardano, etc.

```javascript
import { ed25519GenerateKeyPair, ed25519Sign, ed25519Verify } from 'flatc-wasm/encryption';

// Generate signing keypair
const keypair = ed25519GenerateKeyPair();
// keypair.privateKey: 64 bytes (includes public key)
// keypair.publicKey: 32 bytes

// Sign message
const message = new TextEncoder().encode('Sign this message');
const signature = ed25519Sign(keypair.privateKey, message);
// signature: 64 bytes

// Verify signature
const isValid = ed25519Verify(keypair.publicKey, message, signature);
// isValid: boolean
```

#### secp256k1 ECDSA

Bitcoin/Ethereum-compatible signatures.

```javascript
import { secp256k1GenerateKeyPair, secp256k1Sign, secp256k1Verify, sha256 } from 'flatc-wasm/encryption';

// Generate signing keypair
const keypair = secp256k1GenerateKeyPair();

// Sign message (usually a hash)
const messageHash = sha256(message);
const signature = secp256k1Sign(keypair.privateKey, messageHash);
// signature: 70-72 bytes (DER encoded)

// Verify signature
const isValid = secp256k1Verify(
  keypair.publicKey,
  messageHash,
  signature
);
```

#### P-256 ECDSA

NIST-compliant signatures.

```javascript
import { p256GenerateKeyPair, p256Sign, p256Verify, sha256 } from 'flatc-wasm/encryption';

// Generate signing keypair
const keypair = p256GenerateKeyPair();

// Sign message
const messageHash = sha256(message);
const signature = p256Sign(keypair.privateKey, messageHash);
// signature: 70-72 bytes (DER encoded)

// Verify signature
const isValid = p256Verify(keypair.publicKey, messageHash, signature);
```

### Cryptocurrency Compatibility

The encryption module supports keys compatible with major blockchain ecosystems:

| Blockchain | ECDH Curve | Signature | Private Key | Public Key |
|------------|------------|-----------|-------------|------------|
| Bitcoin | secp256k1 | ECDSA | 32 bytes | 33 bytes |
| Ethereum | secp256k1 | ECDSA | 32 bytes | 33 bytes |
| Solana | X25519 | Ed25519 | 64 bytes | 32 bytes |
| Cosmos | secp256k1 | ECDSA | 32 bytes | 33 bytes |
| Polkadot | X25519 | Ed25519* | 64 bytes | 32 bytes |
| Cardano | X25519 | Ed25519 | 64 bytes | 32 bytes |
| Aptos | X25519 | Ed25519 | 64 bytes | 32 bytes |
| NEAR | X25519 | Ed25519 | 64 bytes | 32 bytes |
| SUI | X25519 | Ed25519 | 64 bytes | 32 bytes |
| Tezos | X25519 | Ed25519 | 64 bytes | 32 bytes |

*Polkadot uses Sr25519, but Ed25519 is compatible for most use cases.

#### Example: Multi-Recipient Encryption

Encrypt a FlatBuffer for multiple recipients:

```javascript
import {
  x25519GenerateKeyPair, x25519SharedSecret, hkdf, encryptBytes, IV_SIZE, KEY_SIZE
} from 'flatc-wasm/encryption';
import { randomBytes } from 'crypto';

// Sender generates ephemeral keypair
const senderKeypair = x25519GenerateKeyPair();

// Encrypt for multiple recipients
const recipients = [recipientAPubKey, recipientBPubKey, recipientCPubKey];
const iv = new Uint8Array(randomBytes(IV_SIZE));

const encryptedPayloads = recipients.map((recipientPub, index) => {
  // Compute shared secret with this recipient
  const shared = x25519SharedSecret(senderKeypair.privateKey, recipientPub);

  // Derive unique key for this recipient
  const key = hkdf(
    shared,
    null,
    new TextEncoder().encode(`recipient-${index}`),
    KEY_SIZE
  );

  // Encrypt (copy to preserve original for other recipients)
  const ciphertext = new Uint8Array(flatbuffer);
  encryptBytes(ciphertext, key, iv);

  return {
    recipientPublicKey: recipientPub,
    ciphertext
  };
});

// Package for transmission
const multiRecipientMessage = {
  senderPublicKey: senderKeypair.publicKey,
  iv,
  payloads: encryptedPayloads
};
```

Each recipient decrypts:

```javascript
import { x25519SharedSecret, hkdf, decryptBytes, KEY_SIZE } from 'flatc-wasm/encryption';

// Find my payload
const myPayload = message.payloads.find(p =>
  arraysEqual(p.recipientPublicKey, myPublicKey)
);

// Derive shared secret
const shared = x25519SharedSecret(myPrivateKey, message.senderPublicKey);

// Derive my key
const myKey = hkdf(
  shared,
  null,
  new TextEncoder().encode(`recipient-${myIndex}`),
  KEY_SIZE
);

// Decrypt (modifies in place)
const plaintext = new Uint8Array(myPayload.ciphertext);
decryptBytes(plaintext, myKey, message.iv);
```

### Cross-Language Support

The encryption WASM module works across 7 programming languages:

| Language | Runtime | Package/Crate |
|----------|---------|---------------|
| Node.js | V8 (native) | `flatc-wasm/encryption` |
| Go | wazero | `github.com/tetratelabs/wazero` |
| Python | wasmtime | `pip install wasmtime` |
| Rust | wasmtime | `wasmtime` crate |
| Java | Chicory | Pure Java WASM runtime |
| C# | Wasmtime | `wasmtime-dotnet` NuGet |
| Swift | Wasmtime C API | Link `libwasmtime` |

All languages can encrypt/decrypt FlatBuffers and verify signatures across language boundaries.

#### Go Example

```go
package main

import (
    "context"
    "github.com/tetratelabs/wazero"
    "github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

func main() {
    ctx := context.Background()
    r := wazero.NewRuntime(ctx)
    defer r.Close(ctx)

    // Instantiate WASI
    wasi_snapshot_preview1.MustInstantiate(ctx, r)

    // Load the WASM module
    wasmBytes, _ := os.ReadFile("flatc-encryption.wasm")
    module, _ := r.InstantiateWithConfig(ctx, wasmBytes,
        wazero.NewModuleConfig().WithName("flatc"))

    // Get exported functions
    malloc := module.ExportedFunction("malloc")
    free := module.ExportedFunction("free")
    encrypt := module.ExportedFunction("wasi_encrypt_bytes")
    decrypt := module.ExportedFunction("wasi_decrypt_bytes")
    sha256 := module.ExportedFunction("wasi_sha256")
    hkdf := module.ExportedFunction("wasi_hkdf")

    // ECDH key exchange
    x25519Generate := module.ExportedFunction("wasi_x25519_generate_keypair")
    x25519Shared := module.ExportedFunction("wasi_x25519_shared_secret")

    // Digital signatures
    ed25519Sign := module.ExportedFunction("wasi_ed25519_sign")
    ed25519Verify := module.ExportedFunction("wasi_ed25519_verify")

    // Allocate memory and call functions...
}
```

#### Python Example

```python
import wasmtime

# Create engine and store
engine = wasmtime.Engine()
store = wasmtime.Store(engine)
linker = wasmtime.Linker(engine)

# Add WASI imports
wasi_config = wasmtime.WasiConfig()
store.set_wasi(wasi_config)
linker.define_wasi()

# Load module
module = wasmtime.Module.from_file(engine, "flatc-encryption.wasm")
instance = linker.instantiate(store, module)

# Get exports
memory = instance.exports(store)["memory"]
malloc = instance.exports(store)["malloc"]
free = instance.exports(store)["free"]
encrypt = instance.exports(store)["wasi_encrypt_bytes"]
decrypt = instance.exports(store)["wasi_decrypt_bytes"]
sha256 = instance.exports(store)["wasi_sha256"]
hkdf = instance.exports(store)["wasi_hkdf"]

# ECDH key exchange
x25519_generate = instance.exports(store)["wasi_x25519_generate_keypair"]
x25519_shared = instance.exports(store)["wasi_x25519_shared_secret"]

# Digital signatures
ed25519_sign = instance.exports(store)["wasi_ed25519_sign"]
ed25519_verify = instance.exports(store)["wasi_ed25519_verify"]

# Helper to write bytes to WASM memory
def write_bytes(ptr: int, data: bytes):
    mem_data = memory.data_ptr(store)
    for i, b in enumerate(data):
        mem_data[ptr + i] = b

# Helper to read bytes from WASM memory
def read_bytes(ptr: int, length: int) -> bytes:
    mem_data = memory.data_ptr(store)
    return bytes(mem_data[ptr:ptr + length])

# Encrypt data
def encrypt_data(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    key_ptr = malloc(store, 32)
    iv_ptr = malloc(store, 16)
    data_ptr = malloc(store, len(plaintext))

    write_bytes(key_ptr, key)
    write_bytes(iv_ptr, iv)
    write_bytes(data_ptr, plaintext)

    encrypt(store, key_ptr, iv_ptr, data_ptr, len(plaintext))
    result = read_bytes(data_ptr, len(plaintext))

    free(store, key_ptr)
    free(store, iv_ptr)
    free(store, data_ptr)
    return result
```

#### Rust Example

```rust
use wasmtime::*;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let engine = Engine::default();
    let module = Module::from_file(&engine, "flatc-encryption.wasm")?;
    let mut store = Store::new(&engine, ());

    // Create linker with WASI stubs
    let mut linker = Linker::new(&engine);
    // Add WASI imports...

    let instance = linker.instantiate(&mut store, &module)?;

    // Get exports
    let memory = instance.get_memory(&mut store, "memory").unwrap();
    let malloc = instance.get_typed_func::<i32, i32>(&mut store, "malloc")?;
    let free = instance.get_typed_func::<i32, ()>(&mut store, "free")?;
    let encrypt = instance.get_typed_func::<(i32, i32, i32, i32), i32>(
        &mut store, "wasi_encrypt_bytes")?;
    let sha256 = instance.get_typed_func::<(i32, i32, i32), ()>(
        &mut store, "wasi_sha256")?;

    // ECDH and signatures
    let x25519_generate = instance.get_typed_func::<(i32, i32), i32>(
        &mut store, "wasi_x25519_generate_keypair")?;
    let ed25519_sign = instance.get_typed_func::<(i32, i32, i32, i32), i32>(
        &mut store, "wasi_ed25519_sign")?;

    // Allocate, write data, call functions, read results...
    Ok(())
}
```

#### Java Example (Chicory)

```java
import com.dylibso.chicory.runtime.*;
import com.dylibso.chicory.wasi.*;
import com.dylibso.chicory.wasm.Parser;
import java.io.File;

public class EncryptionExample {
    public static void main(String[] args) {
        var wasiOptions = WasiOptions.builder().build();
        var wasi = WasiPreview1.builder().withOptions(wasiOptions).build();

        var store = new Store();
        store.addFunction(wasi.toHostFunctions());

        var module = Parser.parse(new File("flatc-encryption.wasm"));
        var instance = store.instantiate("flatc", module);
        var memory = instance.memory();

        // Get exports
        var malloc = instance.export("malloc");
        var free = instance.export("free");
        var encrypt = instance.export("wasi_encrypt_bytes");
        var decrypt = instance.export("wasi_decrypt_bytes");
        var sha256 = instance.export("wasi_sha256");
        var hkdf = instance.export("wasi_hkdf");

        // ECDH key exchange
        var x25519Generate = instance.export("wasi_x25519_generate_keypair");
        var x25519Shared = instance.export("wasi_x25519_shared_secret");

        // Digital signatures
        var ed25519Sign = instance.export("wasi_ed25519_sign");
        var ed25519Verify = instance.export("wasi_ed25519_verify");

        // Encrypt example
        int keyPtr = (int) malloc.apply(32)[0];
        int ivPtr = (int) malloc.apply(16)[0];
        int dataPtr = (int) malloc.apply(100)[0];

        // Write key, iv, and data to memory...
        memory.write(keyPtr, keyBytes);
        memory.write(ivPtr, ivBytes);
        memory.write(dataPtr, plaintextBytes);

        // Encrypt in-place
        encrypt.apply(keyPtr, ivPtr, dataPtr, plaintextBytes.length);

        // Read encrypted data
        byte[] ciphertext = memory.readBytes(dataPtr, plaintextBytes.length);

        // Clean up
        free.apply(keyPtr);
        free.apply(ivPtr);
        free.apply(dataPtr);
    }
}
```

#### C# Example

```csharp
using Wasmtime;

var engine = new Engine();
var store = new Store(engine);
var linker = new Linker(engine);

// Add WASI imports
linker.DefineFunction("wasi_snapshot_preview1", "fd_close", (int fd) => 0);
linker.DefineFunction("wasi_snapshot_preview1", "fd_write",
    (Caller c, int fd, int iovs, int len, int nw) => { /* ... */ return 0; });
// ... other WASI functions

var module = Module.FromFile(engine, "flatc-encryption.wasm");
var instance = linker.Instantiate(store, module);

var memory = instance.GetMemory("memory")!;
var malloc = instance.GetFunction("malloc")!;
var free = instance.GetFunction("free")!;
var encrypt = instance.GetFunction("wasi_encrypt_bytes")!;
var decrypt = instance.GetFunction("wasi_decrypt_bytes")!;
var sha256 = instance.GetFunction("wasi_sha256")!;
var hkdf = instance.GetFunction("wasi_hkdf")!;

// ECDH key exchange
var x25519Generate = instance.GetFunction("wasi_x25519_generate_keypair")!;
var x25519Shared = instance.GetFunction("wasi_x25519_shared_secret")!;

// Digital signatures
var ed25519Sign = instance.GetFunction("wasi_ed25519_sign")!;
var ed25519Verify = instance.GetFunction("wasi_ed25519_verify")!;

// Helper methods
void WriteBytes(int offset, byte[] data) {
    var span = memory.GetSpan(offset, data.Length);
    data.CopyTo(span);
}

byte[] ReadBytes(int offset, int length) {
    var span = memory.GetSpan(offset, length);
    return span.ToArray();
}

// Encrypt example
int keyPtr = (int)malloc.Invoke(32)!;
int ivPtr = (int)malloc.Invoke(16)!;
int dataPtr = (int)malloc.Invoke(plaintext.Length)!;

WriteBytes(keyPtr, key);
WriteBytes(ivPtr, iv);
WriteBytes(dataPtr, plaintext);

encrypt.Invoke(keyPtr, ivPtr, dataPtr, plaintext.Length);

byte[] ciphertext = ReadBytes(dataPtr, plaintext.Length);

free.Invoke(keyPtr);
free.Invoke(ivPtr);
free.Invoke(dataPtr);
```

#### Swift Example

```swift
import CWasmtime  // Link against libwasmtime

let engine = wasm_engine_new()
defer { wasm_engine_delete(engine) }

let store = wasmtime_store_new(engine, nil, nil)
defer { wasmtime_store_delete(store) }

let context = wasmtime_store_context(store)

// Load WASM module
let wasmData = try Data(contentsOf: URL(fileURLWithPath: "flatc-encryption.wasm"))
var module: OpaquePointer?
wasmData.withUnsafeBytes { ptr in
    wasmtime_module_new(engine, ptr.baseAddress, wasmData.count, &module)
}
defer { wasmtime_module_delete(module) }

// Create linker and add WASI
let linker = wasmtime_linker_new(engine)
defer { wasmtime_linker_delete(linker) }
wasmtime_linker_define_wasi(linker)

// Instantiate
var instance = wasmtime_instance_t()
wasmtime_linker_instantiate(linker, context, module, &instance, nil)

// Get memory and functions
var memory = wasmtime_memory_t()
wasmtime_instance_export_get(context, &instance, "memory", 6, &memory)

// Get crypto functions
var mallocFunc = wasmtime_func_t()
var sha256Func = wasmtime_func_t()
var encryptFunc = wasmtime_func_t()
var x25519GenerateFunc = wasmtime_func_t()
var ed25519SignFunc = wasmtime_func_t()

// ... get function exports

// Write bytes to WASM memory
func writeBytes(_ ptr: UInt32, _ data: [UInt8]) {
    let memData = wasmtime_memory_data(context, &memory)
    for (i, byte) in data.enumerated() {
        memData.advanced(by: Int(ptr) + i).pointee = byte
    }
}

// Read bytes from WASM memory
func readBytes(_ ptr: UInt32, _ length: Int) -> [UInt8] {
    let memData = wasmtime_memory_data(context, &memory)
    return (0..<length).map { memData.advanced(by: Int(ptr) + $0).pointee }
}

// Call crypto functions...
```

### WASM Function Reference

All languages use the same WASM exports:

| Function | Signature | Description |
|----------|-----------|-------------|
| `malloc` | `(size: i32) -> i32` | Allocate memory |
| `free` | `(ptr: i32)` | Free memory |
| `wasi_sha256` | `(data, len, out)` | SHA-256 hash |
| `wasi_encrypt_bytes` | `(key, iv, data, len) -> i32` | AES-256-CTR encrypt |
| `wasi_decrypt_bytes` | `(key, iv, data, len) -> i32` | AES-256-CTR decrypt |
| `wasi_hkdf` | `(ikm, ikm_len, salt, salt_len, info, info_len, out, out_len)` | HKDF-SHA256 |
| `wasi_x25519_generate_keypair` | `(priv_out, pub_out) -> i32` | Generate X25519 keypair |
| `wasi_x25519_shared_secret` | `(priv, pub, out) -> i32` | X25519 ECDH |
| `wasi_secp256k1_generate_keypair` | `(priv_out, pub_out) -> i32` | Generate secp256k1 keypair |
| `wasi_secp256k1_shared_secret` | `(priv, pub, pub_len, out) -> i32` | secp256k1 ECDH |
| `wasi_p256_generate_keypair` | `(priv_out, pub_out) -> i32` | Generate P-256 keypair |
| `wasi_p256_shared_secret` | `(priv, pub, pub_len, out) -> i32` | P-256 ECDH |
| `wasi_ed25519_generate_keypair` | `(priv_out, pub_out) -> i32` | Generate Ed25519 keypair |
| `wasi_ed25519_sign` | `(priv, data, len, sig_out) -> i32` | Ed25519 sign |
| `wasi_ed25519_verify` | `(pub, data, len, sig) -> i32` | Ed25519 verify (0=valid) |
| `wasi_secp256k1_sign` | `(priv, data, len, sig_out, sig_len_out) -> i32` | secp256k1 ECDSA sign |
| `wasi_secp256k1_verify` | `(pub, pub_len, data, len, sig, sig_len) -> i32` | secp256k1 verify |
| `wasi_p256_sign` | `(priv, data, len, sig_out, sig_len_out) -> i32` | P-256 ECDSA sign |
| `wasi_p256_verify` | `(pub, pub_len, data, len, sig, sig_len) -> i32` | P-256 verify |

### Security Best Practices

1. **Never reuse IVs** - Generate a new random IV for each encryption operation
2. **Use HKDF for key derivation** - Don't use raw ECDH output directly as encryption key
3. **Include context in HKDF** - Use unique info strings for different purposes
4. **Verify before decrypt** - Always verify signatures before decrypting
5. **Rotate keys regularly** - Use ephemeral keys for forward secrecy

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
