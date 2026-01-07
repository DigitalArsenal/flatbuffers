# FlatBuffers Encryption Examples

This directory contains integration examples showing how to use flatc-wasm's field-level encryption from various languages and environments.

## Overview

Field-level encryption allows you to encrypt specific fields in a FlatBuffer while maintaining binary compatibility. The encrypted buffer:

- Remains a valid FlatBuffer (parseable structure)
- Has only marked field values encrypted
- Can be decrypted in any language using the same key

## Quick Start

```javascript
// Node.js / Browser
import { FlatcRunner, encryptBuffer, decryptBuffer } from 'flatc-wasm';

const flatc = await FlatcRunner.init();
const key = crypto.getRandomValues(new Uint8Array(32));

// Create buffer from JSON
const buffer = flatc.generateBinary(schema, jsonData);

// Encrypt fields marked with (encrypted)
encryptBuffer(buffer, schemaContent, key, 'RootType');

// Later: decrypt
decryptBuffer(buffer, schemaContent, key, 'RootType');
```

## Integration Examples

| Language | Directory | Description |
|----------|-----------|-------------|
| **Node.js** | [node-encryption/](node-encryption/) | Full Node.js example with tests |
| **Python** | [python-encryption/](python-encryption/) | Python implementation (compatible) |
| **Browser** | [browser-encryption/](browser-encryption/) | Interactive web demo |
| **Go** | [go-encryption/](go-encryption/) | Go implementation with tests |
| **Rust** | [rust-encryption/](rust-encryption/) | Rust crate with tests |
| **Deno** | [deno-encryption/](deno-encryption/) | TypeScript for Deno runtime |

## Schema Syntax

Mark fields for encryption using the `(encrypted)` attribute:

```flatbuffers
table SensorData {
  // Public fields
  device_id: string;
  timestamp: uint64;

  // Encrypted fields
  temperature: float (encrypted);
  location_lat: double (encrypted);
  location_lon: double (encrypted);
  raw_data: [ubyte] (encrypted);
  secret_notes: string (encrypted);
}

root_type SensorData;
```

## Supported Types

| Type | Encryption | Notes |
|------|------------|-------|
| `bool`, `byte`, `ubyte` | ✅ | 1-byte XOR |
| `short`, `ushort` | ✅ | 2-byte XOR |
| `int`, `uint`, `float` | ✅ | 4-byte XOR |
| `long`, `ulong`, `double` | ✅ | 8-byte XOR |
| `string` | ✅ | Content encrypted, length visible |
| `[ubyte]`, `[byte]` | ✅ | Content encrypted |
| `[scalar]` | ✅ | All elements encrypted |
| `struct` | ✅ | All bytes encrypted (inline) |
| Nested tables | ⚠️ | Encrypt fields inside table |
| `union` | ❌ | Encrypt union member fields instead |

## Cross-Language Compatibility

All implementations use the same encryption algorithm:

- **Algorithm**: AES-256-CTR
- **Key size**: 256 bits (32 bytes)
- **Key derivation**: HKDF-like per-field derivation
- **IV derivation**: HKDF-like per-field derivation

Data encrypted in one language can be decrypted in any other:

```
Python encrypt → Store on IPFS → Node.js decrypt ✅
Browser encrypt → Send via WebSocket → Go decrypt ✅
Node.js encrypt → Store in DB → Python decrypt ✅
```

## Security Notes

### What's Protected
- ✅ Field values (content)
- ✅ String content
- ✅ Binary blob content
- ✅ Numeric values

### What's NOT Protected
- ❌ Schema structure (visible)
- ❌ String/vector lengths (visible)
- ❌ Which fields are present (visible)
- ❌ Number of elements in vectors (visible)

### Recommendations

1. **Use strong keys**: Generate 256-bit keys cryptographically
2. **Secure key storage**: Never commit keys to version control
3. **Consider signing**: Encryption provides confidentiality, not integrity
4. **Rotate keys**: Don't reuse keys across many buffers

## Running Tests

### Node.js
```bash
cd node-encryption
npm install
npm test
```

### Python
```bash
cd python-encryption
python test_encryption.py
```

### Browser
```bash
cd browser-encryption
npx serve .
# Open http://localhost:3000
```

## License

Apache-2.0
