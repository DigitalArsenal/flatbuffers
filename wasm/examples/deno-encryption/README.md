# Deno Encryption Integration

This example shows how to use flatc-wasm's field-level encryption from Deno.

## Overview

Deno uses the **same encryption module** as Node.js/Browser, ensuring 100% compatibility across all platforms. The JavaScript encryption implementation works directly in Deno without modification.

## Installation

Import directly from the local module or from a CDN:

```typescript
// From local file
import { EncryptionContext, encryptBuffer, decryptBuffer } from './encryption.ts';

// Or from a CDN (when published)
// import { ... } from 'https://esm.sh/flatc-wasm@latest/encryption';
```

## Quick Start

```typescript
import { EncryptionContext, encryptBuffer, decryptBuffer } from './encryption.ts';

const schema = `
table UserData {
  user_id: uint64;
  username: string;
  password_hash: string (encrypted);
  balance: double (encrypted);
}
root_type UserData;
`;

// Create a FlatBuffer (using flatbuffers package)
const buffer: Uint8Array = createFlatBuffer(); // Your FlatBuffer creation

// Generate a 256-bit key
const key = crypto.getRandomValues(new Uint8Array(32));

// Encrypt the buffer
encryptBuffer(buffer, schema, key, 'UserData');

// Later: decrypt
decryptBuffer(buffer, schema, key, 'UserData');
```

## Running the Tests

```bash
cd wasm/examples/deno-encryption
deno test --allow-read
```

## API Reference

### EncryptionContext

```typescript
import { EncryptionContext } from './encryption.ts';

// Create from Uint8Array
const key = crypto.getRandomValues(new Uint8Array(32));
const ctx = new EncryptionContext(key);

// Create from hex string
const ctx = new EncryptionContext('0123456789abcdef...');

// Check validity
if (ctx.isValid()) {
  console.log('Key is valid (32 bytes)');
}

// Derive field-specific keys (for advanced usage)
const fieldKey = ctx.deriveFieldKey(fieldId);  // Uint8Array(32)
const fieldIV = ctx.deriveFieldIV(fieldId);    // Uint8Array(16)
```

### Buffer Encryption

```typescript
import { encryptBuffer, decryptBuffer } from './encryption.ts';

// Encrypt in-place
encryptBuffer(buffer, schemaContent, key, 'RootType');

// Decrypt in-place
decryptBuffer(buffer, schemaContent, key, 'RootType');

// Key can be:
// - Uint8Array: 32-byte key
// - string: 64-character hex string
// - EncryptionContext: pre-created context
```

### Low-Level Encryption

```typescript
import { encryptBytes, decryptBytes } from './encryption.ts';

// Encrypt bytes in-place
const data = new Uint8Array([/* data */]);
encryptBytes(data, key, iv);

// Decrypt (same operation for AES-CTR)
decryptBytes(data, key, iv);
```

## Cross-Language Compatibility

Data encrypted with Deno can be decrypted in Node.js/Python/Go/Rust and vice versa:

```typescript
// Deno encrypts
encryptBuffer(buffer, schema, key, 'MyType');
await saveToIpfs(buffer);
```

```python
# Python decrypts
from flatc_wasm import decrypt_buffer
buffer = load_from_ipfs(cid)
decrypt_buffer(buffer, schema, key, "MyType")
```

## Encryption Algorithm

- **Algorithm**: AES-256-CTR
- **Key size**: 256 bits (32 bytes)
- **Key derivation**: Custom HKDF-like per-field derivation
- **IV derivation**: Custom HKDF-like per-field derivation

## Why Deno?

Deno offers several advantages for FlatBuffer encryption:

1. **Built-in TypeScript**: No build step required
2. **Secure by default**: Explicit permissions model
3. **Web standard APIs**: `crypto.getRandomValues()` works out of the box
4. **ES modules**: Import directly from URLs

## License

Apache-2.0
