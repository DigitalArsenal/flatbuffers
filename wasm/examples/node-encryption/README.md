# Node.js Encryption Example

This example demonstrates how to use flatc-wasm's field-level encryption in Node.js.

## Overview

Field-level encryption allows you to encrypt specific fields in a FlatBuffer while maintaining binary compatibility. This is useful for:

- Storing sensitive data on distributed systems (IPFS, etc.)
- Encrypting data at rest while preserving schema structure
- Selective field encryption (public + private fields in same buffer)

## Installation

```bash
npm install flatc-wasm
```

## Quick Start

```javascript
import { FlatcRunner, encryptBuffer, decryptBuffer, EncryptionContext } from 'flatc-wasm';
import { randomBytes } from 'crypto';

// Define schema with encrypted fields
const schema = `
  table UserRecord {
    user_id: uint64;                      // Public
    username: string;                     // Public
    password_hash: string (encrypted);    // Encrypted!
    balance: double (encrypted);          // Encrypted!
  }
  root_type UserRecord;
`;

// Initialize flatc
const flatc = await FlatcRunner.init();

// Create a FlatBuffer
const json = JSON.stringify({
  user_id: 12345,
  username: "alice",
  password_hash: "secret_hash_value",
  balance: 1000.50
});

const schemaInput = {
  entry: '/user.fbs',
  files: { '/user.fbs': schema }
};

const buffer = flatc.generateBinary(schemaInput, json);

// Generate a 256-bit key
const key = randomBytes(32);

// Encrypt the buffer (in-place)
encryptBuffer(buffer, schema, key, 'UserRecord');

// The buffer is still a valid FlatBuffer!
// But password_hash and balance contain encrypted bytes

// Later: decrypt
decryptBuffer(buffer, schema, key, 'UserRecord');

// Now you can read the original values
const recovered = flatc.generateJSON(schemaInput, { path: '/user.bin', data: buffer });
console.log(JSON.parse(recovered));
```

## Schema Syntax

Mark fields for encryption with the `(encrypted)` attribute:

```flatbuffers
table MyTable {
  public_field: string;           // Not encrypted
  secret_field: string (encrypted);  // Will be encrypted
  secret_number: double (encrypted); // Will be encrypted
}
```

### Supported Types for Encryption

| Type | Support | Notes |
|------|---------|-------|
| Scalars (int, float, etc.) | ✅ | XOR with keystream |
| string | ✅ | Content encrypted, length visible |
| [ubyte], [byte] | ✅ | Content encrypted |
| Vector of scalars | ✅ | All elements encrypted |
| struct (inline) | ✅ | All bytes encrypted |
| Nested tables | ⚠️ | Encrypt fields inside, not the table itself |
| Unions | ❌ | Encrypt union members instead |

## API Reference

### EncryptionContext

```javascript
import { EncryptionContext } from 'flatc-wasm';

// From Uint8Array (32 bytes)
const ctx = new EncryptionContext(keyBytes);

// From hex string (64 characters)
const ctx = new EncryptionContext('0123456789abcdef...');

// Check validity
if (!ctx.isValid()) {
  throw new Error('Invalid key');
}
```

### encryptBuffer / decryptBuffer

```javascript
import { encryptBuffer, decryptBuffer } from 'flatc-wasm';

// Encrypt in-place
encryptBuffer(buffer, schemaContent, key, rootTypeName);

// Decrypt in-place (same operation for AES-CTR)
decryptBuffer(buffer, schemaContent, key, rootTypeName);
```

Parameters:
- `buffer`: `Uint8Array` - The FlatBuffer to encrypt/decrypt (modified in-place)
- `schemaContent`: `string` - The .fbs schema content
- `key`: `Uint8Array | string | EncryptionContext` - 32-byte key
- `rootTypeName`: `string` - Name of the root table type

### Low-Level API

```javascript
import { encryptBytes, EncryptionContext } from 'flatc-wasm';

const ctx = new EncryptionContext(key);

// Derive field-specific key and IV
const fieldKey = ctx.deriveFieldKey(fieldId);
const fieldIV = ctx.deriveFieldIV(fieldId);

// Encrypt arbitrary bytes
encryptBytes(data, fieldKey, fieldIV);
```

## Security Notes

1. **Key Management**: Store keys securely. Never commit keys to version control.

2. **What's NOT encrypted**:
   - Schema structure (field names, types)
   - String/vector lengths
   - Which optional fields are present
   - Number of elements in vectors

3. **Deterministic Encryption**: Same field + same key = same ciphertext. This enables caching but may leak equality.

4. **No Authentication**: This provides confidentiality only. Consider signing the buffer separately if you need integrity verification.

## Running the Example

```bash
cd wasm/examples/node-encryption
npm install
npm test
```
