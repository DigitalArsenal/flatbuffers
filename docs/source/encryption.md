# FlatBuffers Field-Level Encryption

This document describes the field-level encryption feature for the DigitalArsenal FlatBuffers fork.

## Overview

Field-level encryption allows encrypting specific fields in a FlatBuffer while maintaining binary compatibility. Encrypted buffers:

- **Preserve binary layout** - Offsets, vtables, and structure remain valid
- **Are parseable without decryption** - Readers see encrypted bytes as valid (but meaningless) values
- **Support selective encryption** - Only marked fields are encrypted
- **Use a single key per buffer** - All encrypted fields use the same key

## Use Case

Primary use case: **Data at rest on distributed storage** (IPFS, etc.)

When transmitting FlatBuffers over IPFS:
- Node-to-node links use NOISE encryption (in transit)
- But data cached on nodes is **not encrypted**
- Anyone with the CID can fetch and read the data
- Field-level encryption protects sensitive fields at rest

## Schema Syntax

### Declaring the Attribute

```flatbuffers
attribute "encrypted";

table UserRecord {
  public_id: uint64;                    // Not encrypted
  username: string;                     // Not encrypted
  password_hash: string (encrypted);    // Encrypted
  private_key: [ubyte] (encrypted);     // Encrypted
  coordinates: Vec3 (encrypted);        // Encrypted struct
}
```

### Supported Types

| Type | Encryption Method | Notes |
|------|-------------------|-------|
| Scalar (int/float/etc) | XOR with keystream | Same byte size preserved |
| String | AES-CTR on bytes | Length visible, content encrypted |
| [ubyte] / [byte] | AES-CTR on bytes | Length visible, content encrypted |
| Vector of scalars | XOR each element | Element count visible |
| Struct | XOR all bytes | Fixed size preserved |
| Vector of structs | AES-CTR on the element bytes | Element count visible |
| Vector of strings | AES-CTR on each string's bytes | Count and lengths visible |
| Table (nested), vector of tables, union | Walked: their own `(encrypted)` fields are encrypted | Structure visible |

### Unsupported (refused)

`EncryptBuffer` refuses these with `kUnsupportedType` before changing any
byte, instead of leaving them in plaintext:

- **`(encrypted)` on a table, a vector of tables or a union** - Offsets must
  remain valid; mark the fields inside the tables `(encrypted)` instead
- **`(encrypted)` on a union type field** - The type selects how the value is read
- **`(encrypted)` on fields inside a struct** - Mark the struct-typed field
  `(encrypted)` to encrypt the whole struct

## Encryption Algorithm

### Key Derivation (format 3)

`EncryptBuffer` and `DecryptBuffer` write and read format 3 by default. The
format number is `EncryptionHeader.version` and the `version` argument.

```
Master Key (256-bit)
    │
    └── Buffer Key K = HKDF-SHA256(master_key, no salt,
                                   "flatbuffers-buffer-v3" || BE32(record_index))

Each encrypted instance (a scalar, a struct, a string's bytes, a vector's
element bytes, each string of a vector of strings):
    IV         = BE32(position) || 12 zero bytes
    ciphertext = plaintext XOR AES-256-CTR(K, IV)
```

`position` is the offset of the instance's first encrypted byte from the start
of the buffer. Positions are distinct and a FlatBuffer is smaller than 2^32
bytes, so no two instances share a counter block: every instance, including
two fields with the same id in nested tables, vectors of tables or union
members, has its own key stream. A table or string shared by offset is
encrypted once. `(key, record_index)` must be unique per buffer: give each
record encrypted under one key its own `record_index`.

### Format 2 (legacy)

Format 2 (flatc-wasm 26.1.34 and earlier C++ callers) encrypted every
instance of field id F with

```
Field Key = HKDF-SHA256(master_key, "flatbuffers-field" || BE16(F) || BE32(record_index))
IV        = HKDF-SHA256(master_key, "flatbuffers-iv"    || BE16(F) || BE32(record_index))
```

with record 0, walking only the root table and its table-typed fields. Two
fields with the same id in a table and its nested table shared a key stream,
so the XOR of their ciphertexts was the XOR of their plaintexts, and fields in
vectors of tables and unions stayed plaintext. Pass
`kFieldEncryptionV2` to `DecryptBuffer` to read existing format-2 data only.

The per-field primitives (`DeriveFieldKey`, `DeriveFieldIV`, `EncryptScalar`,
`EncryptString`, `EncryptVector`) keep this derivation. They encrypt one
value under an explicit `(field_id, record_index)`, and the caller keeps that
pair unique per key.

### Scalar Encryption (XOR with AES-CTR keystream)

```
plaintext_bytes XOR AES-CTR(field_key, iv, len(plaintext_bytes))
```

For a 4-byte int32:
```
[0x12, 0x34, 0x56, 0x78]  XOR  [keystream 4 bytes]  =  [encrypted 4 bytes]
```

The encrypted bytes are still a valid int32, just with a different (meaningless) value.

### String/Vector Encryption (AES-CTR)

```
ciphertext = AES-CTR(field_key, iv, plaintext_bytes)
```

The string length prefix remains unencrypted (it's part of the FlatBuffer structure), but all content bytes are encrypted.

### Struct Encryption

Structs are fixed-size inline data. Encrypt all bytes as a single block:

```
encrypted_struct = plaintext_struct_bytes XOR AES-CTR(field_key, iv, struct_size)
```

## API

### C++ API

```cpp
#include "flatbuffers/encryption.h"

flatbuffers::EncryptionContext ctx(key, 32);

// Encrypt a buffer in-place (format 3). The .bfbs must be serialized with
// binary_schema_builtins (flatc --bfbs-builtins) to keep the markers.
flatbuffers::EncryptBuffer(
    buffer_pointer,
    buffer_size,
    schema,           // Compiled schema with encrypted field markers
    schema_size,
    ctx,
    record_index      // Unique per buffer under this key (default 0)
);

// Decrypt a buffer in-place
flatbuffers::DecryptBuffer(buffer_pointer, buffer_size, schema, schema_size,
                           ctx, record_index);

// Decrypt format-2 data
flatbuffers::DecryptBuffer(buffer_pointer, buffer_size, schema, schema_size,
                           ctx, 0, flatbuffers::kFieldEncryptionV2);
```

### Generated Code API

```cpp
// Option 1: Encryption context
auto ctx = CreateEncryptionContext(key);
auto record = GetUserRecord(buffer);
std::string password = record->password_hash(ctx);  // Auto-decrypts

// Option 2: Explicit decrypt call
auto record = GetUserRecord(buffer);
std::string encrypted = record->password_hash();     // Returns encrypted bytes
std::string decrypted = Decrypt(encrypted, key, field_id);
```

### JavaScript/WASM API

```javascript
import { FlatcRunner } from 'flatc-wasm';

const flatc = await FlatcRunner.init();

// Encrypt fields marked with (encrypted) attribute
const encrypted = flatc.encrypt(buffer, schemaInput, key);

// Decrypt
const decrypted = flatc.decrypt(encrypted, schemaInput, key);

// Or with the low-level API
import { encryptBuffer, decryptBuffer } from 'flatc-wasm';

const encrypted = encryptBuffer(buffer, compiledSchema, key);
```

## Binary Format

The encrypted buffer has the **exact same structure** as the unencrypted buffer:

```
┌─────────────────────────────────────────────────────┐
│  Root offset (4 bytes) - unchanged                  │
├─────────────────────────────────────────────────────┤
│  VTable - unchanged (field offsets still valid)     │
├─────────────────────────────────────────────────────┤
│  public_id: uint64 - unchanged (not encrypted)      │
│  username offset - unchanged                        │
│  password_hash offset - unchanged                   │
│  private_key offset - unchanged                     │
│  coordinates offset - unchanged                     │
├─────────────────────────────────────────────────────┤
│  username string data - unchanged                   │
├─────────────────────────────────────────────────────┤
│  password_hash string data - ENCRYPTED BYTES        │
├─────────────────────────────────────────────────────┤
│  private_key vector data - ENCRYPTED BYTES          │
├─────────────────────────────────────────────────────┤
│  coordinates struct data - ENCRYPTED BYTES          │
└─────────────────────────────────────────────────────┘
```

## Security Considerations

### What's Protected

- ✅ Field values (content)
- ✅ String content
- ✅ Binary blob content
- ✅ Struct field values

### What's NOT Protected (by design)

- ❌ Schema structure (field names, types)
- ❌ String/vector lengths
- ❌ Presence of optional fields
- ❌ Number of elements in vectors
- ❌ Which fields are present

### Threat Model

This encryption is designed for:
- **Data at rest** on untrusted storage
- **Confidentiality** of field values
- **Single key** per buffer (all-or-nothing access)

NOT designed for:
- Hiding metadata/structure
- Multi-party access control
- Forward secrecy
- Authentication (use signing separately)

### Recommendations

1. **Use with signing** - Encrypt then sign, or use authenticated encryption
2. **Rotate keys** - Don't reuse keys across many buffers
3. **Encrypt sensitive fields only** - Don't encrypt public IDs, timestamps if not needed
4. **Consider padding** - For high-security, pad strings to fixed lengths

## Implementation Status

| Component | Status |
|-----------|--------|
| Schema attribute parsing | Complete |
| C++ encryption library | Complete |
| OpenSSL FIPS backend | Complete |
| Crypto++ backend | Complete |
| C++ code generator | Complete |
| flatc-wasm integration | Complete |
| TypeScript encryption | Complete |
| Python code generator | Planned |
| Rust code generator | Planned |
| Go code generator | Planned |

!!! tip "Homomorphic Encryption"
    For computation on encrypted data without decryption, see
    [Homomorphic Encryption](homomorphic_encryption.md).

## Example

### Schema

```flatbuffers
attribute "encrypted";

namespace Example;

struct Coordinates {
  lat: double;
  lon: double;
}

table SensorReading {
  device_id: string;                    // Public
  timestamp: uint64;                    // Public
  location: Coordinates (encrypted);    // Private
  reading_value: double (encrypted);    // Private
  raw_data: [ubyte] (encrypted);        // Private
}

root_type SensorReading;
```

### Usage (JavaScript)

```javascript
import { FlatcRunner } from 'flatc-wasm';
import { encryptBuffer, decryptBuffer } from 'flatc-wasm';

const flatc = await FlatcRunner.init();

// Create buffer
const json = {
  device_id: "sensor-001",
  timestamp: Date.now(),
  location: { lat: 37.7749, lon: -122.4194 },
  reading_value: 23.5,
  raw_data: [0x01, 0x02, 0x03, 0x04]
};

const schema = {
  entry: '/sensor.fbs',
  files: { '/sensor.fbs': schemaContent }
};

const buffer = flatc.generateBinary(schema, JSON.stringify(json));

// Encrypt
const key = crypto.getRandomValues(new Uint8Array(32));
const encrypted = encryptBuffer(buffer, schema, key);

// The encrypted buffer is still a valid FlatBuffer!
// But location, reading_value, and raw_data contain encrypted bytes

// Store on IPFS
const cid = await ipfs.add(encrypted);

// Later: retrieve and decrypt
const retrieved = await ipfs.cat(cid);
const decrypted = decryptBuffer(retrieved, schema, key);

// Now you can read the actual values
const reading = flatc.generateJSON(schema, { path: '/r.bin', data: decrypted });
console.log(JSON.parse(reading));
```

## Related Work

- [Format-Preserving Encryption (FPE)](https://csrc.nist.gov/publications/detail/sp/800-38g/rev-1/draft) - NIST SP 800-38G
- [CipherSweet](https://ciphersweet.paragonie.com/) - Searchable encryption for databases
- [Google Tink](https://developers.google.com/tink) - Crypto library with streaming AEAD
