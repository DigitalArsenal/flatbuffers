# Python Encryption Integration

This example shows how to use flatc-wasm's field-level encryption from Python.

## Overview

Python uses the **same encryption algorithm** as the JavaScript flatc-wasm module, ensuring 100% compatibility across all platforms. Data encrypted in Python can be decrypted in JavaScript/Node.js and vice versa.

The encryption implementation is pure Python with no dependencies, matching the JavaScript implementation byte-for-byte.

## Installation

No dependencies required for encryption:

```bash
# Just copy flatc_wasm.py to your project
```

Optional (for FlatBuffer creation via WASM):
```bash
pip install wasmtime
```

## Quick Start

```python
import os
from flatc_wasm import EncryptionContext, encrypt_buffer, decrypt_buffer

# Define schema with encrypted fields
SCHEMA = """
table UserData {
  user_id: uint64;
  username: string;
  password_hash: string (encrypted);
  balance: double (encrypted);
}
root_type UserData;
"""

# Create a FlatBuffer (using generated code, flatc, or manually)
buffer = create_flatbuffer(...)  # Your FlatBuffer creation method

# Generate a 256-bit key
key = os.urandom(32)

# Encrypt the buffer
encrypted = encrypt_buffer(buffer, SCHEMA, key, "UserData")

# Later: decrypt
decrypted = decrypt_buffer(encrypted, SCHEMA, key, "UserData")
```

## Running the Tests

```bash
cd wasm/examples/python-encryption
python test_encryption.py
```

## API Reference

### EncryptionContext

```python
from flatc_wasm import EncryptionContext

# Create from bytes
key = os.urandom(32)
ctx = EncryptionContext(key)

# Create from hex string
ctx = EncryptionContext("0123456789abcdef" * 4)

# Check validity
if ctx.is_valid():
    print("Key is valid (32 bytes)")

# Derive field-specific keys (for advanced usage)
field_key = ctx.derive_field_key(field_id)  # 32 bytes
field_iv = ctx.derive_field_iv(field_id)    # 16 bytes
```

### Buffer Encryption

```python
from flatc_wasm import encrypt_buffer, decrypt_buffer

# Encrypt (returns new buffer)
encrypted = encrypt_buffer(buffer, schema_content, key, "RootType")

# Decrypt (returns new buffer)
decrypted = decrypt_buffer(encrypted, schema_content, key, "RootType")

# Key can be:
# - bytes: 32-byte key
# - str: 64-character hex string
# - EncryptionContext: pre-created context
```

### Low-Level Encryption

```python
from flatc_wasm import encrypt_bytes, decrypt_bytes

# Encrypt bytes in-place
data = bytearray(b"secret data")
encrypt_bytes(data, key, iv)

# Decrypt (same operation for AES-CTR)
decrypt_bytes(data, key, iv)
```

### Schema Parsing

```python
from flatc_wasm import parse_schema_for_encryption

# Parse schema to get field info
fields = parse_schema_for_encryption(schema_content, "RootType")
for field in fields:
    print(f"{field.name}: encrypted={field.encrypted}, type={field.type}")
```

## Cross-Language Compatibility

Data encrypted with Python can be decrypted in Node.js and vice versa:

```python
# Python encrypts
encrypted = encrypt_buffer(buffer, schema, key, "MyType")
save_to_ipfs(encrypted)
```

```javascript
// Node.js decrypts
import { decryptBuffer } from 'flatc-wasm/encryption';
const buffer = await loadFromIpfs(cid);
decryptBuffer(buffer, schemaContent, key, 'MyType');
```

## How It Works

1. Python implements the same AES-256-CTR algorithm as the JavaScript module
2. Key derivation produces identical keys for the same input
3. Field locations are parsed from the schema identically
4. The resulting ciphertext is byte-for-byte compatible

### Encryption Algorithm

- **Algorithm**: AES-256-CTR
- **Key size**: 256 bits (32 bytes)
- **Key derivation**: Custom HKDF-like per-field derivation
- **IV derivation**: Custom HKDF-like per-field derivation

## Example: Encrypting Sensor Data for IPFS

```python
import os
import json
from flatc_wasm import EncryptionContext, encrypt_buffer, decrypt_buffer

SCHEMA = """
table SensorReading {
  device_id: string;
  timestamp: uint64;
  temperature: float (encrypted);
  gps_lat: double (encrypted);
  gps_lon: double (encrypted);
}
root_type SensorReading;
"""

def store_encrypted_reading(buffer: bytes, key: bytes) -> bytes:
    """Encrypt a sensor reading buffer."""
    return encrypt_buffer(buffer, SCHEMA, key, "SensorReading")

def load_encrypted_reading(encrypted: bytes, key: bytes) -> bytes:
    """Decrypt a sensor reading buffer."""
    return decrypt_buffer(encrypted, SCHEMA, key, "SensorReading")

# Usage
key = os.urandom(32)

# Assume buffer is created via flatc or generated code
encrypted = store_encrypted_reading(buffer, key)
print(f"Encrypted size: {len(encrypted)} bytes")

# Store to IPFS, database, etc.
# ...

# Later: retrieve and decrypt
decrypted = load_encrypted_reading(encrypted, key)
```

## Optional: Using wasmtime for FlatBuffer Operations

If you need to create FlatBuffers from JSON or convert to JSON, you can optionally use the WASM module via wasmtime:

```python
from flatc_wasm import FlatcWasm

# Initialize with WASM module
flatc = FlatcWasm("path/to/flatc-wasm.wasm")

# Get version
print(flatc.version())  # "flatc version 25.x.x"

# Note: FlatBuffer creation via WASM requires additional setup.
# For encryption-only usage, the standalone functions are recommended.
```

## Security Considerations

### What's Protected
- Field values (content)
- String content
- Binary blob content
- Numeric values

### What's NOT Protected
- Schema structure (visible)
- String/vector lengths (visible)
- Which fields are present (visible)
- Number of elements in vectors (visible)

### Recommendations

1. **Use strong keys**: Generate 256-bit keys cryptographically (`os.urandom(32)`)
2. **Secure key storage**: Never commit keys to version control
3. **Consider signing**: Encryption provides confidentiality, not integrity
4. **Rotate keys**: Don't reuse keys across too many buffers

## License

Apache-2.0
