# Go Encryption Integration

This example shows how to use flatc-wasm's field-level encryption from Go.

## Overview

Go uses the **same encryption algorithm** as the JavaScript flatc-wasm module, ensuring 100% compatibility across all platforms. Data encrypted in Go can be decrypted in JavaScript/Node.js/Python and vice versa.

The encryption implementation is pure Go with no CGo dependencies, matching the JavaScript implementation byte-for-byte.

## Installation

```bash
go get github.com/aspect-build/aspect-workflows/flatbuffers/wasm/go-encryption
# Or copy encryption.go to your project
```

## Quick Start

```go
package main

import (
    "crypto/rand"
    "fmt"
    "github.com/aspect-build/aspect-workflows/flatbuffers/wasm/examples/go-encryption/encryption"
)

func main() {
    schema := `
table UserData {
  user_id: uint64;
  username: string;
  password_hash: string (encrypted);
  balance: double (encrypted);
}
root_type UserData;
`

    // Create a FlatBuffer (using generated code or flatc)
    buffer := createFlatBuffer() // Your FlatBuffer creation method

    // Generate a 256-bit key
    key := make([]byte, 32)
    rand.Read(key)

    // Encrypt the buffer
    encrypted, err := encryption.EncryptBuffer(buffer, schema, key, "UserData")
    if err != nil {
        panic(err)
    }

    // Later: decrypt
    decrypted, err := encryption.DecryptBuffer(encrypted, schema, key, "UserData")
    if err != nil {
        panic(err)
    }

    fmt.Printf("Decrypted %d bytes\n", len(decrypted))
}
```

## Running the Tests

```bash
cd wasm/examples/go-encryption
go test -v
```

## API Reference

### EncryptionContext

```go
import "github.com/.../encryption"

// Create from bytes
key := make([]byte, 32)
rand.Read(key)
ctx := encryption.NewEncryptionContext(key)

// Create from hex string
ctx, err := encryption.NewEncryptionContextFromHex("0123456789abcdef...")

// Check validity
if ctx.IsValid() {
    fmt.Println("Key is valid (32 bytes)")
}

// Derive field-specific keys (for advanced usage)
fieldKey := ctx.DeriveFieldKey(fieldID)  // 32 bytes
fieldIV := ctx.DeriveFieldIV(fieldID)    // 16 bytes
```

### Buffer Encryption

```go
import "github.com/.../encryption"

// Encrypt (returns new buffer)
encrypted, err := encryption.EncryptBuffer(buffer, schemaContent, key, "RootType")

// Decrypt (returns new buffer)
decrypted, err := encryption.DecryptBuffer(encrypted, schemaContent, key, "RootType")

// Using EncryptionContext
ctx := encryption.NewEncryptionContext(key)
encrypted, err := encryption.EncryptBufferWithContext(buffer, schemaContent, ctx, "RootType")
```

### Low-Level Encryption

```go
import "github.com/.../encryption"

// Encrypt bytes in-place
data := []byte("secret data")
encryption.EncryptBytes(data, key, iv)

// Decrypt (same operation for AES-CTR)
encryption.DecryptBytes(data, key, iv)
```

## Cross-Language Compatibility

Data encrypted with Go can be decrypted in Node.js and vice versa:

```go
// Go encrypts
encrypted, _ := encryption.EncryptBuffer(buffer, schema, key, "MyType")
saveToIPFS(encrypted)
```

```javascript
// Node.js decrypts
import { decryptBuffer } from 'flatc-wasm/encryption';
const buffer = await loadFromIpfs(cid);
decryptBuffer(buffer, schemaContent, key, 'MyType');
```

## Encryption Algorithm

- **Algorithm**: AES-256-CTR
- **Key size**: 256 bits (32 bytes)
- **Key derivation**: Custom HKDF-like per-field derivation
- **IV derivation**: Custom HKDF-like per-field derivation

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

1. **Use strong keys**: Generate 256-bit keys cryptographically (`crypto/rand`)
2. **Secure key storage**: Never commit keys to version control
3. **Consider signing**: Encryption provides confidentiality, not integrity
4. **Rotate keys**: Don't reuse keys across too many buffers

## License

Apache-2.0
