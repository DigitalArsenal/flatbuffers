# FlatBuffers Encryption Examples

This directory contains integration examples showing how to use FlatBuffers field-level encryption powered by **Crypto++** via WASM.

## Architecture

All cryptographic operations are performed by a single C++ implementation using Crypto++, compiled to WebAssembly. This provides:

- **Single auditable implementation** - One codebase in C++/Crypto++
- **Battle-tested crypto** - Crypto++ has 30 years of production use
- **Cross-platform** - Works in Go, Node.js, Browser, Python, Rust, Java, C#, Swift via WASM
- **Full feature set** - AES-256-CTR, X25519, secp256k1, P-256, Ed25519, ECDSA

## Features

### Symmetric Encryption

- **AES-256-CTR** - Size-preserving stream cipher
- **HKDF-SHA256** - Key derivation for field-specific keys/IVs

### Key Exchange (ECDH)

- **X25519** - Modern Curve25519 (RFC 7748)
- **secp256k1** - Bitcoin/Ethereum compatible
- **P-256** - NIST standard (secp256r1)

### Digital Signatures

- **Ed25519** - EdDSA with Curve25519
- **ECDSA secp256k1** - Bitcoin/Ethereum transaction signing
- **ECDSA P-256** - NIST standard signatures

## Integration Examples

### WASM-Based (via Crypto++)

All these examples use the same Crypto++ WASM module, ensuring identical cryptographic behavior across languages:

| Directory | Language | Runtime | Description |
|-----------|----------|---------|-------------|
| [go-wasi/](go-wasi/) | **Go** | wazero | Full WASI example using wazero runtime |
| [python-wasi/](python-wasi/) | **Python** | wasmer | Python using wasmer-python |
| [rust-wasi/](rust-wasi/) | **Rust** | wasmer | Rust using wasmer crate |
| [java-wasi/](java-wasi/) | **Java** | Chicory | Java using pure-Java Chicory runtime |
| [csharp-wasi/](csharp-wasi/) | **C#** | Wasmtime | C#/.NET using Wasmtime |
| [swift-wasi/](swift-wasi/) | **Swift** | WasmKit | Swift using WasmKit runtime |
| [node-encryption/](node-encryption/) | **Node.js** | V8 | Node.js with native WASM |
| [browser-encryption/](browser-encryption/) | **Browser** | V8/SpiderMonkey | Interactive web demo |

### Multi-Language Examples

| Directory | Description |
|-----------|-------------|
| [public-key-encryption/](public-key-encryption/) | Hybrid encryption with ECDH |
| [cross-language-test/](cross-language-test/) | Cross-language compatibility tests |

## Quick Start (Node.js)

```javascript
import { FlatcRunner } from 'flatc-wasm';
import { initEncryption, encryptBytes, decryptBytes } from 'flatc-wasm/encryption';

// Initialize WASM module
const flatc = await FlatcRunner.init();
initEncryption(flatc.wasmInstance);

// Generate key and IV
const key = crypto.getRandomValues(new Uint8Array(32));
const iv = crypto.getRandomValues(new Uint8Array(16));

// Encrypt/decrypt
const data = new TextEncoder().encode('secret message');
encryptBytes(data, key, iv);
// data is now encrypted
decryptBytes(data, key, iv);
// data is restored
```

## Quick Start (Go)

```go
import (
    "context"
    "os"
)

func main() {
    ctx := context.Background()

    // Load WASM module
    wasmBytes, _ := os.ReadFile("flatc-encryption.wasm")
    em, _ := NewEncryptionModule(ctx, wasmBytes)
    defer em.Close(ctx)

    // X25519 key exchange
    alicePriv, alicePub, _ := em.X25519GenerateKeypair(ctx)
    bobPriv, bobPub, _ := em.X25519GenerateKeypair(ctx)

    secret, _ := em.X25519SharedSecret(ctx, alicePriv, bobPub)

    // Encrypt with shared secret
    em.EncryptBytes(ctx, secret[:32], iv, data)
}
```

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
| `bool`, `byte`, `ubyte` | Yes | 1-byte XOR |
| `short`, `ushort` | Yes | 2-byte XOR |
| `int`, `uint`, `float` | Yes | 4-byte XOR |
| `long`, `ulong`, `double` | Yes | 8-byte XOR |
| `string` | Yes | Content encrypted, length visible |
| `[ubyte]`, `[byte]` | Yes | Content encrypted |
| `[scalar]` | Yes | All elements encrypted |
| `struct` | Yes | All bytes encrypted (inline) |
| Nested tables | Partial | Encrypt fields inside table |
| `union` | No | Encrypt union member fields instead |

## Cross-Language Compatibility

All implementations use the same WASM module with Crypto++:

- **Symmetric**: AES-256-CTR (size-preserving, no auth tag)
- **Key Exchange**: X25519, secp256k1, P-256
- **Signatures**: Ed25519, ECDSA secp256k1, ECDSA P-256
- **Key Derivation**: HKDF-SHA256

Data encrypted/signed in one language can be verified in any other:

```
Go encrypt → Store on IPFS → Node.js decrypt
Browser encrypt → WebSocket → Python decrypt
Node.js sign → Store in DB → Rust verify
```

## Security Notes

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

1. **Use strong keys**: Generate 256-bit keys cryptographically
2. **Secure key storage**: Never commit keys to version control
3. **Sign important data**: Encryption provides confidentiality, use signatures for integrity
4. **Rotate keys**: Don't reuse keys across many buffers

## Building the WASM Module

```bash
# From flatbuffers root
cmake -B build -S . -DFLATBUFFERS_BUILD_WASM=ON
cmake --build build --target flatc

source build/_deps/emsdk-src/emsdk_env.sh
cmake -B build/wasm -S . \
  -DFLATBUFFERS_BUILD_WASM=ON \
  -DCMAKE_TOOLCHAIN_FILE=build/_deps/emsdk-src/upstream/emscripten/cmake/Modules/Platform/Emscripten.cmake
cmake --build build/wasm --target flatc_wasm_wasi

# Output: build/wasm/wasm/flatc-encryption.wasm
```

## Running Tests

### Go (WASI)

```bash
cd go-wasi
go mod tidy
go test -v
```

### Python (WASI)

```bash
cd python-wasi
pip install -r requirements.txt
python test_encryption.py
```

### Rust (WASI)

```bash
cd rust-wasi
cargo run --bin encryption_demo
```

### Java (WASI)

```bash
cd java-wasi
mvn compile exec:java
# Or run tests:
mvn test
```

### C# (WASI)

```bash
cd csharp-wasi
dotnet run
```

### Swift (WASI)

```bash
cd swift-wasi
swift run encryption-demo
# Or run tests:
swift test
```

### Node.js

```bash
cd node-encryption
npm install
npm test
```

### Browser

```bash
cd browser-encryption
npx serve .
# Open http://localhost:3000
```

## License

Apache-2.0
