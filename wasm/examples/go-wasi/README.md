# Go WASI Encryption Example

This example demonstrates using the FlatBuffers encryption module compiled to WASI with Go and the [wazero](https://wazero.io/) runtime.

## Features

The WASI module provides comprehensive cryptography powered by **Crypto++**:

### Symmetric Encryption
- **AES-256-CTR** - Size-preserving stream cipher
- **HKDF-SHA256** - Key derivation for field-specific keys/IVs
- **SHA-256** - Cryptographic hash function

### Key Exchange (ECDH)
- **X25519** - Modern Curve25519 (RFC 7748)
- **secp256k1** - Bitcoin/Ethereum compatible
- **P-256** - NIST standard (secp256r1)

### Digital Signatures
- **Ed25519** - EdDSA with Curve25519
- **ECDSA secp256k1** - Bitcoin/Ethereum transaction signing
- **ECDSA P-256** - NIST standard signatures

## Why WASI?

Using a single WASM module provides:
- **Single auditable implementation** - One codebase in C++/Crypto++
- **Battle-tested crypto** - Crypto++ has 30 years of production use
- **Cross-platform** - Go, Python, Rust, Node.js, browser, etc.
- **No native dependencies** - Zero CGo, pure Go runtime

## Building the WASM Module

```bash
# From the flatbuffers root directory
cd flatbuffers

# Configure with WASM support
cmake -B build -S . -DFLATBUFFERS_BUILD_WASM=ON

# Build native flatc first (needed for emsdk)
cmake --build build --target flatc

# Install emsdk and build WASI module
source build/_deps/emsdk-src/emsdk_env.sh
cmake -B build/wasm -S . \
  -DFLATBUFFERS_BUILD_WASM=ON \
  -DCMAKE_TOOLCHAIN_FILE=build/_deps/emsdk-src/upstream/emscripten/cmake/Modules/Platform/Emscripten.cmake
cmake --build build/wasm --target flatc_wasm_wasi

# The module will be at: build/wasm/wasm/flatc-encryption.wasm
```

## Running the Example

```bash
cd wasm/examples/go-wasi

# Install dependencies
go mod tidy

# Run the example
go run .

# Run tests (requires WASM module to be built)
go test -v
```

## API Reference

### Module Setup

```go
// Load WASM module
wasmBytes, _ := os.ReadFile("flatc-encryption.wasm")
em, _ := NewEncryptionModule(ctx, wasmBytes)
defer em.Close(ctx)

// Check version and Crypto++ availability
version, _ := em.Version(ctx)       // "2.0.0"
hasCrypto, _ := em.HasCryptopp(ctx) // true
```

### Symmetric Encryption (AES-256-CTR)

```go
// Direct encryption
key := make([]byte, 32)
iv := make([]byte, 16)
rand.Read(key)
rand.Read(iv)

data := []byte("secret message")
em.EncryptBytes(ctx, key, iv, data) // in-place
em.DecryptBytes(ctx, key, iv, data) // in-place

// Field-level key derivation
encCtx, _ := em.NewEncryptionContext(ctx, masterKey)
defer encCtx.Close(ctx)

fieldKey, _ := encCtx.DeriveFieldKey(ctx, fieldID)
fieldIV, _ := encCtx.DeriveFieldIV(ctx, fieldID)
```

### Hash Functions

```go
// SHA-256
hash, _ := em.SHA256(ctx, data)
```

### X25519 Key Exchange

```go
// Generate key pairs for Alice and Bob
alicePriv, alicePub, _ := em.X25519GenerateKeypair(ctx)
bobPriv, bobPub, _ := em.X25519GenerateKeypair(ctx)

// Compute shared secret (both derive the same secret)
secretAlice, _ := em.X25519SharedSecret(ctx, alicePriv, bobPub)
secretBob, _ := em.X25519SharedSecret(ctx, bobPriv, alicePub)
// secretAlice == secretBob
```

### secp256k1 (Bitcoin/Ethereum)

```go
// Key exchange
alicePriv, alicePub, _ := em.Secp256k1GenerateKeypair(ctx)
bobPriv, bobPub, _ := em.Secp256k1GenerateKeypair(ctx)
secret, _ := em.Secp256k1SharedSecret(ctx, alicePriv, bobPub)

// ECDSA signatures
sig, _ := em.Secp256k1Sign(ctx, privateKey, message)
valid, _ := em.Secp256k1Verify(ctx, publicKey, message, sig)
```

### P-256 (NIST)

```go
// Key exchange
alicePriv, alicePub, _ := em.P256GenerateKeypair(ctx)
bobPriv, bobPub, _ := em.P256GenerateKeypair(ctx)
secret, _ := em.P256SharedSecret(ctx, alicePriv, bobPub)

// ECDSA signatures
sig, _ := em.P256Sign(ctx, privateKey, message)
valid, _ := em.P256Verify(ctx, publicKey, message, sig)
```

### Ed25519 Signatures

```go
// Generate signing keypair
privateKey, publicKey, _ := em.Ed25519GenerateKeypair(ctx)

// Sign and verify
sig, _ := em.Ed25519Sign(ctx, privateKey, message)
valid, _ := em.Ed25519Verify(ctx, publicKey, message, sig)
```

## Example: End-to-End Encryption

```go
package main

import (
    "context"
    "crypto/rand"
    "os"
)

func main() {
    ctx := context.Background()

    // Load WASM module
    wasmBytes, _ := os.ReadFile("flatc-encryption.wasm")
    em, _ := NewEncryptionModule(ctx, wasmBytes)
    defer em.Close(ctx)

    // Alice generates X25519 keypair
    alicePriv, alicePub, _ := em.X25519GenerateKeypair(ctx)

    // Bob generates X25519 keypair
    bobPriv, bobPub, _ := em.X25519GenerateKeypair(ctx)

    // Alice computes shared secret with Bob's public key
    sharedSecret, _ := em.X25519SharedSecret(ctx, alicePriv, bobPub)

    // Derive symmetric key from shared secret
    // (In production, use HKDF for proper key derivation)
    key := sharedSecret[:32]

    // Generate random IV
    iv := make([]byte, 16)
    rand.Read(iv)

    // Encrypt message
    message := []byte("Hello Bob!")
    em.EncryptBytes(ctx, key, iv, message)

    // Bob can decrypt using same shared secret
    bobSecret, _ := em.X25519SharedSecret(ctx, bobPriv, alicePub)
    em.DecryptBytes(ctx, bobSecret[:32], iv, message)
    // message is now "Hello Bob!"
}
```

## Key Sizes

| Algorithm | Private Key | Public Key | Signature | Shared Secret |
|-----------|-------------|------------|-----------|---------------|
| X25519 | 32 bytes | 32 bytes | N/A | 32 bytes |
| secp256k1 | 32 bytes | 33 bytes (compressed) | ~72 bytes (DER) | 32 bytes |
| P-256 | 32 bytes | 33 bytes (compressed) | ~72 bytes (DER) | 32 bytes |
| Ed25519 | 64 bytes (seed+pub) | 32 bytes | 64 bytes | N/A |

## Cross-Language Compatibility

Data encrypted/signed with this WASI module can be verified by:
- JavaScript (via same WASM module)
- Node.js (via same WASM module)
- Python (via wasmtime/wasmer)
- Rust (via wasmtime/wasmer)
- Any language with a WASI runtime

## License

Apache-2.0
