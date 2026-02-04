# FlatBuffers WASM Runtime Integration

Run the FlatBuffers encryption module in any language with WebAssembly support. The same cryptographic implementation works across all platforms, ensuring consistent behavior and cross-language interoperability.

## Why WASM Runtimes?

### Single Auditable Implementation

The encryption module is compiled from a single C++ codebase to WebAssembly. This means:

- **One codebase to audit** - Security teams can focus on a single implementation
- **Consistent behavior** - Identical cryptographic operations across all languages
- **No native dependencies** - Pure WASM runs in any compliant runtime

### Battle-Tested Cryptography

Two cryptographic backends are available. **The pre-built WASM module uses Crypto++ by default** (configured via `FLATBUFFERS_USE_CRYPTOPP=1` in the CMake build).

#### Default: Crypto++ (Pre-built)

The default WASM build (`flatc-encryption.wasm`) uses [Crypto++](https://cryptopp.com/), a cryptographic library with:

- 30+ years of production use
- FIPS 140-2 validation
- Extensive peer review and security audits
- Active maintenance and security updates
- Full algorithm support including X25519, Ed25519, secp256k1

#### FIPS Support via hd-wallet-wasm

FIPS 140-3 compatible algorithms are available through `hd-wallet-wasm`, which includes
built-in OpenSSL FIPS support. Enable it with `wallet.initFips()`:

- NIST-approved curves (P-256, P-384)
- AES-256-GCM authenticated encryption
- HKDF, PBKDF2, scrypt key derivation
- Full multi-curve support (secp256k1, Ed25519, X25519) also available in non-FIPS mode

### Cross-Language Interoperability

Data encrypted in one language can be decrypted in any other:

```text
Go ↔ Python ↔ Rust ↔ Java ↔ C# ↔ Swift ↔ Node.js ↔ Browser
```

All implementations use the same:

- Key formats (raw bytes)
- Nonce derivation (96-bit addition from `nonceStart`)
- Encryption algorithms (AES-256-CTR)
- Key derivation (HKDF-SHA256)
- Signature formats (DER-encoded ECDSA, raw Ed25519)

### Nonce-Based Session Security

flatc-wasm uses a **nonce incrementor** to prevent nonce reuse attacks in AES-CTR mode:

1. **Session establishment**: Sender generates random 12-byte `nonceStart` via CSPRNG
2. **Header transmission**: `EncryptionHeader` (containing `nonceStart`) sent before encrypted data
3. **Nonce derivation**: Each field gets unique nonce via `nonceStart + (recordIndex × 65536 + fieldId)`
4. **Offline decryption**: Recipients can decrypt any record in any order using just the header

This enables:

- **Out-of-order decryption** - Records can arrive or be processed in any sequence
- **Parallel decryption** - Multiple workers can decrypt different records simultaneously
- **Offline operation** - No connection to sender required after receiving header
- **Index recovery** - If record index is lost, try sequential indices until decryption succeeds

See [Encryption Sessions & Nonce Management](encryption.md) for detailed documentation.

### Generated Code Encryption

All 12 FlatBuffers code generators now emit encryption support when your schema contains `(encrypted)` fields:

```fbs
table UserRecord {
  id: uint64;
  name: string;
  ssn: string (encrypted);        // Encrypted at rest
  credit_card: string (encrypted); // Encrypted at rest
}
```

Generated code automatically includes:
- `FlatbuffersEncryption` class/module with AES-256-CTR implementation
- `encryptionCtx` field on tables with encrypted fields
- `withEncryption()` factory for creating decryption-enabled readers
- Transparent field decryption when encryption context is provided

| Language | Encryption Library |
|----------|-------------------|
| C++ | `flatbuffers/encryption.h` inline helpers |
| TypeScript | Pure TypeScript AES-256-CTR |
| Python | `cryptography` library |
| Go | `crypto/aes` + `crypto/cipher` |
| Rust | Pure Rust AES-256-CTR |
| Java | `javax.crypto.Cipher` |
| C# | `System.Security.Cryptography` |
| Swift | Pure Swift AES-256-CTR |
| Kotlin | `javax.crypto.Cipher` |
| PHP | `openssl_encrypt/decrypt` |
| Dart | `pointycastle` library |
| Lobster | Placeholder (no crypto library) |

---

## Supported Runtimes

| Language | Runtime | Package | Key Features |
|----------|---------|---------|--------------|
| [Go](go.md) | wazero | `github.com/tetratelabs/wazero` | Pure Go, no CGo, zero dependencies |
| [Python](python.md) | wasmer | `pip install wasmer` | PyPI ready, type hints |
| [Rust](rust.md) | wasmer | `wasmer` crate | no_std support, memory safe |
| [Java](java.md) | Chicory | Maven Central | Pure Java, no JNI |
| [C#](csharp.md) | Wasmtime | NuGet | .NET 6+, async support |
| [Swift](swift.md) | WasmKit | Swift Package Manager | iOS/macOS, pure Swift |
| [Node.js](nodejs.md) | V8 (native) | `npm install flatc-wasm` | ESM/CJS, TypeScript |
| [Browser](browser.md) | V8/SpiderMonkey/JSC | CDN or bundler | All modern browsers |

---

## Cryptographic Operations

### Symmetric Encryption

| Operation | Algorithm | Key Size | IV Size |
|-----------|-----------|----------|---------|
| Encryption/Decryption | AES-256-CTR | 32 bytes | 16 bytes |

### Key Exchange (ECDH)

| Curve | Private Key | Public Key | Shared Secret | Use Case |
|-------|-------------|------------|---------------|----------|
| X25519 | 32 bytes | 32 bytes | 32 bytes | General purpose, Signal, WireGuard |
| secp256k1 | 32 bytes | 33 bytes* | 32 bytes | Bitcoin, Ethereum, cryptocurrencies |
| P-256 | 32 bytes | 33 bytes* | 32 bytes | TLS, enterprise, NIST compliance |

*Compressed format. Uncompressed (65 bytes) also supported for input.

### Digital Signatures

| Algorithm | Private Key | Public Key | Signature | Use Case |
|-----------|-------------|------------|-----------|----------|
| Ed25519 | 64 bytes | 32 bytes | 64 bytes | Fast, deterministic, Solana/Cardano |
| secp256k1 ECDSA | 32 bytes | 33 bytes | 70-72 bytes* | Bitcoin, Ethereum transactions |
| P-256 ECDSA | 32 bytes | 33 bytes | 70-72 bytes* | TLS, enterprise PKI |

*DER-encoded, variable length.

### Key Derivation

| Function | Input | Output | Use Case |
|----------|-------|--------|----------|
| HKDF-SHA256 | IKM + salt + info | Variable length | Derive keys from ECDH shared secrets |
| SHA-256 | Any data | 32 bytes | Hashing, message digests |

---

## API Reference

All runtimes expose the same WASM functions. Memory management follows the pattern:
1. Allocate memory with `malloc`
2. Write input data to allocated memory
3. Call the cryptographic function
4. Read output from memory
5. Free allocated memory with `free`

### Core Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `malloc` | `(size: i32) -> i32` | Allocate `size` bytes, returns pointer |
| `free` | `(ptr: i32)` | Free memory at pointer |

### Hash Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `wasi_sha256` | `(data: i32, len: i32, out: i32)` | SHA-256 hash. `out` must be 32 bytes |
| `wasi_hkdf` | `(ikm: i32, ikm_len: i32, salt: i32, salt_len: i32, info: i32, info_len: i32, out: i32, out_len: i32)` | HKDF-SHA256. `salt` can be NULL (0) |

### Symmetric Encryption

| Function | Signature | Description |
|----------|-----------|-------------|
| `wasi_encrypt_bytes` | `(key: i32, iv: i32, data: i32, len: i32) -> i32` | AES-256-CTR encrypt in-place. Returns 0 on success |
| `wasi_decrypt_bytes` | `(key: i32, iv: i32, data: i32, len: i32) -> i32` | AES-256-CTR decrypt in-place. Returns 0 on success |

### X25519 Key Exchange

| Function | Signature | Description |
|----------|-----------|-------------|
| `wasi_x25519_generate_keypair` | `(priv_out: i32, pub_out: i32) -> i32` | Generate keypair. `priv_out`: 32 bytes, `pub_out`: 32 bytes |
| `wasi_x25519_shared_secret` | `(priv: i32, pub: i32, out: i32) -> i32` | Compute shared secret. `out`: 32 bytes |

### secp256k1 (Bitcoin/Ethereum)

| Function | Signature | Description |
|----------|-----------|-------------|
| `wasi_secp256k1_generate_keypair` | `(priv_out: i32, pub_out: i32) -> i32` | Generate keypair. `priv_out`: 32 bytes, `pub_out`: 33 bytes |
| `wasi_secp256k1_shared_secret` | `(priv: i32, pub: i32, pub_len: i32, out: i32) -> i32` | ECDH. `pub_len`: 33 or 65 |
| `wasi_secp256k1_sign` | `(priv: i32, data: i32, len: i32, sig_out: i32, sig_len_out: i32) -> i32` | Sign (usually a hash). `sig_out`: max 72 bytes |
| `wasi_secp256k1_verify` | `(pub: i32, pub_len: i32, data: i32, len: i32, sig: i32, sig_len: i32) -> i32` | Verify. Returns 0 if valid |

### P-256 (NIST)

| Function | Signature | Description |
|----------|-----------|-------------|
| `wasi_p256_generate_keypair` | `(priv_out: i32, pub_out: i32) -> i32` | Generate keypair. `priv_out`: 32 bytes, `pub_out`: 33 bytes |
| `wasi_p256_shared_secret` | `(priv: i32, pub: i32, pub_len: i32, out: i32) -> i32` | ECDH. `pub_len`: 33 or 65 |
| `wasi_p256_sign` | `(priv: i32, data: i32, len: i32, sig_out: i32, sig_len_out: i32) -> i32` | Sign (usually a hash). `sig_out`: max 72 bytes |
| `wasi_p256_verify` | `(pub: i32, pub_len: i32, data: i32, len: i32, sig: i32, sig_len: i32) -> i32` | Verify. Returns 0 if valid |

### Ed25519 Signatures

| Function | Signature | Description |
|----------|-----------|-------------|
| `wasi_ed25519_generate_keypair` | `(priv_out: i32, pub_out: i32) -> i32` | Generate keypair. `priv_out`: 64 bytes, `pub_out`: 32 bytes |
| `wasi_ed25519_sign` | `(priv: i32, data: i32, len: i32, sig_out: i32) -> i32` | Sign message. `sig_out`: 64 bytes |
| `wasi_ed25519_verify` | `(pub: i32, data: i32, len: i32, sig: i32) -> i32` | Verify. Returns 0 if valid |

---

## Security Considerations

### Key Management

1. **Generate keys securely** - Use the WASM module's key generation functions, which use the platform's cryptographic RNG
2. **Never reuse IVs** - Generate a new random 16-byte IV for each encryption operation
3. **Derive keys with HKDF** - Never use raw ECDH output directly as an encryption key

```
Shared Secret → HKDF(secret, salt, info) → Encryption Key
```

4. **Use unique info strings** - Different purposes should use different HKDF info parameters:

```
HKDF(secret, null, "encryption-key-v1") → Key for encrypting
HKDF(secret, null, "authentication-key-v1") → Key for MAC (if needed)
```

### Memory Handling

1. **Zero sensitive data** - After use, overwrite key material in memory
2. **Minimize key lifetime** - Keep keys in WASM memory only as long as needed
3. **Free allocated memory** - Always call `free()` to prevent memory leaks

### What This Module Does NOT Protect

- **Key storage** - You must implement secure key storage for your platform
- **Side-channel attacks** - WASM runtimes may not be constant-time
- **Authentication** - Use signatures or HMAC to verify message integrity
- **Forward secrecy** - Implement ephemeral keys if needed

---

## Performance Optimization

### 1. Cache the WASM Module

Loading and compiling WASM is expensive. Initialize once and reuse:

```javascript
// Good: Initialize once
const module = await initEncryption();
// Reuse for all operations

// Bad: Initialize per operation
async function encrypt(data) {
  const module = await initEncryption(); // Slow!
  // ...
}
```

### 2. Batch Operations

Minimize WASM boundary crossings by processing multiple items:

```javascript
// Good: Batch processing
const allData = items.map(i => i.data);
const results = encryptBatch(allData, key, ivs);

// Less efficient: One at a time
for (const item of items) {
  encrypt(item.data, key, iv);
}
```

### 3. Reuse Memory Allocations

For repeated operations of the same size, reuse allocated buffers:

```go
// Good: Reuse buffers
keyPtr, _ := malloc(32)
defer free(keyPtr)

for _, data := range items {
    writeBytes(keyPtr, key)
    encrypt(keyPtr, ivPtr, dataPtr, len)
}

// Less efficient: Allocate each time
for _, data := range items {
    keyPtr, _ := malloc(32)
    // ...
    free(keyPtr)
}
```

### 4. Use Streaming for Large Data

For large files, process in chunks rather than loading everything into memory:

```python
CHUNK_SIZE = 64 * 1024  # 64KB chunks

def encrypt_file(input_path, output_path, key):
    iv = os.urandom(16)
    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        f_out.write(iv)  # Prepend IV
        while chunk := f_in.read(CHUNK_SIZE):
            encrypted = encrypt_bytes(key, iv, chunk)
            f_out.write(encrypted)
            # CTR mode: increment IV for next chunk
            iv = increment_iv(iv)
```

---

## Troubleshooting

### Common Issues

#### "Cannot find module" / "WASM module not found"

The WASM binary must be accessible at runtime. Solutions:

1. **Bundle with your application** - Copy `flatc-encryption.wasm` to your build output
2. **Use absolute paths** - Specify the full path to the WASM file
3. **Check file permissions** - Ensure the WASM file is readable

#### "Import not found: wasi_snapshot_preview1"

The WASM module requires WASI imports. Most runtimes provide these automatically:

- **wazero (Go)**: Use `wasi_snapshot_preview1.MustInstantiate()`
- **wasmer (Python)**: Configure WASI before instantiation
- **Wasmtime (C#)**: Call `linker.DefineWasi()`

#### "Import not found: env.invoke_*"

The module uses Emscripten's exception handling. You need to provide stub implementations:

```javascript
// Minimal invoke_* stubs
const imports = {
  env: {
    invoke_v: (idx) => { /* call table[idx]() */ },
    invoke_vi: (idx, a) => { /* call table[idx](a) */ },
    invoke_vii: (idx, a, b) => { /* call table[idx](a, b) */ },
    // ... etc
  }
};
```

See language-specific guides for complete implementations.

#### "Memory access out of bounds"

You're reading or writing outside allocated memory. Check:

1. **Pointer validity** - Ensure `malloc` returned non-zero
2. **Buffer sizes** - Don't write more bytes than allocated
3. **Double-free** - Don't free the same pointer twice

#### "Invalid signature" / "Verification failed"

1. **Check key types** - Ed25519 uses 64-byte private keys, ECDSA uses 32-byte
2. **Hash before signing** - secp256k1 and P-256 expect a 32-byte hash, not raw message
3. **Public key format** - Ensure compressed (33 bytes) vs uncompressed (65 bytes) matches

---

## Examples

### End-to-End Encryption

Complete example of encrypting a FlatBuffer for a recipient:

```javascript
// 1. Generate sender's ephemeral keypair
const senderKeys = x25519GenerateKeyPair();

// 2. Compute shared secret with recipient's public key
const sharedSecret = x25519SharedSecret(
  senderKeys.privateKey,
  recipientPublicKey
);

// 3. Derive encryption key using HKDF
const encryptionKey = hkdf(
  sharedSecret,
  null, // no salt
  new TextEncoder().encode('flatbuffer-encryption-v1'),
  32    // 256 bits
);

// 4. Generate random IV
const iv = crypto.getRandomValues(new Uint8Array(16));

// 5. Encrypt the FlatBuffer
const ciphertext = new Uint8Array(flatbuffer);
encryptBytes(ciphertext, encryptionKey, iv);

// 6. Package for transmission
const message = {
  senderPublicKey: senderKeys.publicKey, // 32 bytes
  iv: iv,                                 // 16 bytes
  ciphertext: ciphertext                  // encrypted data
};
```

### Cross-Language Verification

Verify a signature created in another language:

```go
// Go: Verify Ed25519 signature from Python
func verifyPythonSignature(publicKey, message, signature []byte) bool {
    module := loadEncryptionModule()

    pubPtr := writeBytes(module, publicKey)
    msgPtr := writeBytes(module, message)
    sigPtr := writeBytes(module, signature)
    defer freeAll(module, pubPtr, msgPtr, sigPtr)

    result := module.ed25519Verify(pubPtr, msgPtr, len(message), sigPtr)
    return result == 0 // 0 = valid
}
```

---

## Language Guides

For detailed integration instructions, see:

- [Encryption Sessions](encryption.md) - Nonce management, session establishment, offline decryption
- [Go Integration](go.md) - wazero runtime, pure Go
- [Python Integration](python.md) - wasmer with Cranelift
- [Rust Integration](rust.md) - wasmer crate
- [Java Integration](java.md) - Chicory pure Java runtime
- [C# Integration](csharp.md) - Wasmtime .NET bindings
- [Swift Integration](swift.md) - WasmKit for iOS/macOS
- [Node.js Integration](nodejs.md) - Native V8 WASM support
- [Browser Integration](browser.md) - All modern browsers
