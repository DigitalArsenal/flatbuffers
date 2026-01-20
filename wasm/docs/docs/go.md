# Go Integration Guide

Integrate the FlatBuffers encryption WASM module into Go applications using [wazero](https://wazero.io/), a pure Go WebAssembly runtime with zero dependencies.

## Why wazero?

- **Pure Go** - No CGo, no native dependencies
- **Zero dependencies** - Just Go standard library
- **Fast startup** - Optimized for CLI tools and serverless
- **Full WASI support** - Complete WASI snapshot preview1 implementation
- **Production ready** - Used by Envoy, Dapr, and many others

## Prerequisites

- Go 1.20 or later
- `flatc-encryption.wasm` binary

## Installation

```bash
go get github.com/tetratelabs/wazero
```

## Quick Start

```go
package main

import (
    "context"
    "crypto/rand"
    "fmt"
    "os"

    "github.com/tetratelabs/wazero"
    "github.com/tetratelabs/wazero/api"
    "github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

func main() {
    ctx := context.Background()

    // Create runtime
    r := wazero.NewRuntime(ctx)
    defer r.Close(ctx)

    // Instantiate WASI
    wasi_snapshot_preview1.MustInstantiate(ctx, r)

    // Load WASM module
    wasmBytes, err := os.ReadFile("flatc-encryption.wasm")
    if err != nil {
        panic(err)
    }

    // Instantiate module
    module, err := r.Instantiate(ctx, wasmBytes)
    if err != nil {
        panic(err)
    }

    // Get exported functions
    malloc := module.ExportedFunction("malloc")
    free := module.ExportedFunction("free")
    encrypt := module.ExportedFunction("wasi_encrypt_bytes")
    decrypt := module.ExportedFunction("wasi_decrypt_bytes")

    // Encrypt some data
    key := make([]byte, 32)
    iv := make([]byte, 16)
    rand.Read(key)
    rand.Read(iv)

    plaintext := []byte("Hello, FlatBuffers!")

    // Allocate WASM memory
    keyPtr, _ := malloc.Call(ctx, 32)
    ivPtr, _ := malloc.Call(ctx, 16)
    dataPtr, _ := malloc.Call(ctx, uint64(len(plaintext)))
    defer func() {
        free.Call(ctx, keyPtr[0])
        free.Call(ctx, ivPtr[0])
        free.Call(ctx, dataPtr[0])
    }()

    // Write data to WASM memory
    mem := module.Memory()
    mem.Write(uint32(keyPtr[0]), key)
    mem.Write(uint32(ivPtr[0]), iv)
    mem.Write(uint32(dataPtr[0]), plaintext)

    // Encrypt in-place
    encrypt.Call(ctx, keyPtr[0], ivPtr[0], dataPtr[0], uint64(len(plaintext)))

    // Read encrypted data
    ciphertext, _ := mem.Read(uint32(dataPtr[0]), uint32(len(plaintext)))
    fmt.Printf("Encrypted: %x\n", ciphertext)

    // Decrypt in-place (CTR mode is symmetric)
    decrypt.Call(ctx, keyPtr[0], ivPtr[0], dataPtr[0], uint64(len(plaintext)))

    // Read decrypted data
    decrypted, _ := mem.Read(uint32(dataPtr[0]), uint32(len(plaintext)))
    fmt.Printf("Decrypted: %s\n", decrypted)
}
```

## Complete Module Wrapper

For production use, wrap the WASM module in a Go struct:

```go
package encryption

import (
    "context"
    "crypto/rand"
    "errors"
    "os"

    "github.com/tetratelabs/wazero"
    "github.com/tetratelabs/wazero/api"
    "github.com/tetratelabs/wazero/experimental/table"
    "github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// Key and signature sizes
const (
    AESKeySize   = 32
    AESIVSize    = 16
    SHA256Size   = 32

    X25519PrivateKeySize = 32
    X25519PublicKeySize  = 32

    Secp256k1PrivateKeySize = 32
    Secp256k1PublicKeySize  = 33
    Secp256k1SignatureSize  = 72

    Ed25519PrivateKeySize = 64
    Ed25519PublicKeySize  = 32
    Ed25519SignatureSize  = 64
)

// Module wraps the WASM encryption module
type Module struct {
    ctx     context.Context
    runtime wazero.Runtime
    module  api.Module
    memory  api.Memory

    malloc api.Function
    free   api.Function

    // Symmetric
    encrypt api.Function
    decrypt api.Function

    // Hash
    sha256 api.Function
    hkdf   api.Function

    // X25519
    x25519Generate api.Function
    x25519Shared   api.Function

    // secp256k1
    secp256k1Generate api.Function
    secp256k1Shared   api.Function
    secp256k1Sign     api.Function
    secp256k1Verify   api.Function

    // Ed25519
    ed25519Generate api.Function
    ed25519Sign     api.Function
    ed25519Verify   api.Function
}

// New creates a new encryption module
func New(ctx context.Context, wasmPath string) (*Module, error) {
    wasmBytes, err := os.ReadFile(wasmPath)
    if err != nil {
        return nil, err
    }

    r := wazero.NewRuntime(ctx)

    // Instantiate WASI
    wasi_snapshot_preview1.MustInstantiate(ctx, r)

    // Create env module with Emscripten trampolines
    if err := defineEnvModule(ctx, r); err != nil {
        r.Close(ctx)
        return nil, err
    }

    // Instantiate the encryption module
    module, err := r.Instantiate(ctx, wasmBytes)
    if err != nil {
        r.Close(ctx)
        return nil, err
    }

    m := &Module{
        ctx:     ctx,
        runtime: r,
        module:  module,
        memory:  module.Memory(),

        malloc:  module.ExportedFunction("malloc"),
        free:    module.ExportedFunction("free"),
        encrypt: module.ExportedFunction("wasi_encrypt_bytes"),
        decrypt: module.ExportedFunction("wasi_decrypt_bytes"),
        sha256:  module.ExportedFunction("wasi_sha256"),
        hkdf:    module.ExportedFunction("wasi_hkdf"),

        x25519Generate: module.ExportedFunction("wasi_x25519_generate_keypair"),
        x25519Shared:   module.ExportedFunction("wasi_x25519_shared_secret"),

        secp256k1Generate: module.ExportedFunction("wasi_secp256k1_generate_keypair"),
        secp256k1Shared:   module.ExportedFunction("wasi_secp256k1_shared_secret"),
        secp256k1Sign:     module.ExportedFunction("wasi_secp256k1_sign"),
        secp256k1Verify:   module.ExportedFunction("wasi_secp256k1_verify"),

        ed25519Generate: module.ExportedFunction("wasi_ed25519_generate_keypair"),
        ed25519Sign:     module.ExportedFunction("wasi_ed25519_sign"),
        ed25519Verify:   module.ExportedFunction("wasi_ed25519_verify"),
    }

    return m, nil
}

// Close releases all resources
func (m *Module) Close() error {
    return m.runtime.Close(m.ctx)
}

// Encrypt encrypts data in-place using AES-256-CTR
func (m *Module) Encrypt(key, iv, data []byte) error {
    if len(key) != AESKeySize {
        return errors.New("key must be 32 bytes")
    }
    if len(iv) != AESIVSize {
        return errors.New("iv must be 16 bytes")
    }

    keyPtr, ivPtr, dataPtr, err := m.allocateAndWrite(key, iv, data)
    if err != nil {
        return err
    }
    defer m.freeAll(keyPtr, ivPtr, dataPtr)

    result, err := m.encrypt.Call(m.ctx, keyPtr, ivPtr, dataPtr, uint64(len(data)))
    if err != nil {
        return err
    }
    if result[0] != 0 {
        return errors.New("encryption failed")
    }

    // Read encrypted data back
    encrypted, _ := m.memory.Read(uint32(dataPtr), uint32(len(data)))
    copy(data, encrypted)
    return nil
}

// Decrypt decrypts data in-place using AES-256-CTR
func (m *Module) Decrypt(key, iv, data []byte) error {
    return m.Encrypt(key, iv, data) // CTR mode is symmetric
}

// SHA256 computes SHA-256 hash
func (m *Module) SHA256(data []byte) ([]byte, error) {
    dataPtr, err := m.allocate(uint64(len(data)))
    if err != nil {
        return nil, err
    }
    outPtr, err := m.allocate(SHA256Size)
    if err != nil {
        m.free.Call(m.ctx, dataPtr)
        return nil, err
    }
    defer m.freeAll(dataPtr, outPtr)

    m.memory.Write(uint32(dataPtr), data)

    _, err = m.sha256.Call(m.ctx, dataPtr, uint64(len(data)), outPtr)
    if err != nil {
        return nil, err
    }

    hash, _ := m.memory.Read(uint32(outPtr), SHA256Size)
    return hash, nil
}

// HKDF derives a key using HKDF-SHA256
func (m *Module) HKDF(ikm, salt, info []byte, length int) ([]byte, error) {
    ikmPtr, err := m.allocate(uint64(len(ikm)))
    if err != nil {
        return nil, err
    }
    m.memory.Write(uint32(ikmPtr), ikm)
    defer m.free.Call(m.ctx, ikmPtr)

    var saltPtr uint64 = 0
    saltLen := 0
    if len(salt) > 0 {
        saltPtr, _ = m.allocate(uint64(len(salt)))
        m.memory.Write(uint32(saltPtr), salt)
        saltLen = len(salt)
        defer m.free.Call(m.ctx, saltPtr)
    }

    var infoPtr uint64 = 0
    infoLen := 0
    if len(info) > 0 {
        infoPtr, _ = m.allocate(uint64(len(info)))
        m.memory.Write(uint32(infoPtr), info)
        infoLen = len(info)
        defer m.free.Call(m.ctx, infoPtr)
    }

    outPtr, _ := m.allocate(uint64(length))
    defer m.free.Call(m.ctx, outPtr)

    _, err = m.hkdf.Call(m.ctx,
        ikmPtr, uint64(len(ikm)),
        saltPtr, uint64(saltLen),
        infoPtr, uint64(infoLen),
        outPtr, uint64(length))
    if err != nil {
        return nil, err
    }

    result, _ := m.memory.Read(uint32(outPtr), uint32(length))
    return result, nil
}

// X25519KeyPair represents an X25519 key pair
type X25519KeyPair struct {
    PrivateKey []byte // 32 bytes
    PublicKey  []byte // 32 bytes
}

// X25519GenerateKeyPair generates a new X25519 key pair
func (m *Module) X25519GenerateKeyPair() (*X25519KeyPair, error) {
    privPtr, _ := m.allocate(X25519PrivateKeySize)
    pubPtr, _ := m.allocate(X25519PublicKeySize)
    defer m.freeAll(privPtr, pubPtr)

    result, err := m.x25519Generate.Call(m.ctx, privPtr, pubPtr)
    if err != nil {
        return nil, err
    }
    if result[0] != 0 {
        return nil, errors.New("key generation failed")
    }

    priv, _ := m.memory.Read(uint32(privPtr), X25519PrivateKeySize)
    pub, _ := m.memory.Read(uint32(pubPtr), X25519PublicKeySize)

    return &X25519KeyPair{
        PrivateKey: priv,
        PublicKey:  pub,
    }, nil
}

// X25519SharedSecret computes shared secret
func (m *Module) X25519SharedSecret(privateKey, publicKey []byte) ([]byte, error) {
    privPtr, _ := m.allocate(uint64(len(privateKey)))
    pubPtr, _ := m.allocate(uint64(len(publicKey)))
    outPtr, _ := m.allocate(32)
    defer m.freeAll(privPtr, pubPtr, outPtr)

    m.memory.Write(uint32(privPtr), privateKey)
    m.memory.Write(uint32(pubPtr), publicKey)

    result, err := m.x25519Shared.Call(m.ctx, privPtr, pubPtr, outPtr)
    if err != nil {
        return nil, err
    }
    if result[0] != 0 {
        return nil, errors.New("shared secret computation failed")
    }

    secret, _ := m.memory.Read(uint32(outPtr), 32)
    return secret, nil
}

// Ed25519KeyPair represents an Ed25519 key pair
type Ed25519KeyPair struct {
    PrivateKey []byte // 64 bytes (seed + public key)
    PublicKey  []byte // 32 bytes
}

// Ed25519GenerateKeyPair generates a new Ed25519 key pair
func (m *Module) Ed25519GenerateKeyPair() (*Ed25519KeyPair, error) {
    privPtr, _ := m.allocate(Ed25519PrivateKeySize)
    pubPtr, _ := m.allocate(Ed25519PublicKeySize)
    defer m.freeAll(privPtr, pubPtr)

    result, err := m.ed25519Generate.Call(m.ctx, privPtr, pubPtr)
    if err != nil {
        return nil, err
    }
    if result[0] != 0 {
        return nil, errors.New("key generation failed")
    }

    priv, _ := m.memory.Read(uint32(privPtr), Ed25519PrivateKeySize)
    pub, _ := m.memory.Read(uint32(pubPtr), Ed25519PublicKeySize)

    return &Ed25519KeyPair{
        PrivateKey: priv,
        PublicKey:  pub,
    }, nil
}

// Ed25519Sign signs a message
func (m *Module) Ed25519Sign(privateKey, message []byte) ([]byte, error) {
    privPtr, _ := m.allocate(uint64(len(privateKey)))
    msgPtr, _ := m.allocate(uint64(len(message)))
    sigPtr, _ := m.allocate(Ed25519SignatureSize)
    defer m.freeAll(privPtr, msgPtr, sigPtr)

    m.memory.Write(uint32(privPtr), privateKey)
    m.memory.Write(uint32(msgPtr), message)

    result, err := m.ed25519Sign.Call(m.ctx, privPtr, msgPtr, uint64(len(message)), sigPtr)
    if err != nil {
        return nil, err
    }
    if result[0] != 0 {
        return nil, errors.New("signing failed")
    }

    sig, _ := m.memory.Read(uint32(sigPtr), Ed25519SignatureSize)
    return sig, nil
}

// Ed25519Verify verifies a signature
func (m *Module) Ed25519Verify(publicKey, message, signature []byte) (bool, error) {
    pubPtr, _ := m.allocate(uint64(len(publicKey)))
    msgPtr, _ := m.allocate(uint64(len(message)))
    sigPtr, _ := m.allocate(uint64(len(signature)))
    defer m.freeAll(pubPtr, msgPtr, sigPtr)

    m.memory.Write(uint32(pubPtr), publicKey)
    m.memory.Write(uint32(msgPtr), message)
    m.memory.Write(uint32(sigPtr), signature)

    result, err := m.ed25519Verify.Call(m.ctx, pubPtr, msgPtr, uint64(len(message)), sigPtr)
    if err != nil {
        return false, err
    }

    return result[0] == 0, nil
}

// Helper functions

func (m *Module) allocate(size uint64) (uint64, error) {
    result, err := m.malloc.Call(m.ctx, size)
    if err != nil {
        return 0, err
    }
    return result[0], nil
}

func (m *Module) allocateAndWrite(buffers ...[]byte) ([]uint64, error) {
    ptrs := make([]uint64, len(buffers))
    for i, buf := range buffers {
        ptr, err := m.allocate(uint64(len(buf)))
        if err != nil {
            // Free already allocated
            for j := 0; j < i; j++ {
                m.free.Call(m.ctx, ptrs[j])
            }
            return nil, err
        }
        ptrs[i] = ptr
        m.memory.Write(uint32(ptr), buf)
    }
    return ptrs, nil
}

func (m *Module) freeAll(ptrs ...uint64) {
    for _, ptr := range ptrs {
        m.free.Call(m.ctx, ptr)
    }
}
```

### Emscripten Trampolines

The WASM module requires Emscripten's exception handling trampolines:

```go
func defineEnvModule(ctx context.Context, r wazero.Runtime) error {
    var wasmModule api.Module
    i32 := api.ValueTypeI32

    setException := func(ctx context.Context) {
        if wasmModule != nil {
            if f := wasmModule.ExportedFunction("setThrew"); f != nil {
                f.Call(ctx, 1, 0)
            }
        }
    }

    _, err := r.NewHostModuleBuilder("env").
        NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, idx uint32) {
            defer func() { recover(); setException(ctx) }()
            f := table.LookupFunction(wasmModule, 0, idx, nil, nil)
            f.Call(ctx)
        }).Export("invoke_v").
        NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, idx, a uint32) {
            defer func() { recover(); setException(ctx) }()
            f := table.LookupFunction(wasmModule, 0, idx, []api.ValueType{i32}, nil)
            f.Call(ctx, uint64(a))
        }).Export("invoke_vi").
        NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, idx, a, b uint32) {
            defer func() { recover(); setException(ctx) }()
            f := table.LookupFunction(wasmModule, 0, idx, []api.ValueType{i32, i32}, nil)
            f.Call(ctx, uint64(a), uint64(b))
        }).Export("invoke_vii").
        // Add more invoke_* variants as needed...
        Instantiate(ctx)

    return err
}
```

## Template Project Structure

```
myproject/
├── go.mod
├── go.sum
├── main.go
├── encryption/
│   └── module.go      # WASM wrapper
├── wasm/
│   └── flatc-encryption.wasm
└── README.md
```

**go.mod:**
```go
module myproject

go 1.21

require github.com/tetratelabs/wazero v1.7.0
```

## Advanced Usage

### Context Cancellation

Use context for timeout and cancellation:

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

module, err := New(ctx, "flatc-encryption.wasm")
if err != nil {
    if errors.Is(err, context.DeadlineExceeded) {
        log.Fatal("WASM loading timed out")
    }
    log.Fatal(err)
}
```

### Module Caching

Cache compiled modules for faster subsequent instantiation:

```go
// Compile once
compiled, err := r.CompileModule(ctx, wasmBytes)
if err != nil {
    return nil, err
}

// Instantiate multiple times (fast)
instance1, _ := r.InstantiateModule(ctx, compiled, config)
instance2, _ := r.InstantiateModule(ctx, compiled, config)
```

### Concurrent Usage

Each module instance has its own memory and can be used concurrently:

```go
// Create pool of modules
pool := make(chan *Module, 10)
for i := 0; i < 10; i++ {
    m, _ := New(ctx, "flatc-encryption.wasm")
    pool <- m
}

// Use from pool
func encryptConcurrent(data []byte) []byte {
    m := <-pool
    defer func() { pool <- m }()

    m.Encrypt(key, iv, data)
    return data
}
```

## Performance Tips

1. **Reuse module instances** - Module initialization is expensive
2. **Use compilation cache** - wazero supports filesystem caching
3. **Batch operations** - Minimize Go↔WASM boundary crossings
4. **Pre-allocate memory** - Reuse allocated buffers for repeated operations

### Compilation Cache

```go
// Enable filesystem cache
cache, err := wazero.NewCompilationCacheWithDir("/tmp/wazero-cache")
if err != nil {
    log.Fatal(err)
}

config := wazero.NewRuntimeConfig().WithCompilationCache(cache)
r := wazero.NewRuntimeWithConfig(ctx, config)
```

## Troubleshooting

### "function not exported"

The function name may differ. Check exports:

```go
for name := range module.ExportedFunctionDefinitions() {
    fmt.Println("Exported:", name)
}
```

### "memory access out of bounds"

Check that pointers from `malloc` are valid:

```go
result, err := malloc.Call(ctx, size)
if err != nil {
    return err
}
if result[0] == 0 {
    return errors.New("malloc returned null")
}
```

### "import not found: env.invoke_*"

Add Emscripten trampolines (see above). The exact `invoke_*` variants needed depend on the WASM module.

## See Also

- [wazero Documentation](https://wazero.io/)
- [API Reference](README.md#api-reference)
- [Security Considerations](README.md#security-considerations)
