# C# Integration Guide

Integrate the FlatBuffers encryption WASM module into .NET applications using [Wasmtime](https://wasmtime.dev/), a fast and secure WebAssembly runtime.

## Why Wasmtime?

- **Production ready** - Used by Fastly, Shopify, and others
- **Fast** - Optimizing compiler with excellent performance
- **.NET 6+ support** - Modern .NET integration
- **NuGet package** - Easy installation

## Prerequisites

- .NET 6.0 or later
- `flatc-encryption.wasm` binary

## Installation

```bash
dotnet add package Wasmtime
```

## Quick Start

```csharp
using Wasmtime;

var engine = new Engine();
using var linker = new Linker(engine);
using var store = new Store(engine);

// Add WASI stubs
linker.DefineFunction("wasi_snapshot_preview1", "fd_close", (int fd) => 0);
linker.DefineFunction("wasi_snapshot_preview1", "clock_time_get",
    (Caller caller, int clockId, long precision, int time) => 0);
// Add other WASI functions as needed...

// Load module
using var module = Module.FromFile(engine, "flatc-encryption.wasm");
var instance = linker.Instantiate(store, module);

// Get exports
var memory = instance.GetMemory("memory")!;
var malloc = instance.GetFunction("malloc")!;
var free = instance.GetFunction("free")!;
var encrypt = instance.GetFunction("wasi_encrypt_bytes")!;

// Encrypt data
var key = new byte[32];
var iv = new byte[16];
Random.Shared.NextBytes(key);
Random.Shared.NextBytes(iv);

var plaintext = System.Text.Encoding.UTF8.GetBytes("Hello, FlatBuffers!");

// Allocate WASM memory
var keyPtr = (int)malloc.Invoke(32)!;
var ivPtr = (int)malloc.Invoke(16)!;
var dataPtr = (int)malloc.Invoke(plaintext.Length)!;

// Write to memory
memory.WriteBytes(keyPtr, key);
memory.WriteBytes(ivPtr, iv);
memory.WriteBytes(dataPtr, plaintext);

// Encrypt
encrypt.Invoke(keyPtr, ivPtr, dataPtr, plaintext.Length);

// Read encrypted data
var ciphertext = memory.ReadBytes(dataPtr, plaintext.Length);
Console.WriteLine($"Encrypted: {Convert.ToHexString(ciphertext)}");

// Clean up
free.Invoke(keyPtr);
free.Invoke(ivPtr);
free.Invoke(dataPtr);
```

## Complete Module Wrapper

```csharp
using Wasmtime;
using System.Security.Cryptography;
using System.Text;

namespace FlatBuffers.Encryption;

/// <summary>
/// FlatBuffers Encryption Module for .NET.
///
/// Provides cryptographic operations via the Crypto++ WASM module:
/// - AES-256-CTR symmetric encryption
/// - X25519 ECDH key exchange
/// - secp256k1 ECDH and ECDSA signatures
/// - P-256 ECDH and ECDSA signatures
/// - Ed25519 signatures
/// </summary>
public sealed class EncryptionModule : IDisposable
{
    // Key and signature sizes
    public const int AesKeySize = 32;
    public const int AesIvSize = 16;
    public const int Sha256Size = 32;

    public const int X25519PrivateKeySize = 32;
    public const int X25519PublicKeySize = 32;

    public const int Secp256k1PrivateKeySize = 32;
    public const int Secp256k1PublicKeySize = 33;
    public const int Secp256k1SignatureMaxSize = 72;

    public const int Ed25519PrivateKeySize = 64;
    public const int Ed25519PublicKeySize = 32;
    public const int Ed25519SignatureSize = 64;

    private readonly Engine _engine;
    private readonly Store _store;
    private readonly Linker _linker;
    private readonly Instance _instance;
    private readonly Memory _memory;

    private readonly Func<int, int> _malloc;
    private readonly Action<int> _free;

    private readonly Func<int, int, int, int, int> _encrypt;
    private readonly Func<int, int, int, int, int> _decrypt;
    private readonly Action<int, int, int> _sha256;
    private readonly Action<int, int, int, int, int, int, int, int> _hkdf;

    private readonly Func<int, int, int> _x25519Generate;
    private readonly Func<int, int, int, int> _x25519Shared;

    private readonly Func<int, int, int> _secp256k1Generate;
    private readonly Func<int, int, int, int, int> _secp256k1Shared;
    private readonly Func<int, int, int, int, int, int> _secp256k1Sign;
    private readonly Func<int, int, int, int, int, int, int> _secp256k1Verify;

    private readonly Func<int, int, int> _ed25519Generate;
    private readonly Func<int, int, int, int, int> _ed25519Sign;
    private readonly Func<int, int, int, int, int> _ed25519Verify;

    public EncryptionModule(string wasmPath)
    {
        _engine = new Engine();
        _store = new Store(_engine);
        _linker = new Linker(_engine);

        // Define WASI stubs
        DefineWasiStubs();
        DefineEnvStubs();

        // Load and instantiate module
        using var module = Module.FromFile(_engine, wasmPath);
        _instance = _linker.Instantiate(_store, module);

        // Get memory
        _memory = _instance.GetMemory("memory")
            ?? throw new InvalidOperationException("Memory export not found");

        // Get functions
        _malloc = _instance.GetFunction<int, int>("malloc")
            ?? throw new InvalidOperationException("malloc not found");
        _free = _instance.GetAction<int>("free")
            ?? throw new InvalidOperationException("free not found");

        _encrypt = _instance.GetFunction<int, int, int, int, int>("wasi_encrypt_bytes")!;
        _decrypt = _instance.GetFunction<int, int, int, int, int>("wasi_decrypt_bytes")!;
        _sha256 = _instance.GetAction<int, int, int>("wasi_sha256")!;
        _hkdf = _instance.GetAction<int, int, int, int, int, int, int, int>("wasi_hkdf")!;

        _x25519Generate = _instance.GetFunction<int, int, int>("wasi_x25519_generate_keypair")!;
        _x25519Shared = _instance.GetFunction<int, int, int, int>("wasi_x25519_shared_secret")!;

        _secp256k1Generate = _instance.GetFunction<int, int, int>("wasi_secp256k1_generate_keypair")!;
        _secp256k1Shared = _instance.GetFunction<int, int, int, int, int>("wasi_secp256k1_shared_secret")!;
        _secp256k1Sign = _instance.GetFunction<int, int, int, int, int, int>("wasi_secp256k1_sign")!;
        _secp256k1Verify = _instance.GetFunction<int, int, int, int, int, int, int>("wasi_secp256k1_verify")!;

        _ed25519Generate = _instance.GetFunction<int, int, int>("wasi_ed25519_generate_keypair")!;
        _ed25519Sign = _instance.GetFunction<int, int, int, int, int>("wasi_ed25519_sign")!;
        _ed25519Verify = _instance.GetFunction<int, int, int, int, int>("wasi_ed25519_verify")!;
    }

    private void DefineWasiStubs()
    {
        _linker.DefineFunction("wasi_snapshot_preview1", "fd_close",
            (int fd) => 0);
        _linker.DefineFunction("wasi_snapshot_preview1", "fd_seek",
            (Caller c, int fd, long offset, int whence, int newOffset) => 0);
        _linker.DefineFunction("wasi_snapshot_preview1", "fd_write",
            (Caller c, int fd, int iovs, int iovsLen, int nwritten) => 0);
        _linker.DefineFunction("wasi_snapshot_preview1", "fd_read",
            (Caller c, int fd, int iovs, int iovsLen, int nread) => 0);
        _linker.DefineFunction("wasi_snapshot_preview1", "environ_sizes_get",
            (Caller c, int count, int size) => 0);
        _linker.DefineFunction("wasi_snapshot_preview1", "environ_get",
            (Caller c, int environ, int environBuf) => 0);
        _linker.DefineFunction("wasi_snapshot_preview1", "clock_time_get",
            (Caller c, int clockId, long precision, int time) => 0);
        _linker.DefineFunction("wasi_snapshot_preview1", "proc_exit",
            (int code) => { });
        _linker.DefineFunction("wasi_snapshot_preview1", "random_get",
            (Caller c, int buf, int bufLen) => 0);
    }

    private void DefineEnvStubs()
    {
        _linker.DefineFunction("env", "invoke_v", (int idx) => { });
        _linker.DefineFunction("env", "invoke_vi", (int idx, int a) => { });
        _linker.DefineFunction("env", "invoke_vii", (int idx, int a, int b) => { });
        _linker.DefineFunction("env", "invoke_viii", (int idx, int a, int b, int c) => { });
        _linker.DefineFunction("env", "invoke_i", (int idx) => 0);
        _linker.DefineFunction("env", "invoke_ii", (int idx, int a) => 0);
        _linker.DefineFunction("env", "invoke_iii", (int idx, int a, int b) => 0);
    }

    // Key pair records

    public record X25519KeyPair(byte[] PrivateKey, byte[] PublicKey);
    public record Ed25519KeyPair(byte[] PrivateKey, byte[] PublicKey);
    public record Secp256k1KeyPair(byte[] PrivateKey, byte[] PublicKey);

    // Memory helpers

    private void WriteBytes(int offset, ReadOnlySpan<byte> data)
    {
        var span = _memory.GetSpan<byte>(offset, data.Length);
        data.CopyTo(span);
    }

    private byte[] ReadBytes(int offset, int length)
    {
        var span = _memory.GetSpan<byte>(offset, length);
        return span.ToArray();
    }

    private int Allocate(int size)
    {
        var ptr = _malloc(size);
        if (ptr == 0)
            throw new OutOfMemoryException("WASM malloc returned null");
        return ptr;
    }

    // Symmetric Encryption

    /// <summary>
    /// Encrypt data using AES-256-CTR.
    /// </summary>
    public byte[] Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> data)
    {
        if (key.Length != AesKeySize)
            throw new ArgumentException($"Key must be {AesKeySize} bytes", nameof(key));
        if (iv.Length != AesIvSize)
            throw new ArgumentException($"IV must be {AesIvSize} bytes", nameof(iv));

        var keyPtr = Allocate(key.Length);
        var ivPtr = Allocate(iv.Length);
        var dataPtr = Allocate(data.Length);

        try
        {
            WriteBytes(keyPtr, key);
            WriteBytes(ivPtr, iv);
            WriteBytes(dataPtr, data);

            var result = _encrypt(keyPtr, ivPtr, dataPtr, data.Length);
            if (result != 0)
                throw new CryptographicException("Encryption failed");

            return ReadBytes(dataPtr, data.Length);
        }
        finally
        {
            _free(keyPtr);
            _free(ivPtr);
            _free(dataPtr);
        }
    }

    /// <summary>
    /// Decrypt data using AES-256-CTR.
    /// </summary>
    public byte[] Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> data)
    {
        // CTR mode is symmetric
        return Encrypt(key, iv, data);
    }

    // Hash Functions

    /// <summary>
    /// Compute SHA-256 hash.
    /// </summary>
    public byte[] Sha256(ReadOnlySpan<byte> data)
    {
        var dataPtr = Allocate(data.Length);
        var outPtr = Allocate(Sha256Size);

        try
        {
            WriteBytes(dataPtr, data);
            _sha256(dataPtr, data.Length, outPtr);
            return ReadBytes(outPtr, Sha256Size);
        }
        finally
        {
            _free(dataPtr);
            _free(outPtr);
        }
    }

    /// <summary>
    /// Derive key using HKDF-SHA256.
    /// </summary>
    public byte[] Hkdf(ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info, int length)
    {
        var ikmPtr = Allocate(ikm.Length);
        WriteBytes(ikmPtr, ikm);

        var saltPtr = 0;
        var saltLen = 0;
        if (!salt.IsEmpty)
        {
            saltPtr = Allocate(salt.Length);
            WriteBytes(saltPtr, salt);
            saltLen = salt.Length;
        }

        var infoPtr = Allocate(info.Length);
        WriteBytes(infoPtr, info);

        var outPtr = Allocate(length);

        try
        {
            _hkdf(ikmPtr, ikm.Length, saltPtr, saltLen, infoPtr, info.Length, outPtr, length);
            return ReadBytes(outPtr, length);
        }
        finally
        {
            _free(ikmPtr);
            if (saltPtr != 0) _free(saltPtr);
            _free(infoPtr);
            _free(outPtr);
        }
    }

    // X25519 Key Exchange

    /// <summary>
    /// Generate X25519 key pair.
    /// </summary>
    public X25519KeyPair X25519GenerateKeyPair()
    {
        var privPtr = Allocate(X25519PrivateKeySize);
        var pubPtr = Allocate(X25519PublicKeySize);

        try
        {
            var result = _x25519Generate(privPtr, pubPtr);
            if (result != 0)
                throw new CryptographicException("Key generation failed");

            return new X25519KeyPair(
                ReadBytes(privPtr, X25519PrivateKeySize),
                ReadBytes(pubPtr, X25519PublicKeySize)
            );
        }
        finally
        {
            _free(privPtr);
            _free(pubPtr);
        }
    }

    /// <summary>
    /// Compute X25519 shared secret.
    /// </summary>
    public byte[] X25519SharedSecret(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
    {
        var privPtr = Allocate(privateKey.Length);
        var pubPtr = Allocate(publicKey.Length);
        var outPtr = Allocate(32);

        try
        {
            WriteBytes(privPtr, privateKey);
            WriteBytes(pubPtr, publicKey);

            var result = _x25519Shared(privPtr, pubPtr, outPtr);
            if (result != 0)
                throw new CryptographicException("Shared secret computation failed");

            return ReadBytes(outPtr, 32);
        }
        finally
        {
            _free(privPtr);
            _free(pubPtr);
            _free(outPtr);
        }
    }

    // Ed25519 Signatures

    /// <summary>
    /// Generate Ed25519 key pair.
    /// </summary>
    public Ed25519KeyPair Ed25519GenerateKeyPair()
    {
        var privPtr = Allocate(Ed25519PrivateKeySize);
        var pubPtr = Allocate(Ed25519PublicKeySize);

        try
        {
            var result = _ed25519Generate(privPtr, pubPtr);
            if (result != 0)
                throw new CryptographicException("Key generation failed");

            return new Ed25519KeyPair(
                ReadBytes(privPtr, Ed25519PrivateKeySize),
                ReadBytes(pubPtr, Ed25519PublicKeySize)
            );
        }
        finally
        {
            _free(privPtr);
            _free(pubPtr);
        }
    }

    /// <summary>
    /// Sign with Ed25519.
    /// </summary>
    public byte[] Ed25519Sign(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> message)
    {
        var privPtr = Allocate(privateKey.Length);
        var msgPtr = Allocate(message.Length);
        var sigPtr = Allocate(Ed25519SignatureSize);

        try
        {
            WriteBytes(privPtr, privateKey);
            WriteBytes(msgPtr, message);

            var result = _ed25519Sign(privPtr, msgPtr, message.Length, sigPtr);
            if (result != 0)
                throw new CryptographicException("Signing failed");

            return ReadBytes(sigPtr, Ed25519SignatureSize);
        }
        finally
        {
            _free(privPtr);
            _free(msgPtr);
            _free(sigPtr);
        }
    }

    /// <summary>
    /// Verify Ed25519 signature.
    /// </summary>
    public bool Ed25519Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        var pubPtr = Allocate(publicKey.Length);
        var msgPtr = Allocate(message.Length);
        var sigPtr = Allocate(signature.Length);

        try
        {
            WriteBytes(pubPtr, publicKey);
            WriteBytes(msgPtr, message);
            WriteBytes(sigPtr, signature);

            var result = _ed25519Verify(pubPtr, msgPtr, message.Length, sigPtr);
            return result == 0;
        }
        finally
        {
            _free(pubPtr);
            _free(msgPtr);
            _free(sigPtr);
        }
    }

    public void Dispose()
    {
        _store.Dispose();
        _linker.Dispose();
        _engine.Dispose();
    }
}
```

## Template Project Structure

```
MyProject/
├── MyProject.csproj
├── Program.cs
├── Encryption/
│   └── EncryptionModule.cs
├── wasm/
│   └── flatc-encryption.wasm
└── Tests/
    └── EncryptionTests.cs
```

**MyProject.csproj:**
```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <Nullable>enable</Nullable>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="Wasmtime" Version="18.0.0" />
  </ItemGroup>

  <ItemGroup>
    <None Update="wasm\flatc-encryption.wasm">
      <CopyToOutputDirectory>PreserveNewest</CopyToOutputDirectory>
    </None>
  </ItemGroup>
</Project>
```

## Usage Examples

### Basic Encryption

```csharp
using var module = new EncryptionModule("flatc-encryption.wasm");

var key = new byte[32];
var iv = new byte[16];
Random.Shared.NextBytes(key);
Random.Shared.NextBytes(iv);

var plaintext = Encoding.UTF8.GetBytes("Secret message");
var ciphertext = module.Encrypt(key, iv, plaintext);
var decrypted = module.Decrypt(key, iv, ciphertext);

Debug.Assert(plaintext.SequenceEqual(decrypted));
```

### End-to-End Encryption

```csharp
using var module = new EncryptionModule("flatc-encryption.wasm");

// Generate key pairs
var alice = module.X25519GenerateKeyPair();
var bob = module.X25519GenerateKeyPair();

// Compute shared secrets
var aliceShared = module.X25519SharedSecret(alice.PrivateKey, bob.PublicKey);
var bobShared = module.X25519SharedSecret(bob.PrivateKey, alice.PublicKey);

Debug.Assert(aliceShared.SequenceEqual(bobShared));

// Derive encryption key
var encryptionKey = module.Hkdf(aliceShared, default, "encryption-v1"u8, 32);

// Encrypt
var iv = new byte[16];
Random.Shared.NextBytes(iv);
var ciphertext = module.Encrypt(encryptionKey, iv, "Hello Bob!"u8);

// Decrypt
var decrypted = module.Decrypt(encryptionKey, iv, ciphertext);
Console.WriteLine(Encoding.UTF8.GetString(decrypted)); // "Hello Bob!"
```

## Performance Tips

1. **Reuse module instances** - Module loading is expensive
2. **Use Span<byte>** - Avoid unnecessary allocations
3. **Consider object pooling** - For high-throughput scenarios

```csharp
// Good: Reuse instance
using var module = new EncryptionModule("wasm");
foreach (var item in items)
{
    module.Encrypt(key, iv, item);
}

// Bad: Create new instance each time
foreach (var item in items)
{
    using var module = new EncryptionModule("wasm"); // Slow!
    module.Encrypt(key, iv, item);
}
```

## Troubleshooting

### "Function not found"

Ensure WASI and env stubs are defined before instantiation.

### "Memory access out of bounds"

Check allocation succeeded:

```csharp
var ptr = _malloc(size);
if (ptr == 0)
    throw new OutOfMemoryException("Allocation failed");
```

## See Also

- [Wasmtime .NET Documentation](https://docs.wasmtime.dev/)
- [API Reference](README.md#api-reference)
- [Security Considerations](README.md#security-considerations)
