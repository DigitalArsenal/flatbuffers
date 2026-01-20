# Swift Integration Guide

Integrate the FlatBuffers encryption WASM module into Swift applications using [WasmKit](https://github.com/AO/WasmKit), a pure Swift WebAssembly runtime.

## Why WasmKit?

- **Pure Swift** - No C dependencies, native Swift types
- **Swift Package Manager** - Easy integration
- **Cross-platform** - iOS, macOS, Linux
- **Modern API** - Swift concurrency support

## Prerequisites

- Swift 5.9 or later
- macOS 13+ or iOS 16+
- `flatc-encryption.wasm` binary

## Installation

Add to `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/AO/WasmKit.git", from: "0.0.5")
]
```

## Quick Start

```swift
import WasmKit
import Foundation

// Load WASM module
let wasmData = try Data(contentsOf: URL(fileURLWithPath: "flatc-encryption.wasm"))
let module = try WasmKit.parseWasm(bytes: Array(wasmData))

// Create runtime
let runtime = Runtime()
let moduleInstance = try runtime.instantiate(module: module)

// Get exports
let memory = try runtime.getExport(moduleInstance, name: "memory") as! Memory
let malloc = try runtime.getExport(moduleInstance, name: "malloc") as! Function
let free = try runtime.getExport(moduleInstance, name: "free") as! Function
let encrypt = try runtime.getExport(moduleInstance, name: "wasi_encrypt_bytes") as! Function

// Generate key and IV
var key = [UInt8](repeating: 0, count: 32)
var iv = [UInt8](repeating: 0, count: 16)
_ = SecRandomCopyBytes(kSecRandomDefault, key.count, &key)
_ = SecRandomCopyBytes(kSecRandomDefault, iv.count, &iv)

let plaintext = Array("Hello, FlatBuffers!".utf8)

// Allocate WASM memory
let keyPtr = try malloc.invoke([.i32(Int32(32))]).first!.i32
let ivPtr = try malloc.invoke([.i32(Int32(16))]).first!.i32
let dataPtr = try malloc.invoke([.i32(Int32(plaintext.count))]).first!.i32

// Write to memory
try memory.write(offset: Int(keyPtr), bytes: key)
try memory.write(offset: Int(ivPtr), bytes: iv)
try memory.write(offset: Int(dataPtr), bytes: plaintext)

// Encrypt
_ = try encrypt.invoke([
    .i32(keyPtr),
    .i32(ivPtr),
    .i32(dataPtr),
    .i32(Int32(plaintext.count))
])

// Read encrypted data
let ciphertext = try memory.read(offset: Int(dataPtr), count: plaintext.count)
print("Encrypted: \(ciphertext.map { String(format: "%02x", $0) }.joined())")

// Clean up
_ = try free.invoke([.i32(keyPtr)])
_ = try free.invoke([.i32(ivPtr)])
_ = try free.invoke([.i32(dataPtr)])
```

## Complete Module Wrapper

```swift
import WasmKit
import Foundation
import Security

/// Key and signature sizes
public enum CryptoConstants {
    public static let aesKeySize = 32
    public static let aesIVSize = 16
    public static let sha256Size = 32

    public static let x25519PrivateKeySize = 32
    public static let x25519PublicKeySize = 32

    public static let secp256k1PrivateKeySize = 32
    public static let secp256k1PublicKeySize = 33
    public static let secp256k1SignatureMaxSize = 72

    public static let ed25519PrivateKeySize = 64
    public static let ed25519PublicKeySize = 32
    public static let ed25519SignatureSize = 64
}

/// Encryption errors
public enum EncryptionError: Error, LocalizedError {
    case moduleLoadFailed(String)
    case exportNotFound(String)
    case allocationFailed
    case encryptionFailed
    case decryptionFailed
    case keyGenerationFailed
    case signatureFailed
    case verificationFailed
    case invalidKeySize(expected: Int, actual: Int)

    public var errorDescription: String? {
        switch self {
        case .moduleLoadFailed(let msg): return "Module load failed: \(msg)"
        case .exportNotFound(let name): return "Export not found: \(name)"
        case .allocationFailed: return "Memory allocation failed"
        case .encryptionFailed: return "Encryption operation failed"
        case .decryptionFailed: return "Decryption operation failed"
        case .keyGenerationFailed: return "Key generation failed"
        case .signatureFailed: return "Signature operation failed"
        case .verificationFailed: return "Verification operation failed"
        case .invalidKeySize(let expected, let actual):
            return "Invalid key size: expected \(expected), got \(actual)"
        }
    }
}

/// X25519 key pair
public struct X25519KeyPair {
    public let privateKey: [UInt8]  // 32 bytes
    public let publicKey: [UInt8]   // 32 bytes
}

/// Ed25519 key pair
public struct Ed25519KeyPair {
    public let privateKey: [UInt8]  // 64 bytes (seed + public key)
    public let publicKey: [UInt8]   // 32 bytes
}

/// secp256k1 key pair
public struct Secp256k1KeyPair {
    public let privateKey: [UInt8]  // 32 bytes
    public let publicKey: [UInt8]   // 33 bytes (compressed)
}

/// FlatBuffers Encryption Module for Swift
public final class EncryptionModule {
    private let runtime: Runtime
    private let moduleInstance: ModuleInstance
    private let memory: Memory

    private let mallocFn: Function
    private let freeFn: Function

    private let encryptFn: Function
    private let decryptFn: Function
    private let sha256Fn: Function
    private let hkdfFn: Function

    private let x25519GenerateFn: Function
    private let x25519SharedFn: Function

    private let secp256k1GenerateFn: Function
    private let secp256k1SharedFn: Function
    private let secp256k1SignFn: Function
    private let secp256k1VerifyFn: Function

    private let ed25519GenerateFn: Function
    private let ed25519SignFn: Function
    private let ed25519VerifyFn: Function

    /// Initialize from file path
    public convenience init(path: String) throws {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        try self.init(wasmData: data)
    }

    /// Initialize from data
    public init(wasmData: Data) throws {
        let module = try WasmKit.parseWasm(bytes: Array(wasmData))

        runtime = Runtime()

        // Register WASI stubs
        try registerWasiStubs(runtime: runtime)
        try registerEnvStubs(runtime: runtime)

        moduleInstance = try runtime.instantiate(module: module)
        memory = try getExport("memory")

        mallocFn = try getExport("malloc")
        freeFn = try getExport("free")

        encryptFn = try getExport("wasi_encrypt_bytes")
        decryptFn = try getExport("wasi_decrypt_bytes")
        sha256Fn = try getExport("wasi_sha256")
        hkdfFn = try getExport("wasi_hkdf")

        x25519GenerateFn = try getExport("wasi_x25519_generate_keypair")
        x25519SharedFn = try getExport("wasi_x25519_shared_secret")

        secp256k1GenerateFn = try getExport("wasi_secp256k1_generate_keypair")
        secp256k1SharedFn = try getExport("wasi_secp256k1_shared_secret")
        secp256k1SignFn = try getExport("wasi_secp256k1_sign")
        secp256k1VerifyFn = try getExport("wasi_secp256k1_verify")

        ed25519GenerateFn = try getExport("wasi_ed25519_generate_keypair")
        ed25519SignFn = try getExport("wasi_ed25519_sign")
        ed25519VerifyFn = try getExport("wasi_ed25519_verify")
    }

    private func getExport<T>(_ name: String) throws -> T {
        guard let export = try runtime.getExport(moduleInstance, name: name) as? T else {
            throw EncryptionError.exportNotFound(name)
        }
        return export
    }

    // MARK: - Memory Management

    private func allocate(_ size: Int) throws -> Int32 {
        let result = try mallocFn.invoke([.i32(Int32(size))])
        let ptr = result.first!.i32
        if ptr == 0 {
            throw EncryptionError.allocationFailed
        }
        return ptr
    }

    private func free(_ ptr: Int32) throws {
        _ = try freeFn.invoke([.i32(ptr)])
    }

    private func writeBytes(_ ptr: Int32, _ data: [UInt8]) throws {
        try memory.write(offset: Int(ptr), bytes: data)
    }

    private func readBytes(_ ptr: Int32, _ length: Int) throws -> [UInt8] {
        return try memory.read(offset: Int(ptr), count: length)
    }

    // MARK: - Symmetric Encryption

    /// Encrypt data using AES-256-CTR
    public func encrypt(key: [UInt8], iv: [UInt8], data: [UInt8]) throws -> [UInt8] {
        guard key.count == CryptoConstants.aesKeySize else {
            throw EncryptionError.invalidKeySize(
                expected: CryptoConstants.aesKeySize,
                actual: key.count
            )
        }
        guard iv.count == CryptoConstants.aesIVSize else {
            throw EncryptionError.invalidKeySize(
                expected: CryptoConstants.aesIVSize,
                actual: iv.count
            )
        }

        let keyPtr = try allocate(key.count)
        let ivPtr = try allocate(iv.count)
        let dataPtr = try allocate(data.count)

        defer {
            try? free(keyPtr)
            try? free(ivPtr)
            try? free(dataPtr)
        }

        try writeBytes(keyPtr, key)
        try writeBytes(ivPtr, iv)
        try writeBytes(dataPtr, data)

        let result = try encryptFn.invoke([
            .i32(keyPtr),
            .i32(ivPtr),
            .i32(dataPtr),
            .i32(Int32(data.count))
        ])

        if result.first?.i32 != 0 {
            throw EncryptionError.encryptionFailed
        }

        return try readBytes(dataPtr, data.count)
    }

    /// Decrypt data using AES-256-CTR
    public func decrypt(key: [UInt8], iv: [UInt8], data: [UInt8]) throws -> [UInt8] {
        // CTR mode is symmetric
        return try encrypt(key: key, iv: iv, data: data)
    }

    // MARK: - Hash Functions

    /// Compute SHA-256 hash
    public func sha256(_ data: [UInt8]) throws -> [UInt8] {
        let dataPtr = try allocate(data.count)
        let outPtr = try allocate(CryptoConstants.sha256Size)

        defer {
            try? free(dataPtr)
            try? free(outPtr)
        }

        try writeBytes(dataPtr, data)
        _ = try sha256Fn.invoke([
            .i32(dataPtr),
            .i32(Int32(data.count)),
            .i32(outPtr)
        ])

        return try readBytes(outPtr, CryptoConstants.sha256Size)
    }

    /// Derive key using HKDF-SHA256
    public func hkdf(ikm: [UInt8], salt: [UInt8]?, info: [UInt8], length: Int) throws -> [UInt8] {
        let ikmPtr = try allocate(ikm.count)
        try writeBytes(ikmPtr, ikm)

        var saltPtr: Int32 = 0
        var saltLen = 0
        if let salt = salt, !salt.isEmpty {
            saltPtr = try allocate(salt.count)
            try writeBytes(saltPtr, salt)
            saltLen = salt.count
        }

        let infoPtr = try allocate(info.count)
        try writeBytes(infoPtr, info)

        let outPtr = try allocate(length)

        defer {
            try? free(ikmPtr)
            if saltPtr != 0 { try? free(saltPtr) }
            try? free(infoPtr)
            try? free(outPtr)
        }

        _ = try hkdfFn.invoke([
            .i32(ikmPtr), .i32(Int32(ikm.count)),
            .i32(saltPtr), .i32(Int32(saltLen)),
            .i32(infoPtr), .i32(Int32(info.count)),
            .i32(outPtr), .i32(Int32(length))
        ])

        return try readBytes(outPtr, length)
    }

    // MARK: - X25519 Key Exchange

    /// Generate X25519 key pair
    public func x25519GenerateKeyPair() throws -> X25519KeyPair {
        let privPtr = try allocate(CryptoConstants.x25519PrivateKeySize)
        let pubPtr = try allocate(CryptoConstants.x25519PublicKeySize)

        defer {
            try? free(privPtr)
            try? free(pubPtr)
        }

        let result = try x25519GenerateFn.invoke([.i32(privPtr), .i32(pubPtr)])

        if result.first?.i32 != 0 {
            throw EncryptionError.keyGenerationFailed
        }

        return X25519KeyPair(
            privateKey: try readBytes(privPtr, CryptoConstants.x25519PrivateKeySize),
            publicKey: try readBytes(pubPtr, CryptoConstants.x25519PublicKeySize)
        )
    }

    /// Compute X25519 shared secret
    public func x25519SharedSecret(privateKey: [UInt8], publicKey: [UInt8]) throws -> [UInt8] {
        let privPtr = try allocate(privateKey.count)
        let pubPtr = try allocate(publicKey.count)
        let outPtr = try allocate(32)

        defer {
            try? free(privPtr)
            try? free(pubPtr)
            try? free(outPtr)
        }

        try writeBytes(privPtr, privateKey)
        try writeBytes(pubPtr, publicKey)

        let result = try x25519SharedFn.invoke([
            .i32(privPtr),
            .i32(pubPtr),
            .i32(outPtr)
        ])

        if result.first?.i32 != 0 {
            throw EncryptionError.encryptionFailed
        }

        return try readBytes(outPtr, 32)
    }

    // MARK: - Ed25519 Signatures

    /// Generate Ed25519 key pair
    public func ed25519GenerateKeyPair() throws -> Ed25519KeyPair {
        let privPtr = try allocate(CryptoConstants.ed25519PrivateKeySize)
        let pubPtr = try allocate(CryptoConstants.ed25519PublicKeySize)

        defer {
            try? free(privPtr)
            try? free(pubPtr)
        }

        let result = try ed25519GenerateFn.invoke([.i32(privPtr), .i32(pubPtr)])

        if result.first?.i32 != 0 {
            throw EncryptionError.keyGenerationFailed
        }

        return Ed25519KeyPair(
            privateKey: try readBytes(privPtr, CryptoConstants.ed25519PrivateKeySize),
            publicKey: try readBytes(pubPtr, CryptoConstants.ed25519PublicKeySize)
        )
    }

    /// Sign with Ed25519
    public func ed25519Sign(privateKey: [UInt8], message: [UInt8]) throws -> [UInt8] {
        let privPtr = try allocate(privateKey.count)
        let msgPtr = try allocate(message.count)
        let sigPtr = try allocate(CryptoConstants.ed25519SignatureSize)

        defer {
            try? free(privPtr)
            try? free(msgPtr)
            try? free(sigPtr)
        }

        try writeBytes(privPtr, privateKey)
        try writeBytes(msgPtr, message)

        let result = try ed25519SignFn.invoke([
            .i32(privPtr),
            .i32(msgPtr),
            .i32(Int32(message.count)),
            .i32(sigPtr)
        ])

        if result.first?.i32 != 0 {
            throw EncryptionError.signatureFailed
        }

        return try readBytes(sigPtr, CryptoConstants.ed25519SignatureSize)
    }

    /// Verify Ed25519 signature
    public func ed25519Verify(publicKey: [UInt8], message: [UInt8], signature: [UInt8]) throws -> Bool {
        let pubPtr = try allocate(publicKey.count)
        let msgPtr = try allocate(message.count)
        let sigPtr = try allocate(signature.count)

        defer {
            try? free(pubPtr)
            try? free(msgPtr)
            try? free(sigPtr)
        }

        try writeBytes(pubPtr, publicKey)
        try writeBytes(msgPtr, message)
        try writeBytes(sigPtr, signature)

        let result = try ed25519VerifyFn.invoke([
            .i32(pubPtr),
            .i32(msgPtr),
            .i32(Int32(message.count)),
            .i32(sigPtr)
        ])

        return result.first?.i32 == 0
    }
}

// MARK: - WASI Stubs

private func registerWasiStubs(runtime: Runtime) throws {
    try runtime.defineHostFunction(
        module: "wasi_snapshot_preview1",
        name: "fd_close",
        paramTypes: [.i32],
        resultTypes: [.i32]
    ) { _ in [.i32(0)] }

    try runtime.defineHostFunction(
        module: "wasi_snapshot_preview1",
        name: "clock_time_get",
        paramTypes: [.i32, .i64, .i32],
        resultTypes: [.i32]
    ) { _ in [.i32(0)] }

    // Add other WASI stubs as needed...
}

private func registerEnvStubs(runtime: Runtime) throws {
    try runtime.defineHostFunction(
        module: "env",
        name: "invoke_v",
        paramTypes: [.i32],
        resultTypes: []
    ) { _ in [] }

    try runtime.defineHostFunction(
        module: "env",
        name: "invoke_vi",
        paramTypes: [.i32, .i32],
        resultTypes: []
    ) { _ in [] }

    // Add other invoke_* stubs as needed...
}
```

## Template Project Structure

```
MyProject/
├── Package.swift
├── Sources/
│   └── MyProject/
│       ├── main.swift
│       └── Encryption/
│           └── EncryptionModule.swift
├── Resources/
│   └── flatc-encryption.wasm
└── Tests/
    └── MyProjectTests/
        └── EncryptionTests.swift
```

**Package.swift:**
```swift
// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "MyProject",
    platforms: [.macOS(.v13), .iOS(.v16)],
    dependencies: [
        .package(url: "https://github.com/AO/WasmKit.git", from: "0.0.5")
    ],
    targets: [
        .executableTarget(
            name: "MyProject",
            dependencies: ["WasmKit"],
            resources: [.copy("Resources/flatc-encryption.wasm")]
        ),
        .testTarget(
            name: "MyProjectTests",
            dependencies: ["MyProject"]
        )
    ]
)
```

## Usage Examples

### Basic Encryption

```swift
let module = try EncryptionModule(path: "flatc-encryption.wasm")

var key = [UInt8](repeating: 0, count: 32)
var iv = [UInt8](repeating: 0, count: 16)
_ = SecRandomCopyBytes(kSecRandomDefault, key.count, &key)
_ = SecRandomCopyBytes(kSecRandomDefault, iv.count, &iv)

let plaintext = Array("Secret message".utf8)
let ciphertext = try module.encrypt(key: key, iv: iv, data: plaintext)
let decrypted = try module.decrypt(key: key, iv: iv, data: ciphertext)

assert(plaintext == decrypted)
```

### End-to-End Encryption

```swift
let module = try EncryptionModule(path: "flatc-encryption.wasm")

// Generate key pairs
let alice = try module.x25519GenerateKeyPair()
let bob = try module.x25519GenerateKeyPair()

// Compute shared secrets
let aliceShared = try module.x25519SharedSecret(
    privateKey: alice.privateKey,
    publicKey: bob.publicKey
)
let bobShared = try module.x25519SharedSecret(
    privateKey: bob.privateKey,
    publicKey: alice.publicKey
)

assert(aliceShared == bobShared)

// Derive encryption key
let encryptionKey = try module.hkdf(
    ikm: aliceShared,
    salt: nil,
    info: Array("encryption-v1".utf8),
    length: 32
)

// Encrypt
var iv = [UInt8](repeating: 0, count: 16)
_ = SecRandomCopyBytes(kSecRandomDefault, iv.count, &iv)
let ciphertext = try module.encrypt(key: encryptionKey, iv: iv, data: Array("Hello Bob!".utf8))

// Decrypt
let decrypted = try module.decrypt(key: encryptionKey, iv: iv, data: ciphertext)
print(String(bytes: decrypted, encoding: .utf8)!) // "Hello Bob!"
```

## Performance Tips

1. **Reuse module instances** - Module loading is expensive
2. **Use async/await** - For non-blocking operations in SwiftUI
3. **Batch allocations** - Minimize malloc/free calls

## Troubleshooting

### "Export not found"

Ensure WASI and env stubs are registered before instantiation.

### "Memory access out of bounds"

Check allocation succeeded and sizes are correct.

## See Also

- [WasmKit Documentation](https://github.com/AO/WasmKit)
- [API Reference](README.md#api-reference)
- [Security Considerations](README.md#security-considerations)
