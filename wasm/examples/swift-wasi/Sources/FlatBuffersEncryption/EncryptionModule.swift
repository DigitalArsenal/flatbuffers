import Foundation
import WasmKit
import WASI

/// FlatBuffers WASI Encryption Module for Swift.
///
/// This class provides encryption functionality using Crypto++ compiled to WASM,
/// executed via the WasmKit pure-Swift WebAssembly runtime.
///
/// Features:
/// - AES-256-CTR symmetric encryption
/// - X25519 ECDH key exchange
/// - secp256k1 ECDH and ECDSA signatures (Bitcoin/Ethereum compatible)
/// - P-256 ECDH and ECDSA signatures (NIST)
/// - Ed25519 signatures
/// - SHA-256 hashing
/// - HKDF key derivation
public final class EncryptionModule {

    // MARK: - Constants

    public static let aesKeySize = 32
    public static let aesIvSize = 16
    public static let sha256Size = 32
    public static let sharedSecretSize = 32

    public static let x25519PrivateKeySize = 32
    public static let x25519PublicKeySize = 32

    public static let secp256k1PrivateKeySize = 32
    public static let secp256k1PublicKeySize = 33  // compressed
    public static let secp256k1SignatureSize = 72  // DER encoded max

    public static let p256PrivateKeySize = 32
    public static let p256PublicKeySize = 33       // compressed
    public static let p256SignatureSize = 72       // DER encoded max

    public static let ed25519PrivateKeySize = 64   // seed + public key
    public static let ed25519PublicKeySize = 32
    public static let ed25519SignatureSize = 64

    private static let defaultWasmPath = "../../../build/wasm/wasm/flatc-encryption.wasm"

    // MARK: - Properties

    private let runtime: Runtime
    private let instance: ModuleInstance
    private let store: Store

    // Exported functions
    private let mallocFunc: Function
    private let freeFunc: Function
    private let getVersionFunc: Function
    private let hasCryptoppFunc: Function
    private let encryptBytesFunc: Function
    private let decryptBytesFunc: Function
    private let sha256Func: Function
    private let hkdfFunc: Function
    private let x25519GenerateKeypairFunc: Function
    private let x25519SharedSecretFunc: Function
    private let secp256k1GenerateKeypairFunc: Function
    private let secp256k1SharedSecretFunc: Function
    private let secp256k1SignFunc: Function
    private let secp256k1VerifyFunc: Function
    private let p256GenerateKeypairFunc: Function
    private let p256SharedSecretFunc: Function
    private let p256SignFunc: Function
    private let p256VerifyFunc: Function
    private let ed25519GenerateKeypairFunc: Function
    private let ed25519SignFunc: Function
    private let ed25519VerifyFunc: Function
    private let deriveSymmetricKeyFunc: Function

    // HE (Homomorphic Encryption) functions - optional, may not be in the WASM module
    private let heCreateClientFunc: Function?
    private let heCreateServerFunc: Function?
    private let heDestroyContextFunc: Function?
    private let heGetPublicKeyFunc: Function?
    private let heGetRelinKeysFunc: Function?
    private let heGetSecretKeyFunc: Function?
    private let heSetRelinKeysFunc: Function?
    private let heEncryptInt64Func: Function?
    private let heDecryptInt64Func: Function?
    private let heEncryptDoubleFunc: Function?
    private let heDecryptDoubleFunc: Function?
    private let heAddFunc: Function?
    private let heSubFunc: Function?
    private let heMultiplyFunc: Function?
    private let heNegateFunc: Function?
    private let heAddPlainFunc: Function?
    private let heMultiplyPlainFunc: Function?

    // Exception state
    private var threwValue: Int32 = 0
    private var threwType: Int32 = 0

    // MARK: - Initialization

    /// Creates a new EncryptionModule using the default WASM path.
    public convenience init() throws {
        try self.init(wasmPath: Self.defaultWasmPath)
    }

    /// Creates a new EncryptionModule from the specified WASM file path.
    public convenience init(wasmPath: String) throws {
        let url = URL(fileURLWithPath: wasmPath)
        let data = try Data(contentsOf: url)
        try self.init(wasmBytes: [UInt8](data))
    }

    /// Creates a new EncryptionModule from WASM bytes.
    public init(wasmBytes: [UInt8]) throws {
        // Create engine and store
        let engine = Engine()
        self.store = Store(engine: engine)
        self.runtime = Runtime(store: store)

        // Parse the module
        let module = try parseWasm(bytes: wasmBytes)

        // Create WASI bridge
        let wasi = try WASIBridgeToHost()

        // Create host module with Emscripten imports
        var hostFunctions: [String: HostFunction] = [:]

        // setThrew
        hostFunctions["setThrew"] = HostFunction(type: FunctionType(parameters: [.i32, .i32], results: [])) { caller, args in
            // Store threw state
            return []
        }

        // Exception handling stubs
        hostFunctions["__cxa_find_matching_catch_2"] = HostFunction(type: FunctionType(parameters: [], results: [.i32])) { _, _ in
            return [.i32(0)]
        }

        hostFunctions["__cxa_find_matching_catch_3"] = HostFunction(type: FunctionType(parameters: [.i32], results: [.i32])) { _, _ in
            return [.i32(0)]
        }

        hostFunctions["__resumeException"] = HostFunction(type: FunctionType(parameters: [.i32], results: [])) { _, _ in
            return []
        }

        hostFunctions["__cxa_begin_catch"] = HostFunction(type: FunctionType(parameters: [.i32], results: [.i32])) { _, _ in
            return [.i32(0)]
        }

        hostFunctions["__cxa_end_catch"] = HostFunction(type: FunctionType(parameters: [], results: [])) { _, _ in
            return []
        }

        hostFunctions["llvm_eh_typeid_for"] = HostFunction(type: FunctionType(parameters: [.i32], results: [.i32])) { _, _ in
            return [.i32(0)]
        }

        hostFunctions["__cxa_throw"] = HostFunction(type: FunctionType(parameters: [.i32, .i32, .i32], results: [])) { _, _ in
            return []
        }

        hostFunctions["__cxa_uncaught_exceptions"] = HostFunction(type: FunctionType(parameters: [], results: [.i32])) { _, _ in
            return [.i32(0)]
        }

        // invoke_* trampolines - stubs that call into the function table
        Self.addInvokeTrampolines(to: &hostFunctions)

        // Register host functions
        for (name, function) in hostFunctions {
            try runtime.register(hostFunction: function, module: "env", name: name)
        }

        // Register WASI
        try wasi.register(to: runtime, module: "wasi_snapshot_preview1")

        // Instantiate the module
        self.instance = try runtime.instantiate(module: module)

        // Get exported functions
        self.mallocFunc = try getFunction("malloc")
        self.freeFunc = try getFunction("free")
        self.getVersionFunc = try getFunction("get_version")
        self.hasCryptoppFunc = try getFunction("has_cryptopp")
        self.encryptBytesFunc = try getFunction("encrypt_bytes")
        self.decryptBytesFunc = try getFunction("decrypt_bytes")
        self.sha256Func = try getFunction("sha256")
        self.hkdfFunc = try getFunction("hkdf")
        self.x25519GenerateKeypairFunc = try getFunction("x25519_generate_keypair")
        self.x25519SharedSecretFunc = try getFunction("x25519_shared_secret")
        self.secp256k1GenerateKeypairFunc = try getFunction("secp256k1_generate_keypair")
        self.secp256k1SharedSecretFunc = try getFunction("secp256k1_shared_secret")
        self.secp256k1SignFunc = try getFunction("secp256k1_sign")
        self.secp256k1VerifyFunc = try getFunction("secp256k1_verify")
        self.p256GenerateKeypairFunc = try getFunction("p256_generate_keypair")
        self.p256SharedSecretFunc = try getFunction("p256_shared_secret")
        self.p256SignFunc = try getFunction("p256_sign")
        self.p256VerifyFunc = try getFunction("p256_verify")
        self.ed25519GenerateKeypairFunc = try getFunction("ed25519_generate_keypair")
        self.ed25519SignFunc = try getFunction("ed25519_sign")
        self.ed25519VerifyFunc = try getFunction("ed25519_verify")
        self.deriveSymmetricKeyFunc = try getFunction("derive_symmetric_key")

        // HE functions are optional - resolve them without throwing
        self.heCreateClientFunc = try? getFunction("wasi_he_context_create_client")
        self.heCreateServerFunc = try? getFunction("wasi_he_context_create_server")
        self.heDestroyContextFunc = try? getFunction("wasi_he_context_destroy")
        self.heGetPublicKeyFunc = try? getFunction("wasi_he_get_public_key")
        self.heGetRelinKeysFunc = try? getFunction("wasi_he_get_relin_keys")
        self.heGetSecretKeyFunc = try? getFunction("wasi_he_get_secret_key")
        self.heSetRelinKeysFunc = try? getFunction("wasi_he_set_relin_keys")
        self.heEncryptInt64Func = try? getFunction("wasi_he_encrypt_int64")
        self.heDecryptInt64Func = try? getFunction("wasi_he_decrypt_int64")
        self.heEncryptDoubleFunc = try? getFunction("wasi_he_encrypt_double")
        self.heDecryptDoubleFunc = try? getFunction("wasi_he_decrypt_double")
        self.heAddFunc = try? getFunction("wasi_he_add")
        self.heSubFunc = try? getFunction("wasi_he_sub")
        self.heMultiplyFunc = try? getFunction("wasi_he_multiply")
        self.heNegateFunc = try? getFunction("wasi_he_negate")
        self.heAddPlainFunc = try? getFunction("wasi_he_add_plain")
        self.heMultiplyPlainFunc = try? getFunction("wasi_he_multiply_plain")
    }

    private func getFunction(_ name: String) throws -> Function {
        guard let export = instance.exports[function: name] else {
            throw EncryptionError.functionNotFound(name)
        }
        return export
    }

    private static func addInvokeTrampolines(to functions: inout [String: HostFunction]) {
        // invoke_v: (idx) -> void
        functions["invoke_v"] = HostFunction(type: FunctionType(parameters: [.i32], results: [])) { caller, args in
            // Call function from table at index args[0]
            return []
        }

        // invoke_vi: (idx, i32) -> void
        functions["invoke_vi"] = HostFunction(type: FunctionType(parameters: [.i32, .i32], results: [])) { caller, args in
            return []
        }

        // invoke_vii: (idx, i32, i32) -> void
        functions["invoke_vii"] = HostFunction(type: FunctionType(parameters: [.i32, .i32, .i32], results: [])) { caller, args in
            return []
        }

        // invoke_viii: (idx, i32, i32, i32) -> void
        functions["invoke_viii"] = HostFunction(type: FunctionType(parameters: [.i32, .i32, .i32, .i32], results: [])) { caller, args in
            return []
        }

        // invoke_viiii: (idx, i32 x 4) -> void
        functions["invoke_viiii"] = HostFunction(type: FunctionType(parameters: [.i32, .i32, .i32, .i32, .i32], results: [])) { caller, args in
            return []
        }

        // invoke_viiiii: (idx, i32 x 5) -> void
        functions["invoke_viiiii"] = HostFunction(type: FunctionType(parameters: [.i32, .i32, .i32, .i32, .i32, .i32], results: [])) { caller, args in
            return []
        }

        // invoke_viiiiii: (idx, i32 x 6) -> void
        functions["invoke_viiiiii"] = HostFunction(type: FunctionType(parameters: [.i32, .i32, .i32, .i32, .i32, .i32, .i32], results: [])) { caller, args in
            return []
        }

        // invoke_viiiiiii: (idx, i32 x 7) -> void
        functions["invoke_viiiiiii"] = HostFunction(type: FunctionType(parameters: [.i32, .i32, .i32, .i32, .i32, .i32, .i32, .i32], results: [])) { caller, args in
            return []
        }

        // invoke_viiiiiiiii: (idx, i32 x 9) -> void
        functions["invoke_viiiiiiiii"] = HostFunction(type: FunctionType(parameters: [.i32, .i32, .i32, .i32, .i32, .i32, .i32, .i32, .i32, .i32], results: [])) { caller, args in
            return []
        }

        // invoke_i: (idx) -> i32
        functions["invoke_i"] = HostFunction(type: FunctionType(parameters: [.i32], results: [.i32])) { caller, args in
            return [.i32(0)]
        }

        // invoke_ii: (idx, i32) -> i32
        functions["invoke_ii"] = HostFunction(type: FunctionType(parameters: [.i32, .i32], results: [.i32])) { caller, args in
            return [.i32(0)]
        }

        // invoke_iii: (idx, i32, i32) -> i32
        functions["invoke_iii"] = HostFunction(type: FunctionType(parameters: [.i32, .i32, .i32], results: [.i32])) { caller, args in
            return [.i32(0)]
        }

        // invoke_iiii: (idx, i32 x 3) -> i32
        functions["invoke_iiii"] = HostFunction(type: FunctionType(parameters: [.i32, .i32, .i32, .i32], results: [.i32])) { caller, args in
            return [.i32(0)]
        }

        // invoke_iiiii: (idx, i32 x 4) -> i32
        functions["invoke_iiiii"] = HostFunction(type: FunctionType(parameters: [.i32, .i32, .i32, .i32, .i32], results: [.i32])) { caller, args in
            return [.i32(0)]
        }

        // invoke_iiiiii: (idx, i32 x 5) -> i32
        functions["invoke_iiiiii"] = HostFunction(type: FunctionType(parameters: [.i32, .i32, .i32, .i32, .i32, .i32], results: [.i32])) { caller, args in
            return [.i32(0)]
        }

        // invoke_iiiiiii: (idx, i32 x 6) -> i32
        functions["invoke_iiiiiii"] = HostFunction(type: FunctionType(parameters: [.i32, .i32, .i32, .i32, .i32, .i32, .i32], results: [.i32])) { caller, args in
            return [.i32(0)]
        }

        // invoke_iiiiiiii: (idx, i32 x 7) -> i32
        functions["invoke_iiiiiiii"] = HostFunction(type: FunctionType(parameters: [.i32, .i32, .i32, .i32, .i32, .i32, .i32, .i32], results: [.i32])) { caller, args in
            return [.i32(0)]
        }

        // invoke_iiiiiiiiii: (idx, i32 x 9) -> i32
        functions["invoke_iiiiiiiiii"] = HostFunction(type: FunctionType(parameters: [.i32, .i32, .i32, .i32, .i32, .i32, .i32, .i32, .i32, .i32], results: [.i32])) { caller, args in
            return [.i32(0)]
        }
    }

    // MARK: - Memory Helpers

    private var memory: Memory {
        instance.exports[memory: "memory"]!
    }

    private func allocate(_ size: Int) throws -> Int32 {
        let results = try mallocFunc.invoke([.i32(Int32(size))], runtime: runtime)
        return results[0].i32
    }

    private func deallocate(_ ptr: Int32) throws {
        _ = try freeFunc.invoke([.i32(ptr)], runtime: runtime)
    }

    private func writeBytes(_ ptr: Int32, _ data: [UInt8]) {
        memory.data.withUnsafeMutableBytes { buffer in
            for (i, byte) in data.enumerated() {
                buffer[Int(ptr) + i] = byte
            }
        }
    }

    private func readBytes(_ ptr: Int32, _ length: Int) -> [UInt8] {
        return memory.data.withUnsafeBytes { buffer in
            Array(buffer[Int(ptr)..<Int(ptr) + length])
        }
    }

    private func readInt32(_ ptr: Int32) -> Int32 {
        return memory.data.withUnsafeBytes { buffer in
            buffer.load(fromByteOffset: Int(ptr), as: Int32.self)
        }
    }

    private func readUInt32(_ ptr: Int32) -> UInt32 {
        let bytes = readBytes(ptr, 4)
        return UInt32(bytes[0])
            | (UInt32(bytes[1]) << 8)
            | (UInt32(bytes[2]) << 16)
            | (UInt32(bytes[3]) << 24)
    }

    private func readInt64(_ ptr: Int32) -> Int64 {
        return memory.data.withUnsafeBytes { buffer in
            buffer.load(fromByteOffset: Int(ptr), as: Int64.self)
        }
    }

    private func readFloat64(_ ptr: Int32) -> Double {
        return memory.data.withUnsafeBytes { buffer in
            buffer.load(fromByteOffset: Int(ptr), as: Double.self)
        }
    }

    private func writeInt64(_ ptr: Int32, _ value: Int64) {
        var v = value
        withUnsafeBytes(of: &v) { src in
            memory.data.withUnsafeMutableBytes { buffer in
                for i in 0..<8 {
                    buffer[Int(ptr) + i] = src[i]
                }
            }
        }
    }

    private func writeFloat64(_ ptr: Int32, _ value: Double) {
        var v = value
        withUnsafeBytes(of: &v) { src in
            memory.data.withUnsafeMutableBytes { buffer in
                for i in 0..<8 {
                    buffer[Int(ptr) + i] = src[i]
                }
            }
        }
    }

    private func writeUInt32(_ ptr: Int32, _ value: UInt32) {
        let bytes: [UInt8] = [
            UInt8(value & 0xFF),
            UInt8((value >> 8) & 0xFF),
            UInt8((value >> 16) & 0xFF),
            UInt8((value >> 24) & 0xFF)
        ]
        writeBytes(ptr, bytes)
    }

    private func requireHEFunc(_ func: Function?, name: String) throws -> Function {
        guard let f = `func` else {
            throw EncryptionError.heNotAvailable(name)
        }
        return f
    }

    // MARK: - Public API

    /// Returns the module version string.
    public func version() throws -> String {
        let results = try getVersionFunc.invoke([], runtime: runtime)
        let ptr = results[0].i32
        if ptr == 0 { return "unknown" }

        var bytes: [UInt8] = []
        var i: Int32 = 0
        while true {
            let byte = readBytes(ptr + i, 1)[0]
            if byte == 0 { break }
            bytes.append(byte)
            i += 1
        }
        return String(bytes: bytes, encoding: .utf8) ?? "unknown"
    }

    /// Returns true if Crypto++ is available.
    public func hasCryptopp() throws -> Bool {
        let results = try hasCryptoppFunc.invoke([], runtime: runtime)
        return results[0].i32 != 0
    }

    /// Encrypts data using AES-256-CTR.
    public func encrypt(key: [UInt8], iv: [UInt8], plaintext: [UInt8]) throws -> [UInt8] {
        guard key.count == Self.aesKeySize else {
            throw EncryptionError.invalidKeySize(expected: Self.aesKeySize, actual: key.count)
        }
        guard iv.count == Self.aesIvSize else {
            throw EncryptionError.invalidIvSize(expected: Self.aesIvSize, actual: iv.count)
        }
        if plaintext.isEmpty { return [] }

        let keyPtr = try allocate(Self.aesKeySize)
        let ivPtr = try allocate(Self.aesIvSize)
        let dataPtr = try allocate(plaintext.count)

        defer {
            try? deallocate(keyPtr)
            try? deallocate(ivPtr)
            try? deallocate(dataPtr)
        }

        writeBytes(keyPtr, key)
        writeBytes(ivPtr, iv)
        writeBytes(dataPtr, plaintext)

        _ = try encryptBytesFunc.invoke([
            .i32(keyPtr),
            .i32(ivPtr),
            .i32(dataPtr),
            .i32(Int32(plaintext.count))
        ], runtime: runtime)

        return readBytes(dataPtr, plaintext.count)
    }

    /// Decrypts data using AES-256-CTR.
    public func decrypt(key: [UInt8], iv: [UInt8], ciphertext: [UInt8]) throws -> [UInt8] {
        guard key.count == Self.aesKeySize else {
            throw EncryptionError.invalidKeySize(expected: Self.aesKeySize, actual: key.count)
        }
        guard iv.count == Self.aesIvSize else {
            throw EncryptionError.invalidIvSize(expected: Self.aesIvSize, actual: iv.count)
        }
        if ciphertext.isEmpty { return [] }

        let keyPtr = try allocate(Self.aesKeySize)
        let ivPtr = try allocate(Self.aesIvSize)
        let dataPtr = try allocate(ciphertext.count)

        defer {
            try? deallocate(keyPtr)
            try? deallocate(ivPtr)
            try? deallocate(dataPtr)
        }

        writeBytes(keyPtr, key)
        writeBytes(ivPtr, iv)
        writeBytes(dataPtr, ciphertext)

        _ = try decryptBytesFunc.invoke([
            .i32(keyPtr),
            .i32(ivPtr),
            .i32(dataPtr),
            .i32(Int32(ciphertext.count))
        ], runtime: runtime)

        return readBytes(dataPtr, ciphertext.count)
    }

    /// Computes SHA-256 hash of data.
    public func sha256(_ data: [UInt8]) throws -> [UInt8] {
        let dataPtr = try allocate(max(data.count, 1))
        let hashPtr = try allocate(Self.sha256Size)

        defer {
            try? deallocate(dataPtr)
            try? deallocate(hashPtr)
        }

        if !data.isEmpty {
            writeBytes(dataPtr, data)
        }

        _ = try sha256Func.invoke([
            .i32(dataPtr),
            .i32(Int32(data.count)),
            .i32(hashPtr)
        ], runtime: runtime)

        return readBytes(hashPtr, Self.sha256Size)
    }

    /// Derives a key using HKDF-SHA256.
    public func hkdf(ikm: [UInt8], salt: [UInt8], info: [UInt8], length: Int) throws -> [UInt8] {
        let ikmPtr = try allocate(max(ikm.count, 1))
        let saltPtr = try allocate(max(salt.count, 1))
        let infoPtr = try allocate(max(info.count, 1))
        let outPtr = try allocate(length)

        defer {
            try? deallocate(ikmPtr)
            try? deallocate(saltPtr)
            try? deallocate(infoPtr)
            try? deallocate(outPtr)
        }

        if !ikm.isEmpty { writeBytes(ikmPtr, ikm) }
        if !salt.isEmpty { writeBytes(saltPtr, salt) }
        if !info.isEmpty { writeBytes(infoPtr, info) }

        _ = try hkdfFunc.invoke([
            .i32(ikmPtr),
            .i32(Int32(ikm.count)),
            .i32(saltPtr),
            .i32(Int32(salt.count)),
            .i32(infoPtr),
            .i32(Int32(info.count)),
            .i32(outPtr),
            .i32(Int32(length))
        ], runtime: runtime)

        return readBytes(outPtr, length)
    }

    /// Generates an X25519 key pair.
    public func x25519GenerateKeypair() throws -> KeyPair {
        let privPtr = try allocate(Self.x25519PrivateKeySize)
        let pubPtr = try allocate(Self.x25519PublicKeySize)

        defer {
            try? deallocate(privPtr)
            try? deallocate(pubPtr)
        }

        _ = try x25519GenerateKeypairFunc.invoke([.i32(privPtr), .i32(pubPtr)], runtime: runtime)

        return KeyPair(
            privateKey: readBytes(privPtr, Self.x25519PrivateKeySize),
            publicKey: readBytes(pubPtr, Self.x25519PublicKeySize)
        )
    }

    /// Computes X25519 shared secret.
    public func x25519SharedSecret(privateKey: [UInt8], publicKey: [UInt8]) throws -> [UInt8] {
        let privPtr = try allocate(Self.x25519PrivateKeySize)
        let pubPtr = try allocate(Self.x25519PublicKeySize)
        let secretPtr = try allocate(Self.sharedSecretSize)

        defer {
            try? deallocate(privPtr)
            try? deallocate(pubPtr)
            try? deallocate(secretPtr)
        }

        writeBytes(privPtr, privateKey)
        writeBytes(pubPtr, publicKey)

        _ = try x25519SharedSecretFunc.invoke([
            .i32(privPtr),
            .i32(pubPtr),
            .i32(secretPtr)
        ], runtime: runtime)

        return readBytes(secretPtr, Self.sharedSecretSize)
    }

    /// Generates a secp256k1 key pair.
    public func secp256k1GenerateKeypair() throws -> KeyPair {
        let privPtr = try allocate(Self.secp256k1PrivateKeySize)
        let pubPtr = try allocate(Self.secp256k1PublicKeySize)

        defer {
            try? deallocate(privPtr)
            try? deallocate(pubPtr)
        }

        _ = try secp256k1GenerateKeypairFunc.invoke([.i32(privPtr), .i32(pubPtr)], runtime: runtime)

        return KeyPair(
            privateKey: readBytes(privPtr, Self.secp256k1PrivateKeySize),
            publicKey: readBytes(pubPtr, Self.secp256k1PublicKeySize)
        )
    }

    /// Computes secp256k1 ECDH shared secret.
    public func secp256k1SharedSecret(privateKey: [UInt8], publicKey: [UInt8]) throws -> [UInt8] {
        let privPtr = try allocate(Self.secp256k1PrivateKeySize)
        let pubPtr = try allocate(Self.secp256k1PublicKeySize)
        let secretPtr = try allocate(Self.sharedSecretSize)

        defer {
            try? deallocate(privPtr)
            try? deallocate(pubPtr)
            try? deallocate(secretPtr)
        }

        writeBytes(privPtr, privateKey)
        writeBytes(pubPtr, publicKey)

        _ = try secp256k1SharedSecretFunc.invoke([
            .i32(privPtr),
            .i32(pubPtr),
            .i32(secretPtr)
        ], runtime: runtime)

        return readBytes(secretPtr, Self.sharedSecretSize)
    }

    /// Signs a message using secp256k1 ECDSA.
    public func secp256k1Sign(privateKey: [UInt8], message: [UInt8]) throws -> [UInt8] {
        let privPtr = try allocate(Self.secp256k1PrivateKeySize)
        let msgPtr = try allocate(max(message.count, 1))
        let sigPtr = try allocate(Self.secp256k1SignatureSize)
        let sigLenPtr = try allocate(4)

        defer {
            try? deallocate(privPtr)
            try? deallocate(msgPtr)
            try? deallocate(sigPtr)
            try? deallocate(sigLenPtr)
        }

        writeBytes(privPtr, privateKey)
        if !message.isEmpty { writeBytes(msgPtr, message) }

        _ = try secp256k1SignFunc.invoke([
            .i32(privPtr),
            .i32(msgPtr),
            .i32(Int32(message.count)),
            .i32(sigPtr),
            .i32(sigLenPtr)
        ], runtime: runtime)

        let sigLen = readInt32(sigLenPtr)
        return readBytes(sigPtr, Int(sigLen))
    }

    /// Verifies a secp256k1 ECDSA signature.
    public func secp256k1Verify(publicKey: [UInt8], message: [UInt8], signature: [UInt8]) throws -> Bool {
        let pubPtr = try allocate(Self.secp256k1PublicKeySize)
        let msgPtr = try allocate(max(message.count, 1))
        let sigPtr = try allocate(signature.count)

        defer {
            try? deallocate(pubPtr)
            try? deallocate(msgPtr)
            try? deallocate(sigPtr)
        }

        writeBytes(pubPtr, publicKey)
        if !message.isEmpty { writeBytes(msgPtr, message) }
        writeBytes(sigPtr, signature)

        let results = try secp256k1VerifyFunc.invoke([
            .i32(pubPtr),
            .i32(msgPtr),
            .i32(Int32(message.count)),
            .i32(sigPtr),
            .i32(Int32(signature.count))
        ], runtime: runtime)

        return results[0].i32 != 0
    }

    /// Generates a P-256 key pair.
    public func p256GenerateKeypair() throws -> KeyPair {
        let privPtr = try allocate(Self.p256PrivateKeySize)
        let pubPtr = try allocate(Self.p256PublicKeySize)

        defer {
            try? deallocate(privPtr)
            try? deallocate(pubPtr)
        }

        _ = try p256GenerateKeypairFunc.invoke([.i32(privPtr), .i32(pubPtr)], runtime: runtime)

        return KeyPair(
            privateKey: readBytes(privPtr, Self.p256PrivateKeySize),
            publicKey: readBytes(pubPtr, Self.p256PublicKeySize)
        )
    }

    /// Computes P-256 ECDH shared secret.
    public func p256SharedSecret(privateKey: [UInt8], publicKey: [UInt8]) throws -> [UInt8] {
        let privPtr = try allocate(Self.p256PrivateKeySize)
        let pubPtr = try allocate(Self.p256PublicKeySize)
        let secretPtr = try allocate(Self.sharedSecretSize)

        defer {
            try? deallocate(privPtr)
            try? deallocate(pubPtr)
            try? deallocate(secretPtr)
        }

        writeBytes(privPtr, privateKey)
        writeBytes(pubPtr, publicKey)

        _ = try p256SharedSecretFunc.invoke([
            .i32(privPtr),
            .i32(pubPtr),
            .i32(secretPtr)
        ], runtime: runtime)

        return readBytes(secretPtr, Self.sharedSecretSize)
    }

    /// Signs a message using P-256 ECDSA.
    public func p256Sign(privateKey: [UInt8], message: [UInt8]) throws -> [UInt8] {
        let privPtr = try allocate(Self.p256PrivateKeySize)
        let msgPtr = try allocate(max(message.count, 1))
        let sigPtr = try allocate(Self.p256SignatureSize)
        let sigLenPtr = try allocate(4)

        defer {
            try? deallocate(privPtr)
            try? deallocate(msgPtr)
            try? deallocate(sigPtr)
            try? deallocate(sigLenPtr)
        }

        writeBytes(privPtr, privateKey)
        if !message.isEmpty { writeBytes(msgPtr, message) }

        _ = try p256SignFunc.invoke([
            .i32(privPtr),
            .i32(msgPtr),
            .i32(Int32(message.count)),
            .i32(sigPtr),
            .i32(sigLenPtr)
        ], runtime: runtime)

        let sigLen = readInt32(sigLenPtr)
        return readBytes(sigPtr, Int(sigLen))
    }

    /// Verifies a P-256 ECDSA signature.
    public func p256Verify(publicKey: [UInt8], message: [UInt8], signature: [UInt8]) throws -> Bool {
        let pubPtr = try allocate(Self.p256PublicKeySize)
        let msgPtr = try allocate(max(message.count, 1))
        let sigPtr = try allocate(signature.count)

        defer {
            try? deallocate(pubPtr)
            try? deallocate(msgPtr)
            try? deallocate(sigPtr)
        }

        writeBytes(pubPtr, publicKey)
        if !message.isEmpty { writeBytes(msgPtr, message) }
        writeBytes(sigPtr, signature)

        let results = try p256VerifyFunc.invoke([
            .i32(pubPtr),
            .i32(msgPtr),
            .i32(Int32(message.count)),
            .i32(sigPtr),
            .i32(Int32(signature.count))
        ], runtime: runtime)

        return results[0].i32 != 0
    }

    /// Generates an Ed25519 key pair.
    public func ed25519GenerateKeypair() throws -> KeyPair {
        let privPtr = try allocate(Self.ed25519PrivateKeySize)
        let pubPtr = try allocate(Self.ed25519PublicKeySize)

        defer {
            try? deallocate(privPtr)
            try? deallocate(pubPtr)
        }

        _ = try ed25519GenerateKeypairFunc.invoke([.i32(privPtr), .i32(pubPtr)], runtime: runtime)

        return KeyPair(
            privateKey: readBytes(privPtr, Self.ed25519PrivateKeySize),
            publicKey: readBytes(pubPtr, Self.ed25519PublicKeySize)
        )
    }

    /// Signs a message using Ed25519.
    public func ed25519Sign(privateKey: [UInt8], message: [UInt8]) throws -> [UInt8] {
        let privPtr = try allocate(Self.ed25519PrivateKeySize)
        let msgPtr = try allocate(max(message.count, 1))
        let sigPtr = try allocate(Self.ed25519SignatureSize)

        defer {
            try? deallocate(privPtr)
            try? deallocate(msgPtr)
            try? deallocate(sigPtr)
        }

        writeBytes(privPtr, privateKey)
        if !message.isEmpty { writeBytes(msgPtr, message) }

        _ = try ed25519SignFunc.invoke([
            .i32(privPtr),
            .i32(msgPtr),
            .i32(Int32(message.count)),
            .i32(sigPtr)
        ], runtime: runtime)

        return readBytes(sigPtr, Self.ed25519SignatureSize)
    }

    /// Verifies an Ed25519 signature.
    public func ed25519Verify(publicKey: [UInt8], message: [UInt8], signature: [UInt8]) throws -> Bool {
        let pubPtr = try allocate(Self.ed25519PublicKeySize)
        let msgPtr = try allocate(max(message.count, 1))
        let sigPtr = try allocate(Self.ed25519SignatureSize)

        defer {
            try? deallocate(pubPtr)
            try? deallocate(msgPtr)
            try? deallocate(sigPtr)
        }

        writeBytes(pubPtr, publicKey)
        if !message.isEmpty { writeBytes(msgPtr, message) }
        writeBytes(sigPtr, signature)

        let results = try ed25519VerifyFunc.invoke([
            .i32(pubPtr),
            .i32(msgPtr),
            .i32(Int32(message.count)),
            .i32(sigPtr)
        ], runtime: runtime)

        return results[0].i32 != 0
    }

    /// Derives a symmetric key from a shared secret using HKDF.
    public func deriveSymmetricKey(sharedSecret: [UInt8], context: String) throws -> DerivedKey {
        let contextBytes = Array(context.utf8)

        let secretPtr = try allocate(sharedSecret.count)
        let contextPtr = try allocate(max(contextBytes.count, 1))
        let keyPtr = try allocate(Self.aesKeySize)
        let ivPtr = try allocate(Self.aesIvSize)

        defer {
            try? deallocate(secretPtr)
            try? deallocate(contextPtr)
            try? deallocate(keyPtr)
            try? deallocate(ivPtr)
        }

        writeBytes(secretPtr, sharedSecret)
        if !contextBytes.isEmpty { writeBytes(contextPtr, contextBytes) }

        _ = try deriveSymmetricKeyFunc.invoke([
            .i32(secretPtr),
            .i32(Int32(sharedSecret.count)),
            .i32(contextPtr),
            .i32(Int32(contextBytes.count)),
            .i32(keyPtr),
            .i32(ivPtr)
        ], runtime: runtime)

        return DerivedKey(
            key: readBytes(keyPtr, Self.aesKeySize),
            iv: readBytes(ivPtr, Self.aesIvSize)
        )
    }

    // MARK: - Homomorphic Encryption (HE) API

    /// Returns true if homomorphic encryption functions are available in the WASM module.
    public func hasHE() -> Bool {
        return heCreateClientFunc != nil
    }

    /// Creates an HE client context with optional polynomial degree.
    /// Returns a context ID used for subsequent HE operations.
    public func heCreateClient(polyDegree: UInt32 = 0) throws -> Int32 {
        let f = try requireHEFunc(heCreateClientFunc, name: "wasi_he_context_create_client")
        let results = try f.invoke([.i32(Int32(bitPattern: polyDegree))], runtime: runtime)
        let ctxId = results[0].i32
        if ctxId < 0 {
            throw EncryptionError.heOperationFailed("heCreateClient returned error code \(ctxId)")
        }
        return ctxId
    }

    /// Creates an HE server context from the given public key bytes.
    /// Returns a context ID used for subsequent HE operations.
    public func heCreateServer(publicKey: [UInt8]) throws -> Int32 {
        let f = try requireHEFunc(heCreateServerFunc, name: "wasi_he_context_create_server")

        let pkPtr = try allocate(publicKey.count)
        defer { try? deallocate(pkPtr) }
        writeBytes(pkPtr, publicKey)

        let results = try f.invoke([
            .i32(pkPtr),
            .i32(Int32(publicKey.count))
        ], runtime: runtime)
        let ctxId = results[0].i32
        if ctxId < 0 {
            throw EncryptionError.heOperationFailed("heCreateServer returned error code \(ctxId)")
        }
        return ctxId
    }

    /// Destroys an HE context, freeing its resources.
    public func heDestroyContext(_ ctxId: Int32) {
        guard let f = heDestroyContextFunc else { return }
        _ = try? f.invoke([.i32(ctxId)], runtime: runtime)
    }

    /// Returns the public key bytes for the given HE context.
    public func heGetPublicKey(_ ctxId: Int32) throws -> [UInt8] {
        let f = try requireHEFunc(heGetPublicKeyFunc, name: "wasi_he_get_public_key")
        let outLenPtr = try allocate(4)
        defer { try? deallocate(outLenPtr) }
        writeUInt32(outLenPtr, 0)

        let results = try f.invoke([.i32(ctxId), .i32(outLenPtr)], runtime: runtime)
        let dataPtr = results[0].i32
        if dataPtr == 0 {
            throw EncryptionError.heOperationFailed("heGetPublicKey returned null pointer")
        }
        let length = readUInt32(outLenPtr)
        return readBytes(dataPtr, Int(length))
    }

    /// Returns the relinearization keys bytes for the given HE context.
    public func heGetRelinKeys(_ ctxId: Int32) throws -> [UInt8] {
        let f = try requireHEFunc(heGetRelinKeysFunc, name: "wasi_he_get_relin_keys")
        let outLenPtr = try allocate(4)
        defer { try? deallocate(outLenPtr) }
        writeUInt32(outLenPtr, 0)

        let results = try f.invoke([.i32(ctxId), .i32(outLenPtr)], runtime: runtime)
        let dataPtr = results[0].i32
        if dataPtr == 0 {
            throw EncryptionError.heOperationFailed("heGetRelinKeys returned null pointer")
        }
        let length = readUInt32(outLenPtr)
        return readBytes(dataPtr, Int(length))
    }

    /// Returns the secret key bytes for the given HE context.
    public func heGetSecretKey(_ ctxId: Int32) throws -> [UInt8] {
        let f = try requireHEFunc(heGetSecretKeyFunc, name: "wasi_he_get_secret_key")
        let outLenPtr = try allocate(4)
        defer { try? deallocate(outLenPtr) }
        writeUInt32(outLenPtr, 0)

        let results = try f.invoke([.i32(ctxId), .i32(outLenPtr)], runtime: runtime)
        let dataPtr = results[0].i32
        if dataPtr == 0 {
            throw EncryptionError.heOperationFailed("heGetSecretKey returned null pointer")
        }
        let length = readUInt32(outLenPtr)
        return readBytes(dataPtr, Int(length))
    }

    /// Sets the relinearization keys on the given HE context.
    public func heSetRelinKeys(_ ctxId: Int32, relinKeys: [UInt8]) throws {
        let f = try requireHEFunc(heSetRelinKeysFunc, name: "wasi_he_set_relin_keys")

        let rkPtr = try allocate(relinKeys.count)
        defer { try? deallocate(rkPtr) }
        writeBytes(rkPtr, relinKeys)

        let results = try f.invoke([
            .i32(ctxId),
            .i32(rkPtr),
            .i32(Int32(relinKeys.count))
        ], runtime: runtime)
        let rc = results[0].i32
        if rc != 0 {
            throw EncryptionError.heOperationFailed("heSetRelinKeys returned error code \(rc)")
        }
    }

    /// Encrypts a 64-bit integer using homomorphic encryption.
    /// Returns the ciphertext bytes.
    public func heEncryptInt64(_ ctxId: Int32, value: Int64) throws -> [UInt8] {
        let f = try requireHEFunc(heEncryptInt64Func, name: "wasi_he_encrypt_int64")
        let outLenPtr = try allocate(4)
        defer { try? deallocate(outLenPtr) }
        writeUInt32(outLenPtr, 0)

        // Pass Int64 as two i32 values (low, high) for WASM i64 compatibility
        let lo = Int32(truncatingIfNeeded: value)
        let hi = Int32(truncatingIfNeeded: value >> 32)

        let results = try f.invoke([
            .i32(ctxId),
            .i32(lo),
            .i32(hi),
            .i32(outLenPtr)
        ], runtime: runtime)
        let dataPtr = results[0].i32
        if dataPtr == 0 {
            throw EncryptionError.heOperationFailed("heEncryptInt64 returned null pointer")
        }
        let length = readUInt32(outLenPtr)
        return readBytes(dataPtr, Int(length))
    }

    /// Decrypts a ciphertext back to a 64-bit integer.
    public func heDecryptInt64(_ ctxId: Int32, ciphertext: [UInt8]) throws -> Int64 {
        let f = try requireHEFunc(heDecryptInt64Func, name: "wasi_he_decrypt_int64")

        let ctPtr = try allocate(ciphertext.count)
        let resultPtr = try allocate(8)
        defer {
            try? deallocate(ctPtr)
            try? deallocate(resultPtr)
        }
        writeBytes(ctPtr, ciphertext)

        let results = try f.invoke([
            .i32(ctxId),
            .i32(ctPtr),
            .i32(Int32(ciphertext.count)),
            .i32(resultPtr)
        ], runtime: runtime)
        let rc = results[0].i32
        if rc != 0 {
            throw EncryptionError.heOperationFailed("heDecryptInt64 returned error code \(rc)")
        }
        return readInt64(resultPtr)
    }

    /// Encrypts a Double using homomorphic encryption.
    /// Returns the ciphertext bytes.
    public func heEncryptDouble(_ ctxId: Int32, value: Double) throws -> [UInt8] {
        let f = try requireHEFunc(heEncryptDoubleFunc, name: "wasi_he_encrypt_double")
        let outLenPtr = try allocate(4)
        let valPtr = try allocate(8)
        defer {
            try? deallocate(outLenPtr)
            try? deallocate(valPtr)
        }
        writeUInt32(outLenPtr, 0)
        writeFloat64(valPtr, value)

        let results = try f.invoke([
            .i32(ctxId),
            .i32(valPtr),
            .i32(outLenPtr)
        ], runtime: runtime)
        let dataPtr = results[0].i32
        if dataPtr == 0 {
            throw EncryptionError.heOperationFailed("heEncryptDouble returned null pointer")
        }
        let length = readUInt32(outLenPtr)
        return readBytes(dataPtr, Int(length))
    }

    /// Decrypts a ciphertext back to a Double.
    public func heDecryptDouble(_ ctxId: Int32, ciphertext: [UInt8]) throws -> Double {
        let f = try requireHEFunc(heDecryptDoubleFunc, name: "wasi_he_decrypt_double")

        let ctPtr = try allocate(ciphertext.count)
        let resultPtr = try allocate(8)
        defer {
            try? deallocate(ctPtr)
            try? deallocate(resultPtr)
        }
        writeBytes(ctPtr, ciphertext)

        let results = try f.invoke([
            .i32(ctxId),
            .i32(ctPtr),
            .i32(Int32(ciphertext.count)),
            .i32(resultPtr)
        ], runtime: runtime)
        let rc = results[0].i32
        if rc != 0 {
            throw EncryptionError.heOperationFailed("heDecryptDouble returned error code \(rc)")
        }
        return readFloat64(resultPtr)
    }

    /// Adds two ciphertexts homomorphically. Returns the resulting ciphertext.
    public func heAdd(_ ctxId: Int32, ct1: [UInt8], ct2: [UInt8]) throws -> [UInt8] {
        let f = try requireHEFunc(heAddFunc, name: "wasi_he_add")
        let ct1Ptr = try allocate(ct1.count)
        let ct2Ptr = try allocate(ct2.count)
        let outLenPtr = try allocate(4)
        defer {
            try? deallocate(ct1Ptr)
            try? deallocate(ct2Ptr)
            try? deallocate(outLenPtr)
        }
        writeBytes(ct1Ptr, ct1)
        writeBytes(ct2Ptr, ct2)
        writeUInt32(outLenPtr, 0)

        let results = try f.invoke([
            .i32(ctxId),
            .i32(ct1Ptr), .i32(Int32(ct1.count)),
            .i32(ct2Ptr), .i32(Int32(ct2.count)),
            .i32(outLenPtr)
        ], runtime: runtime)
        let dataPtr = results[0].i32
        if dataPtr == 0 {
            throw EncryptionError.heOperationFailed("heAdd returned null pointer")
        }
        let length = readUInt32(outLenPtr)
        return readBytes(dataPtr, Int(length))
    }

    /// Subtracts two ciphertexts homomorphically. Returns the resulting ciphertext.
    public func heSub(_ ctxId: Int32, ct1: [UInt8], ct2: [UInt8]) throws -> [UInt8] {
        let f = try requireHEFunc(heSubFunc, name: "wasi_he_sub")
        let ct1Ptr = try allocate(ct1.count)
        let ct2Ptr = try allocate(ct2.count)
        let outLenPtr = try allocate(4)
        defer {
            try? deallocate(ct1Ptr)
            try? deallocate(ct2Ptr)
            try? deallocate(outLenPtr)
        }
        writeBytes(ct1Ptr, ct1)
        writeBytes(ct2Ptr, ct2)
        writeUInt32(outLenPtr, 0)

        let results = try f.invoke([
            .i32(ctxId),
            .i32(ct1Ptr), .i32(Int32(ct1.count)),
            .i32(ct2Ptr), .i32(Int32(ct2.count)),
            .i32(outLenPtr)
        ], runtime: runtime)
        let dataPtr = results[0].i32
        if dataPtr == 0 {
            throw EncryptionError.heOperationFailed("heSub returned null pointer")
        }
        let length = readUInt32(outLenPtr)
        return readBytes(dataPtr, Int(length))
    }

    /// Multiplies two ciphertexts homomorphically. Returns the resulting ciphertext.
    public func heMultiply(_ ctxId: Int32, ct1: [UInt8], ct2: [UInt8]) throws -> [UInt8] {
        let f = try requireHEFunc(heMultiplyFunc, name: "wasi_he_multiply")
        let ct1Ptr = try allocate(ct1.count)
        let ct2Ptr = try allocate(ct2.count)
        let outLenPtr = try allocate(4)
        defer {
            try? deallocate(ct1Ptr)
            try? deallocate(ct2Ptr)
            try? deallocate(outLenPtr)
        }
        writeBytes(ct1Ptr, ct1)
        writeBytes(ct2Ptr, ct2)
        writeUInt32(outLenPtr, 0)

        let results = try f.invoke([
            .i32(ctxId),
            .i32(ct1Ptr), .i32(Int32(ct1.count)),
            .i32(ct2Ptr), .i32(Int32(ct2.count)),
            .i32(outLenPtr)
        ], runtime: runtime)
        let dataPtr = results[0].i32
        if dataPtr == 0 {
            throw EncryptionError.heOperationFailed("heMultiply returned null pointer")
        }
        let length = readUInt32(outLenPtr)
        return readBytes(dataPtr, Int(length))
    }

    /// Negates a ciphertext homomorphically. Returns the resulting ciphertext.
    public func heNegate(_ ctxId: Int32, ct: [UInt8]) throws -> [UInt8] {
        let f = try requireHEFunc(heNegateFunc, name: "wasi_he_negate")
        let ctPtr = try allocate(ct.count)
        let outLenPtr = try allocate(4)
        defer {
            try? deallocate(ctPtr)
            try? deallocate(outLenPtr)
        }
        writeBytes(ctPtr, ct)
        writeUInt32(outLenPtr, 0)

        let results = try f.invoke([
            .i32(ctxId),
            .i32(ctPtr), .i32(Int32(ct.count)),
            .i32(outLenPtr)
        ], runtime: runtime)
        let dataPtr = results[0].i32
        if dataPtr == 0 {
            throw EncryptionError.heOperationFailed("heNegate returned null pointer")
        }
        let length = readUInt32(outLenPtr)
        return readBytes(dataPtr, Int(length))
    }

    /// Adds a plaintext Int64 to a ciphertext homomorphically. Returns the resulting ciphertext.
    public func heAddPlain(_ ctxId: Int32, ct: [UInt8], plain: Int64) throws -> [UInt8] {
        let f = try requireHEFunc(heAddPlainFunc, name: "wasi_he_add_plain")
        let ctPtr = try allocate(ct.count)
        let outLenPtr = try allocate(4)
        defer {
            try? deallocate(ctPtr)
            try? deallocate(outLenPtr)
        }
        writeBytes(ctPtr, ct)
        writeUInt32(outLenPtr, 0)

        let lo = Int32(truncatingIfNeeded: plain)
        let hi = Int32(truncatingIfNeeded: plain >> 32)

        let results = try f.invoke([
            .i32(ctxId),
            .i32(ctPtr), .i32(Int32(ct.count)),
            .i32(lo), .i32(hi),
            .i32(outLenPtr)
        ], runtime: runtime)
        let dataPtr = results[0].i32
        if dataPtr == 0 {
            throw EncryptionError.heOperationFailed("heAddPlain returned null pointer")
        }
        let length = readUInt32(outLenPtr)
        return readBytes(dataPtr, Int(length))
    }

    /// Multiplies a ciphertext by a plaintext Int64 homomorphically. Returns the resulting ciphertext.
    public func heMultiplyPlain(_ ctxId: Int32, ct: [UInt8], plain: Int64) throws -> [UInt8] {
        let f = try requireHEFunc(heMultiplyPlainFunc, name: "wasi_he_multiply_plain")
        let ctPtr = try allocate(ct.count)
        let outLenPtr = try allocate(4)
        defer {
            try? deallocate(ctPtr)
            try? deallocate(outLenPtr)
        }
        writeBytes(ctPtr, ct)
        writeUInt32(outLenPtr, 0)

        let lo = Int32(truncatingIfNeeded: plain)
        let hi = Int32(truncatingIfNeeded: plain >> 32)

        let results = try f.invoke([
            .i32(ctxId),
            .i32(ctPtr), .i32(Int32(ct.count)),
            .i32(lo), .i32(hi),
            .i32(outLenPtr)
        ], runtime: runtime)
        let dataPtr = results[0].i32
        if dataPtr == 0 {
            throw EncryptionError.heOperationFailed("heMultiplyPlain returned null pointer")
        }
        let length = readUInt32(outLenPtr)
        return readBytes(dataPtr, Int(length))
    }

    /// Generates random bytes using a secure random number generator.
    public static func randomBytes(_ count: Int) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        return bytes
    }
}

// MARK: - Supporting Types

public struct KeyPair {
    public let privateKey: [UInt8]
    public let publicKey: [UInt8]
}

public struct DerivedKey {
    public let key: [UInt8]
    public let iv: [UInt8]
}

public enum EncryptionError: Error, LocalizedError {
    case functionNotFound(String)
    case invalidKeySize(expected: Int, actual: Int)
    case invalidIvSize(expected: Int, actual: Int)
    case wasmError(String)
    case heNotAvailable(String)
    case heOperationFailed(String)

    public var errorDescription: String? {
        switch self {
        case .functionNotFound(let name):
            return "Function '\(name)' not found in WASM module"
        case .invalidKeySize(let expected, let actual):
            return "Invalid key size: expected \(expected), got \(actual)"
        case .invalidIvSize(let expected, let actual):
            return "Invalid IV size: expected \(expected), got \(actual)"
        case .wasmError(let message):
            return "WASM error: \(message)"
        case .heNotAvailable(let name):
            return "Homomorphic encryption function '\(name)' not available in WASM module"
        case .heOperationFailed(let message):
            return "Homomorphic encryption operation failed: \(message)"
        }
    }
}
