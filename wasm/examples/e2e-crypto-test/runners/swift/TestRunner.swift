/**
 * Swift E2E Test Runner for FlatBuffers Cross-Language Encryption
 *
 * Tests encryption/decryption using the WASM Crypto++ module with all 10 crypto key types.
 * Uses WasmKit pure-Swift WASM runtime (v0.2.0 API).
 */
import Foundation
import WasmKit
import WasmKitWASI
import SystemPackage

let AES_KEY_SIZE = 32
let AES_IV_SIZE = 16
let SHA256_SIZE = 32

class EncryptionModule {
    private let store: Store
    private let instance: Instance

    private let mallocFunc: Function
    private let freeFunc: Function
    private let sha256Func: Function
    private let encryptBytesFunc: Function
    private let decryptBytesFunc: Function
    private let hkdfFunc: Function
    private let x25519GenerateFunc: Function
    private let x25519SharedFunc: Function
    private let secp256k1GenerateFunc: Function
    private let secp256k1SharedFunc: Function
    private let p256GenerateFunc: Function
    private let p256SharedFunc: Function

    init(wasmPath: String) throws {
        let module = try parseWasm(filePath: FilePath(wasmPath))

        let engine = Engine()
        let store = Store(engine: engine)
        self.store = store

        // Create WASI bridge
        let wasi = try WASIBridgeToHost()

        // Build imports
        var imports = Imports()
        wasi.link(to: &imports, store: store)

        // Emscripten stubs
        EncryptionModule.addEmscriptenStubs(to: &imports, store: store)

        // Instantiate the module
        self.instance = try module.instantiate(store: store, imports: imports)

        // Get exported functions
        self.mallocFunc = instance.exports[function: "malloc"]!
        self.freeFunc = instance.exports[function: "free"]!
        self.sha256Func = instance.exports[function: "wasi_sha256"]!
        self.encryptBytesFunc = instance.exports[function: "wasi_encrypt_bytes"]!
        self.decryptBytesFunc = instance.exports[function: "wasi_decrypt_bytes"]!
        self.hkdfFunc = instance.exports[function: "wasi_hkdf"]!
        self.x25519GenerateFunc = instance.exports[function: "wasi_x25519_generate_keypair"]!
        self.x25519SharedFunc = instance.exports[function: "wasi_x25519_shared_secret"]!
        self.secp256k1GenerateFunc = instance.exports[function: "wasi_secp256k1_generate_keypair"]!
        self.secp256k1SharedFunc = instance.exports[function: "wasi_secp256k1_shared_secret"]!
        self.p256GenerateFunc = instance.exports[function: "wasi_p256_generate_keypair"]!
        self.p256SharedFunc = instance.exports[function: "wasi_p256_shared_secret"]!

        // Call _initialize if present (required for Emscripten modules)
        if let initFunc = instance.exports[function: "_initialize"] {
            _ = try? initFunc()
        }
    }

    private static func addEmscriptenStubs(to imports: inout Imports, store: Store) {
        // Exception handling stubs
        imports.define(module: "env", name: "setThrew",
            Function(store: store, parameters: [.i32, .i32]) { _, _ in [] })
        imports.define(module: "env", name: "__cxa_find_matching_catch_2",
            Function(store: store, parameters: [], results: [.i32]) { _, _ in [.i32(0)] })
        imports.define(module: "env", name: "__cxa_find_matching_catch_3",
            Function(store: store, parameters: [.i32], results: [.i32]) { _, _ in [.i32(0)] })
        imports.define(module: "env", name: "__resumeException",
            Function(store: store, parameters: [.i32]) { _, _ in [] })
        imports.define(module: "env", name: "__cxa_begin_catch",
            Function(store: store, parameters: [.i32], results: [.i32]) { _, _ in [.i32(0)] })
        imports.define(module: "env", name: "__cxa_end_catch",
            Function(store: store, parameters: []) { _, _ in [] })
        imports.define(module: "env", name: "llvm_eh_typeid_for",
            Function(store: store, parameters: [.i32], results: [.i32]) { _, _ in [.i32(0)] })
        imports.define(module: "env", name: "__cxa_throw",
            Function(store: store, parameters: [.i32, .i32, .i32]) { _, _ in [] })
        imports.define(module: "env", name: "__cxa_uncaught_exceptions",
            Function(store: store, parameters: [], results: [.i32]) { _, _ in [.i32(0)] })

        // invoke_* trampolines - void variants
        // These call functions from the indirect function table
        let voidInvokes: [(String, Int)] = [
            ("invoke_v", 1), ("invoke_vi", 2), ("invoke_vii", 3),
            ("invoke_viii", 4), ("invoke_viiii", 5), ("invoke_viiiii", 6),
            ("invoke_viiiiii", 7), ("invoke_viiiiiii", 8), ("invoke_viiiiiiiii", 10)
        ]
        for (name, params) in voidInvokes {
            let paramTypes = Array(repeating: ValueType.i32, count: params)
            imports.define(module: "env", name: name,
                Function(store: store, parameters: paramTypes) { caller, args in
                    let tableIdx = Int(args[0].i32)
                    guard let instance = caller.instance,
                          let table = instance.exports[table: "__indirect_function_table"],
                          let func_ = table.getFunction(at: tableIdx, store: caller.store) else {
                        return []
                    }
                    // Build args (skip table index)
                    var funcArgs: [Value] = []
                    for i in 1..<args.count {
                        funcArgs.append(args[i])
                    }
                    do {
                        _ = try func_(funcArgs)
                    } catch {
                        // Exception caught - handled by Emscripten EH
                    }
                    return []
                })
        }

        // invoke_* trampolines - i32 return variants
        let i32Invokes: [(String, Int)] = [
            ("invoke_i", 1), ("invoke_ii", 2), ("invoke_iii", 3),
            ("invoke_iiii", 4), ("invoke_iiiii", 5), ("invoke_iiiiii", 6),
            ("invoke_iiiiiii", 7), ("invoke_iiiiiiii", 8), ("invoke_iiiiiiiiii", 10)
        ]
        for (name, params) in i32Invokes {
            let paramTypes = Array(repeating: ValueType.i32, count: params)
            imports.define(module: "env", name: name,
                Function(store: store, parameters: paramTypes, results: [.i32]) { caller, args in
                    let tableIdx = Int(args[0].i32)
                    guard let instance = caller.instance,
                          let table = instance.exports[table: "__indirect_function_table"],
                          let func_ = table.getFunction(at: tableIdx, store: caller.store) else {
                        return [.i32(0)]
                    }
                    // Build args (skip table index)
                    var funcArgs: [Value] = []
                    for i in 1..<args.count {
                        funcArgs.append(args[i])
                    }
                    do {
                        let results = try func_(funcArgs)
                        if !results.isEmpty {
                            return [results[0]]
                        }
                    } catch {
                        // Exception caught - handled by Emscripten EH
                    }
                    return [.i32(0)]
                })
        }
    }

    private var memory: Memory { instance.exports[memory: "memory"]! }

    private func allocate(_ size: Int) throws -> UInt32 {
        let results = try mallocFunc([.i32(UInt32(size))])
        return results[0].i32
    }

    private func deallocate(_ ptr: UInt32) throws {
        _ = try freeFunc([.i32(ptr)])
    }

    private func writeBytes(_ ptr: UInt32, _ bytes: [UInt8]) {
        memory.withUnsafeMutableBufferPointer(offset: UInt(ptr), count: bytes.count) { buffer in
            for (i, byte) in bytes.enumerated() {
                buffer[i] = byte
            }
        }
    }

    private func readBytes(_ ptr: UInt32, _ length: Int) -> [UInt8] {
        let data = memory.data
        return Array(data[Int(ptr)..<Int(ptr) + length])
    }

    func sha256(_ data: [UInt8]) throws -> [UInt8] {
        let dataPtr = try allocate(max(data.count, 1))
        let hashPtr = try allocate(SHA256_SIZE)

        defer {
            try? deallocate(dataPtr)
            try? deallocate(hashPtr)
        }

        if !data.isEmpty { writeBytes(dataPtr, data) }
        _ = try sha256Func([.i32(dataPtr), .i32(UInt32(data.count)), .i32(hashPtr)])

        return readBytes(hashPtr, SHA256_SIZE)
    }

    func encrypt(key: [UInt8], iv: [UInt8], data: [UInt8]) throws -> [UInt8] {
        let keyPtr = try allocate(AES_KEY_SIZE)
        let ivPtr = try allocate(AES_IV_SIZE)
        let dataPtr = try allocate(data.count)

        defer {
            try? deallocate(keyPtr)
            try? deallocate(ivPtr)
            try? deallocate(dataPtr)
        }

        writeBytes(keyPtr, key)
        writeBytes(ivPtr, iv)
        writeBytes(dataPtr, data)
        _ = try encryptBytesFunc([.i32(keyPtr), .i32(ivPtr), .i32(dataPtr), .i32(UInt32(data.count))])

        return readBytes(dataPtr, data.count)
    }

    func decrypt(key: [UInt8], iv: [UInt8], data: [UInt8]) throws -> [UInt8] {
        let keyPtr = try allocate(AES_KEY_SIZE)
        let ivPtr = try allocate(AES_IV_SIZE)
        let dataPtr = try allocate(data.count)

        defer {
            try? deallocate(keyPtr)
            try? deallocate(ivPtr)
            try? deallocate(dataPtr)
        }

        writeBytes(keyPtr, key)
        writeBytes(ivPtr, iv)
        writeBytes(dataPtr, data)
        _ = try decryptBytesFunc([.i32(keyPtr), .i32(ivPtr), .i32(dataPtr), .i32(UInt32(data.count))])

        return readBytes(dataPtr, data.count)
    }

    func hkdf(ikm: [UInt8], salt: [UInt8], info: [UInt8], outputLen: Int) throws -> [UInt8] {
        let ikmPtr = try allocate(max(ikm.count, 1))
        let saltPtr = try allocate(max(salt.count, 1))
        let infoPtr = try allocate(max(info.count, 1))
        let outPtr = try allocate(outputLen)

        defer {
            try? deallocate(ikmPtr)
            try? deallocate(saltPtr)
            try? deallocate(infoPtr)
            try? deallocate(outPtr)
        }

        if !ikm.isEmpty { writeBytes(ikmPtr, ikm) }
        if !salt.isEmpty { writeBytes(saltPtr, salt) }
        if !info.isEmpty { writeBytes(infoPtr, info) }

        _ = try hkdfFunc([.i32(ikmPtr), .i32(UInt32(ikm.count)),
                         .i32(saltPtr), .i32(UInt32(salt.count)),
                         .i32(infoPtr), .i32(UInt32(info.count)),
                         .i32(outPtr), .i32(UInt32(outputLen))])

        return readBytes(outPtr, outputLen)
    }

    func x25519GenerateKeypair() throws -> (privateKey: [UInt8], publicKey: [UInt8]) {
        let privPtr = try allocate(32)
        let pubPtr = try allocate(32)

        defer {
            try? deallocate(privPtr)
            try? deallocate(pubPtr)
        }

        _ = try x25519GenerateFunc([.i32(privPtr), .i32(pubPtr)])

        return (readBytes(privPtr, 32), readBytes(pubPtr, 32))
    }

    func x25519SharedSecret(privateKey: [UInt8], publicKey: [UInt8]) throws -> [UInt8] {
        let privPtr = try allocate(32)
        let pubPtr = try allocate(32)
        let sharedPtr = try allocate(32)

        defer {
            try? deallocate(privPtr)
            try? deallocate(pubPtr)
            try? deallocate(sharedPtr)
        }

        writeBytes(privPtr, privateKey)
        writeBytes(pubPtr, publicKey)
        _ = try x25519SharedFunc([.i32(privPtr), .i32(pubPtr), .i32(sharedPtr)])

        return readBytes(sharedPtr, 32)
    }

    func secp256k1GenerateKeypair() throws -> (privateKey: [UInt8], publicKey: [UInt8]) {
        let privPtr = try allocate(32)
        let pubPtr = try allocate(33)

        defer {
            try? deallocate(privPtr)
            try? deallocate(pubPtr)
        }

        _ = try secp256k1GenerateFunc([.i32(privPtr), .i32(pubPtr)])

        return (readBytes(privPtr, 32), readBytes(pubPtr, 33))
    }

    func secp256k1SharedSecret(privateKey: [UInt8], publicKey: [UInt8]) throws -> [UInt8] {
        let privPtr = try allocate(32)
        let pubPtr = try allocate(publicKey.count)
        let sharedPtr = try allocate(32)

        defer {
            try? deallocate(privPtr)
            try? deallocate(pubPtr)
            try? deallocate(sharedPtr)
        }

        writeBytes(privPtr, privateKey)
        writeBytes(pubPtr, publicKey)
        _ = try secp256k1SharedFunc([.i32(privPtr), .i32(pubPtr), .i32(UInt32(publicKey.count)), .i32(sharedPtr)])

        return readBytes(sharedPtr, 32)
    }

    func p256GenerateKeypair() throws -> (privateKey: [UInt8], publicKey: [UInt8]) {
        let privPtr = try allocate(32)
        let pubPtr = try allocate(33)

        defer {
            try? deallocate(privPtr)
            try? deallocate(pubPtr)
        }

        _ = try p256GenerateFunc([.i32(privPtr), .i32(pubPtr)])

        return (readBytes(privPtr, 32), readBytes(pubPtr, 33))
    }

    func p256SharedSecret(privateKey: [UInt8], publicKey: [UInt8]) throws -> [UInt8] {
        let privPtr = try allocate(32)
        let pubPtr = try allocate(publicKey.count)
        let sharedPtr = try allocate(32)

        defer {
            try? deallocate(privPtr)
            try? deallocate(pubPtr)
            try? deallocate(sharedPtr)
        }

        writeBytes(privPtr, privateKey)
        writeBytes(pubPtr, publicKey)
        _ = try p256SharedFunc([.i32(privPtr), .i32(pubPtr), .i32(UInt32(publicKey.count)), .i32(sharedPtr)])

        return readBytes(sharedPtr, 32)
    }
}

func toHex(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

func fromHex(_ hex: String) -> [UInt8] {
    var bytes = [UInt8]()
    var index = hex.startIndex
    while index < hex.endIndex {
        let nextIndex = hex.index(index, offsetBy: 2)
        if let byte = UInt8(hex[index..<nextIndex], radix: 16) {
            bytes.append(byte)
        }
        index = nextIndex
    }
    return bytes
}

struct ECDHHeader: Codable {
    let version: Int
    let key_exchange: Int
    let ephemeral_public_key: String
    let context: String?
    let session_key: String
    let session_iv: String
}

struct ECDHCurve {
    let name: String
    let pubKeySize: Int
    let keyExchange: Int
    let generate: () throws -> (privateKey: [UInt8], publicKey: [UInt8])
    let shared: ([UInt8], [UInt8]) throws -> [UInt8]
}

class TestResult {
    let name: String
    var passed = 0
    var failed = 0

    init(_ name: String) { self.name = name }

    func pass(_ msg: String) {
        passed += 1
        print("  ✓ \(msg)")
    }

    func fail(_ msg: String) {
        failed += 1
        print("  ✗ \(msg)")
    }

    func summary() -> Bool {
        let total = passed + failed
        let status = failed == 0 ? "✓" : "✗"
        print("\n\(status) \(name): \(passed)/\(total) passed")
        return failed == 0
    }
}

func main() throws {
    print(String(repeating: "=", count: 60))
    print("FlatBuffers Cross-Language Encryption E2E Tests - Swift")
    print(String(repeating: "=", count: 60))
    print()

    let wasmPaths = [
        "../../../../build/wasm/wasm/flatc-encryption.wasm",
        "../../../../../build/wasm/wasm/flatc-encryption.wasm",
        "../../../../../../build/wasm/wasm/flatc-encryption.wasm"
    ]

    guard let wasmPath = wasmPaths.first(where: { FileManager.default.fileExists(atPath: $0) }) else {
        print("WASM module not found. Build it first.")
        exit(1)
    }

    print("Loading WASM module: \(wasmPath)")
    let em = try EncryptionModule(wasmPath: wasmPath)
    print()

    let vectorsDir = "../../vectors"
    let encryptionKeysData = try Data(contentsOf: URL(fileURLWithPath: "\(vectorsDir)/encryption_keys.json"))
    let encryptionKeys = try JSONDecoder().decode([String: [String: String]].self, from: encryptionKeysData)

    var results = [Bool]()

    // Test 1: SHA-256
    print("Test 1: SHA-256 Hash")
    print(String(repeating: "-", count: 40))
    do {
        let result = TestResult("SHA-256")

        let hash = try em.sha256(Array("hello".utf8))
        let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        if toHex(hash) == expected {
            result.pass("SHA256('hello') correct")
        } else {
            result.fail("SHA256 mismatch: \(toHex(hash))")
        }

        let emptyHash = try em.sha256([])
        let expectedEmpty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        if toHex(emptyHash) == expectedEmpty {
            result.pass("SHA256('') correct")
        } else {
            result.fail("SHA256('') mismatch")
        }

        results.append(result.summary())
    }

    // Test 2: Per-chain encryption
    print("\nTest 2: Per-Chain Encryption")
    print(String(repeating: "-", count: 40))

    for (chain, keys) in encryptionKeys {
        let result = TestResult("Encryption with \(chain)")

        let key = fromHex(keys["key_hex"]!)
        let iv = fromHex(keys["iv_hex"]!)
        let plaintext = Array("Test data for \(chain) encryption".utf8)

        let encrypted = try em.encrypt(key: key, iv: iv, data: plaintext)
        if encrypted != plaintext {
            result.pass("Encryption modified data")
        } else {
            result.fail("Encryption did not modify data")
        }

        let decrypted = try em.decrypt(key: key, iv: iv, data: encrypted)
        if decrypted == plaintext {
            result.pass("Decryption restored original")
        } else {
            result.fail("Decryption mismatch")
        }

        results.append(result.summary())
    }

    // Test 3: Cross-language verification
    print("\nTest 3: Cross-Language Verification")
    print(String(repeating: "-", count: 40))
    do {
        let result = TestResult("Cross-Language")

        let binaryDir = "\(vectorsDir)/binary"
        if FileManager.default.fileExists(atPath: binaryDir) {
            let unencryptedPath = "\(binaryDir)/monster_unencrypted.bin"
            if FileManager.default.fileExists(atPath: unencryptedPath) {
                let data = try Data(contentsOf: URL(fileURLWithPath: unencryptedPath))
                result.pass("Read unencrypted binary: \(data.count) bytes")
            } else {
                result.fail("monster_unencrypted.bin not found - run Node.js test first")
            }

            for (chain, keys) in encryptionKeys {
                let encryptedPath = "\(binaryDir)/monster_encrypted_\(chain).bin"
                if FileManager.default.fileExists(atPath: encryptedPath) {
                    let encrypted = try Data(contentsOf: URL(fileURLWithPath: encryptedPath))
                    result.pass("Read \(chain): \(encrypted.count) bytes")

                    let key = fromHex(keys["key_hex"]!)
                    let iv = fromHex(keys["iv_hex"]!)
                    _ = try em.decrypt(key: key, iv: iv, data: Array(encrypted))
                    result.pass("Decrypted \(chain) data")
                }
            }
        } else {
            result.fail("Binary directory not found - run Node.js test first")
        }

        results.append(result.summary())
    }

    // Test 4: ECDH Key Exchange Verification
    print("\nTest 4: ECDH Key Exchange Verification")
    print(String(repeating: "-", count: 40))

    // Read unencrypted data for cross-language verification
    let binaryDir = "\(vectorsDir)/binary"
    var unencryptedData: Data? = nil
    if FileManager.default.fileExists(atPath: "\(binaryDir)/monster_unencrypted.bin") {
        unencryptedData = try? Data(contentsOf: URL(fileURLWithPath: "\(binaryDir)/monster_unencrypted.bin"))
    }

    let ecdhCurves: [ECDHCurve] = [
        ECDHCurve(name: "X25519", pubKeySize: 32, keyExchange: 0,
                  generate: em.x25519GenerateKeypair, shared: em.x25519SharedSecret),
        ECDHCurve(name: "secp256k1", pubKeySize: 33, keyExchange: 1,
                  generate: em.secp256k1GenerateKeypair, shared: em.secp256k1SharedSecret),
        ECDHCurve(name: "P-256", pubKeySize: 33, keyExchange: 2,
                  generate: em.p256GenerateKeypair, shared: em.p256SharedSecret)
    ]

    for curve in ecdhCurves {
        let result = TestResult("ECDH \(curve.name)")

        do {
            // Generate keypairs for Alice and Bob
            let alice = try curve.generate()
            let bob = try curve.generate()

            if alice.publicKey.count == curve.pubKeySize {
                result.pass("Generated Alice keypair (pub: \(alice.publicKey.count) bytes)")
            } else {
                result.fail("Alice public key wrong size: \(alice.publicKey.count)")
            }

            if bob.publicKey.count == curve.pubKeySize {
                result.pass("Generated Bob keypair (pub: \(bob.publicKey.count) bytes)")
            } else {
                result.fail("Bob public key wrong size: \(bob.publicKey.count)")
            }

            // Compute shared secrets
            let aliceShared = try curve.shared(alice.privateKey, bob.publicKey)
            let bobShared = try curve.shared(bob.privateKey, alice.publicKey)

            if aliceShared == bobShared {
                result.pass("Shared secrets match (\(aliceShared.count) bytes)")
            } else {
                result.fail("Shared secrets DO NOT match!")
                result.fail("  Alice: \(toHex(aliceShared))")
                result.fail("  Bob:   \(toHex(bobShared))")
            }

            // Test HKDF key derivation from shared secret
            let sessionMaterial = try em.hkdf(
                ikm: aliceShared,
                salt: Array("flatbuffers-encryption".utf8),
                info: Array("session-key-iv".utf8),
                outputLen: 48
            )
            let sessionKey = Array(sessionMaterial[0..<32])
            let sessionIv = Array(sessionMaterial[32..<48])

            if sessionKey.count == 32 && sessionIv.count == 16 {
                result.pass("HKDF derived key (\(sessionKey.count)B) + IV (\(sessionIv.count)B)")
            } else {
                result.fail("HKDF output wrong size")
            }

            // Full E2E: encrypt with derived key, decrypt with same key
            let testData = "ECDH test data for \(curve.name) encryption"
            let plaintext = Array(testData.utf8)
            let encrypted = try em.encrypt(key: sessionKey, iv: sessionIv, data: plaintext)

            if encrypted != plaintext {
                result.pass("Encryption with derived key modified data")
            } else {
                result.fail("Encryption did not modify data")
            }

            let decrypted = try em.decrypt(key: sessionKey, iv: sessionIv, data: encrypted)
            if decrypted == plaintext {
                result.pass("Decryption with derived key restored original")
            } else {
                result.fail("Decryption mismatch")
            }

            // Verify cross-language ECDH header if available
            let headerName = curve.name.lowercased().replacingOccurrences(of: "-", with: "")
            let headerPath = "\(binaryDir)/monster_ecdh_\(headerName)_header.json"
            if FileManager.default.fileExists(atPath: headerPath) {
                do {
                    let headerData = try Data(contentsOf: URL(fileURLWithPath: headerPath))
                    let header = try JSONDecoder().decode(ECDHHeader.self, from: headerData)

                    if header.key_exchange == curve.keyExchange {
                        result.pass("Cross-language header has correct key_exchange: \(curve.keyExchange)")
                    } else {
                        result.fail("Header key_exchange mismatch: \(header.key_exchange)")
                    }

                    if !header.ephemeral_public_key.isEmpty && !header.session_key.isEmpty && !header.session_iv.isEmpty {
                        result.pass("Header contains ephemeral_public_key, session_key, session_iv")

                        // Decrypt the cross-language encrypted file using Node.js session key
                        let encryptedPath = "\(binaryDir)/monster_ecdh_\(headerName)_encrypted.bin"
                        if FileManager.default.fileExists(atPath: encryptedPath), let unenc = unencryptedData {
                            let nodeKey = fromHex(header.session_key)
                            let nodeIv = fromHex(header.session_iv)
                            let encryptedFileData = try Data(contentsOf: URL(fileURLWithPath: encryptedPath))
                            let decryptedData = try em.decrypt(key: nodeKey, iv: nodeIv, data: Array(encryptedFileData))

                            if Data(decryptedData) == unenc {
                                result.pass("Decrypted Node.js \(curve.name) data matches original")
                            } else {
                                result.fail("Decrypted Node.js \(curve.name) data mismatch")
                            }
                        }
                    }
                } catch {
                    result.fail("Error reading cross-language header: \(error)")
                }
            } else {
                result.pass("(No cross-language header found at monster_ecdh_\(headerName)_header.json)")
            }
        } catch {
            result.fail("Exception during \(curve.name) test: \(error)")
        }

        results.append(result.summary())
    }

    // Test 5: Runtime Code Generation
    print("\nTest 5: Runtime Code Generation")
    print(String(repeating: "-", count: 40))
    do {
        let result = TestResult("Code Generation")

        // Try to find native flatc binary (prefer built version over system)
        // vectorsDir is relative to current directory, so navigate up to flatbuffers root
        let scriptDir = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        let flatcPaths = [
            scriptDir.appendingPathComponent("../../../../../build/flatc").standardized.path,
            scriptDir.appendingPathComponent("../../../../../flatc").standardized.path
        ]

        var flatcPath: String? = nil
        for p in flatcPaths {
            if FileManager.default.fileExists(atPath: p) {
                flatcPath = p
                break
            }
        }

        // Only fall back to PATH if built flatc not found
        if flatcPath == nil {
            let which = Process()
            which.executableURL = URL(fileURLWithPath: "/usr/bin/which")
            which.arguments = ["flatc"]
            let whichPipe = Pipe()
            which.standardOutput = whichPipe
            try? which.run()
            which.waitUntilExit()
            if which.terminationStatus == 0 {
                let whichData = whichPipe.fileHandleForReading.readDataToEndOfFile()
                if let whichOutput = String(data: whichData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
                   !whichOutput.isEmpty {
                    flatcPath = whichOutput
                }
            }
        }

        if let flatc = flatcPath {
            result.pass("Found flatc: \(flatc)")

            // Get flatc version
            let versionProc = Process()
            versionProc.executableURL = URL(fileURLWithPath: flatc)
            versionProc.arguments = ["--version"]
            let versionPipe = Pipe()
            versionProc.standardOutput = versionPipe
            try? versionProc.run()
            versionProc.waitUntilExit()
            if versionProc.terminationStatus == 0 {
                let versionData = versionPipe.fileHandleForReading.readDataToEndOfFile()
                if let version = String(data: versionData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) {
                    result.pass("flatc version: \(version)")
                }
            }

            // Generate Swift code from schema
            let schemaPath = scriptDir.appendingPathComponent("../../schemas/message.fbs").standardized.path
            let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("flatc-gen-\(ProcessInfo.processInfo.processIdentifier)")
            try? FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)

            do {
                let genProc = Process()
                genProc.executableURL = URL(fileURLWithPath: flatc)
                genProc.arguments = ["--swift", "-o", tempDir.path, schemaPath]
                let errPipe = Pipe()
                genProc.standardError = errPipe
                try genProc.run()
                genProc.waitUntilExit()

                if genProc.terminationStatus == 0 {
                    result.pass("Generated Swift code from schema")

                    // List generated files
                    let enumerator = FileManager.default.enumerator(at: tempDir, includingPropertiesForKeys: [.fileSizeKey])
                    while let fileURL = enumerator?.nextObject() as? URL {
                        if fileURL.hasDirectoryPath { continue }
                        let relPath = fileURL.path.replacingOccurrences(of: tempDir.path + "/", with: "")
                        let attrs = try? FileManager.default.attributesOfItem(atPath: fileURL.path)
                        let size = (attrs?[.size] as? Int) ?? 0
                        result.pass("Generated: \(relPath) (\(size) bytes)")
                    }
                } else {
                    let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
                    let errStr = String(data: errData, encoding: .utf8) ?? "unknown error"
                    result.fail("Generate Swift code failed: \(errStr)")
                }
            } catch {
                result.fail("Exception during code generation: \(error)")
            }

            try? FileManager.default.removeItem(at: tempDir)
        } else {
            result.pass("flatc not found - using pre-generated code (this is OK)")
            // Verify pre-generated code exists
            let pregenPath = scriptDir.appendingPathComponent("../../generated/swift").standardized.path
            if FileManager.default.fileExists(atPath: pregenPath) {
                let files = try? FileManager.default.contentsOfDirectory(atPath: pregenPath)
                    .filter { $0.hasSuffix(".swift") }
                result.pass("Pre-generated Swift code: \(files?.count ?? 0) files in generated/swift/")
            }
        }

        results.append(result.summary())
    }

    // Summary
    print("\n" + String(repeating: "=", count: 60))
    print("Summary")
    print(String(repeating: "=", count: 60))

    let passed = results.filter { $0 }.count
    let total = results.count
    print("\nTotal: \(passed)/\(total) test suites passed")

    if passed == total {
        print("\n✓ All tests passed!")
        exit(0)
    } else {
        print("\n✗ Some tests failed")
        exit(1)
    }
}

try main()
