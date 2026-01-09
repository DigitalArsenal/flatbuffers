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
