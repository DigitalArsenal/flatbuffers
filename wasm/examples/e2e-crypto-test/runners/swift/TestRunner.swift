/**
 * Swift E2E Test Runner for FlatBuffers Cross-Language Encryption
 *
 * Tests encryption/decryption using the WASM Crypto++ module with all 10 crypto key types.
 * Uses Wasmtime C API for full WebAssembly support including indirect function calls.
 */
import Foundation
import CWasmtime

let AES_KEY_SIZE: Int = 32
let AES_IV_SIZE: Int = 16
let SHA256_SIZE: Int = 32

// MARK: - Wasmtime Wrapper

class WasmtimeEngine {
    private var engine: OpaquePointer!
    private var store: OpaquePointer!
    private var linker: OpaquePointer!
    private var context: OpaquePointer!
    private var instance: wasmtime_instance_t = wasmtime_instance_t()
    private var memory: wasmtime_memory_t = wasmtime_memory_t()
    private var hasMemory = false
    private var table: wasmtime_table_t = wasmtime_table_t()
    private var hasTable = false

    // Exported functions stored as wasmtime_func_t structs
    private var mallocFunc: wasmtime_func_t = wasmtime_func_t()
    private var freeFunc: wasmtime_func_t = wasmtime_func_t()
    private var sha256Func: wasmtime_func_t = wasmtime_func_t()
    private var encryptBytesFunc: wasmtime_func_t = wasmtime_func_t()
    private var decryptBytesFunc: wasmtime_func_t = wasmtime_func_t()
    private var hkdfFunc: wasmtime_func_t = wasmtime_func_t()
    private var x25519GenerateFunc: wasmtime_func_t = wasmtime_func_t()
    private var x25519SharedFunc: wasmtime_func_t = wasmtime_func_t()
    private var secp256k1GenerateFunc: wasmtime_func_t = wasmtime_func_t()
    private var secp256k1SharedFunc: wasmtime_func_t = wasmtime_func_t()
    private var p256GenerateFunc: wasmtime_func_t = wasmtime_func_t()
    private var p256SharedFunc: wasmtime_func_t = wasmtime_func_t()
    private var ed25519GenerateFunc: wasmtime_func_t = wasmtime_func_t()
    private var ed25519SignFunc: wasmtime_func_t = wasmtime_func_t()
    private var ed25519VerifyFunc: wasmtime_func_t = wasmtime_func_t()
    private var secp256k1SignFunc: wasmtime_func_t = wasmtime_func_t()
    private var secp256k1VerifyFunc: wasmtime_func_t = wasmtime_func_t()
    private var p256SignFunc: wasmtime_func_t = wasmtime_func_t()
    private var p256VerifyFunc: wasmtime_func_t = wasmtime_func_t()

    // Track threw state for exception handling
    private var threwValue: Int32 = 0

    init(wasmPath: String) throws {
        // Create engine
        engine = wasm_engine_new()
        guard engine != nil else {
            throw WasmError.engineCreationFailed
        }

        // Create store
        store = wasmtime_store_new(engine, nil, nil)
        guard store != nil else {
            throw WasmError.storeCreationFailed
        }
        context = wasmtime_store_context(store)

        // Create linker
        linker = wasmtime_linker_new(engine)
        guard linker != nil else {
            throw WasmError.linkerCreationFailed
        }

        // Add WASI
        let wasiConfig = wasi_config_new()
        wasi_config_inherit_env(wasiConfig)
        wasi_config_inherit_stdin(wasiConfig)
        wasi_config_inherit_stdout(wasiConfig)
        wasi_config_inherit_stderr(wasiConfig)

        var trap: OpaquePointer? = nil
        var error = wasmtime_context_set_wasi(context, wasiConfig)
        if error != nil {
            wasmtime_error_delete(error)
            throw WasmError.wasiSetupFailed
        }

        error = wasmtime_linker_define_wasi(linker)
        if error != nil {
            wasmtime_error_delete(error)
            throw WasmError.wasiSetupFailed
        }

        // Define Emscripten stubs
        try defineEmscriptenStubs()

        // Load module
        let wasmData = try Data(contentsOf: URL(fileURLWithPath: wasmPath))
        var module: OpaquePointer? = nil
        error = wasmData.withUnsafeBytes { bytes in
            wasmtime_module_new(engine, bytes.baseAddress?.assumingMemoryBound(to: UInt8.self), bytes.count, &module)
        }
        if error != nil {
            wasmtime_error_delete(error)
            throw WasmError.moduleLoadFailed
        }

        // Instantiate
        error = wasmtime_linker_instantiate(linker, context, module, &instance, &trap)
        wasmtime_module_delete(module)
        if error != nil {
            wasmtime_error_delete(error)
            throw WasmError.instantiationFailed
        }
        if trap != nil {
            wasm_trap_delete(trap)
            throw WasmError.instantiationFailed
        }

        // Get exports
        try getExports()

        // Call _initialize if present
        var initExport = wasmtime_extern_t()
        var initName = "_initialize"
        if wasmtime_instance_export_get(context, &instance, initName, initName.count, &initExport) {
            if initExport.kind == UInt8(WASMTIME_EXTERN_FUNC) {
                var results: [wasmtime_val_t] = []
                error = wasmtime_func_call(context, &initExport.of.func, nil, 0, &results, 0, &trap)
                // Ignore errors from _initialize
            }
        }
    }

    deinit {
        if linker != nil { wasmtime_linker_delete(linker) }
        if store != nil { wasmtime_store_delete(store) }
        if engine != nil { wasm_engine_delete(engine) }
    }

    private func defineEmscriptenStubs() throws {
        // Exception handling stubs
        try defineHostFunc(module: "env", name: "setThrew", params: [WASM_I32, WASM_I32], results: []) { context, args, results in
            return nil
        }

        try defineHostFunc(module: "env", name: "__cxa_find_matching_catch_2", params: [], results: [WASM_I32]) { context, args, results in
            results![0].kind = UInt8(WASMTIME_I32)
            results![0].of.i32 = 0
            return nil
        }

        try defineHostFunc(module: "env", name: "__cxa_find_matching_catch_3", params: [WASM_I32], results: [WASM_I32]) { context, args, results in
            results![0].kind = UInt8(WASMTIME_I32)
            results![0].of.i32 = 0
            return nil
        }

        try defineHostFunc(module: "env", name: "__resumeException", params: [WASM_I32], results: []) { context, args, results in
            return nil
        }

        try defineHostFunc(module: "env", name: "__cxa_begin_catch", params: [WASM_I32], results: [WASM_I32]) { context, args, results in
            results![0].kind = UInt8(WASMTIME_I32)
            results![0].of.i32 = 0
            return nil
        }

        try defineHostFunc(module: "env", name: "__cxa_end_catch", params: [], results: []) { context, args, results in
            return nil
        }

        try defineHostFunc(module: "env", name: "llvm_eh_typeid_for", params: [WASM_I32], results: [WASM_I32]) { context, args, results in
            results![0].kind = UInt8(WASMTIME_I32)
            results![0].of.i32 = 0
            return nil
        }

        try defineHostFunc(module: "env", name: "__cxa_throw", params: [WASM_I32, WASM_I32, WASM_I32], results: []) { context, args, results in
            return nil
        }

        try defineHostFunc(module: "env", name: "__cxa_uncaught_exceptions", params: [], results: [WASM_I32]) { context, args, results in
            results![0].kind = UInt8(WASMTIME_I32)
            results![0].of.i32 = 0
            return nil
        }

        // invoke_* trampolines - these call functions from the indirect function table
        // Void variants
        let voidInvokes = [
            ("invoke_v", 1), ("invoke_vi", 2), ("invoke_vii", 3),
            ("invoke_viii", 4), ("invoke_viiii", 5), ("invoke_viiiii", 6),
            ("invoke_viiiiii", 7), ("invoke_viiiiiii", 8), ("invoke_viiiiiiiii", 10)
        ]
        for (name, paramCount) in voidInvokes {
            try defineInvokeVoid(name: name, paramCount: paramCount)
        }

        // i32 return variants
        let i32Invokes = [
            ("invoke_i", 1), ("invoke_ii", 2), ("invoke_iii", 3),
            ("invoke_iiii", 4), ("invoke_iiiii", 5), ("invoke_iiiiii", 6),
            ("invoke_iiiiiii", 7), ("invoke_iiiiiiii", 8), ("invoke_iiiiiiiiii", 10)
        ]
        for (name, paramCount) in i32Invokes {
            try defineInvokeI32(name: name, paramCount: paramCount)
        }
    }

    private func defineHostFunc(module: String, name: String, params: [wasm_valkind_enum], results: [wasm_valkind_enum],
                                callback: @escaping (OpaquePointer?, UnsafePointer<wasmtime_val_t>?, UnsafeMutablePointer<wasmtime_val_t>?) -> OpaquePointer?) throws {
        // Create valtype arrays
        var paramVec = wasm_valtype_vec_t()
        var resultVec = wasm_valtype_vec_t()

        if params.isEmpty {
            wasm_valtype_vec_new_empty(&paramVec)
        } else {
            var paramTypes = params.map { wasm_valtype_new(wasm_valkind_t($0.rawValue)) }
            wasm_valtype_vec_new(&paramVec, paramTypes.count, &paramTypes)
        }

        if results.isEmpty {
            wasm_valtype_vec_new_empty(&resultVec)
        } else {
            var resultTypes = results.map { wasm_valtype_new(wasm_valkind_t($0.rawValue)) }
            wasm_valtype_vec_new(&resultVec, resultTypes.count, &resultTypes)
        }

        let funcType = wasm_functype_new(&paramVec, &resultVec)

        // Store callback in a box that we can pass through the C API
        let callbackBox = CallbackBox(callback: callback)
        let callbackPtr = Unmanaged.passRetained(callbackBox).toOpaque()

        var funcVal = wasmtime_func_t()
        wasmtime_func_new(context, funcType, { env, caller, args, nargs, results, nresults in
            guard let env = env else { return nil }
            let box = Unmanaged<CallbackBox>.fromOpaque(env).takeUnretainedValue()
            return box.callback(caller, args, results)
        }, callbackPtr, nil, &funcVal)

        wasm_functype_delete(funcType)

        // Define in linker
        var externVal = wasmtime_extern_t()
        externVal.kind = UInt8(WASMTIME_EXTERN_FUNC)
        externVal.of.func = funcVal

        let error = wasmtime_linker_define(linker, context, module, module.count, name, name.count, &externVal)
        if error != nil {
            wasmtime_error_delete(error)
            throw WasmError.linkingFailed(name)
        }
    }

    private func defineInvokeVoid(name: String, paramCount: Int) throws {
        let params = Array(repeating: WASM_I32, count: paramCount)
        try defineHostFunc(module: "env", name: name, params: params, results: []) { [weak self] context, args, results in
            guard let self = self, let args = args else { return nil }
            let tableIdx = args[0].of.i32

            // Get function from table and call it
            self.callTableFunction(tableIdx: tableIdx, args: args, argCount: paramCount - 1, wantsResult: false, results: nil)
            return nil
        }
    }

    private func defineInvokeI32(name: String, paramCount: Int) throws {
        let params = Array(repeating: WASM_I32, count: paramCount)
        try defineHostFunc(module: "env", name: name, params: params, results: [WASM_I32]) { [weak self] context, args, results in
            guard let self = self, let args = args, let results = results else { return nil }
            let tableIdx = args[0].of.i32

            // Get function from table and call it
            let result = self.callTableFunction(tableIdx: tableIdx, args: args, argCount: paramCount - 1, wantsResult: true, results: results)
            if result == nil {
                results[0].kind = UInt8(WASMTIME_I32)
                results[0].of.i32 = 0
            }
            return nil
        }
    }

    private func callTableFunction(tableIdx: Int32, args: UnsafePointer<wasmtime_val_t>, argCount: Int, wantsResult: Bool, results: UnsafeMutablePointer<wasmtime_val_t>?) -> Bool? {
        guard hasTable else { return nil }

        // Get function from table
        var funcRef = wasmtime_val_t()
        var tableCopy = table
        if !wasmtime_table_get(context, &tableCopy, UInt64(tableIdx), &funcRef) {
            return nil
        }

        guard funcRef.kind == UInt8(WASMTIME_FUNCREF) else { return nil }

        // Check if funcref is null
        if wasmtime_funcref_is_null(&funcRef.of.funcref) {
            return nil
        }

        // Build arguments (skip first arg which is table index)
        var funcArgs = [wasmtime_val_t]()
        if argCount > 0 {
            for i in 1...argCount {
                funcArgs.append(args[i])
            }
        }

        // Call the function
        var trap: OpaquePointer? = nil
        var funcResults = [wasmtime_val_t](repeating: wasmtime_val_t(), count: wantsResult ? 1 : 0)

        let error = funcArgs.withUnsafeMutableBufferPointer { argsPtr in
            funcResults.withUnsafeMutableBufferPointer { resultsPtr in
                wasmtime_func_call(context, &funcRef.of.funcref, argsPtr.baseAddress, argsPtr.count, resultsPtr.baseAddress, resultsPtr.count, &trap)
            }
        }

        if trap != nil {
            wasm_trap_delete(trap)
            threwValue = 1
            return nil
        }

        if error != nil {
            wasmtime_error_delete(error)
            threwValue = 1
            return nil
        }

        if wantsResult && !funcResults.isEmpty, let results = results {
            results[0] = funcResults[0]
            return true
        }

        return true
    }

    private func getExports() throws {
        // Get memory
        var memExport = wasmtime_extern_t()
        if wasmtime_instance_export_get(context, &instance, "memory", 6, &memExport) && memExport.kind == UInt8(WASMTIME_EXTERN_MEMORY) {
            memory = memExport.of.memory
            hasMemory = true
        }

        // Get indirect function table
        var tableExport = wasmtime_extern_t()
        if wasmtime_instance_export_get(context, &instance, "__indirect_function_table", 25, &tableExport) && tableExport.kind == UInt8(WASMTIME_EXTERN_TABLE) {
            table = tableExport.of.table
            hasTable = true
        }

        // Get functions
        mallocFunc = try getExportedFunc(name: "malloc")
        freeFunc = try getExportedFunc(name: "free")
        sha256Func = try getExportedFunc(name: "wasi_sha256")
        encryptBytesFunc = try getExportedFunc(name: "wasi_encrypt_bytes")
        decryptBytesFunc = try getExportedFunc(name: "wasi_decrypt_bytes")
        hkdfFunc = try getExportedFunc(name: "wasi_hkdf")
        x25519GenerateFunc = try getExportedFunc(name: "wasi_x25519_generate_keypair")
        x25519SharedFunc = try getExportedFunc(name: "wasi_x25519_shared_secret")
        secp256k1GenerateFunc = try getExportedFunc(name: "wasi_secp256k1_generate_keypair")
        secp256k1SharedFunc = try getExportedFunc(name: "wasi_secp256k1_shared_secret")
        p256GenerateFunc = try getExportedFunc(name: "wasi_p256_generate_keypair")
        p256SharedFunc = try getExportedFunc(name: "wasi_p256_shared_secret")
        ed25519GenerateFunc = try getExportedFunc(name: "wasi_ed25519_generate_keypair")
        ed25519SignFunc = try getExportedFunc(name: "wasi_ed25519_sign")
        ed25519VerifyFunc = try getExportedFunc(name: "wasi_ed25519_verify")
        secp256k1SignFunc = try getExportedFunc(name: "wasi_secp256k1_sign")
        secp256k1VerifyFunc = try getExportedFunc(name: "wasi_secp256k1_verify")
        p256SignFunc = try getExportedFunc(name: "wasi_p256_sign")
        p256VerifyFunc = try getExportedFunc(name: "wasi_p256_verify")
    }

    private func getExportedFunc(name: String) throws -> wasmtime_func_t {
        var externVal = wasmtime_extern_t()
        guard wasmtime_instance_export_get(context, &instance, name, name.count, &externVal),
              externVal.kind == UInt8(WASMTIME_EXTERN_FUNC) else {
            throw WasmError.exportNotFound(name)
        }
        return externVal.of.func
    }

    // Memory operations
    func allocate(_ size: Int) throws -> UInt32 {
        // Return a sentinel value for 0-size allocations
        guard size > 0 else {
            return 0
        }

        var args = [wasmtime_val_t()]
        args[0].kind = UInt8(WASMTIME_I32)
        args[0].of.i32 = Int32(size)

        var results = [wasmtime_val_t()]
        var trap: OpaquePointer? = nil

        var funcCopy = mallocFunc
        let error = wasmtime_func_call(context, &funcCopy, &args, 1, &results, 1, &trap)
        if error != nil || trap != nil {
            if error != nil { wasmtime_error_delete(error) }
            if trap != nil { wasm_trap_delete(trap) }
            throw WasmError.allocationFailed
        }

        return UInt32(bitPattern: results[0].of.i32)
    }

    func deallocate(_ ptr: UInt32) {
        // Don't free sentinel value (0-size allocation)
        guard ptr != 0 else { return }

        var args = [wasmtime_val_t()]
        args[0].kind = UInt8(WASMTIME_I32)
        args[0].of.i32 = Int32(bitPattern: ptr)

        var trap: OpaquePointer? = nil
        var funcCopy = freeFunc
        _ = wasmtime_func_call(context, &funcCopy, &args, 1, nil, 0, &trap)
        if trap != nil { wasm_trap_delete(trap) }
    }

    func writeBytes(_ ptr: UInt32, _ bytes: [UInt8]) {
        guard hasMemory else { return }
        var memCopy = memory
        let dataPtr = wasmtime_memory_data(context, &memCopy)
        guard let data = dataPtr else { return }

        for (i, byte) in bytes.enumerated() {
            data.advanced(by: Int(ptr) + i).pointee = byte
        }
    }

    func readBytes(_ ptr: UInt32, _ length: Int) -> [UInt8] {
        guard hasMemory else { return [] }
        var memCopy = memory
        let dataPtr = wasmtime_memory_data(context, &memCopy)
        guard let data = dataPtr else { return [] }

        var result = [UInt8](repeating: 0, count: length)
        for i in 0..<length {
            result[i] = data.advanced(by: Int(ptr) + i).pointee
        }
        return result
    }

    // Crypto functions
    // wasi_sha256(data, data_size, hash) - void, writes 32 bytes to hash
    func sha256(_ data: [UInt8]) throws -> [UInt8] {
        let inputLen = max(data.count, 1)
        let inputPtr = try allocate(inputLen)
        let outputPtr = try allocate(SHA256_SIZE)
        defer {
            deallocate(inputPtr)
            deallocate(outputPtr)
        }

        if !data.isEmpty {
            writeBytes(inputPtr, data)
        }

        var args = [wasmtime_val_t](repeating: wasmtime_val_t(), count: 3)
        args[0].kind = UInt8(WASMTIME_I32); args[0].of.i32 = Int32(bitPattern: inputPtr)
        args[1].kind = UInt8(WASMTIME_I32); args[1].of.i32 = Int32(data.count)
        args[2].kind = UInt8(WASMTIME_I32); args[2].of.i32 = Int32(bitPattern: outputPtr)

        var trap: OpaquePointer? = nil
        var funcCopy = sha256Func
        let error = wasmtime_func_call(context, &funcCopy, &args, 3, nil, 0, &trap)
        if error != nil { wasmtime_error_delete(error) }
        if trap != nil { wasm_trap_delete(trap); throw WasmError.functionCallFailed("sha256") }

        return readBytes(outputPtr, SHA256_SIZE)
    }

    // wasi_encrypt_bytes(key, iv, data, size) -> int32 (0=success), encrypts in-place
    func encrypt(key: [UInt8], iv: [UInt8], plaintext: [UInt8]) throws -> [UInt8] {
        let keyPtr = try allocate(32)
        let ivPtr = try allocate(16)
        let dataPtr = try allocate(plaintext.count)
        defer {
            deallocate(keyPtr)
            deallocate(ivPtr)
            deallocate(dataPtr)
        }

        writeBytes(keyPtr, key)
        writeBytes(ivPtr, iv)
        writeBytes(dataPtr, plaintext)

        var args = [wasmtime_val_t](repeating: wasmtime_val_t(), count: 4)
        args[0].kind = UInt8(WASMTIME_I32); args[0].of.i32 = Int32(bitPattern: keyPtr)
        args[1].kind = UInt8(WASMTIME_I32); args[1].of.i32 = Int32(bitPattern: ivPtr)
        args[2].kind = UInt8(WASMTIME_I32); args[2].of.i32 = Int32(bitPattern: dataPtr)
        args[3].kind = UInt8(WASMTIME_I32); args[3].of.i32 = Int32(plaintext.count)

        var results = [wasmtime_val_t()]
        var trap: OpaquePointer? = nil
        var funcCopy = encryptBytesFunc
        let error = wasmtime_func_call(context, &funcCopy, &args, 4, &results, 1, &trap)
        if error != nil { wasmtime_error_delete(error) }
        if trap != nil { wasm_trap_delete(trap); throw WasmError.functionCallFailed("encrypt") }

        let retval = results[0].of.i32
        if retval != 0 { throw WasmError.functionCallFailed("encrypt returned \(retval)") }
        return readBytes(dataPtr, plaintext.count)
    }

    // wasi_decrypt_bytes is the same as encrypt (CTR mode is symmetric)
    func decrypt(key: [UInt8], iv: [UInt8], ciphertext: [UInt8]) throws -> [UInt8] {
        return try encrypt(key: key, iv: iv, plaintext: ciphertext)
    }

    func hkdf(ikm: [UInt8], salt: [UInt8], info: [UInt8], outputLen: Int) throws -> [UInt8] {
        let ikmPtr = try allocate(ikm.count)
        let saltPtr = try allocate(salt.count)
        let infoPtr = try allocate(info.count)
        let outputPtr = try allocate(outputLen)
        defer {
            deallocate(ikmPtr)
            deallocate(saltPtr)
            deallocate(infoPtr)
            deallocate(outputPtr)
        }

        writeBytes(ikmPtr, ikm)
        writeBytes(saltPtr, salt)
        writeBytes(infoPtr, info)

        var args = [wasmtime_val_t](repeating: wasmtime_val_t(), count: 8)
        args[0].kind = UInt8(WASMTIME_I32); args[0].of.i32 = Int32(bitPattern: ikmPtr)
        args[1].kind = UInt8(WASMTIME_I32); args[1].of.i32 = Int32(ikm.count)
        args[2].kind = UInt8(WASMTIME_I32); args[2].of.i32 = Int32(bitPattern: saltPtr)
        args[3].kind = UInt8(WASMTIME_I32); args[3].of.i32 = Int32(salt.count)
        args[4].kind = UInt8(WASMTIME_I32); args[4].of.i32 = Int32(bitPattern: infoPtr)
        args[5].kind = UInt8(WASMTIME_I32); args[5].of.i32 = Int32(info.count)
        args[6].kind = UInt8(WASMTIME_I32); args[6].of.i32 = Int32(bitPattern: outputPtr)
        args[7].kind = UInt8(WASMTIME_I32); args[7].of.i32 = Int32(outputLen)

        var trap: OpaquePointer? = nil
        var funcCopy = hkdfFunc
        // HKDF returns void (nil, 0)
        let error = wasmtime_func_call(context, &funcCopy, &args, 8, nil, 0, &trap)
        if error != nil { wasmtime_error_delete(error) }
        if trap != nil { wasm_trap_delete(trap); throw WasmError.functionCallFailed("hkdf") }

        return readBytes(outputPtr, outputLen)
    }

    // ECDH key generation and shared secrets
    func x25519GenerateKeypair() throws -> (privateKey: [UInt8], publicKey: [UInt8]) {
        let privPtr = try allocate(32)
        let pubPtr = try allocate(32)
        defer {
            deallocate(privPtr)
            deallocate(pubPtr)
        }

        // wasi_x25519_generate_keypair(private_key, public_key) -> int32 (only 2 args)
        var args = [wasmtime_val_t](repeating: wasmtime_val_t(), count: 2)
        args[0].kind = UInt8(WASMTIME_I32); args[0].of.i32 = Int32(bitPattern: privPtr)
        args[1].kind = UInt8(WASMTIME_I32); args[1].of.i32 = Int32(bitPattern: pubPtr)

        var results = [wasmtime_val_t()]
        var trap: OpaquePointer? = nil
        var funcCopy = x25519GenerateFunc
        let error = wasmtime_func_call(context, &funcCopy, &args, 2, &results, 1, &trap)
        if error != nil { wasmtime_error_delete(error) }
        if trap != nil { wasm_trap_delete(trap); throw WasmError.functionCallFailed("x25519_generate") }

        return (readBytes(privPtr, 32), readBytes(pubPtr, 32))
    }

    // wasi_x25519_shared_secret(private_key, public_key, shared_secret) -> int32
    func x25519SharedSecret(privateKey: [UInt8], publicKey: [UInt8]) throws -> [UInt8] {
        let privPtr = try allocate(32)
        let pubPtr = try allocate(32)
        let sharedPtr = try allocate(32)
        defer {
            deallocate(privPtr)
            deallocate(pubPtr)
            deallocate(sharedPtr)
        }

        writeBytes(privPtr, privateKey)
        writeBytes(pubPtr, publicKey)

        var args = [wasmtime_val_t](repeating: wasmtime_val_t(), count: 3)
        args[0].kind = UInt8(WASMTIME_I32); args[0].of.i32 = Int32(bitPattern: privPtr)
        args[1].kind = UInt8(WASMTIME_I32); args[1].of.i32 = Int32(bitPattern: pubPtr)
        args[2].kind = UInt8(WASMTIME_I32); args[2].of.i32 = Int32(bitPattern: sharedPtr)

        var results = [wasmtime_val_t()]
        var trap: OpaquePointer? = nil
        var funcCopy = x25519SharedFunc
        let error = wasmtime_func_call(context, &funcCopy, &args, 3, &results, 1, &trap)
        if error != nil { wasmtime_error_delete(error) }
        if trap != nil { wasm_trap_delete(trap); throw WasmError.functionCallFailed("x25519_shared") }

        return readBytes(sharedPtr, 32)
    }

    // wasi_secp256k1_generate_keypair(private_key, public_key) -> int32
    func secp256k1GenerateKeypair() throws -> (privateKey: [UInt8], publicKey: [UInt8]) {
        let privPtr = try allocate(32)
        let pubPtr = try allocate(33)  // Compressed public key is 33 bytes
        defer {
            deallocate(privPtr)
            deallocate(pubPtr)
        }

        var args = [wasmtime_val_t](repeating: wasmtime_val_t(), count: 2)
        args[0].kind = UInt8(WASMTIME_I32); args[0].of.i32 = Int32(bitPattern: privPtr)
        args[1].kind = UInt8(WASMTIME_I32); args[1].of.i32 = Int32(bitPattern: pubPtr)

        var results = [wasmtime_val_t()]
        var trap: OpaquePointer? = nil
        var funcCopy = secp256k1GenerateFunc
        let error = wasmtime_func_call(context, &funcCopy, &args, 2, &results, 1, &trap)
        if error != nil { wasmtime_error_delete(error) }
        if trap != nil { wasm_trap_delete(trap); throw WasmError.functionCallFailed("secp256k1_generate") }

        return (readBytes(privPtr, 32), readBytes(pubPtr, 33))  // 33-byte compressed public key
    }

    // wasi_secp256k1_shared_secret(private_key, public_key, public_key_size, shared_secret) -> int32
    func secp256k1SharedSecret(privateKey: [UInt8], publicKey: [UInt8]) throws -> [UInt8] {
        let privPtr = try allocate(32)
        let pubPtr = try allocate(publicKey.count)
        let sharedPtr = try allocate(32)
        defer {
            deallocate(privPtr)
            deallocate(pubPtr)
            deallocate(sharedPtr)
        }

        writeBytes(privPtr, privateKey)
        writeBytes(pubPtr, publicKey)

        var args = [wasmtime_val_t](repeating: wasmtime_val_t(), count: 4)
        args[0].kind = UInt8(WASMTIME_I32); args[0].of.i32 = Int32(bitPattern: privPtr)
        args[1].kind = UInt8(WASMTIME_I32); args[1].of.i32 = Int32(bitPattern: pubPtr)
        args[2].kind = UInt8(WASMTIME_I32); args[2].of.i32 = Int32(publicKey.count)
        args[3].kind = UInt8(WASMTIME_I32); args[3].of.i32 = Int32(bitPattern: sharedPtr)

        var results = [wasmtime_val_t()]
        var trap: OpaquePointer? = nil
        var funcCopy = secp256k1SharedFunc
        let error = wasmtime_func_call(context, &funcCopy, &args, 4, &results, 1, &trap)

        let retval = results[0].of.i32
        if error != nil { wasmtime_error_delete(error) }
        if trap != nil { wasm_trap_delete(trap); throw WasmError.functionCallFailed("secp256k1_shared") }
        if retval != 0 { throw WasmError.functionCallFailed("secp256k1_shared returned \(retval)") }

        return readBytes(sharedPtr, 32)
    }

    // wasi_p256_generate_keypair(private_key, public_key) -> int32
    func p256GenerateKeypair() throws -> (privateKey: [UInt8], publicKey: [UInt8]) {
        let privPtr = try allocate(32)
        let pubPtr = try allocate(33)  // Compressed public key is 33 bytes
        defer {
            deallocate(privPtr)
            deallocate(pubPtr)
        }

        var args = [wasmtime_val_t](repeating: wasmtime_val_t(), count: 2)
        args[0].kind = UInt8(WASMTIME_I32); args[0].of.i32 = Int32(bitPattern: privPtr)
        args[1].kind = UInt8(WASMTIME_I32); args[1].of.i32 = Int32(bitPattern: pubPtr)

        var results = [wasmtime_val_t()]
        var trap: OpaquePointer? = nil
        var funcCopy = p256GenerateFunc
        let error = wasmtime_func_call(context, &funcCopy, &args, 2, &results, 1, &trap)
        if error != nil { wasmtime_error_delete(error) }
        if trap != nil { wasm_trap_delete(trap); throw WasmError.functionCallFailed("p256_generate") }

        return (readBytes(privPtr, 32), readBytes(pubPtr, 33))  // 33-byte compressed public key
    }

    // wasi_p256_shared_secret(private_key, public_key, public_key_size, shared_secret) -> int32
    func p256SharedSecret(privateKey: [UInt8], publicKey: [UInt8]) throws -> [UInt8] {
        let privPtr = try allocate(32)
        let pubPtr = try allocate(publicKey.count)
        let sharedPtr = try allocate(32)
        defer {
            deallocate(privPtr)
            deallocate(pubPtr)
            deallocate(sharedPtr)
        }

        writeBytes(privPtr, privateKey)
        writeBytes(pubPtr, publicKey)

        var args = [wasmtime_val_t](repeating: wasmtime_val_t(), count: 4)
        args[0].kind = UInt8(WASMTIME_I32); args[0].of.i32 = Int32(bitPattern: privPtr)
        args[1].kind = UInt8(WASMTIME_I32); args[1].of.i32 = Int32(bitPattern: pubPtr)
        args[2].kind = UInt8(WASMTIME_I32); args[2].of.i32 = Int32(publicKey.count)
        args[3].kind = UInt8(WASMTIME_I32); args[3].of.i32 = Int32(bitPattern: sharedPtr)

        var results = [wasmtime_val_t()]
        var trap: OpaquePointer? = nil
        var funcCopy = p256SharedFunc
        let error = wasmtime_func_call(context, &funcCopy, &args, 4, &results, 1, &trap)

        let retval = results[0].of.i32
        if error != nil { wasmtime_error_delete(error) }
        if trap != nil { wasm_trap_delete(trap); throw WasmError.functionCallFailed("p256_shared") }
        if retval != 0 { throw WasmError.functionCallFailed("p256_shared returned \(retval)") }

        return readBytes(sharedPtr, 32)
    }

    // Digital signatures
    // wasi_ed25519_generate_keypair(private_key, public_key) -> int32
    func ed25519GenerateKeypair() throws -> (privateKey: [UInt8], publicKey: [UInt8]) {
        let privPtr = try allocate(64)
        let pubPtr = try allocate(32)
        defer {
            deallocate(privPtr)
            deallocate(pubPtr)
        }

        var args = [wasmtime_val_t](repeating: wasmtime_val_t(), count: 2)
        args[0].kind = UInt8(WASMTIME_I32); args[0].of.i32 = Int32(bitPattern: privPtr)
        args[1].kind = UInt8(WASMTIME_I32); args[1].of.i32 = Int32(bitPattern: pubPtr)

        var results = [wasmtime_val_t()]
        var trap: OpaquePointer? = nil
        var funcCopy = ed25519GenerateFunc
        let error = wasmtime_func_call(context, &funcCopy, &args, 2, &results, 1, &trap)
        if error != nil { wasmtime_error_delete(error) }
        if trap != nil { wasm_trap_delete(trap); throw WasmError.functionCallFailed("ed25519_generate") }

        return (readBytes(privPtr, 64), readBytes(pubPtr, 32))
    }

    // wasi_ed25519_sign(private_key, data, data_size, signature) -> int32
    func ed25519Sign(privateKey: [UInt8], data: [UInt8]) throws -> [UInt8] {
        let privPtr = try allocate(64)
        let dataPtr = try allocate(data.count)
        let sigPtr = try allocate(64)
        defer {
            deallocate(privPtr)
            deallocate(dataPtr)
            deallocate(sigPtr)
        }

        writeBytes(privPtr, privateKey)
        writeBytes(dataPtr, data)

        var args = [wasmtime_val_t](repeating: wasmtime_val_t(), count: 4)
        args[0].kind = UInt8(WASMTIME_I32); args[0].of.i32 = Int32(bitPattern: privPtr)
        args[1].kind = UInt8(WASMTIME_I32); args[1].of.i32 = Int32(bitPattern: dataPtr)
        args[2].kind = UInt8(WASMTIME_I32); args[2].of.i32 = Int32(data.count)
        args[3].kind = UInt8(WASMTIME_I32); args[3].of.i32 = Int32(bitPattern: sigPtr)

        var results = [wasmtime_val_t()]
        var trap: OpaquePointer? = nil
        var funcCopy = ed25519SignFunc
        let error = wasmtime_func_call(context, &funcCopy, &args, 4, &results, 1, &trap)
        if error != nil { wasmtime_error_delete(error) }
        if trap != nil { wasm_trap_delete(trap); throw WasmError.functionCallFailed("ed25519_sign") }

        let retval = results[0].of.i32
        if retval != 0 { throw WasmError.functionCallFailed("ed25519_sign returned \(retval)") }
        return readBytes(sigPtr, 64)
    }

    // wasi_ed25519_verify(public_key, data, data_size, signature) -> int32
    func ed25519Verify(publicKey: [UInt8], data: [UInt8], signature: [UInt8]) throws -> Bool {
        let pubPtr = try allocate(32)
        let dataPtr = try allocate(data.count)
        let sigPtr = try allocate(64)
        defer {
            deallocate(pubPtr)
            deallocate(dataPtr)
            deallocate(sigPtr)
        }

        writeBytes(pubPtr, publicKey)
        writeBytes(dataPtr, data)
        writeBytes(sigPtr, signature)

        var args = [wasmtime_val_t](repeating: wasmtime_val_t(), count: 4)
        args[0].kind = UInt8(WASMTIME_I32); args[0].of.i32 = Int32(bitPattern: pubPtr)
        args[1].kind = UInt8(WASMTIME_I32); args[1].of.i32 = Int32(bitPattern: dataPtr)
        args[2].kind = UInt8(WASMTIME_I32); args[2].of.i32 = Int32(data.count)
        args[3].kind = UInt8(WASMTIME_I32); args[3].of.i32 = Int32(bitPattern: sigPtr)

        var results = [wasmtime_val_t()]
        var trap: OpaquePointer? = nil
        var funcCopy = ed25519VerifyFunc
        let error = wasmtime_func_call(context, &funcCopy, &args, 4, &results, 1, &trap)
        if error != nil { wasmtime_error_delete(error) }
        if trap != nil { wasm_trap_delete(trap); throw WasmError.functionCallFailed("ed25519_verify") }

        return results[0].of.i32 == 0  // 0 = valid, -1 = invalid
    }

    // wasi_secp256k1_sign(private_key, data, data_size, signature, signature_size_ptr) -> int32
    func secp256k1Sign(privateKey: [UInt8], data: [UInt8]) throws -> [UInt8] {
        let privPtr = try allocate(32)
        let dataPtr = try allocate(data.count)
        let sigPtr = try allocate(72)
        let sigSizePtr = try allocate(4)  // uint32_t output
        defer {
            deallocate(privPtr)
            deallocate(dataPtr)
            deallocate(sigPtr)
            deallocate(sigSizePtr)
        }

        writeBytes(privPtr, privateKey)
        writeBytes(dataPtr, data)

        var args = [wasmtime_val_t](repeating: wasmtime_val_t(), count: 5)
        args[0].kind = UInt8(WASMTIME_I32); args[0].of.i32 = Int32(bitPattern: privPtr)
        args[1].kind = UInt8(WASMTIME_I32); args[1].of.i32 = Int32(bitPattern: dataPtr)
        args[2].kind = UInt8(WASMTIME_I32); args[2].of.i32 = Int32(data.count)
        args[3].kind = UInt8(WASMTIME_I32); args[3].of.i32 = Int32(bitPattern: sigPtr)
        args[4].kind = UInt8(WASMTIME_I32); args[4].of.i32 = Int32(bitPattern: sigSizePtr)

        var results = [wasmtime_val_t()]
        var trap: OpaquePointer? = nil
        var funcCopy = secp256k1SignFunc
        let error = wasmtime_func_call(context, &funcCopy, &args, 5, &results, 1, &trap)
        if error != nil { wasmtime_error_delete(error) }
        if trap != nil { wasm_trap_delete(trap); throw WasmError.functionCallFailed("secp256k1_sign") }

        // Read signature size from output pointer
        let sigSizeBytes = readBytes(sigSizePtr, 4)
        let sigLen = Int(UInt32(sigSizeBytes[0]) | UInt32(sigSizeBytes[1]) << 8 | UInt32(sigSizeBytes[2]) << 16 | UInt32(sigSizeBytes[3]) << 24)
        return readBytes(sigPtr, sigLen > 0 && sigLen <= 72 ? sigLen : 72)
    }

    func secp256k1Verify(publicKey: [UInt8], data: [UInt8], signature: [UInt8]) throws -> Bool {
        let pubPtr = try allocate(65)
        let dataPtr = try allocate(data.count)
        let sigPtr = try allocate(signature.count)
        defer {
            deallocate(pubPtr)
            deallocate(dataPtr)
            deallocate(sigPtr)
        }

        writeBytes(pubPtr, publicKey)
        writeBytes(dataPtr, data)
        writeBytes(sigPtr, signature)

        var args = [wasmtime_val_t](repeating: wasmtime_val_t(), count: 6)
        args[0].kind = UInt8(WASMTIME_I32); args[0].of.i32 = Int32(bitPattern: pubPtr)
        args[1].kind = UInt8(WASMTIME_I32); args[1].of.i32 = Int32(publicKey.count)
        args[2].kind = UInt8(WASMTIME_I32); args[2].of.i32 = Int32(bitPattern: dataPtr)
        args[3].kind = UInt8(WASMTIME_I32); args[3].of.i32 = Int32(data.count)
        args[4].kind = UInt8(WASMTIME_I32); args[4].of.i32 = Int32(bitPattern: sigPtr)
        args[5].kind = UInt8(WASMTIME_I32); args[5].of.i32 = Int32(signature.count)

        var results = [wasmtime_val_t()]
        var trap: OpaquePointer? = nil
        var funcCopy = secp256k1VerifyFunc
        let error = wasmtime_func_call(context, &funcCopy, &args, 6, &results, 1, &trap)
        if error != nil { wasmtime_error_delete(error) }
        if trap != nil { wasm_trap_delete(trap); throw WasmError.functionCallFailed("secp256k1_verify") }

        return results[0].of.i32 == 0  // 0 = valid, -1 = invalid
    }

    // wasi_p256_sign(private_key, data, data_size, signature, signature_size_ptr) -> int32
    func p256Sign(privateKey: [UInt8], data: [UInt8]) throws -> [UInt8] {
        let privPtr = try allocate(32)
        let dataPtr = try allocate(data.count)
        let sigPtr = try allocate(72)
        let sigSizePtr = try allocate(4)  // uint32_t output
        defer {
            deallocate(privPtr)
            deallocate(dataPtr)
            deallocate(sigPtr)
            deallocate(sigSizePtr)
        }

        writeBytes(privPtr, privateKey)
        writeBytes(dataPtr, data)

        var args = [wasmtime_val_t](repeating: wasmtime_val_t(), count: 5)
        args[0].kind = UInt8(WASMTIME_I32); args[0].of.i32 = Int32(bitPattern: privPtr)
        args[1].kind = UInt8(WASMTIME_I32); args[1].of.i32 = Int32(bitPattern: dataPtr)
        args[2].kind = UInt8(WASMTIME_I32); args[2].of.i32 = Int32(data.count)
        args[3].kind = UInt8(WASMTIME_I32); args[3].of.i32 = Int32(bitPattern: sigPtr)
        args[4].kind = UInt8(WASMTIME_I32); args[4].of.i32 = Int32(bitPattern: sigSizePtr)

        var results = [wasmtime_val_t()]
        var trap: OpaquePointer? = nil
        var funcCopy = p256SignFunc
        let error = wasmtime_func_call(context, &funcCopy, &args, 5, &results, 1, &trap)
        if error != nil { wasmtime_error_delete(error) }
        if trap != nil { wasm_trap_delete(trap); throw WasmError.functionCallFailed("p256_sign") }

        // Read signature size from output pointer
        let sigSizeBytes = readBytes(sigSizePtr, 4)
        let sigLen = Int(UInt32(sigSizeBytes[0]) | UInt32(sigSizeBytes[1]) << 8 | UInt32(sigSizeBytes[2]) << 16 | UInt32(sigSizeBytes[3]) << 24)
        return readBytes(sigPtr, sigLen > 0 && sigLen <= 72 ? sigLen : 72)
    }

    func p256Verify(publicKey: [UInt8], data: [UInt8], signature: [UInt8]) throws -> Bool {
        let pubPtr = try allocate(65)
        let dataPtr = try allocate(data.count)
        let sigPtr = try allocate(signature.count)
        defer {
            deallocate(pubPtr)
            deallocate(dataPtr)
            deallocate(sigPtr)
        }

        writeBytes(pubPtr, publicKey)
        writeBytes(dataPtr, data)
        writeBytes(sigPtr, signature)

        var args = [wasmtime_val_t](repeating: wasmtime_val_t(), count: 6)
        args[0].kind = UInt8(WASMTIME_I32); args[0].of.i32 = Int32(bitPattern: pubPtr)
        args[1].kind = UInt8(WASMTIME_I32); args[1].of.i32 = Int32(publicKey.count)
        args[2].kind = UInt8(WASMTIME_I32); args[2].of.i32 = Int32(bitPattern: dataPtr)
        args[3].kind = UInt8(WASMTIME_I32); args[3].of.i32 = Int32(data.count)
        args[4].kind = UInt8(WASMTIME_I32); args[4].of.i32 = Int32(bitPattern: sigPtr)
        args[5].kind = UInt8(WASMTIME_I32); args[5].of.i32 = Int32(signature.count)

        var results = [wasmtime_val_t()]
        var trap: OpaquePointer? = nil
        var funcCopy = p256VerifyFunc
        let error = wasmtime_func_call(context, &funcCopy, &args, 6, &results, 1, &trap)
        if error != nil { wasmtime_error_delete(error) }
        if trap != nil { wasm_trap_delete(trap); throw WasmError.functionCallFailed("p256_verify") }

        return results[0].of.i32 == 0  // 0 = valid, -1 = invalid
    }
}

// Callback box for passing Swift closures through C API
class CallbackBox {
    let callback: (OpaquePointer?, UnsafePointer<wasmtime_val_t>?, UnsafeMutablePointer<wasmtime_val_t>?) -> OpaquePointer?
    init(callback: @escaping (OpaquePointer?, UnsafePointer<wasmtime_val_t>?, UnsafeMutablePointer<wasmtime_val_t>?) -> OpaquePointer?) {
        self.callback = callback
    }
}

enum WasmError: Error {
    case engineCreationFailed
    case storeCreationFailed
    case linkerCreationFailed
    case wasiSetupFailed
    case moduleLoadFailed
    case instantiationFailed
    case exportNotFound(String)
    case linkingFailed(String)
    case allocationFailed
    case functionCallFailed(String)
}

// MARK: - Test Runner

func runTests() {
    print("Swift E2E Crypto Test Runner (Wasmtime)")
    print("========================================")

    var passed = 0
    var failed = 0

    // Navigate from runners/swift up to flatbuffers root, then to build/wasm/wasm
    let wasmPath = "../../../../../build/wasm/wasm/flatc-encryption.wasm"
    var engine: WasmtimeEngine!

    // Test 1: WASM module loading
    do {
        engine = try WasmtimeEngine(wasmPath: wasmPath)
        print("✓ Test 1: WASM module loaded successfully")
        passed += 1
    } catch {
        print("✗ Test 1: WASM module loading failed - \(error)")
        failed += 1
        print("\nResults: \(passed)/\(passed + failed) tests passed")
        return
    }

    // Test 2: SHA256 hashing
    do {
        let input = Array("Hello, World!".utf8)
        let hash = try engine.sha256(input)
        let expected: [UInt8] = [
            0xdf, 0xfd, 0x60, 0x21, 0xbb, 0x2b, 0xd5, 0xb0,
            0xaf, 0x67, 0x62, 0x90, 0x80, 0x9e, 0xc3, 0xa5,
            0x31, 0x91, 0xdd, 0x81, 0xc7, 0xf7, 0x0a, 0x4b,
            0x28, 0x68, 0x8a, 0x36, 0x21, 0x82, 0x98, 0x6f
        ]
        if hash == expected {
            print("✓ Test 2: SHA256 hash correct")
            passed += 1
        } else {
            print("✗ Test 2: SHA256 hash mismatch")
            failed += 1
        }
    } catch {
        print("✗ Test 2: SHA256 failed - \(error)")
        failed += 1
    }

    // Test 3: AES-256-GCM encryption/decryption
    do {
        let key = [UInt8](repeating: 0x42, count: 32)
        let iv = [UInt8](repeating: 0x24, count: 16)
        let plaintext = Array("Secret message for AES test".utf8)

        let ciphertext = try engine.encrypt(key: key, iv: iv, plaintext: plaintext)
        let decrypted = try engine.decrypt(key: key, iv: iv, ciphertext: ciphertext)

        if decrypted == plaintext {
            print("✓ Test 3: AES-256-GCM encryption/decryption")
            passed += 1
        } else {
            print("✗ Test 3: AES decryption mismatch")
            failed += 1
        }
    } catch {
        print("✗ Test 3: AES encryption failed - \(error)")
        failed += 1
    }

    // Test 4: HKDF key derivation
    do {
        let ikm = Array("initial key material".utf8)
        let salt = Array("salty".utf8)
        let info = Array("info".utf8)
        let derived = try engine.hkdf(ikm: ikm, salt: salt, info: info, outputLen: 32)

        if derived.count == 32 && !derived.allSatisfy({ $0 == 0 }) {
            print("✓ Test 4: HKDF key derivation")
            passed += 1
        } else {
            print("✗ Test 4: HKDF produced invalid output")
            failed += 1
        }
    } catch {
        print("✗ Test 4: HKDF failed - \(error)")
        failed += 1
    }

    // Test 5: X25519 ECDH key exchange
    do {
        let (alicePriv, alicePub) = try engine.x25519GenerateKeypair()
        let (bobPriv, bobPub) = try engine.x25519GenerateKeypair()

        let aliceShared = try engine.x25519SharedSecret(privateKey: alicePriv, publicKey: bobPub)
        let bobShared = try engine.x25519SharedSecret(privateKey: bobPriv, publicKey: alicePub)

        if aliceShared == bobShared && !aliceShared.allSatisfy({ $0 == 0 }) {
            print("✓ Test 5: X25519 ECDH key exchange")
            passed += 1
        } else {
            print("✗ Test 5: X25519 shared secrets don't match")
            failed += 1
        }
    } catch {
        print("✗ Test 5: X25519 ECDH failed - \(error)")
        failed += 1
    }

    // Test 6: Secp256k1 ECDH key exchange
    do {
        let (alicePriv, alicePub) = try engine.secp256k1GenerateKeypair()
        let (bobPriv, bobPub) = try engine.secp256k1GenerateKeypair()

        let aliceShared = try engine.secp256k1SharedSecret(privateKey: alicePriv, publicKey: bobPub)
        let bobShared = try engine.secp256k1SharedSecret(privateKey: bobPriv, publicKey: alicePub)

        if aliceShared == bobShared && !aliceShared.allSatisfy({ $0 == 0 }) {
            print("✓ Test 6: Secp256k1 ECDH key exchange")
            passed += 1
        } else {
            print("✗ Test 6: Secp256k1 shared secrets don't match")
            failed += 1
        }
    } catch {
        print("✗ Test 6: Secp256k1 ECDH failed - \(error)")
        failed += 1
    }

    // Test 7: P-256 ECDH key exchange
    do {
        let (alicePriv, alicePub) = try engine.p256GenerateKeypair()
        let (bobPriv, bobPub) = try engine.p256GenerateKeypair()

        let aliceShared = try engine.p256SharedSecret(privateKey: alicePriv, publicKey: bobPub)
        let bobShared = try engine.p256SharedSecret(privateKey: bobPriv, publicKey: alicePub)

        if aliceShared == bobShared && !aliceShared.allSatisfy({ $0 == 0 }) {
            print("✓ Test 7: P-256 ECDH key exchange")
            passed += 1
        } else {
            print("✗ Test 7: P-256 shared secrets don't match")
            failed += 1
        }
    } catch {
        print("✗ Test 7: P-256 ECDH failed - \(error)")
        failed += 1
    }

    // Test 8: Ed25519 signatures
    do {
        let (privateKey, publicKey) = try engine.ed25519GenerateKeypair()
        let message = Array("Test message for Ed25519".utf8)

        let signature = try engine.ed25519Sign(privateKey: privateKey, data: message)
        let valid = try engine.ed25519Verify(publicKey: publicKey, data: message, signature: signature)

        if valid && signature.count == 64 {
            print("✓ Test 8: Ed25519 signature sign/verify")
            passed += 1
        } else {
            print("✗ Test 8: Ed25519 verification failed")
            failed += 1
        }
    } catch {
        print("✗ Test 8: Ed25519 signatures failed - \(error)")
        failed += 1
    }

    // Test 9: Secp256k1 signatures
    do {
        let (privateKey, publicKey) = try engine.secp256k1GenerateKeypair()
        let message = Array("Test message for secp256k1".utf8)

        let signature = try engine.secp256k1Sign(privateKey: privateKey, data: message)
        let valid = try engine.secp256k1Verify(publicKey: publicKey, data: message, signature: signature)

        if valid {
            print("✓ Test 9: Secp256k1 signature sign/verify")
            passed += 1
        } else {
            print("✗ Test 9: Secp256k1 verification failed")
            failed += 1
        }
    } catch {
        print("✗ Test 9: Secp256k1 signatures failed - \(error)")
        failed += 1
    }

    // Test 10: P-256 signatures
    do {
        let (privateKey, publicKey) = try engine.p256GenerateKeypair()
        let message = Array("Test message for P-256".utf8)

        let signature = try engine.p256Sign(privateKey: privateKey, data: message)
        let valid = try engine.p256Verify(publicKey: publicKey, data: message, signature: signature)

        if valid {
            print("✓ Test 10: P-256 signature sign/verify")
            passed += 1
        } else {
            print("✗ Test 10: P-256 verification failed")
            failed += 1
        }
    } catch {
        print("✗ Test 10: P-256 signatures failed - \(error)")
        failed += 1
    }

    // Test 11: Full encryption pipeline with ECDH derived keys
    do {
        // Generate X25519 keypairs
        let (alicePriv, alicePub) = try engine.x25519GenerateKeypair()
        let (bobPriv, bobPub) = try engine.x25519GenerateKeypair()

        // Derive shared secret
        let shared = try engine.x25519SharedSecret(privateKey: alicePriv, publicKey: bobPub)

        // Derive encryption key using HKDF
        let encKey = try engine.hkdf(ikm: shared, salt: [], info: Array("encryption".utf8), outputLen: 32)
        let iv = [UInt8](repeating: 0, count: 16)

        // Encrypt and decrypt
        let plaintext = Array("Hello from X25519 encrypted channel!".utf8)
        let ciphertext = try engine.encrypt(key: encKey, iv: iv, plaintext: plaintext)
        let decrypted = try engine.decrypt(key: encKey, iv: iv, ciphertext: ciphertext)

        if decrypted == plaintext {
            print("✓ Test 11: Full X25519 + HKDF + AES pipeline")
            passed += 1
        } else {
            print("✗ Test 11: Pipeline decryption mismatch")
            failed += 1
        }
    } catch {
        print("✗ Test 11: Pipeline failed - \(error)")
        failed += 1
    }

    // Test 12: Large data encryption
    do {
        let key = [UInt8](repeating: 0x55, count: 32)
        let iv = [UInt8](repeating: 0xAA, count: 16)
        let plaintext = [UInt8](repeating: 0x42, count: 10000)

        let ciphertext = try engine.encrypt(key: key, iv: iv, plaintext: plaintext)
        let decrypted = try engine.decrypt(key: key, iv: iv, ciphertext: ciphertext)

        if decrypted == plaintext {
            print("✓ Test 12: Large data (10KB) encryption")
            passed += 1
        } else {
            print("✗ Test 12: Large data decryption mismatch")
            failed += 1
        }
    } catch {
        print("✗ Test 12: Large data encryption failed - \(error)")
        failed += 1
    }

    // Test 13: Ed25519 invalid signature rejection
    do {
        let (privateKey, publicKey) = try engine.ed25519GenerateKeypair()
        let message = Array("Original message".utf8)

        let signature = try engine.ed25519Sign(privateKey: privateKey, data: message)

        // Modify message
        let tamperedMessage = Array("Tampered message".utf8)
        let valid = try engine.ed25519Verify(publicKey: publicKey, data: tamperedMessage, signature: signature)

        if !valid {
            print("✓ Test 13: Ed25519 invalid signature rejection")
            passed += 1
        } else {
            print("✗ Test 13: Ed25519 accepted invalid signature")
            failed += 1
        }
    } catch {
        print("✗ Test 13: Ed25519 signature test failed - \(error)")
        failed += 1
    }

    // Test 14: Secp256k1 invalid signature rejection
    do {
        let (privateKey, publicKey) = try engine.secp256k1GenerateKeypair()
        let message = Array("Original message".utf8)

        let signature = try engine.secp256k1Sign(privateKey: privateKey, data: message)

        // Modify message
        let tamperedMessage = Array("Tampered message".utf8)
        let valid = try engine.secp256k1Verify(publicKey: publicKey, data: tamperedMessage, signature: signature)

        if !valid {
            print("✓ Test 14: Secp256k1 invalid signature rejection")
            passed += 1
        } else {
            print("✗ Test 14: Secp256k1 accepted invalid signature")
            failed += 1
        }
    } catch {
        print("✗ Test 14: Secp256k1 signature test failed - \(error)")
        failed += 1
    }

    // Test 15: P-256 invalid signature rejection
    do {
        let (privateKey, publicKey) = try engine.p256GenerateKeypair()
        let message = Array("Original message".utf8)

        let signature = try engine.p256Sign(privateKey: privateKey, data: message)

        // Modify message
        let tamperedMessage = Array("Tampered message".utf8)
        let valid = try engine.p256Verify(publicKey: publicKey, data: tamperedMessage, signature: signature)

        if !valid {
            print("✓ Test 15: P-256 invalid signature rejection")
            passed += 1
        } else {
            print("✗ Test 15: P-256 accepted invalid signature")
            failed += 1
        }
    } catch {
        print("✗ Test 15: P-256 signature test failed - \(error)")
        failed += 1
    }

    // Test 16: Secp256k1 signed encryption
    do {
        let (sigPriv, sigPub) = try engine.secp256k1GenerateKeypair()
        let (_, _) = try engine.secp256k1GenerateKeypair() // Recipient keypair (unused here)

        let key = [UInt8](repeating: 0x33, count: 32)
        let iv = [UInt8](repeating: 0x44, count: 16)
        let plaintext = Array("Signed and encrypted message".utf8)

        // Encrypt
        let ciphertext = try engine.encrypt(key: key, iv: iv, plaintext: plaintext)

        // Sign the ciphertext
        let signature = try engine.secp256k1Sign(privateKey: sigPriv, data: ciphertext)

        // Verify signature and decrypt
        let sigValid = try engine.secp256k1Verify(publicKey: sigPub, data: ciphertext, signature: signature)
        let decrypted = try engine.decrypt(key: key, iv: iv, ciphertext: ciphertext)

        if sigValid && decrypted == plaintext {
            print("✓ Test 16: Secp256k1 signed encryption")
            passed += 1
        } else {
            print("✗ Test 16: Signed encryption failed")
            failed += 1
        }
    } catch {
        print("✗ Test 16: Signed encryption failed - \(error)")
        failed += 1
    }

    // Test 17: Multi-recipient encryption
    do {
        let (senderPriv, senderPub) = try engine.x25519GenerateKeypair()
        let (_, recipient1Pub) = try engine.x25519GenerateKeypair()
        let (recipient2Priv, recipient2Pub) = try engine.x25519GenerateKeypair()
        let (recipient3Priv, recipient3Pub) = try engine.x25519GenerateKeypair()

        // Sender derives shared secrets with each recipient
        let shared1 = try engine.x25519SharedSecret(privateKey: senderPriv, publicKey: recipient1Pub)
        let shared2 = try engine.x25519SharedSecret(privateKey: senderPriv, publicKey: recipient2Pub)
        let shared3 = try engine.x25519SharedSecret(privateKey: senderPriv, publicKey: recipient3Pub)

        // Derive encryption keys
        let key1 = try engine.hkdf(ikm: shared1, salt: [], info: Array("recipient1".utf8), outputLen: 32)
        let key2 = try engine.hkdf(ikm: shared2, salt: [], info: Array("recipient2".utf8), outputLen: 32)
        let key3 = try engine.hkdf(ikm: shared3, salt: [], info: Array("recipient3".utf8), outputLen: 32)

        let iv = [UInt8](repeating: 0x12, count: 16)
        let originalPlaintext = Array("Multi-recipient message".utf8)

        // Encrypt for each recipient (use fresh copies since encrypt modifies in-place)
        _ = try engine.encrypt(key: key1, iv: iv, plaintext: originalPlaintext)
        let ct2 = try engine.encrypt(key: key2, iv: iv, plaintext: originalPlaintext)
        let ct3 = try engine.encrypt(key: key3, iv: iv, plaintext: originalPlaintext)

        // Each recipient decrypts with their own derived key
        // Recipient 2 derives shared secret using their private key and sender's public key
        let r2Shared = try engine.x25519SharedSecret(privateKey: recipient2Priv, publicKey: senderPub)
        let r2Key = try engine.hkdf(ikm: r2Shared, salt: [], info: Array("recipient2".utf8), outputLen: 32)
        let r2Decrypted = try engine.decrypt(key: r2Key, iv: iv, ciphertext: ct2)

        // Recipient 3 decrypts
        let r3Shared = try engine.x25519SharedSecret(privateKey: recipient3Priv, publicKey: senderPub)
        let r3Key = try engine.hkdf(ikm: r3Shared, salt: [], info: Array("recipient3".utf8), outputLen: 32)
        let r3Decrypted = try engine.decrypt(key: r3Key, iv: iv, ciphertext: ct3)

        if r2Decrypted == originalPlaintext && r3Decrypted == originalPlaintext {
            print("✓ Test 17: Multi-recipient encryption")
            passed += 1
        } else {
            print("  [DEBUG] r2Key == key2: \(r2Key == key2)")
            print("  [DEBUG] r2Decrypted == original: \(r2Decrypted == originalPlaintext)")
            print("  [DEBUG] r3Decrypted == original: \(r3Decrypted == originalPlaintext)")
            print("  [DEBUG] original: \(String(bytes: originalPlaintext, encoding: .utf8) ?? "nil")")
            print("  [DEBUG] r2 dec: \(String(bytes: r2Decrypted, encoding: .utf8) ?? "nil")")
            print("  [DEBUG] r3 dec: \(String(bytes: r3Decrypted, encoding: .utf8) ?? "nil")")
            print("✗ Test 17: Multi-recipient decryption failed")
            failed += 1
        }
    } catch {
        print("✗ Test 17: Multi-recipient encryption failed - \(error)")
        failed += 1
    }

    print("\n========================================")
    print("Results: \(passed)/\(passed + failed) tests passed")

    if failed > 0 {
        exit(1)
    }
}

// Run tests
runTests()
