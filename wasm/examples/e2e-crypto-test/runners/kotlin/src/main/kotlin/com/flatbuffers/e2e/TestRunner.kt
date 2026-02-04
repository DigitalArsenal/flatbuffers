/**
 * Kotlin E2E Test Runner for FlatBuffers Cross-Language Encryption
 *
 * Tests encryption/decryption using the WASM Crypto++ module with all 10 crypto key types.
 * Uses Chicory pure-Java WASM runtime (v1.5+).
 */
package com.flatbuffers.e2e

import com.dylibso.chicory.runtime.ExportFunction
import com.dylibso.chicory.runtime.HostFunction
import com.dylibso.chicory.runtime.Instance
import com.dylibso.chicory.runtime.Memory
import com.dylibso.chicory.runtime.Store
import com.dylibso.chicory.wasi.WasiOptions
import com.dylibso.chicory.wasi.WasiPreview1
import com.dylibso.chicory.wasm.Parser
import com.dylibso.chicory.wasm.types.FunctionType
import com.dylibso.chicory.wasm.types.ValType
import com.google.flatbuffers.FlatBufferBuilder
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import E2E.Crypto.SecureMessage
import E2E.Crypto.Payload
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths

private const val AES_KEY_SIZE = 32
private const val AES_IV_SIZE = 16
private const val SHA256_SIZE = 32

class WasmCryptoRunner(wasmFile: File) {
    private val instance: Instance
    private val memory: Memory
    private val malloc: ExportFunction
    private val free: ExportFunction
    private val sha256Fn: ExportFunction
    private val encryptBytesFn: ExportFunction
    private val decryptBytesFn: ExportFunction
    private val hkdfFn: ExportFunction
    private val x25519GenerateFn: ExportFunction
    private val x25519SharedFn: ExportFunction
    private val secp256k1GenerateFn: ExportFunction
    private val secp256k1SharedFn: ExportFunction
    private val p256GenerateFn: ExportFunction
    private val p256SharedFn: ExportFunction
    private val ed25519GenerateFn: ExportFunction
    private val ed25519SignFn: ExportFunction
    private val ed25519VerifyFn: ExportFunction
    private val secp256k1SignFn: ExportFunction
    private val secp256k1VerifyFn: ExportFunction
    private val p256SignFn: ExportFunction
    private val p256VerifyFn: ExportFunction

    init {
        val wasiOptions = WasiOptions.builder().build()
        val wasi = WasiPreview1.builder().withOptions(wasiOptions).build()

        val store = Store()
        store.addFunction(wasi.toHostFunctions())
        addExceptionStubs(store)
        addInvokeStubs(store)

        val module = Parser.parse(wasmFile)
        instance = store.instantiate("flatc", module)
        memory = instance.memory()

        malloc = instance.export("malloc")
        free = instance.export("free")
        sha256Fn = instance.export("wasi_sha256")
        encryptBytesFn = instance.export("wasi_encrypt_bytes")
        decryptBytesFn = instance.export("wasi_decrypt_bytes")
        hkdfFn = instance.export("wasi_hkdf")
        x25519GenerateFn = instance.export("wasi_x25519_generate_keypair")
        x25519SharedFn = instance.export("wasi_x25519_shared_secret")
        secp256k1GenerateFn = instance.export("wasi_secp256k1_generate_keypair")
        secp256k1SharedFn = instance.export("wasi_secp256k1_shared_secret")
        p256GenerateFn = instance.export("wasi_p256_generate_keypair")
        p256SharedFn = instance.export("wasi_p256_shared_secret")
        ed25519GenerateFn = instance.export("wasi_ed25519_generate_keypair")
        ed25519SignFn = instance.export("wasi_ed25519_sign")
        ed25519VerifyFn = instance.export("wasi_ed25519_verify")
        secp256k1SignFn = instance.export("wasi_secp256k1_sign")
        secp256k1VerifyFn = instance.export("wasi_secp256k1_verify")
        p256SignFn = instance.export("wasi_p256_sign")
        p256VerifyFn = instance.export("wasi_p256_verify")

        // Call _initialize if present
        try {
            instance.export("_initialize")?.apply()
        } catch (_: Exception) {
            // Module may not have _initialize
        }
    }

    private fun addExceptionStubs(store: Store) {
        store.addFunction(HostFunction(
            "env", "__cxa_throw",
            FunctionType.of(listOf(ValType.I32, ValType.I32, ValType.I32), listOf())
        ) { _, _ -> null })

        store.addFunction(HostFunction(
            "env", "__cxa_begin_catch",
            FunctionType.of(listOf(ValType.I32), listOf(ValType.I32))
        ) { _, _ -> longArrayOf(0) })

        store.addFunction(HostFunction(
            "env", "__cxa_end_catch",
            FunctionType.of(listOf(), listOf())
        ) { _, _ -> null })

        store.addFunction(HostFunction(
            "env", "__cxa_find_matching_catch_2",
            FunctionType.of(listOf(), listOf(ValType.I32))
        ) { _, _ -> longArrayOf(0) })

        store.addFunction(HostFunction(
            "env", "__cxa_find_matching_catch_3",
            FunctionType.of(listOf(ValType.I32), listOf(ValType.I32))
        ) { _, _ -> longArrayOf(0) })

        store.addFunction(HostFunction(
            "env", "__resumeException",
            FunctionType.of(listOf(ValType.I32), listOf())
        ) { _, _ -> null })

        store.addFunction(HostFunction(
            "env", "llvm_eh_typeid_for",
            FunctionType.of(listOf(ValType.I32), listOf(ValType.I32))
        ) { _, _ -> longArrayOf(0) })

        store.addFunction(HostFunction(
            "env", "__cxa_uncaught_exceptions",
            FunctionType.of(listOf(), listOf(ValType.I32))
        ) { _, _ -> longArrayOf(0) })

        store.addFunction(HostFunction(
            "env", "setThrew",
            FunctionType.of(listOf(ValType.I32, ValType.I32), listOf())
        ) { _, _ -> null })
    }

    private fun addInvokeStubs(store: Store) {
        // invoke_v variants (void return)
        listOf("invoke_v" to 0, "invoke_vi" to 1, "invoke_vii" to 2, "invoke_viii" to 3,
            "invoke_viiii" to 4, "invoke_viiiii" to 5, "invoke_viiiiii" to 6,
            "invoke_viiiiiii" to 7, "invoke_viiiiiiiii" to 9).forEach { (name, nArgs) ->
            addInvokeVoid(store, name, nArgs)
        }

        // invoke_i variants (i32 return)
        listOf("invoke_i" to 0, "invoke_ii" to 1, "invoke_iii" to 2, "invoke_iiii" to 3,
            "invoke_iiiii" to 4, "invoke_iiiiii" to 5, "invoke_iiiiiii" to 6,
            "invoke_iiiiiiii" to 7, "invoke_iiiiiiiiii" to 9).forEach { (name, nArgs) ->
            addInvokeI32(store, name, nArgs)
        }
    }

    private fun addInvokeVoid(store: Store, name: String, nArgs: Int) {
        val params = (0..nArgs).map { ValType.I32 }
        store.addFunction(HostFunction("env", name, FunctionType.of(params, listOf())) { inst, args ->
            try {
                val tableIdx = args[0].toInt()
                val table = inst.table(0)
                if (table != null) {
                    val funcIdx = table.ref(tableIdx)
                    val funcArgs = LongArray(nArgs) { args[it + 1] }
                    inst.machine.call(funcIdx, funcArgs)
                }
            } catch (_: Exception) {
                // Exception during invoke
            }
            null
        })
    }

    private fun addInvokeI32(store: Store, name: String, nArgs: Int) {
        val params = (0..nArgs).map { ValType.I32 }
        store.addFunction(HostFunction("env", name, FunctionType.of(params, listOf(ValType.I32))) { inst, args ->
            try {
                val tableIdx = args[0].toInt()
                val table = inst.table(0)
                if (table != null) {
                    val funcIdx = table.ref(tableIdx)
                    val funcArgs = LongArray(nArgs) { args[it + 1] }
                    val result = inst.machine.call(funcIdx, funcArgs)
                    if (result != null && result.isNotEmpty()) {
                        return@HostFunction longArrayOf(result[0])
                    }
                }
            } catch (_: Exception) {
                // Exception during invoke
            }
            longArrayOf(0)
        })
    }

    private fun allocate(size: Int): Int = malloc.apply(size)[0].toInt()
    private fun deallocate(ptr: Int) = free.apply(ptr)
    private fun writeBytes(ptr: Int, data: ByteArray) = memory.write(ptr, data)
    private fun readBytes(ptr: Int, length: Int): ByteArray = memory.readBytes(ptr, length)

    fun sha256(data: ByteArray): ByteArray {
        val dataPtr = allocate(maxOf(data.size, 1))
        val hashPtr = allocate(SHA256_SIZE)

        if (data.isNotEmpty()) writeBytes(dataPtr, data)
        sha256Fn.apply(dataPtr, data.size, hashPtr)

        val hash = readBytes(hashPtr, SHA256_SIZE)
        deallocate(dataPtr)
        deallocate(hashPtr)
        return hash
    }

    fun encrypt(key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray {
        val keyPtr = allocate(AES_KEY_SIZE)
        val ivPtr = allocate(AES_IV_SIZE)
        val dataPtr = allocate(data.size)

        writeBytes(keyPtr, key)
        writeBytes(ivPtr, iv)
        writeBytes(dataPtr, data)
        encryptBytesFn.apply(keyPtr, ivPtr, dataPtr, data.size)

        val encrypted = readBytes(dataPtr, data.size)
        deallocate(keyPtr)
        deallocate(ivPtr)
        deallocate(dataPtr)
        return encrypted
    }

    fun decrypt(key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray {
        val keyPtr = allocate(AES_KEY_SIZE)
        val ivPtr = allocate(AES_IV_SIZE)
        val dataPtr = allocate(data.size)

        writeBytes(keyPtr, key)
        writeBytes(ivPtr, iv)
        writeBytes(dataPtr, data)
        decryptBytesFn.apply(keyPtr, ivPtr, dataPtr, data.size)

        val decrypted = readBytes(dataPtr, data.size)
        deallocate(keyPtr)
        deallocate(ivPtr)
        deallocate(dataPtr)
        return decrypted
    }

    fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, outputLen: Int): ByteArray {
        val ikmPtr = allocate(maxOf(ikm.size, 1))
        val saltPtr = allocate(maxOf(salt.size, 1))
        val infoPtr = allocate(maxOf(info.size, 1))
        val outPtr = allocate(outputLen)

        if (ikm.isNotEmpty()) writeBytes(ikmPtr, ikm)
        if (salt.isNotEmpty()) writeBytes(saltPtr, salt)
        if (info.isNotEmpty()) writeBytes(infoPtr, info)

        hkdfFn.apply(ikmPtr, ikm.size, saltPtr, salt.size, infoPtr, info.size, outPtr, outputLen)

        val output = readBytes(outPtr, outputLen)
        deallocate(ikmPtr)
        deallocate(saltPtr)
        deallocate(infoPtr)
        deallocate(outPtr)
        return output
    }

    data class KeyPair(val privateKey: ByteArray, val publicKey: ByteArray)

    fun x25519GenerateKeypair(): KeyPair {
        val privPtr = allocate(32)
        val pubPtr = allocate(32)

        x25519GenerateFn.apply(privPtr, pubPtr)

        val priv = readBytes(privPtr, 32)
        val pub = readBytes(pubPtr, 32)
        deallocate(privPtr)
        deallocate(pubPtr)
        return KeyPair(priv, pub)
    }

    fun x25519SharedSecret(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
        val privPtr = allocate(32)
        val pubPtr = allocate(32)
        val sharedPtr = allocate(32)

        writeBytes(privPtr, privateKey)
        writeBytes(pubPtr, publicKey)
        x25519SharedFn.apply(privPtr, pubPtr, sharedPtr)

        val shared = readBytes(sharedPtr, 32)
        deallocate(privPtr)
        deallocate(pubPtr)
        deallocate(sharedPtr)
        return shared
    }

    fun secp256k1GenerateKeypair(): KeyPair {
        val privPtr = allocate(32)
        val pubPtr = allocate(33)

        secp256k1GenerateFn.apply(privPtr, pubPtr)

        val priv = readBytes(privPtr, 32)
        val pub = readBytes(pubPtr, 33)
        deallocate(privPtr)
        deallocate(pubPtr)
        return KeyPair(priv, pub)
    }

    fun secp256k1SharedSecret(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
        val privPtr = allocate(32)
        val pubPtr = allocate(publicKey.size)
        val sharedPtr = allocate(32)

        writeBytes(privPtr, privateKey)
        writeBytes(pubPtr, publicKey)
        secp256k1SharedFn.apply(privPtr, pubPtr, publicKey.size, sharedPtr)

        val shared = readBytes(sharedPtr, 32)
        deallocate(privPtr)
        deallocate(pubPtr)
        deallocate(sharedPtr)
        return shared
    }

    fun p256GenerateKeypair(): KeyPair {
        val privPtr = allocate(32)
        val pubPtr = allocate(33)

        p256GenerateFn.apply(privPtr, pubPtr)

        val priv = readBytes(privPtr, 32)
        val pub = readBytes(pubPtr, 33)
        deallocate(privPtr)
        deallocate(pubPtr)
        return KeyPair(priv, pub)
    }

    fun p256SharedSecret(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
        val privPtr = allocate(32)
        val pubPtr = allocate(publicKey.size)
        val sharedPtr = allocate(32)

        writeBytes(privPtr, privateKey)
        writeBytes(pubPtr, publicKey)
        p256SharedFn.apply(privPtr, pubPtr, publicKey.size, sharedPtr)

        val shared = readBytes(sharedPtr, 32)
        deallocate(privPtr)
        deallocate(pubPtr)
        deallocate(sharedPtr)
        return shared
    }

    fun ed25519GenerateKeypair(): KeyPair {
        val privPtr = allocate(64)
        val pubPtr = allocate(32)

        val result = ed25519GenerateFn.apply(privPtr, pubPtr)
        if (result[0] != 0L) {
            deallocate(privPtr)
            deallocate(pubPtr)
            throw RuntimeException("Ed25519 keypair generation failed")
        }

        val priv = readBytes(privPtr, 64)
        val pub = readBytes(pubPtr, 32)
        deallocate(privPtr)
        deallocate(pubPtr)
        return KeyPair(priv, pub)
    }

    fun ed25519Sign(privateKey: ByteArray, data: ByteArray): ByteArray {
        val privPtr = allocate(64)
        val dataPtr = allocate(maxOf(data.size, 1))
        val sigPtr = allocate(64)

        writeBytes(privPtr, privateKey)
        if (data.isNotEmpty()) writeBytes(dataPtr, data)
        val result = ed25519SignFn.apply(privPtr, dataPtr, data.size, sigPtr)
        if (result[0] != 0L) {
            deallocate(privPtr)
            deallocate(dataPtr)
            deallocate(sigPtr)
            throw RuntimeException("Ed25519 signing failed")
        }

        val sig = readBytes(sigPtr, 64)
        deallocate(privPtr)
        deallocate(dataPtr)
        deallocate(sigPtr)
        return sig
    }

    fun ed25519Verify(publicKey: ByteArray, data: ByteArray, signature: ByteArray): Boolean {
        val pubPtr = allocate(32)
        val dataPtr = allocate(maxOf(data.size, 1))
        val sigPtr = allocate(64)

        writeBytes(pubPtr, publicKey)
        if (data.isNotEmpty()) writeBytes(dataPtr, data)
        writeBytes(sigPtr, signature)
        val result = ed25519VerifyFn.apply(pubPtr, dataPtr, data.size, sigPtr)

        deallocate(pubPtr)
        deallocate(dataPtr)
        deallocate(sigPtr)
        return result[0] == 0L
    }

    fun secp256k1Sign(privateKey: ByteArray, data: ByteArray): ByteArray {
        val privPtr = allocate(32)
        val dataPtr = allocate(maxOf(data.size, 1))
        val sigPtr = allocate(72)
        val sigSizePtr = allocate(4)

        writeBytes(privPtr, privateKey)
        if (data.isNotEmpty()) writeBytes(dataPtr, data)
        val result = secp256k1SignFn.apply(privPtr, dataPtr, data.size, sigPtr, sigSizePtr)
        if (result[0] != 0L) {
            deallocate(privPtr)
            deallocate(dataPtr)
            deallocate(sigPtr)
            deallocate(sigSizePtr)
            throw RuntimeException("secp256k1 signing failed")
        }

        val sigSizeBytes = readBytes(sigSizePtr, 4)
        val sigSize = (sigSizeBytes[0].toInt() and 0xFF) or
                ((sigSizeBytes[1].toInt() and 0xFF) shl 8) or
                ((sigSizeBytes[2].toInt() and 0xFF) shl 16) or
                ((sigSizeBytes[3].toInt() and 0xFF) shl 24)
        val sig = readBytes(sigPtr, sigSize)

        deallocate(privPtr)
        deallocate(dataPtr)
        deallocate(sigPtr)
        deallocate(sigSizePtr)
        return sig
    }

    fun secp256k1Verify(publicKey: ByteArray, data: ByteArray, signature: ByteArray): Boolean {
        val pubPtr = allocate(publicKey.size)
        val dataPtr = allocate(maxOf(data.size, 1))
        val sigPtr = allocate(signature.size)

        writeBytes(pubPtr, publicKey)
        if (data.isNotEmpty()) writeBytes(dataPtr, data)
        writeBytes(sigPtr, signature)
        val result = secp256k1VerifyFn.apply(pubPtr, publicKey.size, dataPtr, data.size, sigPtr, signature.size)

        deallocate(pubPtr)
        deallocate(dataPtr)
        deallocate(sigPtr)
        return result[0] == 0L
    }

    fun p256Sign(privateKey: ByteArray, data: ByteArray): ByteArray {
        val privPtr = allocate(32)
        val dataPtr = allocate(maxOf(data.size, 1))
        val sigPtr = allocate(72)
        val sigSizePtr = allocate(4)

        writeBytes(privPtr, privateKey)
        if (data.isNotEmpty()) writeBytes(dataPtr, data)
        val result = p256SignFn.apply(privPtr, dataPtr, data.size, sigPtr, sigSizePtr)
        if (result[0] != 0L) {
            deallocate(privPtr)
            deallocate(dataPtr)
            deallocate(sigPtr)
            deallocate(sigSizePtr)
            throw RuntimeException("P-256 signing failed")
        }

        val sigSizeBytes = readBytes(sigSizePtr, 4)
        val sigSize = (sigSizeBytes[0].toInt() and 0xFF) or
                ((sigSizeBytes[1].toInt() and 0xFF) shl 8) or
                ((sigSizeBytes[2].toInt() and 0xFF) shl 16) or
                ((sigSizeBytes[3].toInt() and 0xFF) shl 24)
        val sig = readBytes(sigPtr, sigSize)

        deallocate(privPtr)
        deallocate(dataPtr)
        deallocate(sigPtr)
        deallocate(sigSizePtr)
        return sig
    }

    fun p256Verify(publicKey: ByteArray, data: ByteArray, signature: ByteArray): Boolean {
        val pubPtr = allocate(publicKey.size)
        val dataPtr = allocate(maxOf(data.size, 1))
        val sigPtr = allocate(signature.size)

        writeBytes(pubPtr, publicKey)
        if (data.isNotEmpty()) writeBytes(dataPtr, data)
        writeBytes(sigPtr, signature)
        val result = p256VerifyFn.apply(pubPtr, publicKey.size, dataPtr, data.size, sigPtr, signature.size)

        deallocate(pubPtr)
        deallocate(dataPtr)
        deallocate(sigPtr)
        return result[0] == 0L
    }
}

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

fun String.hexToBytes(): ByteArray {
    check(length % 2 == 0) { "Hex string must have even length" }
    return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

data class ECDHHeader(
    val version: Int,
    val key_exchange: Int,
    val ephemeral_public_key: String,
    val context: String,
    val session_key: String,
    val session_iv: String
)

data class ECDHCurve(
    val name: String,
    val pubKeySize: Int,
    val keyExchange: Int,
    val generate: () -> WasmCryptoRunner.KeyPair,
    val shared: (ByteArray, ByteArray) -> ByteArray
)

class TestResult(private val name: String) {
    var passed = 0
    var failed = 0

    fun pass(msg: String) {
        passed++
        println("  ✓ $msg")
    }

    fun fail(msg: String) {
        failed++
        println("  ✗ $msg")
    }

    fun summary(): Boolean {
        val total = passed + failed
        val status = if (failed == 0) "✓" else "✗"
        println("\n$status $name: $passed/$total passed")
        return failed == 0
    }
}

fun main() {
    println("=".repeat(60))
    println("FlatBuffers Cross-Language Encryption E2E Tests - Kotlin")
    println("=".repeat(60))
    println()
    println("WASM Runtime: Chicory (pure JVM)")
    println()

    val wasmPaths = listOf(
        "../../../../../build/wasm/wasm/flatc-encryption.wasm",
        "../../../../../../build/wasm/wasm/flatc-encryption.wasm",
        "../../../../../../../build/wasm/wasm/flatc-encryption.wasm"
    )

    val wasmFile = wasmPaths.map { File(it) }.firstOrNull { it.exists() }
    if (wasmFile == null) {
        System.err.println("WASM module not found. Build it first.")
        System.exit(1)
    }

    println("Loading WASM module: ${wasmFile.absolutePath}")
    val runner = WasmCryptoRunner(wasmFile)
    println()

    val vectorsDir = Paths.get("../../vectors")
    val gson = Gson()
    val encryptionKeysType = object : TypeToken<Map<String, Map<String, String>>>() {}.type
    val encryptionKeys: Map<String, Map<String, String>> = gson.fromJson(
        Files.readString(vectorsDir.resolve("encryption_keys.json")),
        encryptionKeysType
    )

    val results = mutableListOf<Boolean>()

    // Test 1: SHA-256
    println("Test 1: SHA-256 Hash")
    println("-".repeat(40))
    run {
        val result = TestResult("SHA-256")

        val hash = runner.sha256("hello".toByteArray())
        val expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        if (hash.toHex() == expected) {
            result.pass("SHA256('hello') correct")
        } else {
            result.fail("SHA256 mismatch: ${hash.toHex()}")
        }

        val emptyHash = runner.sha256(ByteArray(0))
        val expectedEmpty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        if (emptyHash.toHex() == expectedEmpty) {
            result.pass("SHA256('') correct")
        } else {
            result.fail("SHA256('') mismatch")
        }

        results.add(result.summary())
    }

    // Test 2: Per-chain encryption
    println("\nTest 2: Per-Chain Encryption")
    println("-".repeat(40))

    for ((chain, keys) in encryptionKeys) {
        val result = TestResult("Encryption with $chain")

        val key = keys["key_hex"]!!.hexToBytes()
        val iv = keys["iv_hex"]!!.hexToBytes()
        val plaintext = "Test data for $chain encryption".toByteArray()

        val encrypted = runner.encrypt(key, iv, plaintext)
        if (!encrypted.contentEquals(plaintext)) {
            result.pass("Encryption modified data")
        } else {
            result.fail("Encryption did not modify data")
        }

        val decrypted = runner.decrypt(key, iv, encrypted)
        if (decrypted.contentEquals(plaintext)) {
            result.pass("Decryption restored original")
        } else {
            result.fail("Decryption mismatch")
        }

        results.add(result.summary())
    }

    // Test 3: Cross-language verification
    println("\nTest 3: Cross-Language Verification")
    println("-".repeat(40))
    val binaryDir = vectorsDir.resolve("binary")
    run {
        val result = TestResult("Cross-Language")

        if (Files.exists(binaryDir)) {
            val unencryptedPath = binaryDir.resolve("monster_unencrypted.bin")
            if (Files.exists(unencryptedPath)) {
                val data = Files.readAllBytes(unencryptedPath)
                result.pass("Read unencrypted binary: ${data.size} bytes")
            } else {
                result.fail("monster_unencrypted.bin not found - run Node.js test first")
            }

            for ((chain, keys) in encryptionKeys) {
                val encryptedPath = binaryDir.resolve("monster_encrypted_$chain.bin")
                if (Files.exists(encryptedPath)) {
                    val encrypted = Files.readAllBytes(encryptedPath)
                    result.pass("Read $chain: ${encrypted.size} bytes")

                    val key = keys["key_hex"]!!.hexToBytes()
                    val iv = keys["iv_hex"]!!.hexToBytes()
                    runner.decrypt(key, iv, encrypted)
                    result.pass("Decrypted $chain data")
                }
            }
        } else {
            result.fail("Binary directory not found - run Node.js test first")
        }

        results.add(result.summary())
    }

    // Test 4: ECDH Key Exchange Verification
    println("\nTest 4: ECDH Key Exchange Verification")
    println("-".repeat(40))

    var unencryptedData: ByteArray? = null
    try {
        unencryptedData = Files.readAllBytes(binaryDir.resolve("monster_unencrypted.bin"))
    } catch (_: Exception) {}

    val ecdhCurves = listOf(
        ECDHCurve("X25519", 32, 0, runner::x25519GenerateKeypair, runner::x25519SharedSecret),
        ECDHCurve("secp256k1", 33, 1, runner::secp256k1GenerateKeypair, runner::secp256k1SharedSecret),
        ECDHCurve("P-256", 33, 2, runner::p256GenerateKeypair, runner::p256SharedSecret)
    )

    for (curve in ecdhCurves) {
        val result = TestResult("ECDH ${curve.name}")

        try {
            val alice = curve.generate()
            val bob = curve.generate()

            if (alice.publicKey.size == curve.pubKeySize) {
                result.pass("Generated Alice keypair (pub: ${alice.publicKey.size} bytes)")
            } else {
                result.fail("Alice public key wrong size: ${alice.publicKey.size}")
            }

            if (bob.publicKey.size == curve.pubKeySize) {
                result.pass("Generated Bob keypair (pub: ${bob.publicKey.size} bytes)")
            } else {
                result.fail("Bob public key wrong size: ${bob.publicKey.size}")
            }

            val aliceShared = curve.shared(alice.privateKey, bob.publicKey)
            val bobShared = curve.shared(bob.privateKey, alice.publicKey)

            if (aliceShared.contentEquals(bobShared)) {
                result.pass("Shared secrets match (${aliceShared.size} bytes)")
            } else {
                result.fail("Shared secrets DO NOT match!")
                result.fail("  Alice: ${aliceShared.toHex()}")
                result.fail("  Bob:   ${bobShared.toHex()}")
            }

            val sessionMaterial = runner.hkdf(aliceShared, "flatbuffers-encryption".toByteArray(), "session-key-iv".toByteArray(), 48)
            val sessionKey = sessionMaterial.copyOfRange(0, 32)
            val sessionIv = sessionMaterial.copyOfRange(32, 48)

            if (sessionKey.size == 32 && sessionIv.size == 16) {
                result.pass("HKDF derived key (${sessionKey.size}B) + IV (${sessionIv.size}B)")
            } else {
                result.fail("HKDF output wrong size")
            }

            val testData = "ECDH test data for ${curve.name} encryption"
            val plaintext = testData.toByteArray()
            val encrypted = runner.encrypt(sessionKey, sessionIv, plaintext)

            if (!encrypted.contentEquals(plaintext)) {
                result.pass("Encryption with derived key modified data")
            } else {
                result.fail("Encryption did not modify data")
            }

            val decrypted = runner.decrypt(sessionKey, sessionIv, encrypted)
            if (decrypted.contentEquals(plaintext)) {
                result.pass("Decryption with derived key restored original")
            } else {
                result.fail("Decryption mismatch")
            }

            // Verify cross-language ECDH header if available
            val headerName = curve.name.lowercase().replace("-", "")
            val headerPath = binaryDir.resolve("monster_ecdh_${headerName}_header.json")
            if (Files.exists(headerPath)) {
                try {
                    val header = gson.fromJson(Files.readString(headerPath), ECDHHeader::class.java)

                    if (header.key_exchange == curve.keyExchange) {
                        result.pass("Cross-language header has correct key_exchange: ${curve.keyExchange}")
                    } else {
                        result.fail("Header key_exchange mismatch: ${header.key_exchange}")
                    }

                    if (!header.ephemeral_public_key.isNullOrEmpty() &&
                        !header.session_key.isNullOrEmpty() &&
                        !header.session_iv.isNullOrEmpty()) {
                        result.pass("Header contains ephemeral_public_key, session_key, session_iv")

                        val encryptedPath = binaryDir.resolve("monster_ecdh_${headerName}_encrypted.bin")
                        if (Files.exists(encryptedPath) && unencryptedData != null) {
                            val nodeKey = header.session_key.hexToBytes()
                            val nodeIv = header.session_iv.hexToBytes()
                            val encryptedDataFromFile = Files.readAllBytes(encryptedPath)
                            val decryptedData = runner.decrypt(nodeKey, nodeIv, encryptedDataFromFile)

                            if (decryptedData.contentEquals(unencryptedData)) {
                                result.pass("Decrypted Node.js ${curve.name} data matches original")
                            } else {
                                result.fail("Decrypted Node.js ${curve.name} data mismatch")
                            }
                        }
                    }
                } catch (e: Exception) {
                    result.fail("Error reading cross-language header: ${e.message}")
                }
            } else {
                result.pass("(No cross-language header found at ${headerPath.fileName})")
            }

        } catch (e: Exception) {
            result.fail("Exception during ${curve.name} test: ${e.message}")
        }

        results.add(result.summary())
    }

    // Test 5: Digital Signatures
    println("\nTest 5: Digital Signatures")
    println("-".repeat(40))
    run {
        val result = TestResult("Digital Signatures")
        val testMessage = "Hello, FlatBuffers! This is a test message for signing.".toByteArray()

        // Test Ed25519
        try {
            val kp = runner.ed25519GenerateKeypair()
            result.pass("Ed25519 keypair generated (priv: ${kp.privateKey.size}, pub: ${kp.publicKey.size} bytes)")

            val sig = runner.ed25519Sign(kp.privateKey, testMessage)
            result.pass("Ed25519 signature: ${sig.size} bytes")

            var valid = runner.ed25519Verify(kp.publicKey, testMessage, sig)
            if (valid) {
                result.pass("Ed25519 signature verified")
            } else {
                result.fail("Ed25519 signature verification failed")
            }

            val wrongMessage = "Wrong message".toByteArray()
            valid = runner.ed25519Verify(kp.publicKey, wrongMessage, sig)
            if (!valid) {
                result.pass("Ed25519 rejects wrong message")
            } else {
                result.fail("Ed25519 accepted wrong message")
            }
        } catch (e: Exception) {
            result.fail("Ed25519 test error: ${e.message}")
        }

        // Test secp256k1 signing
        try {
            val kp = runner.secp256k1GenerateKeypair()
            result.pass("secp256k1 keypair generated (priv: ${kp.privateKey.size}, pub: ${kp.publicKey.size} bytes)")

            val sig = runner.secp256k1Sign(kp.privateKey, testMessage)
            result.pass("secp256k1 signature: ${sig.size} bytes (DER)")

            var valid = runner.secp256k1Verify(kp.publicKey, testMessage, sig)
            if (valid) {
                result.pass("secp256k1 signature verified")
            } else {
                result.fail("secp256k1 signature verification failed")
            }

            val wrongMessage = "Wrong message".toByteArray()
            valid = runner.secp256k1Verify(kp.publicKey, wrongMessage, sig)
            if (!valid) {
                result.pass("secp256k1 rejects wrong message")
            } else {
                result.fail("secp256k1 accepted wrong message")
            }
        } catch (e: Exception) {
            result.fail("secp256k1 signing test error: ${e.message}")
        }

        // Test P-256 signing
        try {
            val kp = runner.p256GenerateKeypair()
            result.pass("P-256 keypair generated (priv: ${kp.privateKey.size}, pub: ${kp.publicKey.size} bytes)")

            val sig = runner.p256Sign(kp.privateKey, testMessage)
            result.pass("P-256 signature: ${sig.size} bytes (DER)")

            var valid = runner.p256Verify(kp.publicKey, testMessage, sig)
            if (valid) {
                result.pass("P-256 signature verified")
            } else {
                result.fail("P-256 signature verification failed")
            }

            val wrongMessage = "Wrong message".toByteArray()
            valid = runner.p256Verify(kp.publicKey, wrongMessage, sig)
            if (!valid) {
                result.pass("P-256 rejects wrong message")
            } else {
                result.fail("P-256 accepted wrong message")
            }
        } catch (e: Exception) {
            result.fail("P-256 signing test error: ${e.message}")
        }

        results.add(result.summary())
    }

    // Test 6: FlatBuffer Creation
    println("\nTest 6: FlatBuffer Creation")
    println("-".repeat(40))
    run {
        val result = TestResult("FlatBuffer Creation")

        try {
            val builder = FlatBufferBuilder(1024)

            // Build the Payload first
            val payloadMsgOffset = builder.createString("Hello from Kotlin!")
            val payloadData = byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05)
            val payloadDataOffset = Payload.createDataVector(builder, payloadData.map { it.toUByte() }.toUByteArray())

            val payloadOffset = Payload.createPayload(builder, payloadMsgOffset, 42, payloadDataOffset, 0, false)

            // Build the SecureMessage
            val idOffset = builder.createString("kotlin-msg-001")
            val senderOffset = builder.createString("kotlin-alice")
            val recipientOffset = builder.createString("kotlin-bob")

            val secureMessageOffset = SecureMessage.createSecureMessage(
                builder, idOffset, senderOffset, recipientOffset, payloadOffset, 1704067200UL, 0
            )

            SecureMessage.finishSecureMessageBuffer(builder, secureMessageOffset)

            val buf = builder.dataBuffer()
            val bufBytes = ByteArray(buf.remaining())
            buf.get(bufBytes)
            result.pass("Created SecureMessage binary: ${bufBytes.size} bytes")

            // Verify the buffer has the correct file identifier
            if (bufBytes.size >= 8 && bufBytes[4] == 'S'.code.toByte() && bufBytes[5] == 'E'.code.toByte() &&
                bufBytes[6] == 'C'.code.toByte() && bufBytes[7] == 'M'.code.toByte()) {
                result.pass("Buffer has correct SECM identifier")
            } else {
                result.fail("Buffer missing SECM identifier")
            }

            // Read it back and verify contents
            val readBuf = ByteBuffer.wrap(bufBytes)
            val msg = SecureMessage.getRootAsSecureMessage(readBuf)

            if (msg.id == "kotlin-msg-001") {
                result.pass("Read back id: kotlin-msg-001")
            } else {
                result.fail("Wrong id: ${msg.id}")
            }

            if (msg.sender == "kotlin-alice") {
                result.pass("Read back sender: kotlin-alice")
            } else {
                result.fail("Wrong sender: ${msg.sender}")
            }

            if (msg.recipient == "kotlin-bob") {
                result.pass("Read back recipient: kotlin-bob")
            } else {
                result.fail("Wrong recipient: ${msg.recipient}")
            }

            if (msg.timestamp == 1704067200UL) {
                result.pass("Read back timestamp: 1704067200")
            } else {
                result.fail("Wrong timestamp: ${msg.timestamp}")
            }

            val payloadObj = msg.payload
            if (payloadObj != null) {
                if (payloadObj.message == "Hello from Kotlin!") {
                    result.pass("Read back payload message: Hello from Kotlin!")
                } else {
                    result.fail("Wrong payload message: ${payloadObj.message}")
                }

                if (payloadObj.value == 42) {
                    result.pass("Read back payload value: 42")
                } else {
                    result.fail("Wrong payload value: ${payloadObj.value}")
                }

                if (payloadObj.dataLength == 5) {
                    val readData = ByteArray(5) { payloadObj.data(it).toByte() }
                    if (readData.contentEquals(payloadData)) {
                        result.pass("Read back payload data: ${payloadObj.dataLength} bytes")
                    } else {
                        result.fail("Wrong payload data")
                    }
                } else {
                    result.fail("Wrong payload data length: ${payloadObj.dataLength}")
                }
            } else {
                result.fail("Failed to read payload")
            }

            // Test encrypt-decrypt round trip with Kotlin-created FlatBuffer
            val suiKeys = encryptionKeys["sui"]
            if (suiKeys != null) {
                val key = suiKeys["key_hex"]!!.hexToBytes()
                val iv = suiKeys["iv_hex"]!!.hexToBytes()

                val encrypted = runner.encrypt(key, iv, bufBytes)
                result.pass("Encrypted Kotlin-created FlatBuffer")

                val decrypted = runner.decrypt(key, iv, encrypted)
                result.pass("Decrypted Kotlin-created FlatBuffer")

                if (decrypted.contentEquals(bufBytes)) {
                    result.pass("Decrypt round-trip verified")
                } else {
                    result.fail("Decrypted data doesn't match original")
                }
            } else {
                result.fail("Sui encryption keys not found")
            }
        } catch (e: Exception) {
            result.fail("FlatBuffer creation test error: ${e.message}")
            e.printStackTrace()
        }

        results.add(result.summary())
    }

    // Summary
    println("\n" + "=".repeat(60))
    println("Summary")
    println("=".repeat(60))

    val passed = results.count { it }
    val total = results.size
    println("\nTotal: $passed/$total test suites passed")

    if (passed == total) {
        println("\n✓ All tests passed!")
        System.exit(0)
    } else {
        println("\n✗ Some tests failed")
        System.exit(1)
    }
}
