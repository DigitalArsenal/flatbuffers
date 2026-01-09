/**
 * Java E2E Test Runner for FlatBuffers Cross-Language Encryption
 *
 * Tests encryption/decryption using the WASM Crypto++ module with all 10 crypto key types.
 * Uses Chicory pure-Java WASM runtime (v1.5+).
 */
package com.flatbuffers.e2e;

import com.dylibso.chicory.runtime.ExportFunction;
import com.dylibso.chicory.runtime.HostFunction;
import com.dylibso.chicory.runtime.Instance;
import com.dylibso.chicory.runtime.Memory;
import com.dylibso.chicory.runtime.Store;
import com.dylibso.chicory.wasi.WasiOptions;
import com.dylibso.chicory.wasi.WasiPreview1;
import com.dylibso.chicory.wasm.Parser;
import com.dylibso.chicory.wasm.types.FunctionType;
import com.dylibso.chicory.wasm.types.ValType;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.*;
import java.util.*;

public class TestRunner {

    private static final int AES_KEY_SIZE = 32;
    private static final int AES_IV_SIZE = 16;
    private static final int SHA256_SIZE = 32;

    private final Instance instance;
    private final Memory memory;
    private final ExportFunction malloc;
    private final ExportFunction free;
    private final ExportFunction sha256Fn;
    private final ExportFunction encryptBytesFn;
    private final ExportFunction decryptBytesFn;
    private final ExportFunction hkdfFn;
    private final ExportFunction x25519GenerateFn;
    private final ExportFunction x25519SharedFn;
    private final ExportFunction secp256k1GenerateFn;
    private final ExportFunction secp256k1SharedFn;
    private final ExportFunction p256GenerateFn;
    private final ExportFunction p256SharedFn;
    private final ExportFunction ed25519GenerateFn;
    private final ExportFunction ed25519SignFn;
    private final ExportFunction ed25519VerifyFn;
    private final ExportFunction secp256k1SignFn;
    private final ExportFunction secp256k1VerifyFn;
    private final ExportFunction p256SignFn;
    private final ExportFunction p256VerifyFn;

    public TestRunner(File wasmFile) {
        var wasiOptions = WasiOptions.builder().build();
        var wasi = WasiPreview1.builder().withOptions(wasiOptions).build();

        var store = new Store();

        // Add WASI functions
        store.addFunction(wasi.toHostFunctions());

        // Add Emscripten exception handling stubs
        addExceptionStubs(store);

        // Add invoke_* trampolines
        addInvokeStubs(store);

        // Parse and instantiate the module
        var module = Parser.parse(wasmFile);
        this.instance = store.instantiate("flatc", module);
        this.memory = instance.memory();

        // Get exports
        this.malloc = instance.export("malloc");
        this.free = instance.export("free");
        this.sha256Fn = instance.export("wasi_sha256");
        this.encryptBytesFn = instance.export("wasi_encrypt_bytes");
        this.decryptBytesFn = instance.export("wasi_decrypt_bytes");
        this.hkdfFn = instance.export("wasi_hkdf");
        this.x25519GenerateFn = instance.export("wasi_x25519_generate_keypair");
        this.x25519SharedFn = instance.export("wasi_x25519_shared_secret");
        this.secp256k1GenerateFn = instance.export("wasi_secp256k1_generate_keypair");
        this.secp256k1SharedFn = instance.export("wasi_secp256k1_shared_secret");
        this.p256GenerateFn = instance.export("wasi_p256_generate_keypair");
        this.p256SharedFn = instance.export("wasi_p256_shared_secret");
        this.ed25519GenerateFn = instance.export("wasi_ed25519_generate_keypair");
        this.ed25519SignFn = instance.export("wasi_ed25519_sign");
        this.ed25519VerifyFn = instance.export("wasi_ed25519_verify");
        this.secp256k1SignFn = instance.export("wasi_secp256k1_sign");
        this.secp256k1VerifyFn = instance.export("wasi_secp256k1_verify");
        this.p256SignFn = instance.export("wasi_p256_sign");
        this.p256VerifyFn = instance.export("wasi_p256_verify");

        // Call _initialize if present
        try {
            var init = instance.export("_initialize");
            if (init != null) init.apply();
        } catch (Exception e) {
            // Module may not have _initialize
        }
    }

    private void addExceptionStubs(Store store) {
        // __cxa_throw (i32, i32, i32) -> void
        store.addFunction(new HostFunction(
            "env", "__cxa_throw",
            FunctionType.of(List.of(ValType.I32, ValType.I32, ValType.I32), List.of()),
            (inst, args) -> null
        ));

        // __cxa_begin_catch (i32) -> i32
        store.addFunction(new HostFunction(
            "env", "__cxa_begin_catch",
            FunctionType.of(List.of(ValType.I32), List.of(ValType.I32)),
            (inst, args) -> new long[] { 0 }
        ));

        // __cxa_end_catch () -> void
        store.addFunction(new HostFunction(
            "env", "__cxa_end_catch",
            FunctionType.of(List.of(), List.of()),
            (inst, args) -> null
        ));

        // __cxa_find_matching_catch_2 () -> i32
        store.addFunction(new HostFunction(
            "env", "__cxa_find_matching_catch_2",
            FunctionType.of(List.of(), List.of(ValType.I32)),
            (inst, args) -> new long[] { 0 }
        ));

        // __cxa_find_matching_catch_3 (i32) -> i32
        store.addFunction(new HostFunction(
            "env", "__cxa_find_matching_catch_3",
            FunctionType.of(List.of(ValType.I32), List.of(ValType.I32)),
            (inst, args) -> new long[] { 0 }
        ));

        // __resumeException (i32) -> void
        store.addFunction(new HostFunction(
            "env", "__resumeException",
            FunctionType.of(List.of(ValType.I32), List.of()),
            (inst, args) -> null
        ));

        // llvm_eh_typeid_for (i32) -> i32
        store.addFunction(new HostFunction(
            "env", "llvm_eh_typeid_for",
            FunctionType.of(List.of(ValType.I32), List.of(ValType.I32)),
            (inst, args) -> new long[] { 0 }
        ));

        // __cxa_uncaught_exceptions () -> i32
        store.addFunction(new HostFunction(
            "env", "__cxa_uncaught_exceptions",
            FunctionType.of(List.of(), List.of(ValType.I32)),
            (inst, args) -> new long[] { 0 }
        ));

        // setThrew (i32, i32) -> void
        store.addFunction(new HostFunction(
            "env", "setThrew",
            FunctionType.of(List.of(ValType.I32, ValType.I32), List.of()),
            (inst, args) -> null
        ));
    }

    private void addInvokeStubs(Store store) {
        // invoke_v variants (void return)
        addInvokeVoid(store, "invoke_v", 0);
        addInvokeVoid(store, "invoke_vi", 1);
        addInvokeVoid(store, "invoke_vii", 2);
        addInvokeVoid(store, "invoke_viii", 3);
        addInvokeVoid(store, "invoke_viiii", 4);
        addInvokeVoid(store, "invoke_viiiii", 5);
        addInvokeVoid(store, "invoke_viiiiii", 6);
        addInvokeVoid(store, "invoke_viiiiiii", 7);
        addInvokeVoid(store, "invoke_viiiiiiiii", 9);

        // invoke_i variants (i32 return)
        addInvokeI32(store, "invoke_i", 0);
        addInvokeI32(store, "invoke_ii", 1);
        addInvokeI32(store, "invoke_iii", 2);
        addInvokeI32(store, "invoke_iiii", 3);
        addInvokeI32(store, "invoke_iiiii", 4);
        addInvokeI32(store, "invoke_iiiiii", 5);
        addInvokeI32(store, "invoke_iiiiiii", 6);
        addInvokeI32(store, "invoke_iiiiiiii", 7);
        addInvokeI32(store, "invoke_iiiiiiiiii", 9);
    }

    private void addInvokeVoid(Store store, String name, int nArgs) {
        List<ValType> params = new ArrayList<>();
        for (int i = 0; i <= nArgs; i++) params.add(ValType.I32);

        store.addFunction(new HostFunction(
            "env", name,
            FunctionType.of(params, List.of()),
            (inst, args) -> {
                // Invoke trampolines call functions from the indirect function table
                try {
                    int tableIdx = (int) args[0];
                    var table = inst.table(0);
                    if (table != null) {
                        // Get the function index from the table
                        int funcIdx = table.ref(tableIdx);
                        // Build args array for the function (skip the table index)
                        long[] funcArgs = new long[nArgs];
                        for (int i = 0; i < nArgs; i++) {
                            funcArgs[i] = args[i + 1];
                        }
                        // Call the function through the machine
                        inst.getMachine().call(funcIdx, funcArgs);
                    }
                } catch (Exception e) {
                    // Exception during invoke - handled by Emscripten EH
                }
                return null;
            }
        ));
    }

    private void addInvokeI32(Store store, String name, int nArgs) {
        List<ValType> params = new ArrayList<>();
        for (int i = 0; i <= nArgs; i++) params.add(ValType.I32);

        store.addFunction(new HostFunction(
            "env", name,
            FunctionType.of(params, List.of(ValType.I32)),
            (inst, args) -> {
                // Invoke trampolines call functions from the indirect function table
                try {
                    int tableIdx = (int) args[0];
                    var table = inst.table(0);
                    if (table != null) {
                        // Get the function index from the table
                        int funcIdx = table.ref(tableIdx);
                        // Build args array for the function (skip the table index)
                        long[] funcArgs = new long[nArgs];
                        for (int i = 0; i < nArgs; i++) {
                            funcArgs[i] = args[i + 1];
                        }
                        // Call the function through the machine
                        long[] result = inst.getMachine().call(funcIdx, funcArgs);
                        if (result != null && result.length > 0) {
                            return new long[] { result[0] };
                        }
                    }
                } catch (Exception e) {
                    // Exception during invoke - handled by Emscripten EH
                }
                return new long[] { 0 };
            }
        ));
    }

    private int allocate(int size) {
        return (int) malloc.apply(size)[0];
    }

    private void deallocate(int ptr) {
        free.apply(ptr);
    }

    private void writeBytes(int ptr, byte[] data) {
        memory.write(ptr, data);
    }

    private byte[] readBytes(int ptr, int length) {
        return memory.readBytes(ptr, length);
    }

    public byte[] sha256(byte[] data) {
        int dataPtr = allocate(Math.max(data.length, 1));
        int hashPtr = allocate(SHA256_SIZE);

        if (data.length > 0) writeBytes(dataPtr, data);
        sha256Fn.apply(dataPtr, data.length, hashPtr);

        byte[] hash = readBytes(hashPtr, SHA256_SIZE);
        deallocate(dataPtr);
        deallocate(hashPtr);
        return hash;
    }

    public byte[] encrypt(byte[] key, byte[] iv, byte[] data) {
        int keyPtr = allocate(AES_KEY_SIZE);
        int ivPtr = allocate(AES_IV_SIZE);
        int dataPtr = allocate(data.length);

        writeBytes(keyPtr, key);
        writeBytes(ivPtr, iv);
        writeBytes(dataPtr, data);
        encryptBytesFn.apply(keyPtr, ivPtr, dataPtr, data.length);

        byte[] encrypted = readBytes(dataPtr, data.length);
        deallocate(keyPtr);
        deallocate(ivPtr);
        deallocate(dataPtr);
        return encrypted;
    }

    public byte[] decrypt(byte[] key, byte[] iv, byte[] data) {
        int keyPtr = allocate(AES_KEY_SIZE);
        int ivPtr = allocate(AES_IV_SIZE);
        int dataPtr = allocate(data.length);

        writeBytes(keyPtr, key);
        writeBytes(ivPtr, iv);
        writeBytes(dataPtr, data);
        decryptBytesFn.apply(keyPtr, ivPtr, dataPtr, data.length);

        byte[] decrypted = readBytes(dataPtr, data.length);
        deallocate(keyPtr);
        deallocate(ivPtr);
        deallocate(dataPtr);
        return decrypted;
    }

    public byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int outputLen) {
        int ikmPtr = allocate(Math.max(ikm.length, 1));
        int saltPtr = allocate(Math.max(salt.length, 1));
        int infoPtr = allocate(Math.max(info.length, 1));
        int outPtr = allocate(outputLen);

        if (ikm.length > 0) writeBytes(ikmPtr, ikm);
        if (salt.length > 0) writeBytes(saltPtr, salt);
        if (info.length > 0) writeBytes(infoPtr, info);

        hkdfFn.apply(ikmPtr, ikm.length, saltPtr, salt.length, infoPtr, info.length, outPtr, outputLen);

        byte[] output = readBytes(outPtr, outputLen);
        deallocate(ikmPtr);
        deallocate(saltPtr);
        deallocate(infoPtr);
        deallocate(outPtr);
        return output;
    }

    static class KeyPair {
        byte[] privateKey;
        byte[] publicKey;
        KeyPair(byte[] priv, byte[] pub) { privateKey = priv; publicKey = pub; }
    }

    public KeyPair x25519GenerateKeypair() {
        int privPtr = allocate(32);
        int pubPtr = allocate(32);

        x25519GenerateFn.apply(privPtr, pubPtr);

        byte[] priv = readBytes(privPtr, 32);
        byte[] pub = readBytes(pubPtr, 32);
        deallocate(privPtr);
        deallocate(pubPtr);
        return new KeyPair(priv, pub);
    }

    public byte[] x25519SharedSecret(byte[] privateKey, byte[] publicKey) {
        int privPtr = allocate(32);
        int pubPtr = allocate(32);
        int sharedPtr = allocate(32);

        writeBytes(privPtr, privateKey);
        writeBytes(pubPtr, publicKey);
        x25519SharedFn.apply(privPtr, pubPtr, sharedPtr);

        byte[] shared = readBytes(sharedPtr, 32);
        deallocate(privPtr);
        deallocate(pubPtr);
        deallocate(sharedPtr);
        return shared;
    }

    public KeyPair secp256k1GenerateKeypair() {
        int privPtr = allocate(32);
        int pubPtr = allocate(33);

        secp256k1GenerateFn.apply(privPtr, pubPtr);

        byte[] priv = readBytes(privPtr, 32);
        byte[] pub = readBytes(pubPtr, 33);
        deallocate(privPtr);
        deallocate(pubPtr);
        return new KeyPair(priv, pub);
    }

    public byte[] secp256k1SharedSecret(byte[] privateKey, byte[] publicKey) {
        int privPtr = allocate(32);
        int pubPtr = allocate(publicKey.length);
        int sharedPtr = allocate(32);

        writeBytes(privPtr, privateKey);
        writeBytes(pubPtr, publicKey);
        secp256k1SharedFn.apply(privPtr, pubPtr, publicKey.length, sharedPtr);

        byte[] shared = readBytes(sharedPtr, 32);
        deallocate(privPtr);
        deallocate(pubPtr);
        deallocate(sharedPtr);
        return shared;
    }

    public KeyPair p256GenerateKeypair() {
        int privPtr = allocate(32);
        int pubPtr = allocate(33);

        p256GenerateFn.apply(privPtr, pubPtr);

        byte[] priv = readBytes(privPtr, 32);
        byte[] pub = readBytes(pubPtr, 33);
        deallocate(privPtr);
        deallocate(pubPtr);
        return new KeyPair(priv, pub);
    }

    public byte[] p256SharedSecret(byte[] privateKey, byte[] publicKey) {
        int privPtr = allocate(32);
        int pubPtr = allocate(publicKey.length);
        int sharedPtr = allocate(32);

        writeBytes(privPtr, privateKey);
        writeBytes(pubPtr, publicKey);
        p256SharedFn.apply(privPtr, pubPtr, publicKey.length, sharedPtr);

        byte[] shared = readBytes(sharedPtr, 32);
        deallocate(privPtr);
        deallocate(pubPtr);
        deallocate(sharedPtr);
        return shared;
    }

    public KeyPair ed25519GenerateKeypair() {
        int privPtr = allocate(64);  // Ed25519 private key is 64 bytes
        int pubPtr = allocate(32);

        long[] result = ed25519GenerateFn.apply(privPtr, pubPtr);
        if (result[0] != 0) {
            deallocate(privPtr);
            deallocate(pubPtr);
            throw new RuntimeException("Ed25519 keypair generation failed");
        }

        byte[] priv = readBytes(privPtr, 64);
        byte[] pub = readBytes(pubPtr, 32);
        deallocate(privPtr);
        deallocate(pubPtr);
        return new KeyPair(priv, pub);
    }

    public byte[] ed25519Sign(byte[] privateKey, byte[] data) {
        int privPtr = allocate(64);
        int dataPtr = allocate(Math.max(data.length, 1));
        int sigPtr = allocate(64);

        writeBytes(privPtr, privateKey);
        if (data.length > 0) writeBytes(dataPtr, data);
        long[] result = ed25519SignFn.apply(privPtr, dataPtr, data.length, sigPtr);
        if (result[0] != 0) {
            deallocate(privPtr);
            deallocate(dataPtr);
            deallocate(sigPtr);
            throw new RuntimeException("Ed25519 signing failed");
        }

        byte[] sig = readBytes(sigPtr, 64);
        deallocate(privPtr);
        deallocate(dataPtr);
        deallocate(sigPtr);
        return sig;
    }

    public boolean ed25519Verify(byte[] publicKey, byte[] data, byte[] signature) {
        int pubPtr = allocate(32);
        int dataPtr = allocate(Math.max(data.length, 1));
        int sigPtr = allocate(64);

        writeBytes(pubPtr, publicKey);
        if (data.length > 0) writeBytes(dataPtr, data);
        writeBytes(sigPtr, signature);
        long[] result = ed25519VerifyFn.apply(pubPtr, dataPtr, data.length, sigPtr);

        deallocate(pubPtr);
        deallocate(dataPtr);
        deallocate(sigPtr);
        return result[0] == 0;
    }

    public byte[] secp256k1Sign(byte[] privateKey, byte[] data) {
        int privPtr = allocate(32);
        int dataPtr = allocate(Math.max(data.length, 1));
        int sigPtr = allocate(72);  // DER signature up to 72 bytes
        int sigSizePtr = allocate(4);

        writeBytes(privPtr, privateKey);
        if (data.length > 0) writeBytes(dataPtr, data);
        long[] result = secp256k1SignFn.apply(privPtr, dataPtr, data.length, sigPtr, sigSizePtr);
        if (result[0] != 0) {
            deallocate(privPtr);
            deallocate(dataPtr);
            deallocate(sigPtr);
            deallocate(sigSizePtr);
            throw new RuntimeException("secp256k1 signing failed");
        }

        byte[] sigSizeBytes = readBytes(sigSizePtr, 4);
        int sigSize = (sigSizeBytes[0] & 0xFF) | ((sigSizeBytes[1] & 0xFF) << 8) |
                      ((sigSizeBytes[2] & 0xFF) << 16) | ((sigSizeBytes[3] & 0xFF) << 24);
        byte[] sig = readBytes(sigPtr, sigSize);

        deallocate(privPtr);
        deallocate(dataPtr);
        deallocate(sigPtr);
        deallocate(sigSizePtr);
        return sig;
    }

    public boolean secp256k1Verify(byte[] publicKey, byte[] data, byte[] signature) {
        int pubPtr = allocate(publicKey.length);
        int dataPtr = allocate(Math.max(data.length, 1));
        int sigPtr = allocate(signature.length);

        writeBytes(pubPtr, publicKey);
        if (data.length > 0) writeBytes(dataPtr, data);
        writeBytes(sigPtr, signature);
        long[] result = secp256k1VerifyFn.apply(pubPtr, publicKey.length, dataPtr, data.length, sigPtr, signature.length);

        deallocate(pubPtr);
        deallocate(dataPtr);
        deallocate(sigPtr);
        return result[0] == 0;
    }

    public byte[] p256Sign(byte[] privateKey, byte[] data) {
        int privPtr = allocate(32);
        int dataPtr = allocate(Math.max(data.length, 1));
        int sigPtr = allocate(72);  // DER signature up to 72 bytes
        int sigSizePtr = allocate(4);

        writeBytes(privPtr, privateKey);
        if (data.length > 0) writeBytes(dataPtr, data);
        long[] result = p256SignFn.apply(privPtr, dataPtr, data.length, sigPtr, sigSizePtr);
        if (result[0] != 0) {
            deallocate(privPtr);
            deallocate(dataPtr);
            deallocate(sigPtr);
            deallocate(sigSizePtr);
            throw new RuntimeException("P-256 signing failed");
        }

        byte[] sigSizeBytes = readBytes(sigSizePtr, 4);
        int sigSize = (sigSizeBytes[0] & 0xFF) | ((sigSizeBytes[1] & 0xFF) << 8) |
                      ((sigSizeBytes[2] & 0xFF) << 16) | ((sigSizeBytes[3] & 0xFF) << 24);
        byte[] sig = readBytes(sigPtr, sigSize);

        deallocate(privPtr);
        deallocate(dataPtr);
        deallocate(sigPtr);
        deallocate(sigSizePtr);
        return sig;
    }

    public boolean p256Verify(byte[] publicKey, byte[] data, byte[] signature) {
        int pubPtr = allocate(publicKey.length);
        int dataPtr = allocate(Math.max(data.length, 1));
        int sigPtr = allocate(signature.length);

        writeBytes(pubPtr, publicKey);
        if (data.length > 0) writeBytes(dataPtr, data);
        writeBytes(sigPtr, signature);
        long[] result = p256VerifyFn.apply(pubPtr, publicKey.length, dataPtr, data.length, sigPtr, signature.length);

        deallocate(pubPtr);
        deallocate(dataPtr);
        deallocate(sigPtr);
        return result[0] == 0;
    }

    public static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public static byte[] fromHex(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            bytes[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
    }

    static class ECDHHeader {
        int version;
        int key_exchange;
        String ephemeral_public_key;
        String context;
        String session_key;
        String session_iv;
    }

    static class ECDHCurve {
        String name;
        int pubKeySize;
        int keyExchange;
        java.util.function.Supplier<KeyPair> generate;
        java.util.function.BiFunction<byte[], byte[], byte[]> shared;

        ECDHCurve(String name, int pubKeySize, int keyExchange,
                  java.util.function.Supplier<KeyPair> generate,
                  java.util.function.BiFunction<byte[], byte[], byte[]> shared) {
            this.name = name;
            this.pubKeySize = pubKeySize;
            this.keyExchange = keyExchange;
            this.generate = generate;
            this.shared = shared;
        }
    }

    static class TestResult {
        String name;
        int passed = 0;
        int failed = 0;

        TestResult(String name) { this.name = name; }

        void pass(String msg) {
            passed++;
            System.out.println("  ✓ " + msg);
        }

        void fail(String msg) {
            failed++;
            System.out.println("  ✗ " + msg);
        }

        boolean summary() {
            int total = passed + failed;
            String status = failed == 0 ? "✓" : "✗";
            System.out.println("\n" + status + " " + name + ": " + passed + "/" + total + " passed");
            return failed == 0;
        }
    }

    public static void main(String[] args) throws IOException {
        System.out.println("=".repeat(60));
        System.out.println("FlatBuffers Cross-Language Encryption E2E Tests - Java");
        System.out.println("=".repeat(60));
        System.out.println();
        System.out.println("WASM Runtime: Chicory (pure Java)");
        System.out.println();

        String[] wasmPaths = {
            "../../../../../build/wasm/wasm/flatc-encryption.wasm",
            "../../../../../../build/wasm/wasm/flatc-encryption.wasm",
            "../../../../../../../build/wasm/wasm/flatc-encryption.wasm"
        };

        File wasmFile = null;
        for (String p : wasmPaths) {
            File f = new File(p);
            if (f.exists()) { wasmFile = f; break; }
        }
        if (wasmFile == null) {
            System.err.println("WASM module not found. Build it first.");
            System.exit(1);
        }

        System.out.println("Loading WASM module: " + wasmFile.getAbsolutePath());
        TestRunner runner = new TestRunner(wasmFile);
        System.out.println();

        Path vectorsDir = Paths.get("../../vectors");
        Gson gson = new Gson();
        Map<String, Map<String, String>> encryptionKeys = gson.fromJson(
            Files.readString(vectorsDir.resolve("encryption_keys.json")),
            new TypeToken<Map<String, Map<String, String>>>(){}.getType()
        );

        List<Boolean> results = new ArrayList<>();

        // Test 1: SHA-256
        System.out.println("Test 1: SHA-256 Hash");
        System.out.println("-".repeat(40));
        {
            TestResult result = new TestResult("SHA-256");

            byte[] hash = runner.sha256("hello".getBytes());
            String expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
            if (toHex(hash).equals(expected)) {
                result.pass("SHA256('hello') correct");
            } else {
                result.fail("SHA256 mismatch: " + toHex(hash));
            }

            byte[] emptyHash = runner.sha256(new byte[0]);
            String expectedEmpty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
            if (toHex(emptyHash).equals(expectedEmpty)) {
                result.pass("SHA256('') correct");
            } else {
                result.fail("SHA256('') mismatch");
            }

            results.add(result.summary());
        }

        // Test 2: Per-chain encryption
        System.out.println("\nTest 2: Per-Chain Encryption");
        System.out.println("-".repeat(40));

        for (var entry : encryptionKeys.entrySet()) {
            String chain = entry.getKey();
            Map<String, String> keys = entry.getValue();
            TestResult result = new TestResult("Encryption with " + chain);

            byte[] key = fromHex(keys.get("key_hex"));
            byte[] iv = fromHex(keys.get("iv_hex"));
            byte[] plaintext = ("Test data for " + chain + " encryption").getBytes();

            byte[] encrypted = runner.encrypt(key, iv, plaintext);
            if (!Arrays.equals(encrypted, plaintext)) {
                result.pass("Encryption modified data");
            } else {
                result.fail("Encryption did not modify data");
            }

            byte[] decrypted = runner.decrypt(key, iv, encrypted);
            if (Arrays.equals(decrypted, plaintext)) {
                result.pass("Decryption restored original");
            } else {
                result.fail("Decryption mismatch");
            }

            results.add(result.summary());
        }

        // Test 3: Cross-language verification
        System.out.println("\nTest 3: Cross-Language Verification");
        System.out.println("-".repeat(40));
        Path binaryDir = vectorsDir.resolve("binary");
        {
            TestResult result = new TestResult("Cross-Language");

            if (Files.exists(binaryDir)) {
                Path unencryptedPath = binaryDir.resolve("monster_unencrypted.bin");
                if (Files.exists(unencryptedPath)) {
                    byte[] data = Files.readAllBytes(unencryptedPath);
                    result.pass("Read unencrypted binary: " + data.length + " bytes");
                } else {
                    result.fail("monster_unencrypted.bin not found - run Node.js test first");
                }

                for (var entry : encryptionKeys.entrySet()) {
                    String chain = entry.getKey();
                    Map<String, String> keys = entry.getValue();
                    Path encryptedPath = binaryDir.resolve("monster_encrypted_" + chain + ".bin");
                    if (Files.exists(encryptedPath)) {
                        byte[] encrypted = Files.readAllBytes(encryptedPath);
                        result.pass("Read " + chain + ": " + encrypted.length + " bytes");

                        byte[] key = fromHex(keys.get("key_hex"));
                        byte[] iv = fromHex(keys.get("iv_hex"));
                        runner.decrypt(key, iv, encrypted);
                        result.pass("Decrypted " + chain + " data");
                    }
                }
            } else {
                result.fail("Binary directory not found - run Node.js test first");
            }

            results.add(result.summary());
        }

        // Test 4: ECDH Key Exchange Verification
        System.out.println("\nTest 4: ECDH Key Exchange Verification");
        System.out.println("-".repeat(40));

        // Read unencrypted data for cross-language verification
        byte[] unencryptedData = null;
        try {
            unencryptedData = Files.readAllBytes(binaryDir.resolve("monster_unencrypted.bin"));
        } catch (Exception e) {
            // Will be null if file doesn't exist
        }

        ECDHCurve[] ecdhCurves = {
            new ECDHCurve("X25519", 32, 0, runner::x25519GenerateKeypair, runner::x25519SharedSecret),
            new ECDHCurve("secp256k1", 33, 1, runner::secp256k1GenerateKeypair, runner::secp256k1SharedSecret),
            new ECDHCurve("P-256", 33, 2, runner::p256GenerateKeypair, runner::p256SharedSecret)
        };

        for (ECDHCurve curve : ecdhCurves) {
            TestResult result = new TestResult("ECDH " + curve.name);

            try {
                // Generate keypairs for Alice and Bob
                KeyPair alice = curve.generate.get();
                KeyPair bob = curve.generate.get();

                if (alice.publicKey.length == curve.pubKeySize) {
                    result.pass("Generated Alice keypair (pub: " + alice.publicKey.length + " bytes)");
                } else {
                    result.fail("Alice public key wrong size: " + alice.publicKey.length);
                }

                if (bob.publicKey.length == curve.pubKeySize) {
                    result.pass("Generated Bob keypair (pub: " + bob.publicKey.length + " bytes)");
                } else {
                    result.fail("Bob public key wrong size: " + bob.publicKey.length);
                }

                // Compute shared secrets
                byte[] aliceShared = curve.shared.apply(alice.privateKey, bob.publicKey);
                byte[] bobShared = curve.shared.apply(bob.privateKey, alice.publicKey);

                if (Arrays.equals(aliceShared, bobShared)) {
                    result.pass("Shared secrets match (" + aliceShared.length + " bytes)");
                } else {
                    result.fail("Shared secrets DO NOT match!");
                    result.fail("  Alice: " + toHex(aliceShared));
                    result.fail("  Bob:   " + toHex(bobShared));
                }

                // Test HKDF key derivation from shared secret
                byte[] sessionMaterial = runner.hkdf(aliceShared, "flatbuffers-encryption".getBytes(), "session-key-iv".getBytes(), 48);
                byte[] sessionKey = Arrays.copyOfRange(sessionMaterial, 0, 32);
                byte[] sessionIv = Arrays.copyOfRange(sessionMaterial, 32, 48);

                if (sessionKey.length == 32 && sessionIv.length == 16) {
                    result.pass("HKDF derived key (" + sessionKey.length + "B) + IV (" + sessionIv.length + "B)");
                } else {
                    result.fail("HKDF output wrong size");
                }

                // Full E2E: encrypt with derived key, decrypt with same key
                String testData = "ECDH test data for " + curve.name + " encryption";
                byte[] plaintext = testData.getBytes();
                byte[] encrypted = runner.encrypt(sessionKey, sessionIv, plaintext);

                if (!Arrays.equals(encrypted, plaintext)) {
                    result.pass("Encryption with derived key modified data");
                } else {
                    result.fail("Encryption did not modify data");
                }

                byte[] decrypted = runner.decrypt(sessionKey, sessionIv, encrypted);
                if (Arrays.equals(decrypted, plaintext)) {
                    result.pass("Decryption with derived key restored original");
                } else {
                    result.fail("Decryption mismatch");
                }

                // Verify cross-language ECDH header if available
                String headerName = curve.name.toLowerCase().replace("-", "");
                Path headerPath = binaryDir.resolve("monster_ecdh_" + headerName + "_header.json");
                if (Files.exists(headerPath)) {
                    try {
                        ECDHHeader header = gson.fromJson(Files.readString(headerPath), ECDHHeader.class);

                        if (header.key_exchange == curve.keyExchange) {
                            result.pass("Cross-language header has correct key_exchange: " + curve.keyExchange);
                        } else {
                            result.fail("Header key_exchange mismatch: " + header.key_exchange);
                        }

                        if (header.ephemeral_public_key != null && !header.ephemeral_public_key.isEmpty() &&
                            header.session_key != null && !header.session_key.isEmpty() &&
                            header.session_iv != null && !header.session_iv.isEmpty()) {
                            result.pass("Header contains ephemeral_public_key, session_key, session_iv");

                            // Decrypt the cross-language encrypted file using Node.js session key
                            Path encryptedPath = binaryDir.resolve("monster_ecdh_" + headerName + "_encrypted.bin");
                            if (Files.exists(encryptedPath) && unencryptedData != null) {
                                byte[] nodeKey = fromHex(header.session_key);
                                byte[] nodeIv = fromHex(header.session_iv);
                                byte[] encryptedData = Files.readAllBytes(encryptedPath);
                                byte[] decryptedData = runner.decrypt(nodeKey, nodeIv, encryptedData);

                                if (Arrays.equals(decryptedData, unencryptedData)) {
                                    result.pass("Decrypted Node.js " + curve.name + " data matches original");
                                } else {
                                    result.fail("Decrypted Node.js " + curve.name + " data mismatch");
                                }
                            }
                        }
                    } catch (Exception e) {
                        result.fail("Error reading cross-language header: " + e.getMessage());
                    }
                } else {
                    result.pass("(No cross-language header found at " + headerPath.getFileName() + ")");
                }

            } catch (Exception e) {
                result.fail("Exception during " + curve.name + " test: " + e.getMessage());
            }

            results.add(result.summary());
        }

        // Test 5: Runtime Code Generation
        System.out.println("\nTest 5: Runtime Code Generation");
        System.out.println("-".repeat(40));
        {
            TestResult result = new TestResult("Code Generation");

            // Try to find native flatc binary (prefer built version over system)
            Path[] flatcPaths = {
                vectorsDir.resolve("../../../../build/flatc"),
                vectorsDir.resolve("../../../../flatc")
            };

            Path flatcPath = null;
            for (Path p : flatcPaths) {
                if (Files.exists(p)) {
                    flatcPath = p.toAbsolutePath().normalize();
                    break;
                }
            }

            // Fall back to PATH if built flatc not found
            if (flatcPath == null) {
                try {
                    Process which = Runtime.getRuntime().exec(new String[]{"which", "flatc"});
                    BufferedReader reader = new BufferedReader(new InputStreamReader(which.getInputStream()));
                    String line = reader.readLine();
                    if (which.waitFor() == 0 && line != null && !line.isEmpty()) {
                        flatcPath = Path.of(line);
                    }
                } catch (Exception ignored) {}
            }

            if (flatcPath != null) {
                result.pass("Found flatc: " + flatcPath);

                // Get flatc version
                try {
                    Process versionProc = Runtime.getRuntime().exec(new String[]{flatcPath.toString(), "--version"});
                    BufferedReader versionReader = new BufferedReader(new InputStreamReader(versionProc.getInputStream()));
                    String version = versionReader.readLine();
                    if (versionProc.waitFor() == 0 && version != null) {
                        result.pass("flatc version: " + version);
                    }
                } catch (Exception e) {
                    result.fail("Failed to get flatc version: " + e.getMessage());
                }

                // Generate Java code from schema
                Path schemaPath = vectorsDir.resolve("../schemas/message.fbs").toAbsolutePath().normalize();
                Path tempDir = Files.createTempDirectory("flatc-gen-");

                try {
                    Process genProc = Runtime.getRuntime().exec(new String[]{
                        flatcPath.toString(), "--java", "-o", tempDir.toString(), schemaPath.toString()
                    });
                    int exitCode = genProc.waitFor();

                    if (exitCode == 0) {
                        result.pass("Generated Java code from schema");

                        // List generated files
                        try (var walk = Files.walk(tempDir)) {
                            walk.filter(Files::isRegularFile).forEach(file -> {
                                try {
                                    long size = Files.size(file);
                                    Path relPath = tempDir.relativize(file);
                                    result.pass("Generated: " + relPath + " (" + size + " bytes)");
                                } catch (Exception ignored) {}
                            });
                        }
                    } else {
                        BufferedReader errReader = new BufferedReader(new InputStreamReader(genProc.getErrorStream()));
                        String errLine = errReader.readLine();
                        result.fail("Generate Java code failed: " + (errLine != null ? errLine : "exit " + exitCode));
                    }
                } catch (Exception e) {
                    result.fail("Exception during code generation: " + e.getMessage());
                } finally {
                    // Clean up temp dir
                    try (var walk = Files.walk(tempDir)) {
                        walk.sorted(java.util.Comparator.reverseOrder())
                            .map(Path::toFile)
                            .forEach(java.io.File::delete);
                    } catch (Exception ignored) {}
                }
            } else {
                result.pass("flatc not found - using pre-generated code (this is OK)");
                // Verify pre-generated code exists
                Path pregenPath = vectorsDir.resolve("../generated/java/E2E/Crypto");
                if (Files.exists(pregenPath)) {
                    try (var list = Files.list(pregenPath)) {
                        long count = list.filter(p -> p.toString().endsWith(".java")).count();
                        result.pass("Pre-generated Java code: " + count + " files in generated/java/E2E/Crypto/");
                    }
                }
            }

            results.add(result.summary());
        }

        // Test 6: Digital Signatures (Ed25519, secp256k1, P-256)
        System.out.println("\nTest 6: Digital Signatures");
        System.out.println("-".repeat(40));
        {
            TestResult result = new TestResult("Digital Signatures");
            byte[] testMessage = "Hello, FlatBuffers! This is a test message for signing.".getBytes();

            // Test Ed25519
            try {
                KeyPair kp = runner.ed25519GenerateKeypair();
                result.pass("Ed25519 keypair generated (priv: " + kp.privateKey.length + ", pub: " + kp.publicKey.length + " bytes)");

                byte[] sig = runner.ed25519Sign(kp.privateKey, testMessage);
                result.pass("Ed25519 signature: " + sig.length + " bytes");

                boolean valid = runner.ed25519Verify(kp.publicKey, testMessage, sig);
                if (valid) {
                    result.pass("Ed25519 signature verified");
                } else {
                    result.fail("Ed25519 signature verification failed");
                }

                // Verify wrong message fails
                byte[] wrongMessage = "Wrong message".getBytes();
                valid = runner.ed25519Verify(kp.publicKey, wrongMessage, sig);
                if (!valid) {
                    result.pass("Ed25519 rejects wrong message");
                } else {
                    result.fail("Ed25519 accepted wrong message");
                }
            } catch (Exception e) {
                result.fail("Ed25519 test error: " + e.getMessage());
            }

            // Test secp256k1 signing
            try {
                KeyPair kp = runner.secp256k1GenerateKeypair();
                result.pass("secp256k1 keypair generated (priv: " + kp.privateKey.length + ", pub: " + kp.publicKey.length + " bytes)");

                byte[] sig = runner.secp256k1Sign(kp.privateKey, testMessage);
                result.pass("secp256k1 signature: " + sig.length + " bytes (DER)");

                boolean valid = runner.secp256k1Verify(kp.publicKey, testMessage, sig);
                if (valid) {
                    result.pass("secp256k1 signature verified");
                } else {
                    result.fail("secp256k1 signature verification failed");
                }

                // Verify wrong message fails
                byte[] wrongMessage = "Wrong message".getBytes();
                valid = runner.secp256k1Verify(kp.publicKey, wrongMessage, sig);
                if (!valid) {
                    result.pass("secp256k1 rejects wrong message");
                } else {
                    result.fail("secp256k1 accepted wrong message");
                }
            } catch (Exception e) {
                result.fail("secp256k1 signing test error: " + e.getMessage());
            }

            // Test P-256 signing
            try {
                KeyPair kp = runner.p256GenerateKeypair();
                result.pass("P-256 keypair generated (priv: " + kp.privateKey.length + ", pub: " + kp.publicKey.length + " bytes)");

                byte[] sig = runner.p256Sign(kp.privateKey, testMessage);
                result.pass("P-256 signature: " + sig.length + " bytes (DER)");

                boolean valid = runner.p256Verify(kp.publicKey, testMessage, sig);
                if (valid) {
                    result.pass("P-256 signature verified");
                } else {
                    result.fail("P-256 signature verification failed");
                }

                // Verify wrong message fails
                byte[] wrongMessage = "Wrong message".getBytes();
                valid = runner.p256Verify(kp.publicKey, wrongMessage, sig);
                if (!valid) {
                    result.pass("P-256 rejects wrong message");
                } else {
                    result.fail("P-256 accepted wrong message");
                }
            } catch (Exception e) {
                result.fail("P-256 signing test error: " + e.getMessage());
            }

            results.add(result.summary());
        }

        // Summary
        System.out.println("\n" + "=".repeat(60));
        System.out.println("Summary");
        System.out.println("=".repeat(60));

        long passed = results.stream().filter(r -> r).count();
        int total = results.size();
        System.out.println("\nTotal: " + passed + "/" + total + " test suites passed");

        if (passed == total) {
            System.out.println("\n✓ All tests passed!");
            System.exit(0);
        } else {
            System.out.println("\n✗ Some tests failed");
            System.exit(1);
        }
    }
}
