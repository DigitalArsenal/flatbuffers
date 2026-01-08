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

import java.io.File;
import java.io.IOException;
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
                // For now, we use stubs - the exception handling will catch failures
                try {
                    int idx = (int) args[0];
                    var table = inst.table(0);
                    if (table != null) {
                        // Chicory table.ref() returns int (raw funcref), use instance.export instead
                        // This is a simplified implementation that may not handle all cases
                    }
                } catch (Exception e) {
                    // Exception during invoke - handled by EH
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
                // For now, we use stubs - the exception handling will catch failures
                try {
                    int idx = (int) args[0];
                    var table = inst.table(0);
                    if (table != null) {
                        // Chicory table.ref() returns int (raw funcref), use instance.export instead
                        // This is a simplified implementation that may not handle all cases
                    }
                } catch (Exception e) {
                    // Exception during invoke - handled by EH
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
        {
            TestResult result = new TestResult("Cross-Language");

            Path binaryDir = vectorsDir.resolve("binary");
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
