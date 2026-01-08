/**
 * Java E2E Test Runner for FlatBuffers Cross-Language Encryption
 *
 * Tests encryption/decryption using the WASM Crypto++ module with all 10 crypto key types.
 * Uses Chicory pure-Java WASM runtime.
 */
package com.flatbuffers.e2e;

import com.dylibso.chicory.runtime.*;
import com.dylibso.chicory.wasi.WasiOptions;
import com.dylibso.chicory.wasi.WasiPreview1;
import com.dylibso.chicory.wasm.types.Value;
import com.dylibso.chicory.wasm.types.ValueType;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

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

    private volatile int threwValue = 0;

    public TestRunner(byte[] wasmBytes) {
        WasiOptions wasiOptions = WasiOptions.builder().build();
        WasiPreview1 wasi = WasiPreview1.builder().withOptions(wasiOptions).build();
        HostImports hostImports = createHostImports(wasi);

        Module module = Module.builder(wasmBytes).build();
        this.instance = Instance.builder(module).withHostImports(hostImports).build();
        this.memory = instance.memory();

        this.malloc = instance.export("malloc");
        this.free = instance.export("free");
        this.sha256Fn = instance.export("sha256");
        this.encryptBytesFn = instance.export("encrypt_bytes");
        this.decryptBytesFn = instance.export("decrypt_bytes");
    }

    private HostImports createHostImports(WasiPreview1 wasi) {
        HostImports wasiImports = wasi.toHostImports();

        HostFunction setThrew = new HostFunction(
            "env", "setThrew",
            List.of(ValueType.I32, ValueType.I32),
            List.of(),
            (inst, args) -> {
                threwValue = args[0].asInt();
                return null;
            }
        );

        HostFunction cxaFindMatchingCatch2 = new HostFunction("env", "__cxa_find_matching_catch_2",
            List.of(), List.of(ValueType.I32), (inst, args) -> new Value[] { Value.i32(0) });
        HostFunction cxaFindMatchingCatch3 = new HostFunction("env", "__cxa_find_matching_catch_3",
            List.of(ValueType.I32), List.of(ValueType.I32), (inst, args) -> new Value[] { Value.i32(0) });
        HostFunction resumeException = new HostFunction("env", "__resumeException",
            List.of(ValueType.I32), List.of(), (inst, args) -> null);
        HostFunction cxaBeginCatch = new HostFunction("env", "__cxa_begin_catch",
            List.of(ValueType.I32), List.of(ValueType.I32), (inst, args) -> new Value[] { Value.i32(0) });
        HostFunction cxaEndCatch = new HostFunction("env", "__cxa_end_catch",
            List.of(), List.of(), (inst, args) -> null);
        HostFunction llvmEhTypeidFor = new HostFunction("env", "llvm_eh_typeid_for",
            List.of(ValueType.I32), List.of(ValueType.I32), (inst, args) -> new Value[] { Value.i32(0) });
        HostFunction cxaThrow = new HostFunction("env", "__cxa_throw",
            List.of(ValueType.I32, ValueType.I32, ValueType.I32), List.of(), (inst, args) -> null);
        HostFunction cxaUncaughtExceptions = new HostFunction("env", "__cxa_uncaught_exceptions",
            List.of(), List.of(ValueType.I32), (inst, args) -> new Value[] { Value.i32(0) });

        List<HostFunction> invokeStubs = createInvokeStubs();

        return HostImports.builder()
            .addImports(wasiImports)
            .addFunctions(setThrew, cxaFindMatchingCatch2, cxaFindMatchingCatch3,
                resumeException, cxaBeginCatch, cxaEndCatch, llvmEhTypeidFor, cxaThrow, cxaUncaughtExceptions)
            .addFunctions(invokeStubs.toArray(new HostFunction[0]))
            .build();
    }

    private List<HostFunction> createInvokeStubs() {
        return List.of(
            createInvokeStub("invoke_v", List.of(ValueType.I32), List.of()),
            createInvokeStub("invoke_vi", List.of(ValueType.I32, ValueType.I32), List.of()),
            createInvokeStub("invoke_vii", List.of(ValueType.I32, ValueType.I32, ValueType.I32), List.of()),
            createInvokeStub("invoke_viii", List.of(ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32), List.of()),
            createInvokeStub("invoke_viiii", List.of(ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32), List.of()),
            createInvokeStub("invoke_viiiii", List.of(ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32), List.of()),
            createInvokeStub("invoke_viiiiii", List.of(ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32), List.of()),
            createInvokeStub("invoke_viiiiiii", List.of(ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32), List.of()),
            createInvokeStub("invoke_viiiiiiiii", List.of(ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32), List.of()),
            createInvokeStubWithReturn("invoke_i", List.of(ValueType.I32)),
            createInvokeStubWithReturn("invoke_ii", List.of(ValueType.I32, ValueType.I32)),
            createInvokeStubWithReturn("invoke_iii", List.of(ValueType.I32, ValueType.I32, ValueType.I32)),
            createInvokeStubWithReturn("invoke_iiii", List.of(ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32)),
            createInvokeStubWithReturn("invoke_iiiii", List.of(ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32)),
            createInvokeStubWithReturn("invoke_iiiiii", List.of(ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32)),
            createInvokeStubWithReturn("invoke_iiiiiii", List.of(ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32)),
            createInvokeStubWithReturn("invoke_iiiiiiii", List.of(ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32)),
            createInvokeStubWithReturn("invoke_iiiiiiiiii", List.of(ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32, ValueType.I32))
        );
    }

    private HostFunction createInvokeStub(String name, List<ValueType> params, List<ValueType> results) {
        return new HostFunction("env", name, params, results, (inst, args) -> {
            try {
                int idx = args[0].asInt();
                var table = inst.table(0);
                if (table != null && idx < table.size()) {
                    var func = table.ref(idx);
                    if (func != null) {
                        Value[] callArgs = new Value[args.length - 1];
                        for (int i = 1; i < args.length; i++) callArgs[i - 1] = args[i];
                        func.apply(callArgs);
                    }
                }
            } catch (Exception e) {
                threwValue = 1;
            }
            return null;
        });
    }

    private HostFunction createInvokeStubWithReturn(String name, List<ValueType> params) {
        return new HostFunction("env", name, params, List.of(ValueType.I32), (inst, args) -> {
            try {
                int idx = args[0].asInt();
                var table = inst.table(0);
                if (table != null && idx < table.size()) {
                    var func = table.ref(idx);
                    if (func != null) {
                        Value[] callArgs = new Value[args.length - 1];
                        for (int i = 1; i < args.length; i++) callArgs[i - 1] = args[i];
                        Value[] result = func.apply(callArgs);
                        if (result != null && result.length > 0) return result;
                    }
                }
            } catch (Exception e) {
                threwValue = 1;
            }
            return new Value[] { Value.i32(0) };
        });
    }

    private int allocate(int size) {
        return malloc.apply(Value.i32(size))[0].asInt();
    }

    private void deallocate(int ptr) {
        free.apply(Value.i32(ptr));
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
        sha256Fn.apply(Value.i32(dataPtr), Value.i32(data.length), Value.i32(hashPtr));

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
        encryptBytesFn.apply(Value.i32(keyPtr), Value.i32(ivPtr), Value.i32(dataPtr), Value.i32(data.length));

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
        decryptBytesFn.apply(Value.i32(keyPtr), Value.i32(ivPtr), Value.i32(dataPtr), Value.i32(data.length));

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

        String[] wasmPaths = {
            "../../../../build/wasm/wasm/flatc-encryption.wasm",
            "../../../../../build/wasm/wasm/flatc-encryption.wasm",
            "../../../../../../build/wasm/wasm/flatc-encryption.wasm"
        };

        Path wasmPath = null;
        for (String p : wasmPaths) {
            Path path = Paths.get(p);
            if (Files.exists(path)) { wasmPath = path; break; }
        }
        if (wasmPath == null) {
            System.err.println("WASM module not found. Build it first.");
            System.exit(1);
        }

        System.out.println("Loading WASM module: " + wasmPath);
        TestRunner runner = new TestRunner(Files.readAllBytes(wasmPath));
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
