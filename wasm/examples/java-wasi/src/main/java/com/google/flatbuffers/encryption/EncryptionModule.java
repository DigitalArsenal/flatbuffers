package com.google.flatbuffers.encryption;

import com.dylibso.chicory.runtime.ExportFunction;
import com.dylibso.chicory.runtime.HostFunction;
import com.dylibso.chicory.runtime.HostImports;
import com.dylibso.chicory.runtime.Instance;
import com.dylibso.chicory.runtime.Memory;
import com.dylibso.chicory.runtime.Module;
import com.dylibso.chicory.runtime.Store;
import com.dylibso.chicory.wasi.WasiOptions;
import com.dylibso.chicory.wasi.WasiPreview1;
import com.dylibso.chicory.wasm.types.Value;
import com.dylibso.chicory.wasm.types.ValueType;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.List;

/**
 * FlatBuffers WASI Encryption Module for Java.
 *
 * This class provides encryption functionality using Crypto++ compiled to WASM,
 * executed via the Chicory pure-Java WebAssembly runtime.
 *
 * Features:
 * - AES-256-CTR symmetric encryption
 * - X25519 ECDH key exchange
 * - secp256k1 ECDH and ECDSA signatures (Bitcoin/Ethereum compatible)
 * - P-256 ECDH and ECDSA signatures (NIST)
 * - Ed25519 signatures
 * - SHA-256 hashing
 * - HKDF key derivation
 */
public class EncryptionModule implements AutoCloseable {

    // Key and signature sizes
    public static final int AES_KEY_SIZE = 32;
    public static final int AES_IV_SIZE = 16;
    public static final int SHA256_SIZE = 32;
    public static final int SHARED_SECRET_SIZE = 32;

    public static final int X25519_PRIVATE_KEY_SIZE = 32;
    public static final int X25519_PUBLIC_KEY_SIZE = 32;

    public static final int SECP256K1_PRIVATE_KEY_SIZE = 32;
    public static final int SECP256K1_PUBLIC_KEY_SIZE = 33;  // compressed
    public static final int SECP256K1_SIGNATURE_SIZE = 72;   // DER encoded max

    public static final int P256_PRIVATE_KEY_SIZE = 32;
    public static final int P256_PUBLIC_KEY_SIZE = 33;       // compressed
    public static final int P256_SIGNATURE_SIZE = 72;        // DER encoded max

    public static final int ED25519_PRIVATE_KEY_SIZE = 64;   // seed + public key
    public static final int ED25519_PUBLIC_KEY_SIZE = 32;
    public static final int ED25519_SIGNATURE_SIZE = 64;

    private static final String DEFAULT_WASM_PATH = "../../../build/wasm/wasm/flatc-encryption.wasm";

    private final Instance instance;
    private final Memory memory;
    private final SecureRandom random = new SecureRandom();

    // Exported functions
    private final ExportFunction malloc;
    private final ExportFunction free;
    private final ExportFunction getVersion;
    private final ExportFunction hasCryptopp;
    private final ExportFunction encryptBytes;
    private final ExportFunction decryptBytes;
    private final ExportFunction sha256;
    private final ExportFunction hkdf;
    private final ExportFunction x25519GenerateKeypair;
    private final ExportFunction x25519SharedSecret;
    private final ExportFunction secp256k1GenerateKeypair;
    private final ExportFunction secp256k1SharedSecret;
    private final ExportFunction secp256k1Sign;
    private final ExportFunction secp256k1Verify;
    private final ExportFunction p256GenerateKeypair;
    private final ExportFunction p256SharedSecret;
    private final ExportFunction p256Sign;
    private final ExportFunction p256Verify;
    private final ExportFunction ed25519GenerateKeypair;
    private final ExportFunction ed25519Sign;
    private final ExportFunction ed25519Verify;
    private final ExportFunction deriveSymmetricKey;

    // Exception state from Emscripten
    private volatile int threwValue = 0;
    private volatile int threwType = 0;

    /**
     * Creates a new EncryptionModule using the default WASM path.
     */
    public EncryptionModule() throws IOException {
        this(Path.of(DEFAULT_WASM_PATH));
    }

    /**
     * Creates a new EncryptionModule from the specified WASM file path.
     */
    public EncryptionModule(Path wasmPath) throws IOException {
        this(Files.readAllBytes(wasmPath));
    }

    /**
     * Creates a new EncryptionModule from WASM bytes.
     */
    public EncryptionModule(byte[] wasmBytes) {
        // Create WASI with minimal configuration
        WasiOptions wasiOptions = WasiOptions.builder().build();
        WasiPreview1 wasi = WasiPreview1.builder().withOptions(wasiOptions).build();

        // Create host imports for Emscripten exception handling
        HostImports hostImports = createHostImports(wasi);

        // Parse and instantiate the module
        Module module = Module.builder(wasmBytes).build();
        this.instance = Instance.builder(module)
            .withHostImports(hostImports)
            .build();

        this.memory = instance.memory();

        // Get exported functions
        this.malloc = instance.export("malloc");
        this.free = instance.export("free");
        this.getVersion = instance.export("get_version");
        this.hasCryptopp = instance.export("has_cryptopp");
        this.encryptBytes = instance.export("encrypt_bytes");
        this.decryptBytes = instance.export("decrypt_bytes");
        this.sha256 = instance.export("sha256");
        this.hkdf = instance.export("hkdf");
        this.x25519GenerateKeypair = instance.export("x25519_generate_keypair");
        this.x25519SharedSecret = instance.export("x25519_shared_secret");
        this.secp256k1GenerateKeypair = instance.export("secp256k1_generate_keypair");
        this.secp256k1SharedSecret = instance.export("secp256k1_shared_secret");
        this.secp256k1Sign = instance.export("secp256k1_sign");
        this.secp256k1Verify = instance.export("secp256k1_verify");
        this.p256GenerateKeypair = instance.export("p256_generate_keypair");
        this.p256SharedSecret = instance.export("p256_shared_secret");
        this.p256Sign = instance.export("p256_sign");
        this.p256Verify = instance.export("p256_verify");
        this.ed25519GenerateKeypair = instance.export("ed25519_generate_keypair");
        this.ed25519Sign = instance.export("ed25519_sign");
        this.ed25519Verify = instance.export("ed25519_verify");
        this.deriveSymmetricKey = instance.export("derive_symmetric_key");
    }

    private HostImports createHostImports(WasiPreview1 wasi) {
        // Get WASI imports
        HostImports wasiImports = wasi.toHostImports();

        // Create Emscripten exception handling stubs
        HostFunction setThrew = new HostFunction(
            "env", "setThrew",
            List.of(ValueType.I32, ValueType.I32),
            List.of(),
            (inst, args) -> {
                threwValue = args[0].asInt();
                threwType = args[1].asInt();
                return null;
            }
        );

        HostFunction cxaFindMatchingCatch2 = new HostFunction(
            "env", "__cxa_find_matching_catch_2",
            List.of(),
            List.of(ValueType.I32),
            (inst, args) -> new Value[] { Value.i32(0) }
        );

        HostFunction cxaFindMatchingCatch3 = new HostFunction(
            "env", "__cxa_find_matching_catch_3",
            List.of(ValueType.I32),
            List.of(ValueType.I32),
            (inst, args) -> new Value[] { Value.i32(0) }
        );

        HostFunction resumeException = new HostFunction(
            "env", "__resumeException",
            List.of(ValueType.I32),
            List.of(),
            (inst, args) -> null
        );

        HostFunction cxaBeginCatch = new HostFunction(
            "env", "__cxa_begin_catch",
            List.of(ValueType.I32),
            List.of(ValueType.I32),
            (inst, args) -> new Value[] { Value.i32(0) }
        );

        HostFunction cxaEndCatch = new HostFunction(
            "env", "__cxa_end_catch",
            List.of(),
            List.of(),
            (inst, args) -> null
        );

        HostFunction llvmEhTypeidFor = new HostFunction(
            "env", "llvm_eh_typeid_for",
            List.of(ValueType.I32),
            List.of(ValueType.I32),
            (inst, args) -> new Value[] { Value.i32(0) }
        );

        HostFunction cxaThrow = new HostFunction(
            "env", "__cxa_throw",
            List.of(ValueType.I32, ValueType.I32, ValueType.I32),
            List.of(),
            (inst, args) -> null
        );

        HostFunction cxaUncaughtExceptions = new HostFunction(
            "env", "__cxa_uncaught_exceptions",
            List.of(),
            List.of(ValueType.I32),
            (inst, args) -> new Value[] { Value.i32(0) }
        );

        // Create invoke_* trampolines that call the function table
        // These are needed for Emscripten exception handling
        List<HostFunction> invokeStubs = createInvokeStubs();

        // Combine all imports
        HostFunction[] envFunctions = new HostFunction[] {
            setThrew,
            cxaFindMatchingCatch2,
            cxaFindMatchingCatch3,
            resumeException,
            cxaBeginCatch,
            cxaEndCatch,
            llvmEhTypeidFor,
            cxaThrow,
            cxaUncaughtExceptions
        };

        // Merge WASI and env imports
        return HostImports.builder()
            .addImports(wasiImports)
            .addFunctions(envFunctions)
            .addFunctions(invokeStubs.toArray(new HostFunction[0]))
            .build();
    }

    private List<HostFunction> createInvokeStubs() {
        // invoke_* trampolines - these need to call into the WASM function table
        // For now, create stubs that call setThrew on any invocation
        // In a full implementation, these would look up and call functions from the table

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
        return new HostFunction(
            "env", name,
            params,
            results,
            (inst, args) -> {
                // Get function index
                int idx = args[0].asInt();

                // Call the function from the table
                try {
                    var table = inst.table(0);
                    if (table != null && idx < table.size()) {
                        var func = table.ref(idx);
                        if (func != null) {
                            // Build args (skip the index)
                            Value[] callArgs = new Value[args.length - 1];
                            for (int i = 1; i < args.length; i++) {
                                callArgs[i - 1] = args[i];
                            }
                            func.apply(callArgs);
                        }
                    }
                } catch (Exception e) {
                    threwValue = 1;
                    threwType = 0;
                }
                return null;
            }
        );
    }

    private HostFunction createInvokeStubWithReturn(String name, List<ValueType> params) {
        return new HostFunction(
            "env", name,
            params,
            List.of(ValueType.I32),
            (inst, args) -> {
                // Get function index
                int idx = args[0].asInt();

                // Call the function from the table
                try {
                    var table = inst.table(0);
                    if (table != null && idx < table.size()) {
                        var func = table.ref(idx);
                        if (func != null) {
                            // Build args (skip the index)
                            Value[] callArgs = new Value[args.length - 1];
                            for (int i = 1; i < args.length; i++) {
                                callArgs[i - 1] = args[i];
                            }
                            Value[] result = func.apply(callArgs);
                            if (result != null && result.length > 0) {
                                return result;
                            }
                        }
                    }
                } catch (Exception e) {
                    threwValue = 1;
                    threwType = 0;
                }
                return new Value[] { Value.i32(0) };
            }
        );
    }

    // Helper methods for memory management

    private int allocate(int size) {
        Value[] result = malloc.apply(Value.i32(size));
        return result[0].asInt();
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

    // Public API

    /**
     * Returns the module version string.
     */
    public String version() {
        Value[] result = getVersion.apply();
        int ptr = result[0].asInt();
        if (ptr == 0) return "unknown";

        // Read null-terminated string
        StringBuilder sb = new StringBuilder();
        int i = 0;
        while (true) {
            byte b = memory.read(ptr + i);
            if (b == 0) break;
            sb.append((char) b);
            i++;
        }
        return sb.toString();
    }

    /**
     * Returns true if Crypto++ is available.
     */
    public boolean hasCryptopp() {
        Value[] result = hasCryptopp.apply();
        return result[0].asInt() != 0;
    }

    /**
     * Encrypts data using AES-256-CTR.
     *
     * @param key 32-byte AES key
     * @param iv 16-byte initialization vector
     * @param plaintext Data to encrypt
     * @return Encrypted data (same length as plaintext)
     */
    public byte[] encrypt(byte[] key, byte[] iv, byte[] plaintext) {
        if (key.length != AES_KEY_SIZE) {
            throw new IllegalArgumentException("Key must be " + AES_KEY_SIZE + " bytes");
        }
        if (iv.length != AES_IV_SIZE) {
            throw new IllegalArgumentException("IV must be " + AES_IV_SIZE + " bytes");
        }
        if (plaintext.length == 0) {
            return new byte[0];
        }

        int keyPtr = allocate(AES_KEY_SIZE);
        int ivPtr = allocate(AES_IV_SIZE);
        int dataPtr = allocate(plaintext.length);

        try {
            writeBytes(keyPtr, key);
            writeBytes(ivPtr, iv);
            writeBytes(dataPtr, plaintext);

            encryptBytes.apply(
                Value.i32(keyPtr),
                Value.i32(ivPtr),
                Value.i32(dataPtr),
                Value.i32(plaintext.length)
            );

            return readBytes(dataPtr, plaintext.length);
        } finally {
            deallocate(keyPtr);
            deallocate(ivPtr);
            deallocate(dataPtr);
        }
    }

    /**
     * Decrypts data using AES-256-CTR.
     *
     * @param key 32-byte AES key
     * @param iv 16-byte initialization vector
     * @param ciphertext Data to decrypt
     * @return Decrypted data (same length as ciphertext)
     */
    public byte[] decrypt(byte[] key, byte[] iv, byte[] ciphertext) {
        if (key.length != AES_KEY_SIZE) {
            throw new IllegalArgumentException("Key must be " + AES_KEY_SIZE + " bytes");
        }
        if (iv.length != AES_IV_SIZE) {
            throw new IllegalArgumentException("IV must be " + AES_IV_SIZE + " bytes");
        }
        if (ciphertext.length == 0) {
            return new byte[0];
        }

        int keyPtr = allocate(AES_KEY_SIZE);
        int ivPtr = allocate(AES_IV_SIZE);
        int dataPtr = allocate(ciphertext.length);

        try {
            writeBytes(keyPtr, key);
            writeBytes(ivPtr, iv);
            writeBytes(dataPtr, ciphertext);

            decryptBytes.apply(
                Value.i32(keyPtr),
                Value.i32(ivPtr),
                Value.i32(dataPtr),
                Value.i32(ciphertext.length)
            );

            return readBytes(dataPtr, ciphertext.length);
        } finally {
            deallocate(keyPtr);
            deallocate(ivPtr);
            deallocate(dataPtr);
        }
    }

    /**
     * Computes SHA-256 hash of data.
     *
     * @param data Input data
     * @return 32-byte SHA-256 hash
     */
    public byte[] sha256(byte[] data) {
        int dataPtr = allocate(Math.max(data.length, 1));
        int hashPtr = allocate(SHA256_SIZE);

        try {
            if (data.length > 0) {
                writeBytes(dataPtr, data);
            }

            sha256.apply(
                Value.i32(dataPtr),
                Value.i32(data.length),
                Value.i32(hashPtr)
            );

            return readBytes(hashPtr, SHA256_SIZE);
        } finally {
            deallocate(dataPtr);
            deallocate(hashPtr);
        }
    }

    /**
     * Derives a key using HKDF-SHA256.
     *
     * @param ikm Input keying material
     * @param salt Salt (can be empty)
     * @param info Context info (can be empty)
     * @param length Output length
     * @return Derived key
     */
    public byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int length) {
        int ikmPtr = allocate(Math.max(ikm.length, 1));
        int saltPtr = allocate(Math.max(salt.length, 1));
        int infoPtr = allocate(Math.max(info.length, 1));
        int outPtr = allocate(length);

        try {
            if (ikm.length > 0) writeBytes(ikmPtr, ikm);
            if (salt.length > 0) writeBytes(saltPtr, salt);
            if (info.length > 0) writeBytes(infoPtr, info);

            hkdf.apply(
                Value.i32(ikmPtr),
                Value.i32(ikm.length),
                Value.i32(saltPtr),
                Value.i32(salt.length),
                Value.i32(infoPtr),
                Value.i32(info.length),
                Value.i32(outPtr),
                Value.i32(length)
            );

            return readBytes(outPtr, length);
        } finally {
            deallocate(ikmPtr);
            deallocate(saltPtr);
            deallocate(infoPtr);
            deallocate(outPtr);
        }
    }

    /**
     * Generates an X25519 key pair.
     *
     * @return KeyPair with 32-byte private and public keys
     */
    public KeyPair x25519GenerateKeypair() {
        int privPtr = allocate(X25519_PRIVATE_KEY_SIZE);
        int pubPtr = allocate(X25519_PUBLIC_KEY_SIZE);

        try {
            x25519GenerateKeypair.apply(
                Value.i32(privPtr),
                Value.i32(pubPtr)
            );

            return new KeyPair(
                readBytes(privPtr, X25519_PRIVATE_KEY_SIZE),
                readBytes(pubPtr, X25519_PUBLIC_KEY_SIZE)
            );
        } finally {
            deallocate(privPtr);
            deallocate(pubPtr);
        }
    }

    /**
     * Computes X25519 shared secret.
     *
     * @param privateKey 32-byte private key
     * @param publicKey 32-byte public key
     * @return 32-byte shared secret
     */
    public byte[] x25519SharedSecret(byte[] privateKey, byte[] publicKey) {
        int privPtr = allocate(X25519_PRIVATE_KEY_SIZE);
        int pubPtr = allocate(X25519_PUBLIC_KEY_SIZE);
        int secretPtr = allocate(SHARED_SECRET_SIZE);

        try {
            writeBytes(privPtr, privateKey);
            writeBytes(pubPtr, publicKey);

            x25519SharedSecret.apply(
                Value.i32(privPtr),
                Value.i32(pubPtr),
                Value.i32(secretPtr)
            );

            return readBytes(secretPtr, SHARED_SECRET_SIZE);
        } finally {
            deallocate(privPtr);
            deallocate(pubPtr);
            deallocate(secretPtr);
        }
    }

    /**
     * Generates a secp256k1 key pair.
     *
     * @return KeyPair with 32-byte private key and 33-byte compressed public key
     */
    public KeyPair secp256k1GenerateKeypair() {
        int privPtr = allocate(SECP256K1_PRIVATE_KEY_SIZE);
        int pubPtr = allocate(SECP256K1_PUBLIC_KEY_SIZE);

        try {
            secp256k1GenerateKeypair.apply(
                Value.i32(privPtr),
                Value.i32(pubPtr)
            );

            return new KeyPair(
                readBytes(privPtr, SECP256K1_PRIVATE_KEY_SIZE),
                readBytes(pubPtr, SECP256K1_PUBLIC_KEY_SIZE)
            );
        } finally {
            deallocate(privPtr);
            deallocate(pubPtr);
        }
    }

    /**
     * Computes secp256k1 ECDH shared secret.
     *
     * @param privateKey 32-byte private key
     * @param publicKey 33-byte compressed public key
     * @return 32-byte shared secret
     */
    public byte[] secp256k1SharedSecret(byte[] privateKey, byte[] publicKey) {
        int privPtr = allocate(SECP256K1_PRIVATE_KEY_SIZE);
        int pubPtr = allocate(SECP256K1_PUBLIC_KEY_SIZE);
        int secretPtr = allocate(SHARED_SECRET_SIZE);

        try {
            writeBytes(privPtr, privateKey);
            writeBytes(pubPtr, publicKey);

            secp256k1SharedSecret.apply(
                Value.i32(privPtr),
                Value.i32(pubPtr),
                Value.i32(secretPtr)
            );

            return readBytes(secretPtr, SHARED_SECRET_SIZE);
        } finally {
            deallocate(privPtr);
            deallocate(pubPtr);
            deallocate(secretPtr);
        }
    }

    /**
     * Signs a message using secp256k1 ECDSA.
     *
     * @param privateKey 32-byte private key
     * @param message Message to sign
     * @return DER-encoded signature
     */
    public byte[] secp256k1Sign(byte[] privateKey, byte[] message) {
        int privPtr = allocate(SECP256K1_PRIVATE_KEY_SIZE);
        int msgPtr = allocate(Math.max(message.length, 1));
        int sigPtr = allocate(SECP256K1_SIGNATURE_SIZE);
        int sigLenPtr = allocate(4);

        try {
            writeBytes(privPtr, privateKey);
            if (message.length > 0) writeBytes(msgPtr, message);

            secp256k1Sign.apply(
                Value.i32(privPtr),
                Value.i32(msgPtr),
                Value.i32(message.length),
                Value.i32(sigPtr),
                Value.i32(sigLenPtr)
            );

            int sigLen = memory.readInt(sigLenPtr);
            return readBytes(sigPtr, sigLen);
        } finally {
            deallocate(privPtr);
            deallocate(msgPtr);
            deallocate(sigPtr);
            deallocate(sigLenPtr);
        }
    }

    /**
     * Verifies a secp256k1 ECDSA signature.
     *
     * @param publicKey 33-byte compressed public key
     * @param message Original message
     * @param signature DER-encoded signature
     * @return true if signature is valid
     */
    public boolean secp256k1Verify(byte[] publicKey, byte[] message, byte[] signature) {
        int pubPtr = allocate(SECP256K1_PUBLIC_KEY_SIZE);
        int msgPtr = allocate(Math.max(message.length, 1));
        int sigPtr = allocate(signature.length);

        try {
            writeBytes(pubPtr, publicKey);
            if (message.length > 0) writeBytes(msgPtr, message);
            writeBytes(sigPtr, signature);

            Value[] result = secp256k1Verify.apply(
                Value.i32(pubPtr),
                Value.i32(msgPtr),
                Value.i32(message.length),
                Value.i32(sigPtr),
                Value.i32(signature.length)
            );

            return result[0].asInt() != 0;
        } finally {
            deallocate(pubPtr);
            deallocate(msgPtr);
            deallocate(sigPtr);
        }
    }

    /**
     * Generates a P-256 key pair.
     *
     * @return KeyPair with 32-byte private key and 33-byte compressed public key
     */
    public KeyPair p256GenerateKeypair() {
        int privPtr = allocate(P256_PRIVATE_KEY_SIZE);
        int pubPtr = allocate(P256_PUBLIC_KEY_SIZE);

        try {
            p256GenerateKeypair.apply(
                Value.i32(privPtr),
                Value.i32(pubPtr)
            );

            return new KeyPair(
                readBytes(privPtr, P256_PRIVATE_KEY_SIZE),
                readBytes(pubPtr, P256_PUBLIC_KEY_SIZE)
            );
        } finally {
            deallocate(privPtr);
            deallocate(pubPtr);
        }
    }

    /**
     * Computes P-256 ECDH shared secret.
     *
     * @param privateKey 32-byte private key
     * @param publicKey 33-byte compressed public key
     * @return 32-byte shared secret
     */
    public byte[] p256SharedSecret(byte[] privateKey, byte[] publicKey) {
        int privPtr = allocate(P256_PRIVATE_KEY_SIZE);
        int pubPtr = allocate(P256_PUBLIC_KEY_SIZE);
        int secretPtr = allocate(SHARED_SECRET_SIZE);

        try {
            writeBytes(privPtr, privateKey);
            writeBytes(pubPtr, publicKey);

            p256SharedSecret.apply(
                Value.i32(privPtr),
                Value.i32(pubPtr),
                Value.i32(secretPtr)
            );

            return readBytes(secretPtr, SHARED_SECRET_SIZE);
        } finally {
            deallocate(privPtr);
            deallocate(pubPtr);
            deallocate(secretPtr);
        }
    }

    /**
     * Signs a message using P-256 ECDSA.
     *
     * @param privateKey 32-byte private key
     * @param message Message to sign
     * @return DER-encoded signature
     */
    public byte[] p256Sign(byte[] privateKey, byte[] message) {
        int privPtr = allocate(P256_PRIVATE_KEY_SIZE);
        int msgPtr = allocate(Math.max(message.length, 1));
        int sigPtr = allocate(P256_SIGNATURE_SIZE);
        int sigLenPtr = allocate(4);

        try {
            writeBytes(privPtr, privateKey);
            if (message.length > 0) writeBytes(msgPtr, message);

            p256Sign.apply(
                Value.i32(privPtr),
                Value.i32(msgPtr),
                Value.i32(message.length),
                Value.i32(sigPtr),
                Value.i32(sigLenPtr)
            );

            int sigLen = memory.readInt(sigLenPtr);
            return readBytes(sigPtr, sigLen);
        } finally {
            deallocate(privPtr);
            deallocate(msgPtr);
            deallocate(sigPtr);
            deallocate(sigLenPtr);
        }
    }

    /**
     * Verifies a P-256 ECDSA signature.
     *
     * @param publicKey 33-byte compressed public key
     * @param message Original message
     * @param signature DER-encoded signature
     * @return true if signature is valid
     */
    public boolean p256Verify(byte[] publicKey, byte[] message, byte[] signature) {
        int pubPtr = allocate(P256_PUBLIC_KEY_SIZE);
        int msgPtr = allocate(Math.max(message.length, 1));
        int sigPtr = allocate(signature.length);

        try {
            writeBytes(pubPtr, publicKey);
            if (message.length > 0) writeBytes(msgPtr, message);
            writeBytes(sigPtr, signature);

            Value[] result = p256Verify.apply(
                Value.i32(pubPtr),
                Value.i32(msgPtr),
                Value.i32(message.length),
                Value.i32(sigPtr),
                Value.i32(signature.length)
            );

            return result[0].asInt() != 0;
        } finally {
            deallocate(pubPtr);
            deallocate(msgPtr);
            deallocate(sigPtr);
        }
    }

    /**
     * Generates an Ed25519 key pair.
     *
     * @return KeyPair with 64-byte private key (seed + public) and 32-byte public key
     */
    public KeyPair ed25519GenerateKeypair() {
        int privPtr = allocate(ED25519_PRIVATE_KEY_SIZE);
        int pubPtr = allocate(ED25519_PUBLIC_KEY_SIZE);

        try {
            ed25519GenerateKeypair.apply(
                Value.i32(privPtr),
                Value.i32(pubPtr)
            );

            return new KeyPair(
                readBytes(privPtr, ED25519_PRIVATE_KEY_SIZE),
                readBytes(pubPtr, ED25519_PUBLIC_KEY_SIZE)
            );
        } finally {
            deallocate(privPtr);
            deallocate(pubPtr);
        }
    }

    /**
     * Signs a message using Ed25519.
     *
     * @param privateKey 64-byte private key
     * @param message Message to sign
     * @return 64-byte signature
     */
    public byte[] ed25519Sign(byte[] privateKey, byte[] message) {
        int privPtr = allocate(ED25519_PRIVATE_KEY_SIZE);
        int msgPtr = allocate(Math.max(message.length, 1));
        int sigPtr = allocate(ED25519_SIGNATURE_SIZE);

        try {
            writeBytes(privPtr, privateKey);
            if (message.length > 0) writeBytes(msgPtr, message);

            ed25519Sign.apply(
                Value.i32(privPtr),
                Value.i32(msgPtr),
                Value.i32(message.length),
                Value.i32(sigPtr)
            );

            return readBytes(sigPtr, ED25519_SIGNATURE_SIZE);
        } finally {
            deallocate(privPtr);
            deallocate(msgPtr);
            deallocate(sigPtr);
        }
    }

    /**
     * Verifies an Ed25519 signature.
     *
     * @param publicKey 32-byte public key
     * @param message Original message
     * @param signature 64-byte signature
     * @return true if signature is valid
     */
    public boolean ed25519Verify(byte[] publicKey, byte[] message, byte[] signature) {
        int pubPtr = allocate(ED25519_PUBLIC_KEY_SIZE);
        int msgPtr = allocate(Math.max(message.length, 1));
        int sigPtr = allocate(ED25519_SIGNATURE_SIZE);

        try {
            writeBytes(pubPtr, publicKey);
            if (message.length > 0) writeBytes(msgPtr, message);
            writeBytes(sigPtr, signature);

            Value[] result = ed25519Verify.apply(
                Value.i32(pubPtr),
                Value.i32(msgPtr),
                Value.i32(message.length),
                Value.i32(sigPtr)
            );

            return result[0].asInt() != 0;
        } finally {
            deallocate(pubPtr);
            deallocate(msgPtr);
            deallocate(sigPtr);
        }
    }

    /**
     * Derives a symmetric key from a shared secret using HKDF.
     *
     * @param sharedSecret Input shared secret
     * @param context Context string for key derivation
     * @return 32-byte derived key and 16-byte IV
     */
    public DerivedKey deriveSymmetricKey(byte[] sharedSecret, String context) {
        byte[] contextBytes = context.getBytes();

        int secretPtr = allocate(sharedSecret.length);
        int contextPtr = allocate(Math.max(contextBytes.length, 1));
        int keyPtr = allocate(AES_KEY_SIZE);
        int ivPtr = allocate(AES_IV_SIZE);

        try {
            writeBytes(secretPtr, sharedSecret);
            if (contextBytes.length > 0) writeBytes(contextPtr, contextBytes);

            deriveSymmetricKey.apply(
                Value.i32(secretPtr),
                Value.i32(sharedSecret.length),
                Value.i32(contextPtr),
                Value.i32(contextBytes.length),
                Value.i32(keyPtr),
                Value.i32(ivPtr)
            );

            return new DerivedKey(
                readBytes(keyPtr, AES_KEY_SIZE),
                readBytes(ivPtr, AES_IV_SIZE)
            );
        } finally {
            deallocate(secretPtr);
            deallocate(contextPtr);
            deallocate(keyPtr);
            deallocate(ivPtr);
        }
    }

    /**
     * Generates random bytes using a secure random number generator.
     *
     * @param length Number of bytes to generate
     * @return Random bytes
     */
    public byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }

    @Override
    public void close() {
        // Chicory instances don't need explicit cleanup
    }

    /**
     * Represents a public/private key pair.
     */
    public static class KeyPair {
        private final byte[] privateKey;
        private final byte[] publicKey;

        public KeyPair(byte[] privateKey, byte[] publicKey) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }

        public byte[] getPrivateKey() {
            return privateKey;
        }

        public byte[] getPublicKey() {
            return publicKey;
        }
    }

    /**
     * Represents a derived symmetric key and IV.
     */
    public static class DerivedKey {
        private final byte[] key;
        private final byte[] iv;

        public DerivedKey(byte[] key, byte[] iv) {
            this.key = key;
            this.iv = iv;
        }

        public byte[] getKey() {
            return key;
        }

        public byte[] getIv() {
            return iv;
        }
    }
}
