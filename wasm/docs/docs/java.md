# Java Integration Guide

Integrate the FlatBuffers encryption WASM module into Java applications using [Chicory](https://github.com/nickmccoll/chicory), a pure Java WebAssembly runtime.

## Why Chicory?

- **Pure Java** - No JNI, no native dependencies
- **JVM optimized** - Designed for Java performance
- **Easy deployment** - Just add a Maven dependency
- **GraalVM compatible** - Works with native-image

## Prerequisites

- Java 17 or later
- Maven or Gradle
- `flatc-encryption.wasm` binary

## Installation

**Maven:**
```xml
<dependency>
    <groupId>com.dylibso.chicory</groupId>
    <artifactId>runtime</artifactId>
    <version>1.5.3</version>
</dependency>
```

**Gradle:**
```groovy
implementation 'com.dylibso.chicory:runtime:1.5.3'
```

## Quick Start

```java
import com.dylibso.chicory.runtime.Instance;
import com.dylibso.chicory.runtime.Module;
import com.dylibso.chicory.runtime.Memory;
import com.dylibso.chicory.wasm.types.Value;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;

public class QuickStart {
    public static void main(String[] args) throws Exception {
        // Load WASM module
        byte[] wasmBytes = Files.readAllBytes(Path.of("flatc-encryption.wasm"));
        Module module = Module.builder(wasmBytes).build();
        Instance instance = module.instantiate();

        // Get memory and functions
        Memory memory = instance.memory();
        var malloc = instance.export("malloc");
        var free = instance.export("free");
        var encrypt = instance.export("wasi_encrypt_bytes");
        var decrypt = instance.export("wasi_decrypt_bytes");

        // Generate key and IV
        SecureRandom random = new SecureRandom();
        byte[] key = new byte[32];
        byte[] iv = new byte[16];
        random.nextBytes(key);
        random.nextBytes(iv);

        byte[] plaintext = "Hello, FlatBuffers!".getBytes();

        // Allocate WASM memory
        int keyPtr = (int) malloc.apply(Value.i32(32))[0].asInt();
        int ivPtr = (int) malloc.apply(Value.i32(16))[0].asInt();
        int dataPtr = (int) malloc.apply(Value.i32(plaintext.length))[0].asInt();

        // Write to memory
        memory.write(keyPtr, key);
        memory.write(ivPtr, iv);
        memory.write(dataPtr, plaintext);

        // Encrypt
        encrypt.apply(
            Value.i32(keyPtr),
            Value.i32(ivPtr),
            Value.i32(dataPtr),
            Value.i32(plaintext.length)
        );

        // Read encrypted data
        byte[] ciphertext = memory.readBytes(dataPtr, plaintext.length);
        System.out.println("Encrypted: " + bytesToHex(ciphertext));

        // Decrypt
        decrypt.apply(
            Value.i32(keyPtr),
            Value.i32(ivPtr),
            Value.i32(dataPtr),
            Value.i32(plaintext.length)
        );

        // Read decrypted data
        byte[] decrypted = memory.readBytes(dataPtr, plaintext.length);
        System.out.println("Decrypted: " + new String(decrypted));

        // Clean up
        free.apply(Value.i32(keyPtr));
        free.apply(Value.i32(ivPtr));
        free.apply(Value.i32(dataPtr));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
```

## Complete Module Wrapper

```java
package com.example.encryption;

import com.dylibso.chicory.runtime.Instance;
import com.dylibso.chicory.runtime.Module;
import com.dylibso.chicory.runtime.Memory;
import com.dylibso.chicory.runtime.ExportFunction;
import com.dylibso.chicory.wasm.types.Value;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;

/**
 * FlatBuffers Encryption Module for Java.
 *
 * Provides cryptographic operations via the Crypto++ WASM module:
 * - AES-256-CTR symmetric encryption
 * - X25519 ECDH key exchange
 * - secp256k1 ECDH and ECDSA signatures
 * - P-256 ECDH and ECDSA signatures
 * - Ed25519 signatures
 */
public class EncryptionModule implements AutoCloseable {

    // Key and signature sizes
    public static final int AES_KEY_SIZE = 32;
    public static final int AES_IV_SIZE = 16;
    public static final int SHA256_SIZE = 32;

    public static final int X25519_PRIVATE_KEY_SIZE = 32;
    public static final int X25519_PUBLIC_KEY_SIZE = 32;

    public static final int SECP256K1_PRIVATE_KEY_SIZE = 32;
    public static final int SECP256K1_PUBLIC_KEY_SIZE = 33;
    public static final int SECP256K1_SIGNATURE_MAX_SIZE = 72;

    public static final int ED25519_PRIVATE_KEY_SIZE = 64;
    public static final int ED25519_PUBLIC_KEY_SIZE = 32;
    public static final int ED25519_SIGNATURE_SIZE = 64;

    private final Instance instance;
    private final Memory memory;
    private final ExportFunction malloc;
    private final ExportFunction free;

    // Encryption
    private final ExportFunction encrypt;
    private final ExportFunction decrypt;

    // Hash
    private final ExportFunction sha256;
    private final ExportFunction hkdf;

    // X25519
    private final ExportFunction x25519Generate;
    private final ExportFunction x25519Shared;

    // secp256k1
    private final ExportFunction secp256k1Generate;
    private final ExportFunction secp256k1Shared;
    private final ExportFunction secp256k1Sign;
    private final ExportFunction secp256k1Verify;

    // Ed25519
    private final ExportFunction ed25519Generate;
    private final ExportFunction ed25519Sign;
    private final ExportFunction ed25519Verify;

    /**
     * Create a new encryption module from WASM bytes.
     */
    public EncryptionModule(byte[] wasmBytes) {
        Module module = Module.builder(wasmBytes).build();
        this.instance = module.instantiate();
        this.memory = instance.memory();

        // Core
        this.malloc = instance.export("malloc");
        this.free = instance.export("free");

        // Encryption
        this.encrypt = instance.export("wasi_encrypt_bytes");
        this.decrypt = instance.export("wasi_decrypt_bytes");

        // Hash
        this.sha256 = instance.export("wasi_sha256");
        this.hkdf = instance.export("wasi_hkdf");

        // X25519
        this.x25519Generate = instance.export("wasi_x25519_generate_keypair");
        this.x25519Shared = instance.export("wasi_x25519_shared_secret");

        // secp256k1
        this.secp256k1Generate = instance.export("wasi_secp256k1_generate_keypair");
        this.secp256k1Shared = instance.export("wasi_secp256k1_shared_secret");
        this.secp256k1Sign = instance.export("wasi_secp256k1_sign");
        this.secp256k1Verify = instance.export("wasi_secp256k1_verify");

        // Ed25519
        this.ed25519Generate = instance.export("wasi_ed25519_generate_keypair");
        this.ed25519Sign = instance.export("wasi_ed25519_sign");
        this.ed25519Verify = instance.export("wasi_ed25519_verify");
    }

    /**
     * Create from file path.
     */
    public static EncryptionModule fromFile(String path) throws Exception {
        byte[] wasmBytes = Files.readAllBytes(Path.of(path));
        return new EncryptionModule(wasmBytes);
    }

    // Key pair classes

    public record X25519KeyPair(byte[] privateKey, byte[] publicKey) {}
    public record Ed25519KeyPair(byte[] privateKey, byte[] publicKey) {}
    public record Secp256k1KeyPair(byte[] privateKey, byte[] publicKey) {}

    // Symmetric Encryption

    /**
     * Encrypt data using AES-256-CTR.
     *
     * @param key 32-byte encryption key
     * @param iv 16-byte initialization vector
     * @param data Data to encrypt
     * @return Encrypted data
     */
    public byte[] encrypt(byte[] key, byte[] iv, byte[] data) {
        if (key.length != AES_KEY_SIZE) {
            throw new IllegalArgumentException("Key must be " + AES_KEY_SIZE + " bytes");
        }
        if (iv.length != AES_IV_SIZE) {
            throw new IllegalArgumentException("IV must be " + AES_IV_SIZE + " bytes");
        }

        int keyPtr = allocate(key.length);
        int ivPtr = allocate(iv.length);
        int dataPtr = allocate(data.length);

        try {
            memory.write(keyPtr, key);
            memory.write(ivPtr, iv);
            memory.write(dataPtr, data);

            Value[] result = encrypt.apply(
                Value.i32(keyPtr),
                Value.i32(ivPtr),
                Value.i32(dataPtr),
                Value.i32(data.length)
            );

            if (result[0].asInt() != 0) {
                throw new RuntimeException("Encryption failed");
            }

            return memory.readBytes(dataPtr, data.length);
        } finally {
            free(keyPtr);
            free(ivPtr);
            free(dataPtr);
        }
    }

    /**
     * Decrypt data using AES-256-CTR.
     */
    public byte[] decrypt(byte[] key, byte[] iv, byte[] data) {
        // CTR mode is symmetric
        return encrypt(key, iv, data);
    }

    // Hash Functions

    /**
     * Compute SHA-256 hash.
     */
    public byte[] sha256(byte[] data) {
        int dataPtr = allocate(data.length);
        int outPtr = allocate(SHA256_SIZE);

        try {
            memory.write(dataPtr, data);
            sha256.apply(
                Value.i32(dataPtr),
                Value.i32(data.length),
                Value.i32(outPtr)
            );
            return memory.readBytes(outPtr, SHA256_SIZE);
        } finally {
            free(dataPtr);
            free(outPtr);
        }
    }

    /**
     * Derive key using HKDF-SHA256.
     *
     * @param ikm Input key material
     * @param salt Optional salt (can be null)
     * @param info Context info
     * @param length Output length
     * @return Derived key
     */
    public byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int length) {
        int ikmPtr = allocate(ikm.length);
        memory.write(ikmPtr, ikm);

        int saltPtr = 0;
        int saltLen = 0;
        if (salt != null && salt.length > 0) {
            saltPtr = allocate(salt.length);
            memory.write(saltPtr, salt);
            saltLen = salt.length;
        }

        int infoPtr = allocate(info.length);
        memory.write(infoPtr, info);

        int outPtr = allocate(length);

        try {
            hkdf.apply(
                Value.i32(ikmPtr), Value.i32(ikm.length),
                Value.i32(saltPtr), Value.i32(saltLen),
                Value.i32(infoPtr), Value.i32(info.length),
                Value.i32(outPtr), Value.i32(length)
            );
            return memory.readBytes(outPtr, length);
        } finally {
            free(ikmPtr);
            if (saltPtr != 0) free(saltPtr);
            free(infoPtr);
            free(outPtr);
        }
    }

    // X25519 Key Exchange

    /**
     * Generate X25519 key pair.
     */
    public X25519KeyPair x25519GenerateKeyPair() {
        int privPtr = allocate(X25519_PRIVATE_KEY_SIZE);
        int pubPtr = allocate(X25519_PUBLIC_KEY_SIZE);

        try {
            Value[] result = x25519Generate.apply(
                Value.i32(privPtr),
                Value.i32(pubPtr)
            );

            if (result[0].asInt() != 0) {
                throw new RuntimeException("Key generation failed");
            }

            return new X25519KeyPair(
                memory.readBytes(privPtr, X25519_PRIVATE_KEY_SIZE),
                memory.readBytes(pubPtr, X25519_PUBLIC_KEY_SIZE)
            );
        } finally {
            free(privPtr);
            free(pubPtr);
        }
    }

    /**
     * Compute X25519 shared secret.
     */
    public byte[] x25519SharedSecret(byte[] privateKey, byte[] publicKey) {
        int privPtr = allocate(privateKey.length);
        int pubPtr = allocate(publicKey.length);
        int outPtr = allocate(32);

        try {
            memory.write(privPtr, privateKey);
            memory.write(pubPtr, publicKey);

            Value[] result = x25519Shared.apply(
                Value.i32(privPtr),
                Value.i32(pubPtr),
                Value.i32(outPtr)
            );

            if (result[0].asInt() != 0) {
                throw new RuntimeException("Shared secret computation failed");
            }

            return memory.readBytes(outPtr, 32);
        } finally {
            free(privPtr);
            free(pubPtr);
            free(outPtr);
        }
    }

    // Ed25519 Signatures

    /**
     * Generate Ed25519 key pair.
     */
    public Ed25519KeyPair ed25519GenerateKeyPair() {
        int privPtr = allocate(ED25519_PRIVATE_KEY_SIZE);
        int pubPtr = allocate(ED25519_PUBLIC_KEY_SIZE);

        try {
            Value[] result = ed25519Generate.apply(
                Value.i32(privPtr),
                Value.i32(pubPtr)
            );

            if (result[0].asInt() != 0) {
                throw new RuntimeException("Key generation failed");
            }

            return new Ed25519KeyPair(
                memory.readBytes(privPtr, ED25519_PRIVATE_KEY_SIZE),
                memory.readBytes(pubPtr, ED25519_PUBLIC_KEY_SIZE)
            );
        } finally {
            free(privPtr);
            free(pubPtr);
        }
    }

    /**
     * Sign with Ed25519.
     */
    public byte[] ed25519Sign(byte[] privateKey, byte[] message) {
        int privPtr = allocate(privateKey.length);
        int msgPtr = allocate(message.length);
        int sigPtr = allocate(ED25519_SIGNATURE_SIZE);

        try {
            memory.write(privPtr, privateKey);
            memory.write(msgPtr, message);

            Value[] result = ed25519Sign.apply(
                Value.i32(privPtr),
                Value.i32(msgPtr),
                Value.i32(message.length),
                Value.i32(sigPtr)
            );

            if (result[0].asInt() != 0) {
                throw new RuntimeException("Signing failed");
            }

            return memory.readBytes(sigPtr, ED25519_SIGNATURE_SIZE);
        } finally {
            free(privPtr);
            free(msgPtr);
            free(sigPtr);
        }
    }

    /**
     * Verify Ed25519 signature.
     */
    public boolean ed25519Verify(byte[] publicKey, byte[] message, byte[] signature) {
        int pubPtr = allocate(publicKey.length);
        int msgPtr = allocate(message.length);
        int sigPtr = allocate(signature.length);

        try {
            memory.write(pubPtr, publicKey);
            memory.write(msgPtr, message);
            memory.write(sigPtr, signature);

            Value[] result = ed25519Verify.apply(
                Value.i32(pubPtr),
                Value.i32(msgPtr),
                Value.i32(message.length),
                Value.i32(sigPtr)
            );

            return result[0].asInt() == 0;
        } finally {
            free(pubPtr);
            free(msgPtr);
            free(sigPtr);
        }
    }

    // Helpers

    private int allocate(int size) {
        Value[] result = malloc.apply(Value.i32(size));
        int ptr = result[0].asInt();
        if (ptr == 0) {
            throw new OutOfMemoryError("WASM malloc returned null");
        }
        return ptr;
    }

    private void free(int ptr) {
        free.apply(Value.i32(ptr));
    }

    @Override
    public void close() {
        // Chicory handles cleanup automatically
    }
}
```

## Template Project Structure

```
myproject/
├── pom.xml
├── src/
│   └── main/
│       ├── java/
│       │   └── com/example/
│       │       ├── Main.java
│       │       └── encryption/
│       │           └── EncryptionModule.java
│       └── resources/
│           └── flatc-encryption.wasm
└── src/
    └── test/
        └── java/
            └── com/example/
                └── EncryptionTest.java
```

**pom.xml:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.example</groupId>
    <artifactId>flatbuffers-encryption</artifactId>
    <version>1.0.0</version>

    <properties>
        <maven.compiler.source>17</maven.compiler.source>
        <maven.compiler.target>17</maven.compiler.target>
    </properties>

    <dependencies>
        <dependency>
            <groupId>com.dylibso.chicory</groupId>
            <artifactId>runtime</artifactId>
            <version>1.5.3</version>
        </dependency>
        <dependency>
            <groupId>org.junit.jupiter</groupId>
            <artifactId>junit-jupiter</artifactId>
            <version>5.10.0</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
</project>
```

## Usage Examples

### Basic Encryption

```java
var module = EncryptionModule.fromFile("flatc-encryption.wasm");

SecureRandom random = new SecureRandom();
byte[] key = new byte[32];
byte[] iv = new byte[16];
random.nextBytes(key);
random.nextBytes(iv);

byte[] plaintext = "Secret message".getBytes();
byte[] ciphertext = module.encrypt(key, iv, plaintext);
byte[] decrypted = module.decrypt(key, iv, ciphertext);

assert Arrays.equals(plaintext, decrypted);
```

### End-to-End Encryption

```java
var module = EncryptionModule.fromFile("flatc-encryption.wasm");

// Generate key pairs
var alice = module.x25519GenerateKeyPair();
var bob = module.x25519GenerateKeyPair();

// Compute shared secrets
byte[] aliceShared = module.x25519SharedSecret(alice.privateKey(), bob.publicKey());
byte[] bobShared = module.x25519SharedSecret(bob.privateKey(), alice.publicKey());

assert Arrays.equals(aliceShared, bobShared);

// Derive encryption key
byte[] encryptionKey = module.hkdf(aliceShared, null, "encryption-v1".getBytes(), 32);

// Encrypt message
byte[] iv = new byte[16];
new SecureRandom().nextBytes(iv);
byte[] ciphertext = module.encrypt(encryptionKey, iv, "Hello Bob!".getBytes());

// Decrypt
byte[] decrypted = module.decrypt(encryptionKey, iv, ciphertext);
System.out.println(new String(decrypted)); // "Hello Bob!"
```

## Performance Tips

1. **Reuse module instances** - Module loading is expensive
2. **Use try-with-resources** - Ensures proper cleanup
3. **Consider thread safety** - Chicory instances are not thread-safe

```java
// Good: Reuse instance
var module = EncryptionModule.fromFile("wasm");
for (var item : items) {
    module.encrypt(key, iv, item);
}

// Bad: Create new instance each time
for (var item : items) {
    var module = EncryptionModule.fromFile("wasm"); // Slow!
    module.encrypt(key, iv, item);
}
```

## Troubleshooting

### "Function not found"

Check that you're using the correct export names (wasi_* prefix).

### "Memory access out of bounds"

Ensure allocated memory is valid:

```java
int ptr = allocate(size);
if (ptr == 0) {
    throw new RuntimeException("Allocation failed");
}
```

## See Also

- [Chicory Documentation](https://github.com/nickmccoll/chicory)
- [API Reference](README.md#api-reference)
- [Security Considerations](README.md#security-considerations)
