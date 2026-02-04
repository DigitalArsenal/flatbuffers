# Kotlin E2E Crypto Test Runner

Cross-language encryption test runner for FlatBuffers WASM using Kotlin and the Chicory pure-Java WASM runtime.

## Prerequisites

- JDK 21 or later
- Gradle 8.x (wrapper included)
- Built FlatBuffers WASM encryption module (`flatc-encryption.wasm`)

## Building

```bash
# From this directory
./gradlew build
```

## Running

```bash
# First, ensure the WASM module is built
cd ../../../../../..
cmake --build build/wasm --target flatc_encryption_wasm

# Run the Kotlin tests
cd wasm/examples/e2e-crypto-test/runners/kotlin
./gradlew run
```

## What This Tests

1. **SHA-256 Hash** - Basic cryptographic hash function
2. **Per-Chain Encryption** - AES-256-CTR encryption with 10 different cryptocurrency-derived keys
3. **Cross-Language Verification** - Decrypting data created by other languages (Node.js)
4. **ECDH Key Exchange** - X25519, secp256k1, and P-256 key agreement
5. **Digital Signatures** - Ed25519, secp256k1, and P-256 ECDSA signing/verification
6. **FlatBuffer Creation** - Creating, encrypting, and verifying FlatBuffer messages

## WASM Runtime

Uses [Chicory](https://github.com/dylibso/chicory) - a pure Java WebAssembly runtime with WASI support.
This allows running WASM modules without native dependencies.

## Dependencies

- `com.dylibso.chicory:runtime:1.5.3` - WASM runtime
- `com.dylibso.chicory:wasi:1.5.3` - WASI support
- `com.google.flatbuffers:flatbuffers-java:24.12.23` - FlatBuffers runtime
- `com.google.code.gson:gson:2.10.1` - JSON parsing
