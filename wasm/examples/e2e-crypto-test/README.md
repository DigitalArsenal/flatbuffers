# FlatBuffers Cross-Language Encryption E2E Tests

End-to-end testing framework for FlatBuffers WASM encryption module across **7 languages**
with full cryptographic support including ECDH key exchange, digital signatures, and
transparent encryption using 10 major cryptocurrency key types.

## Complete E2E Capabilities

All 7 language runners have complete end-to-end capabilities:

| Capability | Node.js | Go | Python | Rust | Java | C# | Swift |
|------------|---------|-----|--------|------|------|-----|-------|
| Load WASM crypto module | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SHA-256 hashing | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| AES-256-CTR encrypt/decrypt | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| HKDF-SHA256 key derivation | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| X25519 ECDH | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| secp256k1 ECDH | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| P-256 ECDH | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Ed25519 signatures | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| secp256k1 ECDSA signatures | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| P-256 ECDSA signatures | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| FlatBuffer creation | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Cross-language verification | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

## End-to-End Flow

The complete E2E flow demonstrates how to use FlatBuffers with encryption across any language:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         END-TO-END ENCRYPTION FLOW                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. SCHEMA DEFINITION                                                        │
│     ┌──────────────────┐                                                    │
│     │  message.fbs     │  Define your FlatBuffers schema                    │
│     │  (IDL schema)    │                                                    │
│     └────────┬─────────┘                                                    │
│              │                                                               │
│              ▼                                                               │
│  2. CODE GENERATION (via WASM flatc or native flatc)                        │
│     ┌──────────────────┐                                                    │
│     │  flatc --ts      │  Generate language-specific code                   │
│     │  flatc --go      │  (TypeScript, Go, Python, Rust, Java, C#, Swift)   │
│     │  flatc --python  │                                                    │
│     │  ...             │                                                    │
│     └────────┬─────────┘                                                    │
│              │                                                               │
│              ▼                                                               │
│  3. CREATE FLATBUFFER                                                        │
│     ┌──────────────────┐                                                    │
│     │  Builder API     │  Use generated code to create FlatBuffer binary    │
│     │  SecureMessage   │  e.g., SecureMessage.createSecureMessage(...)      │
│     └────────┬─────────┘                                                    │
│              │                                                               │
│              ▼                                                               │
│  4. KEY EXCHANGE (ECDH)                                                      │
│     ┌──────────────────────────────────────────────────────────┐            │
│     │  Sender                              Recipient           │            │
│     │  ┌─────────────┐                    ┌─────────────┐     │            │
│     │  │ Private Key │                    │ Private Key │     │            │
│     │  │ Public Key  │◄──────────────────►│ Public Key  │     │            │
│     │  └──────┬──────┘   Exchange Pubs    └──────┬──────┘     │            │
│     │         │                                   │            │            │
│     │         └───────────┬───────────────────────┘            │            │
│     │                     ▼                                    │            │
│     │             ┌───────────────┐                            │            │
│     │             │ Shared Secret │  X25519/secp256k1/P-256    │            │
│     │             └───────┬───────┘                            │            │
│     │                     │                                    │            │
│     │                     ▼                                    │            │
│     │             ┌───────────────┐                            │            │
│     │             │ HKDF-SHA256   │  Derive encryption key     │            │
│     │             │ → AES Key     │                            │            │
│     │             └───────────────┘                            │            │
│     └──────────────────────────────────────────────────────────┘            │
│              │                                                               │
│              ▼                                                               │
│  5. ENCRYPT FLATBUFFER                                                       │
│     ┌──────────────────┐                                                    │
│     │  AES-256-CTR     │  Encrypt entire FlatBuffer binary                  │
│     │  (WASM module)   │  Binary → Ciphertext                               │
│     └────────┬─────────┘                                                    │
│              │                                                               │
│              ▼                                                               │
│  6. SIGN (Optional)                                                          │
│     ┌──────────────────┐                                                    │
│     │  Ed25519 or      │  Sign ciphertext for authentication                │
│     │  ECDSA           │  (Ed25519, secp256k1, P-256)                       │
│     └────────┬─────────┘                                                    │
│              │                                                               │
│              ▼                                                               │
│  7. TRANSMIT                                                                 │
│     ┌──────────────────┐                                                    │
│     │  Network/File    │  Send encrypted + signed data                      │
│     │  Transfer        │                                                    │
│     └────────┬─────────┘                                                    │
│              │                                                               │
│              ▼                                                               │
│  8. VERIFY SIGNATURE (Optional)                                              │
│     ┌──────────────────┐                                                    │
│     │  Verify with     │  Authenticate sender                               │
│     │  Public Key      │                                                    │
│     └────────┬─────────┘                                                    │
│              │                                                               │
│              ▼                                                               │
│  9. DECRYPT                                                                  │
│     ┌──────────────────┐                                                    │
│     │  AES-256-CTR     │  Recipient decrypts with derived key               │
│     │  (WASM module)   │  Ciphertext → Binary                               │
│     └────────┬─────────┘                                                    │
│              │                                                               │
│              ▼                                                               │
│  10. READ FLATBUFFER                                                         │
│     ┌──────────────────┐                                                    │
│     │  Generated Code  │  Parse decrypted binary                            │
│     │  SecureMessage   │  Access fields: id, sender, payload, etc.          │
│     └──────────────────┘                                                    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Code Example (TypeScript/Node.js)

```typescript
import { FlatBufferWasm } from 'flatc-wasm';

// 1. Load WASM modules
const flatc = await FlatBufferWasm.create();
const crypto = await loadCryptoWasm();

// 2. Generate code from schema (or use pre-generated)
const schema = `
namespace E2E.Crypto;
table SecureMessage {
  id: string;
  sender: string;
  recipient: string;
  payload: Payload;
  timestamp: int64;
}
table Payload {
  message: string;
  data: [ubyte];
  is_encrypted: bool;
}
root_type SecureMessage;
file_identifier "SECM";
`;
const code = flatc.generateCode(schema, { lang: 'typescript' });

// 3. Create FlatBuffer
const builder = new flatbuffers.Builder(1024);
const msg = SecureMessage.createSecureMessage(builder, ...);
const buffer = builder.asUint8Array();

// 4. ECDH Key Exchange
const { privateKey: senderPriv, publicKey: senderPub } = crypto.x25519GenerateKeypair();
const { privateKey: recipientPriv, publicKey: recipientPub } = crypto.x25519GenerateKeypair();
const sharedSecret = crypto.x25519SharedSecret(senderPriv, recipientPub);
const aesKey = crypto.hkdf(sharedSecret, salt, info, 32);
const iv = crypto.randomBytes(16);

// 5. Encrypt
const ciphertext = crypto.encrypt(aesKey, iv, buffer);

// 6. Sign (optional)
const signature = crypto.ed25519Sign(senderPriv, ciphertext);

// 7. Transmit (ciphertext + signature + senderPub + iv)

// 8. Verify signature
const isValid = crypto.ed25519Verify(senderPub, ciphertext, signature);

// 9. Decrypt (recipient side)
const recipientShared = crypto.x25519SharedSecret(recipientPriv, senderPub);
const recipientKey = crypto.hkdf(recipientShared, salt, info, 32);
const plaintext = crypto.decrypt(recipientKey, iv, ciphertext);

// 10. Read FlatBuffer
const msg = SecureMessage.getRootAsSecureMessage(new ByteBuffer(plaintext));
console.log(msg.id(), msg.sender(), msg.payload().message());
```

## Transparent Encryption Model

**Key concept:** Encryption is TRANSPARENT. The same FlatBuffers schema works for both
encrypted and unencrypted messages. Encryption is applied to the serialized FlatBuffer
binary, not to specific fields in the schema.

```
┌──────────────┐      ┌─────────────────┐      ┌─────────────────┐
│  JSON Data   │  →   │  FlatBuffer     │  →   │  Encrypted      │
│              │      │  Binary         │      │  Binary         │
└──────────────┘      └─────────────────┘      └─────────────────┘
     Same schema for both encrypted and unencrypted
```

**How users identify encrypted messages:**
- File identifier (e.g., `"MONS"` vs `"MONE"`)
- A user-defined field in the message
- External metadata or protocol headers
- File extension or naming convention

## Test Runners

| Language | Runtime | Tests | Location |
|----------|---------|-------|----------|
| Node.js | V8 (native) | 37/37 | `runners/node/` |
| Go | wazero | 19/19 | `runners/go/` |
| Python | wasmtime | 18/18 | `runners/python/` |
| Rust | wasmtime | 18/18 | `runners/rust/` |
| Java | Chicory | 18/18 | `runners/java/` |
| C# | Wasmtime | 18/18 | `runners/csharp/` |
| Swift | Wasmtime C API | 18/18 | `runners/swift/` |

## Supported Cryptographic Operations

### Symmetric Encryption
| Operation | Algorithm | Key Size | Notes |
|-----------|-----------|----------|-------|
| Encrypt | AES-256-CTR | 256-bit | Stream cipher, no padding needed |
| Decrypt | AES-256-CTR | 256-bit | Same as encrypt (symmetric) |

### Hashing & Key Derivation
| Operation | Algorithm | Output | Notes |
|-----------|-----------|--------|-------|
| Hash | SHA-256 | 32 bytes | Cryptographic hash |
| KDF | HKDF-SHA256 | Variable | Derive keys from shared secrets |

### Key Exchange (ECDH)
| Algorithm | Private Key | Public Key | Shared Secret |
|-----------|-------------|------------|---------------|
| X25519 | 32 bytes | 32 bytes | 32 bytes |
| secp256k1 | 32 bytes | 33 bytes (compressed) | 32 bytes |
| P-256 | 32 bytes | 33 bytes (compressed) | 32 bytes |

### Digital Signatures
| Algorithm | Private Key | Public Key | Signature |
|-----------|-------------|------------|-----------|
| Ed25519 | 64 bytes | 32 bytes | 64 bytes |
| secp256k1 ECDSA | 32 bytes | 33-65 bytes | 70-72 bytes (DER) |
| P-256 ECDSA | 32 bytes | 33-65 bytes | 70-72 bytes (DER) |

## Supported Cryptocurrency Key Types

| # | Chain | Signature Scheme | Curve |
|---|-------|------------------|-------|
| 1 | Bitcoin | ECDSA | secp256k1 |
| 2 | Ethereum | ECDSA | secp256k1 |
| 3 | Solana | EdDSA | Ed25519 |
| 4 | SUI | EdDSA | Ed25519 |
| 5 | Cosmos | ECDSA | secp256k1 |
| 6 | Polkadot | Schnorr | Sr25519 |
| 7 | Cardano | EdDSA | Ed25519 |
| 8 | Tezos | EdDSA | Ed25519 |
| 9 | NEAR | EdDSA | Ed25519 |
| 10 | Aptos | EdDSA | Ed25519 |

## Quick Start

### Prerequisites

1. Build the WASM encryption module:
```bash
cd /path/to/flatbuffers
./scripts/build_wasm.sh
```

2. Generate test vectors (run once):
```bash
cd wasm/examples/e2e-crypto-test
node runners/node/create_messages.mjs
```

### Running Tests

**Node.js (reference implementation):**
```bash
cd runners/node
npm link flatc-wasm  # Link the WASM module
npm test
```

**Go:**
```bash
cd runners/go
go run test_runner.go
```

**Python:**
```bash
cd runners/python
pip install wasmtime
python test_runner.py
```

**Rust:**
```bash
cd runners/rust
cargo run
```

**Java:**
```bash
cd runners/java
mvn compile exec:java
```

**C#:**
```bash
cd runners/csharp
dotnet run
```

**Swift:**
```bash
cd runners/swift
swift run
```

## Test Structure

### Test Vectors

Located in `vectors/`:
- `encryption_keys.json` - AES-256 keys and IVs for each chain
- `crypto_keys.json` - ECDH/signature keypairs for each chain
- `test_vectors.json` - Test configuration pointing to upstream schemas

### Generated Binaries

The Node.js test runner generates binary files in `vectors/binary/`:
- `secure_message_unencrypted.bin` - Unencrypted FlatBuffer
- `secure_message_encrypted_*.bin` - Encrypted with each chain's key
- `ecdh_headers.json` - ECDH public keys and encrypted payloads

## What Each Test Validates

### Test 1: WASM Module Loading
Verifies the WASM crypto module loads correctly with all required exports:
- Memory allocation (`malloc`, `free`)
- Crypto functions (`wasi_sha256`, `wasi_encrypt_bytes`, etc.)
- Indirect function table for `invoke_*` trampolines

### Test 2: SHA-256 Hash
Verifies SHA-256 produces identical output across all WASM runtimes:
```
SHA256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
```

### Test 3: AES-256-CTR Encryption/Decryption
Tests symmetric encryption:
1. Encrypt plaintext with key and IV
2. Verify ciphertext differs from plaintext
3. Decrypt ciphertext
4. Verify decrypted data matches original

### Test 4: HKDF Key Derivation
Derives encryption keys from shared secrets:
```
derivedKey = HKDF-SHA256(ikm=sharedSecret, salt=[], info="context", length=32)
```

### Tests 5-7: ECDH Key Exchange
For each curve (X25519, secp256k1, P-256):
1. Generate keypair for Alice
2. Generate keypair for Bob
3. Alice computes shared secret with her private + Bob's public
4. Bob computes shared secret with his private + Alice's public
5. Verify both shared secrets are identical

### Tests 8-10: Digital Signatures
For each algorithm (Ed25519, secp256k1, P-256):
1. Generate signing keypair
2. Sign message with private key
3. Verify signature with public key
4. Verify invalid signature is rejected

### Test 11: Full ECDH + HKDF + AES Pipeline
Complete encryption flow:
1. Generate ECDH keypairs
2. Compute shared secret
3. Derive AES key via HKDF
4. Encrypt message
5. Decrypt message
6. Verify round-trip

### Tests 12-15: Edge Cases
- Large data encryption (10KB)
- Invalid signature rejection for each algorithm

### Test 16: Signed Encryption
Combines encryption with authentication:
1. Encrypt payload
2. Sign ciphertext
3. Verify signature
4. Decrypt payload

### Test 17: Multi-Recipient Encryption
Encrypts for multiple recipients using ECDH:
1. Sender generates keypair
2. Each recipient generates keypair
3. Sender derives unique key for each recipient
4. Each recipient can decrypt with their own derived key

### Test 18: FlatBuffer Creation
Creates FlatBuffers using generated code:
1. Build SecureMessage with nested Payload
2. Finish buffer with file identifier
3. Verify binary has correct structure
4. Read back and verify all fields

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Test Runner (any language)           │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │   SHA-256   │  │   ECDH      │  │  FlatBuffer │     │
│  │   AES-CTR   │  │   Signing   │  │  Creation   │     │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘     │
│         │                │                │             │
│         └────────────────┼────────────────┘             │
│                          │                              │
│                          ▼                              │
│         ┌────────────────────────────────┐             │
│         │     WASM Runtime Adapter       │             │
│         │  (wazero/wasmtime/Chicory/etc) │             │
│         └────────────────┬───────────────┘             │
│                          │                              │
└──────────────────────────┼──────────────────────────────┘
                           │
                           ▼
            ┌──────────────────────────────┐
            │   flatc-encryption.wasm      │
            │   (Crypto++ compiled)        │
            │                              │
            │  • AES-256-CTR               │
            │  • SHA-256                   │
            │  • HKDF-SHA256               │
            │  • X25519 ECDH               │
            │  • secp256k1 ECDH/ECDSA      │
            │  • P-256 ECDH/ECDSA          │
            │  • Ed25519 Sign/Verify       │
            └──────────────────────────────┘
```

## WASM Runtime Dependencies

| Language | WASM Runtime | Package |
|----------|--------------|---------|
| Node.js | V8 (native) | Built-in WebAssembly |
| Go | wazero | `github.com/tetratelabs/wazero` |
| Python | wasmtime | `pip install wasmtime` |
| Rust | wasmtime | `wasmtime` crate v27 |
| Java | Chicory | `com.dylibso.chicory:runtime:1.5.3` |
| C# | Wasmtime | `Wasmtime` NuGet 22.0.0 |
| Swift | Wasmtime | Wasmtime C API |

## Adding a New Language

1. Create a new directory under `runners/`
2. Implement WASM loading with your chosen runtime
3. Implement Emscripten `invoke_*` trampolines (call indirect function table)
4. Implement exception handling stubs (`__cxa_*`, `setThrew`)
5. Test all crypto operations:
   - SHA-256
   - AES-256-CTR encrypt/decrypt
   - HKDF-SHA256
   - X25519/secp256k1/P-256 ECDH
   - Ed25519/secp256k1/P-256 signatures
6. Implement FlatBuffer creation test
7. Verify against Node.js generated binaries

### Key Implementation Details

**invoke_* Trampolines:**
All `invoke_*` functions must look up and call functions from the indirect function table:
```
invoke_vi(index, arg0) → table[index](arg0)
invoke_viii(index, a0, a1, a2) → table[index](a0, a1, a2)
```

**Exception Handling Stubs:**
```
setThrew(flag, value) → no-op
__cxa_begin_catch(ptr) → return ptr
__cxa_end_catch() → no-op
```

**WASI Stubs:**
```
random_get(buf, len) → fill with random bytes
clock_time_get(id, precision, time_ptr) → write current time
```

## Schema Usage

This test framework uses a custom `SecureMessage` schema for FlatBuffer creation tests:

```flatbuffers
namespace E2E.Crypto;

table SecureMessage {
  id: string;
  sender: string;
  recipient: string;
  payload: Payload;
  timestamp: int64;
}

table Payload {
  message: string;
  value: int32;
  data: [ubyte];
  is_encrypted: bool;
}

root_type SecureMessage;
file_identifier "SECM";
```

The Node.js runner also tests against upstream FlatBuffers test schemas for comprehensive coverage.

## Encryption Keys

The test framework uses pre-generated encryption keys stored in `vectors/encryption_keys.json`. Each cryptocurrency chain has its own AES-256 key and IV for testing transparent encryption.

### Key Format

```json
{
  "bitcoin": {
    "key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "iv": "0123456789abcdef0123456789abcdef"
  },
  "ethereum": {
    "key": "...",
    "iv": "..."
  }
}
```

- **key**: 256-bit AES key (64 hex characters = 32 bytes)
- **iv**: 128-bit initialization vector (32 hex characters = 16 bytes)

### Key Derivation in Practice

In real applications, you would derive the AES key from an ECDH shared secret:

```typescript
// 1. Exchange public keys with recipient
const senderKeypair = crypto.x25519GenerateKeypair();
const recipientPubKey = getRecipientPublicKey();

// 2. Compute shared secret
const sharedSecret = crypto.x25519SharedSecret(
  senderKeypair.privateKey,
  recipientPubKey
);

// 3. Derive AES key using HKDF
const aesKey = crypto.hkdf(
  sharedSecret,           // Input key material
  [],                     // Salt (optional)
  "encryption-key-v1",    // Context info
  32                      // Output length (256 bits)
);

// 4. Generate random IV for each message
const iv = crypto.randomBytes(16);

// 5. Encrypt FlatBuffer binary
const ciphertext = crypto.encrypt(aesKey, iv, flatbufferBinary);
```

## Cryptocurrency Keys

The framework supports cryptographic operations compatible with 10 major blockchain ecosystems. Keys are stored in `vectors/crypto_keys.json`.

### Key Types by Chain

| Chain | ECDH Curve | Signature | Private Key | Public Key |
|-------|------------|-----------|-------------|------------|
| Bitcoin | secp256k1 | ECDSA | 32 bytes | 33 bytes (compressed) |
| Ethereum | secp256k1 | ECDSA | 32 bytes | 33 bytes (compressed) |
| Solana | X25519 | Ed25519 | 64 bytes | 32 bytes |
| SUI | X25519 | Ed25519 | 64 bytes | 32 bytes |
| Cosmos | secp256k1 | ECDSA | 32 bytes | 33 bytes (compressed) |
| Polkadot | X25519 | Sr25519* | 64 bytes | 32 bytes |
| Cardano | X25519 | Ed25519 | 64 bytes | 32 bytes |
| Tezos | X25519 | Ed25519 | 64 bytes | 32 bytes |
| NEAR | X25519 | Ed25519 | 64 bytes | 32 bytes |
| Aptos | X25519 | Ed25519 | 64 bytes | 32 bytes |

*Sr25519 uses Ed25519 in this implementation for compatibility.

### Crypto Keys Format

```json
{
  "bitcoin": {
    "ecdh": {
      "privateKey": "hex...",
      "publicKey": "hex..."
    },
    "signing": {
      "privateKey": "hex...",
      "publicKey": "hex..."
    }
  },
  "solana": {
    "ecdh": {
      "privateKey": "hex...",
      "publicKey": "hex..."
    },
    "signing": {
      "privateKey": "hex...",
      "publicKey": "hex..."
    }
  }
}
```

### Using Cryptocurrency Keys

**For Bitcoin/Ethereum/Cosmos (secp256k1):**

```typescript
// Key generation
const keypair = crypto.secp256k1GenerateKeypair();
// keypair.privateKey: 32 bytes
// keypair.publicKey: 33 bytes (compressed)

// ECDH shared secret
const shared = crypto.secp256k1SharedSecret(
  myPrivateKey,
  theirPublicKey
);

// Signing
const signature = crypto.secp256k1Sign(privateKey, messageHash);
const isValid = crypto.secp256k1Verify(publicKey, messageHash, signature);
```

**For Solana/Cardano/NEAR/Aptos (Ed25519):**

```typescript
// Key generation
const keypair = crypto.ed25519GenerateKeypair();
// keypair.privateKey: 64 bytes (includes public key)
// keypair.publicKey: 32 bytes

// ECDH (use X25519 for key exchange)
const x25519Keypair = crypto.x25519GenerateKeypair();
const shared = crypto.x25519SharedSecret(
  myX25519PrivateKey,
  theirX25519PublicKey
);

// Signing
const signature = crypto.ed25519Sign(privateKey, message);
const isValid = crypto.ed25519Verify(publicKey, message, signature);
```

**For P-256 (NIST curve):**

```typescript
// Key generation
const keypair = crypto.p256GenerateKeypair();
// keypair.privateKey: 32 bytes
// keypair.publicKey: 33 bytes (compressed)

// ECDH shared secret
const shared = crypto.p256SharedSecret(myPrivateKey, theirPublicKey);

// Signing
const signature = crypto.p256Sign(privateKey, messageHash);
const isValid = crypto.p256Verify(publicKey, messageHash, signature);
```

### Key Size Reference

| Algorithm | Private Key | Public Key | Shared Secret | Signature |
|-----------|-------------|------------|---------------|-----------|
| X25519 | 32 bytes | 32 bytes | 32 bytes | N/A |
| Ed25519 | 64 bytes | 32 bytes | N/A | 64 bytes |
| secp256k1 | 32 bytes | 33/65 bytes | 32 bytes | 70-72 bytes |
| P-256 | 32 bytes | 33/65 bytes | 32 bytes | 70-72 bytes |

### Security Considerations

1. **Never reuse IVs** - Generate a new random IV for each encryption operation
2. **Use HKDF for key derivation** - Don't use raw ECDH output directly as encryption key
3. **Include context in HKDF** - Use unique info strings for different purposes
4. **Verify signatures before decryption** - Authenticate messages before processing
5. **Use constant-time operations** - The WASM module handles this internally

### Multi-Recipient Encryption

For encrypting to multiple recipients:

```typescript
// Sender generates ephemeral keypair
const senderKeypair = crypto.x25519GenerateKeypair();

// For each recipient, derive a unique key
const recipients = [recipientAPubKey, recipientBPubKey, recipientCPubKey];
const encryptedPayloads = [];

for (const recipientPub of recipients) {
  // Compute shared secret with this recipient
  const shared = crypto.x25519SharedSecret(senderKeypair.privateKey, recipientPub);

  // Derive unique key for this recipient
  const recipientKey = crypto.hkdf(shared, [], `recipient-${index}`, 32);

  // Encrypt payload
  const encrypted = crypto.encrypt(recipientKey, iv, payload);
  encryptedPayloads.push({
    recipientPublicKey: recipientPub,
    ciphertext: encrypted
  });
}

// Include sender's public key so recipients can derive the shared secret
const message = {
  senderPublicKey: senderKeypair.publicKey,
  iv: iv,
  payloads: encryptedPayloads
};
```

Each recipient decrypts with:

```typescript
// Recipient derives the same shared secret
const shared = crypto.x25519SharedSecret(myPrivateKey, message.senderPublicKey);
const myKey = crypto.hkdf(shared, [], `recipient-${myIndex}`, 32);
const plaintext = crypto.decrypt(myKey, message.iv, myPayload.ciphertext);
```

## License

Apache 2.0 - Same as FlatBuffers
