# Encryption Module

The `encryption.mjs` module provides a comprehensive cryptographic API built on WebAssembly (Crypto++) and Web Crypto. It supports AES-256-CTR encryption, authenticated encryption, multiple elliptic curve key exchange protocols, digital signatures, and per-field FlatBuffer encryption with deterministic nonce management.

## Initialization

Before using any WASM-based crypto functions, initialize the module:

```javascript
import { loadEncryptionWasm, isInitialized, hasCryptopp, getVersion } from 'flatc-wasm';

await loadEncryptionWasm();

console.log(isInitialized());  // true
console.log(hasCryptopp());    // true (Crypto++ backend available)
console.log(getVersion());     // e.g. "1.0.0"
```

> **Note:** P-256 and P-384 functions use the Web Crypto API (`crypto.subtle`) and do not require WASM initialization. All other crypto functions require `loadEncryptionWasm()`.

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `KEY_SIZE` | 32 | AES-256 key size in bytes |
| `IV_SIZE` | 16 | AES-CTR initialization vector size |
| `NONCE_SIZE` | 12 | Nonce size for nonce derivation |
| `SHA256_SIZE` | 32 | SHA-256 digest size |
| `HMAC_SIZE` | 32 | HMAC-SHA256 output size |
| `X25519_PRIVATE_KEY_SIZE` | 32 | X25519 private key size |
| `X25519_PUBLIC_KEY_SIZE` | 32 | X25519 public key size |
| `SECP256K1_PRIVATE_KEY_SIZE` | 32 | secp256k1 private key size |
| `SECP256K1_PUBLIC_KEY_SIZE` | 33 | secp256k1 compressed public key size |
| `P384_PRIVATE_KEY_SIZE` | 48 | P-384 private key size |
| `P384_PUBLIC_KEY_SIZE` | 49 | P-384 compressed public key size |
| `ED25519_PRIVATE_KEY_SIZE` | 64 | Ed25519 private key size (seed + public) |
| `ED25519_PUBLIC_KEY_SIZE` | 32 | Ed25519 public key size |
| `ED25519_SIGNATURE_SIZE` | 64 | Ed25519 signature size |

## Error Handling

All crypto operations throw `CryptoError` on failure:

```javascript
import { CryptoError, CryptoErrorCode } from 'flatc-wasm';

try {
  encryptBytes(data, key, iv);
} catch (e) {
  if (e instanceof CryptoError) {
    console.error(e.code);    // e.g. 'INVALID_KEY'
    console.error(e.message); // Human-readable description
  }
}
```

**Error codes:**

| Code | Description |
|------|-------------|
| `UNINITIALIZED` | WASM module not loaded |
| `INVALID_KEY` | Wrong key size or format |
| `INVALID_IV` | Wrong IV size or format |
| `INVALID_INPUT` | Invalid input data |
| `WASM_ERROR` | Internal WASM operation failure |
| `KEY_GENERATION_FAILED` | Key pair generation failed |
| `ECDH_FAILED` | ECDH key agreement failed |
| `SIGN_FAILED` | Signature creation failed |
| `VERIFY_FAILED` | Signature verification failed |
| `AUTHENTICATION_FAILED` | MAC verification failed |
| `ALLOCATION_FAILED` | WASM memory allocation failed |

---

## Hash Functions

### SHA-256

```javascript
import { sha256 } from 'flatc-wasm';

const digest = sha256(new Uint8Array([1, 2, 3]));
// Returns Uint8Array (32 bytes)
```

### HMAC-SHA256

```javascript
import { hmacSha256, hmacSha256Verify } from 'flatc-wasm';

const mac = hmacSha256(key, data);
// Returns Uint8Array (32 bytes)

const valid = hmacSha256Verify(key, data, mac);
// Returns boolean (constant-time comparison)
```

### HKDF (HMAC-based Key Derivation)

```javascript
import { hkdf } from 'flatc-wasm';

const derivedKey = hkdf(
  inputKeyMaterial,          // Uint8Array
  salt,                      // Uint8Array or null
  info,                      // Uint8Array or null (context/label)
  32                         // Output length in bytes
);
```

---

## AES-256-CTR Encryption

### In-Place Encryption

Encrypts/decrypts the buffer in place (modifies the input array):

```javascript
import { encryptBytes, decryptBytes } from 'flatc-wasm';

const data = new Uint8Array([1, 2, 3, 4]);
const key = crypto.getRandomValues(new Uint8Array(32));
const iv = crypto.getRandomValues(new Uint8Array(16));

encryptBytes(data, key, iv);  // data is now ciphertext
decryptBytes(data, key, iv);  // data is restored to plaintext
```

### Non-Destructive Encryption

Returns new arrays instead of modifying the input:

```javascript
import { encryptBytesCopy, decryptBytesCopy } from 'flatc-wasm';

const { ciphertext, iv } = encryptBytesCopy(plaintext, key);
// iv is auto-generated if not provided

const plaintext = decryptBytesCopy(ciphertext, key, iv);
```

### IV Tracking

The module tracks IVs per key to warn about dangerous IV reuse:

```javascript
import { clearIVTracking, clearAllIVTracking } from 'flatc-wasm';

clearIVTracking(key);    // Clear tracking for a specific key
clearAllIVTracking();    // Clear all IV tracking state
```

---

## Authenticated Encryption

AES-256-CTR + HMAC-SHA256 with optional associated data (AAD).

Wire format: `IV (16 bytes) || ciphertext || HMAC (32 bytes)`

```javascript
import { encryptAuthenticated, decryptAuthenticated } from 'flatc-wasm';

const aad = new TextEncoder().encode('context-string');

// Encrypt with authentication
const message = encryptAuthenticated(plaintext, key, aad);

// Decrypt and verify integrity
const plaintext = decryptAuthenticated(message, key, aad);
// Throws CryptoError (AUTHENTICATION_FAILED) if tampered
```

---

## Key Exchange

### X25519 (Curve25519 ECDH)

Fast elliptic curve Diffie-Hellman. Keys are 32 bytes. Powered by WASM (Crypto++).

```javascript
import { x25519GenerateKeyPair, x25519SharedSecret, x25519DeriveKey } from 'flatc-wasm';

const alice = x25519GenerateKeyPair();
const bob = x25519GenerateKeyPair();

// Compute shared secret (both sides derive the same value)
const secretA = x25519SharedSecret(alice.privateKey, bob.publicKey);
const secretB = x25519SharedSecret(bob.privateKey, alice.publicKey);

// Derive an AES-256 key from shared secret via HKDF
const aesKey = x25519DeriveKey(secretA, 'my-app-context');
```

### secp256k1 (ECDH + ECDSA)

Bitcoin/Ethereum elliptic curve. 32-byte private keys, 33-byte compressed public keys. Powered by WASM (Crypto++).

```javascript
import {
  secp256k1GenerateKeyPair, secp256k1SharedSecret, secp256k1DeriveKey,
  secp256k1Sign, secp256k1Verify
} from 'flatc-wasm';

// Key exchange
const kp = secp256k1GenerateKeyPair();
const shared = secp256k1SharedSecret(kp.privateKey, otherPublicKey);
const aesKey = secp256k1DeriveKey(shared, 'context');

// Sign and verify
const signature = secp256k1Sign(kp.privateKey, data);
const valid = secp256k1Verify(kp.publicKey, data, signature);
```

### P-256 (NIST, Web Crypto)

FIPS-approved NIST curve. Uses the Web Crypto API — all functions are **async**. Private keys are PKCS#8 format, public keys are uncompressed (65 bytes).

```javascript
import {
  p256GenerateKeyPairAsync, p256SharedSecretAsync, p256DeriveKey,
  p256SignAsync, p256VerifyAsync
} from 'flatc-wasm';

const kp = await p256GenerateKeyPairAsync();
const shared = await p256SharedSecretAsync(kp.privateKey, otherPublicKey);
const aesKey = p256DeriveKey(shared, 'context');

const signature = await p256SignAsync(kp.privateKey, data);
const valid = await p256VerifyAsync(kp.publicKey, data, signature);
```

### P-384 (NIST, Web Crypto)

Higher-security NIST curve. Same API pattern as P-256, uses Web Crypto. Public keys are 97 bytes (uncompressed).

```javascript
import {
  p384GenerateKeyPairAsync, p384SharedSecretAsync, p384DeriveKey,
  p384SignAsync, p384VerifyAsync
} from 'flatc-wasm';

const kp = await p384GenerateKeyPairAsync();
const shared = await p384SharedSecretAsync(kp.privateKey, otherPublicKey);
const aesKey = p384DeriveKey(shared, 'context');

const signature = await p384SignAsync(kp.privateKey, data);
const valid = await p384VerifyAsync(kp.publicKey, data, signature);
```

---

## Digital Signatures

### Ed25519

High-performance EdDSA signatures. 64-byte private keys, 32-byte public keys, 64-byte signatures. Powered by WASM (Crypto++).

```javascript
import { ed25519GenerateKeyPair, ed25519Sign, ed25519Verify } from 'flatc-wasm';

const kp = ed25519GenerateKeyPair();

const signature = ed25519Sign(kp.privateKey, data);
const valid = ed25519Verify(kp.publicKey, data, signature);
```

---

## Crypto Backend Summary

| Algorithm | Backend | Sync/Async | Key Sizes |
|-----------|---------|------------|-----------|
| AES-256-CTR | WASM (Crypto++) | Sync | 32-byte key, 16-byte IV |
| SHA-256 | WASM (Crypto++) | Sync | - |
| HMAC-SHA256 | JS + WASM SHA-256 | Sync | Any key size |
| HKDF-SHA256 | WASM (Crypto++) | Sync | Variable |
| X25519 | WASM (Crypto++) | Sync | 32-byte priv/pub |
| secp256k1 | WASM (Crypto++) | Sync | 32-byte priv, 33-byte pub |
| Ed25519 | WASM (Crypto++) | Sync | 64-byte priv, 32-byte pub |
| P-256 | Web Crypto | Async | PKCS#8 priv, 65-byte pub |
| P-384 | Web Crypto | Async | PKCS#8 priv, 97-byte pub |

---

## Nonce Generation and Derivation

### Generating a Nonce Start

```javascript
import { generateNonceStart } from 'flatc-wasm';

const nonceStart = generateNonceStart();  // 12 bytes from CSPRNG
```

### Deriving Nonces

Each field gets a unique 96-bit (12-byte) nonce derived via big-endian addition:

```text
derived_nonce = nonceStart + combined_index
combined_index = recordIndex * 65536 + fieldId
```

This provides:

- **2^16 (65,536) unique field IDs per record**
- **2^80 unique record indices** before the combined index could theoretically wrap
- **Deterministic derivation** - same inputs always produce the same nonce

```javascript
import { deriveNonce } from 'flatc-wasm';

const nonce_r0_f0 = deriveNonce(nonceStart, 0);           // record 0, field 0
const nonce_r0_f1 = deriveNonce(nonceStart, 1);           // record 0, field 1
const nonce_r1_f0 = deriveNonce(nonceStart, 65536);       // record 1, field 0
const nonce_r5_f3 = deriveNonce(nonceStart, 5 * 65536 + 3); // record 5, field 3
```

---

## Header Utilities

Encryption headers carry the parameters needed for decryption (sender's ephemeral public key, nonce start, algorithm, context).

```javascript
import {
  computeKeyId,
  createEncryptionHeader,
  encryptionHeaderToJSON,
  encryptionHeaderFromJSON
} from 'flatc-wasm';

// Compute a key ID (first 8 bytes of SHA-256)
const keyId = computeKeyId(publicKey);

// Create a header manually
const header = createEncryptionHeader({
  algorithm: 'x25519',
  senderPublicKey: ephemeralPublicKey,
  recipientKeyId: keyId,
  nonceStart: generateNonceStart(),
  context: 'my-app'
});

// Serialize/deserialize
const json = encryptionHeaderToJSON(header);
const restored = encryptionHeaderFromJSON(json);
```

### Header Format

| Field | Size | Description |
|-------|------|-------------|
| `version` | 1 byte | Header format version (2 = nonce_start required) |
| `algorithm` | string | Key exchange algorithm (`x25519`, `secp256k1`) |
| `senderPublicKey` | 32-33 bytes | Sender's ephemeral ECDH public key |
| `recipientKeyId` | 8 bytes | First 8 bytes of SHA-256 of recipient's public key |
| `nonceStart` | 12 bytes | Random starting nonce from CSPRNG |
| `context` | variable | Optional HKDF domain separation string |

---

## EncryptionContext (Per-Field ECIES)

The `EncryptionContext` class manages encrypted sessions with per-field key and IV derivation. It supports symmetric mode (direct key) and ECIES mode (ephemeral key exchange).

### Symmetric Mode

```javascript
import { EncryptionContext } from 'flatc-wasm';

const key = crypto.getRandomValues(new Uint8Array(32));
const ctx = new EncryptionContext(key);

// Also accepts hex string
const ctx2 = EncryptionContext.fromHex('abcdef...');  // 64 hex chars
```

### ECIES Mode - Encryption

```javascript
const ctx = EncryptionContext.forEncryption(recipientPublicKey, {
  algorithm: 'x25519',           // or 'secp256k1'
  context: 'my-application-v1',  // HKDF domain separation
  // nonceStart is auto-generated if not provided
});

// Get header to send to recipient
const header = ctx.getHeader();
const headerJSON = ctx.getHeaderJSON();
```

### ECIES Mode - Decryption

```javascript
const ctx = EncryptionContext.forDecryption(
  myPrivateKey,
  header,             // Received from sender
  'my-application-v1' // Must match sender's context
);
```

### Per-Field Encryption

Each FlatBuffer field gets a unique key and IV derived from the session key, field ID, and record index:

```javascript
// Encrypt fields in a FlatBuffer
for (let recordIndex = 0; recordIndex < records.length; recordIndex++) {
  ctx.setRecordIndex(recordIndex);

  for (const field of encryptedFields) {
    ctx.encryptScalar(buffer, field.offset, field.length, field.id, recordIndex);
  }
}

// Decrypt - same API, any record order
ctx.setRecordIndex(42);
ctx.decryptScalar(buffer, field.offset, field.length, field.id, 42);
```

### Nonce Management

```javascript
ctx.getNonceStart();         // Get the 12-byte nonce start
ctx.getRecordIndex();        // Current record index
ctx.setRecordIndex(n);       // Set record index
ctx.nextRecordIndex();       // Increment and return
ctx.deriveFieldNonce(fieldId, recordIndex);  // Get unique nonce for field
```

### EncryptionContext API Reference

```typescript
class EncryptionContext {
  constructor(key: Uint8Array | string, nonceStart?: Uint8Array);
  static fromHex(hexKey: string): EncryptionContext;
  static forEncryption(recipientPublicKey: Uint8Array, options?: {
    algorithm?: 'x25519' | 'secp256k1';
    context?: string;
    nonceStart?: Uint8Array;
  }): EncryptionContext;
  static forDecryption(
    privateKey: Uint8Array,
    header: EncryptionHeader,
    context?: string
  ): EncryptionContext;

  isValid(): boolean;
  getKey(): Uint8Array;
  getNonceStart(): Uint8Array | null;
  getRecordIndex(): number;
  setRecordIndex(index: number): void;
  nextRecordIndex(): number;
  getEphemeralPublicKey(): Uint8Array | null;
  getAlgorithm(): string | null;
  getContext(): string | null;

  deriveFieldKey(fieldId: number, recordIndex?: number): Uint8Array;
  deriveFieldNonce(fieldId: number, recordIndex?: number): Uint8Array;
  encryptScalar(buffer: Uint8Array, offset: number, length: number,
                fieldId: number, recordIndex?: number): void;
  decryptScalar(buffer: Uint8Array, offset: number, length: number,
                fieldId: number, recordIndex?: number): void;

  getHeader(): EncryptionHeader;
  getHeaderJSON(): string;
}
```

---

## Establishing an Encrypted Session

### Step 1: Sender Creates Context

```javascript
import { EncryptionContext } from 'flatc-wasm';

const ctx = EncryptionContext.forEncryption(recipientPublicKey, {
  algorithm: 'x25519',
  context: 'my-application-v1',
});

const header = ctx.getHeader();
```

### Step 2: Send Header First

The `EncryptionHeader` **MUST** be transmitted before any encrypted data.

```javascript
const headerJSON = ctx.getHeaderJSON();
await transport.send({ type: 'encryption_header', payload: headerJSON });
```

### Step 3: Encrypt and Send Records

```javascript
for (let recordIndex = 0; recordIndex < records.length; recordIndex++) {
  ctx.setRecordIndex(recordIndex);

  for (const field of encryptedFields) {
    ctx.encryptScalar(buffer, field.offset, field.length, field.id, recordIndex);
  }

  await transport.send({
    type: 'encrypted_record',
    recordIndex,
    payload: buffer
  });
}
```

### Step 4: Recipient Decrypts

```javascript
import { EncryptionContext, encryptionHeaderFromJSON } from 'flatc-wasm';

const header = encryptionHeaderFromJSON(headerJSON);
const ctx = EncryptionContext.forDecryption(myPrivateKey, header, 'my-application-v1');

// Records can be decrypted in any order
ctx.setRecordIndex(msg.recordIndex);
for (const field of encryptedFields) {
  ctx.decryptScalar(msg.payload, field.offset, field.length, field.id, msg.recordIndex);
}
```

---

## Offline and Out-of-Order Decryption

Once the header is received, decryption requires no further communication:

```javascript
// Store header for later
localStorage.setItem('session_header', ctx.getHeaderJSON());

// Later, even offline
const header = encryptionHeaderFromJSON(localStorage.getItem('session_header'));
const ctx = EncryptionContext.forDecryption(myPrivateKey, header, 'my-app');

// Decrypt any record by index
ctx.setRecordIndex(42);
ctx.decryptScalar(encryptedData, offset, length, fieldId, 42);
```

Records can arrive and be processed in any order since nonces are derived deterministically from the record index.

---

## Parallel Decryption

Different records can be decrypted simultaneously in separate workers:

```javascript
// Main thread
const header = ctx.getHeader();

const workers = encryptedRecords.map((record, index) => {
  return new Promise((resolve) => {
    const worker = new Worker('decrypt-worker.js');
    worker.postMessage({ privateKey: myPrivateKey, header, context: 'my-app', recordIndex: index, encryptedData: record });
    worker.onmessage = (e) => resolve(e.data);
  });
});

const decryptedRecords = await Promise.all(workers);
```

```javascript
// decrypt-worker.js
import { EncryptionContext, encryptionHeaderFromJSON } from 'flatc-wasm';

self.onmessage = (event) => {
  const { privateKey, header, context, recordIndex, encryptedData } = event.data;
  const ctx = EncryptionContext.forDecryption(
    new Uint8Array(privateKey), encryptionHeaderFromJSON(header), context
  );
  ctx.setRecordIndex(recordIndex);
  const decrypted = new Uint8Array(encryptedData);
  ctx.decryptScalar(decrypted, 0, decrypted.length, 0, recordIndex);
  self.postMessage(decrypted);
};
```

---

## Security Considerations

### Why Nonce Reuse is Catastrophic

AES-CTR encrypts by XORing plaintext with a keystream:

```text
ciphertext = plaintext XOR AES_CTR(key, nonce)
```

If the same (key, nonce) encrypts two different plaintexts:

```text
C1 XOR C2 = P1 XOR P2  // Keystream cancels out
```

This reveals the XOR of the plaintexts, enabling statistical recovery.

### How Nonce Incrementing Prevents This

- Every (recordIndex, fieldId) pair produces a unique nonce
- Even with billions of records, no nonce is reused
- The starting nonce is random (CSPRNG), so it's unpredictable

### Recommendations

1. **Always send header first** - Don't encrypt until recipient confirms header receipt
2. **Validate record indices** - Ensure indices are within expected range
3. **Use authenticated encryption** - Use `encryptAuthenticated()` for integrity verification when not using per-field mode
4. **Rotate sessions** - Start new sessions periodically with fresh `nonceStart` values
5. **Secure key storage** - The recipient's private key must be protected

---

## See Also

- [Node.js Integration](nodejs.md) - Using encryption in Node.js
- [Browser Integration](browser.md) - Using encryption in browsers
- [Streaming](streaming.md) - Size-prefixed message framing
