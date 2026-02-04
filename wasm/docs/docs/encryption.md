# Encryption Sessions & Nonce Management

This guide explains how to establish encrypted sessions using flatc-wasm's per-field encryption system, including the critical nonce management that ensures cryptographic security.

## Overview

flatc-wasm uses **AES-256-CTR** for per-field encryption. CTR (Counter) mode requires a unique nonce for every encryption operation with the same key. Reusing a nonce catastrophically compromises security.

To solve this, flatc-wasm implements a **nonce incrementor** system:

1. Generate a random 12-byte `nonceStart` using CSPRNG
2. Derive unique nonces for each field via: `nonceStart + (recordIndex × 65536 + fieldId)`
3. Send the `EncryptionHeader` (containing `nonceStart`) before any encrypted data
4. Recipients use the same derivation to decrypt any record in any order

## Establishing an Encrypted Session

### Step 1: Sender Creates Encryption Context

```javascript
import { EncryptionContext, generateNonceStart } from 'flatc-wasm';

// Create context for encrypting to a recipient
const ctx = EncryptionContext.forEncryption(recipientPublicKey, {
  algorithm: 'x25519',           // Key exchange algorithm
  context: 'my-application-v1',  // Domain separation for HKDF
  // nonceStart is auto-generated via CSPRNG if not provided
});

// Get the encryption header
const header = ctx.getHeader();
```

### Step 2: Send Header First

The `EncryptionHeader` MUST be transmitted before any encrypted data. It contains:

| Field | Size | Description |
|-------|------|-------------|
| `version` | 1 byte | Header format version (2 = nonce_start required) |
| `key_exchange` | 1 byte | Algorithm enum (X25519, Secp256k1, P256, P384) |
| `ephemeral_public_key` | 32-65 bytes | Sender's ephemeral ECDH public key |
| `nonce_start` | 12 bytes | Random starting nonce from CSPRNG |
| `context` | variable | Optional HKDF domain separation string |
| `timestamp` | 8 bytes | Optional Unix epoch milliseconds |

```javascript
// Serialize header as JSON or FlatBuffer
const headerJSON = ctx.getHeaderJSON();

// Send to recipient via your transport layer
await transport.send({
  type: 'encryption_header',
  payload: headerJSON
});
```

### Step 3: Encrypt and Send Records

```javascript
// Encrypt multiple records
for (let recordIndex = 0; recordIndex < records.length; recordIndex++) {
  ctx.setRecordIndex(recordIndex);

  // Encrypt each field
  for (const field of encryptedFields) {
    const nonce = ctx.deriveFieldNonce(field.id, recordIndex);
    ctx.encryptScalar(buffer, field.offset, field.length, field.id, recordIndex);
  }

  // Send encrypted record with its index
  await transport.send({
    type: 'encrypted_record',
    recordIndex: recordIndex,
    payload: buffer
  });
}
```

### Step 4: Recipient Establishes Decryption Context

```javascript
// Receive and parse the header first
const headerJSON = await transport.receive('encryption_header');
const header = encryptionHeaderFromJSON(headerJSON);

// Create decryption context using recipient's private key
const ctx = EncryptionContext.forDecryption(
  myPrivateKey,
  header,
  'my-application-v1'  // Must match sender's context
);
```

### Step 5: Decrypt Records (Any Order)

```javascript
// Records can be decrypted in any order
while (const msg = await transport.receive('encrypted_record')) {
  ctx.setRecordIndex(msg.recordIndex);

  for (const field of encryptedFields) {
    ctx.decryptScalar(msg.payload, field.offset, field.length, field.id, msg.recordIndex);
  }

  // Process decrypted record
  processRecord(msg.payload);
}
```

## Nonce Derivation Deep Dive

### The Algorithm

Each field gets a unique 96-bit (12-byte) nonce derived via big-endian addition:

```text
derived_nonce = nonceStart + combined_index
combined_index = recordIndex × 65536 + fieldId
```

This provides:

- **2^16 (65,536) unique field IDs per record**
- **2^80 unique record indices** before the combined index could theoretically wrap
- **Deterministic derivation** - same inputs always produce the same nonce

### Implementation

```javascript
import { deriveNonce, generateNonceStart } from 'flatc-wasm';

// Generate cryptographically secure starting nonce
const nonceStart = generateNonceStart();  // 12 bytes from CSPRNG

// Derive nonces for different fields
const nonce_r0_f0 = deriveNonce(nonceStart, 0);           // record 0, field 0
const nonce_r0_f1 = deriveNonce(nonceStart, 1);           // record 0, field 1
const nonce_r1_f0 = deriveNonce(nonceStart, 65536);       // record 1, field 0
const nonce_r5_f3 = deriveNonce(nonceStart, 5 * 65536 + 3); // record 5, field 3
```

### 96-Bit Addition with Carry

The nonce is treated as a big-endian 96-bit integer. Addition wraps around at 2^96:

```javascript
// Internal implementation (simplified)
function deriveNonce(nonceStart, recordIndex) {
  // Convert nonceStart to BigInt (big-endian)
  let value = 0n;
  for (let i = 0; i < 12; i++) {
    value = (value << 8n) | BigInt(nonceStart[i]);
  }

  // Add index with 96-bit wraparound
  const mask96 = (1n << 96n) - 1n;
  value = (value + BigInt(recordIndex)) & mask96;

  // Convert back to bytes (big-endian)
  const result = new Uint8Array(12);
  for (let i = 11; i >= 0; i--) {
    result[i] = Number(value & 0xFFn);
    value >>= 8n;
  }
  return result;
}
```

## Offline Decryption

Once the `EncryptionHeader` is received, decryption requires no further communication with the sender:

```javascript
// Store header for later use
localStorage.setItem('session_header', ctx.getHeaderJSON());

// ... Later, even offline ...

// Restore session
const savedHeader = localStorage.getItem('session_header');
const header = encryptionHeaderFromJSON(savedHeader);
const ctx = EncryptionContext.forDecryption(myPrivateKey, header, 'my-app');

// Decrypt any record using just its index
ctx.setRecordIndex(42);
ctx.decryptScalar(encryptedData, offset, length, fieldId);
```

## Out-of-Order Decryption

Records can arrive or be processed in any sequence:

```javascript
const ctx = EncryptionContext.forDecryption(privateKey, header, context);

// Process records as they arrive (not necessarily in order)
websocket.onmessage = (event) => {
  const { recordIndex, data } = parseMessage(event.data);

  // Set index for this specific record
  ctx.setRecordIndex(recordIndex);

  // Decrypt - nonce is derived from recordIndex
  ctx.decryptScalar(data, offset, length, fieldId, recordIndex);

  processDecryptedRecord(recordIndex, data);
};
```

## Parallel Decryption

Different records can be decrypted simultaneously in separate workers:

```javascript
// Main thread
const header = ctx.getHeader();

// Spawn workers for parallel decryption
const workers = encryptedRecords.map((record, index) => {
  return new Promise((resolve) => {
    const worker = new Worker('decrypt-worker.js');
    worker.postMessage({
      privateKey: myPrivateKey,
      header: header,
      context: 'my-app',
      recordIndex: index,
      encryptedData: record
    });
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

  // Each worker creates its own context
  const ctx = EncryptionContext.forDecryption(
    new Uint8Array(privateKey),
    encryptionHeaderFromJSON(header),
    context
  );

  ctx.setRecordIndex(recordIndex);
  const decrypted = new Uint8Array(encryptedData);
  ctx.decryptScalar(decrypted, 0, decrypted.length, 0, recordIndex);

  self.postMessage(decrypted);
};
```

## Recovering Unknown Record Index

If the record index is lost (e.g., corrupted metadata), you can brute-force recovery:

```javascript
async function recoverRecordIndex(encryptedData, ctx, validator, maxAttempts = 10000) {
  for (let i = 0; i < maxAttempts; i++) {
    try {
      // Make a copy to test decryption
      const testData = new Uint8Array(encryptedData);
      ctx.setRecordIndex(i);
      ctx.decryptScalar(testData, 0, testData.length, 0, i);

      // Validate the decrypted data
      if (validator(testData)) {
        return { recordIndex: i, data: testData };
      }
    } catch {
      // Invalid decryption, try next index
    }
  }
  throw new Error('Could not recover record index within max attempts');
}

// Usage with FlatBuffer validation
const result = await recoverRecordIndex(encrypted, ctx, (data) => {
  try {
    // Try to read as FlatBuffer - invalid data will throw
    const fb = MyTable.getRootAsMyTable(new ByteBuffer(data));
    return fb.someRequiredField() !== null;
  } catch {
    return false;
  }
});
```

**Performance note:** This approach is O(n) where n is the unknown range. For production systems, always include the record index in your message framing.

## Security Considerations

### Why Nonce Reuse is Catastrophic

AES-CTR encrypts by XORing plaintext with a keystream generated from the key and nonce:

```text
ciphertext = plaintext XOR AES_CTR(key, nonce)
```

If the same (key, nonce) pair encrypts two different plaintexts:

```text
C1 = P1 XOR keystream
C2 = P2 XOR keystream

C1 XOR C2 = P1 XOR P2  // Keystream cancels out!
```

This reveals:

1. **XOR of plaintexts** - Statistical analysis can recover both
2. **Partial plaintext recovery** - If P1 is known, P2 = C1 XOR C2 XOR P1
3. **Crib dragging** - Guess parts of one plaintext to reveal the other

### How Nonce Incrementing Prevents This

The nonce incrementor guarantees:

- Every (recordIndex, fieldId) pair produces a unique nonce
- Even if you encrypt billions of records, no nonce is ever reused
- The starting nonce is random (CSPRNG), so it's unpredictable

### Additional Recommendations

1. **Always send header first** - Don't encrypt until recipient confirms header receipt
2. **Validate record indices** - Ensure indices are within expected range
3. **Use authenticated encryption** - Consider adding HMAC for integrity verification
4. **Rotate sessions** - Start new sessions periodically with fresh nonceStart values
5. **Secure key storage** - The recipient's private key must be protected

## API Reference

### generateNonceStart()

Generate a cryptographically secure 12-byte starting nonce.

```typescript
function generateNonceStart(): Uint8Array;  // Returns 12 bytes
```

### deriveNonce(nonceStart, recordIndex)

Derive a unique nonce for a specific record/field combination.

```typescript
function deriveNonce(
  nonceStart: Uint8Array,      // 12-byte starting nonce
  recordIndex: number | bigint  // Combined index (recordIndex * 65536 + fieldId)
): Uint8Array;                  // Returns 12-byte derived nonce
```

### EncryptionContext

```typescript
class EncryptionContext {
  constructor(key: Uint8Array | string, nonceStart?: Uint8Array);

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

  // Nonce management
  getNonceStart(): Uint8Array;
  getRecordIndex(): number;
  setRecordIndex(index: number): void;
  nextRecordIndex(): number;
  deriveFieldNonce(fieldId: number, recordIndex?: number): Uint8Array;

  // Encryption operations
  encryptScalar(buffer: Uint8Array, offset: number, length: number, fieldId: number, recordIndex?: number): void;
  decryptScalar(buffer: Uint8Array, offset: number, length: number, fieldId: number, recordIndex?: number): void;

  // Header management
  getHeader(): EncryptionHeader;
  getHeaderJSON(): string;
}
```

### EncryptionHeader

```typescript
interface EncryptionHeader {
  version: number;              // 2 = nonce_start required
  algorithm: string;            // 'x25519', 'secp256k1', etc.
  senderPublicKey: Uint8Array;  // Ephemeral public key
  recipientKeyId: Uint8Array;   // Optional recipient key identifier
  nonceStart: Uint8Array;       // 12-byte starting nonce
  context: string;              // HKDF domain separation
  sequenceNumber?: bigint;      // Optional replay protection
  sessionId?: Uint8Array;       // Optional session identifier
}
```

## See Also

- [Node.js Integration](nodejs.md) - Using encryption in Node.js
- [Browser Integration](browser.md) - Using encryption in browsers
- [Security Considerations](README.md#security-considerations) - General security guidance
