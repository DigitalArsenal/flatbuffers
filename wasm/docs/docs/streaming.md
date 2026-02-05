# Streaming API

The FlatBuffers Streaming Dispatcher routes mixed FlatBuffer messages to type-specific ring buffers for zero-allocation, constant-memory streaming.

---

## Wire Format

Each message in a stream is size-prefixed:

```
[SIZE: 4 bytes LE][FILE_ID: 4 bytes][FLATBUFFER PAYLOAD: SIZE-4 bytes]
```

- **SIZE** — Total message size (excluding the prefix itself), little-endian uint32
- **FILE_ID** — 4-byte ASCII identifier (e.g., `MONS`, `WEAP`) for routing
- **PAYLOAD** — Standard FlatBuffer binary data

Use `FinishSizePrefixed()` when building to create streamable buffers.

---

## StreamingDispatcher API

### Initialization

```javascript
import { StreamingDispatcher } from 'flatc-wasm';

const dispatcher = new StreamingDispatcher(wasmModule);

// Register message types with fixed-size ring buffers
dispatcher.registerType('MONS', 64, 1000);  // 64 bytes/msg, capacity 1000
dispatcher.registerType('WEAP', 32, 500);
dispatcher.registerType('GALX', 16, 200);
```

### Pushing Messages

```javascript
// Push a buffer containing one or more size-prefixed messages
dispatcher.pushBytes(mixedStreamData);

// Messages are automatically routed by FILE_ID to the correct ring buffer
```

### Retrieving Messages

```javascript
// Get a specific message by index (zero-copy view into WASM memory)
const msg = dispatcher.getMessage('MONS', 0);

// Get the latest message
const latest = dispatcher.getLatestMessage('MONS');

// Iterate all messages
for (const msg of dispatcher.iterMessages('MONS')) {
  // process msg (Uint8Array view)
}

// Batch operations
const last10 = dispatcher.getLastN('MONS', 10);
const range = dispatcher.getMessageRange('MONS', 5, 15);
const all = dispatcher.getAllMessages('MONS');
```

### Statistics

```javascript
const stats = dispatcher.getStats('MONS');
// { totalReceived, capacity, head, dropped }

const allStats = dispatcher.getAllStats();
const dropped = dispatcher.getDroppedCount('MONS');
const utilization = dispatcher.getBufferUtilization('MONS'); // 0.0 - 1.0
```

---

## Encrypted Streaming

The streaming dispatcher supports per-type encryption contexts for end-to-end encrypted message streams.

### Producer (Sender)

```javascript
import { EncryptionContext } from 'flatc-wasm';

// 1. Create encryption context with receiver's public key
const ctx = EncryptionContext.forEncryption(receiverPublicKey, {
  algorithm: 'x25519',
  context: 'my-stream-v1'
});

// 2. Send the encryption header FIRST
//    This contains the ephemeral key, nonce_start, and algorithm
const header = ctx.getHeaderJSON();
sendToReceiver(JSON.stringify(header));

// 3. Produce encrypted messages
for (let i = 0; i < recordCount; i++) {
  ctx.setRecordIndex(i);
  const builder = new Builder(256);
  // ... build FlatBuffer ...
  const buf = builder.finishSizePrefixed(root);
  const encrypted = ctx.encryptBuffer(builder.asUint8Array());
  sendToReceiver(encrypted);
}
```

### Consumer (Receiver)

```javascript
import { EncryptionContext } from 'flatc-wasm';

// 1. Receive the encryption header
const header = JSON.parse(receiveFromSender());
const ctx = EncryptionContext.forDecryption(myPrivateKey, header);

// 2. Decrypt messages with known record index
function decryptMessage(encrypted, recordIndex) {
  ctx.setRecordIndex(recordIndex);
  return ctx.decryptBuffer(encrypted);
}

// 3. Brute force fallback for unknown record index
function decryptWithRecovery(encrypted, maxAttempts = 1000) {
  for (let i = 0; i < maxAttempts; i++) {
    ctx.setRecordIndex(i);
    try {
      const result = ctx.decryptBuffer(encrypted);
      // Validate FlatBuffer structure
      const view = new DataView(result.buffer);
      const rootOffset = view.getUint32(0, true);
      if (rootOffset < result.length) {
        return { data: result, recordIndex: i };
      }
    } catch (e) { continue; }
  }
  throw new Error('Decryption failed: record index not found');
}
```

### Per-Type Encryption

```javascript
// Set encryption context per message type
dispatcher.setEncryptionContext('MONS', encryptionCtx);
dispatcher.setEncryptionContext('WEAP', differentCtx);

// Or set global encryption for all types
dispatcher.setEncryption(publicKey, { algorithm: 'x25519' });

// Check and clear
dispatcher.isEncryptionActive();  // true
dispatcher.clearEncryption();     // secure cleanup
```

---

## Encryption Header

The encryption header is sent once at the beginning of a stream. Without it, the receiver cannot decrypt any messages.

| Field | Type | Description |
|-------|------|-------------|
| `ephemeral_public_key` | bytes | Sender's ephemeral public key for ECDH key exchange |
| `nonce_start` | 12 bytes | Random starting nonce — basis for all field nonces |
| `algorithm` | enum | 0 = X25519, 1 = secp256k1, 2 = P-256, 3 = P-384 |
| `context` | string | Application context mixed into HKDF derivation |
| `timestamp` | uint64 | Session creation time (Unix ms) |

### Nonce Derivation

Each field's nonce is derived deterministically:

```
fieldNonce = nonce_start + (recordIndex * 65536 + fieldId)
```

This guarantees a unique nonce for every field in every record. The `nonce_start` is transmitted once in the header, not per-message.

### Why Brute Force Recovery?

When messages arrive out of order or after reconnection, the consumer may not know the `recordIndex`. The brute force approach tries sequential indices and validates the decrypted data against the FlatBuffer structure (vtable, root offset). This is safe because:

- AES-256-CTR with a wrong nonce produces random-looking output
- Valid FlatBuffer structures have detectable patterns (valid vtable pointer, reasonable offsets)
- Typical recovery finds the correct index within a few attempts

---

## Ring Buffer Memory Layout

Messages are stored in contiguous ring buffers in WASM linear memory:

```
Buffer Base (bufferPtr)
├── Message 0:  [offset + 0 * messageSize]
├── Message 1:  [offset + 1 * messageSize]
├── Message 2:  [offset + 2 * messageSize]
│   ...
└── Message N:  [offset + N * messageSize]  (wraps at capacity)
```

| Property | Description |
|----------|-------------|
| O(1) insertion | Head pointer advances, overwrites oldest |
| Zero allocation | Buffer pre-allocated at registration |
| Zero-copy reads | `getMessage()` returns a `Uint8Array` view into WASM memory |
| Lock-free | Single-producer design, no synchronization needed |

---

## Sequence Numbers

The dispatcher provides a monotonic sequence counter for replay protection:

```javascript
const seq = dispatcher.nextSequenceNumber();
// Include in your message for ordering and deduplication
```

---

## Use Cases

- **Telemetry** — Route sensor data by device type
- **Gaming** — Separate entity updates from events
- **Finance** — Dispatch orders, trades, and quotes
- **IoT** — Process heterogeneous device streams
