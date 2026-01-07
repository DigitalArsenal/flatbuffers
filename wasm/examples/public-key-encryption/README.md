# Public Key Encryption for FlatBuffers

This directory contains examples demonstrating hybrid public-key encryption for FlatBuffers using ECDH key exchange.

## Overview

The encryption system uses a hybrid approach:
1. **Asymmetric (ECDH)**: Establish a shared secret between sender and recipient
2. **Symmetric (AES-256-CTR)**: Encrypt the actual FlatBuffer fields

### Supported Curves

| Algorithm | Public Key Size | Use Case |
|-----------|-----------------|----------|
| X25519 | 32 bytes | General purpose, modern |
| secp256k1 | 33 bytes (compressed) | Bitcoin/Ethereum compatibility |
| P-256 | 33 bytes (compressed) | NIST/TLS compatibility |

## How It Works

```
Sender                                    Recipient
------                                    ---------
1. Generate ephemeral key pair
2. Compute shared secret via ECDH
   (ephemeral private + recipient public)
3. Derive symmetric key via HKDF
4. Encrypt FlatBuffer fields
5. Send: encrypted buffer + header  --->  6. Parse header (get ephemeral public key)
                                          7. Compute shared secret via ECDH
                                             (recipient private + ephemeral public)
                                          8. Derive symmetric key via HKDF
                                          9. Decrypt FlatBuffer fields
```

## Matching Headers to Encrypted Data

The `EncryptionHeader` must be retrievable when decrypting. The encrypted FlatBuffer
itself is **never modified** - headers are stored/transmitted separately.

### Strategy 1: Session-Based (Recommended for Streaming/IPFS)

One header applies to all messages in a session. This is the most efficient approach
for streaming and IPFS storage:

```javascript
import { createSession } from "../web-transport/header_store.mjs";

// Create encryption context once per session
const encryptCtx = EncryptionContext.forEncryption(recipientPublicKey, {
  context: "my-app-v1",
});

// Create session descriptor
const session = createSession(encryptCtx.getHeaderJSON(), {
  sessionId: "session-001",
  files: ["001.bin", "002.bin", "003.bin"],
});

// Save session.json alongside encrypted files
fs.writeFileSync("session.json", JSON.stringify(session, null, 2));
```

IPFS folder structure:

```text
/ipfs/Qm.../
  session.json         <- One header for all files
  001.bin              <- Encrypted FlatBuffer (unmodified)
  002.bin              <- Encrypted FlatBuffer (unmodified)
  003.bin              <- Encrypted FlatBuffer (unmodified)
```

To decrypt:

```javascript
const session = JSON.parse(fs.readFileSync("session.json"));
const decryptCtx = EncryptionContext.forDecryption(privateKey, session.header);

// Same context decrypts ALL files in the session
for (const file of session.files) {
  const buffer = fs.readFileSync(file);
  decryptBuffer(buffer, schemaContent, decryptCtx, "Message");
}
```

### Strategy 2: Header Sent at Connection (SSE/WebSocket)

For real-time streams, send the header once at connection time:

```javascript
// Server sends header in "connected" event
ws.send(JSON.stringify({
  type: "session",
  header: encryptCtx.getHeader(),
}));

// All subsequent messages use the same header
ws.send(JSON.stringify({
  type: "message",
  buffer: toBase64(encryptedBuffer),  // No header attached
}));
```

### Strategy 3: Header Rotation

For long-running streams, rotate keys periodically:

```javascript
// After N messages, create new session
if (messageCount % 100 === 0) {
  const newCtx = EncryptionContext.forEncryption(recipientPublicKey, {...});
  ws.send(JSON.stringify({
    type: "rotate",
    header: newCtx.getHeader(),
  }));
}
```

See `../web-transport/` for complete SSE and WebSocket examples.

## Examples

### Basic Encryption/Decryption

```javascript
import {
  EncryptionContext,
  KeyExchangeAlgorithm,
  x25519GenerateKeyPair,
  encryptBuffer,
  decryptBuffer,
  encryptionHeaderFromJSON,
} from "flatc-wasm/encryption";

// Recipient generates long-term key pair (store private key securely!)
const recipientKeys = x25519GenerateKeyPair();

// --- Sender side ---
const encryptCtx = EncryptionContext.forEncryption(recipientKeys.publicKey, {
  keyExchange: KeyExchangeAlgorithm.X25519,
  context: "my-app-v1",
  rootType: "SecretMessage",
});

// Encrypt the FlatBuffer in-place
encryptBuffer(flatbuffer, schemaContent, encryptCtx, "SecretMessage");

// Get the header (must be sent to recipient)
const headerJSON = encryptCtx.getHeaderJSON();

// --- Recipient side ---
const header = encryptionHeaderFromJSON(headerJSON);
const decryptCtx = EncryptionContext.forDecryption(
  recipientKeys.privateKey,
  header
);

// Decrypt the FlatBuffer in-place
decryptBuffer(flatbuffer, schemaContent, decryptCtx, "SecretMessage");
```

### TCP Transport Example

See `tcp_sender.mjs` and `tcp_receiver.mjs` for a complete example.

```bash
# Terminal 1: Start receiver (prints public keys for each curve)
node tcp_receiver.mjs 9999

# Terminal 2: Send encrypted message (copy public key from receiver output)
node tcp_sender.mjs <recipient_public_key_hex> localhost 9999 x25519
node tcp_sender.mjs <recipient_public_key_hex> localhost 9999 secp256k1
node tcp_sender.mjs <recipient_public_key_hex> localhost 9999 p256
```

### Pipe Transport Example

See `pipe_sender.mjs` and `pipe_receiver.mjs` for stdin/stdout transport.

```bash
# Option 1: Use file as intermediary (recommended for testing)
node pipe_sender.mjs --generate > encrypted.bin 2>/dev/null
node pipe_receiver.mjs --file private_key.txt < encrypted.bin

# Option 2: Pre-shared keys
RECIPIENT_KEY=<public_key_hex> node pipe_sender.mjs > encrypted.bin
PRIVATE_KEY=<private_key_hex> node pipe_receiver.mjs < encrypted.bin
```

## Wire Format

The framed protocol uses this format:

```
+----------------+------------------+------------------------+
| Header Length  | EncryptionHeader | Encrypted FlatBuffer   |
| (4 bytes, BE)  | (variable)       | (variable)             |
+----------------+------------------+------------------------+
```

### Framing Functions

```javascript
import { frameMessage, unframeMessage } from "./framing.mjs";

// Sender: frame the message
const framed = frameMessage(headerJSON, encryptedBuffer);

// Receiver: unframe the message
const { header, data } = unframeMessage(framed);
```

## Security Considerations

1. **Private Key Storage**: Recipient private keys must be stored securely
2. **Ephemeral Keys**: Sender generates a new ephemeral key pair for each message
3. **Forward Secrecy**: Compromising the recipient's long-term key doesn't reveal past messages (ephemeral keys are discarded)
4. **Context Binding**: Use unique `context` strings to bind encryption to your application
5. **Schema Binding**: Include `schemaHash` to detect schema mismatches

## Test Files

| File | Description |
|------|-------------|
| `test_x25519.mjs` | X25519 ECDH test with RFC 7748 vectors |
| `test_secp256k1.mjs` | secp256k1 ECDH test with known vectors |
| `test_p256.mjs` | P-256 ECDH test with known vectors |
| `test_multi_curve.mjs` | Full encryption/decryption with all curves |
| `example.mjs` | Basic usage example |
