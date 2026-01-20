# Web Transport Examples for Encrypted FlatBuffers

This directory contains examples of transmitting encrypted FlatBuffers over common web protocols.

## Session-Based Encryption Model

All examples use a **session-based** encryption model optimized for streaming:

1. **One header per session**: The encryption header is sent once at connection
2. **All messages use same key**: Subsequent messages use the same derived key
3. **Optional rotation**: Keys can be rotated periodically for forward secrecy
4. **No per-message overhead**: Encrypted FlatBuffers are sent without modification

This model is suitable for:

- IPFS streaming where data must remain unmodified
- High-throughput message streams
- Real-time communication

```text
Client                              Server
  |                                    |
  |------- hello (public key) -------->|
  |<------ session (header) -----------|  <- One header for the session
  |                                    |
  |------- message (encrypted) ------->|  <- Uses session key
  |<------ message (encrypted) --------|  <- Uses session key
  |------- message (encrypted) ------->|
  |          ...                       |
  |                                    |
  |------- rotate -------------------->|  <- Optional key rotation
  |<------ session (new header) -------|
  |          ...                       |
```

## Header Formats

Headers can be stored/transmitted in two formats:

### JSON Format

Human-readable, good for debugging and APIs:

```json
{
  "version": 1,
  "key_exchange": 0,
  "ephemeral_public_key": [15, 17, 224, ...],
  "context": "my-app-v1",
  "root_type": "Message",
  "timestamp": 1705312200000
}
```

### FlatBuffer Binary Format

Compact binary format, ideal for IPFS and bandwidth-constrained scenarios:

```javascript
import { headerToBinary, headerFromBinary } from "./header_store.mjs";

// Save header as binary
const binary = await headerToBinary(header);
await writeFile("header.bin", binary);

// Load header from binary
const loaded = await headerFromBinary(await readFile("header.bin"));
```

### Session Files

For IPFS storage, sessions include metadata alongside the header:

```javascript
import {
  createSession,
  sessionToJSON,
  sessionFromJSON,
  sessionToBinary,
  sessionFromBinary,
} from "./header_store.mjs";

// Create session
const session = createSession(header, {
  description: "My encrypted data",
  files: ["001.bin", "002.bin"],
});

// JSON format
const json = sessionToJSON(session);
const fromJson = sessionFromJSON(json);

// Binary format (header as FlatBuffer)
const binary = await sessionToBinary(session);
const fromBinary = await sessionFromBinary(binary);
```

Run the demo to see both formats in action:

```bash
node header_formats_demo.mjs
```

## Examples

### REST API

```bash
# Start server
node rest_server.mjs 8080

# Run client (plaintext + encrypted examples)
node rest_client.mjs http://localhost:8080
```

Endpoints:

- `GET /keys` - Get server's public keys
- `POST /message` - Send plaintext FlatBuffer
- `GET /message/:id` - Get plaintext FlatBuffer
- `POST /encrypted` - Send encrypted FlatBuffer (header in `X-Encryption-Header`)
- `GET /encrypted/:id` - Get encrypted FlatBuffer

### Server-Sent Events (SSE)

```bash
# Start server
node sse_server.mjs 8081

# Plaintext client
node sse_client.mjs http://localhost:8081

# Encrypted client
node sse_client.mjs --encrypted http://localhost:8081
```

Events:

- `connected` - Initial connection (includes session header for encrypted)
- `message` - FlatBuffer data (base64 encoded)
- `rotate` - New session header (key rotation)

### WebSocket

```bash
# Start server
node ws_server.mjs 8082

# Plaintext client
node ws_client.mjs ws://localhost:8082

# Encrypted client
node ws_client.mjs --encrypted ws://localhost:8082
```

Protocol:

```json
// Client initiates encryption
{ "type": "hello", "publicKey": "<hex>", "algo": "x25519" }

// Server sends session header
{ "type": "session", "header": {...}, "serverPublicKey": "<hex>" }

// Client sends their session header (for bidirectional)
{ "type": "session", "header": {...} }

// Messages (encrypted or plaintext)
{ "type": "message", "buffer": "<base64>" }

// Request key rotation
{ "type": "rotate" }
```

## For IPFS / Streaming Use Cases

When storing encrypted FlatBuffers on IPFS, you have three options:

### Option 1: JSON Session File

```text
/ipfs/Qm.../
  session.json          <- { sessionId, header, files, ... }
  001.bin               <- Encrypted FlatBuffer (unmodified)
  002.bin               <- Encrypted FlatBuffer (unmodified)
```

### Option 2: Binary Session File

```text
/ipfs/Qm.../
  session.bin           <- [metadata][header FlatBuffer]
  001.bin               <- Encrypted FlatBuffer (unmodified)
  002.bin               <- Encrypted FlatBuffer (unmodified)
```

### Option 3: Header-Only Binary

```text
/ipfs/Qm.../
  header.bin            <- Header as FlatBuffer only
  001.bin               <- Encrypted FlatBuffer (unmodified)
  002.bin               <- Encrypted FlatBuffer (unmodified)
```

All files in a session use the same header.

## Files

| File | Description |
| ---- | ----------- |
| `shared.mjs` | Common utilities and schema |
| `header_store.mjs` | Session/header storage with JSON and binary support |
| `header_formats_demo.mjs` | Demo showing both JSON and binary formats |
| `rest_server.mjs` | REST API server |
| `rest_client.mjs` | REST API client |
| `sse_server.mjs` | SSE server |
| `sse_client.mjs` | SSE client |
| `ws_server.mjs` | WebSocket server |
| `ws_client.mjs` | WebSocket client |

## Dependencies

The WebSocket examples require the `ws` package:

```bash
npm install ws
```
