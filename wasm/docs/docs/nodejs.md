# Node.js Integration Guide

Integrate the FlatBuffers encryption module into Node.js applications using the native WebAssembly support built into V8.

## Why Node.js Native WASM?

- **Zero dependencies** - Built into Node.js
- **Fastest option** - V8's optimizing JIT compiler
- **npm ecosystem** - Use the `flatc-wasm` package directly
- **TypeScript support** - Full type definitions included

## Prerequisites

- Node.js 16 or later (18+ recommended)
- npm or yarn

## Installation

```bash
npm install flatc-wasm
```

## Quick Start

The `flatc-wasm` package provides a high-level API:

```javascript
import {
  encryptBytes,
  decryptBytes,
  sha256,
  hkdf,
  x25519GenerateKeyPair,
  x25519SharedSecret,
  ed25519GenerateKeyPair,
  ed25519Sign,
  ed25519Verify,
  KEY_SIZE,
  IV_SIZE
} from 'flatc-wasm/encryption';

import { randomBytes } from 'crypto';

// Encrypt data
const key = randomBytes(KEY_SIZE);  // 32 bytes
const iv = randomBytes(IV_SIZE);    // 16 bytes
const plaintext = new TextEncoder().encode('Hello, FlatBuffers!');

// Encrypt in-place (make a copy first)
const data = new Uint8Array(plaintext);
encryptBytes(data, key, iv);
console.log('Encrypted:', Buffer.from(data).toString('hex'));

// Decrypt in-place (CTR mode is symmetric)
decryptBytes(data, key, iv);
console.log('Decrypted:', new TextDecoder().decode(data));
```

## API Reference

### Symmetric Encryption

```javascript
import { encryptBytes, decryptBytes, KEY_SIZE, IV_SIZE } from 'flatc-wasm/encryption';

// Key: 32 bytes, IV: 16 bytes
const key = new Uint8Array(32);
const iv = new Uint8Array(16);
crypto.getRandomValues(key);
crypto.getRandomValues(iv);

// Encrypt IN-PLACE (modifies the buffer)
const data = new Uint8Array([1, 2, 3, 4, 5]);
encryptBytes(data, key, iv);
// data is now encrypted

// Decrypt IN-PLACE
decryptBytes(data, key, iv);
// data is back to original
```

### Hash Functions

```javascript
import { sha256, hkdf } from 'flatc-wasm/encryption';

// SHA-256
const hash = sha256(new TextEncoder().encode('Hello'));
// hash: Uint8Array(32)

// HKDF-SHA256
const derivedKey = hkdf(
  sharedSecret,           // Input key material
  null,                   // Salt (optional, can be null)
  new TextEncoder().encode('my-app-v1'),  // Info
  32                      // Output length
);
// derivedKey: Uint8Array(32)
```

### X25519 Key Exchange

```javascript
import { x25519GenerateKeyPair, x25519SharedSecret } from 'flatc-wasm/encryption';

// Generate key pair
const alice = x25519GenerateKeyPair();
// alice.privateKey: Uint8Array(32)
// alice.publicKey: Uint8Array(32)

const bob = x25519GenerateKeyPair();

// Compute shared secret
const aliceShared = x25519SharedSecret(alice.privateKey, bob.publicKey);
const bobShared = x25519SharedSecret(bob.privateKey, alice.publicKey);
// aliceShared === bobShared (32 bytes)
```

### secp256k1 (Bitcoin/Ethereum)

```javascript
import {
  secp256k1GenerateKeyPair,
  secp256k1SharedSecret,
  secp256k1Sign,
  secp256k1Verify,
  sha256
} from 'flatc-wasm/encryption';

// Generate key pair
const keypair = secp256k1GenerateKeyPair();
// keypair.privateKey: Uint8Array(32)
// keypair.publicKey: Uint8Array(33) - compressed

// ECDH shared secret
const shared = secp256k1SharedSecret(myPrivateKey, theirPublicKey);
// shared: Uint8Array(32)

// Sign (usually a hash)
const messageHash = sha256(message);
const signature = secp256k1Sign(keypair.privateKey, messageHash);
// signature: Uint8Array(70-72) - DER encoded

// Verify
const isValid = secp256k1Verify(keypair.publicKey, messageHash, signature);
// isValid: boolean
```

### P-256 (NIST)

```javascript
import {
  p256GenerateKeyPair,
  p256SharedSecret,
  p256Sign,
  p256Verify
} from 'flatc-wasm/encryption';

// Same API as secp256k1
const keypair = p256GenerateKeyPair();
const shared = p256SharedSecret(myPrivateKey, theirPublicKey);
const signature = p256Sign(keypair.privateKey, messageHash);
const isValid = p256Verify(keypair.publicKey, messageHash, signature);
```

### Ed25519 Signatures

```javascript
import {
  ed25519GenerateKeyPair,
  ed25519Sign,
  ed25519Verify
} from 'flatc-wasm/encryption';

// Generate key pair
const keypair = ed25519GenerateKeyPair();
// keypair.privateKey: Uint8Array(64) - seed + public key
// keypair.publicKey: Uint8Array(32)

// Sign (entire message, not hash)
const message = new TextEncoder().encode('Sign this');
const signature = ed25519Sign(keypair.privateKey, message);
// signature: Uint8Array(64)

// Verify
const isValid = ed25519Verify(keypair.publicKey, message, signature);
// isValid: boolean
```

## Complete Example: End-to-End Encryption

```javascript
import { FlatcRunner } from 'flatc-wasm';
import {
  x25519GenerateKeyPair,
  x25519SharedSecret,
  hkdf,
  encryptBytes,
  decryptBytes,
  KEY_SIZE,
  IV_SIZE
} from 'flatc-wasm/encryption';
import { randomBytes } from 'crypto';

// Initialize FlatcRunner
const flatc = await FlatcRunner.init();

// Define schema
const schema = {
  entry: '/message.fbs',
  files: {
    '/message.fbs': `
      table SecureMessage {
        sender_public_key: [ubyte];
        iv: [ubyte];
        ciphertext: [ubyte];
      }
      root_type SecureMessage;
    `
  }
};

// === Sender Side ===

// Generate ephemeral keypair
const sender = x25519GenerateKeyPair();

// Recipient's public key (received earlier)
const recipientPublicKey = /* ... */;

// Compute shared secret
const sharedSecret = x25519SharedSecret(sender.privateKey, recipientPublicKey);

// Derive encryption key
const encryptionKey = hkdf(
  sharedSecret,
  null,
  new TextEncoder().encode('message-encryption-v1'),
  KEY_SIZE
);

// Create the message FlatBuffer
const messageJson = JSON.stringify({ text: 'Hello, secure world!' });
const messageBinary = flatc.generateBinary({
  entry: '/content.fbs',
  files: {
    '/content.fbs': `
      table Content { text: string; }
      root_type Content;
    `
  }
}, messageJson);

// Encrypt the FlatBuffer
const iv = new Uint8Array(randomBytes(IV_SIZE));
const ciphertext = new Uint8Array(messageBinary);
encryptBytes(ciphertext, encryptionKey, iv);

// Package into SecureMessage
const secureMessageJson = JSON.stringify({
  sender_public_key: Array.from(sender.publicKey),
  iv: Array.from(iv),
  ciphertext: Array.from(ciphertext)
});
const secureMessageBinary = flatc.generateBinary(schema, secureMessageJson);

// === Recipient Side ===

// Parse SecureMessage
const receivedJson = JSON.parse(flatc.generateJSON(schema, {
  path: '/received.bin',
  data: secureMessageBinary
}));

// Extract components
const senderPublicKey = new Uint8Array(receivedJson.sender_public_key);
const receivedIv = new Uint8Array(receivedJson.iv);
const receivedCiphertext = new Uint8Array(receivedJson.ciphertext);

// Compute shared secret (recipient's private key)
const recipientPrivateKey = /* ... */;
const recipientSharedSecret = x25519SharedSecret(recipientPrivateKey, senderPublicKey);

// Derive same encryption key
const decryptionKey = hkdf(
  recipientSharedSecret,
  null,
  new TextEncoder().encode('message-encryption-v1'),
  KEY_SIZE
);

// Decrypt
const decrypted = new Uint8Array(receivedCiphertext);
decryptBytes(decrypted, decryptionKey, receivedIv);

// Parse decrypted content
const content = JSON.parse(flatc.generateJSON({
  entry: '/content.fbs',
  files: {
    '/content.fbs': `
      table Content { text: string; }
      root_type Content;
    `
  }
}, {
  path: '/content.bin',
  data: decrypted
}));

console.log('Decrypted message:', content.text);
```

## TypeScript Support

Full TypeScript definitions are included:

```typescript
import {
  encryptBytes,
  decryptBytes,
  x25519GenerateKeyPair,
  KeyPair,
  KEY_SIZE,
  IV_SIZE
} from 'flatc-wasm/encryption';

// Types are inferred
const keypair: KeyPair = x25519GenerateKeyPair();

function encrypt(plaintext: Uint8Array, key: Uint8Array, iv: Uint8Array): Uint8Array {
  const data = new Uint8Array(plaintext);
  encryptBytes(data, key, iv);
  return data;
}
```

## CommonJS Support

```javascript
const { encryptBytes, x25519GenerateKeyPair } = require('flatc-wasm/encryption');

const keypair = x25519GenerateKeyPair();
console.log('Public key:', Buffer.from(keypair.publicKey).toString('hex'));
```

## Performance Tips

### 1. Initialize Once

```javascript
// Good: Initialize at startup
import { initEncryption } from 'flatc-wasm/encryption';
await initEncryption();  // Loads WASM once

// Then use throughout your app
encryptBytes(data, key, iv);
```

### 2. Reuse Buffers

```javascript
// Good: Reuse allocated buffers
const buffer = new Uint8Array(1024);
for (const chunk of chunks) {
  buffer.set(chunk);
  encryptBytes(buffer.subarray(0, chunk.length), key, iv);
}

// Less efficient: Allocate each time
for (const chunk of chunks) {
  const buffer = new Uint8Array(chunk);  // New allocation
  encryptBytes(buffer, key, iv);
}
```

### 3. Use Worker Threads for Heavy Loads

```javascript
// worker.js
import { parentPort } from 'worker_threads';
import { encryptBytes } from 'flatc-wasm/encryption';

parentPort.on('message', ({ data, key, iv }) => {
  const buffer = new Uint8Array(data);
  encryptBytes(buffer, new Uint8Array(key), new Uint8Array(iv));
  parentPort.postMessage(buffer);
});
```

## Error Handling

```javascript
try {
  encryptBytes(data, key, iv);
} catch (error) {
  if (error.message.includes('key')) {
    console.error('Invalid key size');
  } else if (error.message.includes('iv')) {
    console.error('Invalid IV size');
  } else {
    throw error;
  }
}
```

## Security Notes

1. **Use crypto.randomBytes for keys** - Not Math.random()
2. **Never reuse IVs** - Generate fresh IV for each encryption
3. **Clear sensitive data** - Zero out keys after use
4. **Use HKDF** - Never use raw ECDH output as encryption key

```javascript
import { randomBytes } from 'crypto';

// Good: Cryptographically secure
const key = randomBytes(32);

// Bad: Predictable
const badKey = new Uint8Array(32);
for (let i = 0; i < 32; i++) {
  badKey[i] = Math.floor(Math.random() * 256);  // NOT SECURE!
}
```

## Troubleshooting

### "Module not found"

Ensure you're importing from the correct path:

```javascript
// Correct
import { encryptBytes } from 'flatc-wasm/encryption';

// Wrong
import { encryptBytes } from 'flatc-wasm';  // Main module, not encryption
```

### "Invalid key/IV size"

Check your buffer sizes:

```javascript
console.log('Key size:', key.length);  // Should be 32
console.log('IV size:', iv.length);    // Should be 16
```

### "WASM module not initialized"

Call init before using:

```javascript
import { initEncryption, encryptBytes } from 'flatc-wasm/encryption';

await initEncryption();  // Must call first!
encryptBytes(data, key, iv);
```

## See Also

- [npm package](https://www.npmjs.com/package/flatc-wasm)
- [API Reference](README.md#api-reference)
- [Security Considerations](README.md#security-considerations)
- [Browser Integration](browser.md) - Similar API for browsers
