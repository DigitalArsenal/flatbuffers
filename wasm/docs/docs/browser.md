# Browser Integration Guide

Run the FlatBuffers encryption module directly in web browsers using the native WebAssembly API.

## Browser Support

All modern browsers support WebAssembly:

| Browser | Version | Engine |
|---------|---------|--------|
| Chrome | 57+ | V8 |
| Firefox | 52+ | SpiderMonkey |
| Safari | 11+ | JavaScriptCore |
| Edge | 79+ | V8 |

## Installation

### Option 1: npm + Bundler (Recommended)

```bash
npm install flatc-wasm
```

Works with Vite, Webpack, Rollup, Parcel, and other bundlers.

### Option 2: CDN

```html
<script type="module">
  import { initEncryption, encryptBytes } from 'https://esm.sh/flatc-wasm/encryption';
</script>
```

### Option 3: Direct WASM Loading

```html
<script type="module">
  const wasmResponse = await fetch('/flatc-encryption.wasm');
  const wasmBytes = await wasmResponse.arrayBuffer();
  const { instance } = await WebAssembly.instantiate(wasmBytes, imports);
</script>
```

## Quick Start

```html
<!DOCTYPE html>
<html>
<head>
  <title>FlatBuffers Encryption Demo</title>
</head>
<body>
  <script type="module">
    import {
      initEncryption,
      encryptBytes,
      decryptBytes,
      x25519GenerateKeyPair,
      x25519SharedSecret,
      hkdf,
      KEY_SIZE,
      IV_SIZE
    } from 'https://esm.sh/flatc-wasm/encryption';

    // Initialize the WASM module
    await initEncryption();

    // Generate key pair
    const keypair = x25519GenerateKeyPair();
    console.log('Public key:', toHex(keypair.publicKey));

    // Encrypt some data
    const key = crypto.getRandomValues(new Uint8Array(KEY_SIZE));
    const iv = crypto.getRandomValues(new Uint8Array(IV_SIZE));
    const plaintext = new TextEncoder().encode('Hello from the browser!');

    const data = new Uint8Array(plaintext);
    encryptBytes(data, key, iv);
    console.log('Encrypted:', toHex(data));

    // Decrypt
    decryptBytes(data, key, iv);
    console.log('Decrypted:', new TextDecoder().decode(data));

    function toHex(bytes) {
      return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }
  </script>
</body>
</html>
```

## Vite Configuration

For Vite projects, the WASM file is handled automatically:

```javascript
// vite.config.js
export default {
  optimizeDeps: {
    exclude: ['flatc-wasm']
  }
};
```

```javascript
// main.js
import { initEncryption, encryptBytes } from 'flatc-wasm/encryption';

await initEncryption();
// Use encryption functions...
```

## Webpack Configuration

```javascript
// webpack.config.js
module.exports = {
  experiments: {
    asyncWebAssembly: true
  }
};
```

## API Reference

The browser API is identical to Node.js:

### Initialization

```javascript
import { initEncryption } from 'flatc-wasm/encryption';

// Must call before using any other functions
await initEncryption();
```

### Symmetric Encryption

```javascript
import { encryptBytes, decryptBytes, KEY_SIZE, IV_SIZE } from 'flatc-wasm/encryption';

const key = crypto.getRandomValues(new Uint8Array(KEY_SIZE));  // 32 bytes
const iv = crypto.getRandomValues(new Uint8Array(IV_SIZE));    // 16 bytes

// Encrypt in-place
const data = new Uint8Array([1, 2, 3, 4, 5]);
encryptBytes(data, key, iv);

// Decrypt in-place
decryptBytes(data, key, iv);
```

### Key Exchange

```javascript
import {
  x25519GenerateKeyPair,
  x25519SharedSecret,
  hkdf
} from 'flatc-wasm/encryption';

// Generate key pair
const alice = x25519GenerateKeyPair();
const bob = x25519GenerateKeyPair();

// Compute shared secret
const sharedSecret = x25519SharedSecret(alice.privateKey, bob.publicKey);

// Derive encryption key
const encryptionKey = hkdf(
  sharedSecret,
  null,
  new TextEncoder().encode('my-app-v1'),
  32
);
```

### Digital Signatures

```javascript
import {
  ed25519GenerateKeyPair,
  ed25519Sign,
  ed25519Verify
} from 'flatc-wasm/encryption';

const keypair = ed25519GenerateKeyPair();
const message = new TextEncoder().encode('Sign this');

const signature = ed25519Sign(keypair.privateKey, message);
const isValid = ed25519Verify(keypair.publicKey, message, signature);
```

## Complete Example: Secure Messaging App

```html
<!DOCTYPE html>
<html>
<head>
  <title>Secure Messenger</title>
  <style>
    body { font-family: system-ui; max-width: 600px; margin: 50px auto; }
    textarea, input { width: 100%; margin: 10px 0; padding: 10px; }
    button { padding: 10px 20px; cursor: pointer; }
    .key { font-family: monospace; font-size: 12px; word-break: break-all; }
  </style>
</head>
<body>
  <h1>Secure Messenger</h1>

  <div id="setup">
    <h2>Your Keys</h2>
    <p>Public Key:</p>
    <div class="key" id="myPublicKey"></div>
    <p>Share this with others so they can send you encrypted messages.</p>
  </div>

  <div id="encrypt">
    <h2>Send Encrypted Message</h2>
    <label>Recipient's Public Key:</label>
    <input type="text" id="recipientKey" placeholder="Paste recipient's public key">

    <label>Message:</label>
    <textarea id="plaintext" rows="4" placeholder="Enter your message"></textarea>

    <button onclick="encryptMessage()">Encrypt</button>

    <label>Encrypted Package (send this):</label>
    <textarea id="encrypted" rows="4" readonly></textarea>
  </div>

  <div id="decrypt">
    <h2>Receive Encrypted Message</h2>
    <label>Paste encrypted package:</label>
    <textarea id="received" rows="4" placeholder="Paste encrypted message"></textarea>

    <button onclick="decryptMessage()">Decrypt</button>

    <label>Decrypted Message:</label>
    <textarea id="decrypted" rows="4" readonly></textarea>
  </div>

  <script type="module">
    import {
      initEncryption,
      encryptBytes,
      decryptBytes,
      x25519GenerateKeyPair,
      x25519SharedSecret,
      hkdf,
      KEY_SIZE,
      IV_SIZE
    } from 'https://esm.sh/flatc-wasm/encryption';

    // Store keypair globally
    let myKeypair;

    // Initialize
    async function init() {
      await initEncryption();

      // Generate our keypair
      myKeypair = x25519GenerateKeyPair();
      document.getElementById('myPublicKey').textContent = toHex(myKeypair.publicKey);

      // Store private key in sessionStorage (demo only - use better storage in production!)
      sessionStorage.setItem('privateKey', toHex(myKeypair.privateKey));
    }

    init();

    // Make functions available to onclick handlers
    window.encryptMessage = async function() {
      const recipientKeyHex = document.getElementById('recipientKey').value.trim();
      const plaintext = document.getElementById('plaintext').value;

      if (!recipientKeyHex || !plaintext) {
        alert('Please enter recipient key and message');
        return;
      }

      try {
        const recipientKey = fromHex(recipientKeyHex);

        // Compute shared secret
        const sharedSecret = x25519SharedSecret(myKeypair.privateKey, recipientKey);

        // Derive encryption key
        const encryptionKey = hkdf(
          sharedSecret,
          null,
          new TextEncoder().encode('secure-messenger-v1'),
          KEY_SIZE
        );

        // Generate IV
        const iv = crypto.getRandomValues(new Uint8Array(IV_SIZE));

        // Encrypt
        const data = new TextEncoder().encode(plaintext);
        const buffer = new Uint8Array(data);
        encryptBytes(buffer, encryptionKey, iv);

        // Package: sender public key + IV + ciphertext
        const package = {
          sender: toHex(myKeypair.publicKey),
          iv: toHex(iv),
          ciphertext: toHex(buffer)
        };

        document.getElementById('encrypted').value = JSON.stringify(package);
      } catch (e) {
        alert('Encryption failed: ' + e.message);
      }
    };

    window.decryptMessage = async function() {
      const receivedJson = document.getElementById('received').value.trim();

      if (!receivedJson) {
        alert('Please paste encrypted message');
        return;
      }

      try {
        const package = JSON.parse(receivedJson);
        const senderKey = fromHex(package.sender);
        const iv = fromHex(package.iv);
        const ciphertext = fromHex(package.ciphertext);

        // Get our private key
        const privateKeyHex = sessionStorage.getItem('privateKey');
        const privateKey = fromHex(privateKeyHex);

        // Compute shared secret
        const sharedSecret = x25519SharedSecret(privateKey, senderKey);

        // Derive decryption key
        const decryptionKey = hkdf(
          sharedSecret,
          null,
          new TextEncoder().encode('secure-messenger-v1'),
          KEY_SIZE
        );

        // Decrypt
        const buffer = new Uint8Array(ciphertext);
        decryptBytes(buffer, decryptionKey, iv);

        const plaintext = new TextDecoder().decode(buffer);
        document.getElementById('decrypted').value = plaintext;
      } catch (e) {
        alert('Decryption failed: ' + e.message);
      }
    };

    function toHex(bytes) {
      return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    function fromHex(hex) {
      const bytes = new Uint8Array(hex.length / 2);
      for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
      }
      return bytes;
    }
  </script>
</body>
</html>
```

## Web Workers

For heavy encryption workloads, use Web Workers to avoid blocking the main thread:

**worker.js:**
```javascript
import { initEncryption, encryptBytes } from 'flatc-wasm/encryption';

let initialized = false;

self.onmessage = async (e) => {
  if (!initialized) {
    await initEncryption();
    initialized = true;
  }

  const { data, key, iv } = e.data;
  const buffer = new Uint8Array(data);
  encryptBytes(buffer, new Uint8Array(key), new Uint8Array(iv));

  self.postMessage({ encrypted: buffer }, [buffer.buffer]);
};
```

**main.js:**
```javascript
const worker = new Worker('worker.js', { type: 'module' });

worker.onmessage = (e) => {
  console.log('Encrypted:', e.data.encrypted);
};

worker.postMessage({
  data: plaintext,
  key: key,
  iv: iv
}, [plaintext.buffer]);  // Transfer ownership for zero-copy
```

## Streaming Large Files

For large files, process in chunks to avoid memory issues:

```javascript
async function encryptFile(file, key) {
  const CHUNK_SIZE = 64 * 1024;  // 64KB
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const chunks = [];

  chunks.push(iv);  // First chunk is the IV

  const reader = file.stream().getReader();
  let counter = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    // Create IV for this chunk (increment counter)
    const chunkIv = new Uint8Array(iv);
    const view = new DataView(chunkIv.buffer);
    view.setBigUint64(8, BigInt(counter), false);

    // Encrypt chunk
    const encrypted = new Uint8Array(value);
    encryptBytes(encrypted, key, chunkIv);
    chunks.push(encrypted);

    counter++;
  }

  return new Blob(chunks);
}
```

## Security Considerations

### 1. Use crypto.getRandomValues()

```javascript
// Good: Cryptographically secure
const key = crypto.getRandomValues(new Uint8Array(32));

// Bad: Predictable!
const badKey = new Uint8Array(32);
for (let i = 0; i < 32; i++) {
  badKey[i] = Math.floor(Math.random() * 256);
}
```

### 2. Clear Sensitive Data

```javascript
function clearKey(key) {
  key.fill(0);
}

// Use key...
encryptBytes(data, key, iv);

// Then clear it
clearKey(key);
```

### 3. Use HTTPS

Always serve your app over HTTPS. WebAssembly may be restricted on HTTP.

### 4. Consider SubtleCrypto for Some Operations

For operations that don't require cross-language compatibility, consider using the native Web Crypto API:

```javascript
// Native Web Crypto (fast, but different format)
const key = await crypto.subtle.generateKey(
  { name: 'AES-GCM', length: 256 },
  true,
  ['encrypt', 'decrypt']
);

// FlatBuffers WASM (cross-language compatible)
const fbKey = x25519GenerateKeyPair();
```

## Performance Tips

### 1. Initialize Once

```javascript
// At app startup
let encryptionReady = initEncryption();

// In your encryption function
async function encrypt(data, key, iv) {
  await encryptionReady;  // Wait if not ready
  // ...
}
```

### 2. Use Transferable Objects

```javascript
// Transfer buffer ownership (zero-copy)
worker.postMessage({ data: buffer }, [buffer.buffer]);
```

### 3. Batch Operations

```javascript
// Good: Single WASM call for batch
const results = items.map(item => {
  const buf = new Uint8Array(item);
  encryptBytes(buf, key, iv);
  return buf;
});
```

## Troubleshooting

### "CompileError: WebAssembly.instantiate"

The WASM file may be corrupted or incompatible. Ensure you're using the correct version.

### "ReferenceError: crypto is not defined"

Use `window.crypto` or ensure you're in a secure context (HTTPS).

### "Out of memory"

Processing very large files? Use streaming or Web Workers.

### CORS Errors

When loading WASM from a different origin, ensure CORS headers are set:

```
Access-Control-Allow-Origin: *
Content-Type: application/wasm
```

## See Also

- [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- [WebAssembly on MDN](https://developer.mozilla.org/en-US/docs/WebAssembly)
- [Node.js Integration](nodejs.md) - Same API for server-side
- [API Reference](README.md#api-reference)
