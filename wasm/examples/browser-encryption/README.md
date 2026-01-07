# Browser Encryption Integration

This example demonstrates using flatc-wasm's field-level encryption in the browser.

## Overview

The encryption module works in any JavaScript environment, including browsers. This example provides an interactive demo for encrypting FlatBuffers.

## Running the Demo

1. Build flatc-wasm:
   ```bash
   cd /path/to/flatbuffers
   cmake -B build/wasm -S . -DFLATBUFFERS_BUILD_WASM=ON
   cmake --build build/wasm --target flatc_wasm_npm -j
   ```

2. Serve the examples directory:
   ```bash
   cd wasm/examples/browser-encryption
   npx serve .
   # Or: python -m http.server 8080
   ```

3. Open http://localhost:3000 (or :8080) in your browser

## Features

- **Interactive schema editor**: Define FlatBuffers schemas with `(encrypted)` attributes
- **JSON data input**: Enter data to serialize
- **Key generation**: Generate random 256-bit encryption keys
- **Encrypt/Decrypt**: See encryption in action
- **Buffer visualization**: View raw hex bytes
- **Comparison**: See which bytes change after encryption

## Usage in Your Project

### ES Modules (recommended)

```html
<script type="module">
  import { FlatcRunner, encryptBuffer, decryptBuffer } from 'https://esm.sh/flatc-wasm@latest';

  const flatc = await FlatcRunner.init();

  // Create buffer
  const buffer = flatc.generateBinary(schema, json);

  // Encrypt
  const key = crypto.getRandomValues(new Uint8Array(32));
  encryptBuffer(buffer, schemaContent, key, 'MyRootType');
</script>
```

### Using a Bundler (webpack, vite, etc.)

```javascript
import { FlatcRunner, encryptBuffer, decryptBuffer } from 'flatc-wasm';

async function main() {
  const flatc = await FlatcRunner.init();
  // ...
}
```

### Browser Compatibility

The encryption module uses:
- `crypto.getRandomValues()` for random key generation
- Pure JavaScript AES implementation (no WebCrypto dependency)
- ES modules

Supported browsers:
- Chrome 61+
- Firefox 60+
- Safari 11+
- Edge 79+

## Security Considerations

### Browser-Specific Concerns

1. **Key Storage**: Never store encryption keys in localStorage or sessionStorage. Consider:
   - Deriving keys from user passwords (PBKDF2)
   - Using the Web Crypto API's non-extractable keys
   - Storing keys in secure enclaves if available

2. **Memory**: JavaScript doesn't guarantee memory clearing. Keys may persist in memory after use.

3. **Side Channels**: Browser environments may be vulnerable to timing attacks. For high-security applications, consider server-side encryption.

### Example: Key from Password

```javascript
async function deriveKeyFromPassword(password, salt) {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const keyBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    256
  );

  return new Uint8Array(keyBits);
}
```

## Integration with IPFS

A common use case is storing encrypted FlatBuffers on IPFS:

```javascript
import { create } from 'ipfs-core';
import { FlatcRunner, encryptBuffer, EncryptionContext } from 'flatc-wasm';

async function storeEncrypted(data, schema, key) {
  const flatc = await FlatcRunner.init();
  const ipfs = await create();

  // Create and encrypt buffer
  const buffer = flatc.generateBinary(schema, JSON.stringify(data));
  const ctx = new EncryptionContext(key);
  encryptBuffer(buffer, schema.files[schema.entry], ctx, 'MyType');

  // Store on IPFS
  const { cid } = await ipfs.add(buffer);

  return cid.toString();
}

async function retrieveDecrypted(cid, schema, key) {
  const flatc = await FlatcRunner.init();
  const ipfs = await create();

  // Retrieve from IPFS
  const chunks = [];
  for await (const chunk of ipfs.cat(cid)) {
    chunks.push(chunk);
  }
  const buffer = new Uint8Array(Buffer.concat(chunks));

  // Decrypt
  const ctx = new EncryptionContext(key);
  decryptBuffer(buffer, schema.files[schema.entry], ctx, 'MyType');

  // Parse
  return JSON.parse(flatc.generateJSON(schema, { path: '/d.bin', data: buffer }));
}
```
