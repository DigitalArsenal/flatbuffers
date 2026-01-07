# Rust Encryption Integration

This example shows how to use flatc-wasm's field-level encryption from Rust.

## Overview

Rust uses the **same encryption algorithm** as the JavaScript flatc-wasm module, ensuring 100% compatibility across all platforms. Data encrypted in Rust can be decrypted in JavaScript/Node.js/Python/Go and vice versa.

The encryption implementation is pure Rust with no external dependencies for the core algorithm, matching the JavaScript implementation byte-for-byte.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
flatc-wasm-encryption = { path = "path/to/this/crate" }
# Or when published:
# flatc-wasm-encryption = "0.1"
```

## Quick Start

```rust
use flatc_wasm_encryption::{EncryptionContext, encrypt_buffer, decrypt_buffer};
use rand::Rng;

fn main() {
    let schema = r#"
table UserData {
  user_id: uint64;
  username: string;
  password_hash: string (encrypted);
  balance: double (encrypted);
}
root_type UserData;
"#;

    // Create a FlatBuffer (using flatbuffers crate)
    let buffer: Vec<u8> = create_flatbuffer(); // Your FlatBuffer creation

    // Generate a 256-bit key
    let mut key = [0u8; 32];
    rand::thread_rng().fill(&mut key);

    // Encrypt the buffer
    let encrypted = encrypt_buffer(&buffer, schema, &key, "UserData")
        .expect("encryption failed");

    // Later: decrypt
    let decrypted = decrypt_buffer(&encrypted, schema, &key, "UserData")
        .expect("decryption failed");

    println!("Decrypted {} bytes", decrypted.len());
}
```

## Running the Tests

```bash
cd wasm/examples/rust-encryption
cargo test
```

## API Reference

### EncryptionContext

```rust
use flatc_wasm_encryption::EncryptionContext;

// Create from bytes
let key: [u8; 32] = rand::random();
let ctx = EncryptionContext::new(&key);

// Create from hex string
let ctx = EncryptionContext::from_hex("0123456789abcdef...")?;

// Check validity
if ctx.is_valid() {
    println!("Key is valid (32 bytes)");
}

// Derive field-specific keys (for advanced usage)
let field_key = ctx.derive_field_key(field_id);  // [u8; 32]
let field_iv = ctx.derive_field_iv(field_id);    // [u8; 16]
```

### Buffer Encryption

```rust
use flatc_wasm_encryption::{encrypt_buffer, decrypt_buffer};

// Encrypt (returns new buffer)
let encrypted = encrypt_buffer(&buffer, schema_content, &key, "RootType")?;

// Decrypt (returns new buffer)
let decrypted = decrypt_buffer(&encrypted, schema_content, &key, "RootType")?;

// Using EncryptionContext
let ctx = EncryptionContext::new(&key);
let encrypted = encrypt_buffer_with_context(&buffer, schema_content, &ctx, "RootType")?;
```

### Low-Level Encryption

```rust
use flatc_wasm_encryption::encrypt_bytes;

// Encrypt bytes in-place
let mut data = b"secret data".to_vec();
encrypt_bytes(&mut data, &key, &iv);

// Decrypt (same operation for AES-CTR)
encrypt_bytes(&mut data, &key, &iv);
```

## Cross-Language Compatibility

Data encrypted with Rust can be decrypted in Node.js and vice versa:

```rust
// Rust encrypts
let encrypted = encrypt_buffer(&buffer, schema, &key, "MyType")?;
save_to_ipfs(&encrypted);
```

```javascript
// Node.js decrypts
import { decryptBuffer } from 'flatc-wasm/encryption';
const buffer = await loadFromIpfs(cid);
decryptBuffer(buffer, schemaContent, key, 'MyType');
```

## Encryption Algorithm

- **Algorithm**: AES-256-CTR
- **Key size**: 256 bits (32 bytes)
- **Key derivation**: Custom HKDF-like per-field derivation
- **IV derivation**: Custom HKDF-like per-field derivation

## Security Considerations

### What's Protected

- Field values (content)
- String content
- Binary blob content
- Numeric values

### What's NOT Protected

- Schema structure (visible)
- String/vector lengths (visible)
- Which fields are present (visible)
- Number of elements in vectors (visible)

### Recommendations

1. **Use strong keys**: Generate 256-bit keys cryptographically (`rand::random()`)
2. **Secure key storage**: Never commit keys to version control
3. **Consider signing**: Encryption provides confidentiality, not integrity
4. **Rotate keys**: Don't reuse keys across too many buffers

## License

Apache-2.0
