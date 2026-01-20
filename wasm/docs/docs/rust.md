# Rust Integration Guide

Integrate the FlatBuffers encryption WASM module into Rust applications using the [wasmer](https://wasmer.io/) crate.

## Why wasmer?

- **High performance** - Native speed with LLVM, Cranelift, or Singlepass
- **Memory safe** - Rust's safety guarantees for WASM memory access
- **Flexible** - Multiple compiler backends
- **Production ready** - Used in production by many companies

## Prerequisites

- Rust 1.70 or later
- `flatc-encryption.wasm` binary

## Installation

Add to `Cargo.toml`:

```toml
[dependencies]
wasmer = "4.2"
```

## Quick Start

```rust
use wasmer::{imports, Instance, Module, Store, Value};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create store
    let mut store = Store::default();

    // Load WASM
    let wasm_bytes = fs::read("flatc-encryption.wasm")?;
    let module = Module::new(&store, &wasm_bytes)?;

    // Create imports (WASI stubs)
    let import_object = imports! {
        "wasi_snapshot_preview1" => {
            "fd_close" => wasmer::Function::new_typed(&mut store, |_fd: i32| -> i32 { 0 }),
            "clock_time_get" => wasmer::Function::new_typed(&mut store, |_: i32, _: i64, _: i32| -> i32 { 0 }),
            // Add other WASI stubs as needed
        },
    };

    // Instantiate
    let instance = Instance::new(&mut store, &module, &import_object)?;

    // Get exports
    let memory = instance.exports.get_memory("memory")?;
    let malloc = instance.exports.get_function("malloc")?;
    let free = instance.exports.get_function("free")?;
    let encrypt = instance.exports.get_function("wasi_encrypt_bytes")?;
    let decrypt = instance.exports.get_function("wasi_decrypt_bytes")?;

    // Encrypt data
    let key: [u8; 32] = rand::random();
    let iv: [u8; 16] = rand::random();
    let plaintext = b"Hello, FlatBuffers!";

    // Allocate WASM memory
    let key_ptr = malloc.call(&mut store, &[Value::I32(32)])?[0].unwrap_i32() as u32;
    let iv_ptr = malloc.call(&mut store, &[Value::I32(16)])?[0].unwrap_i32() as u32;
    let data_ptr = malloc.call(&mut store, &[Value::I32(plaintext.len() as i32)])?[0].unwrap_i32() as u32;

    // Write to WASM memory
    let mem_view = memory.view(&store);
    mem_view.write(key_ptr as u64, &key)?;
    mem_view.write(iv_ptr as u64, &iv)?;
    mem_view.write(data_ptr as u64, plaintext)?;

    // Encrypt
    encrypt.call(&mut store, &[
        Value::I32(key_ptr as i32),
        Value::I32(iv_ptr as i32),
        Value::I32(data_ptr as i32),
        Value::I32(plaintext.len() as i32),
    ])?;

    // Read encrypted data
    let mut ciphertext = vec![0u8; plaintext.len()];
    mem_view.read(data_ptr as u64, &mut ciphertext)?;
    println!("Encrypted: {:?}", hex::encode(&ciphertext));

    // Clean up
    free.call(&mut store, &[Value::I32(key_ptr as i32)])?;
    free.call(&mut store, &[Value::I32(iv_ptr as i32)])?;
    free.call(&mut store, &[Value::I32(data_ptr as i32)])?;

    Ok(())
}
```

## Complete Module Wrapper

```rust
//! FlatBuffers Encryption Module for Rust
//!
//! Provides cryptographic operations via the Crypto++ WASM module.

use wasmer::{imports, Instance, Module, Store, Value, Memory, Function, FunctionEnv, FunctionEnvMut};
use std::sync::Arc;
use thiserror::Error;

/// Key and signature sizes
pub const AES_KEY_SIZE: usize = 32;
pub const AES_IV_SIZE: usize = 16;
pub const SHA256_SIZE: usize = 32;

pub const X25519_PRIVATE_KEY_SIZE: usize = 32;
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;

pub const SECP256K1_PRIVATE_KEY_SIZE: usize = 32;
pub const SECP256K1_PUBLIC_KEY_SIZE: usize = 33;
pub const SECP256K1_SIGNATURE_MAX_SIZE: usize = 72;

pub const ED25519_PRIVATE_KEY_SIZE: usize = 64;
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;
pub const ED25519_SIGNATURE_SIZE: usize = 64;

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("WASM error: {0}")]
    Wasm(#[from] wasmer::RuntimeError),
    #[error("Export error: {0}")]
    Export(#[from] wasmer::ExportError),
    #[error("Memory error: {0}")]
    Memory(#[from] wasmer::MemoryAccessError),
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize { expected: usize, actual: usize },
    #[error("Operation failed")]
    OperationFailed,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, EncryptionError>;

/// X25519 key pair
#[derive(Clone)]
pub struct X25519KeyPair {
    pub private_key: [u8; X25519_PRIVATE_KEY_SIZE],
    pub public_key: [u8; X25519_PUBLIC_KEY_SIZE],
}

/// Ed25519 key pair
#[derive(Clone)]
pub struct Ed25519KeyPair {
    pub private_key: [u8; ED25519_PRIVATE_KEY_SIZE],
    pub public_key: [u8; ED25519_PUBLIC_KEY_SIZE],
}

/// secp256k1 key pair
#[derive(Clone)]
pub struct Secp256k1KeyPair {
    pub private_key: [u8; SECP256K1_PRIVATE_KEY_SIZE],
    pub public_key: [u8; SECP256K1_PUBLIC_KEY_SIZE],
}

/// Encryption module wrapper
pub struct EncryptionModule {
    store: Store,
    instance: Instance,
}

impl EncryptionModule {
    /// Create a new encryption module from WASM bytes
    pub fn new(wasm_bytes: &[u8]) -> Result<Self> {
        let mut store = Store::default();
        let module = Module::new(&store, wasm_bytes)?;

        // Create WASI stubs
        let import_object = imports! {
            "wasi_snapshot_preview1" => {
                "fd_close" => Function::new_typed(&mut store, |_: i32| -> i32 { 0 }),
                "fd_seek" => Function::new_typed(&mut store, |_: i32, _: i64, _: i32, _: i32| -> i32 { 0 }),
                "fd_write" => Function::new_typed(&mut store, |_: i32, _: i32, _: i32, _: i32| -> i32 { 0 }),
                "fd_read" => Function::new_typed(&mut store, |_: i32, _: i32, _: i32, _: i32| -> i32 { 0 }),
                "environ_sizes_get" => Function::new_typed(&mut store, |_: i32, _: i32| -> i32 { 0 }),
                "environ_get" => Function::new_typed(&mut store, |_: i32, _: i32| -> i32 { 0 }),
                "clock_time_get" => Function::new_typed(&mut store, |_: i32, _: i64, _: i32| -> i32 { 0 }),
                "proc_exit" => Function::new_typed(&mut store, |_: i32| {}),
                "random_get" => Function::new_typed(&mut store, |_: i32, _: i32| -> i32 { 0 }),
            },
            "env" => {
                "invoke_v" => Function::new_typed(&mut store, |_: i32| {}),
                "invoke_vi" => Function::new_typed(&mut store, |_: i32, _: i32| {}),
                "invoke_vii" => Function::new_typed(&mut store, |_: i32, _: i32, _: i32| {}),
                "invoke_viii" => Function::new_typed(&mut store, |_: i32, _: i32, _: i32, _: i32| {}),
                "invoke_i" => Function::new_typed(&mut store, |_: i32| -> i32 { 0 }),
                "invoke_ii" => Function::new_typed(&mut store, |_: i32, _: i32| -> i32 { 0 }),
                "invoke_iii" => Function::new_typed(&mut store, |_: i32, _: i32, _: i32| -> i32 { 0 }),
            },
        };

        let instance = Instance::new(&mut store, &module, &import_object)?;

        Ok(Self { store, instance })
    }

    /// Load from file
    pub fn from_file(path: &str) -> Result<Self> {
        let wasm_bytes = std::fs::read(path)?;
        Self::new(&wasm_bytes)
    }

    fn memory(&self) -> Result<&Memory> {
        Ok(self.instance.exports.get_memory("memory")?)
    }

    fn malloc(&mut self, size: usize) -> Result<u32> {
        let malloc = self.instance.exports.get_function("malloc")?;
        let result = malloc.call(&mut self.store, &[Value::I32(size as i32)])?;
        Ok(result[0].unwrap_i32() as u32)
    }

    fn free(&mut self, ptr: u32) -> Result<()> {
        let free = self.instance.exports.get_function("free")?;
        free.call(&mut self.store, &[Value::I32(ptr as i32)])?;
        Ok(())
    }

    fn write_bytes(&self, ptr: u32, data: &[u8]) -> Result<()> {
        let memory = self.memory()?;
        let view = memory.view(&self.store);
        view.write(ptr as u64, data)?;
        Ok(())
    }

    fn read_bytes(&self, ptr: u32, len: usize) -> Result<Vec<u8>> {
        let memory = self.memory()?;
        let view = memory.view(&self.store);
        let mut buf = vec![0u8; len];
        view.read(ptr as u64, &mut buf)?;
        Ok(buf)
    }

    /// Encrypt data using AES-256-CTR
    pub fn encrypt(&mut self, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        if key.len() != AES_KEY_SIZE {
            return Err(EncryptionError::InvalidKeySize {
                expected: AES_KEY_SIZE,
                actual: key.len(),
            });
        }
        if iv.len() != AES_IV_SIZE {
            return Err(EncryptionError::InvalidKeySize {
                expected: AES_IV_SIZE,
                actual: iv.len(),
            });
        }

        let key_ptr = self.malloc(key.len())?;
        let iv_ptr = self.malloc(iv.len())?;
        let data_ptr = self.malloc(data.len())?;

        self.write_bytes(key_ptr, key)?;
        self.write_bytes(iv_ptr, iv)?;
        self.write_bytes(data_ptr, data)?;

        let encrypt = self.instance.exports.get_function("wasi_encrypt_bytes")?;
        let result = encrypt.call(&mut self.store, &[
            Value::I32(key_ptr as i32),
            Value::I32(iv_ptr as i32),
            Value::I32(data_ptr as i32),
            Value::I32(data.len() as i32),
        ])?;

        if result[0].unwrap_i32() != 0 {
            self.free(key_ptr)?;
            self.free(iv_ptr)?;
            self.free(data_ptr)?;
            return Err(EncryptionError::OperationFailed);
        }

        let encrypted = self.read_bytes(data_ptr, data.len())?;

        self.free(key_ptr)?;
        self.free(iv_ptr)?;
        self.free(data_ptr)?;

        Ok(encrypted)
    }

    /// Decrypt data using AES-256-CTR
    pub fn decrypt(&mut self, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        // CTR mode is symmetric
        self.encrypt(key, iv, data)
    }

    /// Compute SHA-256 hash
    pub fn sha256(&mut self, data: &[u8]) -> Result<[u8; SHA256_SIZE]> {
        let data_ptr = self.malloc(data.len())?;
        let out_ptr = self.malloc(SHA256_SIZE)?;

        self.write_bytes(data_ptr, data)?;

        let sha256 = self.instance.exports.get_function("wasi_sha256")?;
        sha256.call(&mut self.store, &[
            Value::I32(data_ptr as i32),
            Value::I32(data.len() as i32),
            Value::I32(out_ptr as i32),
        ])?;

        let hash = self.read_bytes(out_ptr, SHA256_SIZE)?;

        self.free(data_ptr)?;
        self.free(out_ptr)?;

        let mut result = [0u8; SHA256_SIZE];
        result.copy_from_slice(&hash);
        Ok(result)
    }

    /// Derive key using HKDF-SHA256
    pub fn hkdf(&mut self, ikm: &[u8], salt: Option<&[u8]>, info: &[u8], length: usize) -> Result<Vec<u8>> {
        let ikm_ptr = self.malloc(ikm.len())?;
        self.write_bytes(ikm_ptr, ikm)?;

        let (salt_ptr, salt_len) = if let Some(s) = salt {
            let ptr = self.malloc(s.len())?;
            self.write_bytes(ptr, s)?;
            (ptr, s.len())
        } else {
            (0, 0)
        };

        let info_ptr = self.malloc(info.len())?;
        self.write_bytes(info_ptr, info)?;

        let out_ptr = self.malloc(length)?;

        let hkdf = self.instance.exports.get_function("wasi_hkdf")?;
        hkdf.call(&mut self.store, &[
            Value::I32(ikm_ptr as i32),
            Value::I32(ikm.len() as i32),
            Value::I32(salt_ptr as i32),
            Value::I32(salt_len as i32),
            Value::I32(info_ptr as i32),
            Value::I32(info.len() as i32),
            Value::I32(out_ptr as i32),
            Value::I32(length as i32),
        ])?;

        let result = self.read_bytes(out_ptr, length)?;

        self.free(ikm_ptr)?;
        if salt_ptr != 0 {
            self.free(salt_ptr)?;
        }
        self.free(info_ptr)?;
        self.free(out_ptr)?;

        Ok(result)
    }

    /// Generate X25519 key pair
    pub fn x25519_generate_keypair(&mut self) -> Result<X25519KeyPair> {
        let priv_ptr = self.malloc(X25519_PRIVATE_KEY_SIZE)?;
        let pub_ptr = self.malloc(X25519_PUBLIC_KEY_SIZE)?;

        let generate = self.instance.exports.get_function("wasi_x25519_generate_keypair")?;
        let result = generate.call(&mut self.store, &[
            Value::I32(priv_ptr as i32),
            Value::I32(pub_ptr as i32),
        ])?;

        if result[0].unwrap_i32() != 0 {
            self.free(priv_ptr)?;
            self.free(pub_ptr)?;
            return Err(EncryptionError::OperationFailed);
        }

        let priv_bytes = self.read_bytes(priv_ptr, X25519_PRIVATE_KEY_SIZE)?;
        let pub_bytes = self.read_bytes(pub_ptr, X25519_PUBLIC_KEY_SIZE)?;

        self.free(priv_ptr)?;
        self.free(pub_ptr)?;

        let mut private_key = [0u8; X25519_PRIVATE_KEY_SIZE];
        let mut public_key = [0u8; X25519_PUBLIC_KEY_SIZE];
        private_key.copy_from_slice(&priv_bytes);
        public_key.copy_from_slice(&pub_bytes);

        Ok(X25519KeyPair { private_key, public_key })
    }

    /// Compute X25519 shared secret
    pub fn x25519_shared_secret(&mut self, private_key: &[u8], public_key: &[u8]) -> Result<[u8; 32]> {
        let priv_ptr = self.malloc(private_key.len())?;
        let pub_ptr = self.malloc(public_key.len())?;
        let out_ptr = self.malloc(32)?;

        self.write_bytes(priv_ptr, private_key)?;
        self.write_bytes(pub_ptr, public_key)?;

        let shared = self.instance.exports.get_function("wasi_x25519_shared_secret")?;
        let result = shared.call(&mut self.store, &[
            Value::I32(priv_ptr as i32),
            Value::I32(pub_ptr as i32),
            Value::I32(out_ptr as i32),
        ])?;

        if result[0].unwrap_i32() != 0 {
            self.free(priv_ptr)?;
            self.free(pub_ptr)?;
            self.free(out_ptr)?;
            return Err(EncryptionError::OperationFailed);
        }

        let secret_bytes = self.read_bytes(out_ptr, 32)?;

        self.free(priv_ptr)?;
        self.free(pub_ptr)?;
        self.free(out_ptr)?;

        let mut secret = [0u8; 32];
        secret.copy_from_slice(&secret_bytes);
        Ok(secret)
    }

    /// Generate Ed25519 key pair
    pub fn ed25519_generate_keypair(&mut self) -> Result<Ed25519KeyPair> {
        let priv_ptr = self.malloc(ED25519_PRIVATE_KEY_SIZE)?;
        let pub_ptr = self.malloc(ED25519_PUBLIC_KEY_SIZE)?;

        let generate = self.instance.exports.get_function("wasi_ed25519_generate_keypair")?;
        let result = generate.call(&mut self.store, &[
            Value::I32(priv_ptr as i32),
            Value::I32(pub_ptr as i32),
        ])?;

        if result[0].unwrap_i32() != 0 {
            self.free(priv_ptr)?;
            self.free(pub_ptr)?;
            return Err(EncryptionError::OperationFailed);
        }

        let priv_bytes = self.read_bytes(priv_ptr, ED25519_PRIVATE_KEY_SIZE)?;
        let pub_bytes = self.read_bytes(pub_ptr, ED25519_PUBLIC_KEY_SIZE)?;

        self.free(priv_ptr)?;
        self.free(pub_ptr)?;

        let mut private_key = [0u8; ED25519_PRIVATE_KEY_SIZE];
        let mut public_key = [0u8; ED25519_PUBLIC_KEY_SIZE];
        private_key.copy_from_slice(&priv_bytes);
        public_key.copy_from_slice(&pub_bytes);

        Ok(Ed25519KeyPair { private_key, public_key })
    }

    /// Sign with Ed25519
    pub fn ed25519_sign(&mut self, private_key: &[u8], message: &[u8]) -> Result<[u8; ED25519_SIGNATURE_SIZE]> {
        let priv_ptr = self.malloc(private_key.len())?;
        let msg_ptr = self.malloc(message.len())?;
        let sig_ptr = self.malloc(ED25519_SIGNATURE_SIZE)?;

        self.write_bytes(priv_ptr, private_key)?;
        self.write_bytes(msg_ptr, message)?;

        let sign = self.instance.exports.get_function("wasi_ed25519_sign")?;
        let result = sign.call(&mut self.store, &[
            Value::I32(priv_ptr as i32),
            Value::I32(msg_ptr as i32),
            Value::I32(message.len() as i32),
            Value::I32(sig_ptr as i32),
        ])?;

        if result[0].unwrap_i32() != 0 {
            self.free(priv_ptr)?;
            self.free(msg_ptr)?;
            self.free(sig_ptr)?;
            return Err(EncryptionError::OperationFailed);
        }

        let sig_bytes = self.read_bytes(sig_ptr, ED25519_SIGNATURE_SIZE)?;

        self.free(priv_ptr)?;
        self.free(msg_ptr)?;
        self.free(sig_ptr)?;

        let mut signature = [0u8; ED25519_SIGNATURE_SIZE];
        signature.copy_from_slice(&sig_bytes);
        Ok(signature)
    }

    /// Verify Ed25519 signature
    pub fn ed25519_verify(&mut self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
        let pub_ptr = self.malloc(public_key.len())?;
        let msg_ptr = self.malloc(message.len())?;
        let sig_ptr = self.malloc(signature.len())?;

        self.write_bytes(pub_ptr, public_key)?;
        self.write_bytes(msg_ptr, message)?;
        self.write_bytes(sig_ptr, signature)?;

        let verify = self.instance.exports.get_function("wasi_ed25519_verify")?;
        let result = verify.call(&mut self.store, &[
            Value::I32(pub_ptr as i32),
            Value::I32(msg_ptr as i32),
            Value::I32(message.len() as i32),
            Value::I32(sig_ptr as i32),
        ])?;

        self.free(pub_ptr)?;
        self.free(msg_ptr)?;
        self.free(sig_ptr)?;

        Ok(result[0].unwrap_i32() == 0)
    }
}
```

## Template Project Structure

```
myproject/
├── Cargo.toml
├── src/
│   ├── main.rs
│   └── encryption.rs
├── wasm/
│   └── flatc-encryption.wasm
└── tests/
    └── integration_tests.rs
```

**Cargo.toml:**
```toml
[package]
name = "myproject"
version = "0.1.0"
edition = "2021"

[dependencies]
wasmer = "4.2"
thiserror = "1.0"
rand = "0.8"
hex = "0.4"
```

## Usage Examples

### Basic Encryption

```rust
use crate::encryption::EncryptionModule;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut module = EncryptionModule::from_file("flatc-encryption.wasm")?;

    let key: [u8; 32] = rand::random();
    let iv: [u8; 16] = rand::random();
    let plaintext = b"Secret message";

    let ciphertext = module.encrypt(&key, &iv, plaintext)?;
    let decrypted = module.decrypt(&key, &iv, &ciphertext)?;

    assert_eq!(plaintext.to_vec(), decrypted);
    Ok(())
}
```

### End-to-End Encryption

```rust
use crate::encryption::EncryptionModule;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut module = EncryptionModule::from_file("flatc-encryption.wasm")?;

    // Generate key pairs
    let alice = module.x25519_generate_keypair()?;
    let bob = module.x25519_generate_keypair()?;

    // Compute shared secret
    let alice_shared = module.x25519_shared_secret(&alice.private_key, &bob.public_key)?;
    let bob_shared = module.x25519_shared_secret(&bob.private_key, &alice.public_key)?;

    assert_eq!(alice_shared, bob_shared);

    // Derive encryption key
    let key = module.hkdf(&alice_shared, None, b"encryption-v1", 32)?;

    // Encrypt
    let iv: [u8; 16] = rand::random();
    let message = b"Hello Bob!";
    let ciphertext = module.encrypt(&key, &iv, message)?;

    // Decrypt
    let decrypted = module.decrypt(&key, &iv, &ciphertext)?;
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));

    Ok(())
}
```

## Performance Tips

1. **Reuse module instances** - Module compilation is expensive
2. **Use TypedFunction** - For hot paths, use typed function calls
3. **Batch allocations** - Minimize malloc/free calls

```rust
// Good: Reuse instance
let mut module = EncryptionModule::from_file("wasm")?;
for item in items {
    module.encrypt(&key, &iv, item)?;
}

// Bad: Create new instance each time
for item in items {
    let mut module = EncryptionModule::from_file("wasm")?; // Slow!
    module.encrypt(&key, &iv, item)?;
}
```

## Troubleshooting

### "Import not found"

Ensure all WASI and env imports are provided. See the complete wrapper above.

### "Memory access out of bounds"

Check pointer validity:

```rust
let ptr = self.malloc(size)?;
if ptr == 0 {
    return Err(EncryptionError::OperationFailed);
}
```

## See Also

- [wasmer Documentation](https://docs.wasmer.io/)
- [API Reference](README.md#api-reference)
- [Security Considerations](README.md#security-considerations)
