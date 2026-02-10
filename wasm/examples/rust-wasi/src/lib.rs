//! FlatBuffers WASI Encryption Module for Rust using Wasmer.
//!
//! This module provides cryptographic operations via the Crypto++ WASM module:
//! - AES-256-CTR symmetric encryption
//! - SHA-256 hashing
//! - X25519 ECDH key exchange
//! - secp256k1 ECDH and ECDSA signatures (Bitcoin/Ethereum compatible)
//! - P-256 ECDH and ECDSA signatures (NIST)
//! - P-384 ECDH and ECDSA signatures (NIST)
//! - Ed25519 signatures
//! - HKDF key derivation
//! - Symmetric key derivation from shared secrets
//! - Entropy injection for deterministic testing
//! - Field-level encryption context management
//! - Homomorphic Encryption (HE) via SEAL: encrypt, decrypt, add, sub, multiply

use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use wasmer::{
    imports, Function, FunctionEnv, FunctionEnvMut, Instance, Memory, Module, Store, Table,
    TypedFunction, Value,
};

/// Key and signature sizes
pub const AES_KEY_SIZE: usize = 32;
pub const AES_IV_SIZE: usize = 16;
pub const SHA256_SIZE: usize = 32;
pub const SHARED_SECRET_SIZE: usize = 32;

pub const X25519_PRIVATE_KEY_SIZE: usize = 32;
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;

pub const SECP256K1_PRIVATE_KEY_SIZE: usize = 32;
pub const SECP256K1_PUBLIC_KEY_SIZE: usize = 33;
pub const SECP256K1_SIGNATURE_SIZE: usize = 72;

pub const P256_PRIVATE_KEY_SIZE: usize = 32;
pub const P256_PUBLIC_KEY_SIZE: usize = 33;
pub const P256_SIGNATURE_SIZE: usize = 72;

pub const ED25519_PRIVATE_KEY_SIZE: usize = 64;
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;
pub const ED25519_SIGNATURE_SIZE: usize = 64;

pub const P384_PRIVATE_KEY_SIZE: usize = 48;
pub const P384_PUBLIC_KEY_SIZE: usize = 49;
pub const P384_SIGNATURE_SIZE: usize = 104;
pub const HKDF_DEFAULT_SIZE: usize = 32;

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("WASM module not found: {0}")]
    ModuleNotFound(String),
    #[error("Failed to compile WASM module: {0}")]
    CompileError(String),
    #[error("Failed to instantiate WASM module: {0}")]
    InstantiateError(String),
    #[error("Memory allocation failed")]
    AllocationError,
    #[error("Encryption operation failed")]
    EncryptionFailed,
    #[error("Key generation failed")]
    KeyGenerationFailed,
    #[error("ECDH operation failed")]
    ECDHFailed,
    #[error("Signing failed")]
    SigningFailed,
    #[error("Verification failed")]
    VerificationFailed,
    #[error("Invalid key size")]
    InvalidKeySize,
    #[error("Invalid IV size")]
    InvalidIVSize,
    #[error("Homomorphic encryption operation failed")]
    HEOperationFailed,
    #[error("Homomorphic encryption not available")]
    HENotAvailable,
    #[error("WASM runtime error: {0}")]
    RuntimeError(String),
}

pub type Result<T> = std::result::Result<T, EncryptionError>;

/// Environment for WASM host functions
struct WasmEnv {
    memory: Option<Memory>,
    table: Option<Table>,
    threw: (i32, i32),
}

impl WasmEnv {
    fn new() -> Self {
        Self {
            memory: None,
            table: None,
            threw: (0, 0),
        }
    }
}

/// Wrapper for the FlatBuffers WASI encryption module.
pub struct EncryptionModule {
    store: Store,
    instance: Instance,
    env: FunctionEnv<WasmEnv>,
}

impl EncryptionModule {
    /// Create a new encryption module from the default WASM location.
    pub fn new() -> Result<Self> {
        let wasm_path = Self::find_wasm_module()?;
        Self::from_file(&wasm_path)
    }

    /// Create a new encryption module from a specific file path.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let wasm_bytes = std::fs::read(path.as_ref())
            .map_err(|e| EncryptionError::ModuleNotFound(e.to_string()))?;
        Self::from_bytes(&wasm_bytes)
    }

    /// Create a new encryption module from WASM bytes.
    pub fn from_bytes(wasm_bytes: &[u8]) -> Result<Self> {
        let mut store = Store::default();

        // Compile the module
        let module = Module::new(&store, wasm_bytes)
            .map_err(|e| EncryptionError::CompileError(e.to_string()))?;

        // Create environment
        let env = FunctionEnv::new(&mut store, WasmEnv::new());

        // Create imports
        let import_object = Self::create_imports(&mut store, &env);

        // Instantiate
        let instance = Instance::new(&mut store, &module, &import_object)
            .map_err(|e| EncryptionError::InstantiateError(e.to_string()))?;

        // Store memory and table references in environment
        {
            let env_mut = env.as_mut(&mut store);
            if let Ok(memory) = instance.exports.get_memory("memory") {
                env_mut.memory = Some(memory.clone());
            }
            if let Ok(table) = instance.exports.get_table("__indirect_function_table") {
                env_mut.table = Some(table.clone());
            }
        }

        Ok(Self {
            store,
            instance,
            env,
        })
    }

    fn find_wasm_module() -> Result<String> {
        let paths = [
            "../../build/wasm/wasm/flatc-encryption.wasm",
            "../../build/wasm/flatc-encryption.wasm",
            "../../../build/wasm/wasm/flatc-encryption.wasm",
            "../../../build/wasm/flatc-encryption.wasm",
            "build/wasm/wasm/flatc-encryption.wasm",
            "build/wasm/flatc-encryption.wasm",
        ];

        for p in &paths {
            if Path::new(p).exists() {
                return Ok(p.to_string());
            }
        }

        Err(EncryptionError::ModuleNotFound(
            "Could not find flatc-encryption.wasm".to_string(),
        ))
    }

    fn create_imports(
        store: &mut Store,
        env: &FunctionEnv<WasmEnv>,
    ) -> wasmer::Imports {
        // WASI stubs
        fn fd_close(_: i32) -> i32 { 0 }
        fn fd_seek(_: i32, _: i64, _: i32, _: i32) -> i32 { 0 }
        fn fd_write(_: i32, _: i32, _: i32, _: i32) -> i32 { 0 }
        fn fd_read(_: i32, _: i32, _: i32, _: i32) -> i32 { 0 }
        fn environ_sizes_get(_: i32, _: i32) -> i32 { 0 }
        fn environ_get(_: i32, _: i32) -> i32 { 0 }
        fn proc_exit(_: i32) {}

        fn clock_time_get(mut env: FunctionEnvMut<WasmEnv>, _clock_id: i32, _precision: i64, time_ptr: i32) -> i32 {
            use std::time::{SystemTime, UNIX_EPOCH};
            let ns = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64;

            if let Some(memory) = &env.data().memory {
                let view = memory.view(&env);
                let _ = view.write(time_ptr as u64, &ns.to_le_bytes());
            }
            0
        }

        fn random_get(mut env: FunctionEnvMut<WasmEnv>, buf: i32, buf_len: i32) -> i32 {
            use std::collections::hash_map::RandomState;
            use std::hash::{BuildHasher, Hasher};

            if let Some(memory) = &env.data().memory {
                let view = memory.view(&env);
                let mut random_bytes = vec![0u8; buf_len as usize];

                // Simple random generation using hasher
                let state = RandomState::new();
                for (i, byte) in random_bytes.iter_mut().enumerate() {
                    let mut hasher = state.build_hasher();
                    hasher.write_usize(i);
                    hasher.write_u64(std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos() as u64);
                    *byte = hasher.finish() as u8;
                }

                let _ = view.write(buf as u64, &random_bytes);
            }
            0
        }

        // Emscripten exception handling
        fn set_threw(mut env: FunctionEnvMut<WasmEnv>, threw: i32, value: i32) {
            env.data_mut().threw = (threw, value);
        }

        fn cxa_find_matching_catch_2() -> i32 { 0 }
        fn cxa_find_matching_catch_3(_: i32) -> i32 { 0 }
        fn resume_exception(_: i32) {}
        fn cxa_begin_catch(_: i32) -> i32 { 0 }
        fn cxa_end_catch() {}
        fn llvm_eh_typeid_for(_: i32) -> i32 { 0 }
        fn cxa_throw(_: i32, _: i32, _: i32) {}
        fn cxa_uncaught_exceptions() -> i32 { 0 }

        // invoke_* trampolines - call functions from the indirect function table
        // These use Table.get() to retrieve the function and call it
        fn invoke_v(mut env: FunctionEnvMut<WasmEnv>, idx: i32) {
            let (data, mut store) = env.data_and_store_mut();
            if let Some(table) = &data.table {
                if let Some(Value::FuncRef(Some(func))) = table.get(&mut store, idx as u32) {
                    let _ = func.call(&mut store, &[]);
                }
            }
        }

        fn invoke_vi(mut env: FunctionEnvMut<WasmEnv>, idx: i32, a: i32) {
            let (data, mut store) = env.data_and_store_mut();
            if let Some(table) = &data.table {
                if let Some(Value::FuncRef(Some(func))) = table.get(&mut store, idx as u32) {
                    let _ = func.call(&mut store, &[Value::I32(a)]);
                }
            }
        }

        fn invoke_vii(mut env: FunctionEnvMut<WasmEnv>, idx: i32, a: i32, b: i32) {
            let (data, mut store) = env.data_and_store_mut();
            if let Some(table) = &data.table {
                if let Some(Value::FuncRef(Some(func))) = table.get(&mut store, idx as u32) {
                    let _ = func.call(&mut store, &[Value::I32(a), Value::I32(b)]);
                }
            }
        }

        fn invoke_viii(mut env: FunctionEnvMut<WasmEnv>, idx: i32, a: i32, b: i32, c: i32) {
            let (data, mut store) = env.data_and_store_mut();
            if let Some(table) = &data.table {
                if let Some(Value::FuncRef(Some(func))) = table.get(&mut store, idx as u32) {
                    let _ = func.call(&mut store, &[Value::I32(a), Value::I32(b), Value::I32(c)]);
                }
            }
        }

        fn invoke_viiii(mut env: FunctionEnvMut<WasmEnv>, idx: i32, a: i32, b: i32, c: i32, d: i32) {
            let (data, mut store) = env.data_and_store_mut();
            if let Some(table) = &data.table {
                if let Some(Value::FuncRef(Some(func))) = table.get(&mut store, idx as u32) {
                    let _ = func.call(&mut store, &[Value::I32(a), Value::I32(b), Value::I32(c), Value::I32(d)]);
                }
            }
        }

        fn invoke_viiiii(mut env: FunctionEnvMut<WasmEnv>, idx: i32, a: i32, b: i32, c: i32, d: i32, e: i32) {
            let (data, mut store) = env.data_and_store_mut();
            if let Some(table) = &data.table {
                if let Some(Value::FuncRef(Some(func))) = table.get(&mut store, idx as u32) {
                    let _ = func.call(&mut store, &[Value::I32(a), Value::I32(b), Value::I32(c), Value::I32(d), Value::I32(e)]);
                }
            }
        }

        fn invoke_viiiiii(mut env: FunctionEnvMut<WasmEnv>, idx: i32, a: i32, b: i32, c: i32, d: i32, e: i32, f: i32) {
            let (data, mut store) = env.data_and_store_mut();
            if let Some(table) = &data.table {
                if let Some(Value::FuncRef(Some(func))) = table.get(&mut store, idx as u32) {
                    let _ = func.call(&mut store, &[Value::I32(a), Value::I32(b), Value::I32(c), Value::I32(d), Value::I32(e), Value::I32(f)]);
                }
            }
        }

        fn invoke_viiiiiii(mut env: FunctionEnvMut<WasmEnv>, idx: i32, a: i32, b: i32, c: i32, d: i32, e: i32, f: i32, g: i32) {
            let (data, mut store) = env.data_and_store_mut();
            if let Some(table) = &data.table {
                if let Some(Value::FuncRef(Some(func))) = table.get(&mut store, idx as u32) {
                    let _ = func.call(&mut store, &[Value::I32(a), Value::I32(b), Value::I32(c), Value::I32(d), Value::I32(e), Value::I32(f), Value::I32(g)]);
                }
            }
        }

        fn invoke_viiiiiiiii(mut env: FunctionEnvMut<WasmEnv>, idx: i32, a: i32, b: i32, c: i32, d: i32, e: i32, f: i32, g: i32, h: i32, i: i32) {
            let (data, mut store) = env.data_and_store_mut();
            if let Some(table) = &data.table {
                if let Some(Value::FuncRef(Some(func))) = table.get(&mut store, idx as u32) {
                    let _ = func.call(&mut store, &[Value::I32(a), Value::I32(b), Value::I32(c), Value::I32(d), Value::I32(e), Value::I32(f), Value::I32(g), Value::I32(h), Value::I32(i)]);
                }
            }
        }

        fn invoke_i(mut env: FunctionEnvMut<WasmEnv>, idx: i32) -> i32 {
            let (data, mut store) = env.data_and_store_mut();
            if let Some(table) = &data.table {
                if let Some(Value::FuncRef(Some(func))) = table.get(&mut store, idx as u32) {
                    if let Ok(results) = func.call(&mut store, &[]) {
                        if let Some(Value::I32(v)) = results.first() {
                            return *v;
                        }
                    }
                }
            }
            0
        }

        fn invoke_ii(mut env: FunctionEnvMut<WasmEnv>, idx: i32, a: i32) -> i32 {
            let (data, mut store) = env.data_and_store_mut();
            if let Some(table) = &data.table {
                if let Some(Value::FuncRef(Some(func))) = table.get(&mut store, idx as u32) {
                    if let Ok(results) = func.call(&mut store, &[Value::I32(a)]) {
                        if let Some(Value::I32(v)) = results.first() {
                            return *v;
                        }
                    }
                }
            }
            0
        }

        fn invoke_iii(mut env: FunctionEnvMut<WasmEnv>, idx: i32, a: i32, b: i32) -> i32 {
            let (data, mut store) = env.data_and_store_mut();
            if let Some(table) = &data.table {
                if let Some(Value::FuncRef(Some(func))) = table.get(&mut store, idx as u32) {
                    if let Ok(results) = func.call(&mut store, &[Value::I32(a), Value::I32(b)]) {
                        if let Some(Value::I32(v)) = results.first() {
                            return *v;
                        }
                    }
                }
            }
            0
        }

        fn invoke_iiii(mut env: FunctionEnvMut<WasmEnv>, idx: i32, a: i32, b: i32, c: i32) -> i32 {
            let (data, mut store) = env.data_and_store_mut();
            if let Some(table) = &data.table {
                if let Some(Value::FuncRef(Some(func))) = table.get(&mut store, idx as u32) {
                    if let Ok(results) = func.call(&mut store, &[Value::I32(a), Value::I32(b), Value::I32(c)]) {
                        if let Some(Value::I32(v)) = results.first() {
                            return *v;
                        }
                    }
                }
            }
            0
        }

        fn invoke_iiiii(mut env: FunctionEnvMut<WasmEnv>, idx: i32, a: i32, b: i32, c: i32, d: i32) -> i32 {
            let (data, mut store) = env.data_and_store_mut();
            if let Some(table) = &data.table {
                if let Some(Value::FuncRef(Some(func))) = table.get(&mut store, idx as u32) {
                    if let Ok(results) = func.call(&mut store, &[Value::I32(a), Value::I32(b), Value::I32(c), Value::I32(d)]) {
                        if let Some(Value::I32(v)) = results.first() {
                            return *v;
                        }
                    }
                }
            }
            0
        }

        fn invoke_iiiiii(mut env: FunctionEnvMut<WasmEnv>, idx: i32, a: i32, b: i32, c: i32, d: i32, e: i32) -> i32 {
            let (data, mut store) = env.data_and_store_mut();
            if let Some(table) = &data.table {
                if let Some(Value::FuncRef(Some(func))) = table.get(&mut store, idx as u32) {
                    if let Ok(results) = func.call(&mut store, &[Value::I32(a), Value::I32(b), Value::I32(c), Value::I32(d), Value::I32(e)]) {
                        if let Some(Value::I32(v)) = results.first() {
                            return *v;
                        }
                    }
                }
            }
            0
        }

        fn invoke_iiiiiii(mut env: FunctionEnvMut<WasmEnv>, idx: i32, a: i32, b: i32, c: i32, d: i32, e: i32, f: i32) -> i32 {
            let (data, mut store) = env.data_and_store_mut();
            if let Some(table) = &data.table {
                if let Some(Value::FuncRef(Some(func))) = table.get(&mut store, idx as u32) {
                    if let Ok(results) = func.call(&mut store, &[Value::I32(a), Value::I32(b), Value::I32(c), Value::I32(d), Value::I32(e), Value::I32(f)]) {
                        if let Some(Value::I32(v)) = results.first() {
                            return *v;
                        }
                    }
                }
            }
            0
        }

        fn invoke_iiiiiiii(mut env: FunctionEnvMut<WasmEnv>, idx: i32, a: i32, b: i32, c: i32, d: i32, e: i32, f: i32, g: i32) -> i32 {
            let (data, mut store) = env.data_and_store_mut();
            if let Some(table) = &data.table {
                if let Some(Value::FuncRef(Some(func))) = table.get(&mut store, idx as u32) {
                    if let Ok(results) = func.call(&mut store, &[Value::I32(a), Value::I32(b), Value::I32(c), Value::I32(d), Value::I32(e), Value::I32(f), Value::I32(g)]) {
                        if let Some(Value::I32(v)) = results.first() {
                            return *v;
                        }
                    }
                }
            }
            0
        }

        fn invoke_iiiiiiiiii(mut env: FunctionEnvMut<WasmEnv>, idx: i32, a: i32, b: i32, c: i32, d: i32, e: i32, f: i32, g: i32, h: i32, i: i32) -> i32 {
            let (data, mut store) = env.data_and_store_mut();
            if let Some(table) = &data.table {
                if let Some(Value::FuncRef(Some(func))) = table.get(&mut store, idx as u32) {
                    if let Ok(results) = func.call(&mut store, &[Value::I32(a), Value::I32(b), Value::I32(c), Value::I32(d), Value::I32(e), Value::I32(f), Value::I32(g), Value::I32(h), Value::I32(i)]) {
                        if let Some(Value::I32(v)) = results.first() {
                            return *v;
                        }
                    }
                }
            }
            0
        }

        imports! {
            "wasi_snapshot_preview1" => {
                "fd_close" => Function::new_typed(store, fd_close),
                "fd_seek" => Function::new_typed(store, fd_seek),
                "fd_write" => Function::new_typed(store, fd_write),
                "fd_read" => Function::new_typed(store, fd_read),
                "environ_sizes_get" => Function::new_typed(store, environ_sizes_get),
                "environ_get" => Function::new_typed(store, environ_get),
                "clock_time_get" => Function::new_typed_with_env(store, env, clock_time_get),
                "proc_exit" => Function::new_typed(store, proc_exit),
                "random_get" => Function::new_typed_with_env(store, env, random_get),
            },
            "env" => {
                "setThrew" => Function::new_typed_with_env(store, env, set_threw),
                "__cxa_find_matching_catch_2" => Function::new_typed(store, cxa_find_matching_catch_2),
                "__cxa_find_matching_catch_3" => Function::new_typed(store, cxa_find_matching_catch_3),
                "__resumeException" => Function::new_typed(store, resume_exception),
                "__cxa_begin_catch" => Function::new_typed(store, cxa_begin_catch),
                "__cxa_end_catch" => Function::new_typed(store, cxa_end_catch),
                "llvm_eh_typeid_for" => Function::new_typed(store, llvm_eh_typeid_for),
                "__cxa_throw" => Function::new_typed(store, cxa_throw),
                "__cxa_uncaught_exceptions" => Function::new_typed(store, cxa_uncaught_exceptions),
                "invoke_v" => Function::new_typed_with_env(store, env, invoke_v),
                "invoke_vi" => Function::new_typed_with_env(store, env, invoke_vi),
                "invoke_vii" => Function::new_typed_with_env(store, env, invoke_vii),
                "invoke_viii" => Function::new_typed_with_env(store, env, invoke_viii),
                "invoke_viiii" => Function::new_typed_with_env(store, env, invoke_viiii),
                "invoke_viiiii" => Function::new_typed_with_env(store, env, invoke_viiiii),
                "invoke_viiiiii" => Function::new_typed_with_env(store, env, invoke_viiiiii),
                "invoke_viiiiiii" => Function::new_typed_with_env(store, env, invoke_viiiiiii),
                "invoke_viiiiiiiii" => Function::new_typed_with_env(store, env, invoke_viiiiiiiii),
                "invoke_i" => Function::new_typed_with_env(store, env, invoke_i),
                "invoke_ii" => Function::new_typed_with_env(store, env, invoke_ii),
                "invoke_iii" => Function::new_typed_with_env(store, env, invoke_iii),
                "invoke_iiii" => Function::new_typed_with_env(store, env, invoke_iiii),
                "invoke_iiiii" => Function::new_typed_with_env(store, env, invoke_iiiii),
                "invoke_iiiiii" => Function::new_typed_with_env(store, env, invoke_iiiiii),
                "invoke_iiiiiii" => Function::new_typed_with_env(store, env, invoke_iiiiiii),
                "invoke_iiiiiiii" => Function::new_typed_with_env(store, env, invoke_iiiiiiii),
                "invoke_iiiiiiiiii" => Function::new_typed_with_env(store, env, invoke_iiiiiiiiii),
            }
        }
    }

    fn memory(&self) -> &Memory {
        self.instance.exports.get_memory("memory").unwrap()
    }

    fn allocate(&mut self, size: u32) -> Result<u32> {
        let malloc: TypedFunction<u32, u32> = self
            .instance
            .exports
            .get_typed_function(&self.store, "malloc")
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let ptr = malloc
            .call(&mut self.store, size)
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        if ptr == 0 {
            return Err(EncryptionError::AllocationError);
        }
        Ok(ptr)
    }

    fn deallocate(&mut self, ptr: u32) {
        if ptr == 0 {
            return;
        }
        if let Ok(free) = self
            .instance
            .exports
            .get_typed_function::<u32, ()>(&self.store, "free")
        {
            let _ = free.call(&mut self.store, ptr);
        }
    }

    fn write_bytes(&self, ptr: u32, data: &[u8]) {
        let memory = self.memory();
        let view = memory.view(&self.store);
        let _ = view.write(ptr as u64, data);
    }

    fn read_bytes(&self, ptr: u32, size: usize) -> Vec<u8> {
        let memory = self.memory();
        let view = memory.view(&self.store);
        let mut buffer = vec![0u8; size];
        let _ = view.read(ptr as u64, &mut buffer);
        buffer
    }

    // =========================================================================
    // Symmetric Encryption (AES-256-CTR)
    // =========================================================================

    /// Encrypt data using AES-256-CTR.
    pub fn encrypt_bytes(&mut self, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        if key.len() != AES_KEY_SIZE {
            return Err(EncryptionError::InvalidKeySize);
        }
        if iv.len() != AES_IV_SIZE {
            return Err(EncryptionError::InvalidIVSize);
        }
        if data.is_empty() {
            return Ok(Vec::new());
        }

        let key_ptr = self.allocate(AES_KEY_SIZE as u32)?;
        let iv_ptr = self.allocate(AES_IV_SIZE as u32)?;
        let data_ptr = self.allocate(data.len() as u32)?;

        self.write_bytes(key_ptr, key);
        self.write_bytes(iv_ptr, iv);
        self.write_bytes(data_ptr, data);

        let encrypt_fn: TypedFunction<(u32, u32, u32, u32), i32> = self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_encrypt_bytes")
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let result = encrypt_fn
            .call(&mut self.store, key_ptr, iv_ptr, data_ptr, data.len() as u32)
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let encrypted = if result == 0 {
            Ok(self.read_bytes(data_ptr, data.len()))
        } else {
            Err(EncryptionError::EncryptionFailed)
        };

        self.deallocate(key_ptr);
        self.deallocate(iv_ptr);
        self.deallocate(data_ptr);

        encrypted
    }

    /// Decrypt data using AES-256-CTR.
    pub fn decrypt_bytes(&mut self, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        // AES-CTR is symmetric
        self.encrypt_bytes(key, iv, data)
    }

    // =========================================================================
    // Hash Functions
    // =========================================================================

    /// Compute SHA-256 hash.
    pub fn sha256(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let data_ptr = if data.is_empty() {
            0
        } else {
            let ptr = self.allocate(data.len() as u32)?;
            self.write_bytes(ptr, data);
            ptr
        };

        let hash_ptr = self.allocate(SHA256_SIZE as u32)?;

        let sha256_fn: TypedFunction<(u32, u32, u32), ()> = self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_sha256")
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        sha256_fn
            .call(&mut self.store, data_ptr, data.len() as u32, hash_ptr)
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let hash = self.read_bytes(hash_ptr, SHA256_SIZE);

        if data_ptr != 0 {
            self.deallocate(data_ptr);
        }
        self.deallocate(hash_ptr);

        Ok(hash)
    }

    // =========================================================================
    // Module Info
    // =========================================================================

    /// Get the module version string.
    pub fn version(&mut self) -> String {
        let version_fn: TypedFunction<(), u32> = match self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_get_version")
        {
            Ok(f) => f,
            Err(_) => return "unknown".to_string(),
        };

        let ptr = match version_fn.call(&mut self.store) {
            Ok(p) => p,
            Err(_) => return "unknown".to_string(),
        };

        if ptr == 0 {
            return "unknown".to_string();
        }

        let bytes = self.read_bytes(ptr, 32);
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..end]).to_string()
    }

    /// Check if Crypto++ is available.
    pub fn has_cryptopp(&mut self) -> bool {
        let check_fn: TypedFunction<(), i32> = match self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_has_cryptopp")
        {
            Ok(f) => f,
            Err(_) => return false,
        };

        check_fn.call(&mut self.store).unwrap_or(0) == 1
    }

    // =========================================================================
    // X25519 Key Exchange
    // =========================================================================

    /// Generate an X25519 keypair. Returns (private_key, public_key).
    pub fn x25519_generate_keypair(&mut self) -> Result<(Vec<u8>, Vec<u8>)> {
        let priv_ptr = self.allocate(X25519_PRIVATE_KEY_SIZE as u32)?;
        let pub_ptr = self.allocate(X25519_PUBLIC_KEY_SIZE as u32)?;

        let keygen_fn: TypedFunction<(u32, u32), i32> = self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_x25519_generate_keypair")
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let result = keygen_fn
            .call(&mut self.store, priv_ptr, pub_ptr)
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let keypair = if result == 0 {
            Ok((
                self.read_bytes(priv_ptr, X25519_PRIVATE_KEY_SIZE),
                self.read_bytes(pub_ptr, X25519_PUBLIC_KEY_SIZE),
            ))
        } else {
            Err(EncryptionError::KeyGenerationFailed)
        };

        self.deallocate(priv_ptr);
        self.deallocate(pub_ptr);

        keypair
    }

    /// Compute an X25519 shared secret from a private key and a peer's public key.
    pub fn x25519_shared_secret(
        &mut self,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<Vec<u8>> {
        let priv_ptr = self.allocate(X25519_PRIVATE_KEY_SIZE as u32)?;
        let pub_ptr = self.allocate(X25519_PUBLIC_KEY_SIZE as u32)?;
        let secret_ptr = self.allocate(SHARED_SECRET_SIZE as u32)?;

        self.write_bytes(priv_ptr, private_key);
        self.write_bytes(pub_ptr, public_key);

        let ecdh_fn: TypedFunction<(u32, u32, u32), i32> = self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_x25519_shared_secret")
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let result = ecdh_fn
            .call(&mut self.store, priv_ptr, pub_ptr, secret_ptr)
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let secret = if result == 0 {
            Ok(self.read_bytes(secret_ptr, SHARED_SECRET_SIZE))
        } else {
            Err(EncryptionError::ECDHFailed)
        };

        self.deallocate(priv_ptr);
        self.deallocate(pub_ptr);
        self.deallocate(secret_ptr);

        secret
    }

    // =========================================================================
    // secp256k1 Key Exchange and Signatures
    // =========================================================================

    /// Generate a secp256k1 keypair. Returns (private_key, public_key).
    pub fn secp256k1_generate_keypair(&mut self) -> Result<(Vec<u8>, Vec<u8>)> {
        let priv_ptr = self.allocate(SECP256K1_PRIVATE_KEY_SIZE as u32)?;
        let pub_ptr = self.allocate(SECP256K1_PUBLIC_KEY_SIZE as u32)?;

        let keygen_fn: TypedFunction<(u32, u32), i32> = self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_secp256k1_generate_keypair")
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let result = keygen_fn
            .call(&mut self.store, priv_ptr, pub_ptr)
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let keypair = if result == 0 {
            Ok((
                self.read_bytes(priv_ptr, SECP256K1_PRIVATE_KEY_SIZE),
                self.read_bytes(pub_ptr, SECP256K1_PUBLIC_KEY_SIZE),
            ))
        } else {
            Err(EncryptionError::KeyGenerationFailed)
        };

        self.deallocate(priv_ptr);
        self.deallocate(pub_ptr);

        keypair
    }

    /// Compute a secp256k1 shared secret from a private key and a peer's public key.
    pub fn secp256k1_shared_secret(
        &mut self,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<Vec<u8>> {
        let priv_ptr = self.allocate(SECP256K1_PRIVATE_KEY_SIZE as u32)?;
        let pub_ptr = self.allocate(public_key.len() as u32)?;
        let secret_ptr = self.allocate(SHARED_SECRET_SIZE as u32)?;

        self.write_bytes(priv_ptr, private_key);
        self.write_bytes(pub_ptr, public_key);

        let ecdh_fn: TypedFunction<(u32, u32, u32, u32), i32> = self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_secp256k1_shared_secret")
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let result = ecdh_fn
            .call(
                &mut self.store,
                priv_ptr,
                pub_ptr,
                public_key.len() as u32,
                secret_ptr,
            )
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let secret = if result == 0 {
            Ok(self.read_bytes(secret_ptr, SHARED_SECRET_SIZE))
        } else {
            Err(EncryptionError::ECDHFailed)
        };

        self.deallocate(priv_ptr);
        self.deallocate(pub_ptr);
        self.deallocate(secret_ptr);

        secret
    }

    /// Sign data using secp256k1. Returns a DER-encoded signature.
    pub fn secp256k1_sign(
        &mut self,
        private_key: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let priv_ptr = self.allocate(SECP256K1_PRIVATE_KEY_SIZE as u32)?;
        let data_ptr = self.allocate(data.len() as u32)?;
        let sig_ptr = self.allocate(SECP256K1_SIGNATURE_SIZE as u32)?;
        let sig_size_ptr = self.allocate(4)?;

        self.write_bytes(priv_ptr, private_key);
        self.write_bytes(data_ptr, data);

        let sign_fn: TypedFunction<(u32, u32, u32, u32, u32), i32> = self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_secp256k1_sign")
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let result = sign_fn
            .call(
                &mut self.store,
                priv_ptr,
                data_ptr,
                data.len() as u32,
                sig_ptr,
                sig_size_ptr,
            )
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let signature = if result == 0 {
            let sig_size_bytes = self.read_bytes(sig_size_ptr, 4);
            let sig_size = u32::from_le_bytes([
                sig_size_bytes[0],
                sig_size_bytes[1],
                sig_size_bytes[2],
                sig_size_bytes[3],
            ]) as usize;
            Ok(self.read_bytes(sig_ptr, sig_size))
        } else {
            Err(EncryptionError::SigningFailed)
        };

        self.deallocate(priv_ptr);
        self.deallocate(data_ptr);
        self.deallocate(sig_ptr);
        self.deallocate(sig_size_ptr);

        signature
    }

    /// Verify a secp256k1 signature.
    pub fn secp256k1_verify(
        &mut self,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        let pub_ptr = self.allocate(public_key.len() as u32)?;
        let data_ptr = self.allocate(data.len() as u32)?;
        let sig_ptr = self.allocate(signature.len() as u32)?;

        self.write_bytes(pub_ptr, public_key);
        self.write_bytes(data_ptr, data);
        self.write_bytes(sig_ptr, signature);

        let verify_fn: TypedFunction<(u32, u32, u32, u32, u32, u32), i32> = self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_secp256k1_verify")
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let result = verify_fn
            .call(
                &mut self.store,
                pub_ptr,
                public_key.len() as u32,
                data_ptr,
                data.len() as u32,
                sig_ptr,
                signature.len() as u32,
            )
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        self.deallocate(pub_ptr);
        self.deallocate(data_ptr);
        self.deallocate(sig_ptr);

        Ok(result == 0)
    }

    // =========================================================================
    // P-256 Key Exchange and Signatures
    // =========================================================================

    /// Generate a P-256 keypair. Returns (private_key, public_key).
    pub fn p256_generate_keypair(&mut self) -> Result<(Vec<u8>, Vec<u8>)> {
        let priv_ptr = self.allocate(P256_PRIVATE_KEY_SIZE as u32)?;
        let pub_ptr = self.allocate(P256_PUBLIC_KEY_SIZE as u32)?;

        let keygen_fn: TypedFunction<(u32, u32), i32> = self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_p256_generate_keypair")
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let result = keygen_fn
            .call(&mut self.store, priv_ptr, pub_ptr)
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let keypair = if result == 0 {
            Ok((
                self.read_bytes(priv_ptr, P256_PRIVATE_KEY_SIZE),
                self.read_bytes(pub_ptr, P256_PUBLIC_KEY_SIZE),
            ))
        } else {
            Err(EncryptionError::KeyGenerationFailed)
        };

        self.deallocate(priv_ptr);
        self.deallocate(pub_ptr);

        keypair
    }

    /// Compute a P-256 shared secret from a private key and a peer's public key.
    pub fn p256_shared_secret(
        &mut self,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<Vec<u8>> {
        let priv_ptr = self.allocate(P256_PRIVATE_KEY_SIZE as u32)?;
        let pub_ptr = self.allocate(public_key.len() as u32)?;
        let secret_ptr = self.allocate(SHARED_SECRET_SIZE as u32)?;

        self.write_bytes(priv_ptr, private_key);
        self.write_bytes(pub_ptr, public_key);

        let ecdh_fn: TypedFunction<(u32, u32, u32, u32), i32> = self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_p256_shared_secret")
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let result = ecdh_fn
            .call(
                &mut self.store,
                priv_ptr,
                pub_ptr,
                public_key.len() as u32,
                secret_ptr,
            )
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let secret = if result == 0 {
            Ok(self.read_bytes(secret_ptr, SHARED_SECRET_SIZE))
        } else {
            Err(EncryptionError::ECDHFailed)
        };

        self.deallocate(priv_ptr);
        self.deallocate(pub_ptr);
        self.deallocate(secret_ptr);

        secret
    }

    /// Sign data using P-256. Returns a DER-encoded signature.
    pub fn p256_sign(
        &mut self,
        private_key: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let priv_ptr = self.allocate(P256_PRIVATE_KEY_SIZE as u32)?;
        let data_ptr = self.allocate(data.len() as u32)?;
        let sig_ptr = self.allocate(P256_SIGNATURE_SIZE as u32)?;
        let sig_size_ptr = self.allocate(4)?;

        self.write_bytes(priv_ptr, private_key);
        self.write_bytes(data_ptr, data);

        let sign_fn: TypedFunction<(u32, u32, u32, u32, u32), i32> = self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_p256_sign")
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let result = sign_fn
            .call(
                &mut self.store,
                priv_ptr,
                data_ptr,
                data.len() as u32,
                sig_ptr,
                sig_size_ptr,
            )
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let signature = if result == 0 {
            let sig_size_bytes = self.read_bytes(sig_size_ptr, 4);
            let sig_size = u32::from_le_bytes([
                sig_size_bytes[0],
                sig_size_bytes[1],
                sig_size_bytes[2],
                sig_size_bytes[3],
            ]) as usize;
            Ok(self.read_bytes(sig_ptr, sig_size))
        } else {
            Err(EncryptionError::SigningFailed)
        };

        self.deallocate(priv_ptr);
        self.deallocate(data_ptr);
        self.deallocate(sig_ptr);
        self.deallocate(sig_size_ptr);

        signature
    }

    /// Verify a P-256 signature.
    pub fn p256_verify(
        &mut self,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        let pub_ptr = self.allocate(public_key.len() as u32)?;
        let data_ptr = self.allocate(data.len() as u32)?;
        let sig_ptr = self.allocate(signature.len() as u32)?;

        self.write_bytes(pub_ptr, public_key);
        self.write_bytes(data_ptr, data);
        self.write_bytes(sig_ptr, signature);

        let verify_fn: TypedFunction<(u32, u32, u32, u32, u32, u32), i32> = self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_p256_verify")
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let result = verify_fn
            .call(
                &mut self.store,
                pub_ptr,
                public_key.len() as u32,
                data_ptr,
                data.len() as u32,
                sig_ptr,
                signature.len() as u32,
            )
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        self.deallocate(pub_ptr);
        self.deallocate(data_ptr);
        self.deallocate(sig_ptr);

        Ok(result == 0)
    }

    // =========================================================================
    // P-384 Key Exchange and Signatures
    // =========================================================================

    /// Generate a P-384 keypair. Returns (private_key, public_key).
    pub fn p384_generate_keypair(&mut self) -> Result<(Vec<u8>, Vec<u8>)> {
        let priv_ptr = self.allocate(P384_PRIVATE_KEY_SIZE as u32)?;
        let pub_ptr = self.allocate(P384_PUBLIC_KEY_SIZE as u32)?;

        let keygen_fn: TypedFunction<(u32, u32), i32> = self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_p384_generate_keypair")
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let result = keygen_fn
            .call(&mut self.store, priv_ptr, pub_ptr)
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let keypair = if result == 0 {
            Ok((
                self.read_bytes(priv_ptr, P384_PRIVATE_KEY_SIZE),
                self.read_bytes(pub_ptr, P384_PUBLIC_KEY_SIZE),
            ))
        } else {
            Err(EncryptionError::KeyGenerationFailed)
        };

        self.deallocate(priv_ptr);
        self.deallocate(pub_ptr);

        keypair
    }

    /// Compute a P-384 shared secret from a private key and a peer's public key.
    pub fn p384_shared_secret(
        &mut self,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<Vec<u8>> {
        let priv_ptr = self.allocate(P384_PRIVATE_KEY_SIZE as u32)?;
        let pub_ptr = self.allocate(public_key.len() as u32)?;
        let secret_ptr = self.allocate(SHARED_SECRET_SIZE as u32)?;

        self.write_bytes(priv_ptr, private_key);
        self.write_bytes(pub_ptr, public_key);

        let ecdh_fn: TypedFunction<(u32, u32, u32, u32), i32> = self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_p384_shared_secret")
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let result = ecdh_fn
            .call(
                &mut self.store,
                priv_ptr,
                pub_ptr,
                public_key.len() as u32,
                secret_ptr,
            )
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let secret = if result == 0 {
            Ok(self.read_bytes(secret_ptr, SHARED_SECRET_SIZE))
        } else {
            Err(EncryptionError::ECDHFailed)
        };

        self.deallocate(priv_ptr);
        self.deallocate(pub_ptr);
        self.deallocate(secret_ptr);

        secret
    }

    /// Sign data using P-384. Returns a DER-encoded signature.
    pub fn p384_sign(
        &mut self,
        private_key: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let priv_ptr = self.allocate(P384_PRIVATE_KEY_SIZE as u32)?;
        let data_ptr = self.allocate(data.len() as u32)?;
        let sig_ptr = self.allocate(P384_SIGNATURE_SIZE as u32)?;
        let sig_size_ptr = self.allocate(4)?;

        self.write_bytes(priv_ptr, private_key);
        self.write_bytes(data_ptr, data);

        let sign_fn: TypedFunction<(u32, u32, u32, u32, u32), i32> = self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_p384_sign")
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let result = sign_fn
            .call(
                &mut self.store,
                priv_ptr,
                data_ptr,
                data.len() as u32,
                sig_ptr,
                sig_size_ptr,
            )
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let signature = if result == 0 {
            let sig_size_bytes = self.read_bytes(sig_size_ptr, 4);
            let sig_size = u32::from_le_bytes([
                sig_size_bytes[0],
                sig_size_bytes[1],
                sig_size_bytes[2],
                sig_size_bytes[3],
            ]) as usize;
            Ok(self.read_bytes(sig_ptr, sig_size))
        } else {
            Err(EncryptionError::SigningFailed)
        };

        self.deallocate(priv_ptr);
        self.deallocate(data_ptr);
        self.deallocate(sig_ptr);
        self.deallocate(sig_size_ptr);

        signature
    }

    /// Verify a P-384 signature.
    pub fn p384_verify(
        &mut self,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        let pub_ptr = self.allocate(public_key.len() as u32)?;
        let data_ptr = self.allocate(data.len() as u32)?;
        let sig_ptr = self.allocate(signature.len() as u32)?;

        self.write_bytes(pub_ptr, public_key);
        self.write_bytes(data_ptr, data);
        self.write_bytes(sig_ptr, signature);

        let verify_fn: TypedFunction<(u32, u32, u32, u32, u32, u32), i32> = self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_p384_verify")
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let result = verify_fn
            .call(
                &mut self.store,
                pub_ptr,
                public_key.len() as u32,
                data_ptr,
                data.len() as u32,
                sig_ptr,
                signature.len() as u32,
            )
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        self.deallocate(pub_ptr);
        self.deallocate(data_ptr);
        self.deallocate(sig_ptr);

        Ok(result == 0)
    }

    // =========================================================================
    // Ed25519 Signatures
    // =========================================================================

    /// Generate an Ed25519 keypair. Returns (private_key, public_key).
    pub fn ed25519_generate_keypair(&mut self) -> Result<(Vec<u8>, Vec<u8>)> {
        let priv_ptr = self.allocate(ED25519_PRIVATE_KEY_SIZE as u32)?;
        let pub_ptr = self.allocate(ED25519_PUBLIC_KEY_SIZE as u32)?;

        let keygen_fn: TypedFunction<(u32, u32), i32> = self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_ed25519_generate_keypair")
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let result = keygen_fn
            .call(&mut self.store, priv_ptr, pub_ptr)
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let keypair = if result == 0 {
            Ok((
                self.read_bytes(priv_ptr, ED25519_PRIVATE_KEY_SIZE),
                self.read_bytes(pub_ptr, ED25519_PUBLIC_KEY_SIZE),
            ))
        } else {
            Err(EncryptionError::KeyGenerationFailed)
        };

        self.deallocate(priv_ptr);
        self.deallocate(pub_ptr);

        keypair
    }

    /// Sign data using Ed25519.
    pub fn ed25519_sign(
        &mut self,
        private_key: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let priv_ptr = self.allocate(ED25519_PRIVATE_KEY_SIZE as u32)?;
        let data_ptr = self.allocate(data.len() as u32)?;
        let sig_ptr = self.allocate(ED25519_SIGNATURE_SIZE as u32)?;

        self.write_bytes(priv_ptr, private_key);
        self.write_bytes(data_ptr, data);

        let sign_fn: TypedFunction<(u32, u32, u32, u32), i32> = self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_ed25519_sign")
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let result = sign_fn
            .call(
                &mut self.store,
                priv_ptr,
                data_ptr,
                data.len() as u32,
                sig_ptr,
            )
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let signature = if result == 0 {
            Ok(self.read_bytes(sig_ptr, ED25519_SIGNATURE_SIZE))
        } else {
            Err(EncryptionError::SigningFailed)
        };

        self.deallocate(priv_ptr);
        self.deallocate(data_ptr);
        self.deallocate(sig_ptr);

        signature
    }

    /// Verify an Ed25519 signature.
    pub fn ed25519_verify(
        &mut self,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        let pub_ptr = self.allocate(ED25519_PUBLIC_KEY_SIZE as u32)?;
        let data_ptr = self.allocate(data.len() as u32)?;
        let sig_ptr = self.allocate(ED25519_SIGNATURE_SIZE as u32)?;

        self.write_bytes(pub_ptr, public_key);
        self.write_bytes(data_ptr, data);
        self.write_bytes(sig_ptr, signature);

        let verify_fn: TypedFunction<(u32, u32, u32, u32), i32> = self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_ed25519_verify")
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let result = verify_fn
            .call(
                &mut self.store,
                pub_ptr,
                data_ptr,
                data.len() as u32,
                sig_ptr,
            )
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        self.deallocate(pub_ptr);
        self.deallocate(data_ptr);
        self.deallocate(sig_ptr);

        Ok(result == 0)
    }

    // =========================================================================
    // Key Derivation
    // =========================================================================

    /// Derive key material using HKDF (HMAC-based Key Derivation Function).
    pub fn hkdf(
        &mut self,
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        okm_size: usize,
    ) -> Result<Vec<u8>> {
        let ikm_ptr = self.allocate(ikm.len() as u32)?;
        let salt_ptr = self.allocate(salt.len() as u32)?;
        let info_ptr = self.allocate(info.len() as u32)?;
        let okm_ptr = self.allocate(okm_size as u32)?;

        self.write_bytes(ikm_ptr, ikm);
        self.write_bytes(salt_ptr, salt);
        self.write_bytes(info_ptr, info);

        let hkdf_fn: TypedFunction<(u32, u32, u32, u32, u32, u32, u32, u32), ()> = self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_hkdf")
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        hkdf_fn
            .call(
                &mut self.store,
                ikm_ptr,
                ikm.len() as u32,
                salt_ptr,
                salt.len() as u32,
                info_ptr,
                info.len() as u32,
                okm_ptr,
                okm_size as u32,
            )
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let okm = self.read_bytes(okm_ptr, okm_size);

        self.deallocate(ikm_ptr);
        self.deallocate(salt_ptr);
        self.deallocate(info_ptr);
        self.deallocate(okm_ptr);

        Ok(okm)
    }

    /// Derive a symmetric key from a shared secret and context string.
    /// Returns a 32-byte AES-256 key.
    pub fn derive_symmetric_key(
        &mut self,
        shared_secret: &[u8],
        context: &[u8],
    ) -> Result<Vec<u8>> {
        let secret_ptr = self.allocate(shared_secret.len() as u32)?;
        let context_ptr = self.allocate(context.len() as u32)?;
        let key_ptr = self.allocate(AES_KEY_SIZE as u32)?;

        self.write_bytes(secret_ptr, shared_secret);
        self.write_bytes(context_ptr, context);

        let derive_fn: TypedFunction<(u32, u32, u32, u32), ()> = self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_derive_symmetric_key")
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        derive_fn
            .call(
                &mut self.store,
                secret_ptr,
                context_ptr,
                context.len() as u32,
                key_ptr,
            )
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let key = self.read_bytes(key_ptr, AES_KEY_SIZE);

        self.deallocate(secret_ptr);
        self.deallocate(context_ptr);
        self.deallocate(key_ptr);

        Ok(key)
    }

    // =========================================================================
    // Entropy Injection
    // =========================================================================

    /// Inject entropy seed for deterministic testing.
    pub fn inject_entropy(&mut self, seed: &[u8]) -> Result<()> {
        let seed_ptr = self.allocate(seed.len() as u32)?;

        self.write_bytes(seed_ptr, seed);

        let inject_fn: TypedFunction<(u32, u32), i32> = self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_inject_entropy")
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let result = inject_fn
            .call(&mut self.store, seed_ptr, seed.len() as u32)
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        self.deallocate(seed_ptr);

        if result == 0 {
            Ok(())
        } else {
            Err(EncryptionError::RuntimeError(
                "Entropy injection failed".to_string(),
            ))
        }
    }

    // =========================================================================
    // Field-Level Encryption Context
    // =========================================================================

    /// Create a new encryption context for field-level encryption.
    /// Returns an opaque context pointer to be used with derive_field_key
    /// and derive_field_iv.
    pub fn encryption_create(&mut self, key: &[u8]) -> Result<u32> {
        let key_ptr = self.allocate(key.len() as u32)?;

        self.write_bytes(key_ptr, key);

        let create_fn: TypedFunction<u32, u32> = self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_encryption_create")
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let ctx = create_fn
            .call(&mut self.store, key_ptr)
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        self.deallocate(key_ptr);

        if ctx == 0 {
            Err(EncryptionError::AllocationError)
        } else {
            Ok(ctx)
        }
    }

    /// Destroy an encryption context.
    pub fn encryption_destroy(&mut self, ctx: u32) {
        if ctx == 0 {
            return;
        }
        if let Ok(destroy_fn) = self
            .instance
            .exports
            .get_typed_function::<u32, ()>(&self.store, "wasi_encryption_destroy")
        {
            let _ = destroy_fn.call(&mut self.store, ctx);
        }
    }

    /// Derive a field-specific encryption key from an encryption context.
    /// Returns a 32-byte key for the given field_id.
    pub fn derive_field_key(&mut self, ctx: u32, field_id: u16) -> Result<Vec<u8>> {
        let key_ptr = self.allocate(AES_KEY_SIZE as u32)?;

        let derive_fn: TypedFunction<(u32, u32, u32), ()> = self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_derive_field_key")
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        derive_fn
            .call(&mut self.store, ctx, field_id as u32, key_ptr)
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let key = self.read_bytes(key_ptr, AES_KEY_SIZE);

        self.deallocate(key_ptr);

        Ok(key)
    }

    /// Derive a field-specific IV from an encryption context.
    /// Returns a 16-byte IV for the given field_id.
    pub fn derive_field_iv(&mut self, ctx: u32, field_id: u16) -> Result<Vec<u8>> {
        let iv_ptr = self.allocate(AES_IV_SIZE as u32)?;

        let derive_fn: TypedFunction<(u32, u32, u32), ()> = self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_derive_field_iv")
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        derive_fn
            .call(&mut self.store, ctx, field_id as u32, iv_ptr)
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        let iv = self.read_bytes(iv_ptr, AES_IV_SIZE);

        self.deallocate(iv_ptr);

        Ok(iv)
    }

    // =========================================================================
    // Homomorphic Encryption (HE)
    // =========================================================================

    /// Check if the WASI module supports homomorphic encryption.
    pub fn has_he(&self) -> bool {
        self.instance
            .exports
            .get_typed_function::<u32, i32>(&self.store, "wasi_he_context_create_client")
            .is_ok()
    }

    /// Create a client HE context with full key material (secret + public).
    /// `poly_degree` controls the polynomial modulus degree (e.g., 4096, 8192).
    /// Pass 0 for the default (4096).
    /// Returns a context ID that must be destroyed with `he_destroy_context`.
    pub fn he_create_client(&mut self, poly_degree: u32) -> Result<i32> {
        let create_fn: TypedFunction<u32, i32> = self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_he_context_create_client")
            .map_err(|_| EncryptionError::HENotAvailable)?;

        let ctx_id = create_fn
            .call(&mut self.store, poly_degree)
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()))?;

        if ctx_id < 0 {
            Err(EncryptionError::HEOperationFailed)
        } else {
            Ok(ctx_id)
        }
    }

    /// Create a server HE context from a serialized public key.
    /// The server context can encrypt and perform operations but cannot decrypt.
    /// Returns a context ID that must be destroyed with `he_destroy_context`.
    pub fn he_create_server(&mut self, public_key: &[u8]) -> Result<i32> {
        let create_fn: TypedFunction<(u32, u32), i32> = self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_he_context_create_server")
            .map_err(|_| EncryptionError::HENotAvailable)?;

        let pk_ptr = self.allocate(public_key.len() as u32)?;
        self.write_bytes(pk_ptr, public_key);

        let ctx_id = create_fn
            .call(&mut self.store, pk_ptr, public_key.len() as u32)
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()));

        self.deallocate(pk_ptr);

        let ctx_id = ctx_id?;
        if ctx_id < 0 {
            Err(EncryptionError::HEOperationFailed)
        } else {
            Ok(ctx_id)
        }
    }

    /// Destroy a previously created HE context and free resources.
    pub fn he_destroy_context(&mut self, ctx_id: i32) {
        if let Ok(destroy_fn) = self
            .instance
            .exports
            .get_typed_function::<i32, ()>(&self.store, "wasi_he_context_destroy")
        {
            let _ = destroy_fn.call(&mut self.store, ctx_id);
        }
    }

    /// Helper for HE functions that return variable-length data.
    /// The WASI function signature is: fn(ctx_id: i32, out_len_ptr: u32) -> data_ptr: u32
    fn he_get_variable_length_data(
        &mut self,
        fn_name: &str,
        ctx_id: i32,
    ) -> Result<Vec<u8>> {
        let func: TypedFunction<(i32, u32), u32> = self
            .instance
            .exports
            .get_typed_function(&self.store, fn_name)
            .map_err(|_| EncryptionError::HENotAvailable)?;

        let out_len_ptr = self.allocate(4)?;

        let data_ptr = func
            .call(&mut self.store, ctx_id, out_len_ptr)
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()));

        let result = match data_ptr {
            Ok(ptr) if ptr != 0 => {
                let len_bytes = self.read_bytes(out_len_ptr, 4);
                let data_len = u32::from_le_bytes([
                    len_bytes[0],
                    len_bytes[1],
                    len_bytes[2],
                    len_bytes[3],
                ]) as usize;

                if data_len == 0 {
                    Err(EncryptionError::HEOperationFailed)
                } else {
                    Ok(self.read_bytes(ptr, data_len))
                }
            }
            Ok(_) => Err(EncryptionError::HEOperationFailed),
            Err(e) => Err(e),
        };

        self.deallocate(out_len_ptr);

        result
    }

    /// Get the serialized public key from an HE context.
    pub fn he_get_public_key(&mut self, ctx_id: i32) -> Result<Vec<u8>> {
        self.he_get_variable_length_data("wasi_he_get_public_key", ctx_id)
    }

    /// Get the serialized relinearization keys from an HE context.
    /// Relin keys are needed for multiplication on the server side.
    pub fn he_get_relin_keys(&mut self, ctx_id: i32) -> Result<Vec<u8>> {
        self.he_get_variable_length_data("wasi_he_get_relin_keys", ctx_id)
    }

    /// Get the serialized secret key from a client HE context.
    pub fn he_get_secret_key(&mut self, ctx_id: i32) -> Result<Vec<u8>> {
        self.he_get_variable_length_data("wasi_he_get_secret_key", ctx_id)
    }

    /// Set relinearization keys on a server HE context.
    /// This is required before performing multiplication on the server side.
    pub fn he_set_relin_keys(&mut self, ctx_id: i32, relin_keys: &[u8]) -> Result<()> {
        let set_fn: TypedFunction<(i32, u32, u32), i32> = self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_he_set_relin_keys")
            .map_err(|_| EncryptionError::HENotAvailable)?;

        let rk_ptr = self.allocate(relin_keys.len() as u32)?;
        self.write_bytes(rk_ptr, relin_keys);

        let result = set_fn
            .call(&mut self.store, ctx_id, rk_ptr, relin_keys.len() as u32)
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()));

        self.deallocate(rk_ptr);

        let result = result?;
        if result != 0 {
            Err(EncryptionError::HEOperationFailed)
        } else {
            Ok(())
        }
    }

    /// Encrypt a 64-bit integer using the BFV scheme.
    /// Returns the serialized ciphertext.
    pub fn he_encrypt_int64(&mut self, ctx_id: i32, value: i64) -> Result<Vec<u8>> {
        let encrypt_fn: TypedFunction<(i32, i64, u32), u32> = self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_he_encrypt_int64")
            .map_err(|_| EncryptionError::HENotAvailable)?;

        let out_len_ptr = self.allocate(4)?;

        let data_ptr = encrypt_fn
            .call(&mut self.store, ctx_id, value, out_len_ptr)
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()));

        let result = match data_ptr {
            Ok(ptr) if ptr != 0 => {
                let len_bytes = self.read_bytes(out_len_ptr, 4);
                let data_len = u32::from_le_bytes([
                    len_bytes[0],
                    len_bytes[1],
                    len_bytes[2],
                    len_bytes[3],
                ]) as usize;

                if data_len == 0 {
                    Err(EncryptionError::HEOperationFailed)
                } else {
                    Ok(self.read_bytes(ptr, data_len))
                }
            }
            Ok(_) => Err(EncryptionError::HEOperationFailed),
            Err(e) => Err(e),
        };

        self.deallocate(out_len_ptr);

        result
    }

    /// Decrypt a ciphertext to a 64-bit integer using the BFV scheme.
    /// Requires a client context with a secret key.
    pub fn he_decrypt_int64(&mut self, ctx_id: i32, ciphertext: &[u8]) -> Result<i64> {
        let decrypt_fn: TypedFunction<(i32, u32, u32), i64> = self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_he_decrypt_int64")
            .map_err(|_| EncryptionError::HENotAvailable)?;

        let ct_ptr = self.allocate(ciphertext.len() as u32)?;
        self.write_bytes(ct_ptr, ciphertext);

        let result = decrypt_fn
            .call(&mut self.store, ctx_id, ct_ptr, ciphertext.len() as u32)
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()));

        self.deallocate(ct_ptr);

        result
    }

    /// Encrypt a double-precision float using the CKKS scheme.
    /// Returns the serialized ciphertext.
    pub fn he_encrypt_double(&mut self, ctx_id: i32, value: f64) -> Result<Vec<u8>> {
        let encrypt_fn: TypedFunction<(i32, f64, u32), u32> = self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_he_encrypt_double")
            .map_err(|_| EncryptionError::HENotAvailable)?;

        let out_len_ptr = self.allocate(4)?;

        let data_ptr = encrypt_fn
            .call(&mut self.store, ctx_id, value, out_len_ptr)
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()));

        let result = match data_ptr {
            Ok(ptr) if ptr != 0 => {
                let len_bytes = self.read_bytes(out_len_ptr, 4);
                let data_len = u32::from_le_bytes([
                    len_bytes[0],
                    len_bytes[1],
                    len_bytes[2],
                    len_bytes[3],
                ]) as usize;

                if data_len == 0 {
                    Err(EncryptionError::HEOperationFailed)
                } else {
                    Ok(self.read_bytes(ptr, data_len))
                }
            }
            Ok(_) => Err(EncryptionError::HEOperationFailed),
            Err(e) => Err(e),
        };

        self.deallocate(out_len_ptr);

        result
    }

    /// Decrypt a ciphertext to a double-precision float using the CKKS scheme.
    /// Requires a client context with a secret key.
    pub fn he_decrypt_double(&mut self, ctx_id: i32, ciphertext: &[u8]) -> Result<f64> {
        let decrypt_fn: TypedFunction<(i32, u32, u32), f64> = self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_he_decrypt_double")
            .map_err(|_| EncryptionError::HENotAvailable)?;

        let ct_ptr = self.allocate(ciphertext.len() as u32)?;
        self.write_bytes(ct_ptr, ciphertext);

        let result = decrypt_fn
            .call(&mut self.store, ctx_id, ct_ptr, ciphertext.len() as u32)
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()));

        self.deallocate(ct_ptr);

        result
    }

    /// Helper for binary ciphertext operations (add, sub, multiply).
    /// WASI signature: fn(ctx_id, ct1_ptr, ct1_len, ct2_ptr, ct2_len, out_len_ptr) -> data_ptr
    fn he_binary_ct_op(
        &mut self,
        fn_name: &str,
        ctx_id: i32,
        ct1: &[u8],
        ct2: &[u8],
    ) -> Result<Vec<u8>> {
        let func: TypedFunction<(i32, u32, u32, u32, u32, u32), u32> = self
            .instance
            .exports
            .get_typed_function(&self.store, fn_name)
            .map_err(|_| EncryptionError::HENotAvailable)?;

        let ct1_ptr = self.allocate(ct1.len() as u32)?;
        let ct2_ptr = self.allocate(ct2.len() as u32)?;
        let out_len_ptr = self.allocate(4)?;

        self.write_bytes(ct1_ptr, ct1);
        self.write_bytes(ct2_ptr, ct2);

        let data_ptr = func
            .call(
                &mut self.store,
                ctx_id,
                ct1_ptr,
                ct1.len() as u32,
                ct2_ptr,
                ct2.len() as u32,
                out_len_ptr,
            )
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()));

        let result = match data_ptr {
            Ok(ptr) if ptr != 0 => {
                let len_bytes = self.read_bytes(out_len_ptr, 4);
                let data_len = u32::from_le_bytes([
                    len_bytes[0],
                    len_bytes[1],
                    len_bytes[2],
                    len_bytes[3],
                ]) as usize;

                if data_len == 0 {
                    Err(EncryptionError::HEOperationFailed)
                } else {
                    Ok(self.read_bytes(ptr, data_len))
                }
            }
            Ok(_) => Err(EncryptionError::HEOperationFailed),
            Err(e) => Err(e),
        };

        self.deallocate(ct1_ptr);
        self.deallocate(ct2_ptr);
        self.deallocate(out_len_ptr);

        result
    }

    /// Perform homomorphic addition of two ciphertexts.
    /// Returns a new ciphertext representing the sum of the encrypted values.
    pub fn he_add(&mut self, ctx_id: i32, ct1: &[u8], ct2: &[u8]) -> Result<Vec<u8>> {
        self.he_binary_ct_op("wasi_he_add", ctx_id, ct1, ct2)
    }

    /// Perform homomorphic subtraction of two ciphertexts.
    /// Returns a new ciphertext representing ct1 - ct2.
    pub fn he_sub(&mut self, ctx_id: i32, ct1: &[u8], ct2: &[u8]) -> Result<Vec<u8>> {
        self.he_binary_ct_op("wasi_he_sub", ctx_id, ct1, ct2)
    }

    /// Perform homomorphic multiplication of two ciphertexts.
    /// Returns a new ciphertext representing the product. Relinearization keys
    /// should be set on the context for noise management.
    pub fn he_multiply(&mut self, ctx_id: i32, ct1: &[u8], ct2: &[u8]) -> Result<Vec<u8>> {
        self.he_binary_ct_op("wasi_he_multiply", ctx_id, ct1, ct2)
    }

    /// Perform homomorphic negation of a ciphertext.
    /// Returns a new ciphertext representing the negated value.
    pub fn he_negate(&mut self, ctx_id: i32, ct: &[u8]) -> Result<Vec<u8>> {
        let negate_fn: TypedFunction<(i32, u32, u32, u32), u32> = self
            .instance
            .exports
            .get_typed_function(&self.store, "wasi_he_negate")
            .map_err(|_| EncryptionError::HENotAvailable)?;

        let ct_ptr = self.allocate(ct.len() as u32)?;
        let out_len_ptr = self.allocate(4)?;

        self.write_bytes(ct_ptr, ct);

        let data_ptr = negate_fn
            .call(&mut self.store, ctx_id, ct_ptr, ct.len() as u32, out_len_ptr)
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()));

        let result = match data_ptr {
            Ok(ptr) if ptr != 0 => {
                let len_bytes = self.read_bytes(out_len_ptr, 4);
                let data_len = u32::from_le_bytes([
                    len_bytes[0],
                    len_bytes[1],
                    len_bytes[2],
                    len_bytes[3],
                ]) as usize;

                if data_len == 0 {
                    Err(EncryptionError::HEOperationFailed)
                } else {
                    Ok(self.read_bytes(ptr, data_len))
                }
            }
            Ok(_) => Err(EncryptionError::HEOperationFailed),
            Err(e) => Err(e),
        };

        self.deallocate(ct_ptr);
        self.deallocate(out_len_ptr);

        result
    }

    /// Helper for ciphertext-plaintext operations (add_plain, multiply_plain).
    /// WASI signature: fn(ctx_id, ct_ptr, ct_len, plain_i64, out_len_ptr) -> data_ptr
    fn he_ct_plain_op(
        &mut self,
        fn_name: &str,
        ctx_id: i32,
        ct: &[u8],
        plain: i64,
    ) -> Result<Vec<u8>> {
        let func: TypedFunction<(i32, u32, u32, i64, u32), u32> = self
            .instance
            .exports
            .get_typed_function(&self.store, fn_name)
            .map_err(|_| EncryptionError::HENotAvailable)?;

        let ct_ptr = self.allocate(ct.len() as u32)?;
        let out_len_ptr = self.allocate(4)?;

        self.write_bytes(ct_ptr, ct);

        let data_ptr = func
            .call(
                &mut self.store,
                ctx_id,
                ct_ptr,
                ct.len() as u32,
                plain,
                out_len_ptr,
            )
            .map_err(|e| EncryptionError::RuntimeError(e.to_string()));

        let result = match data_ptr {
            Ok(ptr) if ptr != 0 => {
                let len_bytes = self.read_bytes(out_len_ptr, 4);
                let data_len = u32::from_le_bytes([
                    len_bytes[0],
                    len_bytes[1],
                    len_bytes[2],
                    len_bytes[3],
                ]) as usize;

                if data_len == 0 {
                    Err(EncryptionError::HEOperationFailed)
                } else {
                    Ok(self.read_bytes(ptr, data_len))
                }
            }
            Ok(_) => Err(EncryptionError::HEOperationFailed),
            Err(e) => Err(e),
        };

        self.deallocate(ct_ptr);
        self.deallocate(out_len_ptr);

        result
    }

    /// Perform homomorphic addition of a ciphertext and a plaintext int64.
    /// Returns a new ciphertext representing the sum.
    pub fn he_add_plain(&mut self, ctx_id: i32, ct: &[u8], plain: i64) -> Result<Vec<u8>> {
        self.he_ct_plain_op("wasi_he_add_plain", ctx_id, ct, plain)
    }

    /// Perform homomorphic multiplication of a ciphertext by a plaintext int64.
    /// Returns a new ciphertext representing the product.
    pub fn he_multiply_plain(&mut self, ctx_id: i32, ct: &[u8], plain: i64) -> Result<Vec<u8>> {
        self.he_ct_plain_op("wasi_he_multiply_plain", ctx_id, ct, plain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_module() -> Option<EncryptionModule> {
        EncryptionModule::new().ok()
    }

    #[test]
    fn test_version() {
        if let Some(mut em) = get_module() {
            let version = em.version();
            assert!(!version.is_empty());
            println!("Module version: {}", version);
        }
    }

    #[test]
    fn test_encrypt_decrypt() {
        if let Some(mut em) = get_module() {
            let key = [0u8; 32];
            let iv = [0u8; 16];
            let plaintext = b"Hello, FlatBuffers WASI encryption!";

            let encrypted = em.encrypt_bytes(&key, &iv, plaintext).unwrap();
            assert_eq!(encrypted.len(), plaintext.len());
            assert_ne!(&encrypted[..], &plaintext[..]);

            let decrypted = em.decrypt_bytes(&key, &iv, &encrypted).unwrap();
            assert_eq!(&decrypted[..], &plaintext[..]);
        }
    }

    #[test]
    fn test_sha256() {
        if let Some(mut em) = get_module() {
            let data = b"hello";
            let expected = hex::decode(
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            )
            .unwrap();

            let result = em.sha256(data).unwrap();
            assert_eq!(result, expected);
        }
    }

    #[test]
    fn test_sha256_empty() {
        if let Some(mut em) = get_module() {
            let expected = hex::decode(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            )
            .unwrap();

            let result = em.sha256(b"").unwrap();
            assert_eq!(result, expected);
        }
    }
}
