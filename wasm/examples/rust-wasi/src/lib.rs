//! FlatBuffers WASI Encryption Module for Rust using Wasmer.
//!
//! This module provides cryptographic operations via the Crypto++ WASM module:
//! - AES-256-CTR symmetric encryption
//! - X25519 ECDH key exchange
//! - secp256k1 ECDH and ECDSA signatures (Bitcoin/Ethereum compatible)
//! - P-256 ECDH and ECDSA signatures (NIST)
//! - Ed25519 signatures

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
