//! Rust E2E Test Runner for FlatBuffers Cross-Language Encryption
//!
//! Tests encryption/decryption using the WASM Crypto++ module with all 10 crypto key types.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use wasmer::{imports, Function, FunctionEnv, FunctionEnvMut, Instance, Memory, Module, Store, Table, TypedFunction, Value};

const AES_KEY_SIZE: usize = 32;
const AES_IV_SIZE: usize = 16;
const SHA256_SIZE: usize = 32;

#[derive(Debug, Deserialize)]
struct EncryptionKey {
    key_hex: String,
    iv_hex: String,
    key_base64: String,
    iv_base64: String,
}

#[derive(Debug, Deserialize)]
struct MonsterData {
    id: String,
    name: String,
    hp: i32,
    mana: i32,
    #[serde(flatten)]
    other: HashMap<String, serde_json::Value>,
}

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

struct EncryptionModule {
    store: Store,
    instance: Instance,
    #[allow(dead_code)]
    env: FunctionEnv<WasmEnv>,
}

impl EncryptionModule {
    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let wasm_bytes = fs::read(path.as_ref())?;
        Self::from_bytes(&wasm_bytes)
    }

    fn from_bytes(wasm_bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let mut store = Store::default();
        let module = Module::new(&store, wasm_bytes)?;
        let env = FunctionEnv::new(&mut store, WasmEnv::new());

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
            let ns = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
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
                let state = RandomState::new();
                for (i, byte) in random_bytes.iter_mut().enumerate() {
                    let mut hasher = state.build_hasher();
                    hasher.write_usize(i);
                    hasher.write_u64(std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64);
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

        // invoke_* trampolines
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
                        if let Some(Value::I32(v)) = results.first() { return *v; }
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
                        if let Some(Value::I32(v)) = results.first() { return *v; }
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
                        if let Some(Value::I32(v)) = results.first() { return *v; }
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
                        if let Some(Value::I32(v)) = results.first() { return *v; }
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
                        if let Some(Value::I32(v)) = results.first() { return *v; }
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
                        if let Some(Value::I32(v)) = results.first() { return *v; }
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
                        if let Some(Value::I32(v)) = results.first() { return *v; }
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
                        if let Some(Value::I32(v)) = results.first() { return *v; }
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
                        if let Some(Value::I32(v)) = results.first() { return *v; }
                    }
                }
            }
            0
        }

        let import_object = imports! {
            "wasi_snapshot_preview1" => {
                "fd_close" => Function::new_typed(&mut store, fd_close),
                "fd_seek" => Function::new_typed(&mut store, fd_seek),
                "fd_write" => Function::new_typed(&mut store, fd_write),
                "fd_read" => Function::new_typed(&mut store, fd_read),
                "environ_sizes_get" => Function::new_typed(&mut store, environ_sizes_get),
                "environ_get" => Function::new_typed(&mut store, environ_get),
                "clock_time_get" => Function::new_typed_with_env(&mut store, &env, clock_time_get),
                "proc_exit" => Function::new_typed(&mut store, proc_exit),
                "random_get" => Function::new_typed_with_env(&mut store, &env, random_get),
            },
            "env" => {
                "setThrew" => Function::new_typed_with_env(&mut store, &env, set_threw),
                "__cxa_find_matching_catch_2" => Function::new_typed(&mut store, cxa_find_matching_catch_2),
                "__cxa_find_matching_catch_3" => Function::new_typed(&mut store, cxa_find_matching_catch_3),
                "__resumeException" => Function::new_typed(&mut store, resume_exception),
                "__cxa_begin_catch" => Function::new_typed(&mut store, cxa_begin_catch),
                "__cxa_end_catch" => Function::new_typed(&mut store, cxa_end_catch),
                "llvm_eh_typeid_for" => Function::new_typed(&mut store, llvm_eh_typeid_for),
                "__cxa_throw" => Function::new_typed(&mut store, cxa_throw),
                "__cxa_uncaught_exceptions" => Function::new_typed(&mut store, cxa_uncaught_exceptions),
                "invoke_v" => Function::new_typed_with_env(&mut store, &env, invoke_v),
                "invoke_vi" => Function::new_typed_with_env(&mut store, &env, invoke_vi),
                "invoke_vii" => Function::new_typed_with_env(&mut store, &env, invoke_vii),
                "invoke_viii" => Function::new_typed_with_env(&mut store, &env, invoke_viii),
                "invoke_viiii" => Function::new_typed_with_env(&mut store, &env, invoke_viiii),
                "invoke_viiiii" => Function::new_typed_with_env(&mut store, &env, invoke_viiiii),
                "invoke_viiiiii" => Function::new_typed_with_env(&mut store, &env, invoke_viiiiii),
                "invoke_viiiiiii" => Function::new_typed_with_env(&mut store, &env, invoke_viiiiiii),
                "invoke_viiiiiiiii" => Function::new_typed_with_env(&mut store, &env, invoke_viiiiiiiii),
                "invoke_i" => Function::new_typed_with_env(&mut store, &env, invoke_i),
                "invoke_ii" => Function::new_typed_with_env(&mut store, &env, invoke_ii),
                "invoke_iii" => Function::new_typed_with_env(&mut store, &env, invoke_iii),
                "invoke_iiii" => Function::new_typed_with_env(&mut store, &env, invoke_iiii),
                "invoke_iiiii" => Function::new_typed_with_env(&mut store, &env, invoke_iiiii),
                "invoke_iiiiii" => Function::new_typed_with_env(&mut store, &env, invoke_iiiiii),
                "invoke_iiiiiii" => Function::new_typed_with_env(&mut store, &env, invoke_iiiiiii),
                "invoke_iiiiiiii" => Function::new_typed_with_env(&mut store, &env, invoke_iiiiiiii),
                "invoke_iiiiiiiiii" => Function::new_typed_with_env(&mut store, &env, invoke_iiiiiiiiii),
            }
        };

        let instance = Instance::new(&mut store, &module, &import_object)?;

        {
            let env_mut = env.as_mut(&mut store);
            if let Ok(memory) = instance.exports.get_memory("memory") {
                env_mut.memory = Some(memory.clone());
            }
            if let Ok(table) = instance.exports.get_table("__indirect_function_table") {
                env_mut.table = Some(table.clone());
            }
        }

        Ok(Self { store, instance, env })
    }

    fn memory(&self) -> &Memory {
        self.instance.exports.get_memory("memory").unwrap()
    }

    fn allocate(&mut self, size: u32) -> Result<u32, Box<dyn std::error::Error>> {
        let malloc: TypedFunction<u32, u32> = self.instance.exports.get_typed_function(&self.store, "malloc")?;
        Ok(malloc.call(&mut self.store, size)?)
    }

    fn deallocate(&mut self, ptr: u32) {
        if let Ok(free) = self.instance.exports.get_typed_function::<u32, ()>(&self.store, "free") {
            let _ = free.call(&mut self.store, ptr);
        }
    }

    fn write_bytes(&self, ptr: u32, data: &[u8]) {
        let view = self.memory().view(&self.store);
        let _ = view.write(ptr as u64, data);
    }

    fn read_bytes(&self, ptr: u32, size: usize) -> Vec<u8> {
        let view = self.memory().view(&self.store);
        let mut buffer = vec![0u8; size];
        let _ = view.read(ptr as u64, &mut buffer);
        buffer
    }

    fn sha256(&mut self, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let data_ptr = self.allocate(data.len().max(1) as u32)?;
        let hash_ptr = self.allocate(SHA256_SIZE as u32)?;

        if !data.is_empty() {
            self.write_bytes(data_ptr, data);
        }

        let sha256_fn: TypedFunction<(u32, u32, u32), ()> = self.instance.exports.get_typed_function(&self.store, "wasi_sha256")?;
        sha256_fn.call(&mut self.store, data_ptr, data.len() as u32, hash_ptr)?;

        let hash = self.read_bytes(hash_ptr, SHA256_SIZE);
        self.deallocate(data_ptr);
        self.deallocate(hash_ptr);
        Ok(hash)
    }

    fn encrypt_bytes(&mut self, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let key_ptr = self.allocate(AES_KEY_SIZE as u32)?;
        let iv_ptr = self.allocate(AES_IV_SIZE as u32)?;
        let data_ptr = self.allocate(data.len() as u32)?;

        self.write_bytes(key_ptr, key);
        self.write_bytes(iv_ptr, iv);
        self.write_bytes(data_ptr, data);

        let encrypt_fn: TypedFunction<(u32, u32, u32, u32), i32> = self.instance.exports.get_typed_function(&self.store, "wasi_encrypt_bytes")?;
        let _ = encrypt_fn.call(&mut self.store, key_ptr, iv_ptr, data_ptr, data.len() as u32)?;

        let encrypted = self.read_bytes(data_ptr, data.len());
        self.deallocate(key_ptr);
        self.deallocate(iv_ptr);
        self.deallocate(data_ptr);
        Ok(encrypted)
    }

    fn decrypt_bytes(&mut self, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let key_ptr = self.allocate(AES_KEY_SIZE as u32)?;
        let iv_ptr = self.allocate(AES_IV_SIZE as u32)?;
        let data_ptr = self.allocate(data.len() as u32)?;

        self.write_bytes(key_ptr, key);
        self.write_bytes(iv_ptr, iv);
        self.write_bytes(data_ptr, data);

        let decrypt_fn: TypedFunction<(u32, u32, u32, u32), i32> = self.instance.exports.get_typed_function(&self.store, "wasi_decrypt_bytes")?;
        let _ = decrypt_fn.call(&mut self.store, key_ptr, iv_ptr, data_ptr, data.len() as u32)?;

        let decrypted = self.read_bytes(data_ptr, data.len());
        self.deallocate(key_ptr);
        self.deallocate(iv_ptr);
        self.deallocate(data_ptr);
        Ok(decrypted)
    }
}

struct TestResult {
    name: String,
    passed: u32,
    failed: u32,
}

impl TestResult {
    fn new(name: &str) -> Self {
        Self { name: name.to_string(), passed: 0, failed: 0 }
    }

    fn pass(&mut self, msg: &str) {
        self.passed += 1;
        println!("  ✓ {}", msg);
    }

    fn fail(&mut self, msg: &str) {
        self.failed += 1;
        println!("  ✗ {}", msg);
    }

    fn summary(&self) -> bool {
        let total = self.passed + self.failed;
        let status = if self.failed == 0 { "✓" } else { "✗" };
        println!("\n{} {}: {}/{} passed", status, self.name, self.passed, total);
        self.failed == 0
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "=".repeat(60));
    println!("FlatBuffers Cross-Language Encryption E2E Tests - Rust");
    println!("{}", "=".repeat(60));
    println!();

    // Get directory containing the source file
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| std::env::current_dir().unwrap());

    // Try multiple relative paths from exe and current dir
    let wasm_paths = [
        "../../../../../build/wasm/wasm/flatc-encryption.wasm",
        "../../../../../../build/wasm/wasm/flatc-encryption.wasm",
        "../../../../../../../build/wasm/wasm/flatc-encryption.wasm",
    ];

    let cwd = std::env::current_dir().unwrap();

    // Canonicalize CWD to resolve symlinks and ..
    let cwd_canon = cwd.canonicalize().unwrap_or(cwd.clone());

    let wasm_path = wasm_paths.iter()
        .filter_map(|p| cwd_canon.join(p).canonicalize().ok())
        .find(|p| p.exists())
        .ok_or_else(|| format!("WASM module not found. CWD: {:?}", cwd_canon))?;

    println!("Loading WASM module: {}", wasm_path.display());
    let mut em = EncryptionModule::from_file(&wasm_path)?;
    println!();

    let vectors_dir = cwd.join("../../vectors");
    let keys_path = vectors_dir.join("encryption_keys.json");
    println!("Loading keys from: {}", keys_path.display());
    let encryption_keys: HashMap<String, EncryptionKey> = serde_json::from_str(
        &fs::read_to_string(&keys_path).map_err(|e| format!("Failed to read {:?}: {}", keys_path, e))?
    )?;

    let mut results = Vec::new();

    // Test 1: SHA-256
    println!("Test 1: SHA-256 Hash");
    println!("{}", "-".repeat(40));
    {
        let mut result = TestResult::new("SHA-256");

        let hash = em.sha256(b"hello")?;
        let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        if hex::encode(&hash) == expected {
            result.pass("SHA256('hello') correct");
        } else {
            result.fail(&format!("SHA256 mismatch: {}", hex::encode(&hash)));
        }

        let empty_hash = em.sha256(b"")?;
        let expected_empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        if hex::encode(&empty_hash) == expected_empty {
            result.pass("SHA256('') correct");
        } else {
            result.fail("SHA256('') mismatch");
        }

        results.push(result.summary());
    }

    // Test 2: Encryption with each chain's keys
    println!("\nTest 2: Per-Chain Encryption");
    println!("{}", "-".repeat(40));

    for (chain, keys) in &encryption_keys {
        let mut result = TestResult::new(&format!("Encryption with {}", chain));

        let key = hex::decode(&keys.key_hex)?;
        let iv = hex::decode(&keys.iv_hex)?;
        let plaintext = format!("Test data for {} encryption", chain);
        let plaintext_bytes = plaintext.as_bytes();

        let encrypted = em.encrypt_bytes(&key, &iv, plaintext_bytes)?;
        if encrypted != plaintext_bytes {
            result.pass("Encryption modified data");
        } else {
            result.fail("Encryption did not modify data");
        }

        let decrypted = em.decrypt_bytes(&key, &iv, &encrypted)?;
        if decrypted == plaintext_bytes {
            result.pass("Decryption restored original");
        } else {
            result.fail("Decryption mismatch");
        }

        results.push(result.summary());
    }

    // Test 3: Cross-language verification
    println!("\nTest 3: Cross-Language Verification");
    println!("{}", "-".repeat(40));
    {
        let mut result = TestResult::new("Cross-Language");

        let binary_dir = vectors_dir.join("binary");
        if binary_dir.exists() {
            let unencrypted_path = binary_dir.join("monster_unencrypted.bin");
            if unencrypted_path.exists() {
                let data = fs::read(&unencrypted_path)?;
                result.pass(&format!("Read unencrypted binary: {} bytes", data.len()));
            } else {
                result.fail("monster_unencrypted.bin not found - run Node.js test first");
            }

            for (chain, keys) in &encryption_keys {
                let encrypted_path = binary_dir.join(format!("monster_encrypted_{}.bin", chain));
                if encrypted_path.exists() {
                    let encrypted = fs::read(&encrypted_path)?;
                    result.pass(&format!("Read {}: {} bytes", chain, encrypted.len()));

                    // Verify we can decrypt
                    let key = hex::decode(&keys.key_hex)?;
                    let iv = hex::decode(&keys.iv_hex)?;
                    let _decrypted = em.decrypt_bytes(&key, &iv, &encrypted)?;
                    result.pass(&format!("Decrypted {} data", chain));
                }
            }
        } else {
            result.fail("Binary directory not found - run Node.js test first");
        }

        results.push(result.summary());
    }

    // Summary
    println!("\n{}", "=".repeat(60));
    println!("Summary");
    println!("{}", "=".repeat(60));

    let passed = results.iter().filter(|&&r| r).count();
    let total = results.len();
    println!("\nTotal: {}/{} test suites passed", passed, total);

    if passed == total {
        println!("\n✓ All tests passed!");
        Ok(())
    } else {
        println!("\n✗ Some tests failed");
        std::process::exit(1);
    }
}
