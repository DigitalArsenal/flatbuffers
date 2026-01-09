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

#[derive(Debug, Deserialize)]
struct ECDHHeader {
    version: u8,
    key_exchange: u8,
    ephemeral_public_key: String,
    context: Option<String>,
    session_key: String,
    session_iv: String,
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

    fn hkdf(&mut self, ikm: &[u8], salt: &[u8], info: &[u8], output_len: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let ikm_ptr = self.allocate(ikm.len().max(1) as u32)?;
        let salt_ptr = self.allocate(salt.len().max(1) as u32)?;
        let info_ptr = self.allocate(info.len().max(1) as u32)?;
        let out_ptr = self.allocate(output_len as u32)?;

        if !ikm.is_empty() { self.write_bytes(ikm_ptr, ikm); }
        if !salt.is_empty() { self.write_bytes(salt_ptr, salt); }
        if !info.is_empty() { self.write_bytes(info_ptr, info); }

        let hkdf_fn: TypedFunction<(u32, u32, u32, u32, u32, u32, u32, u32), ()> =
            self.instance.exports.get_typed_function(&self.store, "wasi_hkdf")?;
        hkdf_fn.call(&mut self.store, ikm_ptr, ikm.len() as u32, salt_ptr, salt.len() as u32,
                     info_ptr, info.len() as u32, out_ptr, output_len as u32)?;

        let output = self.read_bytes(out_ptr, output_len);
        self.deallocate(ikm_ptr);
        self.deallocate(salt_ptr);
        self.deallocate(info_ptr);
        self.deallocate(out_ptr);
        Ok(output)
    }

    fn x25519_generate_keypair(&mut self) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        let priv_ptr = self.allocate(32)?;
        let pub_ptr = self.allocate(32)?;

        let gen_fn: TypedFunction<(u32, u32), i32> =
            self.instance.exports.get_typed_function(&self.store, "wasi_x25519_generate_keypair")?;
        gen_fn.call(&mut self.store, priv_ptr, pub_ptr)?;

        let private_key = self.read_bytes(priv_ptr, 32);
        let public_key = self.read_bytes(pub_ptr, 32);
        self.deallocate(priv_ptr);
        self.deallocate(pub_ptr);
        Ok((private_key, public_key))
    }

    fn x25519_shared_secret(&mut self, private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let priv_ptr = self.allocate(32)?;
        let pub_ptr = self.allocate(32)?;
        let shared_ptr = self.allocate(32)?;

        self.write_bytes(priv_ptr, private_key);
        self.write_bytes(pub_ptr, public_key);

        let shared_fn: TypedFunction<(u32, u32, u32), i32> =
            self.instance.exports.get_typed_function(&self.store, "wasi_x25519_shared_secret")?;
        shared_fn.call(&mut self.store, priv_ptr, pub_ptr, shared_ptr)?;

        let shared = self.read_bytes(shared_ptr, 32);
        self.deallocate(priv_ptr);
        self.deallocate(pub_ptr);
        self.deallocate(shared_ptr);
        Ok(shared)
    }

    fn secp256k1_generate_keypair(&mut self) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        let priv_ptr = self.allocate(32)?;
        let pub_ptr = self.allocate(33)?;

        let gen_fn: TypedFunction<(u32, u32), i32> =
            self.instance.exports.get_typed_function(&self.store, "wasi_secp256k1_generate_keypair")?;
        gen_fn.call(&mut self.store, priv_ptr, pub_ptr)?;

        let private_key = self.read_bytes(priv_ptr, 32);
        let public_key = self.read_bytes(pub_ptr, 33);
        self.deallocate(priv_ptr);
        self.deallocate(pub_ptr);
        Ok((private_key, public_key))
    }

    fn secp256k1_shared_secret(&mut self, private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let priv_ptr = self.allocate(32)?;
        let pub_ptr = self.allocate(public_key.len() as u32)?;
        let shared_ptr = self.allocate(32)?;

        self.write_bytes(priv_ptr, private_key);
        self.write_bytes(pub_ptr, public_key);

        let shared_fn: TypedFunction<(u32, u32, u32, u32), i32> =
            self.instance.exports.get_typed_function(&self.store, "wasi_secp256k1_shared_secret")?;
        shared_fn.call(&mut self.store, priv_ptr, pub_ptr, public_key.len() as u32, shared_ptr)?;

        let shared = self.read_bytes(shared_ptr, 32);
        self.deallocate(priv_ptr);
        self.deallocate(pub_ptr);
        self.deallocate(shared_ptr);
        Ok(shared)
    }

    fn p256_generate_keypair(&mut self) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        let priv_ptr = self.allocate(32)?;
        let pub_ptr = self.allocate(33)?;

        let gen_fn: TypedFunction<(u32, u32), i32> =
            self.instance.exports.get_typed_function(&self.store, "wasi_p256_generate_keypair")?;
        gen_fn.call(&mut self.store, priv_ptr, pub_ptr)?;

        let private_key = self.read_bytes(priv_ptr, 32);
        let public_key = self.read_bytes(pub_ptr, 33);
        self.deallocate(priv_ptr);
        self.deallocate(pub_ptr);
        Ok((private_key, public_key))
    }

    fn p256_shared_secret(&mut self, private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let priv_ptr = self.allocate(32)?;
        let pub_ptr = self.allocate(public_key.len() as u32)?;
        let shared_ptr = self.allocate(32)?;

        self.write_bytes(priv_ptr, private_key);
        self.write_bytes(pub_ptr, public_key);

        let shared_fn: TypedFunction<(u32, u32, u32, u32), i32> =
            self.instance.exports.get_typed_function(&self.store, "wasi_p256_shared_secret")?;
        shared_fn.call(&mut self.store, priv_ptr, pub_ptr, public_key.len() as u32, shared_ptr)?;

        let shared = self.read_bytes(shared_ptr, 32);
        self.deallocate(priv_ptr);
        self.deallocate(pub_ptr);
        self.deallocate(shared_ptr);
        Ok(shared)
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

    // Test 4: ECDH Key Exchange Verification
    println!("\nTest 4: ECDH Key Exchange Verification");
    println!("{}", "-".repeat(40));

    struct ECDHCurve<'a> {
        name: &'a str,
        pub_key_size: usize,
        key_exchange: u8,
    }

    let ecdh_curves = [
        ECDHCurve { name: "X25519", pub_key_size: 32, key_exchange: 0 },
        ECDHCurve { name: "secp256k1", pub_key_size: 33, key_exchange: 1 },
        ECDHCurve { name: "P-256", pub_key_size: 33, key_exchange: 2 },
    ];

    // Read unencrypted data for cross-language verification
    let binary_dir = vectors_dir.join("binary");
    let unencrypted_data = fs::read(binary_dir.join("monster_unencrypted.bin")).ok();

    for curve in &ecdh_curves {
        let mut result = TestResult::new(&format!("ECDH {}", curve.name));

        // Generate keypairs for Alice and Bob
        let (alice_priv, alice_pub, bob_priv, bob_pub) = match curve.name {
            "X25519" => {
                let (ap, apub) = em.x25519_generate_keypair()?;
                let (bp, bpub) = em.x25519_generate_keypair()?;
                (ap, apub, bp, bpub)
            },
            "secp256k1" => {
                let (ap, apub) = em.secp256k1_generate_keypair()?;
                let (bp, bpub) = em.secp256k1_generate_keypair()?;
                (ap, apub, bp, bpub)
            },
            "P-256" => {
                let (ap, apub) = em.p256_generate_keypair()?;
                let (bp, bpub) = em.p256_generate_keypair()?;
                (ap, apub, bp, bpub)
            },
            _ => continue,
        };

        if alice_pub.len() == curve.pub_key_size {
            result.pass(&format!("Generated Alice keypair (pub: {} bytes)", alice_pub.len()));
        } else {
            result.fail(&format!("Alice public key wrong size: {}", alice_pub.len()));
        }

        if bob_pub.len() == curve.pub_key_size {
            result.pass(&format!("Generated Bob keypair (pub: {} bytes)", bob_pub.len()));
        } else {
            result.fail(&format!("Bob public key wrong size: {}", bob_pub.len()));
        }

        // Compute shared secrets
        let (alice_shared, bob_shared) = match curve.name {
            "X25519" => {
                let as_ = em.x25519_shared_secret(&alice_priv, &bob_pub)?;
                let bs = em.x25519_shared_secret(&bob_priv, &alice_pub)?;
                (as_, bs)
            },
            "secp256k1" => {
                let as_ = em.secp256k1_shared_secret(&alice_priv, &bob_pub)?;
                let bs = em.secp256k1_shared_secret(&bob_priv, &alice_pub)?;
                (as_, bs)
            },
            "P-256" => {
                let as_ = em.p256_shared_secret(&alice_priv, &bob_pub)?;
                let bs = em.p256_shared_secret(&bob_priv, &alice_pub)?;
                (as_, bs)
            },
            _ => continue,
        };

        if alice_shared == bob_shared {
            result.pass(&format!("Shared secrets match ({} bytes)", alice_shared.len()));
        } else {
            result.fail("Shared secrets DO NOT match!");
            result.fail(&format!("  Alice: {}", hex::encode(&alice_shared)));
            result.fail(&format!("  Bob:   {}", hex::encode(&bob_shared)));
        }

        // Test HKDF key derivation from shared secret
        let session_material = em.hkdf(&alice_shared, b"flatbuffers-encryption", b"session-key-iv", 48)?;
        let session_key = &session_material[..32];
        let session_iv = &session_material[32..48];

        if session_key.len() == 32 && session_iv.len() == 16 {
            result.pass(&format!("HKDF derived key ({}B) + IV ({}B)", session_key.len(), session_iv.len()));
        } else {
            result.fail("HKDF output wrong size");
        }

        // Full E2E: encrypt with derived key, decrypt with same key
        let test_data = format!("ECDH test data for {} encryption", curve.name);
        let plaintext = test_data.as_bytes();
        let encrypted = em.encrypt_bytes(session_key, session_iv, plaintext)?;

        if encrypted != plaintext {
            result.pass("Encryption with derived key modified data");
        } else {
            result.fail("Encryption did not modify data");
        }

        let decrypted = em.decrypt_bytes(session_key, session_iv, &encrypted)?;
        if decrypted == plaintext {
            result.pass("Decryption with derived key restored original");
        } else {
            result.fail("Decryption mismatch");
        }

        // Verify cross-language ECDH header if available
        let header_name = curve.name.to_lowercase().replace("-", "");
        let header_path = binary_dir.join(format!("monster_ecdh_{}_header.json", header_name));
        if header_path.exists() {
            match fs::read_to_string(&header_path) {
                Ok(header_json) => {
                    match serde_json::from_str::<ECDHHeader>(&header_json) {
                        Ok(header) => {
                            if header.key_exchange == curve.key_exchange {
                                result.pass(&format!("Cross-language header has correct key_exchange: {}", curve.key_exchange));
                            } else {
                                result.fail(&format!("Header key_exchange mismatch: {}", header.key_exchange));
                            }

                            if !header.ephemeral_public_key.is_empty() && !header.session_key.is_empty() && !header.session_iv.is_empty() {
                                result.pass("Header contains ephemeral_public_key, session_key, session_iv");

                                // Decrypt the cross-language encrypted file using Node.js session key
                                let encrypted_path = binary_dir.join(format!("monster_ecdh_{}_encrypted.bin", header_name));
                                if encrypted_path.exists() {
                                    if let (Ok(node_key), Ok(node_iv)) = (hex::decode(&header.session_key), hex::decode(&header.session_iv)) {
                                        if let Ok(encrypted_data) = fs::read(&encrypted_path) {
                                            match em.decrypt_bytes(&node_key, &node_iv, &encrypted_data) {
                                                Ok(decrypted_data) => {
                                                    if let Some(ref unenc) = unencrypted_data {
                                                        if decrypted_data == *unenc {
                                                            result.pass(&format!("Decrypted Node.js {} data matches original", curve.name));
                                                        } else {
                                                            result.fail(&format!("Decrypted Node.js {} data mismatch", curve.name));
                                                        }
                                                    }
                                                },
                                                Err(e) => result.fail(&format!("Failed to decrypt: {}", e)),
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        Err(e) => result.fail(&format!("Error parsing header: {}", e)),
                    }
                },
                Err(e) => result.fail(&format!("Error reading header: {}", e)),
            }
        } else {
            result.pass(&format!("(No cross-language header found at {})", header_path.display()));
        }

        results.push(result.summary());
    }

    // Test 5: Runtime Code Generation
    println!("\nTest 5: Runtime Code Generation");
    println!("{}", "-".repeat(40));
    {
        let mut result = TestResult::new("Code Generation");

        // Try to find native flatc binary (prefer built version over system)
        let flatc_paths = vec![
            vectors_dir.join("../../../../build/flatc"),
            vectors_dir.join("../../../../flatc"),
        ];

        let mut flatc_path: Option<std::path::PathBuf> = None;
        for p in &flatc_paths {
            if p.exists() {
                flatc_path = Some(p.clone());
                break;
            }
        }

        // Fall back to PATH if built flatc not found
        if flatc_path.is_none() {
            if let Ok(output) = std::process::Command::new("which").arg("flatc").output() {
                if output.status.success() {
                    let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if !path_str.is_empty() {
                        flatc_path = Some(std::path::PathBuf::from(path_str));
                    }
                }
            }
        }

        if let Some(ref flatc) = flatc_path {
            result.pass(&format!("Found flatc: {}", flatc.display()));

            // Get flatc version
            if let Ok(output) = std::process::Command::new(flatc).arg("--version").output() {
                if output.status.success() {
                    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    result.pass(&format!("flatc version: {}", version));
                }
            }

            // Generate Rust code from schema
            let schema_path = vectors_dir.join("../schemas/message.fbs");
            let temp_dir = std::env::temp_dir().join(format!("flatc-gen-{}", std::process::id()));
            let _ = fs::create_dir_all(&temp_dir);

            let gen_result = std::process::Command::new(flatc)
                .arg("--rust")
                .arg("-o")
                .arg(&temp_dir)
                .arg(&schema_path)
                .output();

            match gen_result {
                Ok(output) if output.status.success() => {
                    result.pass("Generated Rust code from schema");

                    // List generated files
                    if let Ok(entries) = fs::read_dir(&temp_dir) {
                        for entry in entries.flatten() {
                            if let Ok(metadata) = entry.metadata() {
                                if metadata.is_file() {
                                    result.pass(&format!("Generated: {} ({} bytes)",
                                        entry.file_name().to_string_lossy(),
                                        metadata.len()
                                    ));
                                }
                            }
                        }
                    }
                },
                Ok(output) => {
                    result.fail(&format!("Generate Rust code failed: {}",
                        String::from_utf8_lossy(&output.stderr)));
                },
                Err(e) => result.fail(&format!("Failed to run flatc: {}", e)),
            }

            let _ = fs::remove_dir_all(&temp_dir);
        } else {
            result.pass("flatc not found - using pre-generated code (this is OK)");
            // Verify pre-generated code exists
            let pregen_path = vectors_dir.join("../generated/rust");
            if pregen_path.exists() {
                if let Ok(entries) = fs::read_dir(&pregen_path) {
                    let count = entries.filter(|e| e.is_ok()).count();
                    result.pass(&format!("Pre-generated Rust code: {} files in generated/rust/", count));
                }
            }
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
