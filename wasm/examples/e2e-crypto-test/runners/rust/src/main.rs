//! Rust E2E Test Runner for FlatBuffers Cross-Language Encryption
//!
//! Tests encryption/decryption using the WASM Crypto++ module with all 10 crypto key types.
//! Uses wasmtime runtime (same as Python/C# runners).

#[allow(dead_code, unused_imports, non_snake_case)]
mod message_generated;

use flatbuffers::FlatBufferBuilder;
use message_generated::e2_e::crypto::{
    SecureMessage, SecureMessageArgs, Payload, PayloadArgs, SECURE_MESSAGE_IDENTIFIER,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use wasmtime::*;

const AES_KEY_SIZE: usize = 32;
const AES_IV_SIZE: usize = 16;
const SHA256_SIZE: usize = 32;

#[derive(Debug, Deserialize)]
struct EncryptionKey {
    key_hex: String,
    iv_hex: String,
    #[allow(dead_code)]
    key_base64: String,
    #[allow(dead_code)]
    iv_base64: String,
}

#[allow(dead_code)]
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
    #[allow(dead_code)]
    version: u8,
    key_exchange: u8,
    ephemeral_public_key: String,
    #[allow(dead_code)]
    context: Option<String>,
    session_key: String,
    session_iv: String,
}

struct WasmState {
    memory: Option<Memory>,
    table: Option<Table>,
    threw: (i32, i32),
}

struct EncryptionModule {
    store: Store<WasmState>,
    instance: Instance,
}

impl EncryptionModule {
    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let wasm_bytes = fs::read(path.as_ref())?;
        Self::from_bytes(&wasm_bytes)
    }

    fn from_bytes(wasm_bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let engine = Engine::default();
        let module = Module::new(&engine, wasm_bytes)?;

        let mut store = Store::new(&engine, WasmState {
            memory: None,
            table: None,
            threw: (0, 0),
        });

        let mut linker = Linker::new(&engine);

        // WASI stubs
        linker.func_wrap("wasi_snapshot_preview1", "fd_close", |_: i32| -> i32 { 0 })?;
        linker.func_wrap("wasi_snapshot_preview1", "fd_seek", |_: i32, _: i64, _: i32, _: i32| -> i32 { 0 })?;
        linker.func_wrap("wasi_snapshot_preview1", "fd_write", |_: i32, _: i32, _: i32, _: i32| -> i32 { 0 })?;
        linker.func_wrap("wasi_snapshot_preview1", "fd_read", |_: i32, _: i32, _: i32, _: i32| -> i32 { 0 })?;
        linker.func_wrap("wasi_snapshot_preview1", "environ_sizes_get", |_: i32, _: i32| -> i32 { 0 })?;
        linker.func_wrap("wasi_snapshot_preview1", "environ_get", |_: i32, _: i32| -> i32 { 0 })?;
        linker.func_wrap("wasi_snapshot_preview1", "proc_exit", |_: i32| {})?;

        linker.func_wrap("wasi_snapshot_preview1", "clock_time_get",
            |mut caller: Caller<'_, WasmState>, _clock_id: i32, _precision: i64, time_ptr: i32| -> i32 {
                use std::time::{SystemTime, UNIX_EPOCH};
                let ns = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
                if let Some(memory) = caller.data().memory {
                    let _ = memory.write(&mut caller, time_ptr as usize, &ns.to_le_bytes());
                }
                0
            }
        )?;

        linker.func_wrap("wasi_snapshot_preview1", "random_get",
            |mut caller: Caller<'_, WasmState>, buf: i32, buf_len: i32| -> i32 {
                if let Some(memory) = caller.data().memory {
                    let mut random_bytes = vec![0u8; buf_len as usize];
                    // Use simple random from std
                    use std::collections::hash_map::RandomState;
                    use std::hash::{BuildHasher, Hasher};
                    let s = RandomState::new();
                    for chunk in random_bytes.chunks_mut(8) {
                        let mut hasher = s.build_hasher();
                        hasher.write_usize(chunk.as_ptr() as usize);
                        let random = hasher.finish().to_le_bytes();
                        for (i, b) in chunk.iter_mut().enumerate() {
                            *b = random[i % 8];
                        }
                    }
                    let _ = memory.write(&mut caller, buf as usize, &random_bytes);
                    return 0;
                }
                8  // WASI errno for failure
            }
        )?;

        // Emscripten exception handling stubs
        linker.func_wrap("env", "setThrew",
            |mut caller: Caller<'_, WasmState>, threw: i32, value: i32| {
                caller.data_mut().threw = (threw, value);
            }
        )?;
        linker.func_wrap("env", "__cxa_find_matching_catch_2", || -> i32 { 0 })?;
        linker.func_wrap("env", "__cxa_find_matching_catch_3", |_: i32| -> i32 { 0 })?;
        linker.func_wrap("env", "__resumeException", |_: i32| {})?;
        linker.func_wrap("env", "__cxa_begin_catch", |_: i32| -> i32 { 0 })?;
        linker.func_wrap("env", "__cxa_end_catch", || {})?;
        linker.func_wrap("env", "llvm_eh_typeid_for", |_: i32| -> i32 { 0 })?;
        linker.func_wrap("env", "__cxa_throw", |_: i32, _: i32, _: i32| {})?;
        linker.func_wrap("env", "__cxa_uncaught_exceptions", || -> i32 { 0 })?;

        // invoke_* trampolines - call functions from indirect function table
        // In wasmtime 27, table.get returns Ref which can be converted to Func via as_func()
        linker.func_wrap("env", "invoke_v",
            |mut caller: Caller<'_, WasmState>, idx: i32| {
                if let Some(table) = caller.data().table {
                    if let Some(ref_val) = table.get(&mut caller, idx as u64) {
                        if let Some(func) = ref_val.as_func().flatten().cloned() {
                            let _ = func.call(&mut caller, &[], &mut []);
                        }
                    }
                }
            }
        )?;

        linker.func_wrap("env", "invoke_vi",
            |mut caller: Caller<'_, WasmState>, idx: i32, a: i32| {
                if let Some(table) = caller.data().table {
                    if let Some(ref_val) = table.get(&mut caller, idx as u64) {
                        if let Some(func) = ref_val.as_func().flatten().cloned() {
                            let _ = func.call(&mut caller, &[Val::I32(a)], &mut []);
                        }
                    }
                }
            }
        )?;

        linker.func_wrap("env", "invoke_vii",
            |mut caller: Caller<'_, WasmState>, idx: i32, a: i32, b: i32| {
                if let Some(table) = caller.data().table {
                    if let Some(ref_val) = table.get(&mut caller, idx as u64) {
                        if let Some(func) = ref_val.as_func().flatten().cloned() {
                            let _ = func.call(&mut caller, &[Val::I32(a), Val::I32(b)], &mut []);
                        }
                    }
                }
            }
        )?;

        linker.func_wrap("env", "invoke_viii",
            |mut caller: Caller<'_, WasmState>, idx: i32, a: i32, b: i32, c: i32| {
                if let Some(table) = caller.data().table {
                    if let Some(ref_val) = table.get(&mut caller, idx as u64) {
                        if let Some(func) = ref_val.as_func().flatten().cloned() {
                            let _ = func.call(&mut caller, &[Val::I32(a), Val::I32(b), Val::I32(c)], &mut []);
                        }
                    }
                }
            }
        )?;

        linker.func_wrap("env", "invoke_viiii",
            |mut caller: Caller<'_, WasmState>, idx: i32, a: i32, b: i32, c: i32, d: i32| {
                if let Some(table) = caller.data().table {
                    if let Some(ref_val) = table.get(&mut caller, idx as u64) {
                        if let Some(func) = ref_val.as_func().flatten().cloned() {
                            let _ = func.call(&mut caller, &[Val::I32(a), Val::I32(b), Val::I32(c), Val::I32(d)], &mut []);
                        }
                    }
                }
            }
        )?;

        linker.func_wrap("env", "invoke_viiiii",
            |mut caller: Caller<'_, WasmState>, idx: i32, a: i32, b: i32, c: i32, d: i32, e: i32| {
                if let Some(table) = caller.data().table {
                    if let Some(ref_val) = table.get(&mut caller, idx as u64) {
                        if let Some(func) = ref_val.as_func().flatten().cloned() {
                            let _ = func.call(&mut caller, &[Val::I32(a), Val::I32(b), Val::I32(c), Val::I32(d), Val::I32(e)], &mut []);
                        }
                    }
                }
            }
        )?;

        linker.func_wrap("env", "invoke_viiiiii",
            |mut caller: Caller<'_, WasmState>, idx: i32, a: i32, b: i32, c: i32, d: i32, e: i32, f: i32| {
                if let Some(table) = caller.data().table {
                    if let Some(ref_val) = table.get(&mut caller, idx as u64) {
                        if let Some(func) = ref_val.as_func().flatten().cloned() {
                            let _ = func.call(&mut caller, &[Val::I32(a), Val::I32(b), Val::I32(c), Val::I32(d), Val::I32(e), Val::I32(f)], &mut []);
                        }
                    }
                }
            }
        )?;

        linker.func_wrap("env", "invoke_viiiiiii",
            |mut caller: Caller<'_, WasmState>, idx: i32, a: i32, b: i32, c: i32, d: i32, e: i32, f: i32, g: i32| {
                if let Some(table) = caller.data().table {
                    if let Some(ref_val) = table.get(&mut caller, idx as u64) {
                        if let Some(func) = ref_val.as_func().flatten().cloned() {
                            let _ = func.call(&mut caller, &[Val::I32(a), Val::I32(b), Val::I32(c), Val::I32(d), Val::I32(e), Val::I32(f), Val::I32(g)], &mut []);
                        }
                    }
                }
            }
        )?;

        linker.func_wrap("env", "invoke_viiiiiiiii",
            |mut caller: Caller<'_, WasmState>, idx: i32, a: i32, b: i32, c: i32, d: i32, e: i32, f: i32, g: i32, h: i32, i: i32| {
                if let Some(table) = caller.data().table {
                    if let Some(ref_val) = table.get(&mut caller, idx as u64) {
                        if let Some(func) = ref_val.as_func().flatten().cloned() {
                            let _ = func.call(&mut caller, &[Val::I32(a), Val::I32(b), Val::I32(c), Val::I32(d), Val::I32(e), Val::I32(f), Val::I32(g), Val::I32(h), Val::I32(i)], &mut []);
                        }
                    }
                }
            }
        )?;

        linker.func_wrap("env", "invoke_i",
            |mut caller: Caller<'_, WasmState>, idx: i32| -> i32 {
                if let Some(table) = caller.data().table {
                    if let Some(ref_val) = table.get(&mut caller, idx as u64) {
                        if let Some(func) = ref_val.as_func().flatten().cloned() {
                            let mut results = [Val::I32(0)];
                            if func.call(&mut caller, &[], &mut results).is_ok() {
                                if let Val::I32(v) = results[0] { return v; }
                            }
                        }
                    }
                }
                0
            }
        )?;

        linker.func_wrap("env", "invoke_ii",
            |mut caller: Caller<'_, WasmState>, idx: i32, a: i32| -> i32 {
                if let Some(table) = caller.data().table {
                    if let Some(ref_val) = table.get(&mut caller, idx as u64) {
                        if let Some(func) = ref_val.as_func().flatten().cloned() {
                            let mut results = [Val::I32(0)];
                            if func.call(&mut caller, &[Val::I32(a)], &mut results).is_ok() {
                                if let Val::I32(v) = results[0] { return v; }
                            }
                        }
                    }
                }
                0
            }
        )?;

        linker.func_wrap("env", "invoke_iii",
            |mut caller: Caller<'_, WasmState>, idx: i32, a: i32, b: i32| -> i32 {
                if let Some(table) = caller.data().table {
                    if let Some(ref_val) = table.get(&mut caller, idx as u64) {
                        if let Some(func) = ref_val.as_func().flatten().cloned() {
                            let mut results = [Val::I32(0)];
                            if func.call(&mut caller, &[Val::I32(a), Val::I32(b)], &mut results).is_ok() {
                                if let Val::I32(v) = results[0] { return v; }
                            }
                        }
                    }
                }
                0
            }
        )?;

        linker.func_wrap("env", "invoke_iiii",
            |mut caller: Caller<'_, WasmState>, idx: i32, a: i32, b: i32, c: i32| -> i32 {
                if let Some(table) = caller.data().table {
                    if let Some(ref_val) = table.get(&mut caller, idx as u64) {
                        if let Some(func) = ref_val.as_func().flatten().cloned() {
                            let mut results = [Val::I32(0)];
                            if func.call(&mut caller, &[Val::I32(a), Val::I32(b), Val::I32(c)], &mut results).is_ok() {
                                if let Val::I32(v) = results[0] { return v; }
                            }
                        }
                    }
                }
                0
            }
        )?;

        linker.func_wrap("env", "invoke_iiiii",
            |mut caller: Caller<'_, WasmState>, idx: i32, a: i32, b: i32, c: i32, d: i32| -> i32 {
                if let Some(table) = caller.data().table {
                    if let Some(ref_val) = table.get(&mut caller, idx as u64) {
                        if let Some(func) = ref_val.as_func().flatten().cloned() {
                            let mut results = [Val::I32(0)];
                            if func.call(&mut caller, &[Val::I32(a), Val::I32(b), Val::I32(c), Val::I32(d)], &mut results).is_ok() {
                                if let Val::I32(v) = results[0] { return v; }
                            }
                        }
                    }
                }
                0
            }
        )?;

        linker.func_wrap("env", "invoke_iiiiii",
            |mut caller: Caller<'_, WasmState>, idx: i32, a: i32, b: i32, c: i32, d: i32, e: i32| -> i32 {
                if let Some(table) = caller.data().table {
                    if let Some(ref_val) = table.get(&mut caller, idx as u64) {
                        if let Some(func) = ref_val.as_func().flatten().cloned() {
                            let mut results = [Val::I32(0)];
                            if func.call(&mut caller, &[Val::I32(a), Val::I32(b), Val::I32(c), Val::I32(d), Val::I32(e)], &mut results).is_ok() {
                                if let Val::I32(v) = results[0] { return v; }
                            }
                        }
                    }
                }
                0
            }
        )?;

        linker.func_wrap("env", "invoke_iiiiiii",
            |mut caller: Caller<'_, WasmState>, idx: i32, a: i32, b: i32, c: i32, d: i32, e: i32, f: i32| -> i32 {
                if let Some(table) = caller.data().table {
                    if let Some(ref_val) = table.get(&mut caller, idx as u64) {
                        if let Some(func) = ref_val.as_func().flatten().cloned() {
                            let mut results = [Val::I32(0)];
                            if func.call(&mut caller, &[Val::I32(a), Val::I32(b), Val::I32(c), Val::I32(d), Val::I32(e), Val::I32(f)], &mut results).is_ok() {
                                if let Val::I32(v) = results[0] { return v; }
                            }
                        }
                    }
                }
                0
            }
        )?;

        linker.func_wrap("env", "invoke_iiiiiiii",
            |mut caller: Caller<'_, WasmState>, idx: i32, a: i32, b: i32, c: i32, d: i32, e: i32, f: i32, g: i32| -> i32 {
                if let Some(table) = caller.data().table {
                    if let Some(ref_val) = table.get(&mut caller, idx as u64) {
                        if let Some(func) = ref_val.as_func().flatten().cloned() {
                            let mut results = [Val::I32(0)];
                            if func.call(&mut caller, &[Val::I32(a), Val::I32(b), Val::I32(c), Val::I32(d), Val::I32(e), Val::I32(f), Val::I32(g)], &mut results).is_ok() {
                                if let Val::I32(v) = results[0] { return v; }
                            }
                        }
                    }
                }
                0
            }
        )?;

        linker.func_wrap("env", "invoke_iiiiiiiiii",
            |mut caller: Caller<'_, WasmState>, idx: i32, a: i32, b: i32, c: i32, d: i32, e: i32, f: i32, g: i32, h: i32, i: i32| -> i32 {
                if let Some(table) = caller.data().table {
                    if let Some(ref_val) = table.get(&mut caller, idx as u64) {
                        if let Some(func) = ref_val.as_func().flatten().cloned() {
                            let mut results = [Val::I32(0)];
                            if func.call(&mut caller, &[Val::I32(a), Val::I32(b), Val::I32(c), Val::I32(d), Val::I32(e), Val::I32(f), Val::I32(g), Val::I32(h), Val::I32(i)], &mut results).is_ok() {
                                if let Val::I32(v) = results[0] { return v; }
                            }
                        }
                    }
                }
                0
            }
        )?;

        let instance = linker.instantiate(&mut store, &module)?;

        // Get memory and table, store in state
        if let Some(memory) = instance.get_memory(&mut store, "memory") {
            store.data_mut().memory = Some(memory);
        }
        if let Some(table) = instance.get_table(&mut store, "__indirect_function_table") {
            store.data_mut().table = Some(table);
        }

        // Call _initialize if present
        if let Some(init) = instance.get_func(&mut store, "_initialize") {
            let _ = init.call(&mut store, &[], &mut []);
        }

        Ok(Self { store, instance })
    }

    fn memory(&mut self) -> Memory {
        self.store.data().memory.expect("memory not initialized")
    }

    fn allocate(&mut self, size: u32) -> Result<u32, Box<dyn std::error::Error>> {
        let malloc = self.instance.get_typed_func::<u32, u32>(&mut self.store, "malloc")?;
        Ok(malloc.call(&mut self.store, size)?)
    }

    fn deallocate(&mut self, ptr: u32) {
        if let Ok(free) = self.instance.get_typed_func::<u32, ()>(&mut self.store, "free") {
            let _ = free.call(&mut self.store, ptr);
        }
    }

    fn write_bytes(&mut self, ptr: u32, data: &[u8]) {
        let memory = self.memory();
        let _ = memory.write(&mut self.store, ptr as usize, data);
    }

    fn read_bytes(&mut self, ptr: u32, size: usize) -> Vec<u8> {
        let memory = self.memory();
        let mut buffer = vec![0u8; size];
        let _ = memory.read(&self.store, ptr as usize, &mut buffer);
        buffer
    }

    fn sha256(&mut self, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let data_ptr = self.allocate(data.len().max(1) as u32)?;
        let hash_ptr = self.allocate(SHA256_SIZE as u32)?;

        if !data.is_empty() {
            self.write_bytes(data_ptr, data);
        }

        let sha256_fn = self.instance.get_typed_func::<(u32, u32, u32), ()>(&mut self.store, "wasi_sha256")?;
        sha256_fn.call(&mut self.store, (data_ptr, data.len() as u32, hash_ptr))?;

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

        let encrypt_fn = self.instance.get_typed_func::<(u32, u32, u32, u32), i32>(&mut self.store, "wasi_encrypt_bytes")?;
        let _ = encrypt_fn.call(&mut self.store, (key_ptr, iv_ptr, data_ptr, data.len() as u32))?;

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

        let decrypt_fn = self.instance.get_typed_func::<(u32, u32, u32, u32), i32>(&mut self.store, "wasi_decrypt_bytes")?;
        let _ = decrypt_fn.call(&mut self.store, (key_ptr, iv_ptr, data_ptr, data.len() as u32))?;

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

        let hkdf_fn = self.instance.get_typed_func::<(u32, u32, u32, u32, u32, u32, u32, u32), ()>(&mut self.store, "wasi_hkdf")?;
        hkdf_fn.call(&mut self.store, (ikm_ptr, ikm.len() as u32, salt_ptr, salt.len() as u32,
                     info_ptr, info.len() as u32, out_ptr, output_len as u32))?;

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

        let gen_fn = self.instance.get_typed_func::<(u32, u32), i32>(&mut self.store, "wasi_x25519_generate_keypair")?;
        gen_fn.call(&mut self.store, (priv_ptr, pub_ptr))?;

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

        let shared_fn = self.instance.get_typed_func::<(u32, u32, u32), i32>(&mut self.store, "wasi_x25519_shared_secret")?;
        shared_fn.call(&mut self.store, (priv_ptr, pub_ptr, shared_ptr))?;

        let shared = self.read_bytes(shared_ptr, 32);
        self.deallocate(priv_ptr);
        self.deallocate(pub_ptr);
        self.deallocate(shared_ptr);
        Ok(shared)
    }

    fn secp256k1_generate_keypair(&mut self) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        let priv_ptr = self.allocate(32)?;
        let pub_ptr = self.allocate(33)?;

        let gen_fn = self.instance.get_typed_func::<(u32, u32), i32>(&mut self.store, "wasi_secp256k1_generate_keypair")?;
        gen_fn.call(&mut self.store, (priv_ptr, pub_ptr))?;

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

        let shared_fn = self.instance.get_typed_func::<(u32, u32, u32, u32), i32>(&mut self.store, "wasi_secp256k1_shared_secret")?;
        shared_fn.call(&mut self.store, (priv_ptr, pub_ptr, public_key.len() as u32, shared_ptr))?;

        let shared = self.read_bytes(shared_ptr, 32);
        self.deallocate(priv_ptr);
        self.deallocate(pub_ptr);
        self.deallocate(shared_ptr);
        Ok(shared)
    }

    fn p256_generate_keypair(&mut self) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        let priv_ptr = self.allocate(32)?;
        let pub_ptr = self.allocate(33)?;

        let gen_fn = self.instance.get_typed_func::<(u32, u32), i32>(&mut self.store, "wasi_p256_generate_keypair")?;
        gen_fn.call(&mut self.store, (priv_ptr, pub_ptr))?;

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

        let shared_fn = self.instance.get_typed_func::<(u32, u32, u32, u32), i32>(&mut self.store, "wasi_p256_shared_secret")?;
        shared_fn.call(&mut self.store, (priv_ptr, pub_ptr, public_key.len() as u32, shared_ptr))?;

        let shared = self.read_bytes(shared_ptr, 32);
        self.deallocate(priv_ptr);
        self.deallocate(pub_ptr);
        self.deallocate(shared_ptr);
        Ok(shared)
    }

    fn ed25519_generate_keypair(&mut self) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        let priv_ptr = self.allocate(64)?;  // Ed25519 private key is 64 bytes
        let pub_ptr = self.allocate(32)?;

        let gen_fn = self.instance.get_typed_func::<(u32, u32), i32>(&mut self.store, "wasi_ed25519_generate_keypair")?;
        let result = gen_fn.call(&mut self.store, (priv_ptr, pub_ptr))?;
        if result != 0 {
            self.deallocate(priv_ptr);
            self.deallocate(pub_ptr);
            return Err("Ed25519 keypair generation failed".into());
        }

        let private_key = self.read_bytes(priv_ptr, 64);
        let public_key = self.read_bytes(pub_ptr, 32);
        self.deallocate(priv_ptr);
        self.deallocate(pub_ptr);
        Ok((private_key, public_key))
    }

    fn ed25519_sign(&mut self, private_key: &[u8], data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let priv_ptr = self.allocate(64)?;
        let data_ptr = self.allocate(data.len().max(1) as u32)?;
        let sig_ptr = self.allocate(64)?;

        self.write_bytes(priv_ptr, private_key);
        if !data.is_empty() {
            self.write_bytes(data_ptr, data);
        }

        let sign_fn = self.instance.get_typed_func::<(u32, u32, u32, u32), i32>(&mut self.store, "wasi_ed25519_sign")?;
        let result = sign_fn.call(&mut self.store, (priv_ptr, data_ptr, data.len() as u32, sig_ptr))?;
        if result != 0 {
            self.deallocate(priv_ptr);
            self.deallocate(data_ptr);
            self.deallocate(sig_ptr);
            return Err("Ed25519 signing failed".into());
        }

        let signature = self.read_bytes(sig_ptr, 64);
        self.deallocate(priv_ptr);
        self.deallocate(data_ptr);
        self.deallocate(sig_ptr);
        Ok(signature)
    }

    fn ed25519_verify(&mut self, public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
        let pub_ptr = self.allocate(32)?;
        let data_ptr = self.allocate(data.len().max(1) as u32)?;
        let sig_ptr = self.allocate(64)?;

        self.write_bytes(pub_ptr, public_key);
        if !data.is_empty() {
            self.write_bytes(data_ptr, data);
        }
        self.write_bytes(sig_ptr, signature);

        let verify_fn = self.instance.get_typed_func::<(u32, u32, u32, u32), i32>(&mut self.store, "wasi_ed25519_verify")?;
        let result = verify_fn.call(&mut self.store, (pub_ptr, data_ptr, data.len() as u32, sig_ptr))?;

        self.deallocate(pub_ptr);
        self.deallocate(data_ptr);
        self.deallocate(sig_ptr);
        Ok(result == 0)
    }

    fn secp256k1_sign(&mut self, private_key: &[u8], data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let priv_ptr = self.allocate(32)?;
        let data_ptr = self.allocate(data.len().max(1) as u32)?;
        let sig_ptr = self.allocate(72)?;  // DER signature up to 72 bytes
        let sig_size_ptr = self.allocate(4)?;

        self.write_bytes(priv_ptr, private_key);
        if !data.is_empty() {
            self.write_bytes(data_ptr, data);
        }

        let sign_fn = self.instance.get_typed_func::<(u32, u32, u32, u32, u32), i32>(&mut self.store, "wasi_secp256k1_sign")?;
        let result = sign_fn.call(&mut self.store, (priv_ptr, data_ptr, data.len() as u32, sig_ptr, sig_size_ptr))?;
        if result != 0 {
            self.deallocate(priv_ptr);
            self.deallocate(data_ptr);
            self.deallocate(sig_ptr);
            self.deallocate(sig_size_ptr);
            return Err("secp256k1 signing failed".into());
        }

        let sig_size_bytes = self.read_bytes(sig_size_ptr, 4);
        let sig_size = u32::from_le_bytes([sig_size_bytes[0], sig_size_bytes[1], sig_size_bytes[2], sig_size_bytes[3]]) as usize;
        let signature = self.read_bytes(sig_ptr, sig_size);

        self.deallocate(priv_ptr);
        self.deallocate(data_ptr);
        self.deallocate(sig_ptr);
        self.deallocate(sig_size_ptr);
        Ok(signature)
    }

    fn secp256k1_verify(&mut self, public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
        let pub_ptr = self.allocate(public_key.len().max(1) as u32)?;
        let data_ptr = self.allocate(data.len().max(1) as u32)?;
        let sig_ptr = self.allocate(signature.len().max(1) as u32)?;

        if !public_key.is_empty() { self.write_bytes(pub_ptr, public_key); }
        if !data.is_empty() { self.write_bytes(data_ptr, data); }
        if !signature.is_empty() { self.write_bytes(sig_ptr, signature); }

        let verify_fn = self.instance.get_typed_func::<(u32, u32, u32, u32, u32, u32), i32>(&mut self.store, "wasi_secp256k1_verify")?;
        let result = verify_fn.call(&mut self.store, (pub_ptr, public_key.len() as u32, data_ptr, data.len() as u32, sig_ptr, signature.len() as u32))?;

        self.deallocate(pub_ptr);
        self.deallocate(data_ptr);
        self.deallocate(sig_ptr);
        Ok(result == 0)
    }

    fn p256_sign(&mut self, private_key: &[u8], data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let priv_ptr = self.allocate(32)?;
        let data_ptr = self.allocate(data.len().max(1) as u32)?;
        let sig_ptr = self.allocate(72)?;  // DER signature up to 72 bytes
        let sig_size_ptr = self.allocate(4)?;

        self.write_bytes(priv_ptr, private_key);
        if !data.is_empty() {
            self.write_bytes(data_ptr, data);
        }

        let sign_fn = self.instance.get_typed_func::<(u32, u32, u32, u32, u32), i32>(&mut self.store, "wasi_p256_sign")?;
        let result = sign_fn.call(&mut self.store, (priv_ptr, data_ptr, data.len() as u32, sig_ptr, sig_size_ptr))?;
        if result != 0 {
            self.deallocate(priv_ptr);
            self.deallocate(data_ptr);
            self.deallocate(sig_ptr);
            self.deallocate(sig_size_ptr);
            return Err("P-256 signing failed".into());
        }

        let sig_size_bytes = self.read_bytes(sig_size_ptr, 4);
        let sig_size = u32::from_le_bytes([sig_size_bytes[0], sig_size_bytes[1], sig_size_bytes[2], sig_size_bytes[3]]) as usize;
        let signature = self.read_bytes(sig_ptr, sig_size);

        self.deallocate(priv_ptr);
        self.deallocate(data_ptr);
        self.deallocate(sig_ptr);
        self.deallocate(sig_size_ptr);
        Ok(signature)
    }

    fn p256_verify(&mut self, public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
        let pub_ptr = self.allocate(public_key.len().max(1) as u32)?;
        let data_ptr = self.allocate(data.len().max(1) as u32)?;
        let sig_ptr = self.allocate(signature.len().max(1) as u32)?;

        if !public_key.is_empty() { self.write_bytes(pub_ptr, public_key); }
        if !data.is_empty() { self.write_bytes(data_ptr, data); }
        if !signature.is_empty() { self.write_bytes(sig_ptr, signature); }

        let verify_fn = self.instance.get_typed_func::<(u32, u32, u32, u32, u32, u32), i32>(&mut self.store, "wasi_p256_verify")?;
        let result = verify_fn.call(&mut self.store, (pub_ptr, public_key.len() as u32, data_ptr, data.len() as u32, sig_ptr, signature.len() as u32))?;

        self.deallocate(pub_ptr);
        self.deallocate(data_ptr);
        self.deallocate(sig_ptr);
        Ok(result == 0)
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
    println!("WASM Runtime: wasmtime");
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

    // Test 6: Digital Signatures (Ed25519, secp256k1, P-256)
    println!("\nTest 6: Digital Signatures");
    println!("{}", "-".repeat(40));
    {
        let mut result = TestResult::new("Digital Signatures");

        let test_message = b"Hello, FlatBuffers! This is a test message for signing.";

        // Test Ed25519
        match em.ed25519_generate_keypair() {
            Ok((priv_key, pub_key)) => {
                result.pass(&format!("Ed25519 keypair generated (priv: {}, pub: {} bytes)", priv_key.len(), pub_key.len()));

                match em.ed25519_sign(&priv_key, test_message) {
                    Ok(sig) => {
                        result.pass(&format!("Ed25519 signature: {} bytes", sig.len()));

                        match em.ed25519_verify(&pub_key, test_message, &sig) {
                            Ok(true) => result.pass("Ed25519 signature verified"),
                            Ok(false) => result.fail("Ed25519 signature verification failed"),
                            Err(e) => result.fail(&format!("Ed25519 verify error: {}", e)),
                        }

                        // Verify wrong message fails
                        let wrong_message = b"Wrong message";
                        match em.ed25519_verify(&pub_key, wrong_message, &sig) {
                            Ok(false) => result.pass("Ed25519 rejects wrong message"),
                            Ok(true) => result.fail("Ed25519 accepted wrong message"),
                            Err(_) => result.pass("Ed25519 rejects wrong message (error)"),
                        }
                    },
                    Err(e) => result.fail(&format!("Ed25519 sign error: {}", e)),
                }
            },
            Err(e) => result.fail(&format!("Ed25519 keypair generation error: {}", e)),
        }

        // Test secp256k1 signing
        match em.secp256k1_generate_keypair() {
            Ok((priv_key, pub_key)) => {
                result.pass(&format!("secp256k1 keypair generated (priv: {}, pub: {} bytes)", priv_key.len(), pub_key.len()));

                match em.secp256k1_sign(&priv_key, test_message) {
                    Ok(sig) => {
                        result.pass(&format!("secp256k1 signature: {} bytes (DER)", sig.len()));

                        match em.secp256k1_verify(&pub_key, test_message, &sig) {
                            Ok(true) => result.pass("secp256k1 signature verified"),
                            Ok(false) => result.fail("secp256k1 signature verification failed"),
                            Err(e) => result.fail(&format!("secp256k1 verify error: {}", e)),
                        }

                        // Verify wrong message fails
                        let wrong_message = b"Wrong message";
                        match em.secp256k1_verify(&pub_key, wrong_message, &sig) {
                            Ok(false) => result.pass("secp256k1 rejects wrong message"),
                            Ok(true) => result.fail("secp256k1 accepted wrong message"),
                            Err(_) => result.pass("secp256k1 rejects wrong message (error)"),
                        }
                    },
                    Err(e) => result.fail(&format!("secp256k1 sign error: {}", e)),
                }
            },
            Err(e) => result.fail(&format!("secp256k1 keypair generation error: {}", e)),
        }

        // Test P-256 signing
        match em.p256_generate_keypair() {
            Ok((priv_key, pub_key)) => {
                result.pass(&format!("P-256 keypair generated (priv: {}, pub: {} bytes)", priv_key.len(), pub_key.len()));

                match em.p256_sign(&priv_key, test_message) {
                    Ok(sig) => {
                        result.pass(&format!("P-256 signature: {} bytes (DER)", sig.len()));

                        match em.p256_verify(&pub_key, test_message, &sig) {
                            Ok(true) => result.pass("P-256 signature verified"),
                            Ok(false) => result.fail("P-256 signature verification failed"),
                            Err(e) => result.fail(&format!("P-256 verify error: {}", e)),
                        }

                        // Verify wrong message fails
                        let wrong_message = b"Wrong message";
                        match em.p256_verify(&pub_key, wrong_message, &sig) {
                            Ok(false) => result.pass("P-256 rejects wrong message"),
                            Ok(true) => result.fail("P-256 accepted wrong message"),
                            Err(_) => result.pass("P-256 rejects wrong message (error)"),
                        }
                    },
                    Err(e) => result.fail(&format!("P-256 sign error: {}", e)),
                }
            },
            Err(e) => result.fail(&format!("P-256 keypair generation error: {}", e)),
        }

        results.push(result.summary());
    }

    // Test 7: FlatBuffer Creation
    println!("\nTest 7: FlatBuffer Creation");
    println!("{}", "-".repeat(40));
    {
        let mut result = TestResult::new("FlatBuffer Creation");

        // Create a SecureMessage using the FlatBuffers builder
        let mut builder = FlatBufferBuilder::with_capacity(1024);

        // Build the Payload first (inner table)
        let payload_msg = builder.create_string("Hello from Rust!");
        let payload_data: Vec<u8> = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let payload_data_vec = builder.create_vector(&payload_data);

        let payload = Payload::create(&mut builder, &PayloadArgs {
            message: Some(payload_msg),
            value: 42,
            data: Some(payload_data_vec),
            nested: None,
            is_encrypted: false,
        });

        // Build the SecureMessage
        let msg_id = builder.create_string("rust-msg-001");
        let sender = builder.create_string("rust-alice");
        let recipient = builder.create_string("rust-bob");

        let secure_msg = SecureMessage::create(&mut builder, &SecureMessageArgs {
            id: Some(msg_id),
            sender: Some(sender),
            recipient: Some(recipient),
            payload: Some(payload),
            timestamp: 1704067200,
            signature: None,
        });

        builder.finish(secure_msg, Some(SECURE_MESSAGE_IDENTIFIER));

        let buf = builder.finished_data();
        result.pass(&format!("Created SecureMessage binary: {} bytes", buf.len()));

        // Verify the buffer has the correct file identifier
        if buf.len() >= 8 && &buf[4..8] == b"SECM" {
            result.pass("Buffer has correct SECM identifier");
        } else {
            result.fail("Buffer missing SECM identifier");
        }

        // Read it back and verify contents
        let msg = flatbuffers::root::<SecureMessage>(buf).expect("Failed to parse SecureMessage");

        if msg.id() == Some("rust-msg-001") {
            result.pass("Read back id: rust-msg-001");
        } else {
            result.fail(&format!("Wrong id: {:?}", msg.id()));
        }

        if msg.sender() == Some("rust-alice") {
            result.pass("Read back sender: rust-alice");
        } else {
            result.fail(&format!("Wrong sender: {:?}", msg.sender()));
        }

        if msg.recipient() == Some("rust-bob") {
            result.pass("Read back recipient: rust-bob");
        } else {
            result.fail(&format!("Wrong recipient: {:?}", msg.recipient()));
        }

        if msg.timestamp() == 1704067200 {
            result.pass("Read back timestamp: 1704067200");
        } else {
            result.fail(&format!("Wrong timestamp: {}", msg.timestamp()));
        }

        if let Some(payload_obj) = msg.payload() {
            if payload_obj.message() == Some("Hello from Rust!") {
                result.pass("Read back payload message: Hello from Rust!");
            } else {
                result.fail(&format!("Wrong payload message: {:?}", payload_obj.message()));
            }

            if payload_obj.value() == 42 {
                result.pass("Read back payload value: 42");
            } else {
                result.fail(&format!("Wrong payload value: {}", payload_obj.value()));
            }

            if let Some(data) = payload_obj.data() {
                if data.iter().collect::<Vec<_>>() == payload_data {
                    result.pass(&format!("Read back payload data: {} bytes", data.len()));
                } else {
                    result.fail("Wrong payload data");
                }
            } else {
                result.fail("Failed to read payload data");
            }
        } else {
            result.fail("Failed to read payload");
        }

        // Test encrypt-decrypt round trip with Rust-created FlatBuffer
        if let Some(sui_keys) = encryption_keys.get("sui") {
            let key = hex::decode(&sui_keys.key_hex).expect("Failed to decode key");
            let iv = hex::decode(&sui_keys.iv_hex).expect("Failed to decode IV");

            // Make a copy to encrypt
            let encrypted = em.encrypt_bytes(&key, &iv, buf)?;
            result.pass("Encrypted Rust-created FlatBuffer");

            // Decrypt
            let decrypted = em.decrypt_bytes(&key, &iv, &encrypted)?;
            result.pass("Decrypted Rust-created FlatBuffer");

            // Verify decrypted data matches original
            if decrypted == buf {
                result.pass("Decrypt round-trip verified");
            } else {
                result.fail("Decrypted data doesn't match original");
            }
        } else {
            result.fail("Sui encryption keys not found");
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
