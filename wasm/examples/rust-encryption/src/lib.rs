//! FlatBuffers field-level encryption for Rust.
//!
//! This crate implements the same encryption algorithm as the JavaScript
//! flatc-wasm module, ensuring 100% cross-language compatibility.
//!
//! Data encrypted in Rust can be decrypted in JavaScript/Node.js/Python/Go
//! and vice versa.
//!
//! # Example
//!
//! ```rust,ignore
//! use flatc_wasm_encryption::{EncryptionContext, encrypt_buffer, decrypt_buffer};
//!
//! let schema = r#"
//! table Message {
//!   public_text: string;
//!   secret_number: int (encrypted);
//! }
//! root_type Message;
//! "#;
//!
//! let buffer: Vec<u8> = create_flatbuffer(); // Your flatbuffer data
//! let key: [u8; 32] = rand::random(); // Use a real random key!
//!
//! let encrypted = encrypt_buffer(&buffer, schema, &key, "Message").unwrap();
//! let decrypted = decrypt_buffer(&encrypted, schema, &key, "Message").unwrap();
//! ```

use regex::Regex;
use std::error::Error;
use std::fmt;

/// AES S-box for encryption
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16,
];

/// AES round constants
const RCON: [u8; 11] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// Encryption error type
#[derive(Debug)]
pub struct EncryptionError {
    message: String,
}

impl fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for EncryptionError {}

impl EncryptionError {
    fn new(msg: &str) -> Self {
        EncryptionError {
            message: msg.to_string(),
        }
    }
}

/// GF(2^8) multiplication
fn gf_mul(a: u8, b: u8) -> u8 {
    let mut a = a;
    let mut b = b;
    let mut p: u8 = 0;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi_bit = a & 0x80;
        a <<= 1;
        if hi_bit != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

/// Expand AES-256 key to round keys
fn aes256_key_expansion(key: &[u8]) -> Vec<u8> {
    let mut round_keys = vec![0u8; 240];
    round_keys[..32].copy_from_slice(key);

    let mut temp = [0u8; 4];
    let mut i = 8;

    while i < 60 {
        temp.copy_from_slice(&round_keys[(i - 1) * 4..i * 4]);

        if i % 8 == 0 {
            // RotWord + SubWord + Rcon
            let t = temp[0];
            temp[0] = SBOX[temp[1] as usize] ^ RCON[i / 8];
            temp[1] = SBOX[temp[2] as usize];
            temp[2] = SBOX[temp[3] as usize];
            temp[3] = SBOX[t as usize];
        } else if i % 8 == 4 {
            temp[0] = SBOX[temp[0] as usize];
            temp[1] = SBOX[temp[1] as usize];
            temp[2] = SBOX[temp[2] as usize];
            temp[3] = SBOX[temp[3] as usize];
        }

        for j in 0..4 {
            round_keys[i * 4 + j] = round_keys[(i - 8) * 4 + j] ^ temp[j];
        }
        i += 1;
    }

    round_keys
}

/// AES SubBytes transformation
fn sub_bytes(state: &mut [u8; 16]) {
    for i in 0..16 {
        state[i] = SBOX[state[i] as usize];
    }
}

/// AES ShiftRows transformation
fn shift_rows(state: &mut [u8; 16]) {
    // Row 1: shift left by 1
    let temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;
    // Row 2: shift left by 2
    let temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    let temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    // Row 3: shift left by 3
    let temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
}

/// AES MixColumns transformation
fn mix_columns(state: &mut [u8; 16]) {
    for i in 0..4 {
        let a = [state[i * 4], state[i * 4 + 1], state[i * 4 + 2], state[i * 4 + 3]];
        state[i * 4 + 0] = gf_mul(a[0], 2) ^ gf_mul(a[1], 3) ^ a[2] ^ a[3];
        state[i * 4 + 1] = a[0] ^ gf_mul(a[1], 2) ^ gf_mul(a[2], 3) ^ a[3];
        state[i * 4 + 2] = a[0] ^ a[1] ^ gf_mul(a[2], 2) ^ gf_mul(a[3], 3);
        state[i * 4 + 3] = gf_mul(a[0], 3) ^ a[1] ^ a[2] ^ gf_mul(a[3], 2);
    }
}

/// AES AddRoundKey transformation
fn add_round_key(state: &mut [u8; 16], round_key: &[u8]) {
    for i in 0..16 {
        state[i] ^= round_key[i];
    }
}

/// AES-256 encrypt a single 16-byte block
fn aes_encrypt_block(key: &[u8], input: &[u8]) -> [u8; 16] {
    let round_keys = aes256_key_expansion(key);
    let mut state = [0u8; 16];
    state.copy_from_slice(input);

    add_round_key(&mut state, &round_keys[..16]);

    for round in 1..14 {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, &round_keys[round * 16..(round + 1) * 16]);
    }

    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, &round_keys[14 * 16..15 * 16]);

    state
}

/// Generate AES-CTR keystream
fn aes_ctr_keystream(key: &[u8], nonce: &[u8], length: usize) -> Vec<u8> {
    let mut keystream = vec![0u8; length];
    let mut counter = [0u8; 16];
    counter.copy_from_slice(nonce);

    let mut offset = 0;
    while offset < length {
        let block = aes_encrypt_block(key, &counter);
        let to_copy = std::cmp::min(16, length - offset);
        keystream[offset..offset + to_copy].copy_from_slice(&block[..to_copy]);
        offset += to_copy;

        // Increment counter (big-endian)
        for i in (0..16).rev() {
            counter[i] = counter[i].wrapping_add(1);
            if counter[i] != 0 {
                break;
            }
        }
    }

    keystream
}

/// HKDF-like key derivation (matches JavaScript)
fn derive_key(master_key: &[u8], info: &[u8], out_length: usize) -> Vec<u8> {
    let mut out = vec![0u8; out_length];

    // Mix master key into output
    let copy_len = std::cmp::min(out_length, master_key.len());
    out[..copy_len].copy_from_slice(&master_key[..copy_len]);

    // Mix info using a simple hash-like operation
    let mut hash: u8 = 0;
    for &b in info {
        hash ^= b;
        hash = (hash << 1) | (hash >> 7);
    }

    // Apply info hash to derive different keys
    for i in 0..out_length {
        out[i] ^= hash;
        hash = ((hash as u32 * 31 + i as u32) & 0xff) as u8;
    }

    // Additional mixing pass using AES
    if out_length >= 16 {
        let temp = aes_encrypt_block(master_key, &out[..16]);
        let mix_len = std::cmp::min(out_length, 16);
        out[..mix_len].copy_from_slice(&temp[..mix_len]);
        if out_length > 16 {
            let temp2 = aes_encrypt_block(master_key, &temp);
            let remain_len = std::cmp::min(out_length - 16, 16);
            out[16..16 + remain_len].copy_from_slice(&temp2[..remain_len]);
        }
    }

    out
}

/// Encryption context for FlatBuffer field encryption
#[derive(Clone)]
pub struct EncryptionContext {
    key: Vec<u8>,
    valid: bool,
}

impl EncryptionContext {
    /// Create a new EncryptionContext from a 32-byte key
    pub fn new(key: &[u8]) -> Self {
        EncryptionContext {
            key: key.to_vec(),
            valid: key.len() == 32,
        }
    }

    /// Create an EncryptionContext from a hex string
    pub fn from_hex(hex_key: &str) -> Result<Self, EncryptionError> {
        let key = hex::decode(hex_key)
            .map_err(|_| EncryptionError::new("invalid hex string"))?;
        Ok(EncryptionContext::new(&key))
    }

    /// Check if the context has a valid key
    pub fn is_valid(&self) -> bool {
        self.valid
    }

    /// Derive a field-specific 32-byte key
    pub fn derive_field_key(&self, field_id: usize) -> [u8; 32] {
        let mut info = [0u8; 19];
        info[..17].copy_from_slice(b"flatbuffers-field");
        info[17] = ((field_id >> 8) & 0xff) as u8;
        info[18] = (field_id & 0xff) as u8;
        let derived = derive_key(&self.key, &info, 32);
        let mut result = [0u8; 32];
        result.copy_from_slice(&derived);
        result
    }

    /// Derive a field-specific 16-byte IV
    pub fn derive_field_iv(&self, field_id: usize) -> [u8; 16] {
        let mut info = [0u8; 16];
        info[..14].copy_from_slice(b"flatbuffers-iv");
        info[14] = ((field_id >> 8) & 0xff) as u8;
        info[15] = (field_id & 0xff) as u8;
        let derived = derive_key(&self.key, &info, 16);
        let mut result = [0u8; 16];
        result.copy_from_slice(&derived);
        result
    }
}

/// Encrypt bytes in-place using AES-CTR
pub fn encrypt_bytes(data: &mut [u8], key: &[u8], iv: &[u8]) {
    let keystream = aes_ctr_keystream(key, iv, data.len());
    for i in 0..data.len() {
        data[i] ^= keystream[i];
    }
}

/// Decrypt bytes in-place (same as encrypt for AES-CTR)
pub fn decrypt_bytes(data: &mut [u8], key: &[u8], iv: &[u8]) {
    encrypt_bytes(data, key, iv);
}

/// Field information from parsed schema
#[derive(Debug, Clone)]
pub struct FieldInfo {
    pub name: String,
    pub id: usize,
    pub field_type: String,
    pub encrypted: bool,
    pub element_type: Option<String>,
    pub element_size: usize,
    pub struct_size: usize,
}

/// Get the size of a scalar type
fn get_type_size(type_name: &str) -> usize {
    match type_name {
        "bool" | "byte" | "ubyte" => 1,
        "short" | "ushort" => 2,
        "int" | "uint" | "float" => 4,
        "long" | "ulong" | "double" => 8,
        _ => 0,
    }
}

/// Get the base type category
fn get_base_type(type_name: &str) -> String {
    match type_name {
        "bool" | "byte" | "ubyte" | "short" | "ushort" |
        "int" | "uint" | "long" | "ulong" | "float" | "double" => type_name.to_string(),
        "string" => "string".to_string(),
        _ => "struct".to_string(),
    }
}

/// Parse schema to extract field encryption info
pub fn parse_schema_for_encryption(schema_content: &str, root_type: &str) -> Vec<FieldInfo> {
    let mut fields = Vec::new();

    // Find the root table definition
    let pattern = format!(r"table\s+{}\s*\{{([^}}]+)\}}", regex::escape(root_type));
    let re = Regex::new(&pattern).unwrap();

    let table_body = match re.captures(schema_content) {
        Some(caps) => caps.get(1).unwrap().as_str(),
        None => return fields,
    };

    let field_re = Regex::new(r"(\w+)\s*:\s*(\[?\w+\]?)\s*(?:\(([^)]*)\))?").unwrap();

    for (field_id, caps) in field_re.captures_iter(table_body).enumerate() {
        let name = caps.get(1).unwrap().as_str().to_string();
        let field_type_str = caps.get(2).unwrap().as_str();
        let attributes = caps.get(3).map(|m| m.as_str()).unwrap_or("");

        let is_encrypted = attributes.contains("encrypted");
        let is_vector = field_type_str.starts_with('[') && field_type_str.ends_with(']');
        let base_type = if is_vector {
            &field_type_str[1..field_type_str.len() - 1]
        } else {
            field_type_str
        };

        let mut field = FieldInfo {
            name,
            id: field_id,
            field_type: if is_vector { "vector".to_string() } else { get_base_type(base_type) },
            encrypted: is_encrypted,
            element_type: None,
            element_size: 0,
            struct_size: 0,
        };

        if is_vector {
            field.element_type = Some(get_base_type(base_type));
            field.element_size = get_type_size(base_type);
        }

        fields.push(field);
    }

    fields
}

/// Encrypt a region of the buffer in-place
fn encrypt_region(buffer: &mut [u8], start: usize, length: usize, key: &[u8], iv: &[u8]) {
    let keystream = aes_ctr_keystream(key, iv, length);
    for i in 0..length {
        buffer[start + i] ^= keystream[i];
    }
}

/// Read a little-endian u32 from buffer
fn read_u32(buffer: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ])
}

/// Read a little-endian i32 from buffer
fn read_i32(buffer: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ])
}

/// Read a little-endian u16 from buffer
fn read_u16(buffer: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([buffer[offset], buffer[offset + 1]])
}

/// Process a FlatBuffer table, encrypting marked fields
fn process_table(buffer: &mut [u8], table_offset: usize, fields: &[FieldInfo], ctx: &EncryptionContext) {
    // Read vtable offset (signed, relative)
    let vtable_offset_delta = read_i32(buffer, table_offset);
    let vtable_offset = (table_offset as i32 - vtable_offset_delta) as usize;

    // Read vtable size
    let vtable_size = read_u16(buffer, vtable_offset) as usize;

    for field in fields {
        let field_vtable_idx = (field.id + 2) * 2;

        if field_vtable_idx >= vtable_size {
            continue;
        }

        let field_offset = read_u16(buffer, vtable_offset + field_vtable_idx) as usize;
        if field_offset == 0 {
            continue;
        }

        let field_loc = table_offset + field_offset;

        if !field.encrypted {
            continue;
        }

        // Derive keys for this field
        let key = ctx.derive_field_key(field.id);
        let iv = ctx.derive_field_iv(field.id);

        // Encrypt based on type
        match field.field_type.as_str() {
            "bool" | "byte" | "ubyte" => {
                encrypt_region(buffer, field_loc, 1, &key, &iv);
            }
            "short" | "ushort" => {
                encrypt_region(buffer, field_loc, 2, &key, &iv);
            }
            "int" | "uint" | "float" => {
                encrypt_region(buffer, field_loc, 4, &key, &iv);
            }
            "long" | "ulong" | "double" => {
                encrypt_region(buffer, field_loc, 8, &key, &iv);
            }
            "string" => {
                let string_offset = read_u32(buffer, field_loc) as usize;
                let string_loc = field_loc + string_offset;
                let string_len = read_u32(buffer, string_loc) as usize;
                let string_data = string_loc + 4;
                if string_data + string_len <= buffer.len() {
                    encrypt_region(buffer, string_data, string_len, &key, &iv);
                }
            }
            "vector" => {
                let vec_offset = read_u32(buffer, field_loc) as usize;
                let vec_loc = field_loc + vec_offset;
                let vec_len = read_u32(buffer, vec_loc) as usize;
                let vec_data = vec_loc + 4;
                let elem_size = if field.element_size > 0 { field.element_size } else { 1 };
                let total_size = vec_len * elem_size;
                if vec_data + total_size <= buffer.len() {
                    encrypt_region(buffer, vec_data, total_size, &key, &iv);
                }
            }
            "struct" => {
                if field.struct_size > 0 && field_loc + field.struct_size <= buffer.len() {
                    encrypt_region(buffer, field_loc, field.struct_size, &key, &iv);
                }
            }
            _ => {}
        }
    }
}

/// Encrypt a FlatBuffer
pub fn encrypt_buffer(
    buffer: &[u8],
    schema_content: &str,
    key: &[u8],
    root_type: &str,
) -> Result<Vec<u8>, EncryptionError> {
    let ctx = EncryptionContext::new(key);
    encrypt_buffer_with_context(buffer, schema_content, &ctx, root_type)
}

/// Encrypt a FlatBuffer using an existing context
pub fn encrypt_buffer_with_context(
    buffer: &[u8],
    schema_content: &str,
    ctx: &EncryptionContext,
    root_type: &str,
) -> Result<Vec<u8>, EncryptionError> {
    if !ctx.is_valid() {
        return Err(EncryptionError::new("invalid encryption key (must be 32 bytes)"));
    }

    let fields = parse_schema_for_encryption(schema_content, root_type);
    let mut result = buffer.to_vec();

    // Read root table offset
    let root_offset = read_u32(&result, 0) as usize;

    process_table(&mut result, root_offset, &fields, ctx);

    Ok(result)
}

/// Decrypt a FlatBuffer (same as encrypt for AES-CTR)
pub fn decrypt_buffer(
    buffer: &[u8],
    schema_content: &str,
    key: &[u8],
    root_type: &str,
) -> Result<Vec<u8>, EncryptionError> {
    encrypt_buffer(buffer, schema_content, key, root_type)
}

/// Decrypt a FlatBuffer using an existing context
pub fn decrypt_buffer_with_context(
    buffer: &[u8],
    schema_content: &str,
    ctx: &EncryptionContext,
    root_type: &str,
) -> Result<Vec<u8>, EncryptionError> {
    encrypt_buffer_with_context(buffer, schema_content, ctx, root_type)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    const SIMPLE_SCHEMA: &str = r#"
table SimpleMessage {
  public_text: string;
  secret_number: int (encrypted);
  secret_text: string (encrypted);
}
root_type SimpleMessage;
"#;

    fn create_simple_flatbuffer() -> Vec<u8> {
        let mut buf = vec![0u8; 64];

        // Root offset points to table at offset 16
        buf[0..4].copy_from_slice(&16u32.to_le_bytes());

        // VTable at offset 4
        buf[4..6].copy_from_slice(&10u16.to_le_bytes());  // vtable size
        buf[6..8].copy_from_slice(&12u16.to_le_bytes());  // table size
        buf[8..10].copy_from_slice(&4u16.to_le_bytes());  // field 0 offset
        buf[10..12].copy_from_slice(&8u16.to_le_bytes()); // field 1 offset
        buf[12..14].copy_from_slice(&0u16.to_le_bytes()); // field 2 not present

        // Table at offset 16: soffset to vtable
        buf[16..20].copy_from_slice(&12u32.to_le_bytes()); // 16 - 4 = 12

        // Field 0 (string offset) at table+4 = offset 20
        buf[20..24].copy_from_slice(&12u32.to_le_bytes()); // points to string at 32

        // Field 1 (int32) at table+8 = offset 24
        buf[24..28].copy_from_slice(&42u32.to_le_bytes()); // secret_number = 42

        // String at offset 32
        buf[32..36].copy_from_slice(&5u32.to_le_bytes()); // length
        buf[36..41].copy_from_slice(b"hello");

        buf
    }

    #[test]
    fn test_encryption_context_from_bytes() {
        let key: [u8; 32] = rand::random();
        let ctx = EncryptionContext::new(&key);
        assert!(ctx.is_valid());
    }

    #[test]
    fn test_encryption_context_invalid_size() {
        let key = [0u8; 16];
        let ctx = EncryptionContext::new(&key);
        assert!(!ctx.is_valid());
    }

    #[test]
    fn test_derive_different_keys() {
        let key: [u8; 32] = rand::random();
        let ctx = EncryptionContext::new(&key);
        let key1 = ctx.derive_field_key(1);
        let key2 = ctx.derive_field_key(2);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_encrypt_decrypt_bytes() {
        let key: [u8; 32] = rand::random();
        let iv: [u8; 16] = rand::random();
        let original = b"Hello, World!".to_vec();
        let mut data = original.clone();

        encrypt_bytes(&mut data, &key, &iv);
        assert_ne!(data, original);

        decrypt_bytes(&mut data, &key, &iv);
        assert_eq!(data, original);
    }

    #[test]
    fn test_encrypt_buffer_changes_data() {
        let buf = create_simple_flatbuffer();
        let key: [u8; 32] = rand::random();

        let encrypted = encrypt_buffer(&buf, SIMPLE_SCHEMA, &key, "SimpleMessage").unwrap();
        assert_ne!(encrypted, buf);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let buf = create_simple_flatbuffer();
        let key: [u8; 32] = rand::random();

        let encrypted = encrypt_buffer(&buf, SIMPLE_SCHEMA, &key, "SimpleMessage").unwrap();
        let decrypted = decrypt_buffer(&encrypted, SIMPLE_SCHEMA, &key, "SimpleMessage").unwrap();

        assert_eq!(decrypted, buf);
    }

    #[test]
    fn test_different_keys_different_ciphertext() {
        let buf = create_simple_flatbuffer();
        let key1: [u8; 32] = rand::random();
        let key2: [u8; 32] = rand::random();

        let encrypted1 = encrypt_buffer(&buf, SIMPLE_SCHEMA, &key1, "SimpleMessage").unwrap();
        let encrypted2 = encrypt_buffer(&buf, SIMPLE_SCHEMA, &key2, "SimpleMessage").unwrap();

        assert_ne!(encrypted1, encrypted2);
    }

    #[test]
    fn test_encryption_is_deterministic() {
        let buf = create_simple_flatbuffer();
        let key: [u8; 32] = rand::random();
        let ctx = EncryptionContext::new(&key);

        let enc1 = encrypt_buffer_with_context(&buf, SIMPLE_SCHEMA, &ctx, "SimpleMessage").unwrap();
        let enc2 = encrypt_buffer_with_context(&buf, SIMPLE_SCHEMA, &ctx, "SimpleMessage").unwrap();

        assert_eq!(enc1, enc2);
    }

    #[test]
    fn test_invalid_key_returns_error() {
        let buf = create_simple_flatbuffer();
        let key = [0u8; 16]; // Invalid size

        let result = encrypt_buffer(&buf, SIMPLE_SCHEMA, &key, "SimpleMessage");
        assert!(result.is_err());
    }
}
