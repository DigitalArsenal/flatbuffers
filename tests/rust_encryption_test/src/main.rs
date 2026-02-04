//! Rust FlatBuffers Encryption Test
//! Tests that encrypted fields can be correctly decrypted using the generated code.

mod encryption_test_generated;

use encryption_test_generated::encryption_test::*;
use encryption_test_generated::flatbuffers_encryption;

// AES S-box for encryption
const SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];
const RCON: [u8; 10] = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36];

fn xtime(x: u8) -> u8 { ((x << 1) ^ (if x & 0x80 != 0 { 0x1b } else { 0 })) }

fn expand_key(key: &[u8]) -> [u8; 240] {
    let mut expanded = [0u8; 240];
    expanded[..32].copy_from_slice(&key[..32]);
    let mut rcon_idx = 0usize;
    let mut i = 32;
    while i < 240 {
        let mut t = [expanded[i-4], expanded[i-3], expanded[i-2], expanded[i-1]];
        if i % 32 == 0 {
            t = [SBOX[t[1] as usize] ^ RCON[rcon_idx], SBOX[t[2] as usize], SBOX[t[3] as usize], SBOX[t[0] as usize]];
            rcon_idx += 1;
        } else if i % 32 == 16 {
            t = [SBOX[t[0] as usize], SBOX[t[1] as usize], SBOX[t[2] as usize], SBOX[t[3] as usize]];
        }
        for j in 0..4 { expanded[i + j] = expanded[i - 32 + j] ^ t[j]; }
        i += 4;
    }
    expanded
}

fn aes_encrypt_block(block: &[u8; 16], expanded_key: &[u8; 240]) -> [u8; 16] {
    let mut state = *block;
    for i in 0..16 { state[i] ^= expanded_key[i]; }
    for round in 1..=14 {
        for i in 0..16 { state[i] = SBOX[state[i] as usize]; }
        let t1 = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t1;
        let t2 = state[2]; state[2] = state[10]; state[10] = t2;
        let t6 = state[6]; state[6] = state[14]; state[14] = t6;
        let t3 = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t3;
        if round < 14 {
            for c in 0..4 {
                let i = c * 4;
                let (s0, s1, s2, s3) = (state[i], state[i+1], state[i+2], state[i+3]);
                let x = s0 ^ s1 ^ s2 ^ s3;
                state[i] ^= x ^ xtime(s0 ^ s1);
                state[i+1] ^= x ^ xtime(s1 ^ s2);
                state[i+2] ^= x ^ xtime(s2 ^ s3);
                state[i+3] ^= x ^ xtime(s3 ^ s0);
            }
        }
        let offset = round * 16;
        for i in 0..16 { state[i] ^= expanded_key[offset + i]; }
    }
    state
}

fn increment_counter(counter: &mut [u8; 16]) {
    for i in (0..16).rev() {
        counter[i] = counter[i].wrapping_add(1);
        if counter[i] != 0 { break; }
    }
}

fn derive_nonce(ctx: &[u8], field_offset: u16) -> [u8; 16] {
    let mut nonce = [0u8; 16];
    nonce[..12].copy_from_slice(&ctx[..12]);
    nonce[12..16].copy_from_slice(&(field_offset as u32).to_le_bytes());
    nonce
}

fn encrypt_bytes(data: &[u8], ctx: &[u8], field_offset: u16) -> Vec<u8> {
    let key: [u8; 32] = ctx[..32].try_into().unwrap();
    let mut counter = derive_nonce(ctx, field_offset);
    let expanded_key = expand_key(&key);
    let mut result = vec![0u8; data.len()];
    let mut i = 0;
    while i < data.len() {
        let keystream = aes_encrypt_block(&counter, &expanded_key);
        let block_len = core::cmp::min(16, data.len() - i);
        for j in 0..block_len { result[i + j] = data[i + j] ^ keystream[j]; }
        increment_counter(&mut counter);
        i += 16;
    }
    result
}

fn encrypt_f32(value: f32, ctx: &[u8], field_offset: u16) -> f32 {
    let bytes = value.to_le_bytes();
    let encrypted = encrypt_bytes(&bytes, ctx, field_offset);
    f32::from_le_bytes(encrypted.try_into().unwrap())
}

fn encrypt_string(value: &str, ctx: &[u8], field_offset: u16) -> Vec<u8> {
    encrypt_bytes(value.as_bytes(), ctx, field_offset)
}

fn test_sensor_reading() {
    println!("Testing SensorReading with encrypted fields...");

    // Create encryption context (48 bytes)
    let encryption_ctx: Vec<u8> = (0..48u8).collect();

    // Original values
    let original_device_id = "sensor-001";
    let original_timestamp = 1234567890u64;
    let original_temperature = 23.5f32;
    let original_secret_message = "Hello, World!";

    // Field offsets (from generated code)
    let temperature_offset = SensorReading::VT_TEMPERATURE;
    let secret_message_offset = SensorReading::VT_SECRET_MESSAGE;

    // Encrypt values
    let encrypted_temperature = encrypt_f32(original_temperature, &encryption_ctx, temperature_offset);
    let encrypted_secret_message = encrypt_string(original_secret_message, &encryption_ctx, secret_message_offset);

    // Build the FlatBuffer
    let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(256);

    let device_id_offset = builder.create_string(original_device_id);
    // For encrypted string, we store it as raw bytes but in the string field
    // We need to create a string from the encrypted bytes
    let encrypted_secret_str = unsafe { std::str::from_utf8_unchecked(&encrypted_secret_message) };
    let secret_message_vector_offset = builder.create_string(encrypted_secret_str);

    let args = SensorReadingArgs {
        device_id: Some(device_id_offset),
        timestamp: original_timestamp,
        public_data: None,
        location: None,
        temperature: encrypted_temperature,
        raw_data: None,
        secret_message: Some(secret_message_vector_offset),
        readings: None,
    };

    let sensor_reading_offset = SensorReading::create(&mut builder, &args);
    builder.finish(sensor_reading_offset, None);
    let buf = builder.finished_data();

    // Read back using generated code with encryption context
    // The root offset is at position 0, pointing to where the root table starts
    let sensor_reading = unsafe {
        let root_offset = flatbuffers::read_scalar_at::<u32>(buf, 0) as usize;
        let table = flatbuffers::Table::new(buf, root_offset);
        SensorReading::init_from_table_with_ctx(table, Some(encryption_ctx.clone()))
    };

    // Verify public fields
    assert_eq!(sensor_reading.device_id(), Some(original_device_id));
    assert_eq!(sensor_reading.timestamp(), original_timestamp);

    // Verify encrypted fields are correctly decrypted
    let decrypted_temperature = sensor_reading.temperature();
    assert!((decrypted_temperature - original_temperature).abs() < 0.001,
            "Temperature mismatch: {} != {}", decrypted_temperature, original_temperature);

    if let Some(decrypted_secret_message) = sensor_reading.secret_message() {
        assert_eq!(decrypted_secret_message, original_secret_message,
                   "Secret message mismatch: {} != {}", decrypted_secret_message, original_secret_message);
    } else {
        panic!("Secret message is None");
    }

    println!("  Device ID: OK");
    println!("  Timestamp: OK");
    println!("  Temperature (encrypted): OK");
    println!("  Secret Message (encrypted): OK");
    println!("SensorReading test passed!");
}

fn test_without_encryption_context() {
    println!("\nTesting reading without encryption context...");

    let encryption_ctx: Vec<u8> = (0..48u8).collect();
    let original_temperature = 23.5f32;
    let temperature_offset = SensorReading::VT_TEMPERATURE;
    let encrypted_temperature = encrypt_f32(original_temperature, &encryption_ctx, temperature_offset);

    let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(64);
    let device_id_offset = builder.create_string("test");

    let args = SensorReadingArgs {
        device_id: Some(device_id_offset),
        timestamp: 0,
        public_data: None,
        location: None,
        temperature: encrypted_temperature,
        raw_data: None,
        secret_message: None,
        readings: None,
    };

    let sensor_reading_offset = SensorReading::create(&mut builder, &args);
    builder.finish(sensor_reading_offset, None);
    let buf = builder.finished_data();

    // Read without encryption context
    let sensor_reading = unsafe {
        let root_offset = flatbuffers::read_scalar_at::<u32>(buf, 0) as usize;
        let table = flatbuffers::Table::new(buf, root_offset);
        SensorReading::init_from_table(table)
    };

    // Temperature should be returned as-is (encrypted) when no context
    let read_temp = sensor_reading.temperature();
    assert!((read_temp - encrypted_temperature).abs() < 0.001,
            "Expected encrypted value {}, got {}", encrypted_temperature, read_temp);

    println!("  Reading without context returns raw values: OK");
    println!("No encryption context test passed!");
}

fn main() {
    println!("{}", "=".repeat(60));
    println!("Rust FlatBuffers Encryption Test");
    println!("{}", "=".repeat(60));

    test_sensor_reading();
    test_without_encryption_context();

    println!("\n{}", "=".repeat(60));
    println!("All tests passed!");
    println!("{}", "=".repeat(60));
}
