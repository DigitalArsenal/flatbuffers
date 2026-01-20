//! Demo application for the FlatBuffers WASI encryption module.

use encryption::{EncryptionModule, AES_KEY_SIZE, AES_IV_SIZE};

fn main() {
    println!("FlatBuffers WASI Encryption - Rust/Wasmer");
    println!("{}", "=".repeat(50));

    match EncryptionModule::new() {
        Ok(mut em) => {
            println!("Module version: {}", em.version());
            println!("Crypto++ available: {}", em.has_cryptopp());
            println!();

            // Test encryption
            let key = [0x42u8; AES_KEY_SIZE];
            let iv = [0x24u8; AES_IV_SIZE];
            let plaintext = b"Hello, FlatBuffers WASI encryption from Rust!";

            println!("Plaintext: {}", String::from_utf8_lossy(plaintext));
            println!("Key: {}", hex::encode(&key));
            println!("IV: {}", hex::encode(&iv));

            match em.encrypt_bytes(&key, &iv, plaintext) {
                Ok(encrypted) => {
                    println!("Encrypted: {}", hex::encode(&encrypted));

                    match em.decrypt_bytes(&key, &iv, &encrypted) {
                        Ok(decrypted) => {
                            println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));

                            if decrypted == plaintext {
                                println!("\n✓ Encryption/decryption successful!");
                            } else {
                                println!("\n✗ Decryption mismatch!");
                            }
                        }
                        Err(e) => println!("Decryption error: {}", e),
                    }
                }
                Err(e) => println!("Encryption error: {}", e),
            }

            // Test SHA-256
            println!("\nSHA-256 test:");
            match em.sha256(b"hello") {
                Ok(hash) => {
                    println!("SHA256('hello') = {}", hex::encode(&hash));
                    let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
                    if hex::encode(&hash) == expected {
                        println!("✓ SHA-256 correct!");
                    } else {
                        println!("✗ SHA-256 mismatch!");
                    }
                }
                Err(e) => println!("SHA-256 error: {}", e),
            }
        }
        Err(e) => {
            println!("Error: {}", e);
            println!("\nBuild the WASM module first:");
            println!("  cmake --build build/wasm --target flatc_wasm_wasi");
        }
    }
}
