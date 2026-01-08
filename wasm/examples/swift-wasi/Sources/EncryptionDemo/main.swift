import Foundation
import FlatBuffersEncryption

print("FlatBuffers WASI Encryption - Swift/WasmKit")
print(String(repeating: "=", count: 50))

do {
    let em = try EncryptionModule()

    print("Module version: \(try em.version())")
    print("Crypto++ available: \(try em.hasCryptopp())")
    print()

    // Test AES encryption
    try testAesEncryption(em)

    // Test SHA-256
    try testSha256(em)

    // Test X25519
    try testX25519(em)

    // Test secp256k1
    try testSecp256k1(em)

    // Test P-256
    try testP256(em)

    // Test Ed25519
    try testEd25519(em)

} catch {
    print("Error: \(error)")
    print()
    print("Build the WASM module first:")
    print("  cmake --build build/wasm --target flatc_wasm_wasi")
}

func testAesEncryption(_ em: EncryptionModule) throws {
    print("AES-256-CTR Encryption Test:")
    print(String(repeating: "-", count: 30))

    let key = [UInt8](repeating: 0x42, count: 32)
    let iv = [UInt8](repeating: 0x24, count: 16)

    let plaintext = Array("Hello, FlatBuffers WASI encryption from Swift!".utf8)

    print("Plaintext: \(String(bytes: plaintext, encoding: .utf8)!)")
    print("Key: \(bytesToHex(key))")
    print("IV: \(bytesToHex(iv))")

    let encrypted = try em.encrypt(key: key, iv: iv, plaintext: plaintext)
    print("Encrypted: \(bytesToHex(encrypted))")

    let decrypted = try em.decrypt(key: key, iv: iv, ciphertext: encrypted)
    print("Decrypted: \(String(bytes: decrypted, encoding: .utf8)!)")

    if plaintext == decrypted {
        print("OK Encryption/decryption successful!")
    } else {
        print("FAIL Decryption mismatch!")
    }
    print()
}

func testSha256(_ em: EncryptionModule) throws {
    print("SHA-256 Test:")
    print(String(repeating: "-", count: 30))

    let hash = try em.sha256(Array("hello".utf8))
    let hashHex = bytesToHex(hash)
    let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    print("SHA256('hello') = \(hashHex)")

    if hashHex == expected {
        print("OK SHA-256 correct!")
    } else {
        print("FAIL SHA-256 mismatch!")
        print("Expected: \(expected)")
    }
    print()
}

func testX25519(_ em: EncryptionModule) throws {
    print("X25519 ECDH Test:")
    print(String(repeating: "-", count: 30))

    let alice = try em.x25519GenerateKeypair()
    let bob = try em.x25519GenerateKeypair()

    print("Alice public key: \(bytesToHex(alice.publicKey))")
    print("Bob public key: \(bytesToHex(bob.publicKey))")

    let aliceSecret = try em.x25519SharedSecret(privateKey: alice.privateKey, publicKey: bob.publicKey)
    let bobSecret = try em.x25519SharedSecret(privateKey: bob.privateKey, publicKey: alice.publicKey)

    print("Alice's shared secret: \(bytesToHex(aliceSecret))")
    print("Bob's shared secret: \(bytesToHex(bobSecret))")

    if aliceSecret == bobSecret {
        print("OK X25519 key exchange successful!")
    } else {
        print("FAIL Shared secrets don't match!")
    }
    print()
}

func testSecp256k1(_ em: EncryptionModule) throws {
    print("secp256k1 ECDH + ECDSA Test:")
    print(String(repeating: "-", count: 30))

    let kp = try em.secp256k1GenerateKeypair()
    print("Public key: \(bytesToHex(kp.publicKey))")

    let message = Array("Hello, Bitcoin!".utf8)
    let signature = try em.secp256k1Sign(privateKey: kp.privateKey, message: message)
    print("Signature: \(bytesToHex(signature))")

    if try em.secp256k1Verify(publicKey: kp.publicKey, message: message, signature: signature) {
        print("OK secp256k1 signature verified!")
    } else {
        print("FAIL secp256k1 signature verification failed!")
    }

    let wrongMessage = Array("Wrong message".utf8)
    if try !em.secp256k1Verify(publicKey: kp.publicKey, message: wrongMessage, signature: signature) {
        print("OK Wrong message correctly rejected!")
    } else {
        print("FAIL Wrong message was accepted!")
    }
    print()
}

func testP256(_ em: EncryptionModule) throws {
    print("P-256 ECDH + ECDSA Test:")
    print(String(repeating: "-", count: 30))

    let kp = try em.p256GenerateKeypair()
    print("Public key: \(bytesToHex(kp.publicKey))")

    let message = Array("Hello, NIST!".utf8)
    let signature = try em.p256Sign(privateKey: kp.privateKey, message: message)
    print("Signature: \(bytesToHex(signature))")

    if try em.p256Verify(publicKey: kp.publicKey, message: message, signature: signature) {
        print("OK P-256 signature verified!")
    } else {
        print("FAIL P-256 signature verification failed!")
    }
    print()
}

func testEd25519(_ em: EncryptionModule) throws {
    print("Ed25519 Signature Test:")
    print(String(repeating: "-", count: 30))

    let kp = try em.ed25519GenerateKeypair()
    print("Public key: \(bytesToHex(kp.publicKey))")

    let message = Array("Hello, Ed25519!".utf8)
    let signature = try em.ed25519Sign(privateKey: kp.privateKey, message: message)
    print("Signature: \(bytesToHex(signature))")

    if try em.ed25519Verify(publicKey: kp.publicKey, message: message, signature: signature) {
        print("OK Ed25519 signature verified!")
    } else {
        print("FAIL Ed25519 signature verification failed!")
    }
    print()
}

func bytesToHex(_ bytes: [UInt8]) -> String {
    return bytes.map { String(format: "%02x", $0) }.joined()
}
