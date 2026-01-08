import XCTest
@testable import FlatBuffersEncryption

final class EncryptionTests: XCTestCase {

    var em: EncryptionModule!

    override func setUpWithError() throws {
        do {
            em = try EncryptionModule()
        } catch {
            throw XCTSkip("WASM module not found - build it first")
        }
    }

    func testVersion() throws {
        let version = try em.version()
        XCTAssertFalse(version.isEmpty)
        print("Module version: \(version)")
    }

    func testHasCryptopp() throws {
        XCTAssertTrue(try em.hasCryptopp())
    }

    func testEncryptDecrypt() throws {
        let key = EncryptionModule.randomBytes(32)
        let iv = EncryptionModule.randomBytes(16)
        let plaintext = Array("Hello, FlatBuffers WASI encryption!".utf8)

        let encrypted = try em.encrypt(key: key, iv: iv, plaintext: plaintext)
        XCTAssertEqual(plaintext.count, encrypted.count)
        XCTAssertNotEqual(plaintext, encrypted)

        let decrypted = try em.decrypt(key: key, iv: iv, ciphertext: encrypted)
        XCTAssertEqual(plaintext, decrypted)
    }

    func testEncryptEmpty() throws {
        let key = EncryptionModule.randomBytes(32)
        let iv = EncryptionModule.randomBytes(16)

        let result = try em.encrypt(key: key, iv: iv, plaintext: [])
        XCTAssertEqual(result.count, 0)
    }

    func testEncryptLarge() throws {
        let key = EncryptionModule.randomBytes(32)
        let iv = EncryptionModule.randomBytes(16)
        let plaintext = EncryptionModule.randomBytes(10000)

        let encrypted = try em.encrypt(key: key, iv: iv, plaintext: plaintext)
        let decrypted = try em.decrypt(key: key, iv: iv, ciphertext: encrypted)
        XCTAssertEqual(plaintext, decrypted)
    }

    func testSha256() throws {
        let hash = try em.sha256(Array("hello".utf8))
        let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        XCTAssertEqual(bytesToHex(hash), expected)
    }

    func testSha256Empty() throws {
        let hash = try em.sha256([])
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        XCTAssertEqual(bytesToHex(hash), expected)
    }

    func testX25519KeyExchange() throws {
        let alice = try em.x25519GenerateKeypair()
        let bob = try em.x25519GenerateKeypair()

        XCTAssertEqual(alice.privateKey.count, 32)
        XCTAssertEqual(alice.publicKey.count, 32)

        let aliceSecret = try em.x25519SharedSecret(privateKey: alice.privateKey, publicKey: bob.publicKey)
        let bobSecret = try em.x25519SharedSecret(privateKey: bob.privateKey, publicKey: alice.publicKey)

        XCTAssertEqual(aliceSecret, bobSecret)
    }

    func testSecp256k1KeyExchange() throws {
        let alice = try em.secp256k1GenerateKeypair()
        let bob = try em.secp256k1GenerateKeypair()

        XCTAssertEqual(alice.privateKey.count, 32)
        XCTAssertEqual(alice.publicKey.count, 33)

        let aliceSecret = try em.secp256k1SharedSecret(privateKey: alice.privateKey, publicKey: bob.publicKey)
        let bobSecret = try em.secp256k1SharedSecret(privateKey: bob.privateKey, publicKey: alice.publicKey)

        XCTAssertEqual(aliceSecret, bobSecret)
    }

    func testSecp256k1Signature() throws {
        let kp = try em.secp256k1GenerateKeypair()
        let message = Array("Hello, Bitcoin!".utf8)

        let signature = try em.secp256k1Sign(privateKey: kp.privateKey, message: message)
        XCTAssertTrue(signature.count > 0 && signature.count <= 72)

        XCTAssertTrue(try em.secp256k1Verify(publicKey: kp.publicKey, message: message, signature: signature))

        // Wrong message should fail
        let wrongMessage = Array("Wrong message".utf8)
        XCTAssertFalse(try em.secp256k1Verify(publicKey: kp.publicKey, message: wrongMessage, signature: signature))
    }

    func testP256KeyExchange() throws {
        let alice = try em.p256GenerateKeypair()
        let bob = try em.p256GenerateKeypair()

        XCTAssertEqual(alice.privateKey.count, 32)
        XCTAssertEqual(alice.publicKey.count, 33)

        let aliceSecret = try em.p256SharedSecret(privateKey: alice.privateKey, publicKey: bob.publicKey)
        let bobSecret = try em.p256SharedSecret(privateKey: bob.privateKey, publicKey: alice.publicKey)

        XCTAssertEqual(aliceSecret, bobSecret)
    }

    func testP256Signature() throws {
        let kp = try em.p256GenerateKeypair()
        let message = Array("Hello, NIST!".utf8)

        let signature = try em.p256Sign(privateKey: kp.privateKey, message: message)
        XCTAssertTrue(signature.count > 0 && signature.count <= 72)

        XCTAssertTrue(try em.p256Verify(publicKey: kp.publicKey, message: message, signature: signature))

        // Wrong message should fail
        let wrongMessage = Array("Wrong message".utf8)
        XCTAssertFalse(try em.p256Verify(publicKey: kp.publicKey, message: wrongMessage, signature: signature))
    }

    func testEd25519Signature() throws {
        let kp = try em.ed25519GenerateKeypair()
        let message = Array("Hello, Ed25519!".utf8)

        XCTAssertEqual(kp.privateKey.count, 64)
        XCTAssertEqual(kp.publicKey.count, 32)

        let signature = try em.ed25519Sign(privateKey: kp.privateKey, message: message)
        XCTAssertEqual(signature.count, 64)

        XCTAssertTrue(try em.ed25519Verify(publicKey: kp.publicKey, message: message, signature: signature))

        // Wrong message should fail
        let wrongMessage = Array("Wrong message".utf8)
        XCTAssertFalse(try em.ed25519Verify(publicKey: kp.publicKey, message: wrongMessage, signature: signature))
    }

    func testDeriveSymmetricKey() throws {
        let sharedSecret = EncryptionModule.randomBytes(32)
        let dk = try em.deriveSymmetricKey(sharedSecret: sharedSecret, context: "encryption")

        XCTAssertEqual(dk.key.count, 32)
        XCTAssertEqual(dk.iv.count, 16)

        // Same input should produce same output
        let dk2 = try em.deriveSymmetricKey(sharedSecret: sharedSecret, context: "encryption")
        XCTAssertEqual(dk.key, dk2.key)
        XCTAssertEqual(dk.iv, dk2.iv)

        // Different context should produce different output
        let dk3 = try em.deriveSymmetricKey(sharedSecret: sharedSecret, context: "signing")
        XCTAssertNotEqual(dk.key, dk3.key)
    }

    func testHkdf() throws {
        let ikm = Array("input keying material".utf8)
        let salt = Array("salt".utf8)
        let info = Array("info".utf8)

        let derived = try em.hkdf(ikm: ikm, salt: salt, info: info, length: 32)
        XCTAssertEqual(derived.count, 32)

        // Same input should produce same output
        let derived2 = try em.hkdf(ikm: ikm, salt: salt, info: info, length: 32)
        XCTAssertEqual(derived, derived2)
    }

    private func bytesToHex(_ bytes: [UInt8]) -> String {
        return bytes.map { String(format: "%02x", $0) }.joined()
    }
}
