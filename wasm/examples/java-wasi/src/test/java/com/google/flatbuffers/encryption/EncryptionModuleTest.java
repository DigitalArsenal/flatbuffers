package com.google.flatbuffers.encryption;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class EncryptionModuleTest {

    private EncryptionModule em;

    @BeforeAll
    void setUp() throws Exception {
        try {
            em = new EncryptionModule();
        } catch (Exception e) {
            System.err.println("WASM module not found - build it first");
            throw new org.junit.jupiter.api.Assumptions.assumptionViolation(
                "WASM module not available: " + e.getMessage()
            );
        }
    }

    @Test
    void testVersion() {
        String version = em.version();
        assertNotNull(version);
        assertFalse(version.isEmpty());
        System.out.println("Module version: " + version);
    }

    @Test
    void testHasCryptopp() {
        assertTrue(em.hasCryptopp());
    }

    @Test
    void testEncryptDecrypt() {
        byte[] key = em.randomBytes(32);
        byte[] iv = em.randomBytes(16);
        byte[] plaintext = "Hello, FlatBuffers WASI encryption!".getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = em.encrypt(key, iv, plaintext);
        assertEquals(plaintext.length, encrypted.length);
        assertFalse(Arrays.equals(plaintext, encrypted));

        byte[] decrypted = em.decrypt(key, iv, encrypted);
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void testEncryptEmpty() {
        byte[] key = em.randomBytes(32);
        byte[] iv = em.randomBytes(16);

        byte[] result = em.encrypt(key, iv, new byte[0]);
        assertEquals(0, result.length);
    }

    @Test
    void testEncryptLarge() {
        byte[] key = em.randomBytes(32);
        byte[] iv = em.randomBytes(16);
        byte[] plaintext = em.randomBytes(10000);

        byte[] encrypted = em.encrypt(key, iv, plaintext);
        byte[] decrypted = em.decrypt(key, iv, encrypted);
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void testSha256() {
        byte[] hash = em.sha256("hello".getBytes(StandardCharsets.UTF_8));
        String expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        assertEquals(expected, bytesToHex(hash));
    }

    @Test
    void testSha256Empty() {
        byte[] hash = em.sha256(new byte[0]);
        String expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assertEquals(expected, bytesToHex(hash));
    }

    @Test
    void testX25519KeyExchange() {
        EncryptionModule.KeyPair alice = em.x25519GenerateKeypair();
        EncryptionModule.KeyPair bob = em.x25519GenerateKeypair();

        assertEquals(32, alice.getPrivateKey().length);
        assertEquals(32, alice.getPublicKey().length);

        byte[] aliceSecret = em.x25519SharedSecret(alice.getPrivateKey(), bob.getPublicKey());
        byte[] bobSecret = em.x25519SharedSecret(bob.getPrivateKey(), alice.getPublicKey());

        assertArrayEquals(aliceSecret, bobSecret);
    }

    @Test
    void testSecp256k1KeyExchange() {
        EncryptionModule.KeyPair alice = em.secp256k1GenerateKeypair();
        EncryptionModule.KeyPair bob = em.secp256k1GenerateKeypair();

        assertEquals(32, alice.getPrivateKey().length);
        assertEquals(33, alice.getPublicKey().length);

        byte[] aliceSecret = em.secp256k1SharedSecret(alice.getPrivateKey(), bob.getPublicKey());
        byte[] bobSecret = em.secp256k1SharedSecret(bob.getPrivateKey(), alice.getPublicKey());

        assertArrayEquals(aliceSecret, bobSecret);
    }

    @Test
    void testSecp256k1Signature() {
        EncryptionModule.KeyPair kp = em.secp256k1GenerateKeypair();
        byte[] message = "Hello, Bitcoin!".getBytes(StandardCharsets.UTF_8);

        byte[] signature = em.secp256k1Sign(kp.getPrivateKey(), message);
        assertTrue(signature.length > 0 && signature.length <= 72);

        assertTrue(em.secp256k1Verify(kp.getPublicKey(), message, signature));

        // Wrong message should fail
        byte[] wrongMessage = "Wrong message".getBytes(StandardCharsets.UTF_8);
        assertFalse(em.secp256k1Verify(kp.getPublicKey(), wrongMessage, signature));
    }

    @Test
    void testP256KeyExchange() {
        EncryptionModule.KeyPair alice = em.p256GenerateKeypair();
        EncryptionModule.KeyPair bob = em.p256GenerateKeypair();

        assertEquals(32, alice.getPrivateKey().length);
        assertEquals(33, alice.getPublicKey().length);

        byte[] aliceSecret = em.p256SharedSecret(alice.getPrivateKey(), bob.getPublicKey());
        byte[] bobSecret = em.p256SharedSecret(bob.getPrivateKey(), alice.getPublicKey());

        assertArrayEquals(aliceSecret, bobSecret);
    }

    @Test
    void testP256Signature() {
        EncryptionModule.KeyPair kp = em.p256GenerateKeypair();
        byte[] message = "Hello, NIST!".getBytes(StandardCharsets.UTF_8);

        byte[] signature = em.p256Sign(kp.getPrivateKey(), message);
        assertTrue(signature.length > 0 && signature.length <= 72);

        assertTrue(em.p256Verify(kp.getPublicKey(), message, signature));

        // Wrong message should fail
        byte[] wrongMessage = "Wrong message".getBytes(StandardCharsets.UTF_8);
        assertFalse(em.p256Verify(kp.getPublicKey(), wrongMessage, signature));
    }

    @Test
    void testEd25519Signature() {
        EncryptionModule.KeyPair kp = em.ed25519GenerateKeypair();
        byte[] message = "Hello, Ed25519!".getBytes(StandardCharsets.UTF_8);

        assertEquals(64, kp.getPrivateKey().length);
        assertEquals(32, kp.getPublicKey().length);

        byte[] signature = em.ed25519Sign(kp.getPrivateKey(), message);
        assertEquals(64, signature.length);

        assertTrue(em.ed25519Verify(kp.getPublicKey(), message, signature));

        // Wrong message should fail
        byte[] wrongMessage = "Wrong message".getBytes(StandardCharsets.UTF_8);
        assertFalse(em.ed25519Verify(kp.getPublicKey(), wrongMessage, signature));
    }

    @Test
    void testDeriveSymmetricKey() {
        byte[] sharedSecret = em.randomBytes(32);
        EncryptionModule.DerivedKey dk = em.deriveSymmetricKey(sharedSecret, "encryption");

        assertEquals(32, dk.getKey().length);
        assertEquals(16, dk.getIv().length);

        // Same input should produce same output
        EncryptionModule.DerivedKey dk2 = em.deriveSymmetricKey(sharedSecret, "encryption");
        assertArrayEquals(dk.getKey(), dk2.getKey());
        assertArrayEquals(dk.getIv(), dk2.getIv());

        // Different context should produce different output
        EncryptionModule.DerivedKey dk3 = em.deriveSymmetricKey(sharedSecret, "signing");
        assertFalse(Arrays.equals(dk.getKey(), dk3.getKey()));
    }

    @Test
    void testHkdf() {
        byte[] ikm = "input keying material".getBytes(StandardCharsets.UTF_8);
        byte[] salt = "salt".getBytes(StandardCharsets.UTF_8);
        byte[] info = "info".getBytes(StandardCharsets.UTF_8);

        byte[] derived = em.hkdf(ikm, salt, info, 32);
        assertEquals(32, derived.length);

        // Same input should produce same output
        byte[] derived2 = em.hkdf(ikm, salt, info, 32);
        assertArrayEquals(derived, derived2);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
