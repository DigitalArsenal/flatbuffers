package com.google.flatbuffers.encryption;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Demo application for the FlatBuffers WASI encryption module.
 */
public class EncryptionDemo {

    public static void main(String[] args) {
        System.out.println("FlatBuffers WASI Encryption - Java/Chicory");
        System.out.println("=".repeat(50));

        try (EncryptionModule em = new EncryptionModule()) {
            System.out.println("Module version: " + em.version());
            System.out.println("Crypto++ available: " + em.hasCryptopp());
            System.out.println();

            // Test AES encryption
            testAesEncryption(em);

            // Test SHA-256
            testSha256(em);

            // Test X25519
            testX25519(em);

            // Test secp256k1
            testSecp256k1(em);

            // Test P-256
            testP256(em);

            // Test Ed25519
            testEd25519(em);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.out.println();
            System.out.println("Build the WASM module first:");
            System.out.println("  cmake --build build/wasm --target flatc_wasm_wasi");
        }
    }

    private static void testAesEncryption(EncryptionModule em) {
        System.out.println("AES-256-CTR Encryption Test:");
        System.out.println("-".repeat(30));

        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 0x42);
        byte[] iv = new byte[16];
        Arrays.fill(iv, (byte) 0x24);

        String plaintext = "Hello, FlatBuffers WASI encryption from Java!";
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);

        System.out.println("Plaintext: " + plaintext);
        System.out.println("Key: " + bytesToHex(key));
        System.out.println("IV: " + bytesToHex(iv));

        byte[] encrypted = em.encrypt(key, iv, plaintextBytes);
        System.out.println("Encrypted: " + bytesToHex(encrypted));

        byte[] decrypted = em.decrypt(key, iv, encrypted);
        String decryptedText = new String(decrypted, StandardCharsets.UTF_8);
        System.out.println("Decrypted: " + decryptedText);

        if (Arrays.equals(plaintextBytes, decrypted)) {
            System.out.println("OK Encryption/decryption successful!");
        } else {
            System.out.println("FAIL Decryption mismatch!");
        }
        System.out.println();
    }

    private static void testSha256(EncryptionModule em) {
        System.out.println("SHA-256 Test:");
        System.out.println("-".repeat(30));

        byte[] hash = em.sha256("hello".getBytes(StandardCharsets.UTF_8));
        String hashHex = bytesToHex(hash);
        String expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

        System.out.println("SHA256('hello') = " + hashHex);

        if (hashHex.equals(expected)) {
            System.out.println("OK SHA-256 correct!");
        } else {
            System.out.println("FAIL SHA-256 mismatch!");
            System.out.println("Expected: " + expected);
        }
        System.out.println();
    }

    private static void testX25519(EncryptionModule em) {
        System.out.println("X25519 ECDH Test:");
        System.out.println("-".repeat(30));

        // Generate two key pairs
        EncryptionModule.KeyPair alice = em.x25519GenerateKeypair();
        EncryptionModule.KeyPair bob = em.x25519GenerateKeypair();

        System.out.println("Alice public key: " + bytesToHex(alice.getPublicKey()));
        System.out.println("Bob public key: " + bytesToHex(bob.getPublicKey()));

        // Compute shared secrets
        byte[] aliceSecret = em.x25519SharedSecret(alice.getPrivateKey(), bob.getPublicKey());
        byte[] bobSecret = em.x25519SharedSecret(bob.getPrivateKey(), alice.getPublicKey());

        System.out.println("Alice's shared secret: " + bytesToHex(aliceSecret));
        System.out.println("Bob's shared secret: " + bytesToHex(bobSecret));

        if (Arrays.equals(aliceSecret, bobSecret)) {
            System.out.println("OK X25519 key exchange successful!");
        } else {
            System.out.println("FAIL Shared secrets don't match!");
        }
        System.out.println();
    }

    private static void testSecp256k1(EncryptionModule em) {
        System.out.println("secp256k1 ECDH + ECDSA Test:");
        System.out.println("-".repeat(30));

        // Generate key pair
        EncryptionModule.KeyPair kp = em.secp256k1GenerateKeypair();
        System.out.println("Public key: " + bytesToHex(kp.getPublicKey()));

        // Sign a message
        byte[] message = "Hello, Bitcoin!".getBytes(StandardCharsets.UTF_8);
        byte[] signature = em.secp256k1Sign(kp.getPrivateKey(), message);
        System.out.println("Signature: " + bytesToHex(signature));

        // Verify
        boolean valid = em.secp256k1Verify(kp.getPublicKey(), message, signature);
        if (valid) {
            System.out.println("OK secp256k1 signature verified!");
        } else {
            System.out.println("FAIL secp256k1 signature verification failed!");
        }

        // Verify with wrong message fails
        byte[] wrongMessage = "Wrong message".getBytes(StandardCharsets.UTF_8);
        boolean invalid = em.secp256k1Verify(kp.getPublicKey(), wrongMessage, signature);
        if (!invalid) {
            System.out.println("OK Wrong message correctly rejected!");
        } else {
            System.out.println("FAIL Wrong message was accepted!");
        }
        System.out.println();
    }

    private static void testP256(EncryptionModule em) {
        System.out.println("P-256 ECDH + ECDSA Test:");
        System.out.println("-".repeat(30));

        // Generate key pair
        EncryptionModule.KeyPair kp = em.p256GenerateKeypair();
        System.out.println("Public key: " + bytesToHex(kp.getPublicKey()));

        // Sign a message
        byte[] message = "Hello, NIST!".getBytes(StandardCharsets.UTF_8);
        byte[] signature = em.p256Sign(kp.getPrivateKey(), message);
        System.out.println("Signature: " + bytesToHex(signature));

        // Verify
        boolean valid = em.p256Verify(kp.getPublicKey(), message, signature);
        if (valid) {
            System.out.println("OK P-256 signature verified!");
        } else {
            System.out.println("FAIL P-256 signature verification failed!");
        }
        System.out.println();
    }

    private static void testEd25519(EncryptionModule em) {
        System.out.println("Ed25519 Signature Test:");
        System.out.println("-".repeat(30));

        // Generate key pair
        EncryptionModule.KeyPair kp = em.ed25519GenerateKeypair();
        System.out.println("Public key: " + bytesToHex(kp.getPublicKey()));

        // Sign a message
        byte[] message = "Hello, Ed25519!".getBytes(StandardCharsets.UTF_8);
        byte[] signature = em.ed25519Sign(kp.getPrivateKey(), message);
        System.out.println("Signature: " + bytesToHex(signature));

        // Verify
        boolean valid = em.ed25519Verify(kp.getPublicKey(), message, signature);
        if (valid) {
            System.out.println("OK Ed25519 signature verified!");
        } else {
            System.out.println("FAIL Ed25519 signature verification failed!");
        }
        System.out.println();
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
