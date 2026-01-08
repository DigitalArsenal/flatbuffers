#!/usr/bin/env python3
"""Tests for the WASI encryption module."""

import os
import unittest
from encryption import EncryptionModule


class TestEncryptionModule(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Load the WASM module once for all tests."""
        try:
            cls.em = EncryptionModule()
        except FileNotFoundError:
            raise unittest.SkipTest("WASM module not found - build it first")

    def test_version(self):
        """Test version retrieval."""
        version = self.em.version()
        self.assertIsInstance(version, str)
        self.assertGreater(len(version), 0)
        print(f"Module version: {version}")

    def test_has_cryptopp(self):
        """Test Crypto++ availability check."""
        has_cpp = self.em.has_cryptopp()
        self.assertIsInstance(has_cpp, bool)
        print(f"Crypto++ available: {has_cpp}")

    def test_encrypt_decrypt(self):
        """Test AES-256-CTR encryption and decryption."""
        key = os.urandom(32)
        iv = os.urandom(16)
        plaintext = b"Hello, FlatBuffers WASI encryption!"

        # Encrypt
        encrypted = self.em.encrypt_bytes(key, iv, plaintext)
        self.assertEqual(len(encrypted), len(plaintext))
        self.assertNotEqual(encrypted, plaintext)

        # Decrypt
        decrypted = self.em.decrypt_bytes(key, iv, encrypted)
        self.assertEqual(decrypted, plaintext)

    def test_encrypt_empty(self):
        """Test encryption of empty data."""
        key = os.urandom(32)
        iv = os.urandom(16)

        result = self.em.encrypt_bytes(key, iv, b"")
        self.assertEqual(result, b"")

    def test_encrypt_large(self):
        """Test encryption of large data."""
        key = os.urandom(32)
        iv = os.urandom(16)
        plaintext = os.urandom(10000)

        encrypted = self.em.encrypt_bytes(key, iv, plaintext)
        decrypted = self.em.decrypt_bytes(key, iv, encrypted)
        self.assertEqual(decrypted, plaintext)

    def test_sha256(self):
        """Test SHA-256 hash."""
        # Known test vector
        data = b"hello"
        expected = bytes.fromhex(
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        )

        result = self.em.sha256(data)
        self.assertEqual(result, expected)

    def test_sha256_empty(self):
        """Test SHA-256 of empty data."""
        expected = bytes.fromhex(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

        result = self.em.sha256(b"")
        self.assertEqual(result, expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
