#!/usr/bin/env python3
"""
Python Encryption Integration Tests

Tests the Python encryption implementation for compatibility
with the flatc-wasm JavaScript encryption module.

Run with: python test_encryption.py
"""

import os
import sys
import struct
from flatc_wasm import (
    EncryptionContext,
    encrypt_bytes,
    decrypt_bytes,
    encrypt_buffer,
    decrypt_buffer,
    parse_schema_for_encryption,
)


passed = 0
failed = 0


def test(name, fn):
    global passed, failed
    try:
        fn()
        print(f"  ✓ {name}")
        passed += 1
    except Exception as e:
        print(f"  ✗ {name}")
        print(f"    Error: {e}")
        failed += 1


def assert_eq(actual, expected, msg=""):
    if actual != expected:
        raise AssertionError(f"{msg}: expected {expected}, got {actual}")


def assert_ne(actual, expected, msg=""):
    if actual == expected:
        raise AssertionError(f"{msg}: expected different from {expected}")


# Test schema
SIMPLE_SCHEMA = """
table SimpleMessage {
  public_text: string;
  secret_number: int (encrypted);
  secret_text: string (encrypted);
}
root_type SimpleMessage;
"""

SENSOR_SCHEMA = """
table SensorReading {
  device_id: string;
  timestamp: uint64;
  temperature: float (encrypted);
  raw_data: [ubyte] (encrypted);
  secret_message: string (encrypted);
}
root_type SensorReading;
"""


print("\n=== Python Encryption Integration Tests ===\n")

# Test 1: EncryptionContext
print("1. EncryptionContext:")


def test_context_from_bytes():
    key = os.urandom(32)
    ctx = EncryptionContext(key)
    assert_eq(ctx.is_valid(), True, "context should be valid")


def test_context_from_hex():
    hex_key = "0123456789abcdef" * 4
    ctx = EncryptionContext(hex_key)
    assert_eq(ctx.is_valid(), True, "context should be valid")


def test_context_invalid_size():
    key = os.urandom(16)  # Too short
    ctx = EncryptionContext(key)
    assert_eq(ctx.is_valid(), False, "context should be invalid")


def test_derive_different_keys():
    key = os.urandom(32)
    ctx = EncryptionContext(key)
    key1 = ctx.derive_field_key(1)
    key2 = ctx.derive_field_key(2)
    assert_ne(key1, key2, "derived keys should differ")


test("creates valid context from bytes", test_context_from_bytes)
test("creates valid context from hex", test_context_from_hex)
test("rejects invalid key size", test_context_invalid_size)
test("derives different keys for different fields", test_derive_different_keys)

# Test 2: Low-level encryption
print("\n2. Low-level byte encryption:")


def test_encrypt_decrypt_bytes():
    key = os.urandom(32)
    iv = os.urandom(16)
    original = b"Hello, World!"
    data = bytearray(original)

    encrypt_bytes(data, key, iv)
    assert_ne(bytes(data), original, "data should change after encryption")

    decrypt_bytes(data, key, iv)
    assert_eq(bytes(data), original, "data should match after decryption")


def test_different_ivs():
    key = os.urandom(32)
    iv1 = os.urandom(16)
    iv2 = os.urandom(16)
    plaintext = b"Test data"

    data1 = bytearray(plaintext)
    data2 = bytearray(plaintext)

    encrypt_bytes(data1, key, iv1)
    encrypt_bytes(data2, key, iv2)

    assert_ne(bytes(data1), bytes(data2), "different IVs should produce different ciphertext")


test("encrypts and decrypts bytes", test_encrypt_decrypt_bytes)
test("different IVs produce different ciphertext", test_different_ivs)

# Test 3: Schema parsing
print("\n3. Schema parsing:")


def test_parse_simple_schema():
    fields = parse_schema_for_encryption(SIMPLE_SCHEMA, "SimpleMessage")
    assert_eq(len(fields), 3, "field count")

    public_field = next(f for f in fields if f.name == "public_text")
    secret_num = next(f for f in fields if f.name == "secret_number")
    secret_text = next(f for f in fields if f.name == "secret_text")

    assert_eq(public_field.encrypted, False, "public_text should not be encrypted")
    assert_eq(secret_num.encrypted, True, "secret_number should be encrypted")
    assert_eq(secret_text.encrypted, True, "secret_text should be encrypted")


def test_parse_vector_fields():
    fields = parse_schema_for_encryption(SENSOR_SCHEMA, "SensorReading")

    raw_data = next(f for f in fields if f.name == "raw_data")
    assert_eq(raw_data.encrypted, True, "raw_data should be encrypted")
    assert_eq(raw_data.type, "vector", "raw_data should be vector type")


test("parses simple schema", test_parse_simple_schema)
test("parses vector fields", test_parse_vector_fields)

# Test 4: Buffer encryption
print("\n4. Buffer encryption:")


def create_simple_flatbuffer():
    """
    Create a minimal FlatBuffer for SimpleMessage.
    This is a hand-crafted buffer for testing without requiring flatc.

    FlatBuffer layout:
    - Offset 0: root table offset (uoffset_t, 4 bytes)
    - VTable: vtable_size, table_size, field offsets...
    - Table: soffset_t to vtable, then field data

    For SimpleMessage:
      field 0: public_text (string) - not encrypted
      field 1: secret_number (int) - encrypted
      field 2: secret_text (string) - encrypted
    """
    buf = bytearray(64)

    # Layout:
    # [0-3]   root offset -> points to table at offset 16
    # [4-13]  vtable: size=10, table_size=12, f0=4, f1=8, f2=0
    # [16-19] table: soffset to vtable (16-4=12)
    # [20-23] field 0 data: offset to string
    # [24-27] field 1 data: secret_number = 42
    # [32-35] string length
    # [36-40] string data "hello"

    # Root offset points to table at offset 16
    struct.pack_into("<I", buf, 0, 16)

    # VTable at offset 4
    # vtable_size = 10 bytes (2 + 2 + 3*2)
    # table_size = 12 bytes (4 soffset + 4 field0 + 4 field1)
    struct.pack_into("<H", buf, 4, 10)   # vtable size
    struct.pack_into("<H", buf, 6, 12)   # table size
    struct.pack_into("<H", buf, 8, 4)    # field 0 offset from table start
    struct.pack_into("<H", buf, 10, 8)   # field 1 offset from table start
    struct.pack_into("<H", buf, 12, 0)   # field 2 not present

    # Table at offset 16
    # soffset_t to vtable: table_offset - vtable_offset = 16 - 4 = 12
    struct.pack_into("<i", buf, 16, 12)

    # Field 0 (string offset) at table+4 = offset 20
    # Points to string at offset 32, relative offset = 32 - 20 = 12
    struct.pack_into("<I", buf, 20, 12)

    # Field 1 (int32) at table+8 = offset 24
    struct.pack_into("<i", buf, 24, 42)  # secret_number = 42

    # String at offset 32
    test_string = b"hello"
    struct.pack_into("<I", buf, 32, len(test_string))
    buf[36:36 + len(test_string)] = test_string

    return bytes(buf)


def test_encrypt_buffer_changes_data():
    buf = create_simple_flatbuffer()
    key = os.urandom(32)
    ctx = EncryptionContext(key)

    encrypted = encrypt_buffer(buf, SIMPLE_SCHEMA, ctx, "SimpleMessage")

    # The encrypted buffer should be different
    assert_ne(encrypted, buf, "buffer should change after encryption")


def test_encrypt_decrypt_roundtrip():
    buf = create_simple_flatbuffer()
    key = os.urandom(32)
    ctx = EncryptionContext(key)

    encrypted = encrypt_buffer(buf, SIMPLE_SCHEMA, ctx, "SimpleMessage")
    decrypted = decrypt_buffer(encrypted, SIMPLE_SCHEMA, ctx, "SimpleMessage")

    assert_eq(decrypted, buf, "buffer should match after decrypt")


def test_different_keys_different_ciphertext():
    buf = create_simple_flatbuffer()
    key1 = os.urandom(32)
    key2 = os.urandom(32)

    ctx1 = EncryptionContext(key1)
    ctx2 = EncryptionContext(key2)

    encrypted1 = encrypt_buffer(buf, SIMPLE_SCHEMA, ctx1, "SimpleMessage")
    encrypted2 = encrypt_buffer(buf, SIMPLE_SCHEMA, ctx2, "SimpleMessage")

    assert_ne(encrypted1, encrypted2, "different keys should produce different ciphertext")


def test_wrong_key_wrong_result():
    buf = create_simple_flatbuffer()
    key1 = os.urandom(32)
    key2 = os.urandom(32)

    ctx1 = EncryptionContext(key1)
    ctx2 = EncryptionContext(key2)

    encrypted = encrypt_buffer(buf, SIMPLE_SCHEMA, ctx1, "SimpleMessage")
    wrong_decrypt = decrypt_buffer(encrypted, SIMPLE_SCHEMA, ctx2, "SimpleMessage")

    assert_ne(wrong_decrypt, buf, "wrong key should not decrypt correctly")


test("encrypt_buffer changes data", test_encrypt_buffer_changes_data)
test("encrypt/decrypt roundtrip", test_encrypt_decrypt_roundtrip)
test("different keys produce different ciphertext", test_different_keys_different_ciphertext)
test("wrong key produces wrong result", test_wrong_key_wrong_result)

# Test 5: Context reuse
print("\n5. Context reuse:")


def test_context_reuse():
    key = os.urandom(32)
    ctx = EncryptionContext(key)

    buf1 = create_simple_flatbuffer()
    buf2 = create_simple_flatbuffer()

    enc1 = encrypt_buffer(buf1, SIMPLE_SCHEMA, ctx, "SimpleMessage")
    enc2 = encrypt_buffer(buf2, SIMPLE_SCHEMA, ctx, "SimpleMessage")

    dec1 = decrypt_buffer(enc1, SIMPLE_SCHEMA, ctx, "SimpleMessage")
    dec2 = decrypt_buffer(enc2, SIMPLE_SCHEMA, ctx, "SimpleMessage")

    assert_eq(dec1, buf1, "first buffer should decrypt correctly")
    assert_eq(dec2, buf2, "second buffer should decrypt correctly")


test("context can be reused", test_context_reuse)

# Test 6: Interoperability
print("\n6. Interoperability checks:")


def test_key_derivation_consistency():
    """
    Test that key derivation is deterministic.
    The same key + field ID should always produce the same derived key.
    """
    key = bytes.fromhex("0123456789abcdef" * 4)

    ctx1 = EncryptionContext(key)
    ctx2 = EncryptionContext(key)

    derived1 = ctx1.derive_field_key(5)
    derived2 = ctx2.derive_field_key(5)

    assert_eq(derived1, derived2, "key derivation should be deterministic")


def test_encryption_is_deterministic():
    """
    Test that same key + same data = same ciphertext.
    (This is a property of AES-CTR with deterministic IV derivation)
    """
    key = os.urandom(32)
    ctx = EncryptionContext(key)

    buf = create_simple_flatbuffer()

    enc1 = encrypt_buffer(buf, SIMPLE_SCHEMA, ctx, "SimpleMessage")
    enc2 = encrypt_buffer(buf, SIMPLE_SCHEMA, ctx, "SimpleMessage")

    assert_eq(enc1, enc2, "encryption should be deterministic")


def test_hex_key_same_as_bytes():
    """
    Test that hex string key produces same result as bytes key.
    """
    key_bytes = bytes.fromhex("0123456789abcdef" * 4)
    key_hex = "0123456789abcdef" * 4

    ctx_bytes = EncryptionContext(key_bytes)
    ctx_hex = EncryptionContext(key_hex)

    buf = create_simple_flatbuffer()

    enc_bytes = encrypt_buffer(buf, SIMPLE_SCHEMA, ctx_bytes, "SimpleMessage")
    enc_hex = encrypt_buffer(buf, SIMPLE_SCHEMA, ctx_hex, "SimpleMessage")

    assert_eq(enc_bytes, enc_hex, "hex and bytes keys should produce same result")


test("key derivation is deterministic", test_key_derivation_consistency)
test("encryption is deterministic", test_encryption_is_deterministic)
test("hex key same as bytes key", test_hex_key_same_as_bytes)

# Test 7: API variants
print("\n7. API variants:")


def test_direct_key_usage():
    """Test using a key directly instead of EncryptionContext."""
    key = os.urandom(32)
    buf = create_simple_flatbuffer()

    # Using key bytes directly
    encrypted = encrypt_buffer(buf, SIMPLE_SCHEMA, key, "SimpleMessage")
    decrypted = decrypt_buffer(encrypted, SIMPLE_SCHEMA, key, "SimpleMessage")

    assert_eq(decrypted, buf, "direct key usage should work")


def test_hex_key_direct():
    """Test using a hex string key directly."""
    hex_key = "0123456789abcdef" * 4
    buf = create_simple_flatbuffer()

    encrypted = encrypt_buffer(buf, SIMPLE_SCHEMA, hex_key, "SimpleMessage")
    decrypted = decrypt_buffer(encrypted, SIMPLE_SCHEMA, hex_key, "SimpleMessage")

    assert_eq(decrypted, buf, "hex key direct usage should work")


test("direct key usage (bytes)", test_direct_key_usage)
test("direct key usage (hex string)", test_hex_key_direct)

# Summary
print("\n=== Test Summary ===")
print(f"Passed: {passed}")
print(f"Failed: {failed}")
print(f"Total:  {passed + failed}")

if failed > 0:
    print("\n❌ Some tests failed!")
    sys.exit(1)
else:
    print("\n✅ All Python encryption tests passed!")
    sys.exit(0)
