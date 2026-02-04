#!/usr/bin/env python3
"""
Native encryption test for Python FlatBuffers code generation.
Tests that encrypted fields can be correctly decrypted using the generated code.
"""

import os
import sys
import struct

# Add the generated code path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tests', 'py_gen'))

import flatbuffers
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Import generated code
from EncryptionTest.SensorReading import SensorReading
from EncryptionTest import SensorReading as SensorReadingModule


def derive_nonce(ctx: bytes, field_offset: int) -> bytes:
    """Derive a 16-byte nonce from encryption context and field offset."""
    return ctx[:12] + struct.pack('<I', field_offset)


def encrypt_bytes(data: bytes, ctx: bytes, field_offset: int) -> bytes:
    """Encrypt bytes using AES-256-CTR (same as decrypt for CTR mode)."""
    key = ctx[:32]
    nonce = derive_nonce(ctx, field_offset)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def encrypt_float32(value: float, ctx: bytes, field_offset: int) -> float:
    """Encrypt a float32 value."""
    data = struct.pack('<f', value)
    encrypted = encrypt_bytes(data, ctx, field_offset)
    return struct.unpack('<f', encrypted)[0]


def encrypt_string(value: str, ctx: bytes, field_offset: int) -> bytes:
    """Encrypt a string value."""
    data = value.encode('utf-8')
    return encrypt_bytes(data, ctx, field_offset)


def test_sensor_reading():
    """Test SensorReading with encrypted fields."""
    print("Testing SensorReading with encrypted fields...")

    # Create encryption context (32 bytes for key + extra for nonce derivation)
    encryption_ctx = bytes([i for i in range(48)])  # 0, 1, 2, ..., 47

    # Original values
    original_device_id = "sensor-001"
    original_timestamp = 1234567890
    original_temperature = 23.5
    original_secret_message = "Hello, World!"

    # Field offsets from the schema (vtable offsets)
    # device_id: 4, timestamp: 6, public_data: 8, location: 10, temperature: 12, raw_data: 14, secret_message: 16
    temperature_offset = 12
    secret_message_offset = 16

    # Encrypt values for the buffer
    encrypted_temperature = encrypt_float32(original_temperature, encryption_ctx, temperature_offset)
    encrypted_secret_message = encrypt_string(original_secret_message, encryption_ctx, secret_message_offset)

    # Build the FlatBuffer with encrypted values
    builder = flatbuffers.Builder(256)

    # Create string for device_id (not encrypted)
    device_id_offset = builder.CreateString(original_device_id)

    # Create encrypted secret message
    secret_message_offset_val = builder.CreateByteVector(encrypted_secret_message)

    # Start building the table
    SensorReadingModule.SensorReadingStart(builder)
    SensorReadingModule.SensorReadingAddDeviceId(builder, device_id_offset)
    SensorReadingModule.SensorReadingAddTimestamp(builder, original_timestamp)
    SensorReadingModule.SensorReadingAddTemperature(builder, encrypted_temperature)
    SensorReadingModule.SensorReadingAddSecretMessage(builder, secret_message_offset_val)
    sensor_reading_offset = SensorReadingModule.SensorReadingEnd(builder)

    builder.Finish(sensor_reading_offset)
    buf = builder.Output()
    buf = bytes(buf)

    # Read back using generated code with encryption context
    sensor_reading = SensorReading.GetRootAs(buf, 0, encryption_ctx)

    # Verify public fields
    assert sensor_reading.DeviceId().decode('utf-8') == original_device_id, \
        f"Device ID mismatch: {sensor_reading.DeviceId()} != {original_device_id}"
    assert sensor_reading.Timestamp() == original_timestamp, \
        f"Timestamp mismatch: {sensor_reading.Timestamp()} != {original_timestamp}"

    # Verify encrypted fields are correctly decrypted
    decrypted_temperature = sensor_reading.Temperature()
    assert abs(decrypted_temperature - original_temperature) < 0.001, \
        f"Temperature mismatch: {decrypted_temperature} != {original_temperature}"

    secret_message_bytes = sensor_reading.SecretMessage()
    if secret_message_bytes:
        decrypted_secret_message = secret_message_bytes.decode('utf-8')
        assert decrypted_secret_message == original_secret_message, \
            f"Secret message mismatch: {decrypted_secret_message} != {original_secret_message}"

    print("  Device ID: OK")
    print("  Timestamp: OK")
    print("  Temperature (encrypted): OK")
    print("  Secret Message (encrypted): OK")
    print("SensorReading test passed!")


def test_without_encryption_context():
    """Test that reading without encryption context returns raw encrypted values."""
    print("\nTesting reading without encryption context...")

    encryption_ctx = bytes([i for i in range(48)])
    original_temperature = 23.5
    temperature_offset = 12

    encrypted_temperature = encrypt_float32(original_temperature, encryption_ctx, temperature_offset)

    builder = flatbuffers.Builder(64)
    device_id_offset = builder.CreateString("test")
    SensorReadingModule.SensorReadingStart(builder)
    SensorReadingModule.SensorReadingAddDeviceId(builder, device_id_offset)
    SensorReadingModule.SensorReadingAddTemperature(builder, encrypted_temperature)
    sensor_reading_offset = SensorReadingModule.SensorReadingEnd(builder)
    builder.Finish(sensor_reading_offset)
    buf = bytes(builder.Output())

    # Read without encryption context
    sensor_reading = SensorReading.GetRootAs(buf, 0)

    # Temperature should be returned as-is (encrypted) when no context
    read_temp = sensor_reading.Temperature()
    # The FlatbuffersEncryption.decrypt_scalar returns value as-is if ctx is None
    assert abs(read_temp - encrypted_temperature) < 0.001, \
        f"Expected encrypted value {encrypted_temperature}, got {read_temp}"

    print("  Reading without context returns raw values: OK")
    print("No encryption context test passed!")


def main():
    print("=" * 60)
    print("Python FlatBuffers Encryption Test")
    print("=" * 60)

    try:
        test_sensor_reading()
        test_without_encryption_context()
        print("\n" + "=" * 60)
        print("All tests passed!")
        print("=" * 60)
        return 0
    except Exception as e:
        print(f"\nTest failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
