// Native encryption test for Lobster FlatBuffers code generation.
// Tests that encrypted fields can be correctly decrypted using the generated code.
//
// NOTE: The default AES implementation is a placeholder. For actual encryption,
// you need to implement flatbuffers_aes256_ctr_decrypt with a real AES library.

import lobster_gen/encryption_test_generated

def test_sensor_reading():
    print("Testing SensorReading with encrypted fields...")

    // Create encryption context (48 bytes)
    let ctx = flatbuffers_encryption_ctx {
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" +
        "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",  // 32-byte key
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b"  // 12-byte nonce prefix
    }

    // Build a FlatBuffer
    let builder = flatbuffers.builder {}
    builder.Initial(256)

    // Create strings
    let device_id_offset = builder.CreateString("sensor-001")
    // For testing with placeholder encryption, the "encrypted" string is stored as-is
    let secret_message_offset = builder.CreateString("Hello, World!")

    // Build the table
    let sensor_builder = EncryptionTest.SensorReadingBuilder { builder }
    sensor_builder.start()
    sensor_builder.add_device_id(device_id_offset)
    sensor_builder.add_timestamp(1234567890)
    sensor_builder.add_temperature(23.5)  // With placeholder, stored as-is
    sensor_builder.add_secret_message(secret_message_offset)
    let sensor_offset = sensor_builder.end()

    builder.Finish(sensor_offset)
    let buf = builder.SizedCopy()

    // Read back using generated code with encryption context
    let sensor_reading = EncryptionTest.GetRootAsSensorReadingWithEncryption(buf, ctx)

    // Verify public fields
    if sensor_reading.device_id() != "sensor-001":
        print("ERROR: Device ID mismatch")
        return false

    if sensor_reading.timestamp() != 1234567890:
        print("ERROR: Timestamp mismatch")
        return false

    // With placeholder encryption (returns data unchanged), these should work
    // In production with real encryption, you'd need to encrypt values before storing
    let temp = sensor_reading.temperature()
    print("  Temperature: " + string(temp))

    let msg = sensor_reading.secret_message()
    print("  Secret message: " + msg)

    // For placeholder encryption, values should be unchanged
    if abs(temp - 23.5) > 0.001:
        print("ERROR: Temperature mismatch (placeholder should return unchanged)")
        return false

    if msg != "Hello, World!":
        print("ERROR: Secret message mismatch (placeholder should return unchanged)")
        return false

    print("  Device ID: OK")
    print("  Timestamp: OK")
    print("  Temperature (with placeholder decryption): OK")
    print("  Secret Message (with placeholder decryption): OK")
    print("SensorReading test passed!")
    return true

def test_without_encryption_context():
    print("\nTesting reading without encryption context...")

    // Build a FlatBuffer
    let builder = flatbuffers.builder {}
    builder.Initial(64)

    let device_id_offset = builder.CreateString("test")

    let sensor_builder = EncryptionTest.SensorReadingBuilder { builder }
    sensor_builder.start()
    sensor_builder.add_device_id(device_id_offset)
    sensor_builder.add_temperature(23.5)
    let sensor_offset = sensor_builder.end()

    builder.Finish(sensor_offset)
    let buf = builder.SizedCopy()

    // Read without encryption context
    let sensor_reading = EncryptionTest.GetRootAsSensorReading(buf)

    // Temperature should be returned as-is when no context
    let read_temp = sensor_reading.temperature()
    if abs(read_temp - 23.5) > 0.001:
        print("ERROR: Expected raw value, got " + string(read_temp))
        return false

    print("  Reading without context returns raw values: OK")
    print("No encryption context test passed!")
    return true

def main():
    print("============================================================")
    print("Lobster FlatBuffers Encryption Test")
    print("============================================================")
    print("")
    print("NOTE: Using placeholder encryption (returns values unchanged).")
    print("For production use, implement flatbuffers_aes256_ctr_decrypt.")
    print("")

    if not test_sensor_reading():
        return 1
    if not test_without_encryption_context():
        return 1

    print("\n============================================================")
    print("All tests passed!")
    print("============================================================")
    return 0

main()
