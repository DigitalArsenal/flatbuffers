// Native encryption test for Go FlatBuffers code generation.
// Tests that encrypted fields can be correctly decrypted using the generated code.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"math"
	"os"

	flatbuffers "github.com/google/flatbuffers/go"
	EncryptionTest "tests/go_gen/EncryptionTest"
)

// deriveNonce derives a 16-byte nonce from encryption context and field offset.
func deriveNonce(ctx []byte, fieldOffset uint16) []byte {
	nonce := make([]byte, 16)
	copy(nonce[:12], ctx[:12])
	binary.LittleEndian.PutUint32(nonce[12:], uint32(fieldOffset))
	return nonce
}

// encryptBytes encrypts bytes using AES-256-CTR.
func encryptBytes(data []byte, ctx []byte, fieldOffset uint16) []byte {
	key := ctx[:32]
	nonce := deriveNonce(ctx, fieldOffset)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	stream := cipher.NewCTR(block, nonce)
	result := make([]byte, len(data))
	stream.XORKeyStream(result, data)
	return result
}

// encryptFloat32 encrypts a float32 value.
func encryptFloat32(value float32, ctx []byte, fieldOffset uint16) float32 {
	bits := math.Float32bits(value)
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, bits)
	encrypted := encryptBytes(data, ctx, fieldOffset)
	encryptedBits := binary.LittleEndian.Uint32(encrypted)
	return math.Float32frombits(encryptedBits)
}

// encryptString encrypts a string value.
func encryptString(value string, ctx []byte, fieldOffset uint16) []byte {
	data := []byte(value)
	return encryptBytes(data, ctx, fieldOffset)
}

func testSensorReading() error {
	fmt.Println("Testing SensorReading with encrypted fields...")

	// Create encryption context (48 bytes)
	encryptionCtx := make([]byte, 48)
	for i := 0; i < 48; i++ {
		encryptionCtx[i] = byte(i)
	}

	// Original values
	originalDeviceId := "sensor-001"
	originalTimestamp := uint64(1234567890)
	originalTemperature := float32(23.5)
	originalSecretMessage := "Hello, World!"

	// Field offsets
	temperatureOffset := uint16(12)
	secretMessageOffset := uint16(16)

	// Encrypt values
	encryptedTemperature := encryptFloat32(originalTemperature, encryptionCtx, temperatureOffset)
	encryptedSecretMessage := encryptString(originalSecretMessage, encryptionCtx, secretMessageOffset)

	// Build the FlatBuffer
	builder := flatbuffers.NewBuilder(256)

	deviceIdOffset := builder.CreateString(originalDeviceId)
	secretMessageVectorOffset := builder.CreateByteVector(encryptedSecretMessage)

	EncryptionTest.SensorReadingStart(builder)
	EncryptionTest.SensorReadingAddDeviceId(builder, deviceIdOffset)
	EncryptionTest.SensorReadingAddTimestamp(builder, originalTimestamp)
	EncryptionTest.SensorReadingAddTemperature(builder, encryptedTemperature)
	EncryptionTest.SensorReadingAddSecretMessage(builder, secretMessageVectorOffset)
	sensorReadingOffset := EncryptionTest.SensorReadingEnd(builder)

	builder.Finish(sensorReadingOffset)
	buf := builder.FinishedBytes()

	// Read back using generated code with encryption context
	sensorReading := EncryptionTest.GetRootAsSensorReading(buf, 0, encryptionCtx)

	// Verify public fields
	if string(sensorReading.DeviceId()) != originalDeviceId {
		return fmt.Errorf("Device ID mismatch: %s != %s", sensorReading.DeviceId(), originalDeviceId)
	}
	if sensorReading.Timestamp() != originalTimestamp {
		return fmt.Errorf("Timestamp mismatch: %d != %d", sensorReading.Timestamp(), originalTimestamp)
	}

	// Verify encrypted fields are correctly decrypted
	decryptedTemperature := sensorReading.Temperature()
	if math.Abs(float64(decryptedTemperature-originalTemperature)) > 0.001 {
		return fmt.Errorf("Temperature mismatch: %f != %f", decryptedTemperature, originalTemperature)
	}

	secretMessageBytes := sensorReading.SecretMessage()
	if secretMessageBytes != nil {
		decryptedSecretMessage := string(secretMessageBytes)
		if decryptedSecretMessage != originalSecretMessage {
			return fmt.Errorf("Secret message mismatch: %s != %s", decryptedSecretMessage, originalSecretMessage)
		}
	}

	fmt.Println("  Device ID: OK")
	fmt.Println("  Timestamp: OK")
	fmt.Println("  Temperature (encrypted): OK")
	fmt.Println("  Secret Message (encrypted): OK")
	fmt.Println("SensorReading test passed!")
	return nil
}

func testWithoutEncryptionContext() error {
	fmt.Println("\nTesting reading without encryption context...")

	encryptionCtx := make([]byte, 48)
	for i := 0; i < 48; i++ {
		encryptionCtx[i] = byte(i)
	}

	originalTemperature := float32(23.5)
	temperatureOffset := uint16(12)
	encryptedTemperature := encryptFloat32(originalTemperature, encryptionCtx, temperatureOffset)

	builder := flatbuffers.NewBuilder(64)
	deviceIdOffset := builder.CreateString("test")
	EncryptionTest.SensorReadingStart(builder)
	EncryptionTest.SensorReadingAddDeviceId(builder, deviceIdOffset)
	EncryptionTest.SensorReadingAddTemperature(builder, encryptedTemperature)
	sensorReadingOffset := EncryptionTest.SensorReadingEnd(builder)
	builder.Finish(sensorReadingOffset)
	buf := builder.FinishedBytes()

	// Read without encryption context - should panic or return encrypted value
	// In Go, DecryptScalar returns as-is if ctx is nil
	sensorReading := EncryptionTest.GetRootAsSensorReading(buf, 0)

	readTemp := sensorReading.Temperature()
	if math.Abs(float64(readTemp-encryptedTemperature)) > 0.001 {
		return fmt.Errorf("Expected encrypted value %f, got %f", encryptedTemperature, readTemp)
	}

	fmt.Println("  Reading without context returns raw values: OK")
	fmt.Println("No encryption context test passed!")
	return nil
}

func main() {
	fmt.Println(string(bytes.Repeat([]byte("="), 60)))
	fmt.Println("Go FlatBuffers Encryption Test")
	fmt.Println(string(bytes.Repeat([]byte("="), 60)))

	if err := testSensorReading(); err != nil {
		fmt.Printf("\nTest failed: %v\n", err)
		os.Exit(1)
	}

	if err := testWithoutEncryptionContext(); err != nil {
		fmt.Printf("\nTest failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println(string(bytes.Repeat([]byte("="), 60)))
	fmt.Println("All tests passed!")
	fmt.Println(string(bytes.Repeat([]byte("="), 60)))
}
