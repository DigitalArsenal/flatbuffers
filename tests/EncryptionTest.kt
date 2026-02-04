/**
 * Native encryption test for Kotlin FlatBuffers code generation.
 * Tests that encrypted fields can be correctly decrypted using the generated code.
 */

import com.google.flatbuffers.FlatBufferBuilder
import EncryptionTest.SensorReading

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.math.abs

// Derive a 16-byte nonce from encryption context and field offset
fun deriveNonce(ctx: ByteArray, fieldOffset: Int): ByteArray {
    val nonce = ByteArray(16)
    System.arraycopy(ctx, 0, nonce, 0, 12)
    // Little-endian field offset
    nonce[12] = (fieldOffset and 0xFF).toByte()
    nonce[13] = ((fieldOffset shr 8) and 0xFF).toByte()
    nonce[14] = ((fieldOffset shr 16) and 0xFF).toByte()
    nonce[15] = ((fieldOffset shr 24) and 0xFF).toByte()
    return nonce
}

// Encrypt bytes using AES-256-CTR
fun encryptBytes(data: ByteArray, ctx: ByteArray, fieldOffset: Int): ByteArray {
    val key = ctx.copyOfRange(0, 32)
    val nonce = deriveNonce(ctx, fieldOffset)

    val secretKey = SecretKeySpec(key, "AES")
    val iv = IvParameterSpec(nonce)
    val cipher = Cipher.getInstance("AES/CTR/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv)
    return cipher.doFinal(data)
}

// Encrypt a float value
fun encryptFloat(value: Float, ctx: ByteArray, fieldOffset: Int): Float {
    val buffer = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN)
    buffer.putFloat(value)
    val encrypted = encryptBytes(buffer.array(), ctx, fieldOffset)
    return ByteBuffer.wrap(encrypted).order(ByteOrder.LITTLE_ENDIAN).getFloat()
}

// Encrypt a string value
fun encryptString(value: String, ctx: ByteArray, fieldOffset: Int): ByteArray {
    val data = value.toByteArray(Charsets.UTF_8)
    return encryptBytes(data, ctx, fieldOffset)
}

fun testSensorReading() {
    println("Testing SensorReading with encrypted fields...")

    // Create encryption context (48 bytes)
    val encryptionCtx = ByteArray(48) { it.toByte() }

    // Original values
    val originalDeviceId = "sensor-001"
    val originalTimestamp = 1234567890UL
    val originalTemperature = 23.5f
    val originalSecretMessage = "Hello, World!"

    // Field offsets
    val temperatureOffset = 12
    val secretMessageOffset = 16

    // Encrypt values
    val encryptedTemperature = encryptFloat(originalTemperature, encryptionCtx, temperatureOffset)
    val encryptedSecretMessage = encryptString(originalSecretMessage, encryptionCtx, secretMessageOffset)

    // Build the FlatBuffer
    val builder = FlatBufferBuilder(256)

    val deviceIdOffset = builder.createString(originalDeviceId)
    val secretMessageVectorOffset = builder.createByteVector(encryptedSecretMessage)

    SensorReading.startSensorReading(builder)
    SensorReading.addDeviceId(builder, deviceIdOffset)
    SensorReading.addTimestamp(builder, originalTimestamp)
    SensorReading.addTemperature(builder, encryptedTemperature)
    SensorReading.addSecretMessage(builder, secretMessageVectorOffset)
    val sensorReadingOffset = SensorReading.endSensorReading(builder)

    builder.finish(sensorReadingOffset)
    val buf = builder.dataBuffer()

    // Read back using generated code with encryption context
    val sensorReading = SensorReading.getRootAsSensorReading(buf, encryptionCtx)

    // Verify public fields
    check(originalDeviceId == sensorReading.deviceId) {
        "Device ID mismatch: ${sensorReading.deviceId} != $originalDeviceId"
    }
    check(sensorReading.timestamp == originalTimestamp) {
        "Timestamp mismatch: ${sensorReading.timestamp} != $originalTimestamp"
    }

    // Verify encrypted fields are correctly decrypted
    val decryptedTemperature = sensorReading.temperature
    check(abs(decryptedTemperature - originalTemperature) < 0.001f) {
        "Temperature mismatch: $decryptedTemperature != $originalTemperature"
    }

    val decryptedSecretMessage = sensorReading.secretMessage
    check(decryptedSecretMessage == originalSecretMessage) {
        "Secret message mismatch: $decryptedSecretMessage != $originalSecretMessage"
    }

    println("  Device ID: OK")
    println("  Timestamp: OK")
    println("  Temperature (encrypted): OK")
    println("  Secret Message (encrypted): OK")
    println("SensorReading test passed!")
}

fun testWithoutEncryptionContext() {
    println("\nTesting reading without encryption context...")

    val encryptionCtx = ByteArray(48) { it.toByte() }

    val originalTemperature = 23.5f
    val temperatureOffset = 12
    val encryptedTemperature = encryptFloat(originalTemperature, encryptionCtx, temperatureOffset)

    val builder = FlatBufferBuilder(64)
    val deviceIdOffset = builder.createString("test")
    SensorReading.startSensorReading(builder)
    SensorReading.addDeviceId(builder, deviceIdOffset)
    SensorReading.addTemperature(builder, encryptedTemperature)
    val sensorReadingOffset = SensorReading.endSensorReading(builder)
    builder.finish(sensorReadingOffset)
    val buf = builder.dataBuffer()

    // Read without encryption context
    val sensorReading = SensorReading.getRootAsSensorReading(buf)

    // Temperature should be returned as-is (encrypted) when no context
    val readTemp = sensorReading.temperature
    check(abs(readTemp - encryptedTemperature) < 0.001f) {
        "Expected encrypted value $encryptedTemperature, got $readTemp"
    }

    println("  Reading without context returns raw values: OK")
    println("No encryption context test passed!")
}

fun main() {
    println("============================================================")
    println("Kotlin FlatBuffers Encryption Test")
    println("============================================================")

    try {
        testSensorReading()
        testWithoutEncryptionContext()
        println("\n============================================================")
        println("All tests passed!")
        println("============================================================")
    } catch (e: Exception) {
        println("\nTest failed: ${e.message}")
        e.printStackTrace()
        System.exit(1)
    }
}
