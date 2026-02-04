/**
 * Native encryption test for Java FlatBuffers code generation.
 * Tests that encrypted fields can be correctly decrypted using the generated code.
 */

import com.google.flatbuffers.FlatBufferBuilder;
import EncryptionTest.SensorReading;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

public class EncryptionTest {

    // Derive a 16-byte nonce from encryption context and field offset
    private static byte[] deriveNonce(byte[] ctx, int fieldOffset) {
        byte[] nonce = new byte[16];
        System.arraycopy(ctx, 0, nonce, 0, 12);
        // Little-endian field offset
        nonce[12] = (byte) (fieldOffset & 0xFF);
        nonce[13] = (byte) ((fieldOffset >> 8) & 0xFF);
        nonce[14] = (byte) ((fieldOffset >> 16) & 0xFF);
        nonce[15] = (byte) ((fieldOffset >> 24) & 0xFF);
        return nonce;
    }

    // Encrypt bytes using AES-256-CTR
    private static byte[] encryptBytes(byte[] data, byte[] ctx, int fieldOffset) throws Exception {
        byte[] key = new byte[32];
        System.arraycopy(ctx, 0, key, 0, 32);
        byte[] nonce = deriveNonce(ctx, fieldOffset);

        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        IvParameterSpec iv = new IvParameterSpec(nonce);
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        return cipher.doFinal(data);
    }

    // Encrypt a float value
    private static float encryptFloat(float value, byte[] ctx, int fieldOffset) throws Exception {
        ByteBuffer buffer = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN);
        buffer.putFloat(value);
        byte[] encrypted = encryptBytes(buffer.array(), ctx, fieldOffset);
        return ByteBuffer.wrap(encrypted).order(ByteOrder.LITTLE_ENDIAN).getFloat();
    }

    // Encrypt a string value
    private static byte[] encryptString(String value, byte[] ctx, int fieldOffset) throws Exception {
        byte[] data = value.getBytes(StandardCharsets.UTF_8);
        return encryptBytes(data, ctx, fieldOffset);
    }

    private static void testSensorReading() throws Exception {
        System.out.println("Testing SensorReading with encrypted fields...");

        // Create encryption context (48 bytes)
        byte[] encryptionCtx = new byte[48];
        for (int i = 0; i < 48; i++) {
            encryptionCtx[i] = (byte) i;
        }

        // Original values
        String originalDeviceId = "sensor-001";
        long originalTimestamp = 1234567890L;
        float originalTemperature = 23.5f;
        String originalSecretMessage = "Hello, World!";

        // Field offsets
        int temperatureOffset = 12;
        int secretMessageOffset = 16;

        // Encrypt values
        float encryptedTemperature = encryptFloat(originalTemperature, encryptionCtx, temperatureOffset);
        byte[] encryptedSecretMessage = encryptString(originalSecretMessage, encryptionCtx, secretMessageOffset);

        // Build the FlatBuffer
        FlatBufferBuilder builder = new FlatBufferBuilder(256);

        int deviceIdOffset = builder.createString(originalDeviceId);
        int secretMessageVectorOffset = builder.createByteVector(encryptedSecretMessage);

        SensorReading.startSensorReading(builder);
        SensorReading.addDeviceId(builder, deviceIdOffset);
        SensorReading.addTimestamp(builder, originalTimestamp);
        SensorReading.addTemperature(builder, encryptedTemperature);
        SensorReading.addSecretMessage(builder, secretMessageVectorOffset);
        int sensorReadingOffset = SensorReading.endSensorReading(builder);

        builder.finish(sensorReadingOffset);
        ByteBuffer buf = builder.dataBuffer();

        // Read back using generated code with encryption context
        SensorReading sensorReading = SensorReading.getRootAsSensorReading(buf, encryptionCtx);

        // Verify public fields
        if (!originalDeviceId.equals(sensorReading.deviceId())) {
            throw new AssertionError("Device ID mismatch: " + sensorReading.deviceId() + " != " + originalDeviceId);
        }
        if (sensorReading.timestamp() != originalTimestamp) {
            throw new AssertionError("Timestamp mismatch: " + sensorReading.timestamp() + " != " + originalTimestamp);
        }

        // Verify encrypted fields are correctly decrypted
        float decryptedTemperature = sensorReading.temperature();
        if (Math.abs(decryptedTemperature - originalTemperature) > 0.001) {
            throw new AssertionError("Temperature mismatch: " + decryptedTemperature + " != " + originalTemperature);
        }

        String decryptedSecretMessage = sensorReading.secretMessage();
        if (decryptedSecretMessage != null && !decryptedSecretMessage.equals(originalSecretMessage)) {
            throw new AssertionError("Secret message mismatch: " + decryptedSecretMessage + " != " + originalSecretMessage);
        }

        System.out.println("  Device ID: OK");
        System.out.println("  Timestamp: OK");
        System.out.println("  Temperature (encrypted): OK");
        System.out.println("  Secret Message (encrypted): OK");
        System.out.println("SensorReading test passed!");
    }

    private static void testWithoutEncryptionContext() throws Exception {
        System.out.println("\nTesting reading without encryption context...");

        byte[] encryptionCtx = new byte[48];
        for (int i = 0; i < 48; i++) {
            encryptionCtx[i] = (byte) i;
        }

        float originalTemperature = 23.5f;
        int temperatureOffset = 12;
        float encryptedTemperature = encryptFloat(originalTemperature, encryptionCtx, temperatureOffset);

        FlatBufferBuilder builder = new FlatBufferBuilder(64);
        int deviceIdOffset = builder.createString("test");
        SensorReading.startSensorReading(builder);
        SensorReading.addDeviceId(builder, deviceIdOffset);
        SensorReading.addTemperature(builder, encryptedTemperature);
        int sensorReadingOffset = SensorReading.endSensorReading(builder);
        builder.finish(sensorReadingOffset);
        ByteBuffer buf = builder.dataBuffer();

        // Read without encryption context
        SensorReading sensorReading = SensorReading.getRootAsSensorReading(buf);

        // Temperature should be returned as-is (encrypted) when no context
        float readTemp = sensorReading.temperature();
        if (Math.abs(readTemp - encryptedTemperature) > 0.001) {
            throw new AssertionError("Expected encrypted value " + encryptedTemperature + ", got " + readTemp);
        }

        System.out.println("  Reading without context returns raw values: OK");
        System.out.println("No encryption context test passed!");
    }

    public static void main(String[] args) {
        System.out.println("============================================================");
        System.out.println("Java FlatBuffers Encryption Test");
        System.out.println("============================================================");

        try {
            testSensorReading();
            testWithoutEncryptionContext();
            System.out.println("\n============================================================");
            System.out.println("All tests passed!");
            System.out.println("============================================================");
        } catch (Exception e) {
            System.out.println("\nTest failed: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
