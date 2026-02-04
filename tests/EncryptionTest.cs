/**
 * Native encryption test for C# FlatBuffers code generation.
 * Tests that encrypted fields can be correctly decrypted using the generated code.
 */

using System;
using System.Security.Cryptography;
using System.Text;
using Google.FlatBuffers;
using EncryptionTest;

public class EncryptionTestRunner
{
    // Derive a 16-byte nonce from encryption context and field offset
    private static byte[] DeriveNonce(byte[] ctx, int fieldOffset)
    {
        var nonce = new byte[16];
        Array.Copy(ctx, 0, nonce, 0, 12);
        nonce[12] = (byte)(fieldOffset & 0xFF);
        nonce[13] = (byte)((fieldOffset >> 8) & 0xFF);
        nonce[14] = (byte)((fieldOffset >> 16) & 0xFF);
        nonce[15] = (byte)((fieldOffset >> 24) & 0xFF);
        return nonce;
    }

    // Encrypt bytes using AES-256-CTR
    private static byte[] EncryptBytes(byte[] data, byte[] ctx, int fieldOffset)
    {
        var key = new byte[32];
        Array.Copy(ctx, 0, key, 0, 32);
        var nonce = DeriveNonce(ctx, fieldOffset);

        using (var aes = Aes.Create())
        {
            aes.Key = key;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            var result = new byte[data.Length];
            var counter = (byte[])nonce.Clone();
            var encryptor = aes.CreateEncryptor();
            for (int i = 0; i < data.Length; i += 16)
            {
                var keystream = new byte[16];
                encryptor.TransformBlock(counter, 0, 16, keystream, 0);
                int blockLen = Math.Min(16, data.Length - i);
                for (int j = 0; j < blockLen; j++)
                    result[i + j] = (byte)(data[i + j] ^ keystream[j]);
                // Increment counter
                for (int k = 15; k >= 0; k--)
                    if (++counter[k] != 0) break;
            }
            return result;
        }
    }

    // Encrypt a float value
    private static float EncryptFloat(float value, byte[] ctx, int fieldOffset)
    {
        var data = BitConverter.GetBytes(value);
        var encrypted = EncryptBytes(data, ctx, fieldOffset);
        return BitConverter.ToSingle(encrypted, 0);
    }

    // Encrypt a string value
    private static byte[] EncryptString(string value, byte[] ctx, int fieldOffset)
    {
        var data = Encoding.UTF8.GetBytes(value);
        return EncryptBytes(data, ctx, fieldOffset);
    }

    private static void TestSensorReading()
    {
        Console.WriteLine("Testing SensorReading with encrypted fields...");

        // Create encryption context (48 bytes)
        var encryptionCtx = new byte[48];
        for (int i = 0; i < 48; i++)
        {
            encryptionCtx[i] = (byte)i;
        }

        // Original values
        var originalDeviceId = "sensor-001";
        var originalTimestamp = 1234567890UL;
        var originalTemperature = 23.5f;
        var originalSecretMessage = "Hello, World!";

        // Field offsets
        var temperatureOffset = 12;
        var secretMessageOffset = 16;

        // Encrypt values
        var encryptedTemperature = EncryptFloat(originalTemperature, encryptionCtx, temperatureOffset);
        var encryptedSecretMessage = EncryptString(originalSecretMessage, encryptionCtx, secretMessageOffset);

        // Build the FlatBuffer
        var builder = new FlatBufferBuilder(256);

        var deviceIdOffset = builder.CreateString(originalDeviceId);
        var secretMessageVectorOffset = SensorReading.CreateRawDataVector(builder, encryptedSecretMessage);

        SensorReading.StartSensorReading(builder);
        SensorReading.AddDeviceId(builder, deviceIdOffset);
        SensorReading.AddTimestamp(builder, originalTimestamp);
        SensorReading.AddTemperature(builder, encryptedTemperature);
        SensorReading.AddSecretMessage(builder, new StringOffset(secretMessageVectorOffset.Value));
        var sensorReadingOffset = SensorReading.EndSensorReading(builder);

        builder.Finish(sensorReadingOffset.Value);
        var buf = builder.DataBuffer;

        // Read back using generated code with encryption context
        var sensorReading = SensorReading.GetRootAsSensorReading(buf, encryptionCtx);

        // Verify public fields
        if (sensorReading.DeviceId != originalDeviceId)
        {
            throw new Exception($"Device ID mismatch: {sensorReading.DeviceId} != {originalDeviceId}");
        }
        if (sensorReading.Timestamp != originalTimestamp)
        {
            throw new Exception($"Timestamp mismatch: {sensorReading.Timestamp} != {originalTimestamp}");
        }

        // Verify encrypted fields are correctly decrypted
        var decryptedTemperature = sensorReading.Temperature;
        if (Math.Abs(decryptedTemperature - originalTemperature) > 0.001)
        {
            throw new Exception($"Temperature mismatch: {decryptedTemperature} != {originalTemperature}");
        }

        var decryptedSecretMessage = sensorReading.SecretMessage;
        if (decryptedSecretMessage != originalSecretMessage)
        {
            throw new Exception($"Secret message mismatch: {decryptedSecretMessage} != {originalSecretMessage}");
        }

        Console.WriteLine("  Device ID: OK");
        Console.WriteLine("  Timestamp: OK");
        Console.WriteLine("  Temperature (encrypted): OK");
        Console.WriteLine("  Secret Message (encrypted): OK");
        Console.WriteLine("SensorReading test passed!");
    }

    private static void TestWithoutEncryptionContext()
    {
        Console.WriteLine("\nTesting reading without encryption context...");

        var encryptionCtx = new byte[48];
        for (int i = 0; i < 48; i++)
        {
            encryptionCtx[i] = (byte)i;
        }

        var originalTemperature = 23.5f;
        var temperatureOffset = 12;
        var encryptedTemperature = EncryptFloat(originalTemperature, encryptionCtx, temperatureOffset);

        var builder = new FlatBufferBuilder(64);
        var deviceIdOffset = builder.CreateString("test");
        SensorReading.StartSensorReading(builder);
        SensorReading.AddDeviceId(builder, deviceIdOffset);
        SensorReading.AddTemperature(builder, encryptedTemperature);
        var sensorReadingOffset = SensorReading.EndSensorReading(builder);
        builder.Finish(sensorReadingOffset.Value);
        var buf = builder.DataBuffer;

        // Read without encryption context
        var sensorReading = SensorReading.GetRootAsSensorReading(buf);

        // Temperature should be returned as-is (encrypted) when no context
        var readTemp = sensorReading.Temperature;
        if (Math.Abs(readTemp - encryptedTemperature) > 0.001)
        {
            throw new Exception($"Expected encrypted value {encryptedTemperature}, got {readTemp}");
        }

        Console.WriteLine("  Reading without context returns raw values: OK");
        Console.WriteLine("No encryption context test passed!");
    }

    public static int Main(string[] args)
    {
        Console.WriteLine(new string('=', 60));
        Console.WriteLine("C# FlatBuffers Encryption Test");
        Console.WriteLine(new string('=', 60));

        try
        {
            TestSensorReading();
            TestWithoutEncryptionContext();
            Console.WriteLine("\n" + new string('=', 60));
            Console.WriteLine("All tests passed!");
            Console.WriteLine(new string('=', 60));
            return 0;
        }
        catch (Exception e)
        {
            Console.WriteLine($"\nTest failed: {e.Message}");
            Console.Error.WriteLine(e);
            return 1;
        }
    }
}
