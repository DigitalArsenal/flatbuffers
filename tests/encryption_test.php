<?php
/**
 * Native encryption test for PHP FlatBuffers code generation.
 * Tests that encrypted fields can be correctly decrypted using the generated code.
 */

// Include paths
require_once __DIR__ . '/../php/ByteBuffer.php';
require_once __DIR__ . '/../php/FlatbufferBuilder.php';
require_once __DIR__ . '/../php/Table.php';
require_once __DIR__ . '/../php/Struct.php';
require_once __DIR__ . '/../php/Constants.php';
require_once __DIR__ . '/php_gen/EncryptionTest/SensorReading.php';
require_once __DIR__ . '/php_gen/EncryptionTest/FlatbuffersEncryption.php';

use Google\FlatBuffers\ByteBuffer;
use Google\FlatBuffers\FlatbufferBuilder;
use EncryptionTest\SensorReading;
use EncryptionTest\FlatbuffersEncryption;

/**
 * Derive a 16-byte nonce from encryption context and field offset.
 */
function deriveNonce($ctx, $fieldOffset) {
    $nonce = substr($ctx, 0, 12);
    $nonce .= pack('V', $fieldOffset); // Little-endian 4-byte int
    return $nonce;
}

/**
 * Encrypt bytes using AES-256-CTR (same as decrypt for CTR mode).
 */
function encryptBytes($data, $ctx, $fieldOffset) {
    $key = substr($ctx, 0, 32);
    $nonce = deriveNonce($ctx, $fieldOffset);
    return openssl_encrypt($data, 'aes-256-ctr', $key, OPENSSL_RAW_DATA, $nonce);
}

/**
 * Encrypt a float value.
 */
function encryptFloat($value, $ctx, $fieldOffset) {
    $data = pack('g', $value);
    $encrypted = encryptBytes($data, $ctx, $fieldOffset);
    return unpack('g', $encrypted)[1];
}

/**
 * Encrypt a string value.
 */
function encryptString($value, $ctx, $fieldOffset) {
    return encryptBytes($value, $ctx, $fieldOffset);
}

function testSensorReading() {
    echo "Testing SensorReading with encrypted fields...\n";

    // Create encryption context (48 bytes)
    $encryptionCtx = '';
    for ($i = 0; $i < 48; $i++) {
        $encryptionCtx .= chr($i);
    }

    // Original values
    $originalDeviceId = "sensor-001";
    $originalTimestamp = 1234567890;
    $originalTemperature = 23.5;
    $originalSecretMessage = "Hello, World!";

    // Field offsets
    $temperatureOffset = 12;
    $secretMessageOffset = 16;

    // Encrypt values
    $encryptedTemperature = encryptFloat($originalTemperature, $encryptionCtx, $temperatureOffset);
    $encryptedSecretMessage = encryptString($originalSecretMessage, $encryptionCtx, $secretMessageOffset);

    // Build the FlatBuffer
    $builder = new FlatbufferBuilder(256);

    // Create string for device_id (not encrypted)
    $deviceIdOffset = $builder->createString($originalDeviceId);

    // Create encrypted secret message as byte vector
    // Note: For encrypted strings, we store the raw bytes as a vector
    $builder->startVector(1, strlen($encryptedSecretMessage), 1);
    for ($i = strlen($encryptedSecretMessage) - 1; $i >= 0; $i--) {
        $builder->putByte(ord($encryptedSecretMessage[$i]));
    }
    $secretMessageVectorOffset = $builder->endVector();

    // Start building the table
    SensorReading::startSensorReading($builder);
    SensorReading::addDeviceId($builder, $deviceIdOffset);
    SensorReading::addTimestamp($builder, $originalTimestamp);
    SensorReading::addTemperature($builder, $encryptedTemperature);
    SensorReading::addSecretMessage($builder, $secretMessageVectorOffset);
    $sensorReadingOffset = SensorReading::endSensorReading($builder);

    $builder->finish($sensorReadingOffset);
    $buf = $builder->dataBuffer();

    // Read back using generated code with encryption context
    $sensorReading = SensorReading::getRootAsSensorReadingWithEncryption($buf, $encryptionCtx);

    // Verify public fields
    if ($sensorReading->getDeviceId() !== $originalDeviceId) {
        throw new Exception("Device ID mismatch: " . $sensorReading->getDeviceId() . " != $originalDeviceId");
    }
    if ($sensorReading->getTimestamp() != $originalTimestamp) {
        throw new Exception("Timestamp mismatch: " . $sensorReading->getTimestamp() . " != $originalTimestamp");
    }

    // Verify encrypted fields are correctly decrypted
    $decryptedTemperature = $sensorReading->getTemperature();
    if (abs($decryptedTemperature - $originalTemperature) > 0.001) {
        throw new Exception("Temperature mismatch: $decryptedTemperature != $originalTemperature");
    }

    $decryptedSecretMessage = $sensorReading->getSecretMessage();
    if ($decryptedSecretMessage !== $originalSecretMessage) {
        throw new Exception("Secret message mismatch: $decryptedSecretMessage != $originalSecretMessage");
    }

    echo "  Device ID: OK\n";
    echo "  Timestamp: OK\n";
    echo "  Temperature (encrypted): OK\n";
    echo "  Secret Message (encrypted): OK\n";
    echo "SensorReading test passed!\n";
}

function testWithoutEncryptionContext() {
    echo "\nTesting reading without encryption context...\n";

    // Create encryption context
    $encryptionCtx = '';
    for ($i = 0; $i < 48; $i++) {
        $encryptionCtx .= chr($i);
    }

    $originalTemperature = 23.5;
    $temperatureOffset = 12;
    $encryptedTemperature = encryptFloat($originalTemperature, $encryptionCtx, $temperatureOffset);

    // Build the FlatBuffer
    $builder = new FlatbufferBuilder(64);
    $deviceIdOffset = $builder->createString("test");
    SensorReading::startSensorReading($builder);
    SensorReading::addDeviceId($builder, $deviceIdOffset);
    SensorReading::addTemperature($builder, $encryptedTemperature);
    $sensorReadingOffset = SensorReading::endSensorReading($builder);
    $builder->finish($sensorReadingOffset);
    $buf = $builder->dataBuffer();

    // Read without encryption context
    $sensorReading = SensorReading::getRootAsSensorReading($buf);

    // Temperature should be returned as-is (encrypted) when no context
    $readTemp = $sensorReading->getTemperature();
    if (abs($readTemp - $encryptedTemperature) > 0.001) {
        throw new Exception("Expected encrypted value $encryptedTemperature, got $readTemp");
    }

    echo "  Reading without context returns raw values: OK\n";
    echo "No encryption context test passed!\n";
}

// Main
echo "============================================================\n";
echo "PHP FlatBuffers Encryption Test\n";
echo "============================================================\n";

try {
    testSensorReading();
    testWithoutEncryptionContext();
    echo "\n============================================================\n";
    echo "All tests passed!\n";
    echo "============================================================\n";
} catch (Exception $e) {
    echo "\nTest failed: " . $e->getMessage() . "\n";
    echo $e->getTraceAsString() . "\n";
    exit(1);
}
