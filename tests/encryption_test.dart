/// Native encryption test for Dart FlatBuffers code generation.
/// Tests that encrypted fields can be correctly decrypted using the generated code.

import 'dart:typed_data';
import 'package:flat_buffers/flat_buffers.dart' as fb;
import 'package:pointycastle/export.dart';

import 'dart_gen/encryption_test_encryption_test_generated.dart';

/// Derive a 16-byte nonce from encryption context and field offset.
Uint8List deriveNonce(Uint8List ctx, int fieldOffset) {
  final nonce = Uint8List(16);
  nonce.setRange(0, 12, ctx);
  // Little-endian field offset
  nonce[12] = fieldOffset & 0xFF;
  nonce[13] = (fieldOffset >> 8) & 0xFF;
  nonce[14] = (fieldOffset >> 16) & 0xFF;
  nonce[15] = (fieldOffset >> 24) & 0xFF;
  return nonce;
}

/// Encrypt bytes using AES-256-CTR.
Uint8List encryptBytes(Uint8List data, Uint8List ctx, int fieldOffset) {
  final key = ctx.sublist(0, 32);
  final nonce = deriveNonce(ctx, fieldOffset);
  final cipher = CTRStreamCipher(AESEngine())
    ..init(true, ParametersWithIV(KeyParameter(key), nonce));
  return cipher.process(data);
}

/// Encrypt a float32 value.
double encryptFloat32(double value, Uint8List ctx, int fieldOffset) {
  final data = Uint8List(4);
  data.buffer.asByteData().setFloat32(0, value, Endian.little);
  final encrypted = encryptBytes(data, ctx, fieldOffset);
  return encrypted.buffer.asByteData().getFloat32(0, Endian.little);
}

/// Encrypt a string value.
Uint8List encryptString(String value, Uint8List ctx, int fieldOffset) {
  final data = Uint8List.fromList(value.codeUnits);
  return encryptBytes(data, ctx, fieldOffset);
}

void testSensorReading() {
  print('Testing SensorReading with encrypted fields...');

  // Create encryption context (48 bytes)
  final encryptionCtx = Uint8List.fromList(List.generate(48, (i) => i));

  // Original values
  final originalDeviceId = 'sensor-001';
  final originalTimestamp = 1234567890;
  final originalTemperature = 23.5;
  final originalSecretMessage = 'Hello, World!';

  // Field offsets (from generated code)
  final temperatureOffset = 12;
  final secretMessageOffset = 16;

  // Encrypt values
  final encryptedTemperature = encryptFloat32(originalTemperature, encryptionCtx, temperatureOffset);
  final encryptedSecretMessage = encryptString(originalSecretMessage, encryptionCtx, secretMessageOffset);

  // Build the FlatBuffer
  final builder = fb.Builder();

  final deviceIdOffset = builder.writeString(originalDeviceId);

  // Write encrypted secret message as a byte vector
  final secretMessageVectorOffset = builder.writeListUint8(encryptedSecretMessage.toList());

  // Build the table
  builder.startTable(8);
  builder.addOffset(0, deviceIdOffset);
  builder.addUint64(1, originalTimestamp);
  builder.addFloat32(4, encryptedTemperature);
  builder.addOffset(6, secretMessageVectorOffset);
  final sensorReadingOffset = builder.endTable();

  builder.finish(sensorReadingOffset);
  final bytes = builder.buffer;

  // Read back using generated code with encryption context
  final sensorReading = SensorReading.withEncryption(bytes, encryptionCtx);

  // Verify public fields
  if (sensorReading.deviceId != originalDeviceId) {
    throw Exception('Device ID mismatch: ${sensorReading.deviceId} != $originalDeviceId');
  }
  if (sensorReading.timestamp != originalTimestamp) {
    throw Exception('Timestamp mismatch: ${sensorReading.timestamp} != $originalTimestamp');
  }

  // Verify encrypted fields are correctly decrypted
  final decryptedTemperature = sensorReading.temperature;
  if ((decryptedTemperature - originalTemperature).abs() > 0.001) {
    throw Exception('Temperature mismatch: $decryptedTemperature != $originalTemperature');
  }

  final decryptedSecretMessage = sensorReading.secretMessage;
  if (decryptedSecretMessage != originalSecretMessage) {
    throw Exception('Secret message mismatch: $decryptedSecretMessage != $originalSecretMessage');
  }

  print('  Device ID: OK');
  print('  Timestamp: OK');
  print('  Temperature (encrypted): OK');
  print('  Secret Message (encrypted): OK');
  print('SensorReading test passed!');
}

void testWithoutEncryptionContext() {
  print('\nTesting reading without encryption context...');

  final encryptionCtx = Uint8List.fromList(List.generate(48, (i) => i));

  final originalTemperature = 23.5;
  final temperatureOffset = 12;
  final encryptedTemperature = encryptFloat32(originalTemperature, encryptionCtx, temperatureOffset);

  // Build the FlatBuffer
  final builder = fb.Builder();
  final deviceIdOffset = builder.writeString('test');

  builder.startTable(8);
  builder.addOffset(0, deviceIdOffset);
  builder.addFloat32(4, encryptedTemperature);
  final sensorReadingOffset = builder.endTable();

  builder.finish(sensorReadingOffset);
  final bytes = builder.buffer;

  // Read without encryption context
  final sensorReading = SensorReading(bytes);

  // Temperature should be returned as-is (encrypted) when no context
  final readTemp = sensorReading.temperature;
  if ((readTemp - encryptedTemperature).abs() > 0.001) {
    throw Exception('Expected encrypted value $encryptedTemperature, got $readTemp');
  }

  print('  Reading without context returns raw values: OK');
  print('No encryption context test passed!');
}

void main() {
  print('============================================================');
  print('Dart FlatBuffers Encryption Test');
  print('============================================================');

  try {
    testSensorReading();
    testWithoutEncryptionContext();
    print('\n============================================================');
    print('All tests passed!');
    print('============================================================');
  } catch (e, st) {
    print('\nTest failed: $e');
    print(st);
    throw e;
  }
}
