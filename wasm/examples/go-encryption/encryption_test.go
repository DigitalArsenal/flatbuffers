package encryption

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

const simpleSchema = `
table SimpleMessage {
  public_text: string;
  secret_number: int (encrypted);
  secret_text: string (encrypted);
}
root_type SimpleMessage;
`

const sensorSchema = `
table SensorReading {
  device_id: string;
  timestamp: uint64;
  temperature: float (encrypted);
  raw_data: [ubyte] (encrypted);
  secret_message: string (encrypted);
}
root_type SensorReading;
`

// createSimpleFlatBuffer creates a minimal FlatBuffer for SimpleMessage
func createSimpleFlatBuffer() []byte {
	buf := make([]byte, 64)

	// Root offset points to table at offset 16
	binary.LittleEndian.PutUint32(buf[0:], 16)

	// VTable at offset 4
	binary.LittleEndian.PutUint16(buf[4:], 10)  // vtable size
	binary.LittleEndian.PutUint16(buf[6:], 12)  // table size
	binary.LittleEndian.PutUint16(buf[8:], 4)   // field 0 offset
	binary.LittleEndian.PutUint16(buf[10:], 8)  // field 1 offset
	binary.LittleEndian.PutUint16(buf[12:], 0)  // field 2 not present

	// Table at offset 16: soffset to vtable
	binary.LittleEndian.PutUint32(buf[16:], 12) // 16 - 4 = 12

	// Field 0 (string offset) at table+4 = offset 20
	binary.LittleEndian.PutUint32(buf[20:], 12) // points to string at 32

	// Field 1 (int32) at table+8 = offset 24
	binary.LittleEndian.PutUint32(buf[24:], 42) // secret_number = 42

	// String at offset 32
	binary.LittleEndian.PutUint32(buf[32:], 5) // length
	copy(buf[36:], "hello")

	return buf
}

func TestEncryptionContextFromBytes(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	ctx := NewEncryptionContext(key)

	if !ctx.IsValid() {
		t.Error("context should be valid")
	}
}

func TestEncryptionContextFromHex(t *testing.T) {
	hexKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	ctx, err := NewEncryptionContextFromHex(hexKey)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !ctx.IsValid() {
		t.Error("context should be valid")
	}
}

func TestEncryptionContextInvalidSize(t *testing.T) {
	key := make([]byte, 16) // Too short
	ctx := NewEncryptionContext(key)

	if ctx.IsValid() {
		t.Error("context should be invalid")
	}
}

func TestDeriveDifferentKeys(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	ctx := NewEncryptionContext(key)

	key1 := ctx.DeriveFieldKey(1)
	key2 := ctx.DeriveFieldKey(2)

	if bytes.Equal(key1, key2) {
		t.Error("derived keys should differ")
	}
}

func TestEncryptDecryptBytes(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)

	original := []byte("Hello, World!")
	data := make([]byte, len(original))
	copy(data, original)

	EncryptBytes(data, key, iv)
	if bytes.Equal(data, original) {
		t.Error("data should change after encryption")
	}

	DecryptBytes(data, key, iv)
	if !bytes.Equal(data, original) {
		t.Error("data should match after decryption")
	}
}

func TestDifferentIVs(t *testing.T) {
	key := make([]byte, 32)
	iv1 := make([]byte, 16)
	iv2 := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv1)
	rand.Read(iv2)

	plaintext := []byte("Test data")
	data1 := make([]byte, len(plaintext))
	data2 := make([]byte, len(plaintext))
	copy(data1, plaintext)
	copy(data2, plaintext)

	EncryptBytes(data1, key, iv1)
	EncryptBytes(data2, key, iv2)

	if bytes.Equal(data1, data2) {
		t.Error("different IVs should produce different ciphertext")
	}
}

func TestParseSimpleSchema(t *testing.T) {
	fields := ParseSchemaForEncryption(simpleSchema, "SimpleMessage")
	if len(fields) != 3 {
		t.Errorf("expected 3 fields, got %d", len(fields))
	}

	var publicField, secretNum, secretText *FieldInfo
	for i := range fields {
		switch fields[i].Name {
		case "public_text":
			publicField = &fields[i]
		case "secret_number":
			secretNum = &fields[i]
		case "secret_text":
			secretText = &fields[i]
		}
	}

	if publicField == nil || publicField.Encrypted {
		t.Error("public_text should not be encrypted")
	}
	if secretNum == nil || !secretNum.Encrypted {
		t.Error("secret_number should be encrypted")
	}
	if secretText == nil || !secretText.Encrypted {
		t.Error("secret_text should be encrypted")
	}
}

func TestParseVectorFields(t *testing.T) {
	fields := ParseSchemaForEncryption(sensorSchema, "SensorReading")

	var rawData *FieldInfo
	for i := range fields {
		if fields[i].Name == "raw_data" {
			rawData = &fields[i]
			break
		}
	}

	if rawData == nil {
		t.Fatal("raw_data field not found")
	}
	if !rawData.Encrypted {
		t.Error("raw_data should be encrypted")
	}
	if rawData.Type != "vector" {
		t.Errorf("raw_data should be vector type, got %s", rawData.Type)
	}
}

func TestEncryptBufferChangesData(t *testing.T) {
	buf := createSimpleFlatBuffer()
	key := make([]byte, 32)
	rand.Read(key)

	encrypted, err := EncryptBuffer(buf, simpleSchema, key, "SimpleMessage")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if bytes.Equal(encrypted, buf) {
		t.Error("buffer should change after encryption")
	}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	buf := createSimpleFlatBuffer()
	key := make([]byte, 32)
	rand.Read(key)

	encrypted, err := EncryptBuffer(buf, simpleSchema, key, "SimpleMessage")
	if err != nil {
		t.Fatalf("encryption error: %v", err)
	}

	decrypted, err := DecryptBuffer(encrypted, simpleSchema, key, "SimpleMessage")
	if err != nil {
		t.Fatalf("decryption error: %v", err)
	}

	if !bytes.Equal(decrypted, buf) {
		t.Error("buffer should match after decrypt")
	}
}

func TestDifferentKeysDifferentCiphertext(t *testing.T) {
	buf := createSimpleFlatBuffer()
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	encrypted1, _ := EncryptBuffer(buf, simpleSchema, key1, "SimpleMessage")
	encrypted2, _ := EncryptBuffer(buf, simpleSchema, key2, "SimpleMessage")

	if bytes.Equal(encrypted1, encrypted2) {
		t.Error("different keys should produce different ciphertext")
	}
}

func TestWrongKeyWrongResult(t *testing.T) {
	buf := createSimpleFlatBuffer()
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	encrypted, _ := EncryptBuffer(buf, simpleSchema, key1, "SimpleMessage")
	wrongDecrypt, _ := DecryptBuffer(encrypted, simpleSchema, key2, "SimpleMessage")

	if bytes.Equal(wrongDecrypt, buf) {
		t.Error("wrong key should not decrypt correctly")
	}
}

func TestContextReuse(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	ctx := NewEncryptionContext(key)

	buf1 := createSimpleFlatBuffer()
	buf2 := createSimpleFlatBuffer()

	enc1, _ := EncryptBufferWithContext(buf1, simpleSchema, ctx, "SimpleMessage")
	enc2, _ := EncryptBufferWithContext(buf2, simpleSchema, ctx, "SimpleMessage")

	dec1, _ := DecryptBufferWithContext(enc1, simpleSchema, ctx, "SimpleMessage")
	dec2, _ := DecryptBufferWithContext(enc2, simpleSchema, ctx, "SimpleMessage")

	if !bytes.Equal(dec1, buf1) {
		t.Error("first buffer should decrypt correctly")
	}
	if !bytes.Equal(dec2, buf2) {
		t.Error("second buffer should decrypt correctly")
	}
}

func TestKeyDerivationConsistency(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	ctx1 := NewEncryptionContext(key)
	ctx2 := NewEncryptionContext(key)

	derived1 := ctx1.DeriveFieldKey(5)
	derived2 := ctx2.DeriveFieldKey(5)

	if !bytes.Equal(derived1, derived2) {
		t.Error("key derivation should be deterministic")
	}
}

func TestEncryptionIsDeterministic(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	ctx := NewEncryptionContext(key)

	buf := createSimpleFlatBuffer()

	enc1, _ := EncryptBufferWithContext(buf, simpleSchema, ctx, "SimpleMessage")
	enc2, _ := EncryptBufferWithContext(buf, simpleSchema, ctx, "SimpleMessage")

	if !bytes.Equal(enc1, enc2) {
		t.Error("encryption should be deterministic")
	}
}

func TestHexKeySameAsBytes(t *testing.T) {
	keyBytes, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	hexKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	ctxBytes := NewEncryptionContext(keyBytes)
	ctxHex, _ := NewEncryptionContextFromHex(hexKey)

	buf := createSimpleFlatBuffer()

	encBytes, _ := EncryptBufferWithContext(buf, simpleSchema, ctxBytes, "SimpleMessage")
	encHex, _ := EncryptBufferWithContext(buf, simpleSchema, ctxHex, "SimpleMessage")

	if !bytes.Equal(encBytes, encHex) {
		t.Error("hex and bytes keys should produce same result")
	}
}

func TestInvalidKeyReturnsError(t *testing.T) {
	buf := createSimpleFlatBuffer()
	key := make([]byte, 16) // Invalid size

	_, err := EncryptBuffer(buf, simpleSchema, key, "SimpleMessage")
	if err == nil {
		t.Error("expected error for invalid key size")
	}
}
