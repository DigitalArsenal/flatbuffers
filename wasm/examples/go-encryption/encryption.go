// Package encryption provides FlatBuffers field-level encryption for Go.
//
// This package implements the same encryption algorithm as the JavaScript
// flatc-wasm module, ensuring 100% cross-language compatibility.
//
// Data encrypted in Go can be decrypted in JavaScript/Node.js/Python
// and vice versa.
package encryption

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
)

// AES S-box for encryption
var sbox = [256]byte{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
	0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
	0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
	0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
	0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
	0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
	0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
	0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
	0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
	0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
	0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
	0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
	0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
	0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
	0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
	0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
	0xb0, 0x54, 0xbb, 0x16,
}

// AES round constants
var rcon = [11]byte{0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36}

// gfMul performs GF(2^8) multiplication
func gfMul(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			p ^= a
		}
		hiBit := a & 0x80
		a <<= 1
		if hiBit != 0 {
			a ^= 0x1b
		}
		b >>= 1
	}
	return p
}

// aes256KeyExpansion expands AES-256 key to round keys
func aes256KeyExpansion(key []byte) []byte {
	roundKeys := make([]byte, 240)
	copy(roundKeys, key)

	temp := make([]byte, 4)
	i := 8

	for i < 60 {
		copy(temp, roundKeys[(i-1)*4:i*4])

		if i%8 == 0 {
			// RotWord + SubWord + Rcon
			t := temp[0]
			temp[0] = sbox[temp[1]] ^ rcon[i/8]
			temp[1] = sbox[temp[2]]
			temp[2] = sbox[temp[3]]
			temp[3] = sbox[t]
		} else if i%8 == 4 {
			temp[0] = sbox[temp[0]]
			temp[1] = sbox[temp[1]]
			temp[2] = sbox[temp[2]]
			temp[3] = sbox[temp[3]]
		}

		for j := 0; j < 4; j++ {
			roundKeys[i*4+j] = roundKeys[(i-8)*4+j] ^ temp[j]
		}
		i++
	}

	return roundKeys
}

// subBytes performs AES SubBytes transformation
func subBytes(state []byte) {
	for i := 0; i < 16; i++ {
		state[i] = sbox[state[i]]
	}
}

// shiftRows performs AES ShiftRows transformation
func shiftRows(state []byte) {
	// Row 1: shift left by 1
	temp := state[1]
	state[1] = state[5]
	state[5] = state[9]
	state[9] = state[13]
	state[13] = temp
	// Row 2: shift left by 2
	temp = state[2]
	state[2] = state[10]
	state[10] = temp
	temp = state[6]
	state[6] = state[14]
	state[14] = temp
	// Row 3: shift left by 3
	temp = state[15]
	state[15] = state[11]
	state[11] = state[7]
	state[7] = state[3]
	state[3] = temp
}

// mixColumns performs AES MixColumns transformation
func mixColumns(state []byte) {
	for i := 0; i < 4; i++ {
		a := []byte{state[i*4], state[i*4+1], state[i*4+2], state[i*4+3]}
		state[i*4+0] = gfMul(a[0], 2) ^ gfMul(a[1], 3) ^ a[2] ^ a[3]
		state[i*4+1] = a[0] ^ gfMul(a[1], 2) ^ gfMul(a[2], 3) ^ a[3]
		state[i*4+2] = a[0] ^ a[1] ^ gfMul(a[2], 2) ^ gfMul(a[3], 3)
		state[i*4+3] = gfMul(a[0], 3) ^ a[1] ^ a[2] ^ gfMul(a[3], 2)
	}
}

// addRoundKey performs AES AddRoundKey transformation
func addRoundKey(state, roundKey []byte) {
	for i := 0; i < 16; i++ {
		state[i] ^= roundKey[i]
	}
}

// aesEncryptBlock encrypts a single 16-byte block with AES-256
func aesEncryptBlock(key, input []byte) []byte {
	roundKeys := aes256KeyExpansion(key)
	state := make([]byte, 16)
	copy(state, input)

	addRoundKey(state, roundKeys[:16])

	for round := 1; round < 14; round++ {
		subBytes(state)
		shiftRows(state)
		mixColumns(state)
		addRoundKey(state, roundKeys[round*16:(round+1)*16])
	}

	subBytes(state)
	shiftRows(state)
	addRoundKey(state, roundKeys[14*16:15*16])

	return state
}

// aesCtrKeystream generates AES-CTR keystream
func aesCtrKeystream(key, nonce []byte, length int) []byte {
	keystream := make([]byte, length)
	counter := make([]byte, 16)
	copy(counter, nonce)

	offset := 0
	for offset < length {
		block := aesEncryptBlock(key, counter)
		toCopy := 16
		if length-offset < 16 {
			toCopy = length - offset
		}
		copy(keystream[offset:], block[:toCopy])
		offset += toCopy

		// Increment counter (big-endian)
		for i := 15; i >= 0; i-- {
			counter[i]++
			if counter[i] != 0 {
				break
			}
		}
	}

	return keystream
}

// deriveKey performs HKDF-like key derivation (matches JavaScript)
func deriveKey(masterKey, info []byte, outLength int) []byte {
	out := make([]byte, outLength)

	// Mix master key into output
	copyLen := outLength
	if len(masterKey) < copyLen {
		copyLen = len(masterKey)
	}
	copy(out, masterKey[:copyLen])

	// Mix info using a simple hash-like operation
	var hash byte
	for _, b := range info {
		hash ^= b
		hash = (hash << 1) | (hash >> 7)
	}

	// Apply info hash to derive different keys
	for i := 0; i < outLength; i++ {
		out[i] ^= hash
		hash = byte((int(hash)*31 + i) & 0xff)
	}

	// Additional mixing pass using AES
	if outLength >= 16 {
		temp := aesEncryptBlock(masterKey, out[:16])
		mixLen := 16
		if outLength < 16 {
			mixLen = outLength
		}
		copy(out, temp[:mixLen])
		if outLength > 16 {
			temp2 := aesEncryptBlock(masterKey, temp)
			remainLen := 16
			if outLength-16 < 16 {
				remainLen = outLength - 16
			}
			copy(out[16:], temp2[:remainLen])
		}
	}

	return out
}

// EncryptionContext holds encryption state for FlatBuffer field encryption
type EncryptionContext struct {
	key   []byte
	valid bool
}

// NewEncryptionContext creates an EncryptionContext from a 32-byte key
func NewEncryptionContext(key []byte) *EncryptionContext {
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	return &EncryptionContext{
		key:   keyCopy,
		valid: len(key) == 32,
	}
}

// NewEncryptionContextFromHex creates an EncryptionContext from a hex string
func NewEncryptionContextFromHex(hexKey string) (*EncryptionContext, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, err
	}
	return NewEncryptionContext(key), nil
}

// IsValid returns whether the context has a valid key
func (ctx *EncryptionContext) IsValid() bool {
	return ctx.valid
}

// DeriveFieldKey derives a field-specific 32-byte key
func (ctx *EncryptionContext) DeriveFieldKey(fieldID int) []byte {
	// Build info bytes exactly like JavaScript
	info := make([]byte, 19)
	copy(info, "flatbuffers-field")
	info[17] = byte((fieldID >> 8) & 0xff)
	info[18] = byte(fieldID & 0xff)
	return deriveKey(ctx.key, info, 32)
}

// DeriveFieldIV derives a field-specific 16-byte IV
func (ctx *EncryptionContext) DeriveFieldIV(fieldID int) []byte {
	// Build info bytes exactly like JavaScript
	info := make([]byte, 16)
	copy(info, "flatbuffers-iv")
	info[14] = byte((fieldID >> 8) & 0xff)
	info[15] = byte(fieldID & 0xff)
	return deriveKey(ctx.key, info, 16)
}

// EncryptBytes encrypts bytes in-place using AES-CTR
func EncryptBytes(data, key, iv []byte) {
	keystream := aesCtrKeystream(key, iv, len(data))
	for i := range data {
		data[i] ^= keystream[i]
	}
}

// DecryptBytes decrypts bytes in-place (same as encrypt for AES-CTR)
var DecryptBytes = EncryptBytes

// FieldInfo holds parsed field information from schema
type FieldInfo struct {
	Name        string
	ID          int
	Type        string
	Encrypted   bool
	ElementType string
	ElementSize int
	StructSize  int
}

// getTypeSize returns the size of a scalar type
func getTypeSize(typeName string) int {
	switch typeName {
	case "bool", "byte", "ubyte":
		return 1
	case "short", "ushort":
		return 2
	case "int", "uint", "float":
		return 4
	case "long", "ulong", "double":
		return 8
	default:
		return 0
	}
}

// getBaseType returns the base type category
func getBaseType(typeName string) string {
	switch typeName {
	case "bool", "byte", "ubyte", "short", "ushort",
		"int", "uint", "long", "ulong", "float", "double":
		return typeName
	case "string":
		return "string"
	default:
		return "struct"
	}
}

// ParseSchemaForEncryption extracts field encryption info from schema
func ParseSchemaForEncryption(schemaContent, rootType string) []FieldInfo {
	var fields []FieldInfo

	// Find the root table definition
	pattern := regexp.MustCompile(`table\s+` + regexp.QuoteMeta(rootType) + `\s*\{([^}]+)\}`)
	match := pattern.FindStringSubmatch(schemaContent)
	if match == nil {
		return fields
	}

	tableBody := match[1]
	fieldPattern := regexp.MustCompile(`(\w+)\s*:\s*(\[?\w+\]?)\s*(?:\(([^)]*)\))?`)

	fieldID := 0
	for _, fieldMatch := range fieldPattern.FindAllStringSubmatch(tableBody, -1) {
		name := fieldMatch[1]
		fieldType := fieldMatch[2]
		attributes := ""
		if len(fieldMatch) > 3 {
			attributes = fieldMatch[3]
		}

		isEncrypted := strings.Contains(attributes, "encrypted")
		isVector := strings.HasPrefix(fieldType, "[") && strings.HasSuffix(fieldType, "]")
		baseType := fieldType
		if isVector {
			baseType = fieldType[1 : len(fieldType)-1]
		}

		field := FieldInfo{
			Name:      name,
			ID:        fieldID,
			Encrypted: isEncrypted,
		}

		if isVector {
			field.Type = "vector"
			field.ElementType = getBaseType(baseType)
			field.ElementSize = getTypeSize(baseType)
		} else {
			field.Type = getBaseType(baseType)
		}

		fields = append(fields, field)
		fieldID++
	}

	return fields
}

// processTable processes a FlatBuffer table, encrypting marked fields
func processTable(buffer []byte, tableOffset int, fields []FieldInfo, ctx *EncryptionContext) {
	// Read vtable offset (signed, relative)
	vtableOffsetDelta := int32(binary.LittleEndian.Uint32(buffer[tableOffset:]))
	vtableOffset := tableOffset - int(vtableOffsetDelta)

	// Read vtable size
	vtableSize := int(binary.LittleEndian.Uint16(buffer[vtableOffset:]))

	for _, field := range fields {
		fieldVtableIdx := (field.ID + 2) * 2

		if fieldVtableIdx >= vtableSize {
			continue
		}

		fieldOffset := int(binary.LittleEndian.Uint16(buffer[vtableOffset+fieldVtableIdx:]))
		if fieldOffset == 0 {
			continue
		}

		fieldLoc := tableOffset + fieldOffset

		if !field.Encrypted {
			continue
		}

		// Derive keys for this field
		key := ctx.DeriveFieldKey(field.ID)
		iv := ctx.DeriveFieldIV(field.ID)

		// Encrypt based on type
		switch field.Type {
		case "bool", "byte", "ubyte":
			encryptRegion(buffer, fieldLoc, 1, key, iv)
		case "short", "ushort":
			encryptRegion(buffer, fieldLoc, 2, key, iv)
		case "int", "uint", "float":
			encryptRegion(buffer, fieldLoc, 4, key, iv)
		case "long", "ulong", "double":
			encryptRegion(buffer, fieldLoc, 8, key, iv)
		case "string":
			stringOffset := int(binary.LittleEndian.Uint32(buffer[fieldLoc:]))
			stringLoc := fieldLoc + stringOffset
			stringLen := int(binary.LittleEndian.Uint32(buffer[stringLoc:]))
			stringData := stringLoc + 4
			if stringData+stringLen <= len(buffer) {
				encryptRegion(buffer, stringData, stringLen, key, iv)
			}
		case "vector":
			vecOffset := int(binary.LittleEndian.Uint32(buffer[fieldLoc:]))
			vecLoc := fieldLoc + vecOffset
			vecLen := int(binary.LittleEndian.Uint32(buffer[vecLoc:]))
			vecData := vecLoc + 4
			elemSize := field.ElementSize
			if elemSize == 0 {
				elemSize = 1
			}
			totalSize := vecLen * elemSize
			if vecData+totalSize <= len(buffer) {
				encryptRegion(buffer, vecData, totalSize, key, iv)
			}
		case "struct":
			if field.StructSize > 0 && fieldLoc+field.StructSize <= len(buffer) {
				encryptRegion(buffer, fieldLoc, field.StructSize, key, iv)
			}
		}
	}
}

// encryptRegion encrypts a region of the buffer in-place
func encryptRegion(buffer []byte, start, length int, key, iv []byte) {
	keystream := aesCtrKeystream(key, iv, length)
	for i := 0; i < length; i++ {
		buffer[start+i] ^= keystream[i]
	}
}

// EncryptBuffer encrypts a FlatBuffer
func EncryptBuffer(buffer []byte, schemaContent string, key []byte, rootType string) ([]byte, error) {
	ctx := NewEncryptionContext(key)
	return EncryptBufferWithContext(buffer, schemaContent, ctx, rootType)
}

// EncryptBufferWithContext encrypts a FlatBuffer using an existing context
func EncryptBufferWithContext(buffer []byte, schemaContent string, ctx *EncryptionContext, rootType string) ([]byte, error) {
	if !ctx.IsValid() {
		return nil, errors.New("invalid encryption key (must be 32 bytes)")
	}

	fields := ParseSchemaForEncryption(schemaContent, rootType)
	result := make([]byte, len(buffer))
	copy(result, buffer)

	// Read root table offset
	rootOffset := int(binary.LittleEndian.Uint32(result))

	processTable(result, rootOffset, fields, ctx)

	return result, nil
}

// DecryptBuffer decrypts a FlatBuffer (same as encrypt for AES-CTR)
func DecryptBuffer(buffer []byte, schemaContent string, key []byte, rootType string) ([]byte, error) {
	return EncryptBuffer(buffer, schemaContent, key, rootType)
}

// DecryptBufferWithContext decrypts a FlatBuffer using an existing context
func DecryptBufferWithContext(buffer []byte, schemaContent string, ctx *EncryptionContext, rootType string) ([]byte, error) {
	return EncryptBufferWithContext(buffer, schemaContent, ctx, rootType)
}
