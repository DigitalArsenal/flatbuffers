package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// findWasmModule searches for the WASM module in expected locations
func findWasmModule() ([]byte, error) {
	// Try various possible locations
	paths := []string{
		"../../../build/wasm/wasm/flatc-encryption.wasm",
		"../../../build/wasm/flatc-encryption.wasm",
		"build/wasm/wasm/flatc-encryption.wasm",
		"build/wasm/flatc-encryption.wasm",
	}

	for _, p := range paths {
		absPath, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		data, err := os.ReadFile(absPath)
		if err == nil {
			return data, nil
		}
	}

	return nil, os.ErrNotExist
}

func TestEncryptionModule(t *testing.T) {
	wasmBytes, err := findWasmModule()
	if err != nil {
		t.Skip("WASM module not found - run 'cmake --build build/wasm --target flatc_wasm_wasi' first")
	}

	ctx := context.Background()

	em, err := NewEncryptionModule(ctx, wasmBytes)
	if err != nil {
		t.Fatalf("Failed to create encryption module: %v", err)
	}
	defer em.Close(ctx)

	// Test version
	t.Run("Version", func(t *testing.T) {
		version, err := em.Version(ctx)
		if err != nil {
			t.Fatalf("Failed to get version: %v", err)
		}
		t.Logf("Module version: %s", version)
		if version == "" {
			t.Error("Version should not be empty")
		}
	})

	// Test basic encrypt/decrypt
	t.Run("EncryptDecrypt", func(t *testing.T) {
		key := make([]byte, 32)
		rand.Read(key)

		iv := make([]byte, 16)
		rand.Read(iv)

		plaintext := []byte("Hello, FlatBuffers WASI encryption!")
		original := make([]byte, len(plaintext))
		copy(original, plaintext)

		// Encrypt
		err := em.EncryptBytes(ctx, key, iv, plaintext)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		t.Logf("Original:  %s", hex.EncodeToString(original))
		t.Logf("Encrypted: %s", hex.EncodeToString(plaintext))

		// Verify data changed
		same := true
		for i := range plaintext {
			if plaintext[i] != original[i] {
				same = false
				break
			}
		}
		if same {
			t.Error("Encrypted data should differ from original")
		}

		// Decrypt
		err = em.DecryptBytes(ctx, key, iv, plaintext)
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}

		t.Logf("Decrypted: %s", hex.EncodeToString(plaintext))
		t.Logf("As string: %s", string(plaintext))

		// Verify decrypted matches original
		for i := range plaintext {
			if plaintext[i] != original[i] {
				t.Errorf("Decrypted data mismatch at byte %d: got %02x, want %02x",
					i, plaintext[i], original[i])
			}
		}
	})

	// Test encryption context
	t.Run("EncryptionContext", func(t *testing.T) {
		key := make([]byte, 32)
		rand.Read(key)

		encCtx, err := em.NewEncryptionContext(ctx, key)
		if err != nil {
			t.Fatalf("Failed to create encryption context: %v", err)
		}
		defer encCtx.Close(ctx)

		// Test field key derivation
		fieldKey1, err := encCtx.DeriveFieldKey(ctx, 1)
		if err != nil {
			t.Fatalf("DeriveFieldKey failed: %v", err)
		}
		t.Logf("Field 1 key: %s", hex.EncodeToString(fieldKey1))

		fieldKey2, err := encCtx.DeriveFieldKey(ctx, 2)
		if err != nil {
			t.Fatalf("DeriveFieldKey failed: %v", err)
		}
		t.Logf("Field 2 key: %s", hex.EncodeToString(fieldKey2))

		// Field keys should be different
		same := true
		for i := range fieldKey1 {
			if fieldKey1[i] != fieldKey2[i] {
				same = false
				break
			}
		}
		if same {
			t.Error("Different field IDs should produce different keys")
		}

		// Test field IV derivation
		fieldIV1, err := encCtx.DeriveFieldIV(ctx, 1)
		if err != nil {
			t.Fatalf("DeriveFieldIV failed: %v", err)
		}
		t.Logf("Field 1 IV: %s", hex.EncodeToString(fieldIV1))

		if len(fieldIV1) != 16 {
			t.Errorf("IV should be 16 bytes, got %d", len(fieldIV1))
		}
	})

	// Test invalid inputs
	t.Run("InvalidInputs", func(t *testing.T) {
		// Wrong key size
		err := em.EncryptBytes(ctx, make([]byte, 16), make([]byte, 16), make([]byte, 10))
		if err == nil {
			t.Error("Should reject 16-byte key")
		}

		// Wrong IV size
		err = em.EncryptBytes(ctx, make([]byte, 32), make([]byte, 8), make([]byte, 10))
		if err == nil {
			t.Error("Should reject 8-byte IV")
		}

		// Invalid key for context
		_, err = em.NewEncryptionContext(ctx, make([]byte, 16))
		if err == nil {
			t.Error("Should reject 16-byte key for context")
		}
	})
}

// BenchmarkEncryption benchmarks encryption performance
func BenchmarkEncryption(b *testing.B) {
	wasmBytes, err := findWasmModule()
	if err != nil {
		b.Skip("WASM module not found")
	}

	ctx := context.Background()
	em, err := NewEncryptionModule(ctx, wasmBytes)
	if err != nil {
		b.Fatalf("Failed to create module: %v", err)
	}
	defer em.Close(ctx)

	key := make([]byte, 32)
	rand.Read(key)
	iv := make([]byte, 16)
	rand.Read(iv)

	sizes := []int{64, 256, 1024, 4096, 16384}

	for _, size := range sizes {
		data := make([]byte, size)
		rand.Read(data)

		b.Run(string(rune(size)), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				em.EncryptBytes(ctx, key, iv, data)
			}
		})
	}
}
