// Package main demonstrates using the flatc-encryption WASI module from Go.
//
// This example shows how to use the FlatBuffers encryption module compiled
// to WASI with the wazero runtime, providing:
// - AES-256-CTR symmetric encryption
// - X25519 ECDH key exchange
// - secp256k1 ECDH and ECDSA signatures (Bitcoin/Ethereum compatible)
// - P-256 ECDH and ECDSA signatures (NIST)
// - Ed25519 signatures
// - Homomorphic Encryption (HE) operations via BFV/CKKS schemes:
//   - Client/server context creation and key management
//   - Integer and floating-point encryption/decryption
//   - Arithmetic on ciphertexts (add, sub, multiply, negate)
//   - Plaintext-ciphertext arithmetic (add_plain, multiply_plain)
package main

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"math"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental/table"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// WasmModulePath holds the path to the compiled WASM module.
// In production, you would embed this or load from a known location.
const WasmModulePath = "../../../build/wasm/flatc-encryption.wasm"

// Key and signature sizes
const (
	AESKeySize   = 32
	AESIVSize    = 16
	SHA256Size   = 32
	SharedSecret = 32

	X25519PrivateKeySize = 32
	X25519PublicKeySize  = 32

	Secp256k1PrivateKeySize = 32
	Secp256k1PublicKeySize  = 33 // compressed
	Secp256k1SignatureSize  = 72 // DER encoded max

	P256PrivateKeySize = 32
	P256PublicKeySize  = 33 // compressed
	P256SignatureSize  = 72 // DER encoded max

	Ed25519PrivateKeySize = 64 // seed + public key
	Ed25519PublicKeySize  = 32
	Ed25519SignatureSize  = 64
)

// EncryptionModule wraps the WASI encryption module
type EncryptionModule struct {
	runtime wazero.Runtime
	module  api.Module

	// Memory management
	malloc api.Function
	free   api.Function

	// Module info
	getVersion   api.Function
	hasCryptopp  api.Function

	// Symmetric encryption
	encryptionCreate  api.Function
	encryptionDestroy api.Function
	encryptBytes      api.Function
	decryptBytes      api.Function
	deriveFieldKey    api.Function
	deriveFieldIV     api.Function

	// Hash functions
	sha256 api.Function
	hkdf   api.Function

	// X25519
	x25519GenerateKeypair api.Function
	x25519SharedSecret    api.Function

	// secp256k1
	secp256k1GenerateKeypair api.Function
	secp256k1SharedSecret    api.Function
	secp256k1Sign            api.Function
	secp256k1Verify          api.Function

	// P-256
	p256GenerateKeypair api.Function
	p256SharedSecret    api.Function
	p256Sign            api.Function
	p256Verify          api.Function

	// Ed25519
	ed25519GenerateKeypair api.Function
	ed25519Sign            api.Function
	ed25519Verify          api.Function

	// Key derivation
	deriveSymmetricKey api.Function

	// HE (Homomorphic Encryption)
	heContextCreateClient api.Function
	heContextCreateServer api.Function
	heContextDestroy      api.Function
	heGetPublicKey        api.Function
	heGetRelinKeys        api.Function
	heGetSecretKey        api.Function
	heSetRelinKeys        api.Function
	heEncryptInt64        api.Function
	heDecryptInt64        api.Function
	heEncryptDouble       api.Function
	heDecryptDouble       api.Function
	heAdd                 api.Function
	heSub                 api.Function
	heMultiply            api.Function
	heNegate              api.Function
	heAddPlain            api.Function
	heMultiplyPlain       api.Function
}

// wasmModule holds the module reference for invoke_* trampolines
var wasmModule api.Module

// NewEncryptionModule creates a new encryption module from WASM bytes
func NewEncryptionModule(ctx context.Context, wasmBytes []byte) (*EncryptionModule, error) {
	r := wazero.NewRuntime(ctx)

	// Instantiate WASI - this provides clock_time_get, fd_close, fd_read, environ_*
	wasi_snapshot_preview1.MustInstantiate(ctx, r)

	// Create the "env" module with Emscripten exception handling trampolines
	// These use table.LookupFunction to call into the WASM function table
	i32 := api.ValueTypeI32

	// Helper to call setThrew on exception
	setException := func(ctx context.Context) {
		if wasmModule != nil {
			if setThrew := wasmModule.ExportedFunction("setThrew"); setThrew != nil {
				setThrew.Call(ctx, 1, 0)
			}
		}
	}

	_, err := r.NewHostModuleBuilder("env").
		// invoke_v: () -> void
		NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, idx uint32) {
			if wasmModule == nil {
				return
			}
			defer func() {
				if r := recover(); r != nil {
					setException(ctx)
				}
			}()
			f := table.LookupFunction(wasmModule, 0, idx, nil, nil)
			f.Call(ctx)
		}).Export("invoke_v").
		// invoke_vi: (i32) -> void
		NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, idx, a uint32) {
			if wasmModule == nil {
				return
			}
			defer func() {
				if r := recover(); r != nil {
					setException(ctx)
				}
			}()
			f := table.LookupFunction(wasmModule, 0, idx, []api.ValueType{i32}, nil)
			f.Call(ctx, uint64(a))
		}).Export("invoke_vi").
		// invoke_vii: (i32, i32) -> void
		NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, idx, a, b uint32) {
			if wasmModule == nil {
				return
			}
			defer func() {
				if r := recover(); r != nil {
					setException(ctx)
				}
			}()
			f := table.LookupFunction(wasmModule, 0, idx, []api.ValueType{i32, i32}, nil)
			f.Call(ctx, uint64(a), uint64(b))
		}).Export("invoke_vii").
		// invoke_viii: (i32, i32, i32) -> void
		NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, idx, a, b, c uint32) {
			if wasmModule == nil {
				return
			}
			defer func() {
				if r := recover(); r != nil {
					setException(ctx)
				}
			}()
			f := table.LookupFunction(wasmModule, 0, idx, []api.ValueType{i32, i32, i32}, nil)
			f.Call(ctx, uint64(a), uint64(b), uint64(c))
		}).Export("invoke_viii").
		// invoke_viiii: (i32, i32, i32, i32) -> void
		NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, idx, a, b, c, d uint32) {
			if wasmModule == nil {
				return
			}
			defer func() {
				if r := recover(); r != nil {
					setException(ctx)
				}
			}()
			f := table.LookupFunction(wasmModule, 0, idx, []api.ValueType{i32, i32, i32, i32}, nil)
			f.Call(ctx, uint64(a), uint64(b), uint64(c), uint64(d))
		}).Export("invoke_viiii").
		// invoke_viiiii: (i32, i32, i32, i32, i32) -> void
		NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, idx, a, b, c, d, e uint32) {
			if wasmModule == nil {
				return
			}
			defer func() {
				if r := recover(); r != nil {
					setException(ctx)
				}
			}()
			f := table.LookupFunction(wasmModule, 0, idx, []api.ValueType{i32, i32, i32, i32, i32}, nil)
			f.Call(ctx, uint64(a), uint64(b), uint64(c), uint64(d), uint64(e))
		}).Export("invoke_viiiii").
		// invoke_viiiiii: (i32 x 6) -> void
		NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, idx, a, b, c, d, e, ff uint32) {
			if wasmModule == nil {
				return
			}
			defer func() {
				if r := recover(); r != nil {
					setException(ctx)
				}
			}()
			f := table.LookupFunction(wasmModule, 0, idx, []api.ValueType{i32, i32, i32, i32, i32, i32}, nil)
			f.Call(ctx, uint64(a), uint64(b), uint64(c), uint64(d), uint64(e), uint64(ff))
		}).Export("invoke_viiiiii").
		// invoke_viiiiiii: (i32 x 7) -> void
		NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, idx, a, b, c, d, e, ff, g uint32) {
			if wasmModule == nil {
				return
			}
			defer func() {
				if r := recover(); r != nil {
					setException(ctx)
				}
			}()
			f := table.LookupFunction(wasmModule, 0, idx, []api.ValueType{i32, i32, i32, i32, i32, i32, i32}, nil)
			f.Call(ctx, uint64(a), uint64(b), uint64(c), uint64(d), uint64(e), uint64(ff), uint64(g))
		}).Export("invoke_viiiiiii").
		// invoke_viiiiiiiii: (i32 x 9) -> void
		NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, idx, a, b, c, d, e, ff, g, h, ii uint32) {
			if wasmModule == nil {
				return
			}
			defer func() {
				if r := recover(); r != nil {
					setException(ctx)
				}
			}()
			f := table.LookupFunction(wasmModule, 0, idx, []api.ValueType{i32, i32, i32, i32, i32, i32, i32, i32, i32}, nil)
			f.Call(ctx, uint64(a), uint64(b), uint64(c), uint64(d), uint64(e), uint64(ff), uint64(g), uint64(h), uint64(ii))
		}).Export("invoke_viiiiiiiii").
		// invoke_i: () -> i32
		NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, idx uint32) uint32 {
			if wasmModule == nil {
				return 0
			}
			defer func() {
				if r := recover(); r != nil {
					setException(ctx)
				}
			}()
			f := table.LookupFunction(wasmModule, 0, idx, nil, []api.ValueType{i32})
			res, _ := f.Call(ctx)
			if len(res) > 0 {
				return uint32(res[0])
			}
			return 0
		}).Export("invoke_i").
		// invoke_ii: (i32) -> i32
		NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, idx, a uint32) uint32 {
			if wasmModule == nil {
				return 0
			}
			defer func() {
				if r := recover(); r != nil {
					setException(ctx)
				}
			}()
			f := table.LookupFunction(wasmModule, 0, idx, []api.ValueType{i32}, []api.ValueType{i32})
			res, _ := f.Call(ctx, uint64(a))
			if len(res) > 0 {
				return uint32(res[0])
			}
			return 0
		}).Export("invoke_ii").
		// invoke_iii: (i32, i32) -> i32
		NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, idx, a, b uint32) uint32 {
			if wasmModule == nil {
				return 0
			}
			defer func() {
				if r := recover(); r != nil {
					setException(ctx)
				}
			}()
			f := table.LookupFunction(wasmModule, 0, idx, []api.ValueType{i32, i32}, []api.ValueType{i32})
			res, _ := f.Call(ctx, uint64(a), uint64(b))
			if len(res) > 0 {
				return uint32(res[0])
			}
			return 0
		}).Export("invoke_iii").
		// invoke_iiii: (i32, i32, i32) -> i32
		NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, idx, a, b, c uint32) uint32 {
			if wasmModule == nil {
				return 0
			}
			defer func() {
				if r := recover(); r != nil {
					setException(ctx)
				}
			}()
			f := table.LookupFunction(wasmModule, 0, idx, []api.ValueType{i32, i32, i32}, []api.ValueType{i32})
			res, _ := f.Call(ctx, uint64(a), uint64(b), uint64(c))
			if len(res) > 0 {
				return uint32(res[0])
			}
			return 0
		}).Export("invoke_iiii").
		// invoke_iiiii: (i32 x 4) -> i32
		NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, idx, a, b, c, d uint32) uint32 {
			if wasmModule == nil {
				return 0
			}
			defer func() {
				if r := recover(); r != nil {
					setException(ctx)
				}
			}()
			f := table.LookupFunction(wasmModule, 0, idx, []api.ValueType{i32, i32, i32, i32}, []api.ValueType{i32})
			res, _ := f.Call(ctx, uint64(a), uint64(b), uint64(c), uint64(d))
			if len(res) > 0 {
				return uint32(res[0])
			}
			return 0
		}).Export("invoke_iiiii").
		// invoke_iiiiii: (i32 x 5) -> i32
		NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, idx, a, b, c, d, e uint32) uint32 {
			if wasmModule == nil {
				return 0
			}
			defer func() {
				if r := recover(); r != nil {
					setException(ctx)
				}
			}()
			f := table.LookupFunction(wasmModule, 0, idx, []api.ValueType{i32, i32, i32, i32, i32}, []api.ValueType{i32})
			res, _ := f.Call(ctx, uint64(a), uint64(b), uint64(c), uint64(d), uint64(e))
			if len(res) > 0 {
				return uint32(res[0])
			}
			return 0
		}).Export("invoke_iiiiii").
		// invoke_iiiiiii: (i32 x 6) -> i32
		NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, idx, a, b, c, d, e, ff uint32) uint32 {
			if wasmModule == nil {
				return 0
			}
			defer func() {
				if r := recover(); r != nil {
					setException(ctx)
				}
			}()
			f := table.LookupFunction(wasmModule, 0, idx, []api.ValueType{i32, i32, i32, i32, i32, i32}, []api.ValueType{i32})
			res, _ := f.Call(ctx, uint64(a), uint64(b), uint64(c), uint64(d), uint64(e), uint64(ff))
			if len(res) > 0 {
				return uint32(res[0])
			}
			return 0
		}).Export("invoke_iiiiiii").
		// invoke_iiiiiiii: (i32 x 7) -> i32
		NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, idx, a, b, c, d, e, ff, g uint32) uint32 {
			if wasmModule == nil {
				return 0
			}
			defer func() {
				if r := recover(); r != nil {
					setException(ctx)
				}
			}()
			f := table.LookupFunction(wasmModule, 0, idx, []api.ValueType{i32, i32, i32, i32, i32, i32, i32}, []api.ValueType{i32})
			res, _ := f.Call(ctx, uint64(a), uint64(b), uint64(c), uint64(d), uint64(e), uint64(ff), uint64(g))
			if len(res) > 0 {
				return uint32(res[0])
			}
			return 0
		}).Export("invoke_iiiiiiii").
		// invoke_iiiiiiiiii: (i32 x 9) -> i32
		NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, idx, a, b, c, d, e, ff, g, h, ii uint32) uint32 {
			if wasmModule == nil {
				return 0
			}
			defer func() {
				if r := recover(); r != nil {
					setException(ctx)
				}
			}()
			f := table.LookupFunction(wasmModule, 0, idx, []api.ValueType{i32, i32, i32, i32, i32, i32, i32, i32, i32}, []api.ValueType{i32})
			res, _ := f.Call(ctx, uint64(a), uint64(b), uint64(c), uint64(d), uint64(e), uint64(ff), uint64(g), uint64(h), uint64(ii))
			if len(res) > 0 {
				return uint32(res[0])
			}
			return 0
		}).Export("invoke_iiiiiiiiii").
		// Exception handling helpers (stubs - exceptions are handled via setThrew)
		NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module) uint32 { return 0 }).Export("__cxa_find_matching_catch_2").
		NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, a uint32) uint32 { return 0 }).Export("__cxa_find_matching_catch_3").
		NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, a uint32) {}).Export("__resumeException").
		NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, a uint32) uint32 { return 0 }).Export("__cxa_begin_catch").
		NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module) {}).Export("__cxa_end_catch").
		NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, a uint32) uint32 { return 0 }).Export("llvm_eh_typeid_for").
		NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, a, b, c uint32) {}).Export("__cxa_throw").
		NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module) uint32 { return 0 }).Export("__cxa_uncaught_exceptions").
		Instantiate(ctx)
	if err != nil {
		r.Close(ctx)
		return nil, fmt.Errorf("failed to instantiate env module: %w", err)
	}

	// Compile the module
	compiled, err := r.CompileModule(ctx, wasmBytes)
	if err != nil {
		r.Close(ctx)
		return nil, fmt.Errorf("failed to compile module: %w", err)
	}

	// Instantiate with configuration
	config := wazero.NewModuleConfig().
		WithName("flatc-encryption").
		WithStdout(nil).
		WithStderr(nil)

	mod, err := r.InstantiateModule(ctx, compiled, config)
	if err != nil {
		r.Close(ctx)
		return nil, fmt.Errorf("failed to instantiate module: %w", err)
	}

	// Store module reference for invoke_* trampolines
	wasmModule = mod

	em := &EncryptionModule{
		runtime: r,
		module:  mod,

		// Memory management
		malloc: mod.ExportedFunction("malloc"),
		free:   mod.ExportedFunction("free"),

		// Module info
		getVersion:  mod.ExportedFunction("wasi_get_version"),
		hasCryptopp: mod.ExportedFunction("wasi_has_cryptopp"),

		// Symmetric encryption
		encryptionCreate:  mod.ExportedFunction("wasi_encryption_create"),
		encryptionDestroy: mod.ExportedFunction("wasi_encryption_destroy"),
		encryptBytes:      mod.ExportedFunction("wasi_encrypt_bytes"),
		decryptBytes:      mod.ExportedFunction("wasi_decrypt_bytes"),
		deriveFieldKey:    mod.ExportedFunction("wasi_derive_field_key"),
		deriveFieldIV:     mod.ExportedFunction("wasi_derive_field_iv"),

		// Hash functions
		sha256: mod.ExportedFunction("wasi_sha256"),
		hkdf:   mod.ExportedFunction("wasi_hkdf"),

		// X25519
		x25519GenerateKeypair: mod.ExportedFunction("wasi_x25519_generate_keypair"),
		x25519SharedSecret:    mod.ExportedFunction("wasi_x25519_shared_secret"),

		// secp256k1
		secp256k1GenerateKeypair: mod.ExportedFunction("wasi_secp256k1_generate_keypair"),
		secp256k1SharedSecret:    mod.ExportedFunction("wasi_secp256k1_shared_secret"),
		secp256k1Sign:            mod.ExportedFunction("wasi_secp256k1_sign"),
		secp256k1Verify:          mod.ExportedFunction("wasi_secp256k1_verify"),

		// P-256
		p256GenerateKeypair: mod.ExportedFunction("wasi_p256_generate_keypair"),
		p256SharedSecret:    mod.ExportedFunction("wasi_p256_shared_secret"),
		p256Sign:            mod.ExportedFunction("wasi_p256_sign"),
		p256Verify:          mod.ExportedFunction("wasi_p256_verify"),

		// Ed25519
		ed25519GenerateKeypair: mod.ExportedFunction("wasi_ed25519_generate_keypair"),
		ed25519Sign:            mod.ExportedFunction("wasi_ed25519_sign"),
		ed25519Verify:          mod.ExportedFunction("wasi_ed25519_verify"),

		// Key derivation
		deriveSymmetricKey: mod.ExportedFunction("wasi_derive_symmetric_key"),

		// HE functions (optional - only available with HE-enabled WASI module)
		heContextCreateClient: mod.ExportedFunction("wasi_he_context_create_client"),
		heContextCreateServer: mod.ExportedFunction("wasi_he_context_create_server"),
		heContextDestroy:      mod.ExportedFunction("wasi_he_context_destroy"),
		heGetPublicKey:        mod.ExportedFunction("wasi_he_get_public_key"),
		heGetRelinKeys:        mod.ExportedFunction("wasi_he_get_relin_keys"),
		heGetSecretKey:        mod.ExportedFunction("wasi_he_get_secret_key"),
		heSetRelinKeys:        mod.ExportedFunction("wasi_he_set_relin_keys"),
		heEncryptInt64:        mod.ExportedFunction("wasi_he_encrypt_int64"),
		heDecryptInt64:        mod.ExportedFunction("wasi_he_decrypt_int64"),
		heEncryptDouble:       mod.ExportedFunction("wasi_he_encrypt_double"),
		heDecryptDouble:       mod.ExportedFunction("wasi_he_decrypt_double"),
		heAdd:                 mod.ExportedFunction("wasi_he_add"),
		heSub:                 mod.ExportedFunction("wasi_he_sub"),
		heMultiply:            mod.ExportedFunction("wasi_he_multiply"),
		heNegate:              mod.ExportedFunction("wasi_he_negate"),
		heAddPlain:            mod.ExportedFunction("wasi_he_add_plain"),
		heMultiplyPlain:       mod.ExportedFunction("wasi_he_multiply_plain"),
	}

	// Verify required functions are exported
	if em.malloc == nil || em.free == nil {
		em.Close(ctx)
		return nil, errors.New("module missing malloc/free exports")
	}
	if em.encryptBytes == nil || em.decryptBytes == nil {
		em.Close(ctx)
		return nil, errors.New("module missing encryption exports")
	}

	return em, nil
}

// Close releases all resources
func (em *EncryptionModule) Close(ctx context.Context) error {
	return em.runtime.Close(ctx)
}

// Version returns the module version string
func (em *EncryptionModule) Version(ctx context.Context) (string, error) {
	if em.getVersion == nil {
		return "", errors.New("getVersion not exported")
	}

	results, err := em.getVersion.Call(ctx)
	if err != nil {
		return "", err
	}

	ptr := uint32(results[0])
	if ptr == 0 {
		return "", errors.New("version returned null")
	}

	// Read string from memory
	mem := em.module.Memory()
	data, ok := mem.Read(ptr, 32) // Read up to 32 bytes
	if !ok {
		return "", errors.New("failed to read version string")
	}

	// Find null terminator
	for i, b := range data {
		if b == 0 {
			return string(data[:i]), nil
		}
	}
	return string(data), nil
}

// HasCryptopp returns true if Crypto++ is available
func (em *EncryptionModule) HasCryptopp(ctx context.Context) (bool, error) {
	if em.hasCryptopp == nil {
		return false, nil
	}

	results, err := em.hasCryptopp.Call(ctx)
	if err != nil {
		return false, err
	}

	return int32(results[0]) == 1, nil
}

// allocate allocates memory in the WASM module
func (em *EncryptionModule) allocate(ctx context.Context, size uint32) (uint32, error) {
	results, err := em.malloc.Call(ctx, uint64(size))
	if err != nil {
		return 0, fmt.Errorf("malloc failed: %w", err)
	}
	ptr := uint32(results[0])
	if ptr == 0 {
		return 0, errors.New("malloc returned null")
	}
	return ptr, nil
}

// deallocate frees memory in the WASM module
func (em *EncryptionModule) deallocate(ctx context.Context, ptr uint32) {
	if ptr != 0 {
		em.free.Call(ctx, uint64(ptr))
	}
}

// =============================================================================
// Symmetric Encryption (AES-256-CTR)
// =============================================================================

// EncryptBytes encrypts data in-place using AES-256-CTR
func (em *EncryptionModule) EncryptBytes(ctx context.Context, key, iv, data []byte) error {
	if len(key) != AESKeySize {
		return errors.New("key must be 32 bytes")
	}
	if len(iv) != AESIVSize {
		return errors.New("iv must be 16 bytes")
	}
	if len(data) == 0 {
		return nil
	}

	mem := em.module.Memory()

	// Allocate memory for key, iv, and data
	keyPtr, err := em.allocate(ctx, AESKeySize)
	if err != nil {
		return err
	}
	defer em.deallocate(ctx, keyPtr)

	ivPtr, err := em.allocate(ctx, AESIVSize)
	if err != nil {
		return err
	}
	defer em.deallocate(ctx, ivPtr)

	dataPtr, err := em.allocate(ctx, uint32(len(data)))
	if err != nil {
		return err
	}
	defer em.deallocate(ctx, dataPtr)

	// Write data to WASM memory
	if !mem.Write(keyPtr, key) {
		return errors.New("failed to write key")
	}
	if !mem.Write(ivPtr, iv) {
		return errors.New("failed to write iv")
	}
	if !mem.Write(dataPtr, data) {
		return errors.New("failed to write data")
	}

	// Call encrypt function
	results, err := em.encryptBytes.Call(ctx,
		uint64(keyPtr),
		uint64(ivPtr),
		uint64(dataPtr),
		uint64(len(data)))
	if err != nil {
		return fmt.Errorf("encrypt call failed: %w", err)
	}

	if int32(results[0]) != 0 {
		return errors.New("encryption failed")
	}

	// Read encrypted data back
	encrypted, ok := mem.Read(dataPtr, uint32(len(data)))
	if !ok {
		return errors.New("failed to read encrypted data")
	}
	copy(data, encrypted)

	return nil
}

// DecryptBytes decrypts data in-place using AES-256-CTR
func (em *EncryptionModule) DecryptBytes(ctx context.Context, key, iv, data []byte) error {
	// AES-CTR is symmetric, decrypt is the same as encrypt
	return em.EncryptBytes(ctx, key, iv, data)
}

// =============================================================================
// Hash Functions
// =============================================================================

// SHA256 computes SHA-256 hash
func (em *EncryptionModule) SHA256(ctx context.Context, data []byte) ([]byte, error) {
	if em.sha256 == nil {
		return nil, errors.New("sha256 not exported")
	}

	mem := em.module.Memory()

	dataPtr, err := em.allocate(ctx, uint32(len(data)))
	if err != nil {
		return nil, err
	}
	defer em.deallocate(ctx, dataPtr)

	hashPtr, err := em.allocate(ctx, SHA256Size)
	if err != nil {
		return nil, err
	}
	defer em.deallocate(ctx, hashPtr)

	if !mem.Write(dataPtr, data) {
		return nil, errors.New("failed to write data")
	}

	_, err = em.sha256.Call(ctx, uint64(dataPtr), uint64(len(data)), uint64(hashPtr))
	if err != nil {
		return nil, err
	}

	hash, ok := mem.Read(hashPtr, SHA256Size)
	if !ok {
		return nil, errors.New("failed to read hash")
	}

	result := make([]byte, SHA256Size)
	copy(result, hash)
	return result, nil
}

// =============================================================================
// X25519 Key Exchange
// =============================================================================

// X25519GenerateKeypair generates an X25519 key pair
func (em *EncryptionModule) X25519GenerateKeypair(ctx context.Context) (privateKey, publicKey []byte, err error) {
	if em.x25519GenerateKeypair == nil {
		return nil, nil, errors.New("x25519_generate_keypair not exported")
	}

	mem := em.module.Memory()

	privPtr, err := em.allocate(ctx, X25519PrivateKeySize)
	if err != nil {
		return nil, nil, err
	}
	defer em.deallocate(ctx, privPtr)

	pubPtr, err := em.allocate(ctx, X25519PublicKeySize)
	if err != nil {
		return nil, nil, err
	}
	defer em.deallocate(ctx, pubPtr)

	results, err := em.x25519GenerateKeypair.Call(ctx, uint64(privPtr), uint64(pubPtr))
	if err != nil {
		return nil, nil, err
	}

	if int32(results[0]) != 0 {
		return nil, nil, errors.New("key generation failed")
	}

	privData, ok := mem.Read(privPtr, X25519PrivateKeySize)
	if !ok {
		return nil, nil, errors.New("failed to read private key")
	}

	pubData, ok := mem.Read(pubPtr, X25519PublicKeySize)
	if !ok {
		return nil, nil, errors.New("failed to read public key")
	}

	privateKey = make([]byte, X25519PrivateKeySize)
	publicKey = make([]byte, X25519PublicKeySize)
	copy(privateKey, privData)
	copy(publicKey, pubData)

	return privateKey, publicKey, nil
}

// X25519SharedSecret performs X25519 ECDH
func (em *EncryptionModule) X25519SharedSecret(ctx context.Context, privateKey, publicKey []byte) ([]byte, error) {
	if em.x25519SharedSecret == nil {
		return nil, errors.New("x25519_shared_secret not exported")
	}

	mem := em.module.Memory()

	privPtr, err := em.allocate(ctx, X25519PrivateKeySize)
	if err != nil {
		return nil, err
	}
	defer em.deallocate(ctx, privPtr)

	pubPtr, err := em.allocate(ctx, X25519PublicKeySize)
	if err != nil {
		return nil, err
	}
	defer em.deallocate(ctx, pubPtr)

	secretPtr, err := em.allocate(ctx, SharedSecret)
	if err != nil {
		return nil, err
	}
	defer em.deallocate(ctx, secretPtr)

	if !mem.Write(privPtr, privateKey) {
		return nil, errors.New("failed to write private key")
	}
	if !mem.Write(pubPtr, publicKey) {
		return nil, errors.New("failed to write public key")
	}

	results, err := em.x25519SharedSecret.Call(ctx, uint64(privPtr), uint64(pubPtr), uint64(secretPtr))
	if err != nil {
		return nil, err
	}

	if int32(results[0]) != 0 {
		return nil, errors.New("ECDH failed")
	}

	secretData, ok := mem.Read(secretPtr, SharedSecret)
	if !ok {
		return nil, errors.New("failed to read shared secret")
	}

	secret := make([]byte, SharedSecret)
	copy(secret, secretData)
	return secret, nil
}

// =============================================================================
// secp256k1 (Bitcoin/Ethereum)
// =============================================================================

// Secp256k1GenerateKeypair generates a secp256k1 key pair
func (em *EncryptionModule) Secp256k1GenerateKeypair(ctx context.Context) (privateKey, publicKey []byte, err error) {
	if em.secp256k1GenerateKeypair == nil {
		return nil, nil, errors.New("secp256k1_generate_keypair not exported")
	}

	mem := em.module.Memory()

	privPtr, err := em.allocate(ctx, Secp256k1PrivateKeySize)
	if err != nil {
		return nil, nil, err
	}
	defer em.deallocate(ctx, privPtr)

	pubPtr, err := em.allocate(ctx, Secp256k1PublicKeySize)
	if err != nil {
		return nil, nil, err
	}
	defer em.deallocate(ctx, pubPtr)

	results, err := em.secp256k1GenerateKeypair.Call(ctx, uint64(privPtr), uint64(pubPtr))
	if err != nil {
		return nil, nil, err
	}

	if int32(results[0]) != 0 {
		return nil, nil, errors.New("key generation failed")
	}

	privData, ok := mem.Read(privPtr, Secp256k1PrivateKeySize)
	if !ok {
		return nil, nil, errors.New("failed to read private key")
	}

	pubData, ok := mem.Read(pubPtr, Secp256k1PublicKeySize)
	if !ok {
		return nil, nil, errors.New("failed to read public key")
	}

	privateKey = make([]byte, Secp256k1PrivateKeySize)
	publicKey = make([]byte, Secp256k1PublicKeySize)
	copy(privateKey, privData)
	copy(publicKey, pubData)

	return privateKey, publicKey, nil
}

// Secp256k1SharedSecret performs secp256k1 ECDH
func (em *EncryptionModule) Secp256k1SharedSecret(ctx context.Context, privateKey, publicKey []byte) ([]byte, error) {
	if em.secp256k1SharedSecret == nil {
		return nil, errors.New("secp256k1_shared_secret not exported")
	}

	mem := em.module.Memory()

	privPtr, err := em.allocate(ctx, Secp256k1PrivateKeySize)
	if err != nil {
		return nil, err
	}
	defer em.deallocate(ctx, privPtr)

	pubPtr, err := em.allocate(ctx, uint32(len(publicKey)))
	if err != nil {
		return nil, err
	}
	defer em.deallocate(ctx, pubPtr)

	secretPtr, err := em.allocate(ctx, SharedSecret)
	if err != nil {
		return nil, err
	}
	defer em.deallocate(ctx, secretPtr)

	if !mem.Write(privPtr, privateKey) {
		return nil, errors.New("failed to write private key")
	}
	if !mem.Write(pubPtr, publicKey) {
		return nil, errors.New("failed to write public key")
	}

	results, err := em.secp256k1SharedSecret.Call(ctx,
		uint64(privPtr), uint64(pubPtr), uint64(len(publicKey)), uint64(secretPtr))
	if err != nil {
		return nil, err
	}

	if int32(results[0]) != 0 {
		return nil, errors.New("ECDH failed")
	}

	secretData, ok := mem.Read(secretPtr, SharedSecret)
	if !ok {
		return nil, errors.New("failed to read shared secret")
	}

	secret := make([]byte, SharedSecret)
	copy(secret, secretData)
	return secret, nil
}

// Secp256k1Sign signs data with secp256k1 ECDSA
func (em *EncryptionModule) Secp256k1Sign(ctx context.Context, privateKey, data []byte) ([]byte, error) {
	if em.secp256k1Sign == nil {
		return nil, errors.New("secp256k1_sign not exported")
	}

	mem := em.module.Memory()

	privPtr, err := em.allocate(ctx, Secp256k1PrivateKeySize)
	if err != nil {
		return nil, err
	}
	defer em.deallocate(ctx, privPtr)

	dataPtr, err := em.allocate(ctx, uint32(len(data)))
	if err != nil {
		return nil, err
	}
	defer em.deallocate(ctx, dataPtr)

	sigPtr, err := em.allocate(ctx, Secp256k1SignatureSize)
	if err != nil {
		return nil, err
	}
	defer em.deallocate(ctx, sigPtr)

	sigSizePtr, err := em.allocate(ctx, 4)
	if err != nil {
		return nil, err
	}
	defer em.deallocate(ctx, sigSizePtr)

	if !mem.Write(privPtr, privateKey) {
		return nil, errors.New("failed to write private key")
	}
	if !mem.Write(dataPtr, data) {
		return nil, errors.New("failed to write data")
	}

	results, err := em.secp256k1Sign.Call(ctx,
		uint64(privPtr), uint64(dataPtr), uint64(len(data)), uint64(sigPtr), uint64(sigSizePtr))
	if err != nil {
		return nil, err
	}

	if int32(results[0]) != 0 {
		return nil, errors.New("signing failed")
	}

	// Read signature size
	sigSizeData, ok := mem.Read(sigSizePtr, 4)
	if !ok {
		return nil, errors.New("failed to read signature size")
	}
	sigSize := uint32(sigSizeData[0]) | uint32(sigSizeData[1])<<8 |
		uint32(sigSizeData[2])<<16 | uint32(sigSizeData[3])<<24

	sigData, ok := mem.Read(sigPtr, sigSize)
	if !ok {
		return nil, errors.New("failed to read signature")
	}

	sig := make([]byte, sigSize)
	copy(sig, sigData)
	return sig, nil
}

// Secp256k1Verify verifies a secp256k1 ECDSA signature
func (em *EncryptionModule) Secp256k1Verify(ctx context.Context, publicKey, data, signature []byte) (bool, error) {
	if em.secp256k1Verify == nil {
		return false, errors.New("secp256k1_verify not exported")
	}

	mem := em.module.Memory()

	pubPtr, err := em.allocate(ctx, uint32(len(publicKey)))
	if err != nil {
		return false, err
	}
	defer em.deallocate(ctx, pubPtr)

	dataPtr, err := em.allocate(ctx, uint32(len(data)))
	if err != nil {
		return false, err
	}
	defer em.deallocate(ctx, dataPtr)

	sigPtr, err := em.allocate(ctx, uint32(len(signature)))
	if err != nil {
		return false, err
	}
	defer em.deallocate(ctx, sigPtr)

	if !mem.Write(pubPtr, publicKey) {
		return false, errors.New("failed to write public key")
	}
	if !mem.Write(dataPtr, data) {
		return false, errors.New("failed to write data")
	}
	if !mem.Write(sigPtr, signature) {
		return false, errors.New("failed to write signature")
	}

	results, err := em.secp256k1Verify.Call(ctx,
		uint64(pubPtr), uint64(len(publicKey)),
		uint64(dataPtr), uint64(len(data)),
		uint64(sigPtr), uint64(len(signature)))
	if err != nil {
		return false, err
	}

	return int32(results[0]) == 0, nil
}

// =============================================================================
// P-256 (NIST)
// =============================================================================

// P256GenerateKeypair generates a P-256 key pair
func (em *EncryptionModule) P256GenerateKeypair(ctx context.Context) (privateKey, publicKey []byte, err error) {
	if em.p256GenerateKeypair == nil {
		return nil, nil, errors.New("p256_generate_keypair not exported")
	}

	mem := em.module.Memory()

	privPtr, err := em.allocate(ctx, P256PrivateKeySize)
	if err != nil {
		return nil, nil, err
	}
	defer em.deallocate(ctx, privPtr)

	pubPtr, err := em.allocate(ctx, P256PublicKeySize)
	if err != nil {
		return nil, nil, err
	}
	defer em.deallocate(ctx, pubPtr)

	results, err := em.p256GenerateKeypair.Call(ctx, uint64(privPtr), uint64(pubPtr))
	if err != nil {
		return nil, nil, err
	}

	if int32(results[0]) != 0 {
		return nil, nil, errors.New("key generation failed")
	}

	privData, ok := mem.Read(privPtr, P256PrivateKeySize)
	if !ok {
		return nil, nil, errors.New("failed to read private key")
	}

	pubData, ok := mem.Read(pubPtr, P256PublicKeySize)
	if !ok {
		return nil, nil, errors.New("failed to read public key")
	}

	privateKey = make([]byte, P256PrivateKeySize)
	publicKey = make([]byte, P256PublicKeySize)
	copy(privateKey, privData)
	copy(publicKey, pubData)

	return privateKey, publicKey, nil
}

// P256SharedSecret performs P-256 ECDH
func (em *EncryptionModule) P256SharedSecret(ctx context.Context, privateKey, publicKey []byte) ([]byte, error) {
	if em.p256SharedSecret == nil {
		return nil, errors.New("p256_shared_secret not exported")
	}

	mem := em.module.Memory()

	privPtr, err := em.allocate(ctx, P256PrivateKeySize)
	if err != nil {
		return nil, err
	}
	defer em.deallocate(ctx, privPtr)

	pubPtr, err := em.allocate(ctx, uint32(len(publicKey)))
	if err != nil {
		return nil, err
	}
	defer em.deallocate(ctx, pubPtr)

	secretPtr, err := em.allocate(ctx, SharedSecret)
	if err != nil {
		return nil, err
	}
	defer em.deallocate(ctx, secretPtr)

	if !mem.Write(privPtr, privateKey) {
		return nil, errors.New("failed to write private key")
	}
	if !mem.Write(pubPtr, publicKey) {
		return nil, errors.New("failed to write public key")
	}

	results, err := em.p256SharedSecret.Call(ctx,
		uint64(privPtr), uint64(pubPtr), uint64(len(publicKey)), uint64(secretPtr))
	if err != nil {
		return nil, err
	}

	if int32(results[0]) != 0 {
		return nil, errors.New("ECDH failed")
	}

	secretData, ok := mem.Read(secretPtr, SharedSecret)
	if !ok {
		return nil, errors.New("failed to read shared secret")
	}

	secret := make([]byte, SharedSecret)
	copy(secret, secretData)
	return secret, nil
}

// P256Sign signs data with P-256 ECDSA
func (em *EncryptionModule) P256Sign(ctx context.Context, privateKey, data []byte) ([]byte, error) {
	if em.p256Sign == nil {
		return nil, errors.New("p256_sign not exported")
	}

	mem := em.module.Memory()

	privPtr, err := em.allocate(ctx, P256PrivateKeySize)
	if err != nil {
		return nil, err
	}
	defer em.deallocate(ctx, privPtr)

	dataPtr, err := em.allocate(ctx, uint32(len(data)))
	if err != nil {
		return nil, err
	}
	defer em.deallocate(ctx, dataPtr)

	sigPtr, err := em.allocate(ctx, P256SignatureSize)
	if err != nil {
		return nil, err
	}
	defer em.deallocate(ctx, sigPtr)

	sigSizePtr, err := em.allocate(ctx, 4)
	if err != nil {
		return nil, err
	}
	defer em.deallocate(ctx, sigSizePtr)

	if !mem.Write(privPtr, privateKey) {
		return nil, errors.New("failed to write private key")
	}
	if !mem.Write(dataPtr, data) {
		return nil, errors.New("failed to write data")
	}

	results, err := em.p256Sign.Call(ctx,
		uint64(privPtr), uint64(dataPtr), uint64(len(data)), uint64(sigPtr), uint64(sigSizePtr))
	if err != nil {
		return nil, err
	}

	if int32(results[0]) != 0 {
		return nil, errors.New("signing failed")
	}

	// Read signature size
	sigSizeData, ok := mem.Read(sigSizePtr, 4)
	if !ok {
		return nil, errors.New("failed to read signature size")
	}
	sigSize := uint32(sigSizeData[0]) | uint32(sigSizeData[1])<<8 |
		uint32(sigSizeData[2])<<16 | uint32(sigSizeData[3])<<24

	sigData, ok := mem.Read(sigPtr, sigSize)
	if !ok {
		return nil, errors.New("failed to read signature")
	}

	sig := make([]byte, sigSize)
	copy(sig, sigData)
	return sig, nil
}

// P256Verify verifies a P-256 ECDSA signature
func (em *EncryptionModule) P256Verify(ctx context.Context, publicKey, data, signature []byte) (bool, error) {
	if em.p256Verify == nil {
		return false, errors.New("p256_verify not exported")
	}

	mem := em.module.Memory()

	pubPtr, err := em.allocate(ctx, uint32(len(publicKey)))
	if err != nil {
		return false, err
	}
	defer em.deallocate(ctx, pubPtr)

	dataPtr, err := em.allocate(ctx, uint32(len(data)))
	if err != nil {
		return false, err
	}
	defer em.deallocate(ctx, dataPtr)

	sigPtr, err := em.allocate(ctx, uint32(len(signature)))
	if err != nil {
		return false, err
	}
	defer em.deallocate(ctx, sigPtr)

	if !mem.Write(pubPtr, publicKey) {
		return false, errors.New("failed to write public key")
	}
	if !mem.Write(dataPtr, data) {
		return false, errors.New("failed to write data")
	}
	if !mem.Write(sigPtr, signature) {
		return false, errors.New("failed to write signature")
	}

	results, err := em.p256Verify.Call(ctx,
		uint64(pubPtr), uint64(len(publicKey)),
		uint64(dataPtr), uint64(len(data)),
		uint64(sigPtr), uint64(len(signature)))
	if err != nil {
		return false, err
	}

	return int32(results[0]) == 0, nil
}

// =============================================================================
// Ed25519 Signatures
// =============================================================================

// Ed25519GenerateKeypair generates an Ed25519 signing key pair
func (em *EncryptionModule) Ed25519GenerateKeypair(ctx context.Context) (privateKey, publicKey []byte, err error) {
	if em.ed25519GenerateKeypair == nil {
		return nil, nil, errors.New("ed25519_generate_keypair not exported")
	}

	mem := em.module.Memory()

	privPtr, err := em.allocate(ctx, Ed25519PrivateKeySize)
	if err != nil {
		return nil, nil, err
	}
	defer em.deallocate(ctx, privPtr)

	pubPtr, err := em.allocate(ctx, Ed25519PublicKeySize)
	if err != nil {
		return nil, nil, err
	}
	defer em.deallocate(ctx, pubPtr)

	results, err := em.ed25519GenerateKeypair.Call(ctx, uint64(privPtr), uint64(pubPtr))
	if err != nil {
		return nil, nil, err
	}

	if int32(results[0]) != 0 {
		return nil, nil, errors.New("key generation failed")
	}

	privData, ok := mem.Read(privPtr, Ed25519PrivateKeySize)
	if !ok {
		return nil, nil, errors.New("failed to read private key")
	}

	pubData, ok := mem.Read(pubPtr, Ed25519PublicKeySize)
	if !ok {
		return nil, nil, errors.New("failed to read public key")
	}

	privateKey = make([]byte, Ed25519PrivateKeySize)
	publicKey = make([]byte, Ed25519PublicKeySize)
	copy(privateKey, privData)
	copy(publicKey, pubData)

	return privateKey, publicKey, nil
}

// Ed25519Sign signs data with Ed25519
func (em *EncryptionModule) Ed25519Sign(ctx context.Context, privateKey, data []byte) ([]byte, error) {
	if em.ed25519Sign == nil {
		return nil, errors.New("ed25519_sign not exported")
	}

	mem := em.module.Memory()

	privPtr, err := em.allocate(ctx, Ed25519PrivateKeySize)
	if err != nil {
		return nil, err
	}
	defer em.deallocate(ctx, privPtr)

	dataPtr, err := em.allocate(ctx, uint32(len(data)))
	if err != nil {
		return nil, err
	}
	defer em.deallocate(ctx, dataPtr)

	sigPtr, err := em.allocate(ctx, Ed25519SignatureSize)
	if err != nil {
		return nil, err
	}
	defer em.deallocate(ctx, sigPtr)

	if !mem.Write(privPtr, privateKey) {
		return nil, errors.New("failed to write private key")
	}
	if !mem.Write(dataPtr, data) {
		return nil, errors.New("failed to write data")
	}

	results, err := em.ed25519Sign.Call(ctx,
		uint64(privPtr), uint64(dataPtr), uint64(len(data)), uint64(sigPtr))
	if err != nil {
		return nil, err
	}

	if int32(results[0]) != 0 {
		return nil, errors.New("signing failed")
	}

	sigData, ok := mem.Read(sigPtr, Ed25519SignatureSize)
	if !ok {
		return nil, errors.New("failed to read signature")
	}

	sig := make([]byte, Ed25519SignatureSize)
	copy(sig, sigData)
	return sig, nil
}

// Ed25519Verify verifies an Ed25519 signature
func (em *EncryptionModule) Ed25519Verify(ctx context.Context, publicKey, data, signature []byte) (bool, error) {
	if em.ed25519Verify == nil {
		return false, errors.New("ed25519_verify not exported")
	}

	mem := em.module.Memory()

	pubPtr, err := em.allocate(ctx, Ed25519PublicKeySize)
	if err != nil {
		return false, err
	}
	defer em.deallocate(ctx, pubPtr)

	dataPtr, err := em.allocate(ctx, uint32(len(data)))
	if err != nil {
		return false, err
	}
	defer em.deallocate(ctx, dataPtr)

	sigPtr, err := em.allocate(ctx, Ed25519SignatureSize)
	if err != nil {
		return false, err
	}
	defer em.deallocate(ctx, sigPtr)

	if !mem.Write(pubPtr, publicKey) {
		return false, errors.New("failed to write public key")
	}
	if !mem.Write(dataPtr, data) {
		return false, errors.New("failed to write data")
	}
	if !mem.Write(sigPtr, signature) {
		return false, errors.New("failed to write signature")
	}

	results, err := em.ed25519Verify.Call(ctx,
		uint64(pubPtr), uint64(dataPtr), uint64(len(data)), uint64(sigPtr))
	if err != nil {
		return false, err
	}

	return int32(results[0]) == 0, nil
}

// =============================================================================
// Encryption Context (field-level key derivation)
// =============================================================================

// EncryptionContext wraps a WASI encryption context handle
type EncryptionContext struct {
	em  *EncryptionModule
	ptr uint32
}

// NewEncryptionContext creates a new encryption context from a 32-byte key
func (em *EncryptionModule) NewEncryptionContext(ctx context.Context, key []byte) (*EncryptionContext, error) {
	if len(key) != AESKeySize {
		return nil, errors.New("key must be 32 bytes")
	}

	if em.encryptionCreate == nil {
		return nil, errors.New("encryption_create not exported")
	}

	mem := em.module.Memory()

	// Allocate and write key
	keyPtr, err := em.allocate(ctx, AESKeySize)
	if err != nil {
		return nil, err
	}
	defer em.deallocate(ctx, keyPtr)

	if !mem.Write(keyPtr, key) {
		return nil, errors.New("failed to write key")
	}

	// Create context
	results, err := em.encryptionCreate.Call(ctx, uint64(keyPtr), AESKeySize)
	if err != nil {
		return nil, fmt.Errorf("encryption_create failed: %w", err)
	}

	ctxPtr := uint32(results[0])
	if ctxPtr == 0 {
		return nil, errors.New("encryption_create returned null")
	}

	return &EncryptionContext{em: em, ptr: ctxPtr}, nil
}

// Close releases the encryption context
func (ec *EncryptionContext) Close(ctx context.Context) {
	if ec.ptr != 0 && ec.em.encryptionDestroy != nil {
		ec.em.encryptionDestroy.Call(ctx, uint64(ec.ptr))
		ec.ptr = 0
	}
}

// DeriveFieldKey derives a field-specific key
func (ec *EncryptionContext) DeriveFieldKey(ctx context.Context, fieldID uint16) ([]byte, error) {
	if ec.em.deriveFieldKey == nil {
		return nil, errors.New("derive_field_key not exported")
	}

	mem := ec.em.module.Memory()

	// Allocate output buffer
	outPtr, err := ec.em.allocate(ctx, AESKeySize)
	if err != nil {
		return nil, err
	}
	defer ec.em.deallocate(ctx, outPtr)

	// Call derive function
	results, err := ec.em.deriveFieldKey.Call(ctx,
		uint64(ec.ptr),
		uint64(fieldID),
		uint64(outPtr))
	if err != nil {
		return nil, fmt.Errorf("derive_field_key failed: %w", err)
	}

	if int32(results[0]) != 0 {
		return nil, errors.New("key derivation failed")
	}

	// Read derived key
	key, ok := mem.Read(outPtr, AESKeySize)
	if !ok {
		return nil, errors.New("failed to read derived key")
	}

	result := make([]byte, AESKeySize)
	copy(result, key)
	return result, nil
}

// DeriveFieldIV derives a field-specific IV
func (ec *EncryptionContext) DeriveFieldIV(ctx context.Context, fieldID uint16) ([]byte, error) {
	if ec.em.deriveFieldIV == nil {
		return nil, errors.New("derive_field_iv not exported")
	}

	mem := ec.em.module.Memory()

	// Allocate output buffer
	outPtr, err := ec.em.allocate(ctx, AESIVSize)
	if err != nil {
		return nil, err
	}
	defer ec.em.deallocate(ctx, outPtr)

	// Call derive function
	results, err := ec.em.deriveFieldIV.Call(ctx,
		uint64(ec.ptr),
		uint64(fieldID),
		uint64(outPtr))
	if err != nil {
		return nil, fmt.Errorf("derive_field_iv failed: %w", err)
	}

	if int32(results[0]) != 0 {
		return nil, errors.New("IV derivation failed")
	}

	// Read derived IV
	iv, ok := mem.Read(outPtr, AESIVSize)
	if !ok {
		return nil, errors.New("failed to read derived IV")
	}

	result := make([]byte, AESIVSize)
	copy(result, iv)
	return result, nil
}

// =============================================================================
// Homomorphic Encryption (HE)
// =============================================================================

// HasHE returns true if the WASI module supports homomorphic encryption
func (em *EncryptionModule) HasHE() bool {
	return em.heContextCreateClient != nil
}

// HECreateClient creates a new HE context with full key material (client-side).
// polyDegree controls the polynomial modulus degree (e.g., 4096, 8192).
// Returns a context ID that must be destroyed with HEDestroyContext.
func (em *EncryptionModule) HECreateClient(ctx context.Context, polyDegree uint32) (int32, error) {
	if em.heContextCreateClient == nil {
		return 0, errors.New("wasi_he_context_create_client not exported")
	}

	results, err := em.heContextCreateClient.Call(ctx, uint64(polyDegree))
	if err != nil {
		return 0, fmt.Errorf("he_context_create_client failed: %w", err)
	}

	ctxID := int32(results[0])
	if ctxID < 0 {
		return 0, fmt.Errorf("he_context_create_client returned error: %d", ctxID)
	}

	return ctxID, nil
}

// HECreateServer creates a new HE context from a serialized public key (server-side).
// The server context can encrypt and perform operations but cannot decrypt.
// Returns a context ID that must be destroyed with HEDestroyContext.
func (em *EncryptionModule) HECreateServer(ctx context.Context, publicKey []byte) (int32, error) {
	if em.heContextCreateServer == nil {
		return 0, errors.New("wasi_he_context_create_server not exported")
	}

	mem := em.module.Memory()

	pkPtr, err := em.allocate(ctx, uint32(len(publicKey)))
	if err != nil {
		return 0, err
	}
	defer em.deallocate(ctx, pkPtr)

	if !mem.Write(pkPtr, publicKey) {
		return 0, errors.New("failed to write public key")
	}

	results, err := em.heContextCreateServer.Call(ctx, uint64(pkPtr), uint64(len(publicKey)))
	if err != nil {
		return 0, fmt.Errorf("he_context_create_server failed: %w", err)
	}

	ctxID := int32(results[0])
	if ctxID < 0 {
		return 0, fmt.Errorf("he_context_create_server returned error: %d", ctxID)
	}

	return ctxID, nil
}

// HEDestroyContext destroys a previously created HE context and frees resources.
func (em *EncryptionModule) HEDestroyContext(ctx context.Context, ctxID int32) {
	if em.heContextDestroy != nil {
		em.heContextDestroy.Call(ctx, uint64(uint32(ctxID)))
	}
}

// heGetVariableLengthData is a helper for HE functions that return variable-length data.
// The WASI function signature is: fn(ctx_id i32, out_len_ptr i32) -> data_ptr i32
func (em *EncryptionModule) heGetVariableLengthData(ctx context.Context, fn api.Function, fnName string, ctxID int32) ([]byte, error) {
	if fn == nil {
		return nil, fmt.Errorf("%s not exported", fnName)
	}

	mem := em.module.Memory()

	// Allocate 4 bytes for output length
	outLenPtr, err := em.allocate(ctx, 4)
	if err != nil {
		return nil, err
	}
	defer em.deallocate(ctx, outLenPtr)

	// Call the function: returns data pointer, writes length to outLenPtr
	results, err := fn.Call(ctx, uint64(uint32(ctxID)), uint64(outLenPtr))
	if err != nil {
		return nil, fmt.Errorf("%s failed: %w", fnName, err)
	}

	dataPtr := uint32(results[0])
	if dataPtr == 0 {
		return nil, fmt.Errorf("%s returned null", fnName)
	}

	// Read the output length (little-endian uint32)
	lenData, ok := mem.Read(outLenPtr, 4)
	if !ok {
		return nil, fmt.Errorf("failed to read output length from %s", fnName)
	}
	dataLen := uint32(lenData[0]) | uint32(lenData[1])<<8 |
		uint32(lenData[2])<<16 | uint32(lenData[3])<<24

	if dataLen == 0 {
		return nil, fmt.Errorf("%s returned zero-length data", fnName)
	}

	// Read the data
	rawData, ok := mem.Read(dataPtr, dataLen)
	if !ok {
		return nil, fmt.Errorf("failed to read data from %s", fnName)
	}

	result := make([]byte, dataLen)
	copy(result, rawData)

	// Free the data pointer allocated by the WASI module
	em.deallocate(ctx, dataPtr)

	return result, nil
}

// HEGetPublicKey returns the serialized public key from a client HE context.
func (em *EncryptionModule) HEGetPublicKey(ctx context.Context, ctxID int32) ([]byte, error) {
	return em.heGetVariableLengthData(ctx, em.heGetPublicKey, "wasi_he_get_public_key", ctxID)
}

// HEGetRelinKeys returns the serialized relinearization keys from a client HE context.
func (em *EncryptionModule) HEGetRelinKeys(ctx context.Context, ctxID int32) ([]byte, error) {
	return em.heGetVariableLengthData(ctx, em.heGetRelinKeys, "wasi_he_get_relin_keys", ctxID)
}

// HEGetSecretKey returns the serialized secret key from a client HE context.
func (em *EncryptionModule) HEGetSecretKey(ctx context.Context, ctxID int32) ([]byte, error) {
	return em.heGetVariableLengthData(ctx, em.heGetSecretKey, "wasi_he_get_secret_key", ctxID)
}

// HESetRelinKeys sets the relinearization keys on a server HE context.
// This is required before performing multiplication on the server side.
func (em *EncryptionModule) HESetRelinKeys(ctx context.Context, ctxID int32, relinKeys []byte) error {
	if em.heSetRelinKeys == nil {
		return errors.New("wasi_he_set_relin_keys not exported")
	}

	mem := em.module.Memory()

	rkPtr, err := em.allocate(ctx, uint32(len(relinKeys)))
	if err != nil {
		return err
	}
	defer em.deallocate(ctx, rkPtr)

	if !mem.Write(rkPtr, relinKeys) {
		return errors.New("failed to write relin keys")
	}

	results, err := em.heSetRelinKeys.Call(ctx,
		uint64(uint32(ctxID)), uint64(rkPtr), uint64(len(relinKeys)))
	if err != nil {
		return fmt.Errorf("he_set_relin_keys failed: %w", err)
	}

	if int32(results[0]) != 0 {
		return errors.New("he_set_relin_keys failed")
	}

	return nil
}

// HEEncryptInt64 encrypts an int64 value using the BFV scheme.
// Returns the serialized ciphertext.
func (em *EncryptionModule) HEEncryptInt64(ctx context.Context, ctxID int32, value int64) ([]byte, error) {
	if em.heEncryptInt64 == nil {
		return nil, errors.New("wasi_he_encrypt_int64 not exported")
	}

	mem := em.module.Memory()

	// Allocate 4 bytes for output length
	outLenPtr, err := em.allocate(ctx, 4)
	if err != nil {
		return nil, err
	}
	defer em.deallocate(ctx, outLenPtr)

	// Call: wasi_he_encrypt_int64(ctx_id, value_i64, out_len_ptr) -> data_ptr
	results, err := em.heEncryptInt64.Call(ctx,
		uint64(uint32(ctxID)), uint64(value), uint64(outLenPtr))
	if err != nil {
		return nil, fmt.Errorf("he_encrypt_int64 failed: %w", err)
	}

	dataPtr := uint32(results[0])
	if dataPtr == 0 {
		return nil, errors.New("he_encrypt_int64 returned null")
	}

	// Read the output length (little-endian uint32)
	lenData, ok := mem.Read(outLenPtr, 4)
	if !ok {
		return nil, errors.New("failed to read output length")
	}
	dataLen := uint32(lenData[0]) | uint32(lenData[1])<<8 |
		uint32(lenData[2])<<16 | uint32(lenData[3])<<24

	if dataLen == 0 {
		return nil, errors.New("he_encrypt_int64 returned zero-length ciphertext")
	}

	// Read ciphertext data
	rawData, ok := mem.Read(dataPtr, dataLen)
	if !ok {
		return nil, errors.New("failed to read ciphertext")
	}

	result := make([]byte, dataLen)
	copy(result, rawData)

	em.deallocate(ctx, dataPtr)

	return result, nil
}

// HEDecryptInt64 decrypts a ciphertext to an int64 value using the BFV scheme.
func (em *EncryptionModule) HEDecryptInt64(ctx context.Context, ctxID int32, ciphertext []byte) (int64, error) {
	if em.heDecryptInt64 == nil {
		return 0, errors.New("wasi_he_decrypt_int64 not exported")
	}

	mem := em.module.Memory()

	ctPtr, err := em.allocate(ctx, uint32(len(ciphertext)))
	if err != nil {
		return 0, err
	}
	defer em.deallocate(ctx, ctPtr)

	if !mem.Write(ctPtr, ciphertext) {
		return 0, errors.New("failed to write ciphertext")
	}

	// Call: wasi_he_decrypt_int64(ctx_id, ct_ptr, ct_len) -> i64
	results, err := em.heDecryptInt64.Call(ctx,
		uint64(uint32(ctxID)), uint64(ctPtr), uint64(len(ciphertext)))
	if err != nil {
		return 0, fmt.Errorf("he_decrypt_int64 failed: %w", err)
	}

	return int64(results[0]), nil
}

// HEEncryptDouble encrypts a float64 value using the CKKS scheme.
// Returns the serialized ciphertext.
func (em *EncryptionModule) HEEncryptDouble(ctx context.Context, ctxID int32, value float64) ([]byte, error) {
	if em.heEncryptDouble == nil {
		return nil, errors.New("wasi_he_encrypt_double not exported")
	}

	mem := em.module.Memory()

	// Allocate 4 bytes for output length
	outLenPtr, err := em.allocate(ctx, 4)
	if err != nil {
		return nil, err
	}
	defer em.deallocate(ctx, outLenPtr)

	// Call: wasi_he_encrypt_double(ctx_id, value_f64, out_len_ptr) -> data_ptr
	// Pass the float64 as its raw bits for wazero
	results, err := em.heEncryptDouble.Call(ctx,
		uint64(uint32(ctxID)), math.Float64bits(value), uint64(outLenPtr))
	if err != nil {
		return nil, fmt.Errorf("he_encrypt_double failed: %w", err)
	}

	dataPtr := uint32(results[0])
	if dataPtr == 0 {
		return nil, errors.New("he_encrypt_double returned null")
	}

	// Read the output length (little-endian uint32)
	lenData, ok := mem.Read(outLenPtr, 4)
	if !ok {
		return nil, errors.New("failed to read output length")
	}
	dataLen := uint32(lenData[0]) | uint32(lenData[1])<<8 |
		uint32(lenData[2])<<16 | uint32(lenData[3])<<24

	if dataLen == 0 {
		return nil, errors.New("he_encrypt_double returned zero-length ciphertext")
	}

	// Read ciphertext data
	rawData, ok := mem.Read(dataPtr, dataLen)
	if !ok {
		return nil, errors.New("failed to read ciphertext")
	}

	result := make([]byte, dataLen)
	copy(result, rawData)

	em.deallocate(ctx, dataPtr)

	return result, nil
}

// HEDecryptDouble decrypts a ciphertext to a float64 value using the CKKS scheme.
func (em *EncryptionModule) HEDecryptDouble(ctx context.Context, ctxID int32, ciphertext []byte) (float64, error) {
	if em.heDecryptDouble == nil {
		return 0, errors.New("wasi_he_decrypt_double not exported")
	}

	mem := em.module.Memory()

	ctPtr, err := em.allocate(ctx, uint32(len(ciphertext)))
	if err != nil {
		return 0, err
	}
	defer em.deallocate(ctx, ctPtr)

	if !mem.Write(ctPtr, ciphertext) {
		return 0, errors.New("failed to write ciphertext")
	}

	// Call: wasi_he_decrypt_double(ctx_id, ct_ptr, ct_len) -> f64
	results, err := em.heDecryptDouble.Call(ctx,
		uint64(uint32(ctxID)), uint64(ctPtr), uint64(len(ciphertext)))
	if err != nil {
		return 0, fmt.Errorf("he_decrypt_double failed: %w", err)
	}

	return math.Float64frombits(results[0]), nil
}

// heBinaryCtOp is a helper for HE operations on two ciphertexts (add, sub, multiply).
// The WASI function signature is:
//
//	fn(ctx_id, ct1_ptr, ct1_len, ct2_ptr, ct2_len, out_len_ptr) -> data_ptr
func (em *EncryptionModule) heBinaryCtOp(ctx context.Context, fn api.Function, fnName string, ctxID int32, ct1, ct2 []byte) ([]byte, error) {
	if fn == nil {
		return nil, fmt.Errorf("%s not exported", fnName)
	}

	mem := em.module.Memory()

	ct1Ptr, err := em.allocate(ctx, uint32(len(ct1)))
	if err != nil {
		return nil, err
	}
	defer em.deallocate(ctx, ct1Ptr)

	ct2Ptr, err := em.allocate(ctx, uint32(len(ct2)))
	if err != nil {
		return nil, err
	}
	defer em.deallocate(ctx, ct2Ptr)

	outLenPtr, err := em.allocate(ctx, 4)
	if err != nil {
		return nil, err
	}
	defer em.deallocate(ctx, outLenPtr)

	if !mem.Write(ct1Ptr, ct1) {
		return nil, errors.New("failed to write ciphertext 1")
	}
	if !mem.Write(ct2Ptr, ct2) {
		return nil, errors.New("failed to write ciphertext 2")
	}

	results, err := fn.Call(ctx,
		uint64(uint32(ctxID)),
		uint64(ct1Ptr), uint64(len(ct1)),
		uint64(ct2Ptr), uint64(len(ct2)),
		uint64(outLenPtr))
	if err != nil {
		return nil, fmt.Errorf("%s failed: %w", fnName, err)
	}

	dataPtr := uint32(results[0])
	if dataPtr == 0 {
		return nil, fmt.Errorf("%s returned null", fnName)
	}

	// Read the output length (little-endian uint32)
	lenData, ok := mem.Read(outLenPtr, 4)
	if !ok {
		return nil, fmt.Errorf("failed to read output length from %s", fnName)
	}
	dataLen := uint32(lenData[0]) | uint32(lenData[1])<<8 |
		uint32(lenData[2])<<16 | uint32(lenData[3])<<24

	if dataLen == 0 {
		return nil, fmt.Errorf("%s returned zero-length ciphertext", fnName)
	}

	rawData, ok := mem.Read(dataPtr, dataLen)
	if !ok {
		return nil, fmt.Errorf("failed to read result from %s", fnName)
	}

	result := make([]byte, dataLen)
	copy(result, rawData)

	em.deallocate(ctx, dataPtr)

	return result, nil
}

// HEAdd performs homomorphic addition of two ciphertexts.
// Returns a new ciphertext representing the sum of the encrypted values.
func (em *EncryptionModule) HEAdd(ctx context.Context, ctxID int32, ct1, ct2 []byte) ([]byte, error) {
	return em.heBinaryCtOp(ctx, em.heAdd, "wasi_he_add", ctxID, ct1, ct2)
}

// HESub performs homomorphic subtraction of two ciphertexts.
// Returns a new ciphertext representing ct1 - ct2.
func (em *EncryptionModule) HESub(ctx context.Context, ctxID int32, ct1, ct2 []byte) ([]byte, error) {
	return em.heBinaryCtOp(ctx, em.heSub, "wasi_he_sub", ctxID, ct1, ct2)
}

// HEMultiply performs homomorphic multiplication of two ciphertexts.
// Returns a new ciphertext representing the product. Relinearization keys
// should be set on the context for noise management.
func (em *EncryptionModule) HEMultiply(ctx context.Context, ctxID int32, ct1, ct2 []byte) ([]byte, error) {
	return em.heBinaryCtOp(ctx, em.heMultiply, "wasi_he_multiply", ctxID, ct1, ct2)
}

// HENegate performs homomorphic negation of a ciphertext.
// Returns a new ciphertext representing the negated value.
func (em *EncryptionModule) HENegate(ctx context.Context, ctxID int32, ct []byte) ([]byte, error) {
	if em.heNegate == nil {
		return nil, errors.New("wasi_he_negate not exported")
	}

	mem := em.module.Memory()

	ctPtr, err := em.allocate(ctx, uint32(len(ct)))
	if err != nil {
		return nil, err
	}
	defer em.deallocate(ctx, ctPtr)

	outLenPtr, err := em.allocate(ctx, 4)
	if err != nil {
		return nil, err
	}
	defer em.deallocate(ctx, outLenPtr)

	if !mem.Write(ctPtr, ct) {
		return nil, errors.New("failed to write ciphertext")
	}

	results, err := em.heNegate.Call(ctx,
		uint64(uint32(ctxID)),
		uint64(ctPtr), uint64(len(ct)),
		uint64(outLenPtr))
	if err != nil {
		return nil, fmt.Errorf("he_negate failed: %w", err)
	}

	dataPtr := uint32(results[0])
	if dataPtr == 0 {
		return nil, errors.New("he_negate returned null")
	}

	// Read the output length (little-endian uint32)
	lenData, ok := mem.Read(outLenPtr, 4)
	if !ok {
		return nil, errors.New("failed to read output length")
	}
	dataLen := uint32(lenData[0]) | uint32(lenData[1])<<8 |
		uint32(lenData[2])<<16 | uint32(lenData[3])<<24

	if dataLen == 0 {
		return nil, errors.New("he_negate returned zero-length ciphertext")
	}

	rawData, ok := mem.Read(dataPtr, dataLen)
	if !ok {
		return nil, errors.New("failed to read negated ciphertext")
	}

	result := make([]byte, dataLen)
	copy(result, rawData)

	em.deallocate(ctx, dataPtr)

	return result, nil
}

// heCtPlainOp is a helper for HE operations between a ciphertext and a plaintext int64.
// The WASI function signature is:
//
//	fn(ctx_id, ct_ptr, ct_len, plain_i64, out_len_ptr) -> data_ptr
func (em *EncryptionModule) heCtPlainOp(ctx context.Context, fn api.Function, fnName string, ctxID int32, ct []byte, plain int64) ([]byte, error) {
	if fn == nil {
		return nil, fmt.Errorf("%s not exported", fnName)
	}

	mem := em.module.Memory()

	ctPtr, err := em.allocate(ctx, uint32(len(ct)))
	if err != nil {
		return nil, err
	}
	defer em.deallocate(ctx, ctPtr)

	outLenPtr, err := em.allocate(ctx, 4)
	if err != nil {
		return nil, err
	}
	defer em.deallocate(ctx, outLenPtr)

	if !mem.Write(ctPtr, ct) {
		return nil, errors.New("failed to write ciphertext")
	}

	results, err := fn.Call(ctx,
		uint64(uint32(ctxID)),
		uint64(ctPtr), uint64(len(ct)),
		uint64(plain),
		uint64(outLenPtr))
	if err != nil {
		return nil, fmt.Errorf("%s failed: %w", fnName, err)
	}

	dataPtr := uint32(results[0])
	if dataPtr == 0 {
		return nil, fmt.Errorf("%s returned null", fnName)
	}

	// Read the output length (little-endian uint32)
	lenData, ok := mem.Read(outLenPtr, 4)
	if !ok {
		return nil, fmt.Errorf("failed to read output length from %s", fnName)
	}
	dataLen := uint32(lenData[0]) | uint32(lenData[1])<<8 |
		uint32(lenData[2])<<16 | uint32(lenData[3])<<24

	if dataLen == 0 {
		return nil, fmt.Errorf("%s returned zero-length ciphertext", fnName)
	}

	rawData, ok := mem.Read(dataPtr, dataLen)
	if !ok {
		return nil, fmt.Errorf("failed to read result from %s", fnName)
	}

	result := make([]byte, dataLen)
	copy(result, rawData)

	em.deallocate(ctx, dataPtr)

	return result, nil
}

// HEAddPlain performs homomorphic addition of a ciphertext and a plaintext int64.
// Returns a new ciphertext representing the sum.
func (em *EncryptionModule) HEAddPlain(ctx context.Context, ctxID int32, ct []byte, plain int64) ([]byte, error) {
	return em.heCtPlainOp(ctx, em.heAddPlain, "wasi_he_add_plain", ctxID, ct, plain)
}

// HEMultiplyPlain performs homomorphic multiplication of a ciphertext by a plaintext int64.
// Returns a new ciphertext representing the product.
func (em *EncryptionModule) HEMultiplyPlain(ctx context.Context, ctxID int32, ct []byte, plain int64) ([]byte, error) {
	return em.heCtPlainOp(ctx, em.heMultiplyPlain, "wasi_he_multiply_plain", ctxID, ct, plain)
}

func main() {
	fmt.Println("FlatBuffers WASI Encryption Example")
	fmt.Println("====================================")
	fmt.Println()
	fmt.Println("This example demonstrates using the flatc-encryption WASI module")
	fmt.Println("from Go using the wazero runtime.")
	fmt.Println()
	fmt.Println("Features:")
	fmt.Println("  - AES-256-CTR symmetric encryption")
	fmt.Println("  - X25519 ECDH key exchange")
	fmt.Println("  - secp256k1 ECDH and ECDSA signatures (Bitcoin/Ethereum)")
	fmt.Println("  - P-256 ECDH and ECDSA signatures (NIST)")
	fmt.Println("  - Ed25519 signatures")
	fmt.Println("  - Homomorphic Encryption (HE) operations")
	fmt.Println()
	fmt.Println("To run this example:")
	fmt.Println("1. Build the WASI module: cmake --build build/wasm --target flatc_wasm_wasi")
	fmt.Println("2. Run: go run .")
	fmt.Println()

	// Generate a test key
	key := make([]byte, 32)
	rand.Read(key)
	fmt.Printf("Test key: %s\n", hex.EncodeToString(key))

	// Generate a test IV
	iv := make([]byte, 16)
	rand.Read(iv)
	fmt.Printf("Test IV:  %s\n", hex.EncodeToString(iv))

	// Test data
	plaintext := []byte("Hello, FlatBuffers WASI encryption!")
	fmt.Printf("Plaintext: %s\n", string(plaintext))
	fmt.Println()

	fmt.Println("Note: The WASI module must be built before running tests.")
	fmt.Println("See README.md for build instructions.")
}
