#!/usr/bin/env python3
"""
FlatBuffers WASI Encryption Module for Python using Wasmer.

This module provides cryptographic operations via the Crypto++ WASM module:
- AES-256-CTR symmetric encryption
- HKDF-SHA256 key derivation
- X25519 ECDH key exchange
- secp256k1 ECDH and ECDSA signatures (Bitcoin/Ethereum compatible)
- P-256 ECDH and ECDSA signatures (NIST)
- P-384 ECDH and ECDSA signatures (NIST, higher security)
- Ed25519 signatures
- Field-level encryption context management
- Homomorphic Encryption (HE) via SEAL (BFV/CKKS schemes)
"""

from wasmer import engine, Store, Module, Instance, ImportObject, Function, FunctionType, Type, Memory
from wasmer_compiler_cranelift import Compiler
from pathlib import Path
from typing import Optional, Tuple
import struct

# Key and signature sizes
AES_KEY_SIZE = 32
AES_IV_SIZE = 16
SHA256_SIZE = 32
SHARED_SECRET_SIZE = 32

X25519_PRIVATE_KEY_SIZE = 32
X25519_PUBLIC_KEY_SIZE = 32

SECP256K1_PRIVATE_KEY_SIZE = 32
SECP256K1_PUBLIC_KEY_SIZE = 33  # compressed
SECP256K1_SIGNATURE_SIZE = 72   # DER encoded max

P256_PRIVATE_KEY_SIZE = 32
P256_PUBLIC_KEY_SIZE = 33  # compressed
P256_SIGNATURE_SIZE = 72   # DER encoded max

P384_PRIVATE_KEY_SIZE = 48
P384_PUBLIC_KEY_SIZE = 49  # compressed
P384_SIGNATURE_SIZE = 104  # DER encoded max
HKDF_DEFAULT_SIZE = 32

ED25519_PRIVATE_KEY_SIZE = 64  # seed + public key
ED25519_PUBLIC_KEY_SIZE = 32
ED25519_SIGNATURE_SIZE = 64


class EncryptionModule:
    """Wrapper for the FlatBuffers WASI encryption module."""

    def __init__(self, wasm_path: Optional[str] = None):
        """
        Initialize the encryption module.

        Args:
            wasm_path: Path to the WASM module. If None, searches default locations.
        """
        if wasm_path is None:
            wasm_path = self._find_wasm_module()

        # Create the store with Cranelift compiler
        self._store = Store(engine.JIT(Compiler))

        # Load and compile the module
        with open(wasm_path, 'rb') as f:
            wasm_bytes = f.read()
        self._module = Module(self._store, wasm_bytes)

        # Create import object with WASI and env functions
        import_object = self._create_imports()

        # Instantiate
        self._instance = Instance(self._module, import_object)

        # Cache exported functions
        self._malloc = self._instance.exports.malloc
        self._free = self._instance.exports.free
        self._memory = self._instance.exports.memory

    def _find_wasm_module(self) -> str:
        """Search for the WASM module in expected locations."""
        paths = [
            Path(__file__).parent / "../../../build/wasm/wasm/flatc-encryption.wasm",
            Path(__file__).parent / "../../../build/wasm/flatc-encryption.wasm",
            Path("build/wasm/wasm/flatc-encryption.wasm"),
            Path("build/wasm/flatc-encryption.wasm"),
        ]
        for p in paths:
            if p.exists():
                return str(p.resolve())
        raise FileNotFoundError("Could not find flatc-encryption.wasm")

    def _create_imports(self) -> ImportObject:
        """Create the import object with WASI and env module stubs."""
        import_object = ImportObject()

        # Store reference for invoke_* trampolines (will be set after instantiation)
        self._wasm_instance = None

        # Exception state
        self._threw = [0, 0]

        # WASI stubs (minimal implementation)
        def fd_close(fd: int) -> int:
            return 0

        def fd_seek(fd: int, offset: int, whence: int, newoffset: int) -> int:
            return 0

        def fd_write(fd: int, iovs: int, iovs_len: int, nwritten: int) -> int:
            return 0

        def fd_read(fd: int, iovs: int, iovs_len: int, nread: int) -> int:
            return 0

        def environ_sizes_get(count: int, size: int) -> int:
            if self._wasm_instance:
                mem = self._wasm_instance.exports.memory.uint8_view()
                mem[count:count+4] = struct.pack('<I', 0)
                mem[size:size+4] = struct.pack('<I', 0)
            return 0

        def environ_get(environ: int, environ_buf: int) -> int:
            return 0

        def clock_time_get(clock_id: int, precision: int, time: int) -> int:
            import time as time_module
            ns = int(time_module.time() * 1e9)
            if self._wasm_instance:
                mem = self._wasm_instance.exports.memory.uint8_view()
                mem[time:time+8] = struct.pack('<Q', ns)
            return 0

        def proc_exit(code: int):
            raise SystemExit(code)

        def random_get(buf: int, buf_len: int) -> int:
            import os
            if self._wasm_instance:
                mem = self._wasm_instance.exports.memory.uint8_view()
                random_bytes = os.urandom(buf_len)
                for i, b in enumerate(random_bytes):
                    mem[buf + i] = b
            return 0

        # Register WASI functions
        import_object.register(
            "wasi_snapshot_preview1",
            {
                "fd_close": Function(self._store, fd_close, FunctionType([Type.I32], [Type.I32])),
                "fd_seek": Function(self._store, fd_seek, FunctionType([Type.I32, Type.I64, Type.I32, Type.I32], [Type.I32])),
                "fd_write": Function(self._store, fd_write, FunctionType([Type.I32, Type.I32, Type.I32, Type.I32], [Type.I32])),
                "fd_read": Function(self._store, fd_read, FunctionType([Type.I32, Type.I32, Type.I32, Type.I32], [Type.I32])),
                "environ_sizes_get": Function(self._store, environ_sizes_get, FunctionType([Type.I32, Type.I32], [Type.I32])),
                "environ_get": Function(self._store, environ_get, FunctionType([Type.I32, Type.I32], [Type.I32])),
                "clock_time_get": Function(self._store, clock_time_get, FunctionType([Type.I32, Type.I64, Type.I32], [Type.I32])),
                "proc_exit": Function(self._store, proc_exit, FunctionType([Type.I32], [])),
                "random_get": Function(self._store, random_get, FunctionType([Type.I32, Type.I32], [Type.I32])),
            }
        )

        # Emscripten exception handling trampolines
        def set_threw(threw: int, value: int):
            self._threw = [threw, value]

        def invoke_wrapper(param_count: int, has_return: bool):
            """Create an invoke_* wrapper for the given signature."""
            def invoke(*args):
                if not self._wasm_instance:
                    return 0 if has_return else None
                idx = args[0]
                func_args = args[1:]
                try:
                    table = self._wasm_instance.exports.__indirect_function_table
                    func = table.get(idx)
                    if func:
                        result = func(*func_args)
                        return result if has_return else None
                except Exception:
                    set_threw(1, 0)
                return 0 if has_return else None
            return invoke

        # Create invoke functions for various signatures
        env_funcs = {
            "setThrew": Function(self._store, set_threw, FunctionType([Type.I32, Type.I32], [])),
            "__cxa_find_matching_catch_2": Function(self._store, lambda: 0, FunctionType([], [Type.I32])),
            "__cxa_find_matching_catch_3": Function(self._store, lambda a: 0, FunctionType([Type.I32], [Type.I32])),
            "__resumeException": Function(self._store, lambda a: None, FunctionType([Type.I32], [])),
            "__cxa_begin_catch": Function(self._store, lambda a: 0, FunctionType([Type.I32], [Type.I32])),
            "__cxa_end_catch": Function(self._store, lambda: None, FunctionType([], [])),
            "llvm_eh_typeid_for": Function(self._store, lambda a: 0, FunctionType([Type.I32], [Type.I32])),
            "__cxa_throw": Function(self._store, lambda a, b, c: None, FunctionType([Type.I32, Type.I32, Type.I32], [])),
            "__cxa_uncaught_exceptions": Function(self._store, lambda: 0, FunctionType([], [Type.I32])),
        }

        # Add invoke_* stubs - these will be replaced after instantiation
        invoke_sigs = [
            ("invoke_v", [Type.I32], []),
            ("invoke_vi", [Type.I32, Type.I32], []),
            ("invoke_vii", [Type.I32, Type.I32, Type.I32], []),
            ("invoke_viii", [Type.I32, Type.I32, Type.I32, Type.I32], []),
            ("invoke_viiii", [Type.I32, Type.I32, Type.I32, Type.I32, Type.I32], []),
            ("invoke_viiiii", [Type.I32, Type.I32, Type.I32, Type.I32, Type.I32, Type.I32], []),
            ("invoke_viiiiii", [Type.I32, Type.I32, Type.I32, Type.I32, Type.I32, Type.I32, Type.I32], []),
            ("invoke_viiiiiii", [Type.I32, Type.I32, Type.I32, Type.I32, Type.I32, Type.I32, Type.I32, Type.I32], []),
            ("invoke_viiiiiiiii", [Type.I32] * 10, []),
            ("invoke_i", [Type.I32], [Type.I32]),
            ("invoke_ii", [Type.I32, Type.I32], [Type.I32]),
            ("invoke_iii", [Type.I32, Type.I32, Type.I32], [Type.I32]),
            ("invoke_iiii", [Type.I32, Type.I32, Type.I32, Type.I32], [Type.I32]),
            ("invoke_iiiii", [Type.I32, Type.I32, Type.I32, Type.I32, Type.I32], [Type.I32]),
            ("invoke_iiiiii", [Type.I32, Type.I32, Type.I32, Type.I32, Type.I32, Type.I32], [Type.I32]),
            ("invoke_iiiiiii", [Type.I32] * 7, [Type.I32]),
            ("invoke_iiiiiiii", [Type.I32] * 8, [Type.I32]),
            ("invoke_iiiiiiiiii", [Type.I32] * 10, [Type.I32]),
        ]

        for name, params, results in invoke_sigs:
            has_return = len(results) > 0
            param_count = len(params) - 1  # exclude idx
            env_funcs[name] = Function(
                self._store,
                invoke_wrapper(param_count, has_return),
                FunctionType(params, results)
            )

        import_object.register("env", env_funcs)

        return import_object

    def _allocate(self, size: int) -> int:
        """Allocate memory in the WASM module."""
        ptr = self._malloc(size)
        if ptr == 0:
            raise MemoryError("Failed to allocate WASM memory")
        return ptr

    def _deallocate(self, ptr: int):
        """Free memory in the WASM module."""
        if ptr != 0:
            self._free(ptr)

    def _write_bytes(self, ptr: int, data: bytes):
        """Write bytes to WASM memory."""
        mem = self._memory.uint8_view()
        for i, b in enumerate(data):
            mem[ptr + i] = b

    def _read_bytes(self, ptr: int, size: int) -> bytes:
        """Read bytes from WASM memory."""
        mem = self._memory.uint8_view()
        return bytes(mem[ptr:ptr + size])

    # =========================================================================
    # Symmetric Encryption (AES-256-CTR)
    # =========================================================================

    def encrypt_bytes(self, key: bytes, iv: bytes, data: bytes) -> bytes:
        """
        Encrypt data using AES-256-CTR.

        Args:
            key: 32-byte encryption key
            iv: 16-byte initialization vector
            data: Data to encrypt

        Returns:
            Encrypted data (same length as input)
        """
        if len(key) != AES_KEY_SIZE:
            raise ValueError("Key must be 32 bytes")
        if len(iv) != AES_IV_SIZE:
            raise ValueError("IV must be 16 bytes")
        if len(data) == 0:
            return data

        # Allocate memory
        key_ptr = self._allocate(AES_KEY_SIZE)
        iv_ptr = self._allocate(AES_IV_SIZE)
        data_ptr = self._allocate(len(data))

        try:
            # Write data to WASM memory
            self._write_bytes(key_ptr, key)
            self._write_bytes(iv_ptr, iv)
            self._write_bytes(data_ptr, data)

            # Call encrypt function
            encrypt_fn = self._instance.exports.wasi_encrypt_bytes
            result = encrypt_fn(key_ptr, iv_ptr, data_ptr, len(data))

            if result != 0:
                raise RuntimeError("Encryption failed")

            # Read encrypted data
            return self._read_bytes(data_ptr, len(data))
        finally:
            self._deallocate(key_ptr)
            self._deallocate(iv_ptr)
            self._deallocate(data_ptr)

    def decrypt_bytes(self, key: bytes, iv: bytes, data: bytes) -> bytes:
        """
        Decrypt data using AES-256-CTR.

        AES-CTR is symmetric, so decryption is the same as encryption.
        """
        return self.encrypt_bytes(key, iv, data)

    # =========================================================================
    # Hash Functions
    # =========================================================================

    def sha256(self, data: bytes) -> bytes:
        """Compute SHA-256 hash."""
        data_ptr = self._allocate(len(data)) if data else 0
        hash_ptr = self._allocate(SHA256_SIZE)

        try:
            if data:
                self._write_bytes(data_ptr, data)

            sha256_fn = self._instance.exports.wasi_sha256
            sha256_fn(data_ptr, len(data), hash_ptr)

            return self._read_bytes(hash_ptr, SHA256_SIZE)
        finally:
            if data_ptr:
                self._deallocate(data_ptr)
            self._deallocate(hash_ptr)

    # =========================================================================
    # X25519 Key Exchange
    # =========================================================================

    def x25519_generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate an X25519 key pair."""
        priv_ptr = self._allocate(X25519_PRIVATE_KEY_SIZE)
        pub_ptr = self._allocate(X25519_PUBLIC_KEY_SIZE)

        try:
            gen_fn = self._instance.exports.wasi_x25519_generate_keypair
            result = gen_fn(priv_ptr, pub_ptr)

            if result != 0:
                raise RuntimeError("Key generation failed")

            private_key = self._read_bytes(priv_ptr, X25519_PRIVATE_KEY_SIZE)
            public_key = self._read_bytes(pub_ptr, X25519_PUBLIC_KEY_SIZE)
            return private_key, public_key
        finally:
            self._deallocate(priv_ptr)
            self._deallocate(pub_ptr)

    def x25519_shared_secret(self, private_key: bytes, public_key: bytes) -> bytes:
        """Perform X25519 ECDH key exchange."""
        priv_ptr = self._allocate(X25519_PRIVATE_KEY_SIZE)
        pub_ptr = self._allocate(X25519_PUBLIC_KEY_SIZE)
        secret_ptr = self._allocate(SHARED_SECRET_SIZE)

        try:
            self._write_bytes(priv_ptr, private_key)
            self._write_bytes(pub_ptr, public_key)

            ecdh_fn = self._instance.exports.wasi_x25519_shared_secret
            result = ecdh_fn(priv_ptr, pub_ptr, secret_ptr)

            if result != 0:
                raise RuntimeError("ECDH failed")

            return self._read_bytes(secret_ptr, SHARED_SECRET_SIZE)
        finally:
            self._deallocate(priv_ptr)
            self._deallocate(pub_ptr)
            self._deallocate(secret_ptr)

    # =========================================================================
    # Ed25519 Signatures
    # =========================================================================

    def ed25519_generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate an Ed25519 signing key pair."""
        priv_ptr = self._allocate(ED25519_PRIVATE_KEY_SIZE)
        pub_ptr = self._allocate(ED25519_PUBLIC_KEY_SIZE)

        try:
            gen_fn = self._instance.exports.wasi_ed25519_generate_keypair
            result = gen_fn(priv_ptr, pub_ptr)

            if result != 0:
                raise RuntimeError("Key generation failed")

            private_key = self._read_bytes(priv_ptr, ED25519_PRIVATE_KEY_SIZE)
            public_key = self._read_bytes(pub_ptr, ED25519_PUBLIC_KEY_SIZE)
            return private_key, public_key
        finally:
            self._deallocate(priv_ptr)
            self._deallocate(pub_ptr)

    def ed25519_sign(self, private_key: bytes, data: bytes) -> bytes:
        """Sign data with Ed25519."""
        priv_ptr = self._allocate(ED25519_PRIVATE_KEY_SIZE)
        data_ptr = self._allocate(len(data))
        sig_ptr = self._allocate(ED25519_SIGNATURE_SIZE)

        try:
            self._write_bytes(priv_ptr, private_key)
            self._write_bytes(data_ptr, data)

            sign_fn = self._instance.exports.wasi_ed25519_sign
            result = sign_fn(priv_ptr, data_ptr, len(data), sig_ptr)

            if result != 0:
                raise RuntimeError("Signing failed")

            return self._read_bytes(sig_ptr, ED25519_SIGNATURE_SIZE)
        finally:
            self._deallocate(priv_ptr)
            self._deallocate(data_ptr)
            self._deallocate(sig_ptr)

    def ed25519_verify(self, public_key: bytes, data: bytes, signature: bytes) -> bool:
        """Verify an Ed25519 signature."""
        pub_ptr = self._allocate(ED25519_PUBLIC_KEY_SIZE)
        data_ptr = self._allocate(len(data))
        sig_ptr = self._allocate(ED25519_SIGNATURE_SIZE)

        try:
            self._write_bytes(pub_ptr, public_key)
            self._write_bytes(data_ptr, data)
            self._write_bytes(sig_ptr, signature)

            verify_fn = self._instance.exports.wasi_ed25519_verify
            result = verify_fn(pub_ptr, data_ptr, len(data), sig_ptr)

            return result == 0
        finally:
            self._deallocate(pub_ptr)
            self._deallocate(data_ptr)
            self._deallocate(sig_ptr)

    def version(self) -> str:
        """Get the module version string."""
        try:
            version_fn = self._instance.exports.wasi_get_version
            ptr = version_fn()
            if ptr == 0:
                return "unknown"

            # Read null-terminated string
            mem = self._memory.uint8_view()
            result = []
            for i in range(32):
                b = mem[ptr + i]
                if b == 0:
                    break
                result.append(chr(b))
            return ''.join(result)
        except Exception:
            return "unknown"

    def has_cryptopp(self) -> bool:
        """Check if Crypto++ is available."""
        try:
            check_fn = self._instance.exports.wasi_has_cryptopp
            return check_fn() == 1
        except Exception:
            return False

    # =========================================================================
    # HKDF Key Derivation
    # =========================================================================

    def hkdf(self, ikm: bytes, salt: bytes, info: bytes, okm_size: int = 32) -> bytes:
        """
        Derive key material using HKDF-SHA256.

        Args:
            ikm: Input key material
            salt: Salt value (can be empty)
            info: Context/info value (can be empty)
            okm_size: Desired output key material size

        Returns:
            Derived key material of okm_size bytes
        """
        if okm_size <= 0:
            raise ValueError("Output size must be positive")

        ikm_ptr = self._allocate(len(ikm)) if ikm else 0
        salt_ptr = self._allocate(len(salt)) if salt else 0
        info_ptr = self._allocate(len(info)) if info else 0
        okm_ptr = self._allocate(okm_size)

        try:
            if ikm:
                self._write_bytes(ikm_ptr, ikm)
            if salt:
                self._write_bytes(salt_ptr, salt)
            if info:
                self._write_bytes(info_ptr, info)

            hkdf_fn = self._instance.exports.wasi_hkdf
            hkdf_fn(ikm_ptr, len(ikm), salt_ptr, len(salt),
                     info_ptr, len(info), okm_ptr, okm_size)

            return self._read_bytes(okm_ptr, okm_size)
        finally:
            if ikm_ptr:
                self._deallocate(ikm_ptr)
            if salt_ptr:
                self._deallocate(salt_ptr)
            if info_ptr:
                self._deallocate(info_ptr)
            self._deallocate(okm_ptr)

    def derive_symmetric_key(self, shared_secret: bytes, context: bytes = b"") -> bytes:
        """
        Derive a symmetric key from a shared secret using HKDF.

        Args:
            shared_secret: ECDH shared secret (32 bytes)
            context: Optional context/info bytes

        Returns:
            32-byte symmetric key
        """
        secret_ptr = self._allocate(len(shared_secret))
        context_ptr = self._allocate(len(context)) if context else 0
        key_ptr = self._allocate(AES_KEY_SIZE)

        try:
            self._write_bytes(secret_ptr, shared_secret)
            if context:
                self._write_bytes(context_ptr, context)

            derive_fn = self._instance.exports.wasi_derive_symmetric_key
            derive_fn(secret_ptr, context_ptr, len(context), key_ptr)

            return self._read_bytes(key_ptr, AES_KEY_SIZE)
        finally:
            self._deallocate(secret_ptr)
            if context_ptr:
                self._deallocate(context_ptr)
            self._deallocate(key_ptr)

    # =========================================================================
    # secp256k1 Key Exchange and Signatures (Bitcoin/Ethereum)
    # =========================================================================

    def secp256k1_generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a secp256k1 key pair."""
        priv_ptr = self._allocate(SECP256K1_PRIVATE_KEY_SIZE)
        pub_ptr = self._allocate(SECP256K1_PUBLIC_KEY_SIZE)

        try:
            gen_fn = self._instance.exports.wasi_secp256k1_generate_keypair
            result = gen_fn(priv_ptr, pub_ptr)

            if result != 0:
                raise RuntimeError("Key generation failed")

            private_key = self._read_bytes(priv_ptr, SECP256K1_PRIVATE_KEY_SIZE)
            public_key = self._read_bytes(pub_ptr, SECP256K1_PUBLIC_KEY_SIZE)
            return private_key, public_key
        finally:
            self._deallocate(priv_ptr)
            self._deallocate(pub_ptr)

    def secp256k1_shared_secret(self, private_key: bytes, public_key: bytes) -> bytes:
        """Perform secp256k1 ECDH key exchange."""
        priv_ptr = self._allocate(SECP256K1_PRIVATE_KEY_SIZE)
        pub_ptr = self._allocate(len(public_key))
        secret_ptr = self._allocate(SHARED_SECRET_SIZE)

        try:
            self._write_bytes(priv_ptr, private_key)
            self._write_bytes(pub_ptr, public_key)

            ecdh_fn = self._instance.exports.wasi_secp256k1_shared_secret
            result = ecdh_fn(priv_ptr, pub_ptr, len(public_key), secret_ptr)

            if result != 0:
                raise RuntimeError("ECDH failed")

            return self._read_bytes(secret_ptr, SHARED_SECRET_SIZE)
        finally:
            self._deallocate(priv_ptr)
            self._deallocate(pub_ptr)
            self._deallocate(secret_ptr)

    def secp256k1_sign(self, private_key: bytes, data: bytes) -> bytes:
        """Sign data with secp256k1 ECDSA."""
        priv_ptr = self._allocate(SECP256K1_PRIVATE_KEY_SIZE)
        data_ptr = self._allocate(len(data))
        sig_ptr = self._allocate(SECP256K1_SIGNATURE_SIZE)
        sig_size_ptr = self._allocate(4)

        try:
            self._write_bytes(priv_ptr, private_key)
            self._write_bytes(data_ptr, data)

            sign_fn = self._instance.exports.wasi_secp256k1_sign
            result = sign_fn(priv_ptr, data_ptr, len(data), sig_ptr, sig_size_ptr)

            if result != 0:
                raise RuntimeError("Signing failed")

            sig_size = struct.unpack('<I', self._read_bytes(sig_size_ptr, 4))[0]
            return self._read_bytes(sig_ptr, sig_size)
        finally:
            self._deallocate(priv_ptr)
            self._deallocate(data_ptr)
            self._deallocate(sig_ptr)
            self._deallocate(sig_size_ptr)

    def secp256k1_verify(self, public_key: bytes, data: bytes, signature: bytes) -> bool:
        """Verify a secp256k1 ECDSA signature."""
        pub_ptr = self._allocate(len(public_key))
        data_ptr = self._allocate(len(data))
        sig_ptr = self._allocate(len(signature))

        try:
            self._write_bytes(pub_ptr, public_key)
            self._write_bytes(data_ptr, data)
            self._write_bytes(sig_ptr, signature)

            verify_fn = self._instance.exports.wasi_secp256k1_verify
            result = verify_fn(pub_ptr, len(public_key), data_ptr, len(data),
                               sig_ptr, len(signature))

            return result == 0
        finally:
            self._deallocate(pub_ptr)
            self._deallocate(data_ptr)
            self._deallocate(sig_ptr)

    # =========================================================================
    # P-256 Key Exchange and Signatures (NIST)
    # =========================================================================

    def p256_generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a P-256 key pair."""
        priv_ptr = self._allocate(P256_PRIVATE_KEY_SIZE)
        pub_ptr = self._allocate(P256_PUBLIC_KEY_SIZE)

        try:
            gen_fn = self._instance.exports.wasi_p256_generate_keypair
            result = gen_fn(priv_ptr, pub_ptr)

            if result != 0:
                raise RuntimeError("Key generation failed")

            private_key = self._read_bytes(priv_ptr, P256_PRIVATE_KEY_SIZE)
            public_key = self._read_bytes(pub_ptr, P256_PUBLIC_KEY_SIZE)
            return private_key, public_key
        finally:
            self._deallocate(priv_ptr)
            self._deallocate(pub_ptr)

    def p256_shared_secret(self, private_key: bytes, public_key: bytes) -> bytes:
        """Perform P-256 ECDH key exchange."""
        priv_ptr = self._allocate(P256_PRIVATE_KEY_SIZE)
        pub_ptr = self._allocate(len(public_key))
        secret_ptr = self._allocate(SHARED_SECRET_SIZE)

        try:
            self._write_bytes(priv_ptr, private_key)
            self._write_bytes(pub_ptr, public_key)

            ecdh_fn = self._instance.exports.wasi_p256_shared_secret
            result = ecdh_fn(priv_ptr, pub_ptr, len(public_key), secret_ptr)

            if result != 0:
                raise RuntimeError("ECDH failed")

            return self._read_bytes(secret_ptr, SHARED_SECRET_SIZE)
        finally:
            self._deallocate(priv_ptr)
            self._deallocate(pub_ptr)
            self._deallocate(secret_ptr)

    def p256_sign(self, private_key: bytes, data: bytes) -> bytes:
        """Sign data with P-256 ECDSA."""
        priv_ptr = self._allocate(P256_PRIVATE_KEY_SIZE)
        data_ptr = self._allocate(len(data))
        sig_ptr = self._allocate(P256_SIGNATURE_SIZE)
        sig_size_ptr = self._allocate(4)

        try:
            self._write_bytes(priv_ptr, private_key)
            self._write_bytes(data_ptr, data)

            sign_fn = self._instance.exports.wasi_p256_sign
            result = sign_fn(priv_ptr, data_ptr, len(data), sig_ptr, sig_size_ptr)

            if result != 0:
                raise RuntimeError("Signing failed")

            sig_size = struct.unpack('<I', self._read_bytes(sig_size_ptr, 4))[0]
            return self._read_bytes(sig_ptr, sig_size)
        finally:
            self._deallocate(priv_ptr)
            self._deallocate(data_ptr)
            self._deallocate(sig_ptr)
            self._deallocate(sig_size_ptr)

    def p256_verify(self, public_key: bytes, data: bytes, signature: bytes) -> bool:
        """Verify a P-256 ECDSA signature."""
        pub_ptr = self._allocate(len(public_key))
        data_ptr = self._allocate(len(data))
        sig_ptr = self._allocate(len(signature))

        try:
            self._write_bytes(pub_ptr, public_key)
            self._write_bytes(data_ptr, data)
            self._write_bytes(sig_ptr, signature)

            verify_fn = self._instance.exports.wasi_p256_verify
            result = verify_fn(pub_ptr, len(public_key), data_ptr, len(data),
                               sig_ptr, len(signature))

            return result == 0
        finally:
            self._deallocate(pub_ptr)
            self._deallocate(data_ptr)
            self._deallocate(sig_ptr)

    # =========================================================================
    # P-384 Key Exchange and Signatures (NIST, higher security)
    # =========================================================================

    def p384_generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a P-384 key pair."""
        priv_ptr = self._allocate(P384_PRIVATE_KEY_SIZE)
        pub_ptr = self._allocate(P384_PUBLIC_KEY_SIZE)

        try:
            gen_fn = self._instance.exports.wasi_p384_generate_keypair
            result = gen_fn(priv_ptr, pub_ptr)

            if result != 0:
                raise RuntimeError("Key generation failed")

            private_key = self._read_bytes(priv_ptr, P384_PRIVATE_KEY_SIZE)
            public_key = self._read_bytes(pub_ptr, P384_PUBLIC_KEY_SIZE)
            return private_key, public_key
        finally:
            self._deallocate(priv_ptr)
            self._deallocate(pub_ptr)

    def p384_shared_secret(self, private_key: bytes, public_key: bytes) -> bytes:
        """Perform P-384 ECDH key exchange."""
        priv_ptr = self._allocate(P384_PRIVATE_KEY_SIZE)
        pub_ptr = self._allocate(len(public_key))
        secret_ptr = self._allocate(SHARED_SECRET_SIZE)

        try:
            self._write_bytes(priv_ptr, private_key)
            self._write_bytes(pub_ptr, public_key)

            ecdh_fn = self._instance.exports.wasi_p384_shared_secret
            result = ecdh_fn(priv_ptr, pub_ptr, len(public_key), secret_ptr)

            if result != 0:
                raise RuntimeError("ECDH failed")

            return self._read_bytes(secret_ptr, SHARED_SECRET_SIZE)
        finally:
            self._deallocate(priv_ptr)
            self._deallocate(pub_ptr)
            self._deallocate(secret_ptr)

    def p384_sign(self, private_key: bytes, data: bytes) -> bytes:
        """Sign data with P-384 ECDSA."""
        priv_ptr = self._allocate(P384_PRIVATE_KEY_SIZE)
        data_ptr = self._allocate(len(data))
        sig_ptr = self._allocate(P384_SIGNATURE_SIZE)
        sig_size_ptr = self._allocate(4)

        try:
            self._write_bytes(priv_ptr, private_key)
            self._write_bytes(data_ptr, data)

            sign_fn = self._instance.exports.wasi_p384_sign
            result = sign_fn(priv_ptr, data_ptr, len(data), sig_ptr, sig_size_ptr)

            if result != 0:
                raise RuntimeError("Signing failed")

            sig_size = struct.unpack('<I', self._read_bytes(sig_size_ptr, 4))[0]
            return self._read_bytes(sig_ptr, sig_size)
        finally:
            self._deallocate(priv_ptr)
            self._deallocate(data_ptr)
            self._deallocate(sig_ptr)
            self._deallocate(sig_size_ptr)

    def p384_verify(self, public_key: bytes, data: bytes, signature: bytes) -> bool:
        """Verify a P-384 ECDSA signature."""
        pub_ptr = self._allocate(len(public_key))
        data_ptr = self._allocate(len(data))
        sig_ptr = self._allocate(len(signature))

        try:
            self._write_bytes(pub_ptr, public_key)
            self._write_bytes(data_ptr, data)
            self._write_bytes(sig_ptr, signature)

            verify_fn = self._instance.exports.wasi_p384_verify
            result = verify_fn(pub_ptr, len(public_key), data_ptr, len(data),
                               sig_ptr, len(signature))

            return result == 0
        finally:
            self._deallocate(pub_ptr)
            self._deallocate(data_ptr)
            self._deallocate(sig_ptr)

    # =========================================================================
    # Entropy Management
    # =========================================================================

    def inject_entropy(self, seed: bytes) -> None:
        """
        Inject external entropy into the WASM RNG pool.

        Args:
            seed: Entropy bytes (recommended: 32-64 bytes)
        """
        seed_ptr = self._allocate(len(seed))

        try:
            self._write_bytes(seed_ptr, seed)

            inject_fn = self._instance.exports.wasi_inject_entropy
            result = inject_fn(seed_ptr, len(seed))

            if result != 0:
                raise RuntimeError("Entropy injection failed")
        finally:
            self._deallocate(seed_ptr)

    # =========================================================================
    # Field-level Encryption
    # =========================================================================

    def derive_field_key(self, ctx_ptr: int, field_id: int) -> bytes:
        """
        Derive a field-specific key from an encryption context.

        Args:
            ctx_ptr: Encryption context pointer (from EncryptionContext._ptr)
            field_id: Field identifier for key derivation

        Returns:
            32-byte derived key
        """
        out_ptr = self._allocate(AES_KEY_SIZE)

        try:
            fn = self._instance.exports.wasi_derive_field_key
            result = fn(ctx_ptr, field_id, out_ptr)

            if result != 0:
                raise RuntimeError("Field key derivation failed")

            return self._read_bytes(out_ptr, AES_KEY_SIZE)
        finally:
            self._deallocate(out_ptr)

    def derive_field_iv(self, ctx_ptr: int, field_id: int) -> bytes:
        """
        Derive a field-specific IV from an encryption context.

        Args:
            ctx_ptr: Encryption context pointer (from EncryptionContext._ptr)
            field_id: Field identifier for IV derivation

        Returns:
            16-byte derived IV
        """
        out_ptr = self._allocate(AES_IV_SIZE)

        try:
            fn = self._instance.exports.wasi_derive_field_iv
            result = fn(ctx_ptr, field_id, out_ptr)

            if result != 0:
                raise RuntimeError("Field IV derivation failed")

            return self._read_bytes(out_ptr, AES_IV_SIZE)
        finally:
            self._deallocate(out_ptr)

    def create_encryption_context(self, key: bytes) -> 'EncryptionContext':
        """
        Create a field-level encryption context.

        Args:
            key: 32-byte master encryption key

        Returns:
            EncryptionContext instance (use as context manager)
        """
        return EncryptionContext(self, key)

    # =========================================================================
    # Homomorphic Encryption (HE)
    # =========================================================================

    def has_he(self) -> bool:
        """Check if the WASI module supports homomorphic encryption."""
        try:
            _ = self._instance.exports.wasi_he_context_create_client
            return True
        except Exception:
            return False

    def he_create_client(self, poly_degree: int = 0) -> int:
        """
        Create a client HE context with full key material (secret + public).

        Args:
            poly_degree: Polynomial modulus degree (0 = default 4096).

        Returns:
            Context ID (>0) for use with other HE methods.

        Raises:
            RuntimeError: If context creation fails.
        """
        fn = self._instance.exports.wasi_he_context_create_client
        ctx_id = fn(poly_degree)
        if ctx_id < 0:
            raise RuntimeError("HE client context creation failed")
        return ctx_id

    def he_create_server(self, public_key: bytes) -> int:
        """
        Create a server HE context from a serialized public key.
        The server context can encrypt and perform operations but cannot decrypt.

        Args:
            public_key: Serialized public key bytes from a client context.

        Returns:
            Context ID (>0) for use with other HE methods.

        Raises:
            RuntimeError: If context creation fails.
        """
        pk_ptr = self._allocate(len(public_key))

        try:
            self._write_bytes(pk_ptr, public_key)

            fn = self._instance.exports.wasi_he_context_create_server
            ctx_id = fn(pk_ptr, len(public_key))

            if ctx_id < 0:
                raise RuntimeError("HE server context creation failed")

            return ctx_id
        finally:
            self._deallocate(pk_ptr)

    def he_destroy_context(self, ctx_id: int) -> None:
        """
        Destroy an HE context and free its resources.

        Args:
            ctx_id: Context ID returned by he_create_client or he_create_server.
        """
        fn = self._instance.exports.wasi_he_context_destroy
        fn(ctx_id)

    def _he_get_variable_length_data(self, fn_name: str, ctx_id: int) -> bytes:
        """
        Helper for HE functions that return variable-length data.
        Signature: fn(ctx_id i32, out_len_ptr i32) -> data_ptr i32
        """
        fn = getattr(self._instance.exports, fn_name)

        # Allocate 4 bytes for output length
        out_len_ptr = self._allocate(4)

        try:
            data_ptr = fn(ctx_id, out_len_ptr)
            if data_ptr == 0:
                raise RuntimeError(f"{fn_name} returned null")

            # Read the output length (little-endian uint32)
            data_len = struct.unpack('<I', self._read_bytes(out_len_ptr, 4))[0]
            if data_len == 0:
                raise RuntimeError(f"{fn_name} returned zero-length data")

            # Read the data
            return self._read_bytes(data_ptr, data_len)
        finally:
            self._deallocate(out_len_ptr)

    def he_get_public_key(self, ctx_id: int) -> bytes:
        """
        Get the serialized public key from an HE context.

        Args:
            ctx_id: Context ID.

        Returns:
            Serialized public key bytes.
        """
        return self._he_get_variable_length_data("wasi_he_get_public_key", ctx_id)

    def he_get_relin_keys(self, ctx_id: int) -> bytes:
        """
        Get the serialized relinearization keys from an HE context.

        Args:
            ctx_id: Context ID.

        Returns:
            Serialized relinearization key bytes.
        """
        return self._he_get_variable_length_data("wasi_he_get_relin_keys", ctx_id)

    def he_get_secret_key(self, ctx_id: int) -> bytes:
        """
        Get the serialized secret key from a client HE context.

        Args:
            ctx_id: Context ID (must be a client context).

        Returns:
            Serialized secret key bytes.
        """
        return self._he_get_variable_length_data("wasi_he_get_secret_key", ctx_id)

    def he_set_relin_keys(self, ctx_id: int, relin_keys: bytes) -> None:
        """
        Set relinearization keys on a server HE context.
        Required before performing multiplication on the server side.

        Args:
            ctx_id: Context ID (server context).
            relin_keys: Serialized relinearization key bytes.

        Raises:
            RuntimeError: If setting relin keys fails.
        """
        rk_ptr = self._allocate(len(relin_keys))

        try:
            self._write_bytes(rk_ptr, relin_keys)

            fn = self._instance.exports.wasi_he_set_relin_keys
            result = fn(ctx_id, rk_ptr, len(relin_keys))

            if result != 0:
                raise RuntimeError("HE set relin keys failed")
        finally:
            self._deallocate(rk_ptr)

    def he_encrypt_int64(self, ctx_id: int, value: int) -> bytes:
        """
        Encrypt a 64-bit integer using the BFV scheme.

        Args:
            ctx_id: Context ID.
            value: Integer value to encrypt.

        Returns:
            Serialized ciphertext bytes.
        """
        out_len_ptr = self._allocate(4)

        try:
            fn = self._instance.exports.wasi_he_encrypt_int64
            data_ptr = fn(ctx_id, value, out_len_ptr)

            if data_ptr == 0:
                raise RuntimeError("HE encrypt int64 returned null")

            data_len = struct.unpack('<I', self._read_bytes(out_len_ptr, 4))[0]
            if data_len == 0:
                raise RuntimeError("HE encrypt int64 returned zero-length ciphertext")

            return self._read_bytes(data_ptr, data_len)
        finally:
            self._deallocate(out_len_ptr)

    def he_decrypt_int64(self, ctx_id: int, ciphertext: bytes) -> int:
        """
        Decrypt a ciphertext to a 64-bit integer using the BFV scheme.

        Args:
            ctx_id: Context ID (must be a client context with secret key).
            ciphertext: Serialized ciphertext bytes.

        Returns:
            Decrypted integer value.
        """
        ct_ptr = self._allocate(len(ciphertext))

        try:
            self._write_bytes(ct_ptr, ciphertext)

            fn = self._instance.exports.wasi_he_decrypt_int64
            return fn(ctx_id, ct_ptr, len(ciphertext))
        finally:
            self._deallocate(ct_ptr)

    def he_encrypt_double(self, ctx_id: int, value: float) -> bytes:
        """
        Encrypt a double-precision float using the CKKS scheme.

        Args:
            ctx_id: Context ID.
            value: Double value to encrypt.

        Returns:
            Serialized ciphertext bytes.
        """
        out_len_ptr = self._allocate(4)

        try:
            fn = self._instance.exports.wasi_he_encrypt_double
            data_ptr = fn(ctx_id, value, out_len_ptr)

            if data_ptr == 0:
                raise RuntimeError("HE encrypt double returned null")

            data_len = struct.unpack('<I', self._read_bytes(out_len_ptr, 4))[0]
            if data_len == 0:
                raise RuntimeError("HE encrypt double returned zero-length ciphertext")

            return self._read_bytes(data_ptr, data_len)
        finally:
            self._deallocate(out_len_ptr)

    def he_decrypt_double(self, ctx_id: int, ciphertext: bytes) -> float:
        """
        Decrypt a ciphertext to a double-precision float using the CKKS scheme.

        Args:
            ctx_id: Context ID (must be a client context with secret key).
            ciphertext: Serialized ciphertext bytes.

        Returns:
            Decrypted double value.
        """
        ct_ptr = self._allocate(len(ciphertext))

        try:
            self._write_bytes(ct_ptr, ciphertext)

            fn = self._instance.exports.wasi_he_decrypt_double
            return fn(ctx_id, ct_ptr, len(ciphertext))
        finally:
            self._deallocate(ct_ptr)

    def _he_binary_ct_op(self, fn_name: str, ctx_id: int, ct1: bytes, ct2: bytes) -> bytes:
        """
        Helper for HE binary ciphertext operations (add, sub, multiply).
        Signature: fn(ctx_id, ct1_ptr, ct1_len, ct2_ptr, ct2_len, out_len_ptr) -> data_ptr
        """
        fn = getattr(self._instance.exports, fn_name)

        ct1_ptr = self._allocate(len(ct1))
        ct2_ptr = self._allocate(len(ct2))
        out_len_ptr = self._allocate(4)

        try:
            self._write_bytes(ct1_ptr, ct1)
            self._write_bytes(ct2_ptr, ct2)

            data_ptr = fn(ctx_id, ct1_ptr, len(ct1), ct2_ptr, len(ct2), out_len_ptr)

            if data_ptr == 0:
                raise RuntimeError(f"{fn_name} returned null")

            data_len = struct.unpack('<I', self._read_bytes(out_len_ptr, 4))[0]
            if data_len == 0:
                raise RuntimeError(f"{fn_name} returned zero-length ciphertext")

            return self._read_bytes(data_ptr, data_len)
        finally:
            self._deallocate(ct1_ptr)
            self._deallocate(ct2_ptr)
            self._deallocate(out_len_ptr)

    def he_add(self, ctx_id: int, ct1: bytes, ct2: bytes) -> bytes:
        """
        Perform homomorphic addition of two ciphertexts.

        Args:
            ctx_id: Context ID.
            ct1: First ciphertext.
            ct2: Second ciphertext.

        Returns:
            Ciphertext representing ct1 + ct2.
        """
        return self._he_binary_ct_op("wasi_he_add", ctx_id, ct1, ct2)

    def he_sub(self, ctx_id: int, ct1: bytes, ct2: bytes) -> bytes:
        """
        Perform homomorphic subtraction of two ciphertexts.

        Args:
            ctx_id: Context ID.
            ct1: First ciphertext.
            ct2: Second ciphertext.

        Returns:
            Ciphertext representing ct1 - ct2.
        """
        return self._he_binary_ct_op("wasi_he_sub", ctx_id, ct1, ct2)

    def he_multiply(self, ctx_id: int, ct1: bytes, ct2: bytes) -> bytes:
        """
        Perform homomorphic multiplication of two ciphertexts.
        Relinearization keys should be set on the context for noise management.

        Args:
            ctx_id: Context ID.
            ct1: First ciphertext.
            ct2: Second ciphertext.

        Returns:
            Ciphertext representing ct1 * ct2.
        """
        return self._he_binary_ct_op("wasi_he_multiply", ctx_id, ct1, ct2)

    def he_negate(self, ctx_id: int, ct: bytes) -> bytes:
        """
        Perform homomorphic negation of a ciphertext.

        Args:
            ctx_id: Context ID.
            ct: Ciphertext to negate.

        Returns:
            Ciphertext representing -ct.
        """
        ct_ptr = self._allocate(len(ct))
        out_len_ptr = self._allocate(4)

        try:
            self._write_bytes(ct_ptr, ct)

            fn = self._instance.exports.wasi_he_negate
            data_ptr = fn(ctx_id, ct_ptr, len(ct), out_len_ptr)

            if data_ptr == 0:
                raise RuntimeError("HE negate returned null")

            data_len = struct.unpack('<I', self._read_bytes(out_len_ptr, 4))[0]
            if data_len == 0:
                raise RuntimeError("HE negate returned zero-length ciphertext")

            return self._read_bytes(data_ptr, data_len)
        finally:
            self._deallocate(ct_ptr)
            self._deallocate(out_len_ptr)

    def _he_ct_plain_op(self, fn_name: str, ctx_id: int, ct: bytes, plain: int) -> bytes:
        """
        Helper for HE operations between a ciphertext and a plaintext int64.
        Signature: fn(ctx_id, ct_ptr, ct_len, plain_i64, out_len_ptr) -> data_ptr
        """
        fn = getattr(self._instance.exports, fn_name)

        ct_ptr = self._allocate(len(ct))
        out_len_ptr = self._allocate(4)

        try:
            self._write_bytes(ct_ptr, ct)

            data_ptr = fn(ctx_id, ct_ptr, len(ct), plain, out_len_ptr)

            if data_ptr == 0:
                raise RuntimeError(f"{fn_name} returned null")

            data_len = struct.unpack('<I', self._read_bytes(out_len_ptr, 4))[0]
            if data_len == 0:
                raise RuntimeError(f"{fn_name} returned zero-length ciphertext")

            return self._read_bytes(data_ptr, data_len)
        finally:
            self._deallocate(ct_ptr)
            self._deallocate(out_len_ptr)

    def he_add_plain(self, ctx_id: int, ct: bytes, plain: int) -> bytes:
        """
        Perform homomorphic addition of a ciphertext and a plaintext int64.

        Args:
            ctx_id: Context ID.
            ct: Ciphertext.
            plain: Plaintext integer value to add.

        Returns:
            Ciphertext representing ct + plain.
        """
        return self._he_ct_plain_op("wasi_he_add_plain", ctx_id, ct, plain)

    def he_multiply_plain(self, ctx_id: int, ct: bytes, plain: int) -> bytes:
        """
        Perform homomorphic multiplication of a ciphertext by a plaintext int64.

        Args:
            ctx_id: Context ID.
            ct: Ciphertext.
            plain: Plaintext integer value to multiply by.

        Returns:
            Ciphertext representing ct * plain.
        """
        return self._he_ct_plain_op("wasi_he_multiply_plain", ctx_id, ct, plain)


class EncryptionContext:
    """Field-level encryption context wrapping a WASI encryption context handle."""

    def __init__(self, module: 'EncryptionModule', key: bytes):
        if len(key) != AES_KEY_SIZE:
            raise ValueError("Key must be 32 bytes")
        self._module = module
        # Call wasi_encryption_create(key_ptr, key_size) -> ptr
        key_ptr = module._allocate(AES_KEY_SIZE)
        try:
            module._write_bytes(key_ptr, key)
            create_fn = module._instance.exports.wasi_encryption_create
            self._ptr = create_fn(key_ptr, AES_KEY_SIZE)
            if self._ptr == 0:
                raise RuntimeError("Failed to create encryption context")
        finally:
            module._deallocate(key_ptr)

    def close(self):
        """Destroy the encryption context and free resources."""
        if self._ptr != 0:
            destroy_fn = self._module._instance.exports.wasi_encryption_destroy
            destroy_fn(self._ptr)
            self._ptr = 0

    def derive_field_key(self, field_id: int) -> bytes:
        """
        Derive a field-specific key.

        Args:
            field_id: Field identifier for key derivation

        Returns:
            32-byte derived key
        """
        out_ptr = self._module._allocate(AES_KEY_SIZE)
        try:
            fn = self._module._instance.exports.wasi_derive_field_key
            result = fn(self._ptr, field_id, out_ptr)
            if result != 0:
                raise RuntimeError("Field key derivation failed")
            return self._module._read_bytes(out_ptr, AES_KEY_SIZE)
        finally:
            self._module._deallocate(out_ptr)

    def derive_field_iv(self, field_id: int) -> bytes:
        """
        Derive a field-specific IV.

        Args:
            field_id: Field identifier for IV derivation

        Returns:
            16-byte derived IV
        """
        out_ptr = self._module._allocate(AES_IV_SIZE)
        try:
            fn = self._module._instance.exports.wasi_derive_field_iv
            result = fn(self._ptr, field_id, out_ptr)
            if result != 0:
                raise RuntimeError("Field IV derivation failed")
            return self._module._read_bytes(out_ptr, AES_IV_SIZE)
        finally:
            self._module._deallocate(out_ptr)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def main():
    """Demo the encryption module."""
    import os

    print("FlatBuffers WASI Encryption - Python/Wasmer")
    print("=" * 50)

    try:
        em = EncryptionModule()
        print(f"Module version: {em.version()}")
        print(f"Crypto++ available: {em.has_cryptopp()}")
        print()

        # Test encryption
        key = os.urandom(32)
        iv = os.urandom(16)
        plaintext = b"Hello, FlatBuffers WASI encryption from Python!"

        print(f"Plaintext: {plaintext.decode()}")
        print(f"Key: {key.hex()}")
        print(f"IV: {iv.hex()}")

        encrypted = em.encrypt_bytes(key, iv, plaintext)
        print(f"Encrypted: {encrypted.hex()}")

        decrypted = em.decrypt_bytes(key, iv, encrypted)
        print(f"Decrypted: {decrypted.decode()}")

        assert decrypted == plaintext, "Decryption failed!"
        print("\n✓ Encryption/decryption successful!")

    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("\nBuild the WASM module first:")
        print("  cmake --build build/wasm --target flatc_wasm_wasi")


if __name__ == "__main__":
    main()
