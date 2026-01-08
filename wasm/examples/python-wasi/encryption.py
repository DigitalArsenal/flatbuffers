#!/usr/bin/env python3
"""
FlatBuffers WASI Encryption Module for Python using Wasmer.

This module provides cryptographic operations via the Crypto++ WASM module:
- AES-256-CTR symmetric encryption
- X25519 ECDH key exchange
- secp256k1 ECDH and ECDSA signatures (Bitcoin/Ethereum compatible)
- P-256 ECDH and ECDSA signatures (NIST)
- Ed25519 signatures
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
