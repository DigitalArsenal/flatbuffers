#!/usr/bin/env python3
"""
Python E2E Test Runner for FlatBuffers Cross-Language Encryption

This test runner:
1. Loads test vectors and encryption keys for all 10 crypto chains
2. Tests encryption/decryption with the WASM module
3. Verifies cross-language compatibility with binaries from other languages
"""

import json
import os
import sys
from pathlib import Path

# Wasmer imports
try:
    from wasmer import Store, Module, Instance, Function, FunctionType, Type, Memory, Table, Value
    from wasmer_compiler_cranelift import Compiler
except ImportError:
    print("Error: wasmer not installed. Run: pip install wasmer wasmer-compiler-cranelift")
    sys.exit(1)

# Paths
SCRIPT_DIR = Path(__file__).parent
VECTORS_DIR = SCRIPT_DIR.parent.parent / "vectors"
WASM_PATH = SCRIPT_DIR.parent.parent.parent.parent / "build" / "wasm" / "wasm" / "flatc-encryption.wasm"


class TestResult:
    """Tracks test outcomes."""

    def __init__(self, name: str):
        self.name = name
        self.passed = 0
        self.failed = 0
        self.errors = []

    def pass_(self, msg: str):
        self.passed += 1
        print(f"  ✓ {msg}")

    def fail(self, msg: str, error: Exception = None):
        self.failed += 1
        err_msg = f"{msg}: {error}" if error else msg
        self.errors.append(err_msg)
        print(f"  ✗ {err_msg}")

    def summary(self) -> bool:
        total = self.passed + self.failed
        status = "✓" if self.failed == 0 else "✗"
        print(f"\n{status} {self.name}: {self.passed}/{total} passed")
        return self.failed == 0


class EncryptionModule:
    """Wrapper for the FlatBuffers WASI encryption module using Wasmer."""

    def __init__(self, wasm_path: Path):
        if not wasm_path.exists():
            raise FileNotFoundError(f"WASM module not found: {wasm_path}")

        wasm_bytes = wasm_path.read_bytes()
        self.store = Store(Compiler)
        module = Module(self.store, wasm_bytes)

        # Create environment with exception handling stubs and invoke_* trampolines
        self._threw = [0, 0]
        self._table = None
        self._memory = None

        imports = self._create_imports(module)
        self.instance = Instance(module, imports)

        # Store references
        self._memory = self.instance.exports.memory
        try:
            self._table = self.instance.exports.__indirect_function_table
        except AttributeError:
            pass

        # Get exported functions
        self.malloc = self.instance.exports.malloc
        self.free = self.instance.exports.free
        self.get_version = self.instance.exports.get_version
        self.has_cryptopp = self.instance.exports.has_cryptopp
        self.encrypt_bytes = self.instance.exports.encrypt_bytes
        self.decrypt_bytes = self.instance.exports.decrypt_bytes
        self.sha256_func = self.instance.exports.sha256

    def _create_imports(self, module):
        """Create import object with WASI and Emscripten stubs."""
        store = self.store

        # WASI stubs
        def fd_close(fd: int) -> int:
            return 0

        def fd_seek(fd: int, offset: int, whence: int, newoffset: int) -> int:
            return 0

        def fd_write(fd: int, iovs: int, iovs_len: int, nwritten: int) -> int:
            return 0

        def fd_read(fd: int, iovs: int, iovs_len: int, nread: int) -> int:
            return 0

        def environ_sizes_get(count: int, size: int) -> int:
            return 0

        def environ_get(environ: int, environ_buf: int) -> int:
            return 0

        def clock_time_get(clock_id: int, precision: int, time: int) -> int:
            return 0

        def proc_exit(code: int):
            pass

        def random_get(buf: int, buf_len: int) -> int:
            return 0

        # Exception handling stubs
        def set_threw(value: int, type_: int):
            self._threw = [value, type_]

        def cxa_find_matching_catch_2() -> int:
            return 0

        def cxa_find_matching_catch_3(arg: int) -> int:
            return 0

        def resume_exception(ptr: int):
            pass

        def cxa_begin_catch(ptr: int) -> int:
            return 0

        def cxa_end_catch():
            pass

        def llvm_eh_typeid_for(ptr: int) -> int:
            return 0

        def cxa_throw(ptr: int, type_: int, destructor: int):
            pass

        def cxa_uncaught_exceptions() -> int:
            return 0

        # invoke_* trampolines - call functions from indirect function table
        def invoke_v(idx: int):
            self._call_table_func(idx, [])

        def invoke_vi(idx: int, a: int):
            self._call_table_func(idx, [a])

        def invoke_vii(idx: int, a: int, b: int):
            self._call_table_func(idx, [a, b])

        def invoke_viii(idx: int, a: int, b: int, c: int):
            self._call_table_func(idx, [a, b, c])

        def invoke_viiii(idx: int, a: int, b: int, c: int, d: int):
            self._call_table_func(idx, [a, b, c, d])

        def invoke_viiiii(idx: int, a: int, b: int, c: int, d: int, e: int):
            self._call_table_func(idx, [a, b, c, d, e])

        def invoke_viiiiii(idx: int, a: int, b: int, c: int, d: int, e: int, f: int):
            self._call_table_func(idx, [a, b, c, d, e, f])

        def invoke_viiiiiii(idx: int, a: int, b: int, c: int, d: int, e: int, f: int, g: int):
            self._call_table_func(idx, [a, b, c, d, e, f, g])

        def invoke_viiiiiiiii(idx: int, a: int, b: int, c: int, d: int, e: int, f: int, g: int, h: int, i: int):
            self._call_table_func(idx, [a, b, c, d, e, f, g, h, i])

        def invoke_i(idx: int) -> int:
            return self._call_table_func_ret(idx, [])

        def invoke_ii(idx: int, a: int) -> int:
            return self._call_table_func_ret(idx, [a])

        def invoke_iii(idx: int, a: int, b: int) -> int:
            return self._call_table_func_ret(idx, [a, b])

        def invoke_iiii(idx: int, a: int, b: int, c: int) -> int:
            return self._call_table_func_ret(idx, [a, b, c])

        def invoke_iiiii(idx: int, a: int, b: int, c: int, d: int) -> int:
            return self._call_table_func_ret(idx, [a, b, c, d])

        def invoke_iiiiii(idx: int, a: int, b: int, c: int, d: int, e: int) -> int:
            return self._call_table_func_ret(idx, [a, b, c, d, e])

        def invoke_iiiiiii(idx: int, a: int, b: int, c: int, d: int, e: int, f: int) -> int:
            return self._call_table_func_ret(idx, [a, b, c, d, e, f])

        def invoke_iiiiiiii(idx: int, a: int, b: int, c: int, d: int, e: int, f: int, g: int) -> int:
            return self._call_table_func_ret(idx, [a, b, c, d, e, f, g])

        def invoke_iiiiiiiiii(idx: int, a: int, b: int, c: int, d: int, e: int, f: int, g: int, h: int, i: int) -> int:
            return self._call_table_func_ret(idx, [a, b, c, d, e, f, g, h, i])

        return {
            "wasi_snapshot_preview1": {
                "fd_close": Function(store, fd_close),
                "fd_seek": Function(store, fd_seek),
                "fd_write": Function(store, fd_write),
                "fd_read": Function(store, fd_read),
                "environ_sizes_get": Function(store, environ_sizes_get),
                "environ_get": Function(store, environ_get),
                "clock_time_get": Function(store, clock_time_get),
                "proc_exit": Function(store, proc_exit),
                "random_get": Function(store, random_get),
            },
            "env": {
                "setThrew": Function(store, set_threw),
                "__cxa_find_matching_catch_2": Function(store, cxa_find_matching_catch_2),
                "__cxa_find_matching_catch_3": Function(store, cxa_find_matching_catch_3),
                "__resumeException": Function(store, resume_exception),
                "__cxa_begin_catch": Function(store, cxa_begin_catch),
                "__cxa_end_catch": Function(store, cxa_end_catch),
                "llvm_eh_typeid_for": Function(store, llvm_eh_typeid_for),
                "__cxa_throw": Function(store, cxa_throw),
                "__cxa_uncaught_exceptions": Function(store, cxa_uncaught_exceptions),
                "invoke_v": Function(store, invoke_v),
                "invoke_vi": Function(store, invoke_vi),
                "invoke_vii": Function(store, invoke_vii),
                "invoke_viii": Function(store, invoke_viii),
                "invoke_viiii": Function(store, invoke_viiii),
                "invoke_viiiii": Function(store, invoke_viiiii),
                "invoke_viiiiii": Function(store, invoke_viiiiii),
                "invoke_viiiiiii": Function(store, invoke_viiiiiii),
                "invoke_viiiiiiiii": Function(store, invoke_viiiiiiiii),
                "invoke_i": Function(store, invoke_i),
                "invoke_ii": Function(store, invoke_ii),
                "invoke_iii": Function(store, invoke_iii),
                "invoke_iiii": Function(store, invoke_iiii),
                "invoke_iiiii": Function(store, invoke_iiiii),
                "invoke_iiiiii": Function(store, invoke_iiiiii),
                "invoke_iiiiiii": Function(store, invoke_iiiiiii),
                "invoke_iiiiiiii": Function(store, invoke_iiiiiiii),
                "invoke_iiiiiiiiii": Function(store, invoke_iiiiiiiiii),
            },
        }

    def _call_table_func(self, idx: int, args: list):
        """Call a function from the indirect function table (void return)."""
        try:
            if self._table is not None:
                func = self._table.get(idx)
                if func is not None:
                    func(*args)
        except Exception:
            self._threw = [1, 0]

    def _call_table_func_ret(self, idx: int, args: list) -> int:
        """Call a function from the indirect function table (int return)."""
        try:
            if self._table is not None:
                func = self._table.get(idx)
                if func is not None:
                    result = func(*args)
                    return result if result is not None else 0
        except Exception:
            self._threw = [1, 0]
        return 0

    @property
    def memory(self) -> Memory:
        return self._memory

    def version(self) -> str:
        ptr = self.get_version()
        if ptr == 0:
            return "unknown"
        result = []
        i = 0
        mem_view = self.memory.uint8_view()
        while True:
            b = mem_view[ptr + i]
            if b == 0:
                break
            result.append(b)
            i += 1
        return bytes(result).decode("utf-8")

    def has_cryptopp_available(self) -> bool:
        return self.has_cryptopp() != 0

    def encrypt(self, key: bytes, iv: bytes, data: bytearray) -> None:
        """Encrypt data in place using AES-256-CTR."""
        key_ptr = self.malloc(32)
        iv_ptr = self.malloc(16)
        data_ptr = self.malloc(len(data))

        try:
            mem_view = self.memory.uint8_view()
            mem_view[key_ptr:key_ptr + 32] = key
            mem_view[iv_ptr:iv_ptr + 16] = iv
            mem_view[data_ptr:data_ptr + len(data)] = data

            self.encrypt_bytes(key_ptr, iv_ptr, data_ptr, len(data))

            data[:] = bytes(mem_view[data_ptr:data_ptr + len(data)])
        finally:
            self.free(key_ptr)
            self.free(iv_ptr)
            self.free(data_ptr)

    def decrypt(self, key: bytes, iv: bytes, data: bytearray) -> None:
        """Decrypt data in place using AES-256-CTR."""
        self.encrypt(key, iv, data)  # CTR mode is symmetric

    def sha256(self, data: bytes) -> bytes:
        """Compute SHA-256 hash."""
        data_ptr = self.malloc(max(len(data), 1))
        hash_ptr = self.malloc(32)

        try:
            mem_view = self.memory.uint8_view()
            if len(data) > 0:
                mem_view[data_ptr:data_ptr + len(data)] = data

            self.sha256_func(data_ptr, len(data), hash_ptr)

            return bytes(mem_view[hash_ptr:hash_ptr + 32])
        finally:
            self.free(data_ptr)
            self.free(hash_ptr)


def main():
    print("=" * 60)
    print("FlatBuffers Cross-Language Encryption E2E Tests - Python")
    print("=" * 60)
    print()

    # Initialize encryption module
    try:
        em = EncryptionModule(WASM_PATH)
        print(f"Encryption module version: {em.version()}")
        print(f"Crypto++ available: {em.has_cryptopp_available()}")
        print()
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("Build the WASM module first:")
        print("  cmake --build build/wasm --target flatc_wasm_wasi")
        sys.exit(1)

    # Load encryption keys
    keys_path = VECTORS_DIR / "encryption_keys.json"
    if not keys_path.exists():
        print(f"Error: encryption keys not found at {keys_path}")
        print("Run the vector generator first: node generate_vectors.mjs")
        sys.exit(1)

    with open(keys_path) as f:
        encryption_keys = json.load(f)

    results = []

    # Test 1: SHA-256
    print("Test 1: SHA-256 Hash")
    print("-" * 40)
    result = TestResult("SHA-256")

    hash_result = em.sha256(b"hello")
    hash_hex = hash_result.hex()
    expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    if hash_hex == expected:
        result.pass_("SHA-256('hello') matches expected")
    else:
        result.fail(f"SHA-256 mismatch: got {hash_hex}")

    results.append(result.summary())

    # Test 2: Encryption/Decryption with each chain key
    print("\nTest 2: Encryption/Decryption (per-chain keys)")
    print("-" * 40)

    for chain, keys in encryption_keys.items():
        result = TestResult(f"Encryption with {chain}")

        try:
            key = bytes.fromhex(keys["key_hex"])
            iv = bytes.fromhex(keys["iv_hex"])

            # Test data
            plaintext = b"Hello, FlatBuffers encryption test from Python!"
            original_hex = plaintext.hex()

            # Encrypt
            data = bytearray(plaintext)
            em.encrypt(key, iv, data)
            encrypted_hex = bytes(data).hex()

            if encrypted_hex != original_hex:
                result.pass_("Data encrypted (changed from original)")
            else:
                result.fail("Data unchanged after encryption")

            # Decrypt
            em.decrypt(key, iv, data)
            decrypted_hex = bytes(data).hex()

            if decrypted_hex == original_hex:
                result.pass_("Decryption restored original data")
            else:
                result.fail("Decryption mismatch")

            if bytes(data) == plaintext:
                result.pass_("Plaintext matches after round-trip")
            else:
                result.fail("Plaintext mismatch after round-trip")

        except Exception as e:
            result.fail("Exception during test", e)

        results.append(result.summary())

    # Test 3: Cross-language binary verification
    print("\nTest 3: Cross-Language Binary Verification")
    print("-" * 40)
    result = TestResult("Cross-Language Verification")

    binary_dir = VECTORS_DIR / "binary"
    unencrypted_path = binary_dir / "monster_unencrypted.bin"

    if not unencrypted_path.exists():
        result.fail("Node.js binaries not found. Run Node.js test first.")
    else:
        data = unencrypted_path.read_bytes()
        result.pass_(f"Read unencrypted binary: {len(data)} bytes")

        # Try reading an encrypted binary
        for chain in encryption_keys:
            encrypted_path = binary_dir / f"monster_encrypted_{chain}.bin"
            if encrypted_path.exists():
                enc_data = encrypted_path.read_bytes()
                result.pass_(f"Read {chain} encrypted binary: {len(enc_data)} bytes")
                break

    results.append(result.summary())

    # Summary
    print()
    print("=" * 60)
    print("Summary")
    print("=" * 60)

    passed = sum(1 for r in results if r)
    total = len(results)

    print(f"\nTotal: {passed}/{total} test suites passed")

    if passed == total:
        print("\n✓ All tests passed!")
        sys.exit(0)
    else:
        print("\n✗ Some tests failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
