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

# Try wasmtime first (better platform support), fall back to wasmer
try:
    import wasmtime
    RUNTIME = "wasmtime"
except ImportError:
    try:
        from wasmer import Store, Module, Instance, Function, Memory, Table
        from wasmer_compiler_cranelift import Compiler
        RUNTIME = "wasmer"
    except ImportError:
        print("Error: No WASM runtime available.")
        print("Install wasmtime: pip install wasmtime")
        print("Or wasmer: pip install wasmer wasmer-compiler-cranelift")
        sys.exit(1)

# Paths
SCRIPT_DIR = Path(__file__).parent
VECTORS_DIR = SCRIPT_DIR.parent.parent / "vectors"
WASM_PATH = SCRIPT_DIR.parent.parent.parent.parent.parent / "build" / "wasm" / "wasm" / "flatc-encryption.wasm"


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


class WasmtimeEncryptionModule:
    """Wrapper for the FlatBuffers WASI encryption module using Wasmtime."""

    def __init__(self, wasm_path: Path):
        if not wasm_path.exists():
            raise FileNotFoundError(f"WASM module not found: {wasm_path}")

        # Create engine and store
        self.engine = wasmtime.Engine()
        self.store = wasmtime.Store(self.engine)

        # Create linker with WASI
        self.linker = wasmtime.Linker(self.engine)

        # Add WASI imports
        wasi_config = wasmtime.WasiConfig()
        wasi_config.inherit_env()
        self.store.set_wasi(wasi_config)
        self.linker.define_wasi()

        # Add exception handling stubs
        self._add_env_imports()

        # Load and instantiate module
        module = wasmtime.Module.from_file(self.engine, str(wasm_path))
        self.instance = self.linker.instantiate(self.store, module)

        # Get exports
        self._memory = self.instance.exports(self.store)["memory"]
        self._malloc = self.instance.exports(self.store)["malloc"]
        self._free = self.instance.exports(self.store)["free"]
        self._encrypt = self.instance.exports(self.store)["wasi_encrypt_bytes"]
        self._decrypt = self.instance.exports(self.store)["wasi_decrypt_bytes"]
        self._sha256 = self.instance.exports(self.store)["wasi_sha256"]
        self._hkdf = self.instance.exports(self.store)["wasi_hkdf"]
        self._get_version = self.instance.exports(self.store)["wasi_get_version"]
        self._has_cryptopp = self.instance.exports(self.store)["wasi_has_cryptopp"]

        # ECDH functions
        self._x25519_generate = self.instance.exports(self.store)["wasi_x25519_generate_keypair"]
        self._x25519_shared = self.instance.exports(self.store)["wasi_x25519_shared_secret"]
        self._secp256k1_generate = self.instance.exports(self.store)["wasi_secp256k1_generate_keypair"]
        self._secp256k1_shared = self.instance.exports(self.store)["wasi_secp256k1_shared_secret"]
        self._p256_generate = self.instance.exports(self.store)["wasi_p256_generate_keypair"]
        self._p256_shared = self.instance.exports(self.store)["wasi_p256_shared_secret"]

        # Get indirect function table if available
        try:
            self._table = self.instance.exports(self.store)["__indirect_function_table"]
        except KeyError:
            self._table = None

        # Call _initialize if present (required for Emscripten modules)
        try:
            init_func = self.instance.exports(self.store)["_initialize"]
            init_func(self.store)
        except (KeyError, Exception):
            pass  # Some modules don't have _initialize

    def _add_env_imports(self):
        """Add Emscripten exception handling stubs and invoke_* trampolines."""

        # Helper to create typed functions
        def make_func(param_types, result_types, func):
            ft = wasmtime.FuncType(param_types, result_types)
            return wasmtime.Func(self.store, ft, func)

        i32 = wasmtime.ValType.i32()

        # Exception handling stubs
        self.linker.define(self.store, "env", "__cxa_throw",
            make_func([i32, i32, i32], [], lambda *args: None))
        self.linker.define(self.store, "env", "__cxa_begin_catch",
            make_func([i32], [i32], lambda *args: 0))
        self.linker.define(self.store, "env", "__cxa_end_catch",
            make_func([], [], lambda *args: None))
        self.linker.define(self.store, "env", "__cxa_find_matching_catch_2",
            make_func([], [i32], lambda *args: 0))
        self.linker.define(self.store, "env", "__cxa_find_matching_catch_3",
            make_func([i32], [i32], lambda *args: 0))
        self.linker.define(self.store, "env", "__resumeException",
            make_func([i32], [], lambda *args: None))
        self.linker.define(self.store, "env", "llvm_eh_typeid_for",
            make_func([i32], [i32], lambda *args: 0))
        self.linker.define(self.store, "env", "__cxa_uncaught_exceptions",
            make_func([], [i32], lambda *args: 0))

        # Store reference to self for invoke callbacks
        module_ref = self

        # invoke_* trampolines - call functions from indirect function table
        # Note: wasmtime does NOT pass a caller argument for imported functions.
        # The function signature is (idx, arg1, arg2, ...) directly.
        def make_invoke_v(n_args):
            types = [i32] * (n_args + 1)  # idx + args
            def invoke_impl(idx, *args):
                try:
                    table = module_ref._table
                    store = module_ref.store
                    if table is not None:
                        func = table.get(store, idx)
                        if func is not None:
                            func(store, *args)
                except Exception as e:
                    pass  # Exception during invoke - handled by EH
            return make_func(types, [], invoke_impl)

        def make_invoke_i(n_args):
            types = [i32] * (n_args + 1)  # idx + args
            def invoke_impl(idx, *args):
                try:
                    table = module_ref._table
                    store = module_ref.store
                    if table is not None:
                        func = table.get(store, idx)
                        if func is not None:
                            result = func(store, *args)
                            return result if result is not None else 0
                except Exception:
                    pass  # Exception during invoke
                return 0
            return make_func(types, [i32], invoke_impl)

        self.linker.define(self.store, "env", "invoke_v", make_invoke_v(0))
        self.linker.define(self.store, "env", "invoke_vi", make_invoke_v(1))
        self.linker.define(self.store, "env", "invoke_vii", make_invoke_v(2))
        self.linker.define(self.store, "env", "invoke_viii", make_invoke_v(3))
        self.linker.define(self.store, "env", "invoke_viiii", make_invoke_v(4))
        self.linker.define(self.store, "env", "invoke_viiiii", make_invoke_v(5))
        self.linker.define(self.store, "env", "invoke_viiiiii", make_invoke_v(6))
        self.linker.define(self.store, "env", "invoke_viiiiiii", make_invoke_v(7))
        self.linker.define(self.store, "env", "invoke_viiiiiiiii", make_invoke_v(9))

        self.linker.define(self.store, "env", "invoke_i", make_invoke_i(0))
        self.linker.define(self.store, "env", "invoke_ii", make_invoke_i(1))
        self.linker.define(self.store, "env", "invoke_iii", make_invoke_i(2))
        self.linker.define(self.store, "env", "invoke_iiii", make_invoke_i(3))
        self.linker.define(self.store, "env", "invoke_iiiii", make_invoke_i(4))
        self.linker.define(self.store, "env", "invoke_iiiiii", make_invoke_i(5))
        self.linker.define(self.store, "env", "invoke_iiiiiii", make_invoke_i(6))
        self.linker.define(self.store, "env", "invoke_iiiiiiii", make_invoke_i(7))
        self.linker.define(self.store, "env", "invoke_iiiiiiiiii", make_invoke_i(9))

    def version(self) -> str:
        ptr = self._get_version(self.store)
        if ptr == 0:
            return "unknown"
        result = []
        data = self._memory.data_ptr(self.store)
        i = 0
        while True:
            b = data[ptr + i]
            if b == 0:
                break
            result.append(b)
            i += 1
        return bytes(result).decode("utf-8")

    def has_cryptopp_available(self) -> bool:
        return self._has_cryptopp(self.store) != 0

    def _write_memory(self, ptr: int, data: bytes):
        mem_data = self._memory.data_ptr(self.store)
        for i, b in enumerate(data):
            mem_data[ptr + i] = b

    def _read_memory(self, ptr: int, size: int) -> bytes:
        mem_data = self._memory.data_ptr(self.store)
        return bytes(mem_data[ptr:ptr + size])

    def encrypt(self, key: bytes, iv: bytes, data: bytearray) -> None:
        """Encrypt data in place using AES-256-CTR."""
        key_ptr = self._malloc(self.store, 32)
        iv_ptr = self._malloc(self.store, 16)
        data_ptr = self._malloc(self.store, len(data))

        try:
            self._write_memory(key_ptr, key)
            self._write_memory(iv_ptr, iv)
            self._write_memory(data_ptr, bytes(data))

            self._encrypt(self.store, key_ptr, iv_ptr, data_ptr, len(data))

            data[:] = self._read_memory(data_ptr, len(data))
        finally:
            self._free(self.store, key_ptr)
            self._free(self.store, iv_ptr)
            self._free(self.store, data_ptr)

    def decrypt(self, key: bytes, iv: bytes, data: bytearray) -> None:
        """Decrypt data in place using AES-256-CTR."""
        self.encrypt(key, iv, data)  # CTR mode is symmetric

    def sha256(self, data: bytes) -> bytes:
        """Compute SHA-256 hash."""
        data_ptr = self._malloc(self.store, max(len(data), 1))
        hash_ptr = self._malloc(self.store, 32)

        try:
            if len(data) > 0:
                self._write_memory(data_ptr, data)

            self._sha256(self.store, data_ptr, len(data), hash_ptr)

            return self._read_memory(hash_ptr, 32)
        finally:
            self._free(self.store, data_ptr)
            self._free(self.store, hash_ptr)

    def hkdf(self, ikm: bytes, salt: bytes, info: bytes, output_len: int) -> bytes:
        """Derive key using HKDF-SHA256."""
        ikm_ptr = self._malloc(self.store, max(len(ikm), 1))
        salt_ptr = self._malloc(self.store, max(len(salt), 1))
        info_ptr = self._malloc(self.store, max(len(info), 1))
        out_ptr = self._malloc(self.store, output_len)

        try:
            if len(ikm) > 0:
                self._write_memory(ikm_ptr, ikm)
            if len(salt) > 0:
                self._write_memory(salt_ptr, salt)
            if len(info) > 0:
                self._write_memory(info_ptr, info)

            self._hkdf(self.store, ikm_ptr, len(ikm), salt_ptr, len(salt),
                      info_ptr, len(info), out_ptr, output_len)

            return self._read_memory(out_ptr, output_len)
        finally:
            self._free(self.store, ikm_ptr)
            self._free(self.store, salt_ptr)
            self._free(self.store, info_ptr)
            self._free(self.store, out_ptr)

    def x25519_generate_keypair(self) -> tuple[bytes, bytes]:
        """Generate X25519 keypair. Returns (private_key, public_key)."""
        priv_ptr = self._malloc(self.store, 32)
        pub_ptr = self._malloc(self.store, 32)

        try:
            self._x25519_generate(self.store, priv_ptr, pub_ptr)
            return (self._read_memory(priv_ptr, 32), self._read_memory(pub_ptr, 32))
        finally:
            self._free(self.store, priv_ptr)
            self._free(self.store, pub_ptr)

    def x25519_shared_secret(self, private_key: bytes, public_key: bytes) -> bytes:
        """Compute X25519 shared secret."""
        priv_ptr = self._malloc(self.store, 32)
        pub_ptr = self._malloc(self.store, 32)
        shared_ptr = self._malloc(self.store, 32)

        try:
            self._write_memory(priv_ptr, private_key)
            self._write_memory(pub_ptr, public_key)
            self._x25519_shared(self.store, priv_ptr, pub_ptr, shared_ptr)
            return self._read_memory(shared_ptr, 32)
        finally:
            self._free(self.store, priv_ptr)
            self._free(self.store, pub_ptr)
            self._free(self.store, shared_ptr)

    def secp256k1_generate_keypair(self) -> tuple[bytes, bytes]:
        """Generate secp256k1 keypair. Returns (private_key, public_key)."""
        priv_ptr = self._malloc(self.store, 32)
        pub_ptr = self._malloc(self.store, 33)  # Compressed public key

        try:
            self._secp256k1_generate(self.store, priv_ptr, pub_ptr)
            return (self._read_memory(priv_ptr, 32), self._read_memory(pub_ptr, 33))
        finally:
            self._free(self.store, priv_ptr)
            self._free(self.store, pub_ptr)

    def secp256k1_shared_secret(self, private_key: bytes, public_key: bytes) -> bytes:
        """Compute secp256k1 shared secret."""
        priv_ptr = self._malloc(self.store, 32)
        pub_ptr = self._malloc(self.store, len(public_key))
        shared_ptr = self._malloc(self.store, 32)

        try:
            self._write_memory(priv_ptr, private_key)
            self._write_memory(pub_ptr, public_key)
            self._secp256k1_shared(self.store, priv_ptr, pub_ptr, len(public_key), shared_ptr)
            return self._read_memory(shared_ptr, 32)
        finally:
            self._free(self.store, priv_ptr)
            self._free(self.store, pub_ptr)
            self._free(self.store, shared_ptr)

    def p256_generate_keypair(self) -> tuple[bytes, bytes]:
        """Generate P-256 keypair. Returns (private_key, public_key)."""
        priv_ptr = self._malloc(self.store, 32)
        pub_ptr = self._malloc(self.store, 33)  # Compressed public key

        try:
            self._p256_generate(self.store, priv_ptr, pub_ptr)
            return (self._read_memory(priv_ptr, 32), self._read_memory(pub_ptr, 33))
        finally:
            self._free(self.store, priv_ptr)
            self._free(self.store, pub_ptr)

    def p256_shared_secret(self, private_key: bytes, public_key: bytes) -> bytes:
        """Compute P-256 shared secret."""
        priv_ptr = self._malloc(self.store, 32)
        pub_ptr = self._malloc(self.store, len(public_key))
        shared_ptr = self._malloc(self.store, 32)

        try:
            self._write_memory(priv_ptr, private_key)
            self._write_memory(pub_ptr, public_key)
            self._p256_shared(self.store, priv_ptr, pub_ptr, len(public_key), shared_ptr)
            return self._read_memory(shared_ptr, 32)
        finally:
            self._free(self.store, priv_ptr)
            self._free(self.store, pub_ptr)
            self._free(self.store, shared_ptr)


def main():
    print("=" * 60)
    print("FlatBuffers Cross-Language Encryption E2E Tests - Python")
    print("=" * 60)
    print()
    print(f"WASM Runtime: {RUNTIME}")
    print()

    # Initialize encryption module
    try:
        em = WasmtimeEncryptionModule(WASM_PATH)
        print(f"Encryption module version: {em.version()}")
        print(f"Crypto++ available: {em.has_cryptopp_available()}")
        print()
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("Build the WASM module first:")
        print("  cmake --build build --target flatc_wasm_encryption")
        sys.exit(1)
    except Exception as e:
        print(f"Error loading WASM module: {e}")
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
        unencrypted_data = unencrypted_path.read_bytes()
        result.pass_(f"Read unencrypted binary: {len(unencrypted_data)} bytes")

        # Verify file identifier
        if len(unencrypted_data) >= 8:
            file_ident = unencrypted_data[4:8].decode('ascii', errors='replace')
            if file_ident == "MONS":
                result.pass_("FlatBuffer file identifier: MONS")
            else:
                result.fail(f"Unexpected file identifier: {file_ident}")

        # Decrypt and verify each chain's binary
        for chain, keys in encryption_keys.items():
            encrypted_path = binary_dir / f"monster_encrypted_{chain}.bin"
            if encrypted_path.exists():
                try:
                    key = bytes.fromhex(keys["key_hex"])
                    iv = bytes.fromhex(keys["iv_hex"])

                    encrypted_data = bytearray(encrypted_path.read_bytes())
                    em.decrypt(key, iv, encrypted_data)

                    if bytes(encrypted_data) == unencrypted_data:
                        result.pass_(f"Decrypted {chain} matches original")
                    else:
                        result.fail(f"Decrypted {chain} mismatch")

                    # Verify file identifier after decryption
                    if len(encrypted_data) >= 8 and encrypted_data[4:8].decode('ascii', errors='replace') == "MONS":
                        result.pass_(f"Decrypted {chain}: MONS identifier intact")
                except Exception as e:
                    result.fail(f"Error decrypting {chain}", e)

    results.append(result.summary())

    # Test 4: ECDH Key Exchange Verification
    print("\nTest 4: ECDH Key Exchange Verification")
    print("-" * 40)

    # ECDH curves to test
    ecdh_curves = [
        {
            "name": "X25519",
            "generate": em.x25519_generate_keypair,
            "shared": em.x25519_shared_secret,
            "pub_key_size": 32,
            "key_exchange": 0,
        },
        {
            "name": "secp256k1",
            "generate": em.secp256k1_generate_keypair,
            "shared": em.secp256k1_shared_secret,
            "pub_key_size": 33,
            "key_exchange": 1,
        },
        {
            "name": "P-256",
            "generate": em.p256_generate_keypair,
            "shared": em.p256_shared_secret,
            "pub_key_size": 33,
            "key_exchange": 2,
        },
    ]

    for curve in ecdh_curves:
        result = TestResult(f"ECDH {curve['name']}")

        try:
            # Generate keypairs for Alice and Bob
            alice_priv, alice_pub = curve["generate"]()
            bob_priv, bob_pub = curve["generate"]()

            if len(alice_pub) == curve["pub_key_size"]:
                result.pass_(f"Generated Alice keypair (pub: {len(alice_pub)} bytes)")
            else:
                result.fail(f"Alice public key wrong size: {len(alice_pub)}")

            if len(bob_pub) == curve["pub_key_size"]:
                result.pass_(f"Generated Bob keypair (pub: {len(bob_pub)} bytes)")
            else:
                result.fail(f"Bob public key wrong size: {len(bob_pub)}")

            # Compute shared secrets
            alice_shared = curve["shared"](alice_priv, bob_pub)
            bob_shared = curve["shared"](bob_priv, alice_pub)

            if alice_shared == bob_shared:
                result.pass_(f"Shared secrets match ({len(alice_shared)} bytes)")
            else:
                result.fail(f"Shared secrets DO NOT match!")
                result.fail(f"  Alice: {alice_shared.hex()}")
                result.fail(f"  Bob:   {bob_shared.hex()}")

            # Test HKDF key derivation from shared secret
            session_material = em.hkdf(
                ikm=alice_shared,
                salt=b"flatbuffers-encryption",
                info=b"session-key-iv",
                output_len=48  # 32 bytes key + 16 bytes IV
            )

            session_key = session_material[:32]
            session_iv = session_material[32:48]

            if len(session_key) == 32 and len(session_iv) == 16:
                result.pass_(f"HKDF derived key ({len(session_key)}B) + IV ({len(session_iv)}B)")
            else:
                result.fail(f"HKDF output wrong size")

            # Full E2E: encrypt with derived key, decrypt with same key
            test_data = f"ECDH test data for {curve['name']} encryption"
            plaintext = test_data.encode('utf-8')
            encrypted = bytearray(plaintext)
            em.encrypt(session_key, session_iv, encrypted)

            if bytes(encrypted) != plaintext:
                result.pass_("Encryption with derived key modified data")
            else:
                result.fail("Encryption did not modify data")

            decrypted = bytearray(encrypted)
            em.decrypt(session_key, session_iv, decrypted)

            if bytes(decrypted) == plaintext:
                result.pass_("Decryption with derived key restored original")
            else:
                result.fail("Decryption mismatch")

            # Verify cross-language ECDH header if available
            header_path = binary_dir / f"monster_ecdh_{curve['name'].lower().replace('-', '')}_header.json"
            if header_path.exists():
                try:
                    with open(header_path) as f:
                        header = json.load(f)

                    if header.get("key_exchange") == curve["key_exchange"]:
                        result.pass_(f"Cross-language header has correct key_exchange: {curve['key_exchange']}")
                    else:
                        result.fail(f"Header key_exchange mismatch: {header.get('key_exchange')}")

                    ephemeral_pub_hex = header.get("ephemeral_public_key", "")
                    session_key_hex = header.get("session_key", "")
                    session_iv_hex = header.get("session_iv", "")

                    if ephemeral_pub_hex and session_key_hex and session_iv_hex:
                        result.pass_(f"Header contains ephemeral_public_key, session_key, session_iv")

                        # Decrypt the cross-language encrypted file using Node.js session key
                        encrypted_path = binary_dir / f"monster_ecdh_{curve['name'].lower().replace('-', '')}_encrypted.bin"
                        if encrypted_path.exists():
                            node_key = bytes.fromhex(session_key_hex)
                            node_iv = bytes.fromhex(session_iv_hex)
                            encrypted_data = bytearray(encrypted_path.read_bytes())
                            em.decrypt(node_key, node_iv, encrypted_data)

                            # Should restore to original unencrypted data
                            if bytes(encrypted_data) == unencrypted_data:
                                result.pass_(f"Decrypted Node.js {curve['name']} data matches original")
                            else:
                                result.fail(f"Decrypted Node.js {curve['name']} data mismatch")

                except Exception as e:
                    result.fail(f"Error reading cross-language header", e)
            else:
                result.pass_(f"(No cross-language header found at {header_path.name})")

        except Exception as e:
            result.fail(f"Exception during {curve['name']} test", e)

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
