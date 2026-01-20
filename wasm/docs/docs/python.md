# Python Integration Guide

Integrate the FlatBuffers encryption WASM module into Python applications using [wasmer-python](https://github.com/wasmerio/wasmer-python), Python bindings for the Wasmer WebAssembly runtime.

## Why wasmer-python?

- **High performance** - JIT compilation via Cranelift
- **Easy installation** - `pip install wasmer`
- **Type hints** - Full typing support
- **Cross-platform** - Windows, macOS, Linux

## Prerequisites

- Python 3.7 or later
- `flatc-encryption.wasm` binary

## Installation

```bash
pip install wasmer wasmer-compiler-cranelift
```

Or with wasmtime (alternative runtime):

```bash
pip install wasmtime
```

## Quick Start

```python
from wasmer import engine, Store, Module, Instance, ImportObject, Function, FunctionType, Type
from wasmer_compiler_cranelift import Compiler
import os
import struct

# Create store with Cranelift JIT
store = Store(engine.JIT(Compiler))

# Load WASM module
with open("flatc-encryption.wasm", "rb") as f:
    wasm_bytes = f.read()

module = Module(store, wasm_bytes)

# Create WASI imports (minimal stubs)
import_object = ImportObject()

def fd_close(fd: int) -> int:
    return 0

def clock_time_get(clock_id: int, precision: int, time: int) -> int:
    return 0

import_object.register("wasi_snapshot_preview1", {
    "fd_close": Function(store, fd_close, FunctionType([Type.I32], [Type.I32])),
    "clock_time_get": Function(store, clock_time_get, FunctionType([Type.I32, Type.I64, Type.I32], [Type.I32])),
    # ... add other WASI stubs as needed
})

# Instantiate
instance = Instance(module, import_object)

# Get exports
memory = instance.exports.memory
malloc = instance.exports.malloc
free = instance.exports.free
encrypt = instance.exports.wasi_encrypt_bytes
decrypt = instance.exports.wasi_decrypt_bytes

# Helper functions
def write_bytes(ptr: int, data: bytes):
    mem_view = memory.uint8_view(ptr)
    for i, b in enumerate(data):
        mem_view[i] = b

def read_bytes(ptr: int, length: int) -> bytes:
    mem_view = memory.uint8_view(ptr)
    return bytes(mem_view[0:length])

# Encrypt data
key = os.urandom(32)
iv = os.urandom(16)
plaintext = b"Hello, FlatBuffers!"

key_ptr = malloc(32)
iv_ptr = malloc(16)
data_ptr = malloc(len(plaintext))

write_bytes(key_ptr, key)
write_bytes(iv_ptr, iv)
write_bytes(data_ptr, plaintext)

# Encrypt in-place
encrypt(key_ptr, iv_ptr, data_ptr, len(plaintext))

# Read encrypted data
ciphertext = read_bytes(data_ptr, len(plaintext))
print(f"Encrypted: {ciphertext.hex()}")

# Decrypt
decrypt(key_ptr, iv_ptr, data_ptr, len(plaintext))
decrypted = read_bytes(data_ptr, len(plaintext))
print(f"Decrypted: {decrypted.decode()}")

# Clean up
free(key_ptr)
free(iv_ptr)
free(data_ptr)
```

## Complete Module Wrapper

For production use, create a Python class wrapping the WASM module:

```python
"""
FlatBuffers Encryption Module for Python.

Provides cryptographic operations via the Crypto++ WASM module:
- AES-256-CTR symmetric encryption
- X25519 ECDH key exchange
- secp256k1 ECDH and ECDSA signatures
- P-256 ECDH and ECDSA signatures
- Ed25519 signatures
"""

from wasmer import engine, Store, Module, Instance, ImportObject, Function, FunctionType, Type
from wasmer_compiler_cranelift import Compiler
from pathlib import Path
from typing import Optional, Tuple, NamedTuple
from dataclasses import dataclass
import os
import struct
import time as time_module

# Key and signature sizes
AES_KEY_SIZE = 32
AES_IV_SIZE = 16
SHA256_SIZE = 32

X25519_PRIVATE_KEY_SIZE = 32
X25519_PUBLIC_KEY_SIZE = 32

SECP256K1_PRIVATE_KEY_SIZE = 32
SECP256K1_PUBLIC_KEY_SIZE = 33
SECP256K1_SIGNATURE_MAX_SIZE = 72

ED25519_PRIVATE_KEY_SIZE = 64
ED25519_PUBLIC_KEY_SIZE = 32
ED25519_SIGNATURE_SIZE = 64


@dataclass
class X25519KeyPair:
    """X25519 key pair for ECDH."""
    private_key: bytes  # 32 bytes
    public_key: bytes   # 32 bytes


@dataclass
class Ed25519KeyPair:
    """Ed25519 key pair for signing."""
    private_key: bytes  # 64 bytes (seed + public key)
    public_key: bytes   # 32 bytes


@dataclass
class Secp256k1KeyPair:
    """secp256k1 key pair for ECDH and ECDSA."""
    private_key: bytes  # 32 bytes
    public_key: bytes   # 33 bytes (compressed)


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

        # Create import object with WASI stubs
        import_object = self._create_imports()

        # Instantiate
        self._instance = Instance(self._module, import_object)

        # Cache exported functions
        self._memory = self._instance.exports.memory
        self._malloc = self._instance.exports.malloc
        self._free = self._instance.exports.free

        # Encryption
        self._encrypt = self._instance.exports.wasi_encrypt_bytes
        self._decrypt = self._instance.exports.wasi_decrypt_bytes

        # Hash
        self._sha256 = self._instance.exports.wasi_sha256
        self._hkdf = self._instance.exports.wasi_hkdf

        # X25519
        self._x25519_generate = self._instance.exports.wasi_x25519_generate_keypair
        self._x25519_shared = self._instance.exports.wasi_x25519_shared_secret

        # secp256k1
        self._secp256k1_generate = self._instance.exports.wasi_secp256k1_generate_keypair
        self._secp256k1_shared = self._instance.exports.wasi_secp256k1_shared_secret
        self._secp256k1_sign = self._instance.exports.wasi_secp256k1_sign
        self._secp256k1_verify = self._instance.exports.wasi_secp256k1_verify

        # Ed25519
        self._ed25519_generate = self._instance.exports.wasi_ed25519_generate_keypair
        self._ed25519_sign = self._instance.exports.wasi_ed25519_sign
        self._ed25519_verify = self._instance.exports.wasi_ed25519_verify

    def _find_wasm_module(self) -> str:
        """Search for the WASM module in expected locations."""
        paths = [
            Path(__file__).parent / "flatc-encryption.wasm",
            Path("flatc-encryption.wasm"),
            Path("wasm/flatc-encryption.wasm"),
        ]
        for p in paths:
            if p.exists():
                return str(p.resolve())
        raise FileNotFoundError("Could not find flatc-encryption.wasm")

    def _create_imports(self) -> ImportObject:
        """Create the import object with WASI and env module stubs."""
        import_object = ImportObject()

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
            raise SystemExit(code)

        def random_get(buf: int, buf_len: int) -> int:
            return 0

        import_object.register("wasi_snapshot_preview1", {
            "fd_close": Function(self._store, fd_close, FunctionType([Type.I32], [Type.I32])),
            "fd_seek": Function(self._store, fd_seek, FunctionType([Type.I32, Type.I64, Type.I32, Type.I32], [Type.I32])),
            "fd_write": Function(self._store, fd_write, FunctionType([Type.I32, Type.I32, Type.I32, Type.I32], [Type.I32])),
            "fd_read": Function(self._store, fd_read, FunctionType([Type.I32, Type.I32, Type.I32, Type.I32], [Type.I32])),
            "environ_sizes_get": Function(self._store, environ_sizes_get, FunctionType([Type.I32, Type.I32], [Type.I32])),
            "environ_get": Function(self._store, environ_get, FunctionType([Type.I32, Type.I32], [Type.I32])),
            "clock_time_get": Function(self._store, clock_time_get, FunctionType([Type.I32, Type.I64, Type.I32], [Type.I32])),
            "proc_exit": Function(self._store, proc_exit, FunctionType([Type.I32], [])),
            "random_get": Function(self._store, random_get, FunctionType([Type.I32, Type.I32], [Type.I32])),
        })

        # Emscripten env stubs (invoke_* trampolines)
        def invoke_stub(*args):
            pass

        import_object.register("env", {
            "invoke_v": Function(self._store, invoke_stub, FunctionType([Type.I32], [])),
            "invoke_vi": Function(self._store, invoke_stub, FunctionType([Type.I32, Type.I32], [])),
            "invoke_vii": Function(self._store, invoke_stub, FunctionType([Type.I32, Type.I32, Type.I32], [])),
            "invoke_viii": Function(self._store, invoke_stub, FunctionType([Type.I32, Type.I32, Type.I32, Type.I32], [])),
            "invoke_i": Function(self._store, lambda idx: 0, FunctionType([Type.I32], [Type.I32])),
            "invoke_ii": Function(self._store, lambda idx, a: 0, FunctionType([Type.I32, Type.I32], [Type.I32])),
            "invoke_iii": Function(self._store, lambda idx, a, b: 0, FunctionType([Type.I32, Type.I32, Type.I32], [Type.I32])),
        })

        return import_object

    def _write_bytes(self, ptr: int, data: bytes) -> None:
        """Write bytes to WASM memory."""
        mem_view = self._memory.uint8_view(ptr)
        for i, b in enumerate(data):
            mem_view[i] = b

    def _read_bytes(self, ptr: int, length: int) -> bytes:
        """Read bytes from WASM memory."""
        mem_view = self._memory.uint8_view(ptr)
        return bytes(mem_view[0:length])

    # Symmetric Encryption

    def encrypt(self, key: bytes, iv: bytes, data: bytes) -> bytes:
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
            raise ValueError(f"Key must be {AES_KEY_SIZE} bytes")
        if len(iv) != AES_IV_SIZE:
            raise ValueError(f"IV must be {AES_IV_SIZE} bytes")

        key_ptr = self._malloc(len(key))
        iv_ptr = self._malloc(len(iv))
        data_ptr = self._malloc(len(data))

        try:
            self._write_bytes(key_ptr, key)
            self._write_bytes(iv_ptr, iv)
            self._write_bytes(data_ptr, data)

            result = self._encrypt(key_ptr, iv_ptr, data_ptr, len(data))
            if result != 0:
                raise RuntimeError("Encryption failed")

            return self._read_bytes(data_ptr, len(data))
        finally:
            self._free(key_ptr)
            self._free(iv_ptr)
            self._free(data_ptr)

    def decrypt(self, key: bytes, iv: bytes, data: bytes) -> bytes:
        """
        Decrypt data using AES-256-CTR.

        Args:
            key: 32-byte encryption key
            iv: 16-byte initialization vector
            data: Data to decrypt

        Returns:
            Decrypted data
        """
        # CTR mode is symmetric
        return self.encrypt(key, iv, data)

    # Hash Functions

    def sha256(self, data: bytes) -> bytes:
        """
        Compute SHA-256 hash.

        Args:
            data: Data to hash

        Returns:
            32-byte hash
        """
        data_ptr = self._malloc(len(data))
        out_ptr = self._malloc(SHA256_SIZE)

        try:
            self._write_bytes(data_ptr, data)
            self._sha256(data_ptr, len(data), out_ptr)
            return self._read_bytes(out_ptr, SHA256_SIZE)
        finally:
            self._free(data_ptr)
            self._free(out_ptr)

    def hkdf(self, ikm: bytes, salt: Optional[bytes], info: bytes, length: int) -> bytes:
        """
        Derive key using HKDF-SHA256.

        Args:
            ikm: Input key material
            salt: Optional salt (can be None)
            info: Context/application-specific info
            length: Desired output length

        Returns:
            Derived key material
        """
        ikm_ptr = self._malloc(len(ikm))
        self._write_bytes(ikm_ptr, ikm)

        salt_ptr = 0
        salt_len = 0
        if salt:
            salt_ptr = self._malloc(len(salt))
            self._write_bytes(salt_ptr, salt)
            salt_len = len(salt)

        info_ptr = self._malloc(len(info))
        self._write_bytes(info_ptr, info)

        out_ptr = self._malloc(length)

        try:
            self._hkdf(
                ikm_ptr, len(ikm),
                salt_ptr, salt_len,
                info_ptr, len(info),
                out_ptr, length
            )
            return self._read_bytes(out_ptr, length)
        finally:
            self._free(ikm_ptr)
            if salt_ptr:
                self._free(salt_ptr)
            self._free(info_ptr)
            self._free(out_ptr)

    # X25519 Key Exchange

    def x25519_generate_keypair(self) -> X25519KeyPair:
        """Generate an X25519 key pair."""
        priv_ptr = self._malloc(X25519_PRIVATE_KEY_SIZE)
        pub_ptr = self._malloc(X25519_PUBLIC_KEY_SIZE)

        try:
            result = self._x25519_generate(priv_ptr, pub_ptr)
            if result != 0:
                raise RuntimeError("Key generation failed")

            return X25519KeyPair(
                private_key=self._read_bytes(priv_ptr, X25519_PRIVATE_KEY_SIZE),
                public_key=self._read_bytes(pub_ptr, X25519_PUBLIC_KEY_SIZE)
            )
        finally:
            self._free(priv_ptr)
            self._free(pub_ptr)

    def x25519_shared_secret(self, private_key: bytes, public_key: bytes) -> bytes:
        """
        Compute X25519 shared secret.

        Args:
            private_key: 32-byte private key
            public_key: 32-byte public key

        Returns:
            32-byte shared secret
        """
        priv_ptr = self._malloc(len(private_key))
        pub_ptr = self._malloc(len(public_key))
        out_ptr = self._malloc(32)

        try:
            self._write_bytes(priv_ptr, private_key)
            self._write_bytes(pub_ptr, public_key)

            result = self._x25519_shared(priv_ptr, pub_ptr, out_ptr)
            if result != 0:
                raise RuntimeError("Shared secret computation failed")

            return self._read_bytes(out_ptr, 32)
        finally:
            self._free(priv_ptr)
            self._free(pub_ptr)
            self._free(out_ptr)

    # Ed25519 Signatures

    def ed25519_generate_keypair(self) -> Ed25519KeyPair:
        """Generate an Ed25519 key pair."""
        priv_ptr = self._malloc(ED25519_PRIVATE_KEY_SIZE)
        pub_ptr = self._malloc(ED25519_PUBLIC_KEY_SIZE)

        try:
            result = self._ed25519_generate(priv_ptr, pub_ptr)
            if result != 0:
                raise RuntimeError("Key generation failed")

            return Ed25519KeyPair(
                private_key=self._read_bytes(priv_ptr, ED25519_PRIVATE_KEY_SIZE),
                public_key=self._read_bytes(pub_ptr, ED25519_PUBLIC_KEY_SIZE)
            )
        finally:
            self._free(priv_ptr)
            self._free(pub_ptr)

    def ed25519_sign(self, private_key: bytes, message: bytes) -> bytes:
        """
        Sign a message with Ed25519.

        Args:
            private_key: 64-byte private key
            message: Message to sign

        Returns:
            64-byte signature
        """
        priv_ptr = self._malloc(len(private_key))
        msg_ptr = self._malloc(len(message))
        sig_ptr = self._malloc(ED25519_SIGNATURE_SIZE)

        try:
            self._write_bytes(priv_ptr, private_key)
            self._write_bytes(msg_ptr, message)

            result = self._ed25519_sign(priv_ptr, msg_ptr, len(message), sig_ptr)
            if result != 0:
                raise RuntimeError("Signing failed")

            return self._read_bytes(sig_ptr, ED25519_SIGNATURE_SIZE)
        finally:
            self._free(priv_ptr)
            self._free(msg_ptr)
            self._free(sig_ptr)

    def ed25519_verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """
        Verify an Ed25519 signature.

        Args:
            public_key: 32-byte public key
            message: Original message
            signature: 64-byte signature

        Returns:
            True if valid, False otherwise
        """
        pub_ptr = self._malloc(len(public_key))
        msg_ptr = self._malloc(len(message))
        sig_ptr = self._malloc(len(signature))

        try:
            self._write_bytes(pub_ptr, public_key)
            self._write_bytes(msg_ptr, message)
            self._write_bytes(sig_ptr, signature)

            result = self._ed25519_verify(pub_ptr, msg_ptr, len(message), sig_ptr)
            return result == 0
        finally:
            self._free(pub_ptr)
            self._free(msg_ptr)
            self._free(sig_ptr)

    # secp256k1

    def secp256k1_generate_keypair(self) -> Secp256k1KeyPair:
        """Generate a secp256k1 key pair."""
        priv_ptr = self._malloc(SECP256K1_PRIVATE_KEY_SIZE)
        pub_ptr = self._malloc(SECP256K1_PUBLIC_KEY_SIZE)

        try:
            result = self._secp256k1_generate(priv_ptr, pub_ptr)
            if result != 0:
                raise RuntimeError("Key generation failed")

            return Secp256k1KeyPair(
                private_key=self._read_bytes(priv_ptr, SECP256K1_PRIVATE_KEY_SIZE),
                public_key=self._read_bytes(pub_ptr, SECP256K1_PUBLIC_KEY_SIZE)
            )
        finally:
            self._free(priv_ptr)
            self._free(pub_ptr)

    def secp256k1_sign(self, private_key: bytes, message_hash: bytes) -> bytes:
        """
        Sign with secp256k1 ECDSA.

        Args:
            private_key: 32-byte private key
            message_hash: 32-byte hash to sign

        Returns:
            DER-encoded signature (70-72 bytes)
        """
        priv_ptr = self._malloc(len(private_key))
        msg_ptr = self._malloc(len(message_hash))
        sig_ptr = self._malloc(SECP256K1_SIGNATURE_MAX_SIZE)
        sig_len_ptr = self._malloc(4)

        try:
            self._write_bytes(priv_ptr, private_key)
            self._write_bytes(msg_ptr, message_hash)

            result = self._secp256k1_sign(
                priv_ptr, msg_ptr, len(message_hash),
                sig_ptr, sig_len_ptr
            )
            if result != 0:
                raise RuntimeError("Signing failed")

            sig_len = struct.unpack('<I', self._read_bytes(sig_len_ptr, 4))[0]
            return self._read_bytes(sig_ptr, sig_len)
        finally:
            self._free(priv_ptr)
            self._free(msg_ptr)
            self._free(sig_ptr)
            self._free(sig_len_ptr)

    def secp256k1_verify(self, public_key: bytes, message_hash: bytes, signature: bytes) -> bool:
        """
        Verify secp256k1 ECDSA signature.

        Args:
            public_key: 33 or 65 byte public key
            message_hash: 32-byte hash that was signed
            signature: DER-encoded signature

        Returns:
            True if valid, False otherwise
        """
        pub_ptr = self._malloc(len(public_key))
        msg_ptr = self._malloc(len(message_hash))
        sig_ptr = self._malloc(len(signature))

        try:
            self._write_bytes(pub_ptr, public_key)
            self._write_bytes(msg_ptr, message_hash)
            self._write_bytes(sig_ptr, signature)

            result = self._secp256k1_verify(
                pub_ptr, len(public_key),
                msg_ptr, len(message_hash),
                sig_ptr, len(signature)
            )
            return result == 0
        finally:
            self._free(pub_ptr)
            self._free(msg_ptr)
            self._free(sig_ptr)
```

## Template Project Structure

```
myproject/
├── requirements.txt
├── encryption.py       # WASM wrapper module
├── main.py
├── wasm/
│   └── flatc-encryption.wasm
└── tests/
    └── test_encryption.py
```

**requirements.txt:**
```
wasmer>=1.1.0
wasmer-compiler-cranelift>=1.1.0
```

## Usage Examples

### Basic Encryption

```python
from encryption import EncryptionModule
import os

module = EncryptionModule("flatc-encryption.wasm")

# Generate key and IV
key = os.urandom(32)
iv = os.urandom(16)

# Encrypt
plaintext = b"Secret message"
ciphertext = module.encrypt(key, iv, plaintext)

# Decrypt
decrypted = module.decrypt(key, iv, ciphertext)
assert decrypted == plaintext
```

### End-to-End Encryption

```python
from encryption import EncryptionModule
import os

module = EncryptionModule()

# Alice generates keypair
alice = module.x25519_generate_keypair()

# Bob generates keypair
bob = module.x25519_generate_keypair()

# Alice computes shared secret
alice_shared = module.x25519_shared_secret(alice.private_key, bob.public_key)

# Bob computes same shared secret
bob_shared = module.x25519_shared_secret(bob.private_key, alice.public_key)

assert alice_shared == bob_shared

# Derive encryption key
encryption_key = module.hkdf(
    alice_shared,
    None,  # no salt
    b"my-app-encryption-v1",
    32
)

# Encrypt message
iv = os.urandom(16)
message = b"Hello Bob!"
ciphertext = module.encrypt(encryption_key, iv, message)

# Bob decrypts
decrypted = module.decrypt(encryption_key, iv, ciphertext)
print(decrypted.decode())  # "Hello Bob!"
```

### Digital Signatures

```python
from encryption import EncryptionModule

module = EncryptionModule()

# Generate signing keypair
keypair = module.ed25519_generate_keypair()

# Sign message
message = b"Sign this document"
signature = module.ed25519_sign(keypair.private_key, message)

# Verify
is_valid = module.ed25519_verify(keypair.public_key, message, signature)
print(f"Signature valid: {is_valid}")  # True

# Tampered message fails verification
is_valid = module.ed25519_verify(keypair.public_key, b"tampered", signature)
print(f"Tampered valid: {is_valid}")  # False
```

## Alternative: Using wasmtime-py

If you prefer wasmtime over wasmer:

```python
import wasmtime

# Create engine and store
engine = wasmtime.Engine()
store = wasmtime.Store(engine)
linker = wasmtime.Linker(engine)

# Add WASI
wasi_config = wasmtime.WasiConfig()
store.set_wasi(wasi_config)
linker.define_wasi()

# Load and instantiate
module = wasmtime.Module.from_file(engine, "flatc-encryption.wasm")
instance = linker.instantiate(store, module)

# Get exports
memory = instance.exports(store)["memory"]
malloc = instance.exports(store)["malloc"]
# ...
```

## Performance Tips

1. **Reuse the module instance** - Instantiation is expensive
2. **Batch operations** - Minimize Python↔WASM boundary crossings
3. **Use memoryview** - For large data, avoid copying

```python
# Good: Reuse instance
module = EncryptionModule()
for item in items:
    module.encrypt(key, iv, item)

# Bad: Create new instance each time
for item in items:
    module = EncryptionModule()  # Slow!
    module.encrypt(key, iv, item)
```

## Troubleshooting

### "Import not found: wasi_snapshot_preview1"

Add WASI stubs to your import object. See the complete wrapper above.

### "Import not found: env.invoke_*"

Add Emscripten trampolines. For basic usage, empty stubs work:

```python
import_object.register("env", {
    "invoke_v": Function(store, lambda idx: None, FunctionType([Type.I32], [])),
    # ... add more as needed
})
```

### "Memory access out of bounds"

Check pointer validity and buffer sizes:

```python
ptr = malloc(size)
if ptr == 0:
    raise MemoryError("malloc returned null")
```

## See Also

- [wasmer-python Documentation](https://wasmerio.github.io/wasmer-python/)
- [wasmtime-py Documentation](https://bytecodealliance.github.io/wasmtime-py/)
- [API Reference](README.md#api-reference)
- [Security Considerations](README.md#security-considerations)
