"""
Python wrapper for flatc-wasm encryption.

This module provides the same encryption API as the JavaScript flatc-wasm module,
ensuring 100% compatibility for cross-language interoperability.

The encryption algorithm is implemented identically to the JavaScript version,
so data encrypted in Python can be decrypted in JavaScript/Node.js and vice versa.

For FlatBuffer creation/parsing, this module can optionally use wasmtime to call
the actual flatc-wasm WASM binary, or you can use the encryption functions directly
with buffers created by other means.

Usage:
    from flatc_wasm import EncryptionContext, encrypt_buffer, decrypt_buffer

    key = os.urandom(32)
    ctx = EncryptionContext(key)

    # Encrypt a FlatBuffer
    encrypted = encrypt_buffer(buffer, schema_content, ctx, "RootType")

    # Decrypt
    decrypted = decrypt_buffer(encrypted, schema_content, ctx, "RootType")

Requirements:
    - No dependencies for encryption (pure Python)
    - pip install wasmtime (optional, for FlatBuffer creation/parsing via WASM)
"""

import struct
import re
from typing import List, Optional, Union
from dataclasses import dataclass

# ============================================================================
# AES-256-CTR Implementation (matches JavaScript encryption.mjs exactly)
# ============================================================================

# AES S-box
SBOX = bytes([
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
])

RCON = bytes([0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36])


def _gf_mul(a: int, b: int) -> int:
    """GF(2^8) multiplication - matches JavaScript gfMul"""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit:
            a ^= 0x1B
        b >>= 1
    return p


def _aes256_key_expansion(key: bytes) -> bytes:
    """Expand AES-256 key to round keys - matches JavaScript aes256KeyExpansion"""
    round_keys = bytearray(240)
    round_keys[:32] = key

    i = 8
    while i < 60:
        temp = list(round_keys[(i - 1) * 4:i * 4])

        if i % 8 == 0:
            # RotWord + SubWord + Rcon
            t = temp[0]
            temp[0] = SBOX[temp[1]] ^ RCON[i // 8]
            temp[1] = SBOX[temp[2]]
            temp[2] = SBOX[temp[3]]
            temp[3] = SBOX[t]
        elif i % 8 == 4:
            temp = [SBOX[b] for b in temp]

        for j in range(4):
            round_keys[i * 4 + j] = round_keys[(i - 8) * 4 + j] ^ temp[j]
        i += 1

    return bytes(round_keys)


def _sub_bytes(state: bytearray) -> None:
    """AES SubBytes - matches JavaScript subBytes"""
    for i in range(16):
        state[i] = SBOX[state[i]]


def _shift_rows(state: bytearray) -> None:
    """AES ShiftRows - matches JavaScript shiftRows"""
    # Row 1
    temp = state[1]
    state[1] = state[5]
    state[5] = state[9]
    state[9] = state[13]
    state[13] = temp
    # Row 2
    temp = state[2]
    state[2] = state[10]
    state[10] = temp
    temp = state[6]
    state[6] = state[14]
    state[14] = temp
    # Row 3
    temp = state[15]
    state[15] = state[11]
    state[11] = state[7]
    state[7] = state[3]
    state[3] = temp


def _mix_columns(state: bytearray) -> None:
    """AES MixColumns - matches JavaScript mixColumns"""
    for i in range(4):
        a = [state[i * 4 + j] for j in range(4)]
        state[i * 4 + 0] = _gf_mul(a[0], 2) ^ _gf_mul(a[1], 3) ^ a[2] ^ a[3]
        state[i * 4 + 1] = a[0] ^ _gf_mul(a[1], 2) ^ _gf_mul(a[2], 3) ^ a[3]
        state[i * 4 + 2] = a[0] ^ a[1] ^ _gf_mul(a[2], 2) ^ _gf_mul(a[3], 3)
        state[i * 4 + 3] = _gf_mul(a[0], 3) ^ a[1] ^ a[2] ^ _gf_mul(a[3], 2)


def _add_round_key(state: bytearray, round_key: bytes) -> None:
    """AES AddRoundKey - matches JavaScript addRoundKey"""
    for i in range(16):
        state[i] ^= round_key[i]


def _aes_encrypt_block(key: bytes, input_block: bytes) -> bytes:
    """AES-256 encrypt single 16-byte block - matches JavaScript aesEncryptBlock"""
    round_keys = _aes256_key_expansion(key)
    state = bytearray(input_block)

    _add_round_key(state, round_keys[:16])

    for round_num in range(1, 14):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[round_num * 16:(round_num + 1) * 16])

    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[14 * 16:15 * 16])

    return bytes(state)


def _aes_ctr_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """Generate AES-CTR keystream - matches JavaScript aesCtrKeystream"""
    keystream = bytearray(length)
    counter = bytearray(nonce)

    offset = 0
    while offset < length:
        block = _aes_encrypt_block(key, bytes(counter))
        to_copy = min(16, length - offset)
        keystream[offset:offset + to_copy] = block[:to_copy]
        offset += to_copy

        # Increment counter (big-endian) - matches JavaScript
        for i in range(15, -1, -1):
            counter[i] = (counter[i] + 1) & 0xFF
            if counter[i] != 0:
                break

    return bytes(keystream)


def _derive_key(master_key: bytes, info: bytes, out_length: int) -> bytes:
    """Simple HKDF-like key derivation - matches JavaScript deriveKey EXACTLY"""
    out = bytearray(out_length)

    # Mix master key into output
    for i in range(min(out_length, len(master_key))):
        out[i] = master_key[i]

    # Mix info using a simple hash-like operation
    hash_val = 0
    for b in info:
        hash_val ^= b
        hash_val = ((hash_val << 1) | (hash_val >> 7)) & 0xFF

    # Apply info hash to derive different keys
    for i in range(out_length):
        out[i] ^= hash_val
        hash_val = ((hash_val * 31 + i) & 0xFF)

    # Additional mixing pass using AES
    if out_length >= 16:
        temp = _aes_encrypt_block(master_key, bytes(out[:16]))
        out[:min(out_length, 16)] = temp[:min(out_length, 16)]
        if out_length > 16:
            temp2 = _aes_encrypt_block(master_key, temp)
            out[16:min(out_length, 32)] = temp2[:min(out_length - 16, 16)]

    return bytes(out)


# ============================================================================
# Encryption Context and Functions
# ============================================================================

class EncryptionContext:
    """
    Encryption context for FlatBuffer field encryption.
    Matches JavaScript EncryptionContext class exactly.
    """

    def __init__(self, key: Union[bytes, str]):
        """
        Create encryption context.

        Args:
            key: 32-byte key as bytes or 64-character hex string
        """
        if isinstance(key, str):
            self._key = bytes.fromhex(key)
        else:
            self._key = bytes(key)

        self._valid = len(self._key) == 32

    def is_valid(self) -> bool:
        """Check if context is valid."""
        return self._valid

    def derive_field_key(self, field_id: int) -> bytes:
        """
        Derive field-specific 32-byte key.
        Matches JavaScript deriveFieldKey exactly.
        """
        # Build info bytes exactly like JavaScript:
        # const info = new Uint8Array(19);
        # const infoStr = "flatbuffers-field";
        # for (let i = 0; i < infoStr.length; i++) {
        #     info[i] = infoStr.charCodeAt(i);
        # }
        # info[17] = (fieldId >> 8) & 0xff;
        # info[18] = fieldId & 0xff;
        info = bytearray(19)
        info_str = b"flatbuffers-field"
        info[:len(info_str)] = info_str
        info[17] = (field_id >> 8) & 0xFF
        info[18] = field_id & 0xFF
        return _derive_key(self._key, bytes(info), 32)

    def derive_field_iv(self, field_id: int) -> bytes:
        """
        Derive field-specific 16-byte IV.
        Matches JavaScript deriveFieldIV exactly.
        """
        # Build info bytes exactly like JavaScript:
        # const info = new Uint8Array(16);
        # const infoStr = "flatbuffers-iv";
        # for (let i = 0; i < infoStr.length; i++) {
        #     info[i] = infoStr.charCodeAt(i);
        # }
        # info[14] = (fieldId >> 8) & 0xff;
        # info[15] = fieldId & 0xff;
        info = bytearray(16)
        info_str = b"flatbuffers-iv"
        info[:len(info_str)] = info_str
        info[14] = (field_id >> 8) & 0xFF
        info[15] = field_id & 0xFF
        return _derive_key(self._key, bytes(info), 16)


def encrypt_bytes(data: Union[bytearray, memoryview], key: bytes, iv: bytes) -> None:
    """
    Encrypt bytes in-place using AES-CTR.
    Matches JavaScript encryptBytes exactly.

    Args:
        data: Data to encrypt (modified in-place). Must be a bytearray or memoryview.
        key: 32-byte key
        iv: 16-byte IV
    """
    keystream = _aes_ctr_keystream(key, iv, len(data))
    for i in range(len(data)):
        data[i] ^= keystream[i]


def _encrypt_region(buffer: bytearray, start: int, length: int, key: bytes, iv: bytes) -> None:
    """Encrypt a region of the buffer in-place."""
    keystream = _aes_ctr_keystream(key, iv, length)
    for i in range(length):
        buffer[start + i] ^= keystream[i]


# Decrypt is same as encrypt for CTR mode
decrypt_bytes = encrypt_bytes


# ============================================================================
# Schema Parsing
# ============================================================================

@dataclass
class FieldInfo:
    """Field information from parsed schema."""
    name: str
    id: int
    type: str
    encrypted: bool
    element_type: Optional[str] = None
    element_size: int = 0
    struct_size: int = 0


def _get_type_size(type_name: str) -> int:
    """Get size of scalar type."""
    sizes = {
        "bool": 1, "byte": 1, "ubyte": 1,
        "short": 2, "ushort": 2,
        "int": 4, "uint": 4, "float": 4,
        "long": 8, "ulong": 8, "double": 8,
    }
    return sizes.get(type_name, 0)


def _get_base_type(type_name: str) -> str:
    """Get base type category - matches JavaScript getBaseType."""
    scalar_types = {"bool", "byte", "ubyte", "short", "ushort",
                    "int", "uint", "long", "ulong", "float", "double"}
    if type_name in scalar_types:
        return type_name
    if type_name == "string":
        return "string"
    return "struct"


def parse_schema_for_encryption(schema_content: str, root_type: str) -> List[FieldInfo]:
    """
    Parse schema to extract field encryption info.
    Matches JavaScript parseSchemaForEncryption.

    Args:
        schema_content: FlatBuffers schema content
        root_type: Name of root table type

    Returns:
        List of FieldInfo objects
    """
    fields = []

    # Find root table
    pattern = rf"table\s+{re.escape(root_type)}\s*\{{([^}}]+)\}}"
    match = re.search(pattern, schema_content, re.DOTALL)
    if not match:
        return fields

    table_body = match.group(1)
    field_pattern = r"(\w+)\s*:\s*(\[?\w+\]?)\s*(?:\(([^)]*)\))?"

    field_id = 0
    for match in re.finditer(field_pattern, table_body):
        name = match.group(1)
        field_type = match.group(2)
        attributes = match.group(3) or ""

        is_encrypted = "encrypted" in attributes
        is_vector = field_type.startswith("[") and field_type.endswith("]")
        base_type = field_type[1:-1] if is_vector else field_type

        field = FieldInfo(
            name=name,
            id=field_id,
            type="vector" if is_vector else _get_base_type(base_type),
            encrypted=is_encrypted,
        )

        if is_vector:
            field.element_type = _get_base_type(base_type)
            field.element_size = _get_type_size(base_type)

        fields.append(field)
        field_id += 1

    return fields


# ============================================================================
# FlatBuffer Processing
# ============================================================================

def _read_uint32(buffer: bytes, offset: int) -> int:
    """Read little-endian uint32."""
    return struct.unpack_from("<I", buffer, offset)[0]


def _read_int32(buffer: bytes, offset: int) -> int:
    """Read little-endian int32."""
    return struct.unpack_from("<i", buffer, offset)[0]


def _read_uint16(buffer: bytes, offset: int) -> int:
    """Read little-endian uint16."""
    return struct.unpack_from("<H", buffer, offset)[0]


def _process_table(
    buffer: bytearray,
    table_offset: int,
    fields: List[FieldInfo],
    ctx: EncryptionContext
) -> None:
    """
    Process a table, encrypting/decrypting marked fields.
    Matches JavaScript processTable.
    """
    # Read vtable offset
    vtable_offset_delta = _read_int32(buffer, table_offset)
    vtable_offset = table_offset - vtable_offset_delta

    # Read vtable size
    vtable_size = _read_uint16(buffer, vtable_offset)

    for field in fields:
        field_vtable_idx = (field.id + 2) * 2

        if field_vtable_idx >= vtable_size:
            continue

        field_offset = _read_uint16(buffer, vtable_offset + field_vtable_idx)
        if field_offset == 0:
            continue

        field_loc = table_offset + field_offset

        if not field.encrypted:
            continue

        # Derive keys for this field
        key = ctx.derive_field_key(field.id)
        iv = ctx.derive_field_iv(field.id)

        # Encrypt based on type - matches JavaScript processTable switch cases
        if field.type in ("bool", "byte", "ubyte"):
            _encrypt_region(buffer, field_loc, 1, key, iv)
        elif field.type in ("short", "ushort"):
            _encrypt_region(buffer, field_loc, 2, key, iv)
        elif field.type in ("int", "uint", "float"):
            _encrypt_region(buffer, field_loc, 4, key, iv)
        elif field.type in ("long", "ulong", "double"):
            _encrypt_region(buffer, field_loc, 8, key, iv)
        elif field.type == "string":
            string_offset = _read_uint32(buffer, field_loc)
            string_loc = field_loc + string_offset
            string_len = _read_uint32(buffer, string_loc)
            string_data = string_loc + 4
            if string_data + string_len <= len(buffer):
                _encrypt_region(buffer, string_data, string_len, key, iv)
        elif field.type == "vector":
            vec_offset = _read_uint32(buffer, field_loc)
            vec_loc = field_loc + vec_offset
            vec_len = _read_uint32(buffer, vec_loc)
            vec_data = vec_loc + 4
            elem_size = field.element_size or 1
            total_size = vec_len * elem_size
            if vec_data + total_size <= len(buffer):
                _encrypt_region(buffer, vec_data, total_size, key, iv)
        elif field.type == "struct" and field.struct_size > 0:
            if field_loc + field.struct_size <= len(buffer):
                _encrypt_region(buffer, field_loc, field.struct_size, key, iv)


def encrypt_buffer(
    buffer: bytes,
    schema_content: str,
    key_or_ctx: Union[bytes, str, EncryptionContext],
    root_type: str
) -> bytes:
    """
    Encrypt a FlatBuffer.
    Matches JavaScript encryptBuffer.

    Args:
        buffer: FlatBuffer data
        schema_content: Schema with (encrypted) attributes
        key_or_ctx: 32-byte key, hex string, or EncryptionContext
        root_type: Name of root table type

    Returns:
        Encrypted buffer (new copy)
    """
    if isinstance(key_or_ctx, EncryptionContext):
        ctx = key_or_ctx
    else:
        ctx = EncryptionContext(key_or_ctx)

    if not ctx.is_valid():
        raise ValueError("Invalid encryption key (must be 32 bytes)")

    fields = parse_schema_for_encryption(schema_content, root_type)
    result = bytearray(buffer)

    # Read root table offset
    root_offset = _read_uint32(result, 0)

    _process_table(result, root_offset, fields, ctx)

    return bytes(result)


def decrypt_buffer(
    buffer: bytes,
    schema_content: str,
    key_or_ctx: Union[bytes, str, EncryptionContext],
    root_type: str
) -> bytes:
    """
    Decrypt a FlatBuffer.
    Same as encrypt_buffer since AES-CTR is symmetric.

    Args:
        buffer: Encrypted FlatBuffer data
        schema_content: Schema with (encrypted) attributes
        key_or_ctx: 32-byte key, hex string, or EncryptionContext
        root_type: Name of root table type

    Returns:
        Decrypted buffer (new copy)
    """
    return encrypt_buffer(buffer, schema_content, key_or_ctx, root_type)


# ============================================================================
# Optional: WASM-based FlatBuffer creation (requires wasmtime)
# ============================================================================

class FlatcWasm:
    """
    Optional wrapper for the flatc-wasm WebAssembly module.

    Use this class if you need to create FlatBuffers from JSON or convert
    FlatBuffers to JSON. For encryption only, use the standalone functions.

    Requires: pip install wasmtime
    """

    def __init__(self, wasm_path: Optional[str] = None):
        """
        Initialize the FlatcWasm wrapper.

        Args:
            wasm_path: Path to flatc-wasm.wasm. If not provided, looks in
                       common locations relative to this file.
        """
        try:
            from wasmtime import Store, Module, Instance
        except ImportError:
            raise ImportError(
                "wasmtime is required for FlatcWasm. Install with: pip install wasmtime\n"
                "For encryption-only usage, use the encrypt_buffer/decrypt_buffer functions directly."
            )

        from pathlib import Path

        if wasm_path is None:
            wasm_path = self._find_wasm_binary()

        self._store = Store()
        self._module = Module.from_file(self._store.engine, wasm_path)
        self._instance: Optional[Instance] = None
        self._memory = None

        self._setup_instance()

    def _find_wasm_binary(self) -> str:
        """Find the WASM binary in common locations."""
        from pathlib import Path

        base = Path(__file__).parent
        search_paths = [
            base / "../../dist/flatc-wasm.wasm",
            base / "../../build/flatc-wasm.wasm",
            base / "../../../build/wasm/flatc-wasm.wasm",
            base / "flatc-wasm.wasm",
            Path("flatc-wasm.wasm"),
        ]

        for path in search_paths:
            resolved = path.resolve()
            if resolved.exists():
                return str(resolved)

        raise FileNotFoundError(
            "Could not find flatc-wasm.wasm. Please provide the path explicitly "
            "or build the WASM module first."
        )

    def _setup_instance(self) -> None:
        """Set up the WASM instance."""
        from wasmtime import Instance

        # Try to instantiate - may fail if imports are required
        try:
            self._instance = Instance(self._store, self._module, [])
            memory_export = self._instance.exports(self._store).get("memory")
            if memory_export is not None:
                self._memory = memory_export
        except Exception as e:
            raise RuntimeError(
                f"Failed to instantiate WASM module: {e}\n"
                "The flatc-wasm module may require additional imports."
            )

    def version(self) -> str:
        """Get the flatc version string."""
        get_version = self._instance.exports(self._store).get("wasm_get_version")
        if get_version is None:
            return "unknown"

        ptr = get_version(self._store)
        return self._read_string(ptr)

    def _read_string(self, ptr: int) -> str:
        """Read null-terminated string from WASM memory."""
        if self._memory is None:
            return ""
        mem = self._memory.data_ptr(self._store)
        result = bytearray()
        i = 0
        while mem[ptr + i] != 0:
            result.append(mem[ptr + i])
            i += 1
        return result.decode('utf-8')

    def encrypt_buffer(
        self,
        buffer: bytearray,
        schema_content: str,
        key: bytes,
        root_type: str
    ) -> None:
        """
        Encrypt a FlatBuffer in-place using Python implementation.

        Note: This uses the Python encryption, not WASM, to ensure
        cross-language compatibility with the JavaScript implementation.
        """
        ctx = EncryptionContext(key)
        encrypted = encrypt_buffer(bytes(buffer), schema_content, ctx, root_type)
        buffer[:] = encrypted

    def decrypt_buffer(
        self,
        buffer: bytearray,
        schema_content: str,
        key: bytes,
        root_type: str
    ) -> None:
        """
        Decrypt a FlatBuffer in-place.
        Same as encrypt for AES-CTR.
        """
        self.encrypt_buffer(buffer, schema_content, key, root_type)
