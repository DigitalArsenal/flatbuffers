# FlatBuffers Cross-Language Encryption E2E Tests

End-to-end testing framework for FlatBuffers WASM encryption module across multiple languages
with support for 10 major cryptocurrency key types.

## Transparent Encryption Model

**Key concept:** Encryption is TRANSPARENT. The same FlatBuffers schema works for both
encrypted and unencrypted messages. Encryption is applied to the serialized FlatBuffer
binary, not to specific fields in the schema.

```
┌──────────────┐      ┌─────────────────┐      ┌─────────────────┐
│  JSON Data   │  →   │  FlatBuffer     │  →   │  Encrypted      │
│              │      │  Binary         │      │  Binary         │
└──────────────┘      └─────────────────┘      └─────────────────┘
     Same schema for both encrypted and unencrypted
```

**How users identify encrypted messages:**
- File identifier (e.g., `"MONS"` vs `"MONE"`)
- A user-defined field in the message
- External metadata or protocol headers
- File extension or naming convention

## Schema Usage

This test framework uses the **upstream FlatBuffers test schemas** - no custom schemas:

| File | Purpose |
|------|---------|
| `tests/monster_test.fbs` | Main schema with unions, structs, enums, gRPC |
| `tests/monsterdata_test.json` | Standard test data with all field types |
| `tests/unicode_test.json` | Unicode edge cases (Cyrillic, CJK, surrogate pairs) |
| `tests/optional_scalars.fbs` | Optional/nullable scalar fields |
| `tests/optional_scalars.json` | Test data for null vs zero vs default |
| `tests/monster_extra.fbs` | NaN and Infinity floating-point values |
| `tests/monsterdata_extra.json` | NaN/Inf test data |
| `tests/monsterdata_test.mon` | Golden binary for wire compatibility |
| `tests/nested_union_test.fbs` | Nested unions with bit_flags enum |
| `tests/more_defaults.fbs` | Additional default vector/string tests |
| `tests/nan_inf_test.fbs` | NaN/Inf as DEFAULT values in schema |
| `tests/required_strings.fbs` | Required field attribute |
| `tests/alignment_test.fbs` | Struct alignment edge cases |
| `tests/alignment_test.json` | Alignment test data |
| `tests/alignment_test_before_fix.bin` | Pre-fix alignment binary |
| `tests/alignment_test_after_fix.bin` | Post-fix alignment binary |
| `tests/arrays_test.fbs` | Fixed-size array syntax |
| `tests/default_vectors_strings_test.fbs` | Empty default vectors |
| `tests/unicode_test.mon` | Unicode golden binary |
| `tests/monsterdata_java_wire.mon` | Java wire format binary |
| `tests/monsterdata_java_wire_sp.mon` | Java single-precision binary |
| `tests/monsterdata_python_wire.mon` | Python wire format binary |
| `tests/monsterdata_rust_wire.mon` | Rust wire format binary |
| `tests/javatest.bin` | Additional Java test binary |
| `tests/gold_flexbuffer_example.bin` | FlexBuffer format binary |
| `tests/native_type_test.fbs` | Native C++ type mapping |
| `tests/native_inline_table_test.fbs` | native_inline on table vectors |
| `tests/service_test.fbs` | Standalone gRPC service schema |
| `tests/union_underlying_type_test.fbs` | Union with explicit underlying type |
| `tests/optional_scalars_defaults.json` | Optional scalar default values |

## Supported Cryptocurrency Key Types

| # | Chain | Signature Scheme | Curve |
|---|-------|------------------|-------|
| 1 | Bitcoin | ECDSA | secp256k1 |
| 2 | Ethereum | ECDSA | secp256k1 |
| 3 | Solana | EdDSA | Ed25519 |
| 4 | SUI | EdDSA | Ed25519 |
| 5 | Cosmos | ECDSA | secp256k1 |
| 6 | Polkadot | Schnorr | Sr25519 |
| 7 | Cardano | EdDSA | Ed25519 |
| 8 | Tezos | EdDSA | Ed25519 |
| 9 | NEAR | EdDSA | Ed25519 |
| 10 | Aptos | EdDSA | Ed25519 |

## Test Runners

| Language | Runtime | Location |
|----------|---------|----------|
| Node.js | V8 (native) | `runners/node/` |
| Go | wazero | `runners/go/` |
| Python | wasmer-python | `runners/python/` |
| Rust | wasmer | `runners/rust/` |
| Java | Chicory | `runners/java/` |
| C# | Wasmtime | `runners/csharp/` |
| Swift | WasmKit | `runners/swift/` |

## Quick Start

### Prerequisites

1. Build the WASM encryption module:
```bash
cd /path/to/flatbuffers
cmake --build build/wasm --target flatc_wasm_wasi
```

2. Generate test vectors (run once):
```bash
cd wasm/examples/e2e-crypto-test
node generate_vectors.mjs
```

### Running Tests

**Node.js (reference implementation):**
```bash
cd runners/node
npm link flatc-wasm  # Link the WASM module
node test_runner.mjs
```

**Go:**
```bash
cd runners/go
go run test_runner.go
```

**Python:**
```bash
cd runners/python
pip install wasmer wasmer_compiler_cranelift
python test_runner.py
```

**Rust:**
```bash
cd runners/rust
cargo run
```

**Java:**
```bash
cd runners/java
mvn compile exec:java
```

**C#:**
```bash
cd runners/csharp
dotnet run
```

**Swift:**
```bash
cd runners/swift
swift run
```

## Test Structure

### Test Vectors

Located in `vectors/`:
- `encryption_keys.json` - AES-256 keys and IVs for each chain
- `crypto_keys.json` - ECDH/signature keypairs for each chain
- `test_vectors.json` - Test configuration pointing to upstream schemas

### Generated Binaries

The Node.js test runner generates binary files in `vectors/binary/`:
- `monster_unencrypted.bin` - Unencrypted FlatBuffer (using upstream schema)
- `monster_encrypted_bitcoin.bin` - Entire binary encrypted with Bitcoin key
- `monster_encrypted_ethereum.bin` - Entire binary encrypted with Ethereum key
- ... (one for each chain)

Other language runners read these files to verify cross-language compatibility.

## What Each Test Validates

### Test 1a: Unencrypted FlatBuffer (monsterdata_test.json)

Generates a FlatBuffer using the upstream `monsterdata_test.json` and verifies ALL data types
and edge cases survive the binary round-trip:

| Edge Case | Field | Value | Why It Matters |
|-----------|-------|-------|----------------|
| Basic string | `name` | `"MyMonster"` | Simple string field |
| Numeric scalar | `hp` | `80` | 16-bit integer |
| Nested struct | `pos` | `{x:1, y:2, z:3}` | Struct with multiple fields |
| Sub-struct | `pos.test3` | `{a:5, b:6}` | Struct nested inside struct |
| Enum in struct | `pos.test2` | `"Green"` | Enum value in nested context |
| Byte array | `inventory` | `[0,1,2,3,4]` | Vector of ubyte |
| Long array | `vector_of_longs` | `[1,100,...,100000000]` | Vector of 64-bit integers |
| **Extreme doubles** | `vector_of_doubles` | `[±1.79e+308, 0]` | Near DBL_MAX/DBL_MIN values |
| Union type | `test_type` + `test` | `Monster{name:"Fred"}` | Union with nested table |
| Struct array | `test4`, `test5` | `[{a:10,b:20},...]` | Vector of structs |
| String array | `testarrayofstring` | `["test1","test2"]` | Vector of strings |
| Nested table | `enemy` | `{name:"Fred"}` | Table reference |
| Boolean array | `testarrayofbools` | `[true,false,true]` | Vector of bools |
| Boolean scalar | `testbool` | `true` | Single boolean |
| Sorted struct array | `testarrayofsortedstruct` | Sorted by `id` | Binary search support |
| Sorted table array | `scalar_key_sorted_tables` | 2 entries | Keyed table lookup |
| Native inline | `native_inline` | `{a:1, b:2}` | Inline struct optimization |
| FNV hash fields | `testhashs32_fnv1` | hash value | String-to-hash conversion |

### Test 1b: Unicode Strings (unicode_test.json)

Verifies multi-byte UTF-8 encoding edge cases:

| Unicode Category | Example | Bytes | Why It Matters |
|------------------|---------|-------|----------------|
| Cyrillic/Greek | `Цлїςσδε` | 2-byte UTF-8 | Non-ASCII European scripts |
| Half-width Katakana | `ﾌﾑｱﾑｶﾓｹﾓ` | 3-byte UTF-8 | Japanese text |
| Full-width Katakana | `フムヤムカモケモ` | 3-byte UTF-8 | Japanese text variant |
| CJK Circled | `㊀㊁㊂㊃㊄` | 3-byte UTF-8 | Enclosed CJK characters |
| I Ching Trigrams | `☳☶☲` | 3-byte UTF-8 | Symbols |
| **Surrogate Pairs** | `𡇙𝌆` | **4-byte UTF-8** | Characters > U+FFFF |

### Test 1c: Optional Scalars (optional_scalars.json)

Tests null-capable scalar fields:

| Edge Case | Fields | Why It Matters |
|-----------|--------|----------------|
| Required fields | `just_i8`, `just_i16`, etc. | Always-present scalars |
| Optional with zero | `maybe_u8 = 0` | Distinguishes zero from null |
| Default override | `default_u8 = 0` | Override non-zero default with zero |
| Optional enum | `maybe_enum = One` | Enum with null capability |
| Optional bool | `maybe_bool = null` | Boolean null handling |

### Test 1d: NaN/Infinity (monsterdata_extra.json)

Tests IEEE 754 special floating-point values:

| Edge Case | Field | Value | Why It Matters |
|-----------|-------|-------|----------------|
| NaN double | `d3` | `nan` | Not-a-Number handling |
| +Infinity double | `d1` | `+inf` | Positive infinity |
| -Infinity double | `d2` | `-inf` | Negative infinity |
| NaN float | `f0`, `f1` | `nan` | Single-precision NaN |
| +/- Inf float | `f2`, `f3` | `±inf` | Single-precision infinity |
| Vector with NaN | `dvec`, `fvec` | Mixed special values | Array of special floats |

### Test 1e: Golden Binary Wire Compatibility

Verifies wire format compatibility with pre-generated binaries:

- `monsterdata_test.mon` - Official golden binary (600 bytes)
- Verifies file identifier `"MONS"` at offset 4-7
- Compares generated binary size to golden reference
- Ensures backwards compatibility with existing FlatBuffers

### Test 1f: gRPC/RPC Service Schema

Verifies the schema parser handles `rpc_service` definitions:

| Service | Method | Streaming |
|---------|--------|-----------|
| `MonsterStorage` | `Store(Monster):Stat` | none |
| `MonsterStorage` | `Retrieve(Stat):Monster` | server |
| `MonsterStorage` | `GetMaxHitPoint(Monster):Stat` | client |
| `MonsterStorage` | `GetMinMaxHitPoints(Monster):Stat` | bidi |

### Test 1g: Struct Alignment (alignment_test.json)

Tests memory alignment edge cases:

- `BadAlignmentSmall` - 12-byte struct with 4-byte alignment
- `BadAlignmentLarge` - 8-byte struct with 8-byte alignment
- `EvenSmallStruct` - 2-byte struct with 1-byte alignment
- `OddSmallStruct` - 3-byte struct with 1-byte alignment
- Verifies struct padding survives binary round-trip

### Test 1h: Fixed-Size Arrays (arrays_test.fbs)

Verifies fixed-size array syntax in structs:

| Syntax | Description |
|--------|-------------|
| `[int:2]` | Fixed 2-element int array |
| `[int:0xF]` | Fixed 15-element array (hex size) |
| `[NestedStruct:2]` | Fixed array of structs |
| `[TestEnum:2]` | Fixed array of enums |
| `[int64:2]` | Fixed array of 64-bit integers |

### Test 1i: Default Vectors/Strings (default_vectors_strings_test.fbs)

Tests empty default values:

| Feature | Example |
|---------|---------|
| Empty int vector | `int_vec:[int] = []` |
| Empty string vector | `string_vec:[string] = []` |
| Empty string | `empty_string:string = ""` |
| Default string | `some_string:string = "some"` |
| Empty struct vector | `struct_vec:[MyStruct] = []` |
| 64-bit vectors | `offset64`, `vector64` attributes |

### Test 1j: Cross-Language Wire Format

Verifies binaries from other FlatBuffers implementations:

| Language | File | Size |
|----------|------|------|
| Java | `monsterdata_java_wire.mon` | 312 bytes |
| Python | `monsterdata_python_wire.mon` | 344 bytes |
| Rust | `monsterdata_rust_wire.mon` | 408 bytes |

Each binary is parsed and verified to ensure cross-language wire format compatibility.

### Test 1k: Unicode Golden Binary

Verifies the pre-generated `unicode_test.mon` golden binary:

- 6 unicode string edge cases preserved
- 4-byte UTF-8 surrogate pairs verified
- Cross-language unicode compatibility

### Test 1l: FlexBuffer Binary

Verifies FlexBuffer format compatibility:

- `gold_flexbuffer_example.bin` (166 bytes)
- FlexBuffers are a schema-less self-describing format
- Different binary format from FlatBuffers

### Test 1m: Nested Union (nested_union_test.fbs)

Tests union types with tables and advanced enum attributes:

| Feature | Example | Why It Matters |
|---------|---------|----------------|
| bit_flags enum | `enum Color (bit_flags)` | Bitmask enum values |
| Multiple attributes | `(csharp_partial, private)` | Language-specific hints |
| Union with tables | `union Any { Vec3, TestSimpleTableWithEnum }` | Complex union variants |
| Union round-trip | Vec3 and enum variants | Full union preservation |

### Test 1n: More Defaults (more_defaults.fbs)

Tests additional default value edge cases:

| Feature | Example | Why It Matters |
|---------|---------|----------------|
| Empty int vector | `ints: [int] = []` | Default empty vector |
| Whitespace in default | `floats: [float] = [     ]` | Parser tolerance |
| Empty enum vector | `abcs: [ABC] = []` | Enum vector defaults |
| Empty bool vector | `bools: [bool] = []` | Boolean vector defaults |
| Default string | `some_string = "some"` | String default value |

### Test 1o: NaN/Inf Schema Defaults (nan_inf_test.fbs)

Tests NaN and Infinity as **schema default values** (not just data):

| Feature | Schema Syntax | Why It Matters |
|---------|---------------|----------------|
| NaN default | `default_nan:double = nan` | Parser handles NaN |
| +Inf default | `default_inf:double = inf` | Parser handles +Infinity |
| -Inf default | `default_ninf:double = -inf` | Parser handles -Infinity |

### Test 1p: Alignment Binary Comparison

Tests struct alignment padding correctness:

| Binary | Size | Purpose |
|--------|------|---------|
| `alignment_test_before_fix.bin` | 32 bytes | Pre-fix alignment |
| `alignment_test_after_fix.bin` | 32 bytes | Post-fix alignment |

Verifies that alignment padding bytes differ between pre/post fix versions.

### Test 1q: Java Wire Format SP (Single Precision)

Tests Java-generated FlatBuffer with single-precision floats:

| Feature | Value | Why It Matters |
|---------|-------|----------------|
| File identifier | `MONS` | Same schema as double-precision |
| Binary size | 312 bytes | Different from double-precision |
| Monster data | name, hp, etc. | Full round-trip |

### Test 1r: Java Test Binary (javatest.bin)

Tests additional Java-generated binary:

| Feature | Value | Why It Matters |
|---------|-------|----------------|
| Binary size | 512 bytes | Larger test case |
| Root offset | 168 | Valid FlatBuffer structure |
| Schema compatibility | monster_test.fbs | Cross-language wire format |

### Test 1s: Required Strings (required_strings.fbs)

Tests the `(required)` field attribute:

| Feature | Example | Why It Matters |
|---------|---------|----------------|
| Required string | `str_a:string (required)` | Must be present |
| Required string | `str_b:string (required)` | Must be present |
| Round-trip | Both fields preserved | Required validation |

### Test 1t: Native Type (native_type_test.fbs)

Tests C++ native type mapping attributes:

| Feature | Example | Why It Matters |
|---------|---------|----------------|
| native_type | `(native_type:"Native::Vector3D")` | Maps to C++ type |
| native_type_pack_name | `native_type_pack_name:"Vector3DAlt"` | Custom pack name |
| native_include | `native_include "native_type_test_impl.h"` | Include directive |
| native_inline | `position_inline:Vector3D (native_inline)` | Inline storage |
| Matrix table | `rows`, `columns`, `values` | Table with native_type |

### Test 1u: Native Inline Table (native_inline_table_test.fbs)

Tests `native_inline` attribute on table vectors:

| Feature | Example | Why It Matters |
|---------|---------|----------------|
| native_inline on vector | `t: [NativeInlineTable] (native_inline)` | Inline table storage |
| Table in vector | Vector of tables | Memory layout optimization |

### Test 1v: Service Test (service_test.fbs)

Tests standalone gRPC service schema (separate from monster_test):

| Service | Method | Streaming |
|---------|--------|-----------|
| HelloService | Hello | none (unary) |
| HelloService | StreamClient | client |
| HelloService | StreamServer | server |
| HelloService | Stream | bidi |

### Test 1w: Union Underlying Type (union_underlying_type_test.fbs)

Tests unions with explicit underlying type and values:

| Feature | Example | Why It Matters |
|---------|---------|----------------|
| Explicit type | `union ABC: int` | Union stored as int |
| Explicit value | `A = 555` | Custom discriminant value |
| Explicit value | `B = 666` | Non-sequential values |
| Explicit value | `C = 777` | Sparse enum space |
| Vector of unions | `test_vector_of_union: [ABC]` | Union array |

### Test 1x: Optional Scalars Defaults (optional_scalars_defaults.json)

Tests optional scalar fields with schema default values:

| Feature | Value | Why It Matters |
|---------|-------|----------------|
| Schema default | `default_i8 = 42` | Non-zero default preserved |
| Explicit null | `maybe_i8 = null` | Null vs missing |
| Explicit zero | `just_u8 = 0` | Zero vs null vs default |
| Float default | `default_f32 = 42.0` | Float precision |
| Bool null | `maybe_bool = null` | Boolean null handling |

### Test 2: SHA-256 Hash
Verifies SHA-256 produces identical output across all WASM runtimes:
- `SHA256("hello")` = `2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824`

### Test 3: Transparent Encryption (Per-Chain)

For each of the 10 cryptocurrency chains:
1. Generate FlatBuffer binary from upstream schema/data
2. Encrypt **entire binary** with chain-specific AES-256-CTR key
3. Verify encrypted data differs from original
4. Decrypt entire binary
5. Verify decrypted binary matches original exactly (byte-for-byte)
6. Verify critical edge cases after decryption:
   - Basic fields (`name`, `hp`)
   - Extreme double values (`±1.79e+308`)
   - Nested structures (`pos.test3`, `enemy`)
   - Array integrity (`inventory`, `testarrayofbools`)

### Test 4: Crypto Operations

- Ed25519 keypair generation (Solana, SUI, Cardano, Tezos, NEAR, Aptos)
- Ed25519 sign/verify
- secp256k1 keypair generation (Bitcoin, Ethereum, Cosmos)
- secp256k1 sign/verify

### Test 5: Cross-Language Verification

1. Read binary files generated by Node.js reference implementation
2. Decrypt using same chain keys
3. Verify decrypted bytes match unencrypted reference
4. Confirm FlatBuffer file identifier (`"MONS"`) is intact

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Test Runner (any language)           │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │   Test 1    │  │   Test 2    │  │   Test 3    │     │
│  │   SHA-256   │  │ Transparent │  │ Cross-Lang  │     │
│  │             │  │ Encrypt     │  │   Verify    │     │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘     │
│         │                │                │             │
│         └────────────────┼────────────────┘             │
│                          │                              │
│                          ▼                              │
│         ┌────────────────────────────────┐             │
│         │     WASM Runtime Adapter       │             │
│         │  (wazero/wasmer/wasmtime/etc)  │             │
│         └────────────────┬───────────────┘             │
│                          │                              │
└──────────────────────────┼──────────────────────────────┘
                           │
                           ▼
            ┌──────────────────────────────┐
            │   flatc-encryption.wasm      │
            │   (Crypto++ compiled)        │
            │                              │
            │  • AES-256-CTR (encrypt)    │
            │  • SHA-256                   │
            │  • Ed25519 Sign/Verify      │
            │  • secp256k1 ECDH/ECDSA     │
            └──────────────────────────────┘
```

## Adding a New Language

1. Create a new directory under `runners/`
2. Implement WASM loading with your chosen runtime
3. Implement Emscripten `invoke_*` trampolines (call indirect function table)
4. Test SHA-256 and AES-256-CTR encrypt/decrypt
5. Verify against Node.js generated binaries

Key implementation details:
- All `invoke_*` functions must look up and call functions from the indirect table
- Exception handling stubs (`setThrew`, `__cxa_*`) can return dummy values
- WASI stubs for `random_get` and `clock_time_get` must be functional

## License

Apache 2.0 - Same as FlatBuffers
