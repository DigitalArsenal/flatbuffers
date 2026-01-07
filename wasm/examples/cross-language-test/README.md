# Cross-Language Encryption Test Suite

This directory contains comprehensive test vectors and verification scripts to ensure encryption compatibility across all supported languages.

## Test Coverage

The test vectors cover:

1. **Simple Message** - Basic scalar (int) and string encryption
2. **Sensor Reading** - Complex types including:
   - Structs (Coordinates with lat/lon doubles)
   - Vectors of scalars (`[ubyte]`, `[float]`)
   - Encrypted strings
3. **All Scalar Types** - Every FlatBuffer scalar type encrypted:
   - bool, byte, ubyte
   - short, ushort
   - int, uint
   - long, ulong
   - float, double
4. **Edge Cases** - Empty strings, zero values
5. **Large Values** - Large strings (1000+ chars), MAX_INT32

## Running the Tests

### Generate Test Vectors (JavaScript/Node.js)

```bash
cd wasm
node examples/cross-language-test/generate_test_vectors.mjs > examples/cross-language-test/test_vectors.json
```

### Verify in Each Language

**Node.js:**
```bash
cd wasm
node examples/cross-language-test/verify_node.mjs
```

**Python:**
```bash
cd wasm/examples/cross-language-test
python3 verify_python.py
```

**Go:**
```bash
cd wasm/examples/cross-language-test
go run verify_go.go
```

**Rust:**
```bash
cd wasm/examples/cross-language-test
rustc verify_rust.rs -o verify_rust && ./verify_rust
```

**Deno:**
```bash
cd wasm/examples/cross-language-test
deno run --allow-read verify_deno.ts
```

## Test Vector Format

The `test_vectors.json` file contains:

```json
{
  "key_hex": "00112233...",      // 32-byte key in hex
  "flatc_version": "...",        // FlatBuffers compiler version
  "vectors": [
    {
      "name": "test_name",
      "schema": "...",           // FlatBuffers schema
      "root_type": "TypeName",
      "original_json": {...},    // Original data
      "original_hex": "...",     // Original binary in hex
      "encrypted_hex": "..."     // Encrypted binary in hex
    }
  ]
}
```

## Verification Process

Each language implementation:

1. Loads the test vectors
2. For each vector:
   - Takes the `encrypted_hex` binary
   - Decrypts using the language's encryption implementation
   - Compares result against `original_hex`
3. Reports pass/fail for each test case

## Adding New Languages

To add support for a new language:

1. Implement the encryption algorithm matching `encryption.mjs`
2. Create a verification script that:
   - Reads `test_vectors.json`
   - Decrypts each `encrypted_hex` using your implementation
   - Compares against `original_hex`
3. Add instructions to this README

## Algorithm Details

All implementations must use:
- **AES-256-CTR** for encryption
- **Custom HKDF-like key derivation** per field
- Field key info: `"flatbuffers-field"` + 2-byte field ID
- Field IV info: `"flatbuffers-iv"` + 2-byte field ID

See the JavaScript implementation in `src/encryption.mjs` as the reference.
