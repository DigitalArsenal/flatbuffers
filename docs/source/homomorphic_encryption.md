# Homomorphic Encryption

FlatBuffers supports homomorphic encryption (HE) on individual fields, allowing computation on encrypted data without decryption. This is built on Microsoft SEAL using BFV/BGV lattice-based schemes.

## Overview

Homomorphic encryption lets a server perform arithmetic on ciphertexts. The result, when decrypted by the client, matches the result of performing the same arithmetic on the plaintexts. The server never sees the plaintext values.

```
Client encrypts:  42 → [ciphertext_a]
Client encrypts:  10 → [ciphertext_b]

Server computes:  [ciphertext_a] + [ciphertext_b] → [ciphertext_c]

Client decrypts:  [ciphertext_c] → 52
```

### Two-Context Security Model

| Context | Has Secret Key | Can Encrypt | Can Decrypt | Can Compute |
|---------|---------------|-------------|-------------|-------------|
| Client  | Yes           | Yes         | Yes         | Yes         |
| Server  | No            | Yes (public key) | No    | Yes         |

## Schema Syntax

Mark fields for homomorphic encryption with the `he_encrypted` attribute:

```flatbuffers
attribute "he_encrypted";

table SalaryRecord {
  employee_id: string;                      // Public
  salary: int64 (he_encrypted);             // HE-encrypted
  bonus: int64 (he_encrypted);              // HE-encrypted
  department: string;                       // Public
}
```

### Supported Types

The `he_encrypted` attribute supports integer and floating-point scalar types:

| Type | Supported | Notes |
|------|-----------|-------|
| `int8` / `uint8` | Yes | Encoded as 64-bit integer internally |
| `int16` / `uint16` | Yes | Encoded as 64-bit integer internally |
| `int32` / `uint32` | Yes | Encoded as 64-bit integer internally |
| `int64` / `uint64` | Yes | Native encoding |
| `float` | Yes | Fixed-point encoding (configurable scale) |
| `double` | Yes | Fixed-point encoding (configurable scale) |
| `string` | No | Use field-level encryption instead |
| `[ubyte]` | No | Use field-level encryption instead |
| Structs / Tables | No | Encrypt individual scalar fields |

### Validation Rules

- `he_encrypted` can only be applied to scalar fields (integers and floats)
- Cannot be combined with `deprecated`
- Cannot be applied to key fields
- Cannot be used on struct fields (structs are inline, not offset-based)

## Building with SEAL

SEAL support is **enabled by default**. CMake will fetch Microsoft SEAL v4.1.1 automatically:

```bash
# Default build (SEAL + OpenSSL enabled)
cmake -B build -S .
cmake --build build

# Explicitly disable SEAL if not needed
cmake -B build -S . -DFLATBUFFERS_USE_SEAL=OFF
```

SEAL requires C++17. When `FLATBUFFERS_USE_SEAL=ON`, the build system automatically upgrades the C++ standard.

### CMake Options

| Option | Default | Description |
|--------|---------|-------------|
| `FLATBUFFERS_USE_SEAL` | `ON` | Enable Microsoft SEAL for homomorphic encryption |
| `FLATBUFFERS_USE_OPENSSL` | `ON` | Enable OpenSSL for FIPS-compliant field encryption |
| `FLATBUFFERS_USE_CRYPTOPP` | `OFF` | Enable Crypto++ (alternative to OpenSSL) |

## C++ API

### Headers

```cpp
#include "flatbuffers/he_encryption.h"   // Core HEContext class
#include "flatbuffers/he_operations.h"   // Free function wrappers
```

### Client Setup (Key Generation)

```cpp
using namespace flatbuffers::he;

// Create client with full key pair
auto client = HEContext::CreateClient(
    4096,             // poly_modulus_degree (4096=128-bit security)
    HEScheme::BFV    // BFV scheme for integer arithmetic
);

// Export keys for the server
auto public_key = client.GetPublicKey();
auto relin_keys = client.GetRelinKeys();  // Needed for multiplication
```

### Server Setup (Public Key Only)

```cpp
// Server creates context from client's public key
auto server = HEContext::CreateServer(public_key.data(), public_key.size());
server.SetRelinKeys(relin_keys.data(), relin_keys.size());
```

### Encrypt / Decrypt

```cpp
// Client encrypts values
auto ct_salary = client.EncryptInt64(85000);
auto ct_bonus  = client.EncryptInt64(5000);

// Client decrypts results
int64_t total = client.DecryptInt64(ct_result.data(), ct_result.size());
```

### Homomorphic Operations

```cpp
// Server computes on encrypted data (never sees plaintext)
auto ct_total = server.Add(ct_salary, ct_bonus);           // 85000 + 5000
auto ct_doubled = server.MultiplyPlain(ct_salary, 2);      // 85000 * 2
auto ct_with_raise = server.AddPlain(ct_salary, 10000);    // 85000 + 10000

// Using free functions from he_operations.h
auto ct_sum = Add(ct_salary, ct_bonus, server);
auto ct_diff = Sub(ct_salary, ct_bonus, server);
auto ct_prod = Multiply(ct_salary, ct_bonus, server);  // Requires relin keys
auto ct_neg = Negate(ct_salary, server);
```

### Available Operations

| Operation | Method | Free Function | Requires Relin Keys |
|-----------|--------|---------------|---------------------|
| ct + ct | `Add(ct1, ct2)` | `Add(ct1, ct2, ctx)` | No |
| ct - ct | `Sub(ct1, ct2)` | `Sub(ct1, ct2, ctx)` | No |
| ct * ct | `Multiply(ct1, ct2)` | `Multiply(ct1, ct2, ctx)` | Yes |
| -ct | `Negate(ct)` | `Negate(ct, ctx)` | No |
| ct + plain | `AddPlain(ct, n)` | `AddPlain(ct, n, ctx)` | No |
| ct - plain | `SubPlain(ct, n)` | `SubPlain(ct, n, ctx)` | No |
| ct * plain | `MultiplyPlain(ct, n)` | `MultiplyPlain(ct, n, ctx)` | No |

### Key Serialization

```cpp
// Serialize entire context for storage/transport
auto serialized = client.Serialize();

// Deserialize later
auto restored = HEContext::Deserialize(serialized.data(), serialized.size());
```

### Error Handling

```cpp
auto result = server.SetRelinKeys(rk_data, rk_size);
if (!result.ok()) {
    std::cerr << "Error: " << result.message << std::endl;
}
```

## Security Parameters

| Poly Modulus Degree | Security Level | Ciphertext Size | Performance |
|---------------------|---------------|-----------------|-------------|
| 4096 | ~128-bit | ~2 KB | Fast |
| 8192 | ~192-bit | ~4 KB | Moderate |
| 16384 | ~256-bit | ~8 KB | Slow |

The default is 4096 (128-bit security), which is suitable for most applications.

### Float Precision

Floating-point values use fixed-point encoding with a configurable scale factor. The default scale of 2^20 provides approximately 6 decimal digits of precision:

```cpp
auto ct = client.EncryptDouble(3.14159, 1 << 20);  // ~6 digits
double val = client.DecryptDouble(ct.data(), ct.size(), 1 << 20);
// val ≈ 3.14159
```

## Ciphertext Binary Format

Serialized ciphertexts include a 12-byte header:

```
┌──────────────────────────────────────────┐
│  length (4 bytes)     Total size         │
│  scheme (1 byte)      BFV=0, BGV=1       │
│  reserved (1 byte)                        │
│  poly_degree_log2 (2) log2(N)            │
│  coeff_count (4)      Polynomial coeffs  │
├──────────────────────────────────────────┤
│  SEAL ciphertext data (N bytes)          │
└──────────────────────────────────────────┘
```

## Comparison: Field Encryption vs. Homomorphic Encryption

| Feature | Field Encryption (`encrypted`) | Homomorphic (`he_encrypted`) |
|---------|-------------------------------|------------------------------|
| Purpose | Protect data at rest | Compute on encrypted data |
| Key type | Symmetric (AES-256) | Asymmetric (public/secret) |
| Computation | Must decrypt first | Arithmetic without decryption |
| Ciphertext size | Same as plaintext | ~2-8 KB per value |
| Supported types | All field types | Scalar integers and floats |
| Performance | Near-zero overhead | Significant overhead |
| Use case | Storage encryption | Privacy-preserving computation |

Use `encrypted` for simple data protection. Use `he_encrypted` when a server must compute on data it cannot see.
