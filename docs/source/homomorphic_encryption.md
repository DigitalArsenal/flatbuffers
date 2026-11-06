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
    8192,             // poly_modulus_degree: 8192 slots, 128-bit security
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

### Batching

```cpp
// One ciphertext holds client.SlotCount() values (8192 at n = 8192).
std::vector<int64_t> values = {1, -2, 3};
auto ct = client.EncryptInt64Vector(values);           // |v| < 2^64
auto doubled = server.MultiplyPlain(ct.data(), ct.size(), 2);  // every slot
auto out = client.DecryptInt64Vector(doubled.data(), doubled.size());
// out[0..2] = 2, -4, 6; the other slots are 0

// Integers up to 2^178 - 1 in magnitude
WideInt big;
WideInt::Parse("-383123885216472214589586756787577295904684780545900543", &big);
auto wide = client.EncryptWideVector({big});           // bound 2^178
WideInt back = client.DecryptWideVector(wide.data(), wide.size())[0];

// A value or result past the range is refused, never wrapped
auto refused = client.EncryptInt64Vector({1LL << 40}, 32);  // empty
// client.LastError().error == HEError::kOutOfRange
```

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

| Poly Modulus Degree | Coefficient Modulus Chain | Security Level | Slots | Ciphertext Size |
|---------------------|---------------------------|----------------|-------|-----------------|
| 8192 (default) | 5 primes: 43, 43, 44, 44, 44 bits (218 bits) | 128-bit | 8192 | 1,573,227 bytes (three moduli) |
| 16384 | 9 primes: 48, 48, 48, 49, 49, 49, 49, 49, 49 bits (438 bits) | 128-bit | 16384 | 6,291,819 bytes (three moduli) |

Other degrees give an invalid context. The chains are SEAL 4.1.1
`CoeffModulus::BFVDefault(n, sec_level_type::tc128)`: the
HomomorphicEncryption.org security standard table for 128-bit classical
security with a ternary secret. The last prime of each chain is the
key-switching prime; the others carry ciphertexts. `GetCoeffModulusBits()`
returns a context's chain.

### Noise Budget by Multiplicative Depth

Remaining noise budget in bits, measured 2026-11-06 by
`tests/he_encryption/he-batching-range.e2e.mjs` on the batching above (every
slot filled; a squaring chain of 11-bit slots, bound 176 at depth 4, and a
chain of fresh 35-bit factors, bound 175 at depth 4). A ciphertext whose
budget reaches 0 is refused at decryption (`kNoiseBudgetExhausted`); every
level with budget left decrypts exactly.

| n | Fresh | After 1 multiply | 2 | 3 | 4 |
|---|---|---|---|---|---|
| 8192, squaring | 106 | 34 | 0 (refused) | refused | refused |
| 8192, fresh factors | 106 | 34 | 0 (refused) | refused | refused |
| 16384, squaring | 320 | 247 | 173 | 99 | 25 |
| 16384, fresh factors | 320 | 248 | 175 | 102 | 29 |

n = 8192 carries one multiplication; depths 2 to 4 need n = 16384. The
default stays 8192: it serves depth-1 work at a quarter of the ciphertext
size and a fifth of the multiply time (24 ms against 110 ms per three-modulus
ciphertext on the measuring machine); a caller needing depth 2 to 4 passes
16384 to `CreateClient`. Encryption noise is random, so a figure moves by
about one bit between runs; the E2E holds every level to a registered minimum
(8192: fresh 100, 30 after one multiply, refused after two; 16384: fresh 310,
then 240, 165, 90, 18).

### Float Precision

Floating-point values use fixed-point encoding: the slot holds round(x · scale),
with a power-of-two scale (default 2^16). The round trip returns exactly
round(x · scale) / scale for every x whose scaled integer is inside the bound:

```cpp
auto ct = client.EncryptDouble(3.14159, 1 << 20);
double val = client.DecryptDouble(ct.data(), ct.size(), 1 << 20);
// val == round(3.14159 * 2^20) / 2^20
```

## Batching and Range (registered 2026-11-06)

This section is the contract the implementation and its test
(`tests/he_encryption/he-batching-range.e2e.mjs`) are held to.

### Parameters

| Item | Value |
| --- | --- |
| Scheme | BFV or BGV |
| Poly modulus degree n | 8192 (default) or 16384; any other degree gives an invalid context |
| Coefficient modulus | SEAL `CoeffModulus::BFVDefault(n, tc128)`, 128-bit security: 5 primes of 43, 43, 44, 44, 44 bits (218) at 8192; 9 primes of 48, 48, 48, 49, 49, 49, 49, 49, 49 bits (438) at 16384 |
| Plaintext moduli | three 60-bit batching primes, SEAL `PlainModulus::Batching(n, {60, 60, 60})` |
| Primes at n = 8192 | t1 = 1152921504606683137, t2 = 1152921504606748673, t3 = 1152921504606830593 |
| T = t1 t2 t3 at n = 8192 | 1532495540865518635130821056977027158796330141975560193 (2^179.9999999999997) |
| Primes at n = 16384 | t1 = 1152921504606584833, t2 = 1152921504606683137, t3 = 1152921504606748673 |
| T = t1 t2 t3 at n = 16384 | 1532495540865191964058577030327937992314109603578642433 (2^179.9999999999993) |
| Slots per ciphertext | n |

One value is held as one SEAL ciphertext per prime; the value is the CRT
combination of the three residues, decoded to the centered interval
(-(T-1)/2, (T-1)/2]. At n = 8192, (T-1)/2 =
766247770432759317565410528488513579398165070987780096; at n = 16384,
766247770432595982029288515163968996157054801789321216.

### Range

Every slot holds a signed integer v with |v| <= 2^178 - 1
(2^178 = 383123885216472214589586756787577295904684780545900544).
2^178 <= (T-1)/2, so every value in range decodes exactly. A context whose T
is below 2^179 + 1 is refused at creation.

The previous single 20-bit plaintext modulus held about +/-524,288 and wrapped
any larger value or result silently. That behavior is removed.

### Slot layout

- Slot i is index i of SEAL's `BatchEncoder` matrix: row i / (n/2), column
  i mod (n/2).
- A vector of k <= n values fills slots 0 to k-1; the other slots hold 0.
- A scalar is a vector of one value (slot 0).
- Slot-wise operations: `Add`, `Sub`, `Multiply`, `Negate`. A scalar plain
  operand (`AddPlain`, `SubPlain`, `MultiplyPlain`) applies to every slot.

### Bound tracking

Every ciphertext carries a public bound b in its header: every slot satisfies
|v| < 2^b, with b <= 178.

| Source | b |
| --- | --- |
| `EncryptInt8/16/32/64`, `EncryptUInt8/16/32/64` | 8, 16, 32, 64 |
| integer vectors | declared by the caller (default 64) |
| wide integers (192-bit `WideInt`) | declared by the caller (default 178) |
| fixed point (`EncryptDouble`, `EncryptFloat`, vectors) | declared by the caller (default 64), applied to the scaled integer |
| `Add`, `Sub` | max(b1, b2) + 1 |
| `Negate` | b |
| `Multiply` | b1 + b2 |
| `AddPlain`, `SubPlain` with p | max(b, bitlen(abs(p))) + 1 |
| `MultiplyPlain` with p | b + bitlen(abs(p)) |

### Refusal rule

Nothing wraps. A refusal happens before any encryption or homomorphic
operation runs. `Encrypt*` and the operations return an empty result and
record the code in `LastError()`; decryption throws `HEException`, whose
`code()` is the code. (Amended 2026-11-06 with the implementation: the
registration first said every refusal throws. Codes and cases are unchanged.)

| Code | When |
| --- | --- |
| `kOutOfRange` | an input with abs(v) >= 2^b; a declared b above 178; an operation whose result bound exceeds 178; a non-finite fixed-point input; at decryption, a slot outside the requested type or outside the ciphertext's bound |
| `kTooManyValues` | a vector longer than n |
| `kInvalidScale` | a fixed-point scale that is not a power of two |
| `kNoiseBudgetExhausted` | a ciphertext whose noise budget is 0 at decryption |

The WASI interface returns a null result and reports the same code through
`wasi_he_last_error()`.

### Fixed point

A double x with power-of-two scale s encodes as the integer k = round(x s),
held exactly in the slot; decryption returns k / s. For every x with
abs(k) < 2^b the round trip returns exactly round(x s) / s.

### Ciphertext format

A 12-byte header (`length`, `scheme`, `bound_bits`, `poly_degree_log2`,
`coeff_count`) followed by three records, one per prime: a 4-byte little-endian
size and the SEAL ciphertext. Public keys, relinearization keys and secret
keys use the same three-record layout behind a one-byte record count.

### Known-answer set

- Integers: 0, +/-1, +/-(2^63 - 1), -2^63, 2^64 - 1 (unsigned), and the wide
  values +/-(2^k - 1) and +/-2^(k-1) for every k from 1 to 178.
- Slots: one vector of n distinct values including +/-(2^178 - 1), round trip
  slot by slot.
- Fixed point: scales 2^0, 2^16 and 2^40, values whose scaled integers reach
  +/-(2^178 - 2^125) (the largest doubles below 2^178), and fractions at each
  scale's quantum.
- Arithmetic: products of two 89-bit values (178-bit results) and sums at the
  bound, compared exactly with the plaintext results.
- Refusals: +/-2^178 (one step outside); a value above its declared bound;
  `Multiply` of two 100-bit-bound ciphertexts; `DecryptInt64` of 2^63;
  NaN and infinity in fixed point; scale 3; a vector of n + 1 values; poly
  modulus degrees 4096 and 32768 (refused); a value of bound 1 squared until
  its noise budget is 0, then decrypted (added 2026-11-06 with the restated
  acceptance).
- At n = 16384: the coefficient modulus chain and the three primes above; one
  vector of 16384 distinct values including +/-(2^178 - 1), round trip slot by
  slot; products of two 89-bit values and sums at the bound; the whole
  refusal set, code for code.
- Depth: the noise budget after 1 to 4 multiplications at both degrees
  ("Noise Budget by Multiplicative Depth"), every decryptable level exact.

## Ciphertext Binary Format

Serialized ciphertexts include a 12-byte header and one record per plaintext
modulus:

```
┌──────────────────────────────────────────┐
│  length (4 bytes)     Total size         │
│  scheme (1 byte)      BFV=0, BGV=1       │
│  bound_bits (1 byte)  |v| < 2^bound_bits │
│  poly_degree_log2 (2) log2(N)            │
│  coeff_count (4)      Polynomials        │
├──────────────────────────────────────────┤
│  3 x (size (4 bytes, little-endian)      │
│       + SEAL ciphertext)                 │
└──────────────────────────────────────────┘
```

## Comparison: Field Encryption vs. Homomorphic Encryption

| Feature | Field Encryption (`encrypted`) | Homomorphic (`he_encrypted`) |
|---------|-------------------------------|------------------------------|
| Purpose | Protect data at rest | Compute on encrypted data |
| Key type | Symmetric (AES-256) | Asymmetric (public/secret) |
| Computation | Must decrypt first | Arithmetic without decryption |
| Ciphertext size | Same as plaintext | about 1.5 MB per 8192 slots |
| Supported types | All field types | Scalar integers and floats |
| Performance | Near-zero overhead | Significant overhead |
| Use case | Storage encryption | Privacy-preserving computation |

Use `encrypted` for simple data protection. Use `he_encrypted` when a server must compute on data it cannot see.
