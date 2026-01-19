# OpenSSL FIPS Provider - WebAssembly Build

This directory contains scripts and configuration to build OpenSSL 3.x with the FIPS Provider from source, compiled to WebAssembly using Emscripten.

## FIPS 140-3 Compliance Note

OpenSSL 3.0.9 and 3.1.2 have FIPS 140-3 validation (Certificate #4282). However, FIPS validation is **platform-specific**. Compiling to WebAssembly creates a new operational environment that is **not covered** by the existing NIST certificate.

For true FIPS compliance in production:
- The operational environment must match the validated configuration
- WebAssembly is not currently a NIST-validated operational environment
- This build provides FIPS-**compatible** algorithms, not FIPS-**validated** execution

## Prerequisites

- [Emscripten SDK](https://emscripten.org/docs/getting_started/downloads.html) (3.1.50+)
- Perl (for OpenSSL configure)
- Git

## Build Instructions

```bash
# Activate Emscripten
source /path/to/emsdk/emsdk_env.sh

# Run the build script
./build.sh
```

## Output

After building:
- `dist/libcrypto.a` - Static crypto library
- `dist/libssl.a` - Static SSL library (if needed)
- `dist/fips.wasm` - FIPS provider module
- `dist/openssl-fips.mjs` - JavaScript wrapper

## Algorithm Support

The FIPS Provider includes:
- **AES**: 128, 192, 256 bit keys (ECB, CBC, CTR, GCM, CCM, XTS, WRAP)
- **SHA-2**: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256
- **SHA-3**: SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256
- **HMAC**: All SHA-2 and SHA-3 variants
- **HKDF**: Key derivation (with HMAC)
- **ECDH**: P-256, P-384, P-521 (NIST curves)
- **ECDSA**: P-256, P-384, P-521
- **RSA**: 2048, 3072, 4096 bit keys
- **DRBG**: CTR_DRBG, HASH_DRBG, HMAC_DRBG

**Note**: X25519/Ed25519 are **NOT** included in FIPS mode (not NIST-approved).

## Migration from libsodium

| libsodium Function | OpenSSL FIPS Equivalent |
|-------------------|------------------------|
| `crypto_secretbox` | AES-256-GCM |
| `crypto_box` | ECDH (P-256) + AES-256-GCM |
| `crypto_sign` | ECDSA (P-256/P-384) |
| `crypto_kdf` | HKDF-SHA256 |
| `crypto_hash` | SHA-256/SHA-384/SHA-512 |
| `crypto_scalarmult_curve25519` | ECDH (P-256) - **not direct equivalent** |

## References

- [OpenSSL FIPS 140-3 Announcement](https://openssl-library.org/post/2025-03-11-fips-140-3/)
- [NIST Certificate #4282](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4282)
- [OpenSSL FIPS Provider Documentation](https://docs.openssl.org/3.0/man7/OSSL_PROVIDER-FIPS/)
- [FIPS 140-3 Implementation Guidance](https://csrc.nist.gov/projects/cryptographic-module-validation-program/fips-140-3-standards)
