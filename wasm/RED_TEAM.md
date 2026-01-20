# Security Red Team Assessment: FlatBuffers WASM Module

**Assessment Date**: January 2026
**Target**: `/wasm` directory - FlatBuffers WebAssembly module with cryptographic extensions
**Assessors**: Security Red Team (WASM, Cryptography, FlatBuffers expertise)

---

## Executive Summary

The `/wasm` directory contains a WebAssembly-based FlatBuffers compiler with integrated field-level encryption capabilities. This assessment identified **4 documented vulnerabilities** (VULN-001 through VULN-004), **multiple architectural concerns**, and **several attack surfaces** inherent to JavaScript/WASM cryptographic implementations.

| Severity | Count | Status |
|----------|-------|--------|
| CRITICAL | 1 | Mitigated (IV reuse) |
| HIGH | 2 | Partially mitigated |
| MEDIUM | 3 | Mitigated/Documented |
| LOW | 4 | Documented |
| INFO | 6 | Architectural limitations |

**Overall Risk**: **MEDIUM-HIGH** - Requires careful deployment patterns and operational security controls.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Critical Vulnerabilities](#2-critical-vulnerabilities)
3. [High-Severity Issues](#3-high-severity-issues)
4. [Medium-Severity Issues](#4-medium-severity-issues)
5. [Low-Severity Issues](#5-low-severity-issues)
6. [Architectural Concerns](#6-architectural-concerns)
7. [Attack Surface Analysis](#7-attack-surface-analysis)
8. [Cryptographic Assessment](#8-cryptographic-assessment)
9. [Memory Safety Analysis](#9-memory-safety-analysis)
10. [Recommendations](#10-recommendations)

---

## 1. Architecture Overview

### Component Map

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Layer                        │
└─────────────────────────────┬───────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────┐
│  index.mjs (92 lines)       │  Public API exports           │
├─────────────────────────────┼───────────────────────────────┤
│  runner.mjs (911 lines)     │  FlatBuffers compiler wrapper │
├─────────────────────────────┼───────────────────────────────┤
│  encryption.mjs (2,960 ln)  │  Field-level encryption       │
├─────────────────────────────┼───────────────────────────────┤
│  streaming-dispatcher.mjs   │  Zero-copy message routing    │
├─────────────────────────────┼───────────────────────────────┤
│  aligned-codegen.mjs        │  Struct layout generation     │
└─────────────────────────────┬───────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────┐
│  flatc-wasm.wasm (2.7 MB)   │  FlatBuffers compiler         │
├─────────────────────────────┼───────────────────────────────┤
│  flatc-encryption.wasm      │  Crypto++ WASM bindings       │
└─────────────────────────────┴───────────────────────────────┘
```

### Trust Boundaries

1. **External Input → Schema Validation** (runner.mjs)
2. **Plaintext → Cryptographic Module** (encryption.mjs)
3. **JavaScript → WASM Linear Memory** (all modules)
4. **Application → Key Management** (caller responsibility)

---

## 2. Critical Vulnerabilities

### VULN-001: AES-CTR IV Reuse [CRITICAL]

**Location**: [encryption.mjs:60-156](src/encryption.mjs#L60-L156)

**Description**: AES-CTR mode uses a keystream generated from Key + IV. Reusing the same IV with the same key produces an identical keystream. When two plaintexts are XORed with the same keystream, an attacker can recover `P1 ⊕ P2` by computing `C1 ⊕ C2`.

**Impact**: Complete loss of confidentiality for all data encrypted with reused IV.

**Attack Scenario**:
```
C1 = P1 ⊕ KeyStream(K, IV)
C2 = P2 ⊕ KeyStream(K, IV)  // Same IV!
C1 ⊕ C2 = P1 ⊕ P2           // Attacker learns relationship
```

**Mitigation Status**: ✅ Implemented

The module tracks used IVs per key and throws `CryptoError.IV_REUSE`:

```javascript
const usedIVsByKey = new Map(); // keyId -> Set<ivHex>
const MAX_IVS_PER_KEY = 1_000_000;

function checkAndRecordIV(key, iv, trackUsage = true) {
  const keyId = getKeyId(key);
  const ivHex = bytesToHex(iv);

  if (usedIVs.has(ivHex)) {
    throw new CryptoError(CryptoErrorCode.IV_REUSE,
      'IV has already been used with this key');
  }
  // ...
}
```

**Residual Risks**:
- IV tracking is in-process memory only (lost on restart)
- Key ID uses FNV-1a hash (collision possible, though unlikely)
- No cross-process IV coordination
- Decryption does not verify IV uniqueness (by design)

**Recommendation**: Use auto-generated IVs exclusively; implement persistent IV tracking for high-security deployments.

---

## 3. High-Severity Issues

### VULN-002: Schema Input Size & Complexity Attacks [HIGH]

**Location**: [runner.mjs:12-181](src/runner.mjs#L12-L181)

**Description**: Malicious schema inputs could cause denial of service through:
- Memory exhaustion (large files)
- File count bombing (many small files)
- Stack overflow (deeply nested includes)
- Infinite loops (circular includes)

**Mitigation Status**: ✅ Implemented

| Limit | Value | Purpose |
|-------|-------|---------|
| `MAX_SCHEMA_TOTAL_SIZE` | 10 MB | Memory exhaustion |
| `MAX_SCHEMA_FILES` | 1,000 | File count bombing |
| `MAX_INCLUDE_DEPTH` | 50 | Recursive include attacks |
| `MAX_BINARY_SIZE` | 100 MB | Binary processing limit |

**Residual Risks**:
- Limits are process-wide (no per-user/session isolation)
- No rate limiting on compilation attempts
- Include detection uses regex (potential bypass with encoding tricks)
- Pathological schema content could still cause slow parsing

**Proof of Concept** (blocked):
```javascript
// This will throw due to size limit
const hugeSchema = {
  entry: "/attack.fbs",
  files: { "/attack.fbs": "x".repeat(11 * 1024 * 1024) }
};
```

---

### VULN-003: Malformed FlatBuffer Binary Processing [HIGH]

**Location**: [runner.mjs:187-259](src/runner.mjs#L187-L259)

**Description**: FlatBuffers uses vtable-based indirection. Malformed binaries with invalid offsets could cause:
- Out-of-bounds memory reads
- Integer overflow in offset calculations
- Vtable pointer following to invalid locations
- Buffer over-read during field access

**Mitigation Status**: ⚠️ Partially Implemented

Current validation checks:
- ✅ Size bounds (min 4 bytes, max 100 MB)
- ✅ Root offset within buffer
- ✅ First-level vtable position validation
- ❌ No recursive vtable traversal
- ❌ No field offset validation
- ❌ No string pointer validation
- ❌ No vector bounds checking

**Validation Code**:
```javascript
function validateFlatBufferBinary(buffer) {
  const rootOffset = view.getUint32(0, true);
  if (rootOffset >= buffer.length) {
    throw new Error('Root offset points outside buffer');
  }

  const vtableOffsetSigned = view.getInt32(rootOffset, true);
  const vtablePos = rootOffset - vtableOffsetSigned;
  if (vtablePos < 0 || vtablePos >= buffer.length) {
    throw new Error('Invalid vtable position');
  }
}
```

**Attack Vector**: Crafted FlatBuffer with valid root but invalid nested offsets could crash WASM module.

---

### Unauthenticated Encryption Mode Available [HIGH]

**Location**: [encryption.mjs:913-967](src/encryption.mjs#L913-L967)

**Description**: The `encryptBytes()` and `encryptBuffer()` functions use AES-CTR without authentication. This is vulnerable to bit-flipping attacks where an attacker can modify ciphertext and predictably change the plaintext.

**Attack Scenario**:
```
Original:  {"admin": false}
Encrypted: [ciphertext bytes]
Modified:  [flip specific bit in ciphertext]
Decrypted: {"admin": true }  // Attacker changed value!
```

**Mitigation**: Use `encryptAuthenticated()` instead (Encrypt-then-MAC with HMAC-SHA256).

**Risk**: The unauthenticated functions remain exported for backwards compatibility. Developers may inadvertently use the unsafe variant.

---

## 4. Medium-Severity Issues

### VULN-004: In-Place Data Mutation [MEDIUM]

**Location**: [encryption.mjs:913-967](src/encryption.mjs#L913-L967)

**Description**: Core encryption functions modify input arrays in-place:

```javascript
// DANGEROUS: Modifies caller's data!
export function encryptBytes(data, key, iv) {
  _encryptBytesInternal(data, key, iv, true);  // data is modified
}
```

**Problems**:
- Violates principle of least surprise
- Corrupts caller's data on partial failure
- Makes concurrent usage unsafe
- Prevents defensive copying patterns

**Mitigation Status**: ✅ Alternatives provided

```javascript
// SAFE: Returns new buffer
export function encryptBytesCopy(data, key, iv = null) {
  const ciphertext = new Uint8Array(data);  // Copy first
  _encryptBytesInternal(ciphertext, key, actualIV, true);
  return { ciphertext, iv: actualIV };
}
```

**Recommendation**: Deprecate in-place functions; make copy variants the default.

---

### Private Key Exposure in Memory [MEDIUM]

**Location**: [encryption.mjs:16-48](src/encryption.mjs#L16-L48) (documented limitation)

**Description**: JavaScript provides no secure memory protection. Private keys and plaintext remain in memory until garbage collected. This creates exposure windows for:
- Memory dumps
- Browser extensions
- Debugging tools
- Process inspection

**Mitigation Attempts**:
```javascript
export function zeroBytes(buffer) {
  if (buffer instanceof Uint8Array) {
    buffer.fill(0);
  }
}
```

**Limitation**: JavaScript engines may optimize away zeroing, retain copies during GC, or keep data in JIT-compiled code caches.

---

### Streaming Dispatcher Desynchronization [MEDIUM]

**Location**: [streaming-dispatcher.h:132-161](src/streaming-dispatcher.h#L132-L161)

**Description**: The streaming message parser attempts to resync on malformed messages by skipping one byte:

```cpp
if (msg_size < FILE_ID_LENGTH) {
  offset++;  // Skip one byte and try to resync
  continue;
}
```

**Attack Vector**: An attacker who can inject malformed messages into a stream could cause message boundary desynchronization, leading to:
- Message corruption
- Dropped messages
- Processing of garbage data as valid messages

---

## 5. Low-Severity Issues

### Key ID Collision Risk [LOW]

**Location**: [encryption.mjs:~80](src/encryption.mjs#L80)

**Description**: Key identification uses FNV-1a hash (non-cryptographic). While collision probability is low for typical usage, an attacker with key generation control could potentially create colliding key IDs to confuse IV tracking.

---

### No Timestamp Validation in Headers [LOW]

**Location**: [schemas/encryption_header.fbs](schemas/encryption_header.fbs)

**Description**: The `EncryptionHeader` includes a `timestamp` field but no enforcement of freshness. Old messages can be replayed without detection.

---

### Path Traversal Vectors [LOW]

**Location**: [runner.mjs](src/runner.mjs)

**Description**: Schema file paths are validated but edge cases may exist:
- URL-encoded path components (`%2e%2e%2f` = `../`)
- Unicode normalization attacks
- Null byte injection (validated, but implementation-dependent)

---

### Missing Rate Limiting [LOW]

**Description**: No rate limiting on:
- Compilation attempts
- Cryptographic operations
- Key derivation functions

High-volume requests could exhaust resources or enable timing attacks.

---

## 6. Architectural Concerns

### 6.1 JavaScript/WASM Cryptographic Limitations

| Concern | Impact | Mitigation Possible |
|---------|--------|---------------------|
| No secure memory | Keys exposed in heap | Partial (zeroBytes) |
| Timing side-channels | Key extraction possible | None in WASM |
| Cache timing attacks | Information leakage | None |
| GC unpredictability | Secret retention | None |
| JIT code caching | Secret copies | None |

**Recommendation**: Do NOT use in multi-tenant environments with co-located untrusted code.

---

### 6.2 WASM Linear Memory Shared State

All cryptographic operations share the same WASM linear memory. No isolation between:
- Different keys
- Different operations
- Different "sessions"

**Risk**: Memory corruption in one operation affects all others.

---

### 6.3 FIPS Compliance Claims Invalid

**Location**: [openssl-fips/](openssl-fips/)

The OpenSSL FIPS provider is included but:
- FIPS 140-3 validation is **platform-specific**
- WebAssembly is **not a validated operational environment**
- FIPS compliance claims for WASM builds are **technically invalid**

---

### 6.4 No Schema Evolution Security

The aligned-codegen module generates fixed-layout structs without:
- Version negotiation
- Field deprecation handling
- Type migration paths

Adding fields requires careful binary compatibility management.

---

## 7. Attack Surface Analysis

### 7.1 Input Vectors

| Vector | Entry Point | Validation | Risk |
|--------|-------------|------------|------|
| Schema files | `runner.compileSchema()` | Size, depth, circular | Medium |
| Binary data | `runner.processBinary()` | Root offset, vtable | High |
| Encryption key | `encryption.*()` | Length only | Low |
| IV | `encryptBytes()` | Uniqueness tracking | Critical→Low |
| WASM module | `loadEncryptionWasm()` | None (trusted) | High if compromised |

### 7.2 Output Vectors

| Vector | Risk | Mitigation |
|--------|------|------------|
| Generated code | Code injection | Template escaping |
| Error messages | Information disclosure | Generic errors |
| Timing information | Side-channel | None |

### 7.3 State Manipulation

| State | Manipulation Risk |
|-------|-------------------|
| IV tracking Map | Memory exhaustion (1M IVs/key) |
| WASM memory | Corruption via malformed input |
| Key material | No protection after generation |

---

## 8. Cryptographic Assessment

### 8.1 Algorithm Selection

| Algorithm | Purpose | Assessment |
|-----------|---------|------------|
| AES-256-CTR | Symmetric encryption | ✅ Strong, but requires unique IV |
| X25519 | Key exchange | ✅ Modern, secure |
| Ed25519 | Signatures | ✅ Modern, secure |
| secp256k1 | Key exchange/signing | ✅ Well-tested (Bitcoin/Ethereum) |
| P-256 | Key exchange/signing | ⚠️ Older NIST curve, adequate |
| HKDF-SHA256 | Key derivation | ✅ Standard, secure |
| HMAC-SHA256 | Authentication | ✅ Includes constant-time verify |

### 8.2 Cryptographic Weaknesses

1. **CTR mode without authentication by default** - Bit-flipping vulnerable
2. **No forward secrecy option** - Static key compromise exposes all past messages
3. **No key commitment** - Multi-key attacks possible with crafted ciphertext
4. **No domain separation by default** - Same keys usable across contexts

### 8.3 Random Number Generation

Relies on `crypto.getRandomValues()` (browser) or Node.js crypto module. If unavailable or weak, all security guarantees fail.

**Check**: Module throws if secure random unavailable.

---

## 9. Memory Safety Analysis

### 9.1 JavaScript Layer

| Issue | Code Location | Status |
|-------|---------------|--------|
| TypedArray bounds | All encryption ops | ✅ Automatic |
| BigInt handling | Int64 operations | ✅ Safe |
| String encoding | Schema processing | ⚠️ TextEncoder used |

### 9.2 WASM Layer

| Issue | Code Location | Status |
|-------|---------------|--------|
| Buffer overflows | Crypto++ code | ⚠️ Depends on library |
| Integer overflows | Size calculations | ⚠️ No explicit checks |
| Use-after-free | Memory allocation | ⚠️ Manual management |
| Stack overflow | Recursive parsing | ❓ Unknown limit |

### 9.3 Interop Layer

| Issue | Risk |
|-------|------|
| Pointer validity | WASM functions trust JS-provided pointers |
| Size mismatches | JS length vs WASM expectation |
| Alignment | DataView handles, but perf impact |

---

## 10. Recommendations

### Immediate Actions (Priority 1)

1. **Deprecate unauthenticated encryption exports**
   ```javascript
   // Mark as deprecated in JSDoc and console.warn on use
   /** @deprecated Use encryptAuthenticated() instead */
   export function encryptBytes(data, key, iv) {
     console.warn('encryptBytes is deprecated; use encryptAuthenticated');
     // ...
   }
   ```

2. **Add rate limiting for cryptographic operations**
   - Implement token bucket or sliding window
   - Configurable limits per operation type

3. **Implement persistent IV tracking option**
   - Allow passing external IV store
   - Support for distributed systems (Redis, etc.)

### Short-Term Actions (Priority 2)

4. **Enhance FlatBuffer validation**
   - Recursive vtable chain validation
   - Field offset bounds checking
   - String pointer validation

5. **Add message authentication to streaming dispatcher**
   - Per-message HMAC
   - Sequence numbers for replay detection

6. **Implement key destruction verification**
   - Best-effort memory clearing
   - Audit log of key lifecycle

### Long-Term Actions (Priority 3)

7. **Consider WebCrypto API for browser deployments**
   - Hardware-backed where available
   - Reduces JavaScript key exposure

8. **Add fuzzing infrastructure**
   - Schema parsing fuzzer
   - FlatBuffer binary fuzzer
   - Encryption input fuzzer

9. **Security audit of Crypto++ WASM bindings**
   - Memory safety review
   - Side-channel analysis

---

## Appendix A: File Inventory

### Critical Security Files

| File | Lines | Purpose |
|------|-------|---------|
| [src/encryption.mjs](src/encryption.mjs) | 2,960 | All cryptographic operations |
| [src/runner.mjs](src/runner.mjs) | 911 | Schema validation, binary processing |
| [src/streaming-dispatcher.cpp](src/streaming-dispatcher.cpp) | ~200 | Message parsing |
| [src/streaming-dispatcher.h](src/streaming-dispatcher.h) | 310 | Ring buffer implementation |

### Test Coverage

| File | Coverage Area |
|------|---------------|
| [test/test_encryption.mjs](test/test_encryption.mjs) | Crypto operations, IV tracking |
| [test/test_runner.mjs](test/test_runner.mjs) | Schema validation |
| [test/test_streaming_dispatcher.mjs](test/test_streaming_dispatcher.mjs) | Message routing |

---

## Appendix B: Security Checklist

- [x] IV reuse prevention (VULN-001)
- [x] Schema size limits (VULN-002)
- [x] Basic FlatBuffer validation (VULN-003)
- [x] Non-destructive API variants (VULN-004)
- [x] Path traversal validation
- [x] Circular include detection
- [x] Constant-time MAC verification
- [ ] Rate limiting
- [ ] Persistent IV tracking
- [ ] Deep FlatBuffer validation
- [ ] Message authentication in streaming
- [ ] Forward secrecy option
- [ ] Key commitment scheme
- [ ] Fuzzing test suite

---

## Appendix C: Threat Model Summary

### Trusted

- WASM module integrity (assumed loaded from trusted source)
- `crypto.getRandomValues()` entropy quality
- Emscripten/Crypto++ compilation correctness

### Untrusted

- All schema input
- All binary FlatBuffer input
- All user-provided keys (validated for length only)
- Network transport (encryption required)

### Out of Scope

- Physical side-channels
- OS/browser vulnerabilities
- Hardware backdoors
- Social engineering

---

*End of Red Team Assessment*
