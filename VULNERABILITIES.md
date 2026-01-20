# Security Vulnerability Assessment: `/wasm` Module

**Assessment Date:** 2026-01-20
**Last Updated:** 2026-01-20
**Scope:** FlatBuffers WASM Module (`/wasm`)
**Auditor Focus:** Cryptographic Operations, Input Validation, Memory Safety
**Overall Risk Level:** ~~MODERATE-HIGH~~ **LOW-MODERATE** (after fixes)

---

## Executive Summary

The `/wasm` folder contains a WebAssembly implementation of the FlatBuffers compiler with comprehensive cryptographic capabilities including:

- FlatBuffers schema-to-code compilation (15+ languages)
- Binary/JSON serialization with virtual filesystem
- Field-level encryption using AES-256-CTR
- Key exchange (X25519, secp256k1, P-256)
- Digital signatures (Ed25519, ECDSA)
- HMAC-SHA256 authenticated encryption

This audit identified **4 critical/high severity** issues and **8 moderate** concerns.

### Remediation Status

| Issue                          | Severity | Status       |
| ------------------------------ | -------- | ------------ |
| VULN-001: IV Reuse             | CRITICAL | ✅ **FIXED** |
| VULN-002: Unbounded Includes   | HIGH     | ✅ **FIXED** |
| VULN-003: No Binary Validation | HIGH     | ✅ **FIXED** |
| VULN-004: In-Place Encryption  | HIGH     | ✅ **FIXED** |

---

## Table of Contents

1. [Critical Vulnerabilities](#critical-vulnerabilities)
2. [High Severity Issues](#high-severity-issues)
3. [Moderate Severity Issues](#moderate-severity-issues)
4. [Low Severity Issues](#low-severity-issues)
5. [Positive Security Findings](#positive-security-findings)
6. [Remediation Recommendations](#remediation-recommendations)
7. [Cryptographic Analysis](#cryptographic-analysis)
8. [Attack Surface Analysis](#attack-surface-analysis)

---

## Critical Vulnerabilities

### VULN-001: IV/Nonce Reuse Not Prevented (AES-256-CTR)

**Severity:** CRITICAL
**Location:** `wasm/src/encryption.mjs` - `encryptBytes()`, `encryptAuthenticated()`
**CVSS 3.1 Score:** 8.1 (High)

**Description:**

The AES-256-CTR encryption functions accept any IV without tracking or validating uniqueness. Reusing an IV with the same key completely breaks CTR mode security, allowing trivial plaintext recovery via XOR.

```javascript
// Current implementation - no IV tracking
export function encryptBytes(data, key, iv) {
  if (key.length !== KEY_SIZE) {
    throw new CryptoError(CryptoErrorCode.INVALID_KEY_SIZE, ...);
  }
  if (iv.length !== IV_SIZE) {
    throw new CryptoError(CryptoErrorCode.INVALID_IV_SIZE, ...);
  }
  // No check for IV uniqueness - caller can reuse IVs
  // ...
}
```

**Attack Scenario:**

1. Attacker observes two ciphertexts encrypted with same key+IV
2. XOR ciphertexts together: `C1 XOR C2 = P1 XOR P2`
3. Use frequency analysis or known plaintext to recover messages
4. Complete loss of confidentiality

**Impact:**

- Complete plaintext recovery when IV is reused
- Breaks all confidentiality guarantees of AES-CTR
- Particularly dangerous in multi-user or high-volume scenarios

**Proof of Concept:**

```javascript
const key = crypto.getRandomValues(new Uint8Array(32));
const iv = crypto.getRandomValues(new Uint8Array(16));

// DANGEROUS: Same IV reused
const plaintext1 = new TextEncoder().encode("SECRET MESSAGE 1");
const plaintext2 = new TextEncoder().encode("SECRET MESSAGE 2");

encryptBytes(plaintext1, key, iv);  // Returns ciphertext1
encryptBytes(plaintext2, key, iv);  // Returns ciphertext2

// Attack: XOR ciphertexts reveals XOR of plaintexts
// ciphertext1 XOR ciphertext2 = plaintext1 XOR plaintext2
```

**Remediation:** ✅ **IMPLEMENTED**

The fix adds IV tracking per key with automatic detection of reuse:

```javascript
// Now throws CryptoError with code IV_REUSE if IV is reused
encryptBytes(plaintext1, key, iv);  // OK - first use
encryptBytes(plaintext2, key, iv);  // THROWS - IV reuse detected!

// Recommended: Use encryptBytesCopy() with auto-generated IV
const { ciphertext, iv } = encryptBytesCopy(plaintext, key);  // Safe!

// New helper functions:
generateIV();           // Generate random 16-byte IV
clearIVTracking(key);   // Clear tracking when rotating keys
clearAllIVTracking();   // Clear all tracking (testing only)
```

**Changes Made:**

- Added `CryptoErrorCode.IV_REUSE` error code
- `encryptBytes()` now tracks and rejects duplicate IVs per key
- Added `encryptBytesCopy()` - non-destructive with auto-IV generation
- Added `decryptBytesCopy()` - non-destructive decryption
- Added `generateIV()`, `clearIVTracking()`, `clearAllIVTracking()` helpers
- Maximum 1M IVs tracked per key (memory bounded)

---

### VULN-002: Unbounded Schema Include Depth (DoS)

**Severity:** HIGH
**Location:** `wasm/src/runner.mjs` - `generateCode()`, `generateBinary()`
**CVSS 3.1 Score:** 7.5 (High)

**Description:**

FlatBuffers schemas support `include` directives. The WASM module does not limit include depth, allowing attackers to craft schemas with circular or deeply nested includes that exhaust memory or CPU.

```javascript
// Current implementation - no include depth limit
async generateCode(schemaInput, generator, options = {}) {
  const { entry, files, includes } = validateSchemaInput(schemaInput);
  // No limit on number of includes or nesting depth
  // ...
}
```

**Attack Scenario:**

```fbs
// malicious.fbs
include "malicious.fbs";  // Circular include

table Foo {
  bar: int;
}
```

Or:

```fbs
// deep1.fbs
include "deep2.fbs";
// deep2.fbs
include "deep3.fbs";
// ... continues for thousands of levels
```

**Impact:**

- Denial of Service via memory exhaustion
- CPU exhaustion during compilation
- Potential stack overflow in WASM

**Remediation:** ✅ **IMPLEMENTED**

The fix adds comprehensive schema validation with security limits:

```javascript
// Security constants now enforced:
const MAX_SCHEMA_TOTAL_SIZE = 10 * 1024 * 1024;  // 10 MB total
const MAX_SCHEMA_FILES = 1000;                    // Max files
const MAX_INCLUDE_DEPTH = 50;                     // Max nesting

// Circular includes now detected and rejected:
// "Circular include detected: 'file.fbs' is included in a cycle"

// Deep nesting now rejected:
// "Schema include depth exceeds maximum (50)"
```

**Changes Made:**

- Added `MAX_SCHEMA_TOTAL_SIZE` (10 MB) limit
- Added `MAX_SCHEMA_FILES` (1000) limit
- Added `MAX_INCLUDE_DEPTH` (50) limit
- Added `validateIncludeDepth()` function that:
  - Extracts `include` directives from schema files
  - Resolves relative include paths
  - Detects circular includes via DFS with visited set
  - Enforces maximum include depth

---

## High Severity Issues

### VULN-003: No FlatBuffer Binary Format Validation

**Severity:** HIGH
**Location:** `wasm/src/runner.mjs` - `generateJSON()`
**CVSS 3.1 Score:** 7.5 (High)

**Description:**

The `generateJSON()` function accepts arbitrary binary data and passes it directly to flatc without validating the FlatBuffer format. Malformed binary data could cause crashes, memory corruption, or undefined behavior in the WASM module.

```javascript
async generateJSON(binaryInput, schemaInput, options = {}) {
  const { binary, rootType } = binaryInput;

  // No validation of binary format
  // - No magic number check
  // - No offset validation
  // - No size sanity check

  mountFile(this.module, binaryPath, binary);
  // Binary passed directly to flatc
}
```

**Attack Scenario:**

1. Attacker provides malformed binary with invalid offsets
2. WASM module attempts to read out-of-bounds memory
3. Potential information disclosure or crash

**Impact:**

- Crash/DoS of WASM module
- Potential memory disclosure via error messages
- Undefined behavior in flatc

**Remediation:** ✅ **IMPLEMENTED**

The fix adds comprehensive FlatBuffer binary validation before processing:

```javascript
// Now validates before processing:
generateJSON(schemaInput, binaryInput);  // Auto-validates

// Skip validation if needed (use with caution):
generateJSON(schemaInput, binaryInput, { skipValidation: true });

// Security limits:
const MAX_BINARY_SIZE = 100 * 1024 * 1024;  // 100 MB
const MIN_FLATBUFFER_SIZE = 4;               // Minimum valid size
```

**Changes Made:**

- Added `validateFlatBufferBinary()` function that checks:
  - Buffer is a Uint8Array
  - Size within limits (4 bytes to 100 MB)
  - Root offset points within buffer bounds
  - File identifier bytes are valid ASCII (if present)
  - Vtable offset and size are valid
- Added `skipValidation` option for `generateJSON()` (opt-out)
- Added `MAX_BINARY_SIZE` constant (100 MB)

---

### VULN-004: In-Place Encryption Modifies Caller Data

**Severity:** HIGH
**Location:** `wasm/src/encryption.mjs` - `encryptBytes()`, `decryptBytes()`
**CVSS 3.1 Score:** 6.5 (Medium-High)

**Description:**

The encryption functions modify the input array in-place, destroying the original plaintext. If callers don't expect this behavior, they may inadvertently expose ciphertext where plaintext was expected, or lose access to original data.

```javascript
export function encryptBytes(data, key, iv) {
  // ...
  writeBytes(dataPtr, data);
  wasmModule.wasi_aes256_ctr_encrypt(dataPtr, data.length, keyPtr, ivPtr);

  // WARNING: Modifies original 'data' array in place
  const encrypted = readBytes(dataPtr, data.length);
  data.set(encrypted);  // Original plaintext destroyed

  return data;  // Returns same array, now containing ciphertext
}
```

**Attack Scenario:**

1. Developer stores sensitive plaintext in array
2. Calls `encryptBytes()` to get ciphertext for transmission
3. Later attempts to use original array, expecting plaintext
4. Actually uses ciphertext, causing data corruption or leak

**Impact:**

- Data corruption
- Unintended plaintext/ciphertext confusion
- Potential security bypass if checks rely on original data

**Remediation:** ✅ **IMPLEMENTED**

The fix adds non-destructive encryption/decryption functions:

```javascript
// NEW: Non-destructive encryption (recommended)
const { ciphertext, iv } = encryptBytesCopy(plaintext, key);
// plaintext is unchanged, ciphertext is a new array

// NEW: Non-destructive decryption (recommended)
const decrypted = decryptBytesCopy(ciphertext, key, iv);
// ciphertext is unchanged, decrypted is a new array

// Original in-place functions still available for performance-critical code:
encryptBytes(data, key, iv);  // Modifies data in-place (documented)
decryptBytes(data, key, iv);  // Modifies data in-place (documented)
```

**Changes Made:**

- Added `encryptBytesCopy(data, key, iv?)` - returns `{ciphertext, iv}`
  - Auto-generates IV if not provided
  - Original data unchanged
- Added `decryptBytesCopy(data, key, iv)` - returns plaintext
  - Original data unchanged
- Updated JSDoc for `encryptBytes()`/`decryptBytes()` with clear warnings
- Both copy functions integrate with IV tracking (VULN-001 fix)

---

## Moderate Severity Issues

### VULN-005: No Rate Limiting on Cryptographic Operations

**Severity:** MODERATE
**Location:** `wasm/src/encryption.mjs` - All crypto functions
**CVSS 3.1 Score:** 5.3 (Medium)

**Description:**

Cryptographic operations have no rate limiting, allowing attackers to:
1. Perform timing attacks by measuring operation latency variance
2. Cause DoS by flooding with expensive operations (key generation, signing)

**Impact:**

- Timing side-channel attacks
- Resource exhaustion DoS

**Remediation:**

```javascript
// Add minimum operation time to prevent timing attacks
async function constantTimeWrap(operation, minTimeMs = 50) {
  const start = performance.now();
  const result = await operation();
  const elapsed = performance.now() - start;

  if (elapsed < minTimeMs) {
    await new Promise(r => setTimeout(r, minTimeMs - elapsed));
  }

  return result;
}

// Add rate limiting
const rateLimiter = new Map();
function checkRateLimit(operation, maxPerSecond = 100) {
  const now = Date.now();
  const key = operation;

  if (!rateLimiter.has(key)) {
    rateLimiter.set(key, { count: 0, resetAt: now + 1000 });
  }

  const limit = rateLimiter.get(key);
  if (now > limit.resetAt) {
    limit.count = 0;
    limit.resetAt = now + 1000;
  }

  if (limit.count >= maxPerSecond) {
    throw new Error('Rate limit exceeded');
  }

  limit.count++;
}
```

---

### VULN-006: Regex-Based Schema Parsing

**Severity:** MODERATE
**Location:** `wasm/src/aligned-codegen.mjs`
**CVSS 3.1 Score:** 5.3 (Medium)

**Description:**

The aligned-codegen module uses regex-based parsing to extract schema information. Regex parsing is prone to:
- ReDoS (Regular Expression Denial of Service)
- Edge cases causing incorrect parsing
- Malformed input causing unexpected behavior

```javascript
// Example of regex-based parsing
const structMatch = content.match(/struct\s+(\w+)\s*\{([^}]+)\}/g);
const enumMatch = content.match(/enum\s+(\w+)\s*:\s*(\w+)\s*\{([^}]+)\}/g);
```

**Impact:**

- ReDoS via crafted input
- Incorrect schema parsing
- Potential code generation issues

**Remediation:**

- Use formal FlatBuffers schema parser
- Add timeout for regex operations
- Validate regex patterns for ReDoS vulnerability

---

### VULN-007: WASM Binaries Not Auditable

**Severity:** MODERATE
**Location:** `wasm/dist/flatc.wasm`, `wasm/dist/flatc-encryption.wasm`
**CVSS 3.1 Score:** 5.0 (Medium)

**Description:**

The compiled WASM binaries (~5 MB combined) are opaque and cannot be easily audited. This creates supply chain risk:
- Cannot verify Crypto++ implementation correctness
- Cannot verify Emscripten didn't introduce vulnerabilities
- Cannot verify absence of backdoors

**Impact:**

- Supply chain trust issues
- Difficulty auditing cryptographic implementations
- Potential hidden vulnerabilities

**Remediation:**

1. Publish reproducible build instructions
2. Provide WASM source maps for debugging
3. Regular third-party audits of WASM binaries
4. SBOM (Software Bill of Materials) for dependencies

---

### VULN-008: JavaScript Plaintext Memory Exposure

**Severity:** MODERATE
**Location:** `wasm/src/encryption.mjs`
**CVSS 3.1 Score:** 4.7 (Medium)

**Description:**

While WASM memory is securely zeroed, the original JavaScript Uint8Array containing plaintext remains in memory until garbage collected. An attacker with memory access could recover plaintext.

```javascript
const plaintext = new Uint8Array([...sensitive data...]);
encryptBytes(plaintext, key, iv);
// 'plaintext' array still exists, now containing ciphertext
// Original plaintext bytes may still exist in JS heap
```

**Impact:**

- Plaintext recovery via memory dump
- Increased window for memory-based attacks

**Remediation:**

```javascript
// Helper to zero JS arrays
function secureZero(arr) {
  if (arr instanceof Uint8Array) {
    arr.fill(0);
  }
}

// Document secure usage pattern
/**
 * Secure encryption pattern:
 * 1. const plaintext = new Uint8Array([...]);
 * 2. const ciphertext = encryptBytesCopy(plaintext, key, iv);
 * 3. secureZero(plaintext); // Zero original
 */
```

---

### VULN-009: Error Messages May Leak Sensitive Information

**Severity:** MODERATE
**Location:** Multiple files
**CVSS 3.1 Score:** 4.3 (Medium)

**Description:**

Error messages include internal state information that could aid attackers:

```javascript
throw new Error(`Memory write overflow: ptr=${ptr}, size=${data.length}, memSize=${memSize}`);
throw new CryptoError(CryptoErrorCode.INVALID_KEY_SIZE, `Key must be ${KEY_SIZE} bytes, got ${key.length}`);
```

**Impact:**

- Information disclosure about internal memory layout
- Aids in crafting targeted attacks

**Remediation:**

```javascript
// Generic error for external use
throw new CryptoError(CryptoErrorCode.INVALID_KEY_SIZE, 'Invalid key size');

// Detailed logging for debug mode only
if (process.env.DEBUG) {
  console.error(`Debug: Key size ${key.length}, expected ${KEY_SIZE}`);
}
```

---

### VULN-010: Missing Content Security Policy Guidance

**Severity:** MODERATE
**Location:** Documentation / `wasm/README.md`
**CVSS 3.1 Score:** 4.0 (Medium)

**Description:**

No guidance on Content Security Policy (CSP) for browser deployment. WASM modules require specific CSP directives, and cryptographic operations may be blocked by default policies.

**Impact:**

- Users may deploy with insecure CSP
- WASM may fail silently in strict CSP environments

**Remediation:**

Add to README:
```markdown
## Content Security Policy

For browser deployment, ensure your CSP includes:

```
Content-Security-Policy:
  script-src 'self' 'wasm-unsafe-eval';
  worker-src 'self' blob:;
```

Note: `wasm-unsafe-eval` is required for WebAssembly instantiation.
```

---

### VULN-011: No Subresource Integrity for CDN Deployment

**Severity:** MODERATE
**Location:** Documentation
**CVSS 3.1 Score:** 4.0 (Medium)

**Description:**

No SRI (Subresource Integrity) hashes provided for CDN deployment. If users load the module from a CDN, they cannot verify integrity.

**Remediation:**

Publish SRI hashes:
```html
<script src="https://cdn.example.com/flatc-wasm.js"
        integrity="sha384-[hash]"
        crossorigin="anonymous"></script>
```

---

### VULN-012: Streaming Dispatcher Size Handling

**Severity:** MODERATE
**Location:** `wasm/src/streaming-dispatcher.mjs`
**CVSS 3.1 Score:** 5.0 (Medium)

**Description:**

The streaming dispatcher reads message size from the first 4 bytes without adequate bounds checking. An attacker could specify a large size to trigger memory allocation issues.

```javascript
// Potential issue: unchecked size
const size = view.getUint32(0, true);  // Little-endian size prefix
// If size is 2^32-1 (4GB), this could cause issues
```

**Remediation:**

```javascript
const MAX_MESSAGE_SIZE = 100 * 1024 * 1024; // 100 MB

function parseMessage(buffer) {
  const view = new DataView(buffer);
  const size = view.getUint32(0, true);

  if (size > MAX_MESSAGE_SIZE) {
    throw new Error(`Message size ${size} exceeds maximum ${MAX_MESSAGE_SIZE}`);
  }
  // ...
}
```

---

## Low Severity Issues

### VULN-013: No Key Rotation Guidance

**Severity:** LOW
**Location:** Documentation

**Description:** No documentation on key rotation best practices for long-running applications.

---

### VULN-014: Missing Input Sanitization Logging

**Severity:** LOW
**Location:** `wasm/src/runner.mjs`

**Description:** When path traversal or null bytes are detected, no logging occurs to aid security monitoring.

---

### VULN-015: Timestamp in Error Context

**Severity:** LOW
**Location:** Error handling

**Description:** Errors don't include timestamps, making forensic analysis difficult.

---

## Positive Security Findings

The following security best practices were observed:

### Secure Memory Deallocation

```javascript
function secureDeallocate(ptr, size) {
  if (ptr !== 0 && wasmMemory) {
    const view = new Uint8Array(wasmMemory.buffer, ptr, size);
    view.fill(0);  // Zero before free
    wasmModule.free(ptr);
  }
}
```

### Constant-Time MAC Verification

```javascript
export function hmacSha256Verify(key, data, expectedMac) {
  const computedMac = hmacSha256(key, data);
  let diff = 0;
  for (let i = 0; i < HMAC_SIZE; i++) {
    diff |= computedMac[i] ^ expectedMac[i];  // XOR accumulation
  }
  return diff === 0;  // Constant-time comparison
}
```

### Path Traversal Prevention

```javascript
function validatePath(path, context = 'path') {
  if (path.includes('/../') || path.startsWith('../') || path.endsWith('/..')) {
    throw new ValidationError(`Path traversal detected in ${context}`);
  }
  if (path.includes('\0')) {
    throw new ValidationError(`Null byte detected in ${context}`);
  }
  return normalizePath(path);
}
```

### Encrypt-then-MAC Pattern

```javascript
export function encryptAuthenticated(plaintext, key, associatedData) {
  // Derive separate keys
  const encKey = hkdf(key, null, 'aes-key', 32);
  const macKey = hkdf(key, null, 'mac-key', 32);

  // Encrypt first
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const ciphertext = encryptBytes(plaintext, encKey, iv);

  // Then MAC over (iv || ciphertext || aad)
  const mac = hmacSha256(macKey, concat(iv, ciphertext, associatedData));

  return concat(iv, ciphertext, mac);  // Correct order
}
```

### Proper HKDF Key Derivation

- Uses RFC 5869 compliant HKDF-SHA256
- Separate key derivation for encryption and MAC keys
- Domain separation via context strings

### Comprehensive Test Coverage

- `test_encryption.mjs`: 43 KB of cryptographic tests
- Covers all algorithms, edge cases, and error conditions

---

## Remediation Recommendations

### Priority 1: Critical (Implement Immediately)

| Issue | Remediation | Effort |
|-------|-------------|--------|
| VULN-001 | Add IV tracking/auto-generation | 2-4 hours |
| VULN-002 | Add include depth/size limits | 4-8 hours |

### Priority 2: High (Implement This Sprint)

| Issue | Remediation | Effort |
|-------|-------------|--------|
| VULN-003 | Add FlatBuffer binary validation | 4-8 hours |
| VULN-004 | Add non-destructive encryption API | 2-4 hours |

### Priority 3: Moderate (Implement This Quarter)

| Issue | Remediation | Effort |
|-------|-------------|--------|
| VULN-005 | Add rate limiting | 8-16 hours |
| VULN-006 | Replace regex with formal parser | 16-40 hours |
| VULN-007 | Reproducible builds + SBOM | 8-16 hours |
| VULN-008 | Document secure memory patterns | 2-4 hours |
| VULN-009 | Sanitize error messages | 4-8 hours |
| VULN-010 | CSP documentation | 1-2 hours |
| VULN-011 | Publish SRI hashes | 1-2 hours |
| VULN-012 | Add message size limits | 2-4 hours |

---

## Cryptographic Analysis

### Algorithm Assessment

| Algorithm | Usage | Security Level | Recommendation |
|-----------|-------|----------------|----------------|
| AES-256-CTR | Symmetric encryption | 256-bit | Secure if IV unique |
| HMAC-SHA256 | Authentication | 256-bit | Secure |
| HKDF-SHA256 | Key derivation | 256-bit | Secure |
| X25519 | Key exchange | ~128-bit ECC | Secure |
| secp256k1 | ECDH/ECDSA | ~128-bit ECC | Secure |
| P-256 | ECDH/ECDSA | ~128-bit ECC | Secure |
| Ed25519 | Signatures | ~128-bit ECC | Secure |

### Key Size Compliance

All key sizes meet or exceed current recommendations:
- Symmetric: 256-bit (NIST recommends 128+)
- ECC: ~128-bit security (NIST recommends 112+)

### Cryptographic Implementation Notes

1. **AES-CTR**: Counter mode is secure but requires unique IVs - currently not enforced
2. **Encrypt-then-MAC**: Correct order, prevents padding oracle attacks
3. **Constant-time comparison**: Correctly implemented for MAC verification
4. **HKDF**: Proper key derivation with domain separation

---

## Attack Surface Analysis

### External Inputs

| Input | Entry Point | Validation | Risk |
|-------|-------------|------------|------|
| Schema files | `generateCode()` | Path validation | Medium |
| JSON data | `generateBinary()` | None (flatc) | Medium |
| Binary data | `generateJSON()` | None | High |
| Encryption keys | `encryptBytes()` | Size check | Low |
| IVs | `encryptBytes()` | Size check | High |

### Trust Boundaries

```
┌─────────────────────────────────────────────┐
│ UNTRUSTED: User Input                       │
│ - Schemas, JSON, Binary, Keys               │
├─────────────────────────────────────────────┤
│ VALIDATION LAYER: runner.mjs                │
│ - Path validation, schema structure         │
├─────────────────────────────────────────────┤
│ SEMI-TRUSTED: flatc WASM                    │
│ - Relies on flatc for format validation     │
├─────────────────────────────────────────────┤
│ TRUSTED: Crypto++ WASM                      │
│ - Cryptographic operations                  │
└─────────────────────────────────────────────┘
```

---

## Appendix: Files Analyzed

| File | Lines | Security Relevance |
|------|-------|-------------------|
| `src/encryption.mjs` | ~2,500 | Critical - all crypto |
| `src/runner.mjs` | 713 | High - input handling |
| `src/aligned-codegen.mjs` | ~1,000 | Medium - code gen |
| `src/streaming-dispatcher.mjs` | ~300 | Medium - message routing |
| `src/index.mjs` | 93 | Low - entry point |
| `test/test_encryption.mjs` | ~1,200 | Reference - test vectors |

---

## Revision History

| Date | Version | Changes |
|------|---------|---------|
| 2026-01-20 | 1.0 | Initial security assessment |

---

## Disclaimer

This assessment was performed based on static analysis of the source code and documentation. Dynamic testing, fuzzing, and binary analysis of WASM modules were not performed. A comprehensive security audit should include these additional testing methodologies.
