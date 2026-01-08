#!/usr/bin/env node
/**
 * Node.js E2E Test Runner for FlatBuffers Cross-Language Encryption
 *
 * Uses upstream FlatBuffers test schemas with TRANSPARENT encryption.
 * The entire FlatBuffer binary is encrypted - same schema works for
 * encrypted and unencrypted messages.
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const vectorsDir = join(__dirname, '../../vectors');
const outputDir = join(vectorsDir, 'binary');
const testsDir = join(__dirname, '../../../../../tests');

// Ensure output directory exists
if (!existsSync(outputDir)) {
  mkdirSync(outputDir, { recursive: true });
}

// Load test configuration
const testVectors = JSON.parse(readFileSync(join(vectorsDir, 'test_vectors.json'), 'utf8'));
const encryptionKeys = JSON.parse(readFileSync(join(vectorsDir, 'encryption_keys.json'), 'utf8'));

// Load upstream test data
const monsterDataJson = readFileSync(join(testsDir, 'monsterdata_test.json'), 'utf8');
const monsterSchema = readFileSync(join(testsDir, 'monster_test.fbs'), 'utf8');
const includeSchema = readFileSync(join(testsDir, 'include_test/include_test1.fbs'), 'utf8');
const subIncludeSchema = readFileSync(join(testsDir, 'include_test/sub/include_test2.fbs'), 'utf8');

// Helper functions
function toHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

class TestResult {
  constructor(name) {
    this.name = name;
    this.passed = 0;
    this.failed = 0;
    this.errors = [];
  }

  pass(msg) {
    this.passed++;
    console.log(`  ✓ ${msg}`);
  }

  fail(msg, error) {
    this.failed++;
    this.errors.push({ msg, error });
    console.log(`  ✗ ${msg}`);
    if (error) console.log(`    Error: ${error}`);
  }

  summary() {
    const total = this.passed + this.failed;
    const status = this.failed === 0 ? '✓' : '✗';
    console.log(`\n${status} ${this.name}: ${this.passed}/${total} passed`);
    return this.failed === 0;
  }
}

async function main() {
  console.log('='.repeat(60));
  console.log('FlatBuffers Cross-Language Encryption E2E Tests - Node.js');
  console.log('='.repeat(60));
  console.log();
  console.log('Mode: TRANSPARENT ENCRYPTION');
  console.log('Schema: tests/monster_test.fbs (upstream)');
  console.log();

  let flatc, encryption;

  try {
    const flatcWasm = await import('flatc-wasm');
    flatc = await flatcWasm.FlatcRunner.init();
    encryption = await import('flatc-wasm/encryption');
    console.log(`FlatC version: ${flatc.version()}`);
    console.log();
  } catch (e) {
    console.error('Failed to load flatc-wasm. Make sure it is built and linked.');
    console.error('Run: cd ../../../.. && npm link');
    console.error(e.message);
    process.exit(1);
  }

  // Schema input with includes
  const schemaInput = {
    entry: '/monster_test.fbs',
    files: {
      '/monster_test.fbs': monsterSchema,
      '/include_test1.fbs': includeSchema,
      '/sub/include_test2.fbs': subIncludeSchema,
    }
  };

  const results = [];

  // Test 1: Generate unencrypted FlatBuffer using upstream schema
  console.log('Test 1: Unencrypted FlatBuffer (upstream schema)');
  console.log('-'.repeat(40));
  {
    const result = new TestResult('Unencrypted Generation');

    try {
      const buffer = flatc.generateBinary(schemaInput, monsterDataJson);
      result.pass(`Generated binary: ${buffer.length} bytes`);

      // Save unencrypted binary
      writeFileSync(join(outputDir, 'monster_unencrypted.bin'), Buffer.from(buffer));
      result.pass('Saved: monster_unencrypted.bin');

      // Verify by converting back to JSON
      const json = flatc.binaryToJson(schemaInput, buffer);
      const parsed = JSON.parse(json);

      if (parsed.name === 'MyMonster') {
        result.pass('Verified: name field matches');
      } else {
        result.fail(`Name mismatch: expected MyMonster, got ${parsed.name}`);
      }

      if (parsed.hp === 80) {
        result.pass('Verified: hp field matches');
      } else {
        result.fail(`HP mismatch: expected 80, got ${parsed.hp}`);
      }
    } catch (e) {
      result.fail('Exception during test', e.message);
    }

    results.push(result.summary());
  }

  // Test 2: Transparent encryption with each chain's key
  console.log('\nTest 2: Transparent Encryption (per-chain keys)');
  console.log('-'.repeat(40));

  for (const [chain, keys] of Object.entries(encryptionKeys)) {
    const result = new TestResult(`Encryption with ${chain}`);

    try {
      // Generate fresh buffer
      const buffer = flatc.generateBinary(schemaInput, monsterDataJson);
      const originalBuffer = new Uint8Array(buffer);
      const originalHex = toHex(buffer);

      // Get key and IV
      const key = fromHex(keys.key_hex);
      const iv = fromHex(keys.iv_hex);

      // TRANSPARENT ENCRYPTION: encrypt entire binary
      encryption.initEncryption(flatc.wasmInstance);
      const encrypted = encryption.encryptBytes(key, iv, buffer);
      const encryptedHex = toHex(encrypted);

      if (encryptedHex !== originalHex) {
        result.pass('Binary encrypted (differs from original)');
      } else {
        result.fail('Encryption did not modify data');
      }

      // Save encrypted binary
      writeFileSync(join(outputDir, `monster_encrypted_${chain}.bin`), Buffer.from(encrypted));
      result.pass(`Saved: monster_encrypted_${chain}.bin`);

      // TRANSPARENT DECRYPTION: decrypt entire binary
      const decrypted = encryption.decryptBytes(key, iv, encrypted);
      const decryptedHex = toHex(decrypted);

      if (decryptedHex === originalHex) {
        result.pass('Decryption restored original binary');
      } else {
        result.fail('Decryption mismatch');
      }

      // Verify decrypted data can be parsed
      const json = flatc.binaryToJson(schemaInput, decrypted);
      const parsed = JSON.parse(json);

      if (parsed.name === 'MyMonster' && parsed.hp === 80) {
        result.pass('Decrypted data parses correctly');
      } else {
        result.fail('Decrypted data does not match expected values');
      }
    } catch (e) {
      result.fail('Exception during test', e.message);
    }

    results.push(result.summary());
  }

  // Test 3: Crypto operations (SHA-256, signatures)
  console.log('\nTest 3: Crypto Operations');
  console.log('-'.repeat(40));
  {
    const result = new TestResult('Crypto Operations');

    try {
      encryption.initEncryption(flatc.wasmInstance);

      // Test SHA-256
      const testMsg = new TextEncoder().encode('hello');
      const hash = encryption.sha256(testMsg);
      const expectedHash = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';
      if (toHex(hash) === expectedHash) {
        result.pass('SHA-256 hash correct');
      } else {
        result.fail(`SHA-256 mismatch: ${toHex(hash)}`);
      }

      // Test Ed25519 (Solana, SUI, Cardano, etc.)
      const ed25519Keys = encryption.ed25519GenerateKeypair();
      if (ed25519Keys.privateKey.length === 64 && ed25519Keys.publicKey.length === 32) {
        result.pass('Ed25519 keypair generation');
      } else {
        result.fail('Ed25519 keypair invalid size');
      }

      const message = new TextEncoder().encode('test message');
      const signature = encryption.ed25519Sign(ed25519Keys.privateKey, message);
      const verified = encryption.ed25519Verify(ed25519Keys.publicKey, message, signature);
      if (verified) {
        result.pass('Ed25519 sign/verify');
      } else {
        result.fail('Ed25519 verification failed');
      }

      // Test secp256k1 (Bitcoin, Ethereum, Cosmos)
      const secp256k1Keys = encryption.secp256k1GenerateKeypair();
      if (secp256k1Keys.privateKey.length === 32 && secp256k1Keys.publicKey.length === 33) {
        result.pass('secp256k1 keypair generation');
      } else {
        result.fail('secp256k1 keypair invalid size');
      }

      const secpSig = encryption.secp256k1Sign(secp256k1Keys.privateKey, message);
      const secpVerified = encryption.secp256k1Verify(secp256k1Keys.publicKey, message, secpSig);
      if (secpVerified) {
        result.pass('secp256k1 sign/verify');
      } else {
        result.fail('secp256k1 verification failed');
      }
    } catch (e) {
      result.fail('Exception during crypto test', e.message);
    }

    results.push(result.summary());
  }

  // Summary
  console.log('\n' + '='.repeat(60));
  console.log('Summary');
  console.log('='.repeat(60));

  const passed = results.filter(r => r).length;
  const total = results.length;

  console.log(`\nTotal: ${passed}/${total} test suites passed`);

  if (passed === total) {
    console.log('\n✓ All tests passed!');
    console.log('\nGenerated binary files:');
    console.log(`  ${outputDir}/`);
    console.log('    - monster_unencrypted.bin');
    Object.keys(encryptionKeys).forEach(chain => {
      console.log(`    - monster_encrypted_${chain}.bin`);
    });
    process.exit(0);
  } else {
    console.log('\n✗ Some tests failed');
    process.exit(1);
  }
}

main().catch(e => {
  console.error('Fatal error:', e);
  process.exit(1);
});
