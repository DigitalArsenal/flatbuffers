#!/usr/bin/env node
/**
 * Node.js E2E Test Runner for FlatBuffers Cross-Language Encryption
 *
 * This is the reference implementation that generates binary test vectors
 * and verifies encryption/decryption with all 10 crypto key types.
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const vectorsDir = join(__dirname, '../../vectors');
const outputDir = join(__dirname, '../../vectors/binary');

// Ensure output directory exists
if (!existsSync(outputDir)) {
  mkdirSync(outputDir, { recursive: true });
}

// Load test data
const testVectors = JSON.parse(readFileSync(join(vectorsDir, 'test_vectors.json'), 'utf8'));
const monsterData = JSON.parse(readFileSync(join(vectorsDir, 'monster_data.json'), 'utf8'));
const encryptionKeys = JSON.parse(readFileSync(join(vectorsDir, 'encryption_keys.json'), 'utf8'));
const cryptoKeys = JSON.parse(readFileSync(join(vectorsDir, 'crypto_keys.json'), 'utf8'));

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

  let flatc, encryption;

  try {
    // Dynamic import to handle missing module gracefully
    const flatcWasm = await import('flatc-wasm');
    flatc = await flatcWasm.FlatcRunner.init();

    encryption = await import('flatc-wasm/encryption');
    console.log(`FlatC version: ${flatc.version()}`);
    console.log();
  } catch (e) {
    console.error('Failed to load flatc-wasm. Make sure it is built and linked.');
    console.error('Run: cd ../../.. && npm link');
    console.error(e.message);
    process.exit(1);
  }

  const results = [];

  // Test 1: Unencrypted FlatBuffer generation
  console.log('Test 1: Unencrypted FlatBuffer Generation');
  console.log('-'.repeat(40));
  {
    const result = new TestResult('Unencrypted Generation');

    try {
      const schema = testVectors.schemas.monster_encrypted;
      const schemaInput = {
        entry: '/monster.fbs',
        files: { '/monster.fbs': schema }
      };

      const buffer = flatc.generateBinary(schemaInput, JSON.stringify(monsterData));
      result.pass(`Generated binary: ${buffer.length} bytes`);

      // Save unencrypted binary
      writeFileSync(join(outputDir, 'monster_unencrypted.bin'), Buffer.from(buffer));
      result.pass('Saved: monster_unencrypted.bin');

      // Verify by converting back to JSON
      const json = flatc.binaryToJson(schemaInput, buffer);
      const parsed = JSON.parse(json);

      if (parsed.name === monsterData.name) {
        result.pass('Verified: name field matches');
      } else {
        result.fail('Name field mismatch');
      }

      if (parsed.hp === monsterData.hp) {
        result.pass('Verified: hp field matches');
      } else {
        result.fail('HP field mismatch');
      }
    } catch (e) {
      result.fail('Exception during test', e.message);
    }

    results.push(result.summary());
  }

  // Test 2: Encrypted FlatBuffer with each crypto key
  console.log('\nTest 2: Encrypted FlatBuffer (per-chain keys)');
  console.log('-'.repeat(40));

  for (const [chain, keys] of Object.entries(encryptionKeys)) {
    const result = new TestResult(`Encryption with ${chain}`);

    try {
      const schema = testVectors.schemas.monster_encrypted;
      const schemaInput = {
        entry: '/monster.fbs',
        files: { '/monster.fbs': schema }
      };

      // Generate fresh buffer
      const buffer = flatc.generateBinary(schemaInput, JSON.stringify(monsterData));
      const originalHex = toHex(buffer);

      // Create encryption context
      const key = fromHex(keys.key_hex);
      const iv = fromHex(keys.iv_hex);
      const ctx = new encryption.EncryptionContext(key);

      // Encrypt
      encryption.encryptBuffer(buffer, schema, ctx, 'Monster');
      const encryptedHex = toHex(buffer);

      if (encryptedHex !== originalHex) {
        result.pass('Buffer modified after encryption');
      } else {
        result.fail('Buffer unchanged after encryption');
      }

      // Save encrypted binary
      writeFileSync(join(outputDir, `monster_encrypted_${chain}.bin`), Buffer.from(buffer));
      result.pass(`Saved: monster_encrypted_${chain}.bin`);

      // Decrypt
      encryption.decryptBuffer(buffer, schema, ctx, 'Monster');
      const decryptedHex = toHex(buffer);

      if (decryptedHex === originalHex) {
        result.pass('Decryption restored original data');
      } else {
        result.fail('Decryption mismatch');
      }

      // Verify decrypted data
      const json = flatc.binaryToJson(schemaInput, buffer);
      const parsed = JSON.parse(json);

      if (parsed.hp === monsterData.hp && parsed.mana === monsterData.mana) {
        result.pass('Verified: encrypted fields restored correctly');
      } else {
        result.fail('Encrypted fields not restored correctly');
      }
    } catch (e) {
      result.fail('Exception during test', e.message);
    }

    results.push(result.summary());
  }

  // Test 3: Crypto key operations (ECDH, signatures)
  console.log('\nTest 3: Crypto Key Operations');
  console.log('-'.repeat(40));
  {
    const result = new TestResult('Crypto Operations');

    try {
      // Initialize encryption module
      encryption.initEncryption(flatc.wasmInstance);

      // Test X25519 (for Solana/SUI/etc Ed25519-based chains)
      const x25519Result = encryption.x25519GenerateKeypair();
      if (x25519Result.privateKey.length === 32 && x25519Result.publicKey.length === 32) {
        result.pass('X25519 keypair generation');
      } else {
        result.fail('X25519 keypair invalid size');
      }

      // Test secp256k1 (for Bitcoin/Ethereum)
      const secp256k1Result = encryption.secp256k1GenerateKeypair();
      if (secp256k1Result.privateKey.length === 32 && secp256k1Result.publicKey.length === 33) {
        result.pass('secp256k1 keypair generation');
      } else {
        result.fail('secp256k1 keypair invalid size');
      }

      // Test Ed25519 (for Solana/SUI/Cardano/etc)
      const ed25519Result = encryption.ed25519GenerateKeypair();
      if (ed25519Result.privateKey.length === 64 && ed25519Result.publicKey.length === 32) {
        result.pass('Ed25519 keypair generation');
      } else {
        result.fail('Ed25519 keypair invalid size');
      }

      // Test P-256 (NIST curve)
      const p256Result = encryption.p256GenerateKeypair();
      if (p256Result.privateKey.length === 32 && p256Result.publicKey.length === 33) {
        result.pass('P-256 keypair generation');
      } else {
        result.fail('P-256 keypair invalid size');
      }

      // Test SHA-256
      const testMsg = new TextEncoder().encode('hello');
      const hash = encryption.sha256(testMsg);
      const expectedHash = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';
      if (toHex(hash) === expectedHash) {
        result.pass('SHA-256 hash');
      } else {
        result.fail('SHA-256 hash mismatch');
      }

      // Test Ed25519 signature
      const message = new TextEncoder().encode('test message for signing');
      const signature = encryption.ed25519Sign(ed25519Result.privateKey, message);
      const verified = encryption.ed25519Verify(ed25519Result.publicKey, message, signature);
      if (verified) {
        result.pass('Ed25519 sign/verify');
      } else {
        result.fail('Ed25519 signature verification failed');
      }

      // Test secp256k1 signature
      const secpSig = encryption.secp256k1Sign(secp256k1Result.privateKey, message);
      const secpVerified = encryption.secp256k1Verify(secp256k1Result.publicKey, message, secpSig);
      if (secpVerified) {
        result.pass('secp256k1 sign/verify');
      } else {
        result.fail('secp256k1 signature verification failed');
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
