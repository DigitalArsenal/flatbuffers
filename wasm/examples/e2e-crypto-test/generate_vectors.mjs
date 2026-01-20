#!/usr/bin/env node
/**
 * Test Vector Generator for FlatBuffers Cross-Language Encryption E2E Tests
 *
 * Uses upstream FlatBuffers test schemas and applies transparent encryption
 * to the entire binary output.
 *
 * Key concept: Encryption is TRANSPARENT - the same schema works for encrypted
 * and unencrypted messages. Encryption is applied to the serialized FlatBuffer
 * binary, not to specific fields.
 */

import { writeFileSync, existsSync, mkdirSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { createHash, createHmac } from 'crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));
const vectorsDir = join(__dirname, 'vectors');
const binaryDir = join(vectorsDir, 'binary');

// Ensure directories exist
if (!existsSync(vectorsDir)) mkdirSync(vectorsDir, { recursive: true });
if (!existsSync(binaryDir)) mkdirSync(binaryDir, { recursive: true });

/**
 * Deterministic key derivation from a master seed.
 * Generates consistent keys across runs for reproducible tests.
 */
function deriveKey(seed, context, length = 32) {
  const hmac = createHmac('sha512', seed);
  hmac.update(context);
  return hmac.digest().slice(0, length);
}

function toHex(buffer) {
  return Buffer.from(buffer).toString('hex');
}

// Master seed for deterministic key generation (TEST ONLY - NOT FOR PRODUCTION)
const MASTER_SEED = 'flatbuffers-e2e-crypto-test-v2';

// 10 cryptocurrency chains with their key types
const CHAINS = [
  { name: 'bitcoin', curve: 'secp256k1', sig: 'ECDSA' },
  { name: 'ethereum', curve: 'secp256k1', sig: 'ECDSA' },
  { name: 'solana', curve: 'ed25519', sig: 'EdDSA' },
  { name: 'sui', curve: 'ed25519', sig: 'EdDSA' },
  { name: 'cosmos', curve: 'secp256k1', sig: 'ECDSA' },
  { name: 'polkadot', curve: 'sr25519', sig: 'Schnorr' },
  { name: 'cardano', curve: 'ed25519', sig: 'EdDSA' },
  { name: 'tezos', curve: 'ed25519', sig: 'EdDSA' },
  { name: 'near', curve: 'ed25519', sig: 'EdDSA' },
  { name: 'aptos', curve: 'ed25519', sig: 'EdDSA' },
];

// Generate encryption keys for each chain (AES-256 key + IV)
const encryptionKeys = {};
for (const chain of CHAINS) {
  const key = deriveKey(MASTER_SEED, `${chain.name}-aes-key`, 32);
  const iv = deriveKey(MASTER_SEED, `${chain.name}-aes-iv`, 16);

  encryptionKeys[chain.name] = {
    key_hex: toHex(key),
    iv_hex: toHex(iv),
    key_base64: key.toString('base64'),
    iv_base64: iv.toString('base64'),
    curve: chain.curve,
    signature: chain.sig,
  };
}

// Save encryption keys
writeFileSync(
  join(vectorsDir, 'encryption_keys.json'),
  JSON.stringify(encryptionKeys, null, 2)
);
console.log('Generated: encryption_keys.json');

// Generate crypto keypairs for each chain (for ECDH/signature tests)
const cryptoKeys = {};
for (const chain of CHAINS) {
  const privateKey = deriveKey(MASTER_SEED, `${chain.name}-private`,
    chain.curve === 'ed25519' ? 64 : 32);
  const publicKey = deriveKey(MASTER_SEED, `${chain.name}-public`,
    chain.curve === 'secp256k1' ? 33 : 32);

  cryptoKeys[chain.name] = {
    private_key_hex: toHex(privateKey),
    public_key_hex: toHex(publicKey),
    curve: chain.curve,
    signature: chain.sig,
  };
}

writeFileSync(
  join(vectorsDir, 'crypto_keys.json'),
  JSON.stringify(cryptoKeys, null, 2)
);
console.log('Generated: crypto_keys.json');

// Test configuration pointing to upstream schemas
const testVectors = {
  description: 'FlatBuffers E2E Encryption Test Vectors',
  version: '2.0.0',

  // Use upstream test files (relative to this directory)
  upstream: {
    schema: '../../../tests/monster_test.fbs',
    schema_include: '../../../tests/include_test',
    json_data: '../../../tests/monsterdata_test.json',
    root_type: 'MyGame.Example.Monster',
    file_identifier: 'MONS',
  },

  // Encryption is transparent - applied to entire binary
  encryption: {
    algorithm: 'AES-256-CTR',
    mode: 'transparent',
    description: 'Encryption applied to FlatBuffer binary output. Same schema works for encrypted and unencrypted messages. User determines which messages are encrypted via external means (file identifier, metadata field, etc).',
  },

  chains: CHAINS.map(c => ({ name: c.name, curve: c.curve, signature: c.sig })),
};

writeFileSync(
  join(vectorsDir, 'test_vectors.json'),
  JSON.stringify(testVectors, null, 2)
);
console.log('Generated: test_vectors.json');

console.log('\nTest vector configuration complete.');
console.log('\nUpstream test files used:');
console.log('  Schema: tests/monster_test.fbs');
console.log('  Data:   tests/monsterdata_test.json');
console.log('\nTransparent encryption model:');
console.log('  - Same schema for encrypted and unencrypted messages');
console.log('  - Encrypt entire FlatBuffer binary with AES-256-CTR');
console.log('  - User identifies encrypted messages externally');
console.log('\nRun the test runners to generate and verify binary files.');
