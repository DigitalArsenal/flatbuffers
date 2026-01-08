#!/usr/bin/env node
/**
 * Generate comprehensive test vectors for cross-language encryption testing.
 *
 * This script creates FlatBuffers test data using:
 * 1. Official Monster-style schemas (encrypted version)
 * 2. Multi-chain wallet schemas with real crypto key formats
 * 3. All 10 major cryptocurrency key types
 *
 * Key Types Tested:
 * 1. Bitcoin (secp256k1 ECDSA)
 * 2. Ethereum (secp256k1 ECDSA)
 * 3. Solana (Ed25519)
 * 4. SUI (Ed25519)
 * 5. Cosmos (secp256k1 ECDSA)
 * 6. Polkadot (Sr25519 - simulated as X25519)
 * 7. Cardano (Ed25519 Extended)
 * 8. Tezos (Ed25519)
 * 9. Near (Ed25519)
 * 10. Aptos (Ed25519)
 *
 * Usage: node generate_vectors.mjs
 */

import { readFileSync, writeFileSync, existsSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ============================================================================
// Crypto Key Generation (deterministic from seed for reproducibility)
// ============================================================================

// Master seed for deterministic key generation (DO NOT USE IN PRODUCTION)
const MASTER_SEED = Buffer.from(
  'flatbuffers_cross_language_encryption_test_seed_2024_v1',
  'utf8'
);

function deriveKey(seed, context, length = 32) {
  const hmac = crypto.createHmac('sha512', seed);
  hmac.update(context);
  return hmac.digest().slice(0, length);
}

// Generate deterministic test keys for each crypto type
const CRYPTO_KEYS = {
  // secp256k1 keys (Bitcoin, Ethereum, Cosmos)
  bitcoin: {
    privateKey: deriveKey(MASTER_SEED, 'bitcoin_secp256k1_private'),
    // In real usage, public key would be derived from private key
    publicKey: deriveKey(MASTER_SEED, 'bitcoin_secp256k1_public', 33),
    address: '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', // Example Bitcoin address
    scheme: 'ECDSA_secp256k1',
  },
  ethereum: {
    privateKey: deriveKey(MASTER_SEED, 'ethereum_secp256k1_private'),
    publicKey: deriveKey(MASTER_SEED, 'ethereum_secp256k1_public', 33),
    address: '0x742d35Cc6634C0532925a3b844Bc9e7595f81a5d', // Example ETH address
    scheme: 'ECDSA_secp256k1',
  },
  solana: {
    privateKey: deriveKey(MASTER_SEED, 'solana_ed25519_private', 64), // Ed25519 uses 64-byte private key
    publicKey: deriveKey(MASTER_SEED, 'solana_ed25519_public'),
    address: '4fYNw3dojWmQ4dXtSGE9epjRGy9pFSx62YypT7avPYvA', // Example Solana address
    scheme: 'Ed25519',
  },
  sui: {
    privateKey: deriveKey(MASTER_SEED, 'sui_ed25519_private', 64),
    publicKey: deriveKey(MASTER_SEED, 'sui_ed25519_public'),
    address: '0x2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',
    scheme: 'Ed25519',
  },
  cosmos: {
    privateKey: deriveKey(MASTER_SEED, 'cosmos_secp256k1_private'),
    publicKey: deriveKey(MASTER_SEED, 'cosmos_secp256k1_public', 33),
    address: 'cosmos1hsk6jryyqjfhp5dhc55tc9jtckygx0eph6dd02',
    scheme: 'ECDSA_secp256k1',
  },
  polkadot: {
    privateKey: deriveKey(MASTER_SEED, 'polkadot_sr25519_private'),
    publicKey: deriveKey(MASTER_SEED, 'polkadot_sr25519_public'),
    address: '14ShUZUYUR35RBZW6uVVt1zXDxmSQddkeDdXf1JkMA6P7GNY',
    scheme: 'Sr25519',
  },
  cardano: {
    privateKey: deriveKey(MASTER_SEED, 'cardano_ed25519_private', 64),
    publicKey: deriveKey(MASTER_SEED, 'cardano_ed25519_public'),
    address: 'addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwq2ytjqp',
    scheme: 'Ed25519',
  },
  tezos: {
    privateKey: deriveKey(MASTER_SEED, 'tezos_ed25519_private', 64),
    publicKey: deriveKey(MASTER_SEED, 'tezos_ed25519_public'),
    address: 'tz1VSUr8wwNhLAzempoch5d6hLRiTh8Cjcjb',
    scheme: 'Ed25519',
  },
  near: {
    privateKey: deriveKey(MASTER_SEED, 'near_ed25519_private', 64),
    publicKey: deriveKey(MASTER_SEED, 'near_ed25519_public'),
    address: 'alice.near',
    scheme: 'Ed25519',
  },
  aptos: {
    privateKey: deriveKey(MASTER_SEED, 'aptos_ed25519_private', 64),
    publicKey: deriveKey(MASTER_SEED, 'aptos_ed25519_public'),
    address: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
    scheme: 'Ed25519',
  },
};

// Encryption keys derived from each crypto key type
const ENCRYPTION_KEYS = {};
for (const [chain, keys] of Object.entries(CRYPTO_KEYS)) {
  // Derive AES-256 key and IV from the chain's private key using HKDF-like derivation
  ENCRYPTION_KEYS[chain] = {
    key: deriveKey(keys.privateKey, `${chain}_aes256_key`),
    iv: deriveKey(keys.privateKey, `${chain}_aes256_iv`, 16),
  };
}

// ============================================================================
// Test Data Generation
// ============================================================================

function toHex(buffer) {
  return Buffer.from(buffer).toString('hex');
}

function generateMonsterData() {
  return {
    id: 'monster-001',
    name: 'Test Dragon',
    color: 'Blue',
    pos: { x: 1.5, y: 2.5, z: 3.5 },
    created_at: 1704067200000, // 2024-01-01 00:00:00 UTC

    // Encrypted fields
    hp: 250,
    mana: 500,
    secret_location: { lat: 37.7749, lon: -122.4194 },
    inventory: Array.from({ length: 10 }, (_, i) => i * 10),
    secret_notes: 'This monster guards the treasure!',
    damage_multiplier: 1.5,
    experience: 123456.789,
    is_elite: true,
    loot_values: [100, 200, 300, 500, 1000],
    secret_codes: [0xDE, 0xAD, 0xBE, 0xEF],

    weapons: [
      { name: 'Fire Sword', damage: 50 },
      { name: 'Ice Staff', damage: 75 },
    ],
  };
}

function generateWalletData() {
  const now = Date.now();

  return {
    wallet_id: 'wallet-e2e-test-001',
    label: 'Cross-Language Test Wallet',
    created_at: now,

    // Encrypted master key
    master_seed: Array.from(deriveKey(MASTER_SEED, 'master_seed', 64)),
    master_key_encrypted: 'encrypted_master_key_placeholder',

    // All chain keys
    bitcoin_key: createKeyMaterial('Bitcoin_secp256k1', 'ECDSA_secp256k1', CRYPTO_KEYS.bitcoin),
    ethereum_key: createKeyMaterial('Ethereum_secp256k1', 'ECDSA_secp256k1', CRYPTO_KEYS.ethereum),
    solana_key: createKeyMaterial('Solana_ed25519', 'Ed25519', CRYPTO_KEYS.solana),
    sui_key: createKeyMaterial('SUI_ed25519', 'Ed25519', CRYPTO_KEYS.sui),
    cosmos_key: createKeyMaterial('Cosmos_secp256k1', 'ECDSA_secp256k1', CRYPTO_KEYS.cosmos),
    polkadot_key: createKeyMaterial('Polkadot_sr25519', 'Sr25519', CRYPTO_KEYS.polkadot),
    cardano_key: createKeyMaterial('Cardano_ed25519', 'Ed25519', CRYPTO_KEYS.cardano),
    tezos_key: createKeyMaterial('Tezos_ed25519', 'Ed25519', CRYPTO_KEYS.tezos),
    near_key: createKeyMaterial('Near_ed25519', 'Ed25519', CRYPTO_KEYS.near),
    aptos_key: createKeyMaterial('Aptos_ed25519', 'Ed25519', CRYPTO_KEYS.aptos),

    // Addresses
    addresses: Object.entries(CRYPTO_KEYS).map(([chain, keys]) => ({
      chain,
      address: keys.address,
      key_type: getKeyTypeEnum(chain),
    })),

    // Sample transactions
    pending_transactions: [
      {
        tx_id: 'tx-pending-001',
        chain: 'ethereum',
        timestamp: now,
        from_address: CRYPTO_KEYS.ethereum.address,
        to_address: '0x0000000000000000000000000000000000000000',
        amount: 1000000000000000000, // 1 ETH in wei
        fee: 21000000000000, // 21000 gwei
        memo: 'Test transfer',
        raw_tx_data: Array.from(deriveKey(MASTER_SEED, 'eth_tx_data', 100)),
      },
    ],

    signed_transactions: [
      {
        tx_id: 'tx-signed-001',
        chain: 'bitcoin',
        signature: Array.from(deriveKey(MASTER_SEED, 'btc_signature', 72)),
        signed_tx_hex: toHex(deriveKey(MASTER_SEED, 'btc_signed_tx', 200)),
        signer_public_key: Array.from(CRYPTO_KEYS.bitcoin.publicKey),
      },
    ],
  };
}

function createKeyMaterial(keyType, scheme, keys) {
  return {
    key_type: keyType,
    scheme: scheme,
    created_at: Date.now(),
    private_key: Array.from(keys.privateKey),
    seed_phrase: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
    derivation_path: "m/44'/0'/0'/0/0",
  };
}

function getKeyTypeEnum(chain) {
  const mapping = {
    bitcoin: 'Bitcoin_secp256k1',
    ethereum: 'Ethereum_secp256k1',
    solana: 'Solana_ed25519',
    sui: 'SUI_ed25519',
    cosmos: 'Cosmos_secp256k1',
    polkadot: 'Polkadot_sr25519',
    cardano: 'Cardano_ed25519',
    tezos: 'Tezos_ed25519',
    near: 'Near_ed25519',
    aptos: 'Aptos_ed25519',
  };
  return mapping[chain] || 'Unknown';
}

// ============================================================================
// Main
// ============================================================================

async function main() {
  console.log('Generating cross-language encryption test vectors...\n');

  // Read schemas
  const monsterSchema = readFileSync(join(__dirname, 'schemas/monster_encrypted.fbs'), 'utf8');
  const walletSchema = readFileSync(join(__dirname, 'schemas/wallet_test.fbs'), 'utf8');

  // Generate test data
  const monsterData = generateMonsterData();
  const walletData = generateWalletData();

  // Create test vectors document
  const testVectors = {
    version: '2.0.0',
    generated_at: new Date().toISOString(),
    description: 'Cross-language FlatBuffers encryption test vectors with multi-chain crypto keys',

    // Supported crypto key types
    supported_crypto: [
      { name: 'Bitcoin', curve: 'secp256k1', signature: 'ECDSA', key_size: 32 },
      { name: 'Ethereum', curve: 'secp256k1', signature: 'ECDSA', key_size: 32 },
      { name: 'Solana', curve: 'Ed25519', signature: 'EdDSA', key_size: 64 },
      { name: 'SUI', curve: 'Ed25519', signature: 'EdDSA', key_size: 64 },
      { name: 'Cosmos', curve: 'secp256k1', signature: 'ECDSA', key_size: 32 },
      { name: 'Polkadot', curve: 'Sr25519', signature: 'Schnorr', key_size: 32 },
      { name: 'Cardano', curve: 'Ed25519', signature: 'EdDSA', key_size: 64 },
      { name: 'Tezos', curve: 'Ed25519', signature: 'EdDSA', key_size: 64 },
      { name: 'Near', curve: 'Ed25519', signature: 'EdDSA', key_size: 64 },
      { name: 'Aptos', curve: 'Ed25519', signature: 'EdDSA', key_size: 64 },
    ],

    // Encryption keys for each chain (derived from chain keys)
    encryption_keys: Object.fromEntries(
      Object.entries(ENCRYPTION_KEYS).map(([chain, keys]) => [
        chain,
        {
          key_hex: toHex(keys.key),
          iv_hex: toHex(keys.iv),
        },
      ])
    ),

    // Crypto keys (for signature verification tests)
    crypto_keys: Object.fromEntries(
      Object.entries(CRYPTO_KEYS).map(([chain, keys]) => [
        chain,
        {
          private_key_hex: toHex(keys.privateKey),
          public_key_hex: toHex(keys.publicKey),
          address: keys.address,
          scheme: keys.scheme,
        },
      ])
    ),

    // Schemas
    schemas: {
      monster_encrypted: monsterSchema,
      wallet_test: walletSchema,
    },

    // Test cases
    test_cases: [
      {
        id: 'monster_unencrypted',
        description: 'Monster with encrypted fields - before encryption',
        schema: 'monster_encrypted',
        root_type: 'Monster',
        data: monsterData,
        encrypted: false,
      },
      {
        id: 'wallet_unencrypted',
        description: 'Multi-chain wallet - before encryption',
        schema: 'wallet_test',
        root_type: 'MultiChainWallet',
        data: walletData,
        encrypted: false,
      },
    ],

    // Per-chain encryption test cases
    chain_encryption_tests: Object.keys(CRYPTO_KEYS).map((chain) => ({
      id: `monster_encrypted_${chain}`,
      description: `Monster encrypted with ${chain} derived key`,
      schema: 'monster_encrypted',
      root_type: 'Monster',
      encryption_key: chain,
      data: monsterData,
    })),

    // Instructions for test runners
    test_instructions: {
      unencrypted: [
        '1. Parse JSON data',
        '2. Build FlatBuffer using schema',
        '3. Serialize to binary',
        '4. Verify all field values match expected',
        '5. Share binary with other languages for compatibility check',
      ],
      encrypted: [
        '1. Parse JSON data',
        '2. Build FlatBuffer using schema',
        '3. Encrypt buffer using specified key/IV',
        '4. Verify encrypted fields are no longer readable',
        '5. Decrypt buffer using same key/IV',
        '6. Verify all field values match original',
        '7. Share encrypted binary with other languages',
        '8. Verify cross-language decryption produces identical results',
      ],
      signature: [
        '1. Generate key pair for specified curve',
        '2. Sign test message using private key',
        '3. Verify signature using public key',
        '4. Share signature with other languages for verification',
        '5. Verify cross-language signature verification works',
      ],
    },
  };

  // Write test vectors
  const outputPath = join(__dirname, 'vectors/test_vectors.json');
  writeFileSync(outputPath, JSON.stringify(testVectors, null, 2));
  console.log(`Written: ${outputPath}`);

  // Write individual data files for easier testing
  writeFileSync(
    join(__dirname, 'vectors/monster_data.json'),
    JSON.stringify(monsterData, null, 2)
  );
  console.log('Written: vectors/monster_data.json');

  writeFileSync(
    join(__dirname, 'vectors/wallet_data.json'),
    JSON.stringify(walletData, null, 2)
  );
  console.log('Written: vectors/wallet_data.json');

  // Write encryption keys separately for easy access
  writeFileSync(
    join(__dirname, 'vectors/encryption_keys.json'),
    JSON.stringify(
      Object.fromEntries(
        Object.entries(ENCRYPTION_KEYS).map(([chain, keys]) => [
          chain,
          {
            key_hex: toHex(keys.key),
            iv_hex: toHex(keys.iv),
            key_base64: Buffer.from(keys.key).toString('base64'),
            iv_base64: Buffer.from(keys.iv).toString('base64'),
          },
        ])
      ),
      null,
      2
    )
  );
  console.log('Written: vectors/encryption_keys.json');

  // Write crypto keys separately
  writeFileSync(
    join(__dirname, 'vectors/crypto_keys.json'),
    JSON.stringify(
      Object.fromEntries(
        Object.entries(CRYPTO_KEYS).map(([chain, keys]) => [
          chain,
          {
            private_key_hex: toHex(keys.privateKey),
            public_key_hex: toHex(keys.publicKey),
            address: keys.address,
            scheme: keys.scheme,
          },
        ])
      ),
      null,
      2
    )
  );
  console.log('Written: vectors/crypto_keys.json');

  console.log('\nTest vector generation complete!');
  console.log('\nSupported chains:');
  Object.keys(CRYPTO_KEYS).forEach((chain) => {
    console.log(`  - ${chain} (${CRYPTO_KEYS[chain].scheme})`);
  });
}

main().catch(console.error);
