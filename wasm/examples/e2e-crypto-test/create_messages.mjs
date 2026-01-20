#!/usr/bin/env node
/**
 * Message Creator for E2E Cross-Language Encryption Tests
 *
 * Creates test messages using the generated FlatBuffer code and saves them
 * for cross-language testing. Messages are created both unencrypted and
 * encrypted (using ECDH key exchange).
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const vectorsDir = join(__dirname, 'vectors');
const binaryDir = join(vectorsDir, 'binary');
const generatedDir = join(__dirname, 'generated');

// Ensure directories exist
if (!existsSync(binaryDir)) mkdirSync(binaryDir, { recursive: true });

// Use flatc-wasm to create binaries from JSON (no need for native flatbuffers package)

async function main() {
  console.log('='.repeat(60));
  console.log('FlatBuffers E2E Message Creator');
  console.log('='.repeat(60));
  console.log();

  // Load flatc-wasm for binary generation
  let flatc;
  try {
    const flatcWasm = await import('flatc-wasm');
    flatc = await flatcWasm.FlatcRunner.init();
    console.log(`FlatC version: ${flatc.version()}`);
  } catch (e) {
    console.error('Failed to load flatc-wasm:', e.message);
    process.exit(1);
  }

  // Load encryption module
  let encryption;
  let encryptionAvailable = false;
  try {
    encryption = await import('flatc-wasm/encryption');
    const encryptionWasmPaths = [
      join(__dirname, '../../../build/wasm/wasm/flatc-encryption.wasm'),
      join(__dirname, '../../dist/flatc-encryption.wasm'),
    ];

    for (const p of encryptionWasmPaths) {
      if (existsSync(p)) {
        console.log(`Loading encryption from: ${p}`);
        await encryption.loadEncryptionWasm(p);
        if (encryption.isInitialized()) {
          encryptionAvailable = true;
          break;
        }
      }
    }
  } catch (e) {
    console.log('Encryption not available:', e.message);
  }

  console.log(`Encryption: ${encryptionAvailable ? 'Available' : 'Not available'}`);
  console.log();

  // Load schema
  const schemaPath = join(__dirname, 'schemas/message.fbs');
  const schemaContent = readFileSync(schemaPath, 'utf8');
  const schemaInput = {
    entry: '/message.fbs',
    files: { '/message.fbs': schemaContent }
  };

  // Test messages with various data types
  const testMessages = [
    {
      name: 'simple',
      json: {
        id: 'msg-001',
        sender: 'alice',
        recipient: 'bob',
        payload: {
          message: 'Hello, World!',
          value: 42,
          data: [1, 2, 3, 4, 5],
          is_encrypted: false
        },
        timestamp: '1704067200'
      }
    },
    {
      name: 'nested',
      json: {
        id: 'msg-002',
        sender: 'alice',
        recipient: 'bob',
        payload: {
          message: 'Nested payload test',
          value: 100,
          data: [255, 0, 128, 64, 32],
          nested: [
            { message: 'child1', value: 1, is_encrypted: false },
            { message: 'child2', value: 2, is_encrypted: false }
          ],
          is_encrypted: false
        },
        timestamp: '1704067300'
      }
    },
    {
      name: 'unicode',
      json: {
        id: 'msg-003',
        sender: 'alice-鍵',
        recipient: 'bob-🔑',
        payload: {
          message: 'Unicode: Привет мир! 你好世界! 🌍🔐',
          value: 9999,
          data: [0xDE, 0xAD, 0xBE, 0xEF],
          is_encrypted: false
        },
        timestamp: '1704067400'
      }
    },
    {
      name: 'binary_heavy',
      json: {
        id: 'msg-004',
        sender: 'system',
        recipient: 'all',
        payload: {
          message: 'Binary payload test',
          value: -2147483648,  // INT32_MIN
          data: Array.from({ length: 256 }, (_, i) => i),  // 0-255
          is_encrypted: false
        },
        timestamp: '1704067500'
      }
    },
    {
      name: 'empty',
      json: {
        id: 'msg-005',
        sender: '',
        recipient: '',
        payload: {
          message: '',
          value: 0,
          is_encrypted: false
        },
        timestamp: '0'
      }
    },
    {
      name: 'max_values',
      json: {
        id: 'msg-006',
        sender: 'max-test',
        recipient: 'max-test',
        payload: {
          message: 'Max value test',
          value: 2147483647,  // INT32_MAX
          data: [255, 255, 255, 255],
          is_encrypted: false
        },
        timestamp: '18446744073709551615'  // UINT64_MAX (as string for JSON)
      }
    }
  ];

  // Create unencrypted messages
  console.log('Creating unencrypted messages...');
  console.log('-'.repeat(40));

  const createdFiles = [];
  for (const msg of testMessages) {
    try {
      const jsonStr = JSON.stringify(msg.json);
      const buffer = flatc.generateBinary(schemaInput, jsonStr);
      const filename = `secure_message_${msg.name}.bin`;
      const filepath = join(binaryDir, filename);
      writeFileSync(filepath, Buffer.from(buffer));
      console.log(`  ✓ ${filename} (${buffer.length} bytes)`);
      createdFiles.push({ name: msg.name, file: filename, size: buffer.length, encrypted: false });
    } catch (e) {
      console.log(`  ✗ ${msg.name}: ${e.message}`);
    }
  }

  // Create encrypted messages if encryption is available
  if (encryptionAvailable) {
    console.log();
    console.log('Creating encrypted messages with ECDH...');
    console.log('-'.repeat(40));

    // Generate fresh ECDH test keys for this session (alice/bob)
    const ecdhKeys = {};
    const genFuncs = {
      x25519: encryption.x25519GenerateKeyPair,
      secp256k1: encryption.secp256k1GenerateKeyPair,
      p256: encryption.p256GenerateKeyPair
    };

    for (const curve of ['x25519', 'secp256k1', 'p256']) {
      const genFunc = genFuncs[curve];
      const alice = genFunc();
      const bob = genFunc();
      ecdhKeys[curve] = {
        alice: {
          private: Buffer.from(alice.privateKey).toString('hex'),
          public: Buffer.from(alice.publicKey).toString('hex')
        },
        bob: {
          private: Buffer.from(bob.privateKey).toString('hex'),
          public: Buffer.from(bob.publicKey).toString('hex')
        }
      };
    }

    // Save keys for this session
    const ecdhKeysPath = join(vectorsDir, 'ecdh_message_keys.json');
    writeFileSync(ecdhKeysPath, JSON.stringify(ecdhKeys, null, 2));
    console.log('  Generated ECDH keys for message encryption');

    // Create encrypted versions for each curve
    const curves = [
      { name: 'x25519', sharedSecretFunc: encryption.x25519SharedSecret },
      { name: 'secp256k1', sharedSecretFunc: encryption.secp256k1SharedSecret },
      { name: 'p256', sharedSecretFunc: encryption.p256SharedSecret }
    ];

    for (const curve of curves) {
      console.log(`\n  Curve: ${curve.name}`);

      const keys = ecdhKeys[curve.name];
      const alicePriv = new Uint8Array(Buffer.from(keys.alice.private, 'hex'));
      const bobPub = new Uint8Array(Buffer.from(keys.bob.public, 'hex'));

      // Compute shared secret
      const sharedSecret = curve.sharedSecretFunc(alicePriv, bobPub);
      if (!sharedSecret) {
        console.log(`    ✗ Failed to compute shared secret`);
        continue;
      }

      // Derive encryption key and IV using HKDF
      // hkdf(ikm, salt, info, length)
      const keyMaterial = encryption.hkdf(
        sharedSecret,
        new Uint8Array(0),  // salt (empty)
        new TextEncoder().encode('E2E-Crypto-Test'),  // info
        48  // length (32 for key + 16 for IV)
      );
      const sessionKey = keyMaterial.slice(0, 32);
      const iv = keyMaterial.slice(32, 48);

      // Encrypt the simple message
      for (const msg of testMessages.slice(0, 3)) {  // Only first 3 messages per curve
        try {
          const jsonStr = JSON.stringify(msg.json);
          const buffer = flatc.generateBinary(schemaInput, jsonStr);
          // encryptBytes modifies data in-place, so make a copy
          const encrypted = new Uint8Array(buffer);
          encryption.encryptBytes(encrypted, sessionKey, iv);

          const filename = `secure_message_${msg.name}_${curve.name}.bin`;
          const filepath = join(binaryDir, filename);
          writeFileSync(filepath, Buffer.from(encrypted));

          // Also save the encryption header
          const header = {
            version: 1,
            key_exchange: 'ECDH',
            curve: curve.name,
            encryption: 'AES_256_CTR',
            ephemeral_public_key: keys.alice.public,
            sender_id: 'alice',
            timestamp: Date.now()
          };
          const headerPath = join(binaryDir, `secure_message_${msg.name}_${curve.name}_header.json`);
          writeFileSync(headerPath, JSON.stringify(header, null, 2));

          console.log(`    ✓ ${filename} (${encrypted.length} bytes)`);
          createdFiles.push({
            name: `${msg.name}_${curve.name}`,
            file: filename,
            size: encrypted.length,
            encrypted: true,
            curve: curve.name,
            header: `secure_message_${msg.name}_${curve.name}_header.json`
          });
        } catch (e) {
          console.log(`    ✗ ${msg.name}: ${e.message}`);
        }
      }
    }
  }

  // Write manifest of created files
  const manifest = {
    created: new Date().toISOString(),
    schema: 'schemas/message.fbs',
    messages: createdFiles
  };
  writeFileSync(join(vectorsDir, 'messages_manifest.json'), JSON.stringify(manifest, null, 2));

  // Summary
  console.log();
  console.log('='.repeat(60));
  console.log('Summary');
  console.log('='.repeat(60));
  console.log(`Created ${createdFiles.length} test files`);
  console.log(`  Unencrypted: ${createdFiles.filter(f => !f.encrypted).length}`);
  console.log(`  Encrypted: ${createdFiles.filter(f => f.encrypted).length}`);
  console.log();
  console.log('Files saved to: vectors/binary/');
  console.log('Manifest: vectors/messages_manifest.json');
}

main().catch(e => {
  console.error('Fatal error:', e);
  process.exit(1);
});
