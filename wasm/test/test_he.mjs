#!/usr/bin/env node
/**
 * HE package tests derived from tests/he_encryption_test.cpp.
 *
 * These cover the public JS HE wrapper against the shipped WASM package:
 * - client/server context creation and key exchange
 * - int64 and double round-trip encryption
 * - homomorphic add/sub/multiply/negate/plain ops
 * - conjunction assessment scenario from the upstream C++ tests
 */

import createFlatcWasm from '../dist/flatc-wasm.js';
import { HEContext, initHEModule } from '../src/index.mjs';

let passed = 0;
let failed = 0;
let flatcModule;

function log(msg) {
  console.log(msg);
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(`${message}: expected ${expected}, got ${actual}`);
  }
}

function assertClose(actual, expected, tolerance, message) {
  if (Math.abs(actual - expected) > tolerance) {
    throw new Error(`${message}: expected ~${expected}, got ${actual}`);
  }
}

function assertBytesEqual(actual, expected, message) {
  assert(actual.length === expected.length, `${message}: length mismatch`);
  for (let i = 0; i < actual.length; i++) {
    if (actual[i] !== expected[i]) {
      throw new Error(`${message}: mismatch at byte ${i}`);
    }
  }
}

function assertThrows(fn, expectedSubstring, message) {
  let threw = false;
  try {
    fn();
  } catch (err) {
    threw = true;
    if (expectedSubstring && !err.message.includes(expectedSubstring)) {
      throw new Error(`${message}: expected error containing "${expectedSubstring}", got "${err.message}"`);
    }
  }
  if (!threw) {
    throw new Error(`${message}: expected function to throw`);
  }
}

async function test(name, fn) {
  try {
    await fn();
    log(`  PASS: ${name}`);
    passed++;
  } catch (err) {
    log(`  FAIL: ${name} - ${err.message}`);
    failed++;
  }
}

async function main() {
  log('============================================================');
  log('Homomorphic Encryption Package Tests');
  log('Derived from tests/he_encryption_test.cpp');
  log('============================================================');

  flatcModule = await createFlatcWasm();
  initHEModule(flatcModule);

  await test('HE exports are present in the shipped module', async () => {
    assert(typeof flatcModule._wasm_he_context_create_client === 'function',
      'missing _wasm_he_context_create_client; build with FLATBUFFERS_WASM_ENABLE_HE=ON');
    assert(typeof flatcModule._wasm_he_encrypt_int64 === 'function',
      'missing _wasm_he_encrypt_int64');
  });

  await test('HEContext creation and key exchange', async () => {
    const client = HEContext.createClient();
    try {
      assertEqual(client.canDecrypt(), true, 'client should be able to decrypt');

      const publicKey = client.getPublicKey();
      const relinKeys = client.getRelinKeys();
      const secretKey = client.getSecretKey();

      assert(publicKey.length > 0, 'public key should not be empty');
      assert(relinKeys.length > 0, 'relin keys should not be empty');
      assert(secretKey.length > 0, 'secret key should not be empty');

      const server = HEContext.createServer(publicKey);
      try {
        assertEqual(server.canDecrypt(), false, 'server should not be able to decrypt');
        server.setRelinKeys(relinKeys);
        assertThrows(
          () => server.getSecretKey(),
          'server context',
          'server secret key access'
        );
      } finally {
        server.destroy();
      }
    } finally {
      client.destroy();
    }
  });

  await test('encrypt/decrypt round-trip mirrors upstream values', async () => {
    const client = HEContext.createClient();
    try {
      const positive = 12345n;
      const negative = -98765n;
      const floating = 3.14159;

      assertEqual(client.decryptInt64(client.encryptInt64(positive)), positive, 'positive int64 round-trip');
      assertEqual(client.decryptInt64(client.encryptInt64(negative)), negative, 'negative int64 round-trip');
      assertClose(client.decryptDouble(client.encryptDouble(floating)), floating, 0.0001, 'double round-trip');
    } finally {
      client.destroy();
    }
  });

  await test('homomorphic operations match upstream expectations', async () => {
    const client = HEContext.createClient();
    try {
      const server = HEContext.createServer(client.getPublicKey());
      try {
        server.setRelinKeys(client.getRelinKeys());

        const ct42 = client.encryptInt64(42n);
        const ct10 = client.encryptInt64(10n);

        assertEqual(client.decryptInt64(server.add(ct42, ct10)), 52n, '42 + 10');
        assertEqual(client.decryptInt64(server.sub(ct42, ct10)), 32n, '42 - 10');
        assertEqual(client.decryptInt64(server.multiply(ct42, ct10)), 420n, '42 * 10');
        assertEqual(client.decryptInt64(server.negate(ct10)), -10n, 'negate 10');
        assertEqual(client.decryptInt64(server.addPlain(ct42, 8n)), 50n, '42 + 8');
        assertEqual(client.decryptInt64(server.multiplyPlain(ct42, 3n)), 126n, '42 * 3');
      } finally {
        server.destroy();
      }
    } finally {
      client.destroy();
    }
  });

  await test('seeded contexts are deterministic like the upstream HE test', async () => {
    const seed = new Uint8Array(32);
    for (let i = 0; i < seed.length; i++) {
      seed[i] = i + 1;
    }

    const client1 = HEContext.createClientFromSeed(seed);
    const client2 = HEContext.createClientFromSeed(seed);
    try {
      assertBytesEqual(client1.getPublicKey(), client2.getPublicKey(), 'public keys');
      assertBytesEqual(client1.getRelinKeys(), client2.getRelinKeys(), 'relin keys');
      assertBytesEqual(client1.getSecretKey(), client2.getSecretKey(), 'secret keys');

      const ciphertext = client1.encryptInt64(77n);
      assertEqual(client2.decryptInt64(ciphertext), 77n, 'cross-context decrypt');

      const otherSeed = seed.slice();
      otherSeed[0] ^= 0xff;
      const client3 = HEContext.createClientFromSeed(otherSeed);
      try {
        let identical = client1.getPublicKey().length === client3.getPublicKey().length;
        if (identical) {
          for (let i = 0; i < client1.getPublicKey().length; i++) {
            if (client1.getPublicKey()[i] !== client3.getPublicKey()[i]) {
              identical = false;
              break;
            }
          }
        }
        assert(!identical, 'different seed should produce a different public key');
      } finally {
        client3.destroy();
      }
    } finally {
      client1.destroy();
      client2.destroy();
    }
  });

  await test('conjunction assessment scenario matches upstream result', async () => {
    const assessor = HEContext.createClient();
    try {
      const server = HEContext.createServer(assessor.getPublicKey());
      try {
        server.setRelinKeys(assessor.getRelinKeys());

        const satAX = [6700n, 6695n, 6680n, 6650n, 6610n];
        const satAY = [0n, 100n, 200n, 300n, 400n];
        const satAZ = [0n, 50n, 100n, 150n, 200n];

        const satBX = [6750n, 6700n, 6640n, 6570n, 6490n];
        const satBY = [-50n, 95n, 190n, 280n, 370n];
        const satBZ = [30n, 48n, 70n, 90n, 110n];

        const expectedDist2 = [5900n, 54n, 2600n, 10400n, 23400n];
        const thresholdSq = 225n;

        let conjunctionDetected = false;
        let conjunctionStep = -1;

        for (let i = 0; i < expectedDist2.length; i++) {
          const dx = server.sub(assessor.encryptInt64(satAX[i]), assessor.encryptInt64(satBX[i]));
          const dy = server.sub(assessor.encryptInt64(satAY[i]), assessor.encryptInt64(satBY[i]));
          const dz = server.sub(assessor.encryptInt64(satAZ[i]), assessor.encryptInt64(satBZ[i]));

          const dx2 = server.multiply(dx, dx);
          const dy2 = server.multiply(dy, dy);
          const dz2 = server.multiply(dz, dz);

          const partial = server.add(dx2, dy2);
          const dist2 = assessor.decryptInt64(server.add(partial, dz2));

          assertEqual(dist2, expectedDist2[i], `distance^2 at step ${i}`);

          if (!conjunctionDetected && dist2 < thresholdSq) {
            conjunctionDetected = true;
            conjunctionStep = i;
          }
        }

        assert(conjunctionDetected, 'conjunction should be detected');
        assertEqual(conjunctionStep, 1, 'closest approach step');
      } finally {
        server.destroy();
      }
    } finally {
      assessor.destroy();
    }
  });

  log('============================================================');
  log(`Results: ${passed} passed, ${failed} failed`);
  log('============================================================');

  process.exit(failed > 0 ? 1 : 0);
}

await main();
