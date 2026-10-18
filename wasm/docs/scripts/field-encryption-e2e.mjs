// E2E: the site seals fields to the signed-in wallet, and the wallet opens
// them after the user consents, only for this site and this account.
//
//   node wasm/docs/scripts/field-encryption-e2e.mjs [--root docs]
//
// wallet-fixture.mjs serves the site at https://digitalarsenal.github.io/flatbuffers/
// (the origin hd-wallet-ui 2.2.1 binds this site's client to), the published
// 2.2.1 wallet origin, and an in-memory relay, in Chromium's headless shell.
// The wallet is the throwaway vector account alice_01. The user signs in and
// approves through the wallet popup with real input events.
//
//  1. As published, the page keeps "Decrypt with wallet" off at the shared
//     github.io origin (signed in, fields sealed) and says why.
//  2. Served with SITE_ORIGIN set to the registered origin (the one line the
//     site's own domain will make true), the same page:
//     - seals every field to the wallet; Python `cryptography` and native
//       flatc C++ open them from the seed;
//     - Cancel in the wallet's consent opens nothing;
//     - after consent the wallet opens every field to the bytes Python opens;
//     - a message sealed to your wallet opens; one sealed to another account
//       of the wallet (pasted key) is refused, NOT_ADDRESSED_TO_ACCOUNT;
//     - a field bound to the flatsql site is refused by the client;
//     - the relay never holds a plaintext.
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { PAGES, SEED, answerWallet, fail, startWalletFixture } from './wallet-fixture.mjs';
import { encodeENC, fieldContext } from '../wallet-field-keys.mjs';

const here = path.dirname(new URL(import.meta.url).pathname);
const repo = path.resolve(here, '../../..');
const argRoot = process.argv.indexOf('--root');
const siteRoot = path.resolve(repo, argRoot > 0 ? process.argv[argRoot + 1] : 'docs');
const SITE_ORIGIN = 'https://flatbuffers.spacedatanetwork.org';
const checks = [];
const step = (message) => { if (process.env.E2E_TRACE) console.error(`  ..  ${message}`); };
const pass = (message) => { checks.push(message); console.log(`  ok  ${message}`); };

function python(account, fields) {
  const r = spawnSync('python3', ['-I', path.join(here, 'field_encryption_vector.py')], {
    input: JSON.stringify({ seedHex: SEED, account, fields }), encoding: 'utf8',
  });
  if (r.status !== 0) fail(`python: ${r.stderr}`);
  return JSON.parse(r.stdout);
}

function contactPrivateHex(account) {
  const r = spawnSync('python3', ['-I', '-c', `import sys,hmac,hashlib,struct
seed=bytes.fromhex(sys.argv[1]);d=hmac.new(b'ed25519 seed',seed,hashlib.sha512).digest();k,c=d[:32],d[32:]
for i in (44,0,int(sys.argv[2]),1,0):
  d=hmac.new(c,b'\\0'+k+struct.pack('>I',i|0x80000000),hashlib.sha512).digest();k,c=d[:32],d[32:]
print(k.hex())`, SEED, String(account)], { encoding: 'utf8' });
  return r.stdout.trim();
}

function nativeOpen(fields, privateHex) {
  const bin = path.join(os.tmpdir(), `field-encryption-native-${process.pid}`);
  const ssl = spawnSync('brew', ['--prefix', 'openssl@3'], { encoding: 'utf8' }).stdout?.trim() || '/usr';
  const cc = spawnSync('c++', ['-std=c++17', '-O1', '-DFLATBUFFERS_USE_OPENSSL', `-I${repo}/include`, `-I${ssl}/include`,
    path.join(here, 'field_encryption_native.cpp'), `${repo}/src/encryption.cpp`, `${repo}/src/reflection.cpp`,
    `-L${ssl}/lib`, '-lcrypto', '-o', bin], { encoding: 'utf8' });
  if (cc.status !== 0) fail(`native build: ${cc.stderr}`);
  try {
    return fields.map((f) => spawnSync(bin, [privateHex, f.encHex, f.ciphertextHex, String(f.fieldId)], { encoding: 'utf8' }).stdout.trim());
  } finally {
    fs.rmSync(bin, { force: true });
  }
}

// A field sealed in node (Unified ECIES, node:crypto) to `publicHex` under `context`.
function sealInNode(publicHex, context, fieldId, plaintext) {
  const der = (raw) => crypto.createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), raw]), format: 'der', type: 'spki' });
  const recipient = Buffer.from(publicHex, 'hex');
  const eph = crypto.generateKeyPairSync('x25519');
  const shared = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: der(recipient) });
  const master = Buffer.from(crypto.hkdfSync('sha256', shared, Buffer.alloc(0), Buffer.from(context), 32));
  const info = (label) => Buffer.concat([Buffer.from(label), Buffer.from([fieldId >> 8, fieldId & 255, 0, 0, 0, 0])]);
  const key = Buffer.from(crypto.hkdfSync('sha256', master, Buffer.alloc(0), info('flatbuffers-field'), 32));
  const iv = Buffer.from(crypto.hkdfSync('sha256', master, Buffer.alloc(0), info('flatbuffers-iv'), 16));
  const cipher = crypto.createCipheriv('aes-256-ctr', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const ephemeralPublicKey = eph.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const enc = encodeENC({ ephemeralPublicKey, nonceStart: crypto.randomBytes(12), recipientKeyId: crypto.createHash('sha256').update(recipient).digest().subarray(0, 8), context, rootType: 'cross' });
  return { encHex: Buffer.from(enc).toString('hex'), ciphertextHex: ciphertext.toString('hex'), context, fieldId };
}

let gateOn = false;
const fixture = await startWalletFixture({
  site: 'flatbuffers',
  siteRoot,
  rewrite: (file, body) => {
    if (!gateOn || file !== 'index.html') return body;
    const text = body.toString('utf8');
    if (text.split(SITE_ORIGIN).length !== 2) fail('the page does not name its own origin exactly once');
    return Buffer.from(text.replace(SITE_ORIGIN, PAGES));
  },
});

async function load(tab) {
  step('load');
  await tab.goto(`${PAGES}/flatbuffers/`);
  await tab.waitFor(`!!document.getElementById('generate-single') && document.querySelectorAll('#field-checkboxes .field-checkbox').length > 0`);
  await tab.waitFor(`!!document[Symbol.for('sdn.wallet.public-client.v1')]`);
  await new Promise((r) => setTimeout(r, 1500));
  const signedIn = `document.getElementById('field-wallet-status').textContent.startsWith('Fields are encrypted to your wallet')`;
  if (!(await tab.eval(signedIn))) {
    step('sign in');
    const popup = fixture.nextPopup();
    await tab.click('#field-sign-in');
    await answerWallet(await popup);
    await tab.waitFor(signedIn);
  }
}

async function sealRecord(tab) {
  step('seal record');
  await tab.click('#select-all-fields');
  await tab.click('#generate-single');
  await tab.waitFor(`document.querySelectorAll('#field-body tr[data-enc-hex]').length >= 3`);
  return tab.eval(`[...document.querySelectorAll('#field-body tr[data-enc-hex]')].map((tr) => ({
    fieldId: Number(tr.dataset.fieldId), plaintextHex: tr.dataset.plaintextHex,
    ciphertextHex: tr.dataset.ciphertextHex, encHex: tr.dataset.encHex }))`);
}

async function sealMessage(tab, recipientHex, message) {
  await tab.eval(`document.getElementById('send-recipient-key').value = ${JSON.stringify(recipientHex)}; document.getElementById('send-plaintext').value = ${JSON.stringify(message)};`);
  await tab.click('#send-seal');
  await tab.waitFor(`!document.getElementById('send-output').hidden && document.getElementById('send-output').dataset.plaintextHex === ${JSON.stringify(Buffer.from(message).toString('hex'))}`);
}

async function decryptMessage(tab) {
  const popup = fixture.nextPopup();
  await tab.click('#send-decrypt');
  await answerWallet(await popup);
  await tab.waitFor(`!document.getElementById('send-opened').hidden`);
  return tab.eval(`({ ...document.getElementById('send-opened').dataset })`);
}

try {
  const tab = await fixture.newTab();

  // 1. As published: off at the shared origin.
  await load(tab);
  await sealRecord(tab);
  await sealMessage(tab, '', 'off origin');
  const off = await tab.eval(`({ field: document.getElementById('field-decrypt').disabled, send: document.getElementById('send-decrypt').disabled,
    note: document.getElementById('field-open-note').textContent })`);
  if (!off.field || !off.send) fail('Decrypt with wallet is on at the shared github.io origin');
  if (!off.note.includes('off at this address') || !off.note.includes(SITE_ORIGIN)) fail(`off-origin note: ${off.note}`);
  pass(`as published, "Decrypt with wallet" stays off at ${PAGES} (signed in, fields sealed) and the page names ${SITE_ORIGIN}`);

  // 2. On the registered origin.
  gateOn = true;
  await load(tab);
  const fields = await sealRecord(tab);
  const fromSeed = python(0, fields);
  fields.forEach((f, i) => { if (fromSeed.fields[i].plaintextHex !== f.plaintextHex) fail(`Python did not open field ${f.fieldId}`); });
  const native = nativeOpen(fields, contactPrivateHex(0));
  fields.forEach((f, i) => { if (native[i] !== f.plaintextHex) fail(`native C++ did not open field ${f.fieldId}`); });
  if (!python(1, fields).fields.every((f) => f.refused)) fail('another account opened a field in Python');
  pass(`the page sealed ${fields.length} fields to the wallet; Python and native flatc C++ open all of them from the seed; account 1 cannot`);

  let popup = fixture.nextPopup();
  await tab.click('#field-decrypt');
  const heading = await answerWallet(await popup, { action: 'cancel' });
  if (!/^Open \d+ encrypted fields? for FlatBuffers Documentation$/u.test(heading)) fail(`consent heading: ${heading}`);
  await new Promise((r) => setTimeout(r, 2000));
  if (await tab.eval(`document.querySelectorAll('#field-body tr[data-opened-hex]').length`)) fail('fields opened after Cancel');
  if (fixture.relay.results('sdn.wallet.field-open.v1')) fail('the wallet answered after Cancel');
  pass(`the wallet asks first ("${heading}"); after Cancel nothing opens`);

  await tab.waitFor(`!document.getElementById('field-decrypt').disabled`);
  popup = fixture.nextPopup();
  await tab.click('#field-decrypt');
  await answerWallet(await popup, { remember: true });
  await tab.waitFor(`document.querySelectorAll('#field-body tr[data-opened-hex]').length === ${fields.length}`);
  const opened = await tab.eval(`[...document.querySelectorAll('#field-body tr[data-enc-hex]')].map((tr) => tr.dataset.openedHex)`);
  opened.forEach((hex, i) => { if (hex !== fromSeed.fields[i].plaintextHex) fail(`the wallet opened field ${fields[i].fieldId} to ${hex}`); });
  pass(`after consent the wallet opens all ${fields.length} fields to the plaintexts Python opens`);

  const message = 'meet at the ground station 0400Z';
  await sealMessage(tab, '', message);
  const own = await decryptMessage(tab);
  if (own.openedHex !== Buffer.from(message).toString('hex')) fail(`own message: ${JSON.stringify(own)}`);
  const account1 = python(1, []).publicKeyHex;
  await sealMessage(tab, account1, message);
  const sealedOther = await tab.eval(`({ ...document.getElementById('send-output').dataset })`);
  const other = await decryptMessage(tab);
  if (other.openedRefused !== 'NOT_ADDRESSED_TO_ACCOUNT') fail(`another account's message: ${JSON.stringify(other)}`);
  if (python(1, [{ ...sealedOther, fieldId: 0 }]).fields[0].plaintextHex !== Buffer.from(message).toString('hex')) fail('Python account 1 does not open its message');
  pass('a message sealed to your wallet opens; one sealed to another account (pasted key) is refused NOT_ADDRESSED_TO_ACCOUNT, and Python opens it as account 1');

  const crossSite = sealInNode(fromSeed.publicKeyHex, fieldContext('flatsql', 'Contact', 'email'), 2, Buffer.from('flatsql field'));
  const crossResult = await tab.eval(`(() => {
    const bytes = (h) => Uint8Array.from(h.match(/../g), (p) => parseInt(p, 16));
    const f = ${JSON.stringify(crossSite)};
    return document[Symbol.for('sdn.wallet.public-client.v1')].client
      .openFields({ fields: [{ enc: bytes(f.encHex), ciphertext: bytes(f.ciphertextHex), context: f.context, fieldId: f.fieldId }] })
      .then(() => 'opened', (e) => e?.code ?? String(e));
  })()`);
  if (crossResult !== 'INVALID_REQUEST') fail(`a flatsql-bound field on flatbuffers: ${crossResult}`);
  if (python(0, [crossSite]).fields[0].plaintextHex !== Buffer.from('flatsql field').toString('hex')) fail('Python does not open the cross-site field');
  pass('a field bound to the flatsql site is refused on flatbuffers (INVALID_REQUEST), though it is sealed to this account');

  const results = fixture.relay.results('sdn.wallet.field-open.v1');
  for (const f of fields) if (f.plaintextHex.length >= 8 && results.includes(f.plaintextHex)) fail('the relay holds a plaintext');
  if (results.includes(Buffer.from(message).toString('hex')) || results.includes(Buffer.from(message).toString('base64url'))) fail('the relay holds the message');
  pass('the relay holds only reply ciphertext');

  if (fixture.errors.length) fail(`page errors: ${fixture.errors.join(' | ')}`);
  console.log(`field-encryption E2E PASS (${checks.length} checks)`);
} finally {
  await fixture.close();
}
