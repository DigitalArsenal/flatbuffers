// E2E: the field-encryption demo seals fields to the signed-in wallet, and
// code outside the browser opens them.
//
//   node wasm/docs/scripts/field-encryption-e2e.mjs [--root docs]
//
// The site is served under /flatbuffers/ and loaded in Chromium's headless
// shell with a throwaway test wallet: the public identity of the published
// hd-wallet-wasm vector account alice_01 (test/fixtures/sdn-wallet-vectors.v1.json),
// handed to the page the way the SDN stack nav hands it the wallet client.
// The page gets only public keys. Then:
//   - signed out, Generate seals nothing and asks for sign-in;
//   - two page sessions seal every field; Python `cryptography`
//     (field_encryption_vector.py) opens each from the wallet seed;
//   - native flatc C++ (field_encryption_native.cpp, OpenSSL backend) opens them;
//   - another account of the same wallet is refused.
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';

const here = path.dirname(new URL(import.meta.url).pathname);
const repo = path.resolve(here, '../../..');
const argRoot = process.argv.indexOf('--root');
const siteRoot = path.resolve(repo, argRoot > 0 ? process.argv[argRoot + 1] : 'docs');

const SEED = 'c63fbe791b92d91eb828eab4b203cffe7f333e9d200ec2355d77c7796c080f79c9ed753af213bf155512e3c667c3be26a22c1c599cbae52cb44add279559fe5b';
const IDENTITY = {
  schemaVersion: 1,
  identityScheme: 'sdn-bip32-slip10-purpose-v1',
  seedProfile: 'password-scrypt-v2',
  accountIndex: 0,
  accountLabel: null,
  accountXpub: 'xpub6D9SXNXfAWtnHw8uWqUwMCBFh4R5bvzzWWemXtzwNhojQnYXyQARwhphkvtN4AJ93QFhzzHQZHj7MYQ7KuQ8vsXiTEwUq6MiF7iaLXTPFRT',
  accountPeerId: '16Uiu2HAkzgWPa6HTtNTU8WQi1kppaRsYUDBxNKygQNYUk7N73CMA',
  accountFingerprint: '9b582711',
  keys: [{
    purpose: 'contact-encryption', identityScheme: 'sdn-bip32-slip10-purpose-v1', seedProfile: 'password-scrypt-v2',
    signatureProfile: null, curve: 'x25519', derivation: 'slip10', path: "m/44'/0'/0'/1'/0'", encoding: 'raw',
    publicKeyHex: '1349c6136a8765e4b2a8795037cc6233e22d31a08c76e328ad247daf836c6c0c', bip32Fingerprint: null,
    keyId: 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
  }],
};

function fail(message) {
  console.error(`field-encryption E2E FAIL: ${message}`);
  process.exit(1);
}

function headlessShell() {
  if (process.env.GAUNTLET_HEADLESS_SHELL) return process.env.GAUNTLET_HEADLESS_SHELL;
  const cache = process.env.PLAYWRIGHT_BROWSERS_PATH || path.join(os.homedir(), 'Library', 'Caches', 'ms-playwright');
  const dirs = fs.readdirSync(cache).filter((d) => /^chromium_headless_shell-\d+$/.test(d))
    .sort((a, b) => Number(b.split('-')[1]) - Number(a.split('-')[1]));
  for (const dir of dirs) {
    for (const sub of fs.readdirSync(path.join(cache, dir))) {
      const bin = path.join(cache, dir, sub, 'chrome-headless-shell');
      if (fs.existsSync(bin)) return bin;
    }
  }
  fail('no chromium headless shell');
}

const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.wasm': 'application/wasm', '.json': 'application/json' };
function serve() {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    if (!url.pathname.startsWith('/flatbuffers/')) { res.writeHead(404).end(); return; }
    let file = path.join(siteRoot, decodeURIComponent(url.pathname.slice('/flatbuffers/'.length)));
    if (!file.startsWith(siteRoot)) { res.writeHead(403).end(); return; }
    if (fs.existsSync(file) && fs.statSync(file).isDirectory()) file = path.join(file, 'index.html');
    if (!fs.existsSync(file)) { res.writeHead(404).end(); return; }
    res.writeHead(200, { 'content-type': TYPES[path.extname(file)] || 'application/octet-stream' });
    fs.createReadStream(file).pipe(res);
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

// The wallet record the SDN stack nav would publish, holding the test identity.
function walletScript(identity) {
  return `(() => {
    const snapshot = Object.freeze({ status: 'connected', identity: ${JSON.stringify(identity)} });
    const client = Object.freeze({
      connect: async () => snapshot.identity, openAccount: async () => {}, disconnect: async () => {},
      destroy: async () => {}, getSnapshot: () => snapshot, subscribe: () => () => {},
    });
    Object.defineProperty(document, Symbol.for('sdn.wallet.public-client.v1'), {
      configurable: false, enumerable: false, writable: false,
      value: Object.freeze({ identity: 'sdn.wallet.public-client.document.v1', client,
        addPresenter() {}, getSnapshot: () => snapshot }),
    });
  })();`;
}

class Page {
  static async open(port) {
    const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    const page = new Page(targets.find((t) => t.type === 'page').webSocketDebuggerUrl);
    await new Promise((resolve, reject) => { page.ws.onopen = resolve; page.ws.onerror = reject; });
    return page;
  }
  constructor(url) {
    this.ws = new WebSocket(url);
    this.next = 1;
    this.pending = new Map();
    this.errors = [];
    this.ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        msg.error ? reject(new Error(msg.error.message)) : resolve(msg.result);
      } else if (msg.method === 'Runtime.exceptionThrown') {
        this.errors.push(msg.params.exceptionDetails.exception?.description || msg.params.exceptionDetails.text);
      }
    };
  }
  send(method, params = {}) {
    const id = this.next++;
    this.ws.send(JSON.stringify({ id, method, params }));
    return new Promise((resolve, reject) => this.pending.set(id, { resolve, reject }));
  }
  async eval(expression) {
    const r = await this.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text);
    return r.result.value;
  }
  async waitFor(expression, ms = 60000) {
    const end = Date.now() + ms;
    while (Date.now() < end) {
      if (await this.eval(expression).catch(() => false)) return;
      await new Promise((r) => setTimeout(r, 250));
    }
    fail(`timed out waiting for ${expression}`);
  }
}

// One page session: load, wait for the compiler, select every field, generate.
async function session(page, origin, signedIn) {
  const script = signedIn ? await page.send('Page.addScriptToEvaluateOnNewDocument', { source: walletScript(IDENTITY) }) : null;
  await page.send('Page.navigate', { url: `${origin}/flatbuffers/` });
  await page.waitFor(`document.readyState === 'complete' && !!document.getElementById('generate-single')`);
  await page.waitFor(`document.querySelectorAll('#field-checkboxes .field-checkbox').length > 0`);
  await new Promise((r) => setTimeout(r, 1500));
  await page.eval(`document.getElementById('select-all-fields').click()`);
  await page.eval(`document.getElementById('generate-single').click()`);
  await new Promise((r) => setTimeout(r, 1500));
  const result = await page.eval(`({
    status: document.getElementById('field-wallet-status').textContent,
    fields: [...document.querySelectorAll('#field-body tr[data-enc-hex]')].map((tr) => ({
      fieldId: Number(tr.dataset.fieldId), plaintextHex: tr.dataset.plaintextHex,
      ciphertextHex: tr.dataset.ciphertextHex, encHex: tr.dataset.encHex })),
  })`);
  if (script) await page.send('Page.removeScriptToEvaluateOnNewDocument', { identifier: script.identifier });
  return result;
}

function python(account, fields) {
  const r = spawnSync('python3', ['-I', path.join(here, 'field_encryption_vector.py')], {
    input: JSON.stringify({ seedHex: SEED, account, fields }), encoding: 'utf8',
  });
  if (r.status !== 0) fail(`python: ${r.stderr}`);
  return JSON.parse(r.stdout);
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

const server = await serve();
const origin = `http://127.0.0.1:${server.address().port}`;
const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'field-encryption-e2e-'));
const port = 9300 + (process.pid % 500);
const browser = spawn(headlessShell(), [`--remote-debugging-port=${port}`, `--user-data-dir=${profile}`, '--no-first-run', 'about:blank'], { stdio: 'ignore' });
try {
  let page;
  for (let i = 0; i < 40 && !page; i += 1) {
    page = await Page.open(port).catch(() => null);
    if (!page) await new Promise((r) => setTimeout(r, 250));
  }
  if (!page) fail('headless shell did not start');
  await page.send('Runtime.enable');
  await page.send('Page.enable');

  const signedOut = await session(page, origin, false);
  if (signedOut.fields.length !== 0) fail('signed out, the page sealed fields');
  if (!/sign in/iu.test(signedOut.status)) fail(`signed out, the page did not ask for sign-in: ${signedOut.status}`);

  const first = await session(page, origin, true);
  const second = await session(page, origin, true);
  const fields = [...first.fields, ...second.fields];
  if (first.fields.length < 3 || second.fields.length !== first.fields.length) fail(`sealed ${first.fields.length}/${second.fields.length} fields`);
  if (first.fields[0].ciphertextHex === second.fields[0].ciphertextHex) fail('two sessions produced the same ciphertext (ephemeral key reused)');

  const opened = python(0, fields);
  if (opened.publicKeyHex !== IDENTITY.keys[0].publicKeyHex) fail('Python derives a different wallet key');
  fields.forEach((f, i) => {
    if (opened.fields[i].plaintextHex !== f.plaintextHex) fail(`Python did not open field ${f.fieldId}: ${JSON.stringify(opened.fields[i])}`);
  });
  const other = python(1, fields);
  if (!other.fields.every((f) => f.refused)) fail('another wallet account opened a field');

  const derive = spawnSync('python3', ['-I', '-c', `import sys,hmac,hashlib,struct
seed=bytes.fromhex(sys.argv[1]);d=hmac.new(b'ed25519 seed',seed,hashlib.sha512).digest();k,c=d[:32],d[32:]
for i in (44,0,0,1,0):
  d=hmac.new(c,b'\\0'+k+struct.pack('>I',i|0x80000000),hashlib.sha512).digest();k,c=d[:32],d[32:]
print(k.hex())`, SEED], { encoding: 'utf8' }).stdout.trim();
  const native = nativeOpen(fields, derive);
  fields.forEach((f, i) => { if (native[i] !== f.plaintextHex) fail(`native C++ did not open field ${f.fieldId}: ${native[i]}`); });
  if (page.errors.length) fail(`page errors: ${page.errors.join(' | ')}`);
  console.log(`field-encryption E2E PASS: ${fields.length} fields over two sessions opened by Python and native flatc C++; another account refused; signed out seals nothing`);
} finally {
  browser.kill();
  server.close();
  fs.rmSync(profile, { recursive: true, force: true });
}
