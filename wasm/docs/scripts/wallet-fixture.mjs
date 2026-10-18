// A local wallet origin and relay for the site's E2E, in Chromium's headless
// shell over the DevTools protocol.
//
// The page is served at https://digitalarsenal.github.io/<site>/, the origin
// the hd-wallet-ui 2.2.1 registry binds the site's client to. The wallet
// origin https://wallet.spacedatanetwork.org serves the published 2.2.1
// wallet-origin bundle (npm tarball, integrity pinned; every file checked
// against its integrity.json). The relay is an in-memory store with the
// registry binding of the site's client: the wallet origin and its native
// code do the validation, as in production. Every request is answered here;
// nothing reaches the network.
//
// Clicks and typing are real input events (Input.dispatchMouseEvent,
// Input.insertText): the wallet acts only on trusted events.
import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const WALLET = 'https://wallet.spacedatanetwork.org';
export const PAGES = 'https://digitalarsenal.github.io';
export const USERNAME = 'alice_01';
// The published throwaway vector account (hd-wallet test/fixtures/sdn-wallet-vectors.v1.json).
export const PASSWORD = 'Correct Horse Battery Staple!';
export const SEED = 'c63fbe791b92d91eb828eab4b203cffe7f333e9d200ec2355d77c7796c080f79c9ed753af213bf155512e3c667c3be26a22c1c599cbae52cb44add279559fe5b';

const PACKAGE = 'hd-wallet-ui@2.2.1';
const PACKAGE_INTEGRITY = 'sha512-RKuESVQSbGfVHD5WzG1O1Ft1Apa1AxYQp0hs2amKlRfvlqGjoZy5kqeMVCcjyFnv1E/Goa6qWkF0WoKKtszGKQ==';
const REGISTRY_RELEASE = '63784143e2ad8e2542d22148ff4a0a4da7a10f4b3f9909ae91a20dc0f60db06b';
const CLIENTS = {
  'sdn-flatbuffers-pages-v1': { site: 'flatbuffers', name: 'FlatBuffers Documentation' },
  'sdn-flatsql-pages-v1': { site: 'flatsql', name: 'FlatSQL Documentation' },
};
const TYPES = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.wasm': 'application/wasm', '.json': 'application/json', '.svg': 'image/svg+xml',
  '.png': 'image/png', '.webp': 'image/webp', '.mp4': 'video/mp4', '.woff2': 'font/woff2',
};
const WALLET_HEADERS = {
  'cross-origin-embedder-policy': 'require-corp', 'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin', 'referrer-policy': 'no-referrer', 'x-frame-options': 'DENY',
};

export function fail(message) {
  console.error(`E2E FAIL: ${message}`);
  process.exit(1);
}

// The published wallet-origin bundle, every file checked.
function walletOriginFiles(scratch) {
  const pack = spawnSync('npm', ['pack', PACKAGE, '--json', '--pack-destination', scratch], { encoding: 'utf8' });
  if (pack.status !== 0) fail(`npm pack ${PACKAGE}: ${pack.stderr}`);
  const [{ filename, integrity }] = JSON.parse(pack.stdout);
  if (integrity !== PACKAGE_INTEGRITY) fail(`${PACKAGE} integrity ${integrity}`);
  const tarball = path.join(scratch, filename);
  const digest = `sha512-${createHash('sha512').update(fs.readFileSync(tarball)).digest('base64')}`;
  if (digest !== PACKAGE_INTEGRITY) fail(`${PACKAGE} tarball digest ${digest}`);
  if (spawnSync('tar', ['xzf', tarball, '-C', scratch]).status !== 0) fail('tar');
  const host = path.join(scratch, 'package/dist/wallet-origin-host');
  const files = new Map();
  for (const [name, { sha256 }] of Object.entries(JSON.parse(fs.readFileSync(path.join(host, 'integrity.json'), 'utf8')).files)) {
    const body = fs.readFileSync(path.join(host, name));
    if (createHash('sha256').update(body).digest('hex') !== sha256) fail(`wallet origin ${name} digest`);
    files.set(`/${name}`, body);
  }
  return files;
}

// The relay: transactions, results and code redemption, in memory.
class Relay {
  constructor() {
    this.transactions = new Map();
  }

  reply(status, body, origin) {
    return {
      status,
      headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...(origin ? { 'access-control-allow-origin': origin, vary: 'Origin' } : {}) },
      body: body === null ? '' : JSON.stringify(body),
    };
  }

  handle(method, pathname, origin, text) {
    if (method === 'OPTIONS') {
      return { status: 204, headers: { 'access-control-allow-origin': origin ?? '*', 'access-control-allow-methods': 'POST', 'access-control-allow-headers': 'content-type' }, body: '' };
    }
    if (method === 'POST' && pathname === '/relay/v1/transactions') {
      const body = JSON.parse(text);
      const client = CLIENTS[body.clientId];
      if (!client || origin !== PAGES) return this.reply(400, { error: 'unregistered' }, origin);
      const expiresAt = new Date(Date.now() + 300_000).toISOString();
      this.transactions.set(body.transactionId, {
        codeChallenge: body.codeChallenge,
        public: {
          callbackUri: `${PAGES}/${client.site}/wallet-callback.html`, clientDisplayName: client.name, clientId: body.clientId,
          expiresAt, operation: body.operation, registryVersion: REGISTRY_RELEASE, request: body.request,
          requestOrigin: PAGES, requestSha256: createHash('sha256').update(jcs(body.request)).digest('hex'),
          resultToken: randomBytes(32).toString('base64url'), schemaVersion: 1, state: body.state, transactionId: body.transactionId,
        },
        result: null, resultText: null, code: null,
      });
      return this.reply(201, { expiresAt, schemaVersion: 1, transactionId: body.transactionId }, origin);
    }
    let match = /^\/relay\/v1\/transactions\/([0-9a-f]{64})$/u.exec(pathname);
    if (method === 'GET' && match) {
      const record = this.transactions.get(match[1]);
      return record ? this.reply(200, record.public) : this.reply(404, { error: 'not found' });
    }
    match = /^\/relay\/v1\/transactions\/([0-9a-f]{64})\/result$/u.exec(pathname);
    if (method === 'POST' && match) {
      const record = this.transactions.get(match[1]);
      const body = JSON.parse(text);
      if (!record || record.result || body.resultToken !== record.public.resultToken) return this.reply(400, { error: 'binding' });
      record.result = body.result;
      record.resultText = text;
      record.code = randomBytes(32).toString('hex');
      return this.reply(201, { redirectUri: `${record.public.callbackUri}#code=${record.code}&state=${record.public.state}`, schemaVersion: 1, transactionId: match[1] });
    }
    if (method === 'POST' && pathname === '/relay/v1/codes/redeem') {
      const body = JSON.parse(text);
      const record = this.transactions.get(body.transactionId);
      if (!record?.result || body.code !== record.code || body.state !== record.public.state
          || createHash('sha256').update(body.codeVerifier).digest('base64url') !== record.codeChallenge) {
        return this.reply(400, { error: 'binding' }, origin);
      }
      return this.reply(200, { result: record.result, schemaVersion: 1, transactionId: body.transactionId }, origin);
    }
    match = /^\/relay\/v1\/transactions\/([0-9a-f]{64})\/cancel$/u.exec(pathname);
    if (method === 'POST' && match) return { status: 204, headers: origin ? { 'access-control-allow-origin': origin } : {}, body: '' };
    return this.reply(404, { error: 'not found' });
  }

  /** Every result body the wallet posted for `operation`, as text. */
  results(operation) {
    return [...this.transactions.values()].filter((record) => record.public.operation === operation)
      .map((record) => record.resultText).filter(Boolean).join('\n');
  }
}

// RFC 8785 canonical JSON for the plain request objects the client sends.
function jcs(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${jcs(value[key])}`).join(',')}}`;
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
  return fail('no chromium headless shell');
}

/** One attached page (a CDP session). */
class Tab {
  constructor(browser, sessionId, targetId) {
    this.browser = browser;
    this.sessionId = sessionId;
    this.targetId = targetId;
    this.closed = false;
  }

  send(method, params) {
    return this.browser.send(method, params, this.sessionId);
  }

  async eval(expression) {
    const r = await this.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text);
    return r.result.value;
  }

  async waitFor(expression, ms = 90_000) {
    const end = Date.now() + ms;
    while (Date.now() < end) {
      if (this.closed) throw new Error(`page closed waiting for ${expression}`);
      if (await this.eval(expression).catch(() => false)) return;
      await new Promise((r) => setTimeout(r, 200));
    }
    throw new Error(`timed out waiting for ${expression}`);
  }

  async goto(url) {
    await this.send('Page.navigate', { url });
    await this.waitFor(`document.readyState === 'complete'`);
  }

  /** A trusted click at the center of the element `selector` finds. */
  async click(selector) {
    await this.waitFor(`(() => { const e = document.querySelector(${JSON.stringify(selector)}); return !!e && !e.disabled && e.getClientRects().length > 0; })()`);
    const box = await this.eval(`new Promise((resolve) => {
      const e = document.querySelector(${JSON.stringify(selector)});
      e.scrollIntoView({ block: 'center', behavior: 'instant' });
      requestAnimationFrame(() => requestAnimationFrame(() => {
        const r = e.getBoundingClientRect();
        const x = r.left + r.width / 2;
        const y = r.top + r.height / 2;
        const hit = document.elementFromPoint(x, y);
        resolve({ x, y, ok: hit === e || e.contains(hit) || (e.labels && [...e.labels].some((l) => l.contains(hit))) });
      }));
    })`);
    if (!box.ok) throw new Error(`${selector} is covered at its center`);
    for (const type of ['mousePressed', 'mouseReleased']) {
      await this.send('Input.dispatchMouseEvent', { type, x: box.x, y: box.y, button: 'left', clickCount: 1 });
    }
  }

  /** Trusted typing into the element `selector` finds. */
  async type(selector, text) {
    await this.click(selector);
    await this.send('Input.insertText', { text });
  }
}

/**
 * Start the browser with the site at PAGES/<site>/ from siteRoot. `rewrite`
 * (optional) maps a served page path and its bytes to the bytes to serve.
 */
export async function startWalletFixture({ site, siteRoot, rewrite = null }) {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), `${site}-wallet-e2e-`));
  const walletFiles = walletOriginFiles(scratch);
  const relay = new Relay();
  const profile = path.join(scratch, 'profile');
  const port = 9300 + (process.pid % 500);
  const proc = spawn(headlessShell(), [`--remote-debugging-port=${port}`, `--user-data-dir=${profile}`, '--no-first-run', 'about:blank'], { stdio: 'ignore' });
  let version = null;
  for (let i = 0; i < 60 && !version; i += 1) {
    version = await fetch(`http://127.0.0.1:${port}/json/version`).then((r) => r.json()).catch(() => null);
    if (!version) await new Promise((r) => setTimeout(r, 250));
  }
  if (!version) fail('headless shell did not start');
  const ws = new WebSocket(version.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });

  let next = 1;
  const pending = new Map();
  const tabs = new Map();
  const errors = [];
  const handedOut = new Set();
  const browser = {
    send(method, params = {}, sessionId = undefined) {
      const id = next++;
      ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
      return new Promise((resolve, reject) => pending.set(id, { resolve, reject }));
    },
  };

  const serveSite = (pathname) => {
    const prefix = `/${site}/`;
    if (!pathname.startsWith(prefix)) return null;
    let file = path.join(siteRoot, decodeURIComponent(pathname.slice(prefix.length)));
    if (!file.startsWith(siteRoot)) return null;
    if (fs.existsSync(file) && fs.statSync(file).isDirectory()) file = path.join(file, 'index.html');
    if (!fs.existsSync(file)) return null;
    let body = fs.readFileSync(file);
    if (rewrite) body = rewrite(path.relative(siteRoot, file), body);
    return { status: 200, headers: { 'content-type': TYPES[path.extname(file)] || 'application/octet-stream' }, body };
  };

  const answer = (request) => {
    const url = new URL(request.url);
    const origin = request.headers.Origin ?? request.headers.origin ?? null;
    if (url.origin === WALLET && url.pathname.startsWith('/relay/v1/')) {
      const text = request.postDataEntries ? Buffer.concat(request.postDataEntries.map((e) => Buffer.from(e.bytes ?? '', 'base64'))).toString('utf8') : request.postData;
      const r = relay.handle(request.method, url.pathname, origin, text);
      return { ...r, headers: { ...WALLET_HEADERS, ...r.headers, 'cross-origin-resource-policy': 'cross-origin' } };
    }
    if (url.origin === WALLET) {
      const file = /^\/transaction\/[0-9a-f]{64}$/u.test(url.pathname) ? '/index.html' : url.pathname;
      const body = walletFiles.get(file);
      if (!body) return { status: 404, headers: {}, body: '' };
      return { status: 200, headers: { ...WALLET_HEADERS, 'content-type': TYPES[path.extname(file)] }, body };
    }
    if (url.origin === PAGES) return serveSite(url.pathname) ?? { status: 404, headers: {}, body: '' };
    return { status: 404, headers: {}, body: '' };
  };

  async function attached({ sessionId, targetInfo, waitingForDebugger }) {
    if (process.env.E2E_TRACE_NET) console.error(`  attach ${targetInfo.type} ${targetInfo.url.slice(0, 60)} waiting=${waitingForDebugger} [${sessionId.slice(0, 6)}]`);
    // Sent together: a target paused at start answers some domains only
    // after it runs.
    const setup = [
      browser.send('Fetch.enable', { patterns: [{ urlPattern: '*', requestStage: 'Request' }] }, sessionId),
      browser.send('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: true }, sessionId),
    ];
    if (targetInfo.type === 'page') {
      tabs.set(sessionId, new Tab(browser, sessionId, targetInfo.targetId));
      setup.push(browser.send('Runtime.enable', {}, sessionId), browser.send('Page.enable', {}, sessionId));
    }
    if (waitingForDebugger) setup.push(browser.send('Runtime.runIfWaitingForDebugger', {}, sessionId));
    await Promise.allSettled(setup);
  }

  ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if (msg.id && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? reject(new Error(msg.error.message)) : resolve(msg.result);
      return;
    }
    if (msg.method === 'Target.attachedToTarget') attached(msg.params).catch((e) => errors.push(`attach: ${e.message}`));
    else if (msg.method === 'Target.detachedFromTarget') {
      const tab = tabs.get(msg.params.sessionId);
      if (tab) tab.closed = true;
    } else if (msg.method === 'Fetch.requestPaused') {
      const r = answer(msg.params.request);
      if (process.env.E2E_TRACE_NET) console.error(`  net ${msg.params.request.method} ${msg.params.request.url.slice(0, 90)} -> ${r.status} [${msg.sessionId?.slice(0, 6)}]`);
      const body = Buffer.isBuffer(r.body) ? r.body : Buffer.from(r.body ?? '');
      browser.send('Fetch.fulfillRequest', {
        requestId: msg.params.requestId, responseCode: r.status,
        responseHeaders: Object.entries(r.headers).map(([name, value]) => ({ name, value: String(value) })),
        body: body.toString('base64'),
      }, msg.sessionId).catch(() => {});
    } else if (msg.method === 'Runtime.exceptionThrown') {
      const tab = tabs.get(msg.sessionId);
      if (tab) errors.push(msg.params.exceptionDetails.exception?.description || msg.params.exceptionDetails.text);
    }
  };

  await browser.send('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: true });

  return {
    relay,
    errors,
    browser,
    tabs,
    async newTab() {
      const { targetId } = await browser.send('Target.createTarget', { url: 'about:blank' });
      for (let i = 0; i < 100; i += 1) {
        const tab = [...tabs.values()].find((t) => t.targetId === targetId);
        if (tab) return tab;
        await new Promise((r) => setTimeout(r, 50));
      }
      return fail('new tab did not attach');
    },
    async closeTab(tab) {
      await browser.send('Target.closeTarget', { targetId: tab.targetId }).catch(() => {});
    },
    /**
     * The next wallet page: a page on the wallet origin this fixture has not
     * handed out yet. (Its cross-origin-opener-policy puts the wallet in a
     * new browsing context group, so it is a new target, not the popup the
     * page opened.)
     */
    async nextPopup() {
      for (let i = 0; i < 600; i += 1) {
        const { targetInfos } = await browser.send('Target.getTargets');
        const info = targetInfos.find((t) => t.type === 'page' && t.url.startsWith(WALLET) && !handedOut.has(t.targetId));
        const tab = info && [...tabs.values()].find((t) => t.targetId === info.targetId && !t.closed);
        if (tab) {
          handedOut.add(info.targetId);
          return tab;
        }
        await new Promise((r) => setTimeout(r, 200));
      }
      return fail('no wallet popup opened');
    },
    async close() {
      const exited = new Promise((resolve) => proc.once('exit', resolve));
      proc.kill();
      await exited;
      fs.rmSync(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
    },
  };
}

/**
 * Drive a wallet popup: log in when it asks, then answer its confirmation
 * with `action` ('confirm' or 'cancel'), checking "Don't ask again" when
 * `remember`. Returns the confirmation heading ('' when none was asked).
 */
export async function answerWallet(popup, { action = 'confirm', remember = false } = {}) {
  const state = `(() => {
    if (document.querySelector('section.wallet-confirmation')) return 'confirm';
    if (document.querySelector('input[name="password"]')) return 'login';
    return '';
  })()`;
  const trace = (m) => { if (process.env.E2E_TRACE) console.error(`  ..  wallet: ${m}`); };
  trace('popup');
  await popup.waitFor(`${state} !== ''`);
  trace(await popup.eval(state));
  if (await popup.eval(state) === 'login') {
    await popup.type('input[name="username"]', USERNAME);
    await popup.type('input[name="password"]', PASSWORD);
    await popup.click('button[data-wallet-action="login"]');
  }
  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    if (popup.closed) return '';
    const now = await popup.eval(state).catch(() => '');
    if (now === 'confirm') break;
    await new Promise((r) => setTimeout(r, 250));
  }
  if (popup.closed) return '';
  const heading = await popup.eval(`document.getElementById('wallet-confirmation-heading')?.textContent ?? ''`);
  if (remember) await popup.click('input[data-wallet-control="remember-site"]');
  await popup.click(`section.wallet-confirmation button[data-wallet-action="${action}"]`);
  return heading;
}
