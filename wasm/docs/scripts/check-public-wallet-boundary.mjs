import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const argumentsSet = new Set(process.argv.slice(2));
for (const argument of argumentsSet) {
  if (argument !== "--safe-baseline") throw new Error(`unknown argument: ${argument}`);
}
const safeBaseline = argumentsSet.has("--safe-baseline");
const root = resolve(import.meta.dirname, "..");
const repositoryRoot = resolve(root, "../..");
const html = readFileSync(resolve(root, "index.html"), "utf8");
const app = readFileSync(resolve(root, "app.mjs"), "utf8");
const packageJson = readFileSync(resolve(root, "package.json"), "utf8");
const packageLock = readFileSync(resolve(root, "package-lock.json"), "utf8");
const workflow = readFileSync(resolve(repositoryRoot, ".github/workflows/docs.yml"), "utf8");
const scanned = `${html}\n${app}\n${packageJson}`;

assert.equal(existsSync(resolve(root, "../package-lock.json")), true, "parent WASM npm ci lock is missing");
assert.match(workflow, /working-directory:\s*wasm\s*\n\s*run:\s*npm ci/u, "parent WASM install must use npm ci");
assert.doesNotMatch(workflow, /run:\s*npm install(?:\s|$)/u, "docs workflow must not use mutable npm install");
assert.match(workflow, /GITHUB_EVENT_NAME[^\n]*workflow_dispatch/u, "manual workflow guard is missing");
assert.match(workflow, /GITHUB_REF_NAME[^\n]*master/u, "manual workflow must reject the Pages branch");
assert.match(workflow, /git push origin "HEAD:\$\{GITHUB_REF\}"/u, "manual materialization must push only to its source branch");
assert.match(workflow, /Source commit.*GITHUB_STEP_SUMMARY/su, "workflow summary must record the source commit");
assert.match(workflow, /dist tree SHA-256.*GITHUB_STEP_SUMMARY/su, "workflow summary must record the dist tree digest");

for (const token of ["hd-wallet-ui", "hd-wallet-wasm"]) {
  assert.doesNotMatch(packageLock, new RegExp(token, "iu"), `docs lock contains retired wallet dependency: ${token}`);
}

for (const token of [
  "mnemonic",
  "xprv",
  "WIF",
  "raw seed",
  "privateKeyPem",
  "walletAutoOpen",
  "hd-wallet-ui",
  "hd-wallet-wasm",
]) {
  const pattern = token === "WIF" ? /\bWIF\b/iu : new RegExp(token, "iu");
  assert.doesNotMatch(scanned, pattern, `public docs contain forbidden wallet token: ${token}`);
}

for (const retiredSurface of [
  /id="nav-(?:login|keys|logout)"/u,
  /id="mobile-(?:login|logout)"/u,
  /id="(?:alice|bob)-private-key"/u,
  /id="pki-(?:clear-keys|login-prompt)"/u,
  /function\s+(?:login|logout|exportWallet|savePKIKeys|loadPKIKeys|derivePKIKeysFromHD)\b/u,
  /flatbuffers-pki-keys/u,
]) {
  assert.doesNotMatch(`${html}\n${app}`, retiredSurface, `public docs retain retired private surface: ${retiredSurface}`);
}

const vcfStart = app.indexOf("function parseAndDisplayVCF");
const vcfEnd = app.indexOf("// Help Content", vcfStart);
assert.ok(vcfStart >= 0 && vcfEnd > vcfStart, "VCF parser boundary is missing");
assert.doesNotMatch(app.slice(vcfStart, vcfEnd), /innerHTML\s*=/u, "VCF importer must not inject HTML");

const callbackPath = resolve(root, "public/wallet-callback.html");
if (safeBaseline) {
  assert.doesNotMatch(scanned, /SDNWalletPublicClient|sdn-flatbuffers-pages-v1/u);
  assert.equal(existsSync(callbackPath), false, "safe baseline must not contain a wallet callback");
} else {
  assert.match(html, /sdn-flatbuffers-pages-v1/u);
  assert.equal(existsSync(callbackPath), true, "wallet callback is missing");
  assert.match(readFileSync(callbackPath, "utf8"), /sdn\.wallet\.callback\.v1/u);
}

process.stdout.write(`FlatBuffers public wallet boundary: ${safeBaseline ? "safe baseline" : "pinned consumer"} PASS\n`);
