import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const START_MARKER = "<!-- SDN_CONSUMER_ASSETS_START -->";
const END_MARKER = "<!-- SDN_CONSUMER_ASSETS_END -->";

function countOccurrences(text, value) {
  return text.split(value).length - 1;
}

function stripReviewedAssetRegion(document, { required }) {
  const startCount = countOccurrences(document, START_MARKER);
  const endCount = countOccurrences(document, END_MARKER);
  if (!required) {
    if (startCount !== 0 || endCount !== 0) throw new Error("safe baseline must not contain consumer asset markers");
    return document;
  }
  if (startCount !== 1 || endCount !== 1) throw new Error("pinned consumer requires exactly one asset marker pair");
  const start = document.indexOf(START_MARKER);
  const end = document.indexOf(END_MARKER);
  if (end <= start) throw new Error("consumer asset markers are out of order");
  return `${document.slice(0, start)}${document.slice(end + END_MARKER.length)}`;
}

// Fail-closed parser tests: only one ordered pinner-owned region may be
// excluded, and forbidden content beside that region remains visible.
assert.throws(() => stripReviewedAssetRegion("plain page", { required: true }), /exactly one/u);
assert.throws(() => stripReviewedAssetRegion(`${START_MARKER}${START_MARKER}${END_MARKER}`, { required: true }), /exactly one/u);
assert.throws(() => stripReviewedAssetRegion(`${END_MARKER}${START_MARKER}`, { required: true }), /out of order/u);
const adversarialOutside = stripReviewedAssetRegion(`hd-wallet-ui${START_MARKER}hd-wallet-ui${END_MARKER}`, { required: true });
assert.throws(() => assert.doesNotMatch(adversarialOutside, /hd-wallet-ui/iu));
assert.doesNotMatch(stripReviewedAssetRegion(`${START_MARKER}hd-wallet-ui${END_MARKER}`, { required: true }), /hd-wallet-ui/iu);

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
const htmlOutsideReviewedAssets = stripReviewedAssetRegion(html, { required: !safeBaseline });
const scanned = `${htmlOutsideReviewedAssets}\n${app}\n${packageJson}`;

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
  /id="bulk-(?:private-key|custom-privkey-group|privkey-status)"/u,
  /function\s+(?:login|logout|exportWallet|savePKIKeys|loadPKIKeys|derivePKIKeysFromHD)\b/u,
  /function\s+onBulkPrivateKeyChange\b/u,
  /flatbuffers-pki-keys/u,
]) {
  assert.doesNotMatch(`${html}\n${app}`, retiredSurface, `public docs retain retired private surface: ${retiredSurface}`);
}

assert.doesNotMatch(app, /\bprivate key\b/iu, "executable docs must not retain a private-key prompt or status message");
// Encryption boundary: the page holds only public keys and ciphertext.
// Recipients are the signed-in wallet's contact-encryption key or a pasted
// wallet key; the only ephemeral secret lives inside flatc-wasm's
// EncryptionContext for one seal. Opening ciphertext is the wallet's job:
// the page's one decrypt path is the wallet client's openFields, and only on
// the site's own origin (a shared github.io origin cannot bind a site).
const walletKeys = readFileSync(resolve(root, "wallet-field-keys.mjs"), "utf8");
const encryptionCode = `${app}\n${walletKeys}`;
assert.equal(existsSync(resolve(root, "encryption-stub.mjs")), false, "the session-key encryption stub must stay deleted");
assert.match(app, /from '\.\/wallet-field-keys\.mjs'/u, "encryption must be keyed from the signed-in wallet");
assert.match(app, /sealField\(/u, "encryption must use the wallet-keyed sealField path");
assert.match(walletKeys, /purpose === 'contact-encryption'/u, "the recipient must be the wallet's contact-encryption key");
assert.doesNotMatch(app, /@noble\/|@scure\//u, "the page must not carry its own key-generation library");
for (const pattern of [
  /randomPrivateKey|generateKeyPair|GenerateKeyPair|getRandomValues/u,
  /forDecryption|decryptScalar|decryptBuffer|decryptBytes|decryptFieldAt|SharedSecret\(/u,
  /privateKey|secretKey|seedHex/u,
]) {
  assert.doesNotMatch(encryptionCode, pattern, `public docs hold key or decrypt material: ${pattern}`);
}
assert.match(walletKeys, /export const SITE_ORIGIN = 'https:\/\/flatbuffers\.spacedatanetwork\.org';/u, "the wallet opens fields only on the site's own origin");
assert.doesNotMatch(walletKeys, /SITE_ORIGIN = 'https:\/\/[^']*github\.io/u, "a shared github.io origin is not the site's own");
assert.match(walletKeys, /if \(!walletOpensHere\(\) \|\|/u, "openFields refuses off the site's own origin");
assert.equal((encryptionCode.match(/\.openFields\(/gu) ?? []).length, 1, "the wallet client's openFields is the page's one decrypt path");
assert.match(app, /disabled = !\(here && signedIn && sealed\)/u, "decrypt controls stay off unless on the site's own origin and signed in");
assert.doesNotMatch(html, /\b(?:Alice|Bob)\b/u, "demos encrypt to real wallet keys, not fictional session parties");
for (const id of ["field-recipient-key", "send-recipient-key", "send-seal"]) {
  assert.match(html, new RegExp(`id="${id}"`, "u"), `wallet-keyed encryption control is missing: ${id}`);
}
assert.match(app, /Decrypting through your wallet is off at this address/u, "the page must say why decrypting is off on a shared origin");

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
