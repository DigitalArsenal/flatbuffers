/**
 * Field-encryption format 3: every encrypted field instance gets its own key
 * stream.
 *
 * Format 2 (flatc-wasm 26.1.34) keyed each (encrypted) field by its field id
 * and record index only. Two fields with the same id in one buffer (a table
 * and its nested table) shared a key stream, so the XOR of their ciphertexts
 * was the XOR of their plaintexts. Fields in vectors of tables and unions were
 * never walked and stayed plaintext.
 *
 * Format 3: buffer key K = HKDF-SHA256(session key, no salt,
 * "flatbuffers-buffer-v3" || BE32(record index)); each instance is AES-256-CTR
 * with K and the IV BE32(position of its first byte) || 12 zero bytes.
 *
 * Checks:
 * - The C++ derivation matches independent node:crypto vectors (the same
 *   vectors are in tests/encryption_test.cpp).
 * - generateBinaryEncrypted encrypts every instance in nested tables,
 *   vectors of tables, unions and vectors of unions, and a known-plaintext
 *   XOR recovers nothing.
 * - Cross-language round trip: node:crypto decrypts the WASM (C++) output,
 *   and generateJSONDecrypted decrypts node:crypto output.
 * - An (encrypted) field that cannot be encrypted in place is refused.
 * - The C API wasm_json_to_binary_encrypted / wasm_binary_to_json_decrypted
 *   encrypts and round-trips (it used to serialize the schema without the
 *   (encrypted) markers and encrypt nothing).
 */

import crypto from "node:crypto";
import { FlatcRunner } from "../src/runner.mjs";
import * as enc from "../src/encryption.mjs";

let failures = 0;
function check(condition, message) {
  if (condition) {
    console.log(`  ✓ ${message}`);
  } else {
    console.log(`  ✗ ${message}`);
    failures++;
  }
}
function attempt(message, fn) {
  try {
    return fn();
  } catch (e) {
    check(false, `${message} (threw: ${e.message})`);
    return undefined;
  }
}
const hex = (b) => Buffer.from(b).toString("hex");
const sameBytes = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

// --- node:crypto reference for format 3 -------------------------------------
const hkdf = (ikm, info, length) =>
  new Uint8Array(crypto.hkdfSync("sha256", ikm, new Uint8Array(0), info, length));
function bufferKeyInfo(recordIndex) {
  const label = "flatbuffers-buffer-v3";
  const info = new Uint8Array(label.length + 4);
  info.set(Buffer.from(label), 0);
  new DataView(info.buffer).setUint32(label.length, recordIndex);
  return info;
}
function fieldInfo(label, id, recordIndex) {
  const info = new Uint8Array(label.length + 6);
  info.set(Buffer.from(label), 0);
  new DataView(info.buffer).setUint16(label.length, id);
  new DataView(info.buffer).setUint32(label.length + 2, recordIndex);
  return info;
}
function instanceIV(position) {
  const iv = new Uint8Array(16);
  new DataView(iv.buffer).setUint32(0, position);
  return iv;
}
// AES-CTR is its own inverse: this encrypts and decrypts.
function cipherV3(data, bufferKey, regions) {
  const out = new Uint8Array(data);
  for (const { start, end } of regions) {
    const c = crypto.createCipheriv("aes-256-ctr", bufferKey, instanceIV(start));
    out.set(c.update(out.subarray(start, end)), start);
  }
  return out;
}

// --- FlatBuffer layout ------------------------------------------------------
const view = (b) => new DataView(b.buffer, b.byteOffset, b.byteLength);
const u32 = (b, o) => view(b).getUint32(o, true);
const i32 = (b, o) => view(b).getInt32(o, true);
const u16 = (b, o) => view(b).getUint16(o, true);
function fieldPos(buf, table, id) {
  const vtable = table - i32(buf, table);
  const slot = 4 + 2 * id;
  if (slot >= u16(buf, vtable)) return 0;
  const off = u16(buf, vtable + slot);
  return off ? table + off : 0;
}
const deref = (buf, pos) => pos + u32(buf, pos);
function stringRegion(buf, ref) {
  const s = deref(buf, ref);
  return { start: s + 4, end: s + 4 + u32(buf, s) };
}
function vectorRefs(buf, ref) {
  const v = deref(buf, ref);
  return Array.from({ length: u32(buf, v) }, (_, i) => v + 4 + 4 * i);
}

// Root and Node give secret (id 0) and pin (id 1) the same field ids; Node is
// a nested table, a vector element, a union member and a vector-of-unions
// member.
const NODE_SCHEMA = {
  entry: "/ks/node.fbs",
  files: {
    "/ks/node.fbs": `
namespace KS;
table Node {
  secret: string (encrypted);
  pin: int (encrypted);
  child: Node;
}
union Member { Node }
table Root {
  secret: string (encrypted);
  pin: int (encrypted);
  child: Node;
  items: [Node];
  member: Member;
  members: [Member];
}
root_type Root;
`,
  },
};
// Every secret is 16 bytes; the root's is the attacker's known plaintext.
const NODE_JSON = JSON.stringify({
  secret: "known plaintext!", pin: 1111,
  child: { secret: "hidden nested B", pin: 2222, child: { secret: "hidden nested CC", pin: 3333 } },
  items: [{ secret: "hidden vector DD", pin: 4444 }, { secret: "hidden vector EE", pin: 5555 }],
  member_type: "Node", member: { secret: "hidden union FFF", pin: 6666 },
  members_type: ["Node", "Node"],
  members: [{ secret: "hidden unions GG", pin: 7777 }, { secret: "hidden unions HH", pin: 8888 }],
});

function collectNode(buf, table, what, out) {
  const s = fieldPos(buf, table, 0);
  if (s) out.secrets.push({ what: `${what}.secret`, ...stringRegion(buf, s) });
  const p = fieldPos(buf, table, 1);
  if (p) out.pins.push({ what: `${what}.pin`, start: p, end: p + 4 });
  const c = fieldPos(buf, table, 2);
  if (c) collectNode(buf, deref(buf, c), `${what}.child`, out);
}
function collectRoot(buf) {
  const out = { secrets: [], pins: [] };
  const root = u32(buf, 0);
  collectNode(buf, root, "root", out);
  vectorRefs(buf, fieldPos(buf, root, 3)).forEach((ref, i) =>
    collectNode(buf, deref(buf, ref), `items[${i}]`, out));
  collectNode(buf, deref(buf, fieldPos(buf, root, 5)), "member", out);
  vectorRefs(buf, fieldPos(buf, root, 7)).forEach((ref, i) =>
    collectNode(buf, deref(buf, ref), `members[${i}]`, out));
  return out;
}
const bytesOf = (buf, r) => buf.subarray(r.start, r.end);
// What an attacker who knows `known` recovers of `other` when they share a
// key stream: c_known ^ c_other ^ p_known.
function recovers(plain, cipher, known, other) {
  const got = bytesOf(cipher, other).map(
    (c, k) => c ^ cipher[known.start + k] ^ plain[known.start + k]);
  return sameBytes(got, bytesOf(plain, other));
}

function x25519Recipient() {
  const { privateKey } = crypto.generateKeyPairSync("x25519");
  const jwk = privateKey.export({ format: "jwk" });
  return {
    publicKey: new Uint8Array(Buffer.from(jwk.x, "base64url")),
    privateKey: new Uint8Array(Buffer.from(jwk.d, "base64url")),
    keyObject: privateKey,
  };
}
function sharedSecret(privateKeyObject, publicKeyBytes) {
  return crypto.diffieHellman({
    privateKey: privateKeyObject,
    publicKey: crypto.createPublicKey({
      key: { kty: "OKP", crv: "X25519", x: Buffer.from(publicKeyBytes).toString("base64url") },
      format: "jwk",
    }),
  });
}

console.log("\n=== Field-encryption format 3 ===");
const runner = await FlatcRunner.init();

// --- 1. Derivation vectors ---------------------------------------------------
console.log("\nDerivation vectors (C++ = node:crypto):");
const vectorKey = new Uint8Array(Array.from({ length: 32 }, (_, i) => i));
const VECTORS = {
  fieldKey: "675aaf1b9a01567081b6d38908672704d226b23cb1631af6c22dd58c3bb70e30",
  fieldIV: "2f21d1ea116d9b6b4930e9230b1a11b3",
  bufferKey0: "c4c46faf2e2a1f24f04b70f54031ca2ce4bdcc70a57898619ae60981c968c32e",
  bufferKey7: "96dc099cb3f069b6bb6f67567a4bbe5f5c0e83d8257c714278e3da3f8086ba13",
  keyStream: "6e83aa7422ddbadb1413e5cc5b5f8336866aeb83",
};
check(
  hex(hkdf(vectorKey, fieldInfo("flatbuffers-field", 4, 0), 32)) === VECTORS.fieldKey &&
    hex(hkdf(vectorKey, fieldInfo("flatbuffers-iv", 4, 0), 16)) === VECTORS.fieldIV &&
    hex(hkdf(vectorKey, bufferKeyInfo(0), 32)) === VECTORS.bufferKey0 &&
    hex(hkdf(vectorKey, bufferKeyInfo(7), 32)) === VECTORS.bufferKey7,
  "node:crypto derives the documented vectors"
);
await enc.loadEncryptionWasm();
attempt("EncryptionContext derivations", () => {
  const ctx = new enc.EncryptionContext(vectorKey);
  try {
    check(hex(ctx.deriveFieldKey(4, 0)) === VECTORS.fieldKey,
      "per-field key (format 2 primitive) unchanged: DeriveFieldKey(4, record 0)");
    check(hex(ctx.deriveBufferKey(0)) === VECTORS.bufferKey0 &&
      hex(ctx.deriveBufferKey(7)) === VECTORS.bufferKey7,
      "DeriveBufferKey(0) and (7) match node:crypto");
    check(hex(enc.fieldInstanceIV(0x1234)) === "00001234000000000000000000000000",
      "fieldInstanceIV(0x1234) = BE32(position) || 12 zero bytes");
    const stream = new Uint8Array(20);
    enc.encryptBytes(stream, ctx.deriveBufferKey(7), enc.fieldInstanceIV(0x1234));
    const nodeStream = crypto.createCipheriv("aes-256-ctr",
      Buffer.from(VECTORS.bufferKey7, "hex"), instanceIV(0x1234)).update(new Uint8Array(20));
    check(hex(stream) === VECTORS.keyStream && hex(nodeStream) === VECTORS.keyStream,
      "the key stream at position 0x1234 of record 7 matches node:crypto");
  } finally {
    ctx.destroy();
  }
});

// --- 2. Nested tables, vectors of tables, unions -----------------------------
console.log("\nEqual-id fields in nested tables, vectors of tables and unions:");
const plain = runner.generateBinary(NODE_SCHEMA, NODE_JSON, { sizePrefix: false });
const plainJson = runner.generateJSON(NODE_SCHEMA, { path: "/ks/plain.bin", data: plain });
const { secrets, pins } = collectRoot(plain);
check(secrets.length === 8 && pins.length === 8, "the buffer holds 8 secrets and 8 pins");
const recipient = x25519Recipient();
const result = attempt("generateBinaryEncrypted returns", () =>
  runner.generateBinaryEncrypted(NODE_SCHEMA, NODE_JSON, {
    publicKey: recipient.publicKey, algorithm: "x25519", context: "ks" }));
if (result) {
  const { header, data } = result;
  const parsed = JSON.parse(new TextDecoder().decode(header));
  check(parsed.version === 3, "the header declares format 3");
  const plaintextLeft = [...secrets, ...pins].filter((r) => sameBytes(bytesOf(data, r), bytesOf(plain, r)));
  check(plaintextLeft.length === 0,
    `every instance is ciphertext${plaintextLeft.length ? ` (plaintext: ${plaintextLeft.map((r) => r.what).join(", ")})` : ""}`);
  const leaked = secrets.slice(1).filter((r) => recovers(plain, data, secrets[0], r));
  check(leaked.length === 0,
    `XOR with the known root.secret recovers no other secret${leaked.length ? ` (recovers ${leaked.map((r) => r.what).join(", ")})` : ""}`);
  let pinLeaks = 0;
  for (let a = 0; a < pins.length; a++) {
    for (let b = a + 1; b < pins.length; b++) pinLeaks += recovers(plain, data, pins[a], pins[b]) ? 1 : 0;
  }
  check(pinLeaks === 0, `no pin reveals another pin (${pinLeaks} leaking pairs)`);
  const inside = new Set();
  for (const r of [...secrets, ...pins]) for (let k = r.start; k < r.end; k++) inside.add(k);
  check(plain.every((v, k) => inside.has(k) || data[k] === v), "every other byte is unchanged");

  // C++ (WASM) encrypts, node:crypto decrypts.
  const session = hkdf(sharedSecret(recipient.keyObject, Buffer.from(parsed.senderPublicKey, "hex")),
    Buffer.from("ks"), 32);
  check(sameBytes(cipherV3(data, hkdf(session, bufferKeyInfo(0), 32), [...secrets, ...pins]), plain),
    "node:crypto decrypts the WASM output (C++ -> JS)");
  const json = attempt("generateJSONDecrypted returns", () =>
    runner.generateJSONDecrypted(NODE_SCHEMA, { path: "/ks/enc.bin", data },
      { privateKey: recipient.privateKey, header }));
  check(json === plainJson, "generateJSONDecrypted gives the original JSON");
}

// node:crypto encrypts, C++ (WASM) decrypts.
{
  const ephemeral = x25519Recipient();
  const session = hkdf(sharedSecret(ephemeral.keyObject, recipient.publicKey), Buffer.from("ks"), 32);
  const jsData = cipherV3(plain, hkdf(session, bufferKeyInfo(0), 32), [...secrets, ...pins]);
  const header = JSON.stringify({
    version: 3, algorithm: "x25519", senderPublicKey: hex(ephemeral.publicKey),
    recipientKeyId: "", nonceStart: "00".repeat(12), context: "ks" });
  const json = attempt("generateJSONDecrypted of node:crypto output returns", () =>
    runner.generateJSONDecrypted(NODE_SCHEMA, { path: "/ks/js.bin", data: jsData },
      { privateKey: recipient.privateKey, header }));
  check(json === plainJson, "generateJSONDecrypted decrypts node:crypto output (JS -> C++)");
}

// --- 3. Refusals ---------------------------------------------------------------
console.log("\nUnsupported (encrypted) fields are refused:");
const REFUSED = {
  "a vector of tables": `table Inner { text: string; }
table Outer { items: [Inner] (encrypted); }
root_type Outer;`,
  "a union": `table Inner { text: string; }
union U { Inner }
table Outer { u: U (encrypted); }
root_type Outer;`,
  "a table": `table Inner { text: string; }
table Outer { inner: Inner (encrypted); }
root_type Outer;`,
};
const REFUSED_JSON = {
  "a vector of tables": { items: [{ text: "plaintext" }] },
  "a union": { u_type: "Inner", u: { text: "plaintext" } },
  "a table": { inner: { text: "plaintext" } },
};
for (const [what, text] of Object.entries(REFUSED)) {
  const schema = { entry: "/ks/refused.fbs", files: { "/ks/refused.fbs": text } };
  let message = "";
  let out;
  try {
    out = runner.generateBinaryEncrypted(schema, JSON.stringify(REFUSED_JSON[what]), {
      publicKey: recipient.publicKey });
  } catch (e) {
    message = e.message;
  }
  check(!out && /not supported/.test(message), `(encrypted) on ${what} is refused${message ? `: ${message}` : ""}`);
}

// --- 4. The C API ------------------------------------------------------------
console.log("\nC API wasm_json_to_binary_encrypted / wasm_binary_to_json_decrypted:");
attempt("C API round trip", () => {
  const M = runner.Module;
  const encoder = new TextEncoder();
  const put = (bytes) => {
    const ptr = M._malloc(Math.max(bytes.length, 1));
    M.HEAPU8.set(bytes, ptr);
    return ptr;
  };
  const lastError = () => M.UTF8ToString(M._wasm_get_last_error());
  const nameBytes = encoder.encode("ks-capi.fbs");
  const srcBytes = encoder.encode(NODE_SCHEMA.files["/ks/node.fbs"]);
  const namePtr = put(nameBytes);
  const srcPtr = put(srcBytes);
  const id = M._wasm_schema_add(namePtr, nameBytes.length, srcPtr, srcBytes.length);
  M._free(namePtr);
  M._free(srcPtr);
  if (id < 0) throw new Error(`schema add failed: ${lastError()}`);

  const key = crypto.randomBytes(32);
  const jsonBytes = encoder.encode(NODE_JSON);
  const jsonPtr = put(jsonBytes);
  const keyPtr = put(key);
  const lenPtr = M._malloc(4);
  const hdrLenPtr = M._malloc(4);
  try {
    let ptr = M._wasm_json_to_binary(id, jsonPtr, jsonBytes.length, lenPtr);
    if (!ptr) throw new Error(`json_to_binary failed: ${lastError()}`);
    const capiPlain = M.HEAPU8.slice(ptr, ptr + M.getValue(lenPtr, "i32"));
    ptr = M._wasm_json_to_binary_encrypted(id, jsonPtr, jsonBytes.length, keyPtr, 32, lenPtr, hdrLenPtr);
    if (!ptr) throw new Error(`json_to_binary_encrypted failed: ${lastError()}`);
    const capiData = M.HEAPU8.slice(ptr, ptr + M.getValue(lenPtr, "i32"));
    const regions = collectRoot(capiPlain);
    const all = [...regions.secrets, ...regions.pins];
    check(capiData.length === capiPlain.length, "the encrypted binary keeps the plain length");
    check(all.every((r) => !sameBytes(bytesOf(capiData, r), bytesOf(capiPlain, r))),
      "every (encrypted) instance is ciphertext (it used to be a no-op)");
    check(sameBytes(cipherV3(capiData, hkdf(key, bufferKeyInfo(0), 32), all), capiPlain),
      "node:crypto decrypts it as format 3, record 0");

    const dataPtr = put(capiData);
    const jsonOutPtr = M._wasm_binary_to_json_decrypted(id, dataPtr, capiData.length, keyPtr, 32, lenPtr);
    const decryptedJson = jsonOutPtr ? M.UTF8ToString(jsonOutPtr, M.getValue(lenPtr, "i32")) : "";
    M._free(dataPtr);
    const plainPtr = put(capiPlain);
    const plainOutPtr = M._wasm_binary_to_json(id, plainPtr, capiPlain.length, lenPtr);
    const capiPlainJson = plainOutPtr ? M.UTF8ToString(plainOutPtr, M.getValue(lenPtr, "i32")) : "";
    M._free(plainPtr);
    check(decryptedJson.length > 0 && decryptedJson === capiPlainJson,
      "wasm_binary_to_json_decrypted gives the plain JSON");
  } finally {
    M._free(jsonPtr);
    M._free(keyPtr);
    M._free(lenPtr);
    M._free(hdrLenPtr);
    M._wasm_schema_remove(id);
  }
});

console.log(failures === 0 ? "\nAll format-3 checks passed." : `\n${failures} check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
