/**
 * FlatcRunner encryption round trip: generateBinaryEncrypted produces the
 * package's per-field format, and both the package's own decrypt path
 * (generateJSONDecrypted, EncryptionContext#decryptFieldAt) and an
 * independent decrypt with node:crypto recover the plain generateBinary
 * output.
 *
 * The format (field-encryption format 3): the fields the schema marks
 * (encrypted) are AES-256-CTR encrypted in place. The session key is
 * HKDF-SHA256(ECDH(ephemeral, recipient), no salt, info = context). The
 * buffer key is HKDF-SHA256(session key, no salt, "flatbuffers-buffer-v3" +
 * BE32(record 0)), and each encrypted instance's IV is BE32(position of its
 * first byte) + 12 zero bytes. The header is the UTF-8 JSON of the
 * EncryptionHeader (version 3, hex senderPublicKey, recipientKeyId,
 * nonceStart, context).
 *
 * Before 26.1.34, generateBinaryEncrypted threw
 * "encCtx.encryptBuffer is not a function" on every call. 26.1.34 wrote
 * format 2 (key and IV per field id, so equal-id fields in nested tables
 * shared a key stream); its output still decrypts (the fixture below).
 */

import crypto from "node:crypto";
import fs from "node:fs";
import { FlatcRunner } from "../src/runner.mjs";
import {
  EncryptionContext,
  encryptionHeaderFromJSON,
  isInitialized,
  loadEncryptionWasm,
} from "../src/encryption.mjs";

const SCHEMA = {
  entry: "/enc/user.fbs",
  files: {
    "/enc/user.fbs": `
namespace Enc;
table Address {
  city: string;
  street: string (encrypted);
}
table UserRecord {
  id: uint64;
  name: string;
  ssn: string (encrypted);
  pin: int (encrypted);
  address: Address;
}
root_type UserRecord;
`,
  },
};
const JSON_TEXT = JSON.stringify({
  id: 7,
  name: "Alice",
  ssn: "123-45-6789",
  pin: 4242,
  address: { city: "Springfield", street: "742 Evergreen Terrace" },
});

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
const sameBytes = (a, b) =>
  a.length === b.length && a.every((value, index) => value === b[index]);
const contains = (haystack, text) =>
  Buffer.from(haystack).includes(Buffer.from(text));

// --- FlatBuffer layout: where each (encrypted) field's bytes live ----------
const u32 = (b, o) => new DataView(b.buffer, b.byteOffset).getUint32(o, true);
const i32 = (b, o) => new DataView(b.buffer, b.byteOffset).getInt32(o, true);
const u16 = (b, o) => new DataView(b.buffer, b.byteOffset).getUint16(o, true);
function fieldPos(buf, table, id) {
  const vtable = table - i32(buf, table);
  const slot = 4 + 2 * id;
  if (slot >= u16(buf, vtable)) return 0;
  const off = u16(buf, vtable + slot);
  return off ? table + off : 0;
}
const refPos = (buf, pos) => pos + u32(buf, pos);
function stringRegion(buf, table, id) {
  const str = refPos(buf, fieldPos(buf, table, id));
  return { start: str + 4, end: str + 4 + u32(buf, str) };
}
function encryptedRegions(buf) {
  const root = u32(buf, 0);
  const pinPos = fieldPos(buf, root, 3);
  const address = refPos(buf, fieldPos(buf, root, 4));
  return [
    { id: 2, ...stringRegion(buf, root, 2) }, // UserRecord.ssn
    { id: 3, start: pinPos, end: pinPos + 4 }, // UserRecord.pin
    { id: 1, ...stringRegion(buf, address, 1) }, // Address.street
  ];
}

// --- Independent decrypt with node:crypto ---------------------------------
const hkdf = (ikm, info, length) =>
  new Uint8Array(crypto.hkdfSync("sha256", ikm, new Uint8Array(0), info, length));
function bufferKeyInfo(recordIndex) {
  const label = "flatbuffers-buffer-v3";
  const info = new Uint8Array(label.length + 4);
  info.set(Buffer.from(label), 0);
  new DataView(info.buffer).setUint32(label.length, recordIndex); // big-endian
  return info;
}
function instanceIV(position) {
  const iv = new Uint8Array(16);
  new DataView(iv.buffer).setUint32(0, position); // big-endian, then zeros
  return iv;
}
function nodeDecrypt(data, sharedSecret, context) {
  const sessionKey = hkdf(sharedSecret, Buffer.from(context), 32);
  const bufferKey = hkdf(sessionKey, bufferKeyInfo(0), 32);
  const out = new Uint8Array(data);
  for (const { start, end } of encryptedRegions(out)) {
    const decipher = crypto.createDecipheriv("aes-256-ctr", bufferKey, instanceIV(start));
    out.set(decipher.update(out.subarray(start, end)), start);
  }
  return out;
}
function x25519Recipient() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("x25519");
  const jwk = privateKey.export({ format: "jwk" });
  return {
    publicKey: new Uint8Array(Buffer.from(jwk.x, "base64url")),
    privateKey: new Uint8Array(Buffer.from(jwk.d, "base64url")),
    shared: (senderPublicKey) =>
      crypto.diffieHellman({
        privateKey,
        publicKey: crypto.createPublicKey({
          key: { kty: "OKP", crv: "X25519", x: Buffer.from(senderPublicKey).toString("base64url") },
          format: "jwk",
        }),
      }),
  };
}
function secp256k1Recipient() {
  const ecdh = crypto.createECDH("secp256k1");
  ecdh.generateKeys();
  return {
    publicKey: new Uint8Array(ecdh.getPublicKey(null, "compressed")),
    privateKey: new Uint8Array(ecdh.getPrivateKey()),
    shared: (senderPublicKey) => ecdh.computeSecret(Buffer.from(senderPublicKey)),
  };
}

// --- One round trip -------------------------------------------------------
function roundTrip(runner, label, algorithm, recipient, context) {
  console.log(`\n${label}:`);
  const plain = runner.generateBinary(SCHEMA, JSON_TEXT, { sizePrefix: false });
  const plainJson = runner.generateJSON(SCHEMA, { path: "/enc/plain.bin", data: plain });

  const result = attempt("generateBinaryEncrypted returns", () =>
    runner.generateBinaryEncrypted(SCHEMA, JSON_TEXT, {
      publicKey: recipient.publicKey,
      algorithm,
      context,
    })
  );
  if (!result) return;
  const { header, data } = result;
  check(header instanceof Uint8Array && data instanceof Uint8Array, "returns { header, data } as Uint8Arrays");
  check(data.length === plain.length, "data keeps the plain binary's length");

  const regions = encryptedRegions(plain);
  const inRegion = (i) => regions.some(({ start, end }) => i >= start && i < end);
  check(
    plain.every((value, i) => inRegion(i) || data[i] === value),
    "every byte outside the (encrypted) fields matches generateBinary"
  );
  check(
    regions.every(({ start, end }) => !sameBytes(data.subarray(start, end), plain.subarray(start, end))),
    "each (encrypted) field (ssn, pin, address.street) is ciphertext"
  );
  check(
    contains(data, "Alice") && contains(data, "Springfield") &&
      !contains(data, "123-45-6789") && !contains(data, "742 Evergreen Terrace"),
    "plain fields readable, encrypted strings absent"
  );

  const parsed = JSON.parse(new TextDecoder().decode(header));
  check(
    parsed.version === 3 && parsed.algorithm === algorithm && parsed.context === (context || null),
    "header is EncryptionHeader JSON (version 3, algorithm, context)"
  );
  check(
    /^[0-9a-f]{24}$/.test(parsed.nonceStart) &&
      parsed.recipientKeyId ===
        crypto.createHash("sha256").update(recipient.publicKey).digest("hex").slice(0, 16),
    "header carries nonceStart and recipientKeyId = SHA-256(recipient key)[0..8]"
  );

  const senderPublicKey = Buffer.from(parsed.senderPublicKey, "hex");
  check(
    sameBytes(nodeDecrypt(data, recipient.shared(senderPublicKey), context), plain),
    "node:crypto decrypt of the documented format gives the generateBinary bytes"
  );

  const json = attempt("generateJSONDecrypted returns", () =>
    runner.generateJSONDecrypted(
      SCHEMA,
      { path: "/enc/user.bin", data },
      { privateKey: recipient.privateKey, header }
    )
  );
  check(json === plainJson, "generateJSONDecrypted equals generateJSON of the plain binary");

  const wrong = algorithm === "x25519" ? x25519Recipient() : secp256k1Recipient();
  let wrongJson = "";
  try {
    wrongJson = runner.generateJSONDecrypted(
      SCHEMA,
      { path: "/enc/user.bin", data },
      { privateKey: wrong.privateKey, header }
    );
  } catch {
    // A garbled string may not survive JSON output; either way no plaintext.
  }
  check(!wrongJson.includes("123-45-6789"), "the wrong private key does not recover ssn");
  return { header, data, plain };
}

console.log("\n=== FlatcRunner encryption round trip ===");

const runner = await FlatcRunner.init();

// Runner only, as in the README: no loadEncryptionWasm().
roundTrip(runner, "x25519 on the runner's own module", "x25519", x25519Recipient(), "user-records");
check(!isInitialized(), "the runner leaves the encryption module unloaded");
roundTrip(runner, "secp256k1 on the runner's own module", "secp256k1", secp256k1Recipient(), "user-records");

console.log("\nInput checks:");
let message = "";
try {
  runner.generateBinaryEncrypted(SCHEMA, JSON_TEXT, {
    publicKey: x25519Recipient().publicKey,
    fields: ["ssn"],
  });
} catch (e) {
  message = e.message;
}
check(message.includes("(encrypted)"), "a fields list is refused: the schema selects the fields");
message = "";
try {
  runner.generateJSONDecrypted(
    SCHEMA,
    { path: "/enc/user.bin", data: runner.generateBinary(SCHEMA, JSON_TEXT, { sizePrefix: false }) },
    { privateKey: x25519Recipient().privateKey }
  );
} catch (e) {
  message = e.message;
}
check(message.includes("header"), "decryption without the header is refused");

// Format 2 from the published flatc-wasm 26.1.34 still decrypts: its header
// carries version 2.
console.log("\nFormat 2 (flatc-wasm 26.1.34 output):");
const fixture = JSON.parse(
  fs.readFileSync(new URL("./fixtures/field-encryption-v2-26.1.34.json", import.meta.url), "utf8")
);
const fixtureSchema = { entry: "/fixture/user.fbs", files: { "/fixture/user.fbs": fixture.schema } };
check(JSON.parse(fixture.header).version === 2, "the 26.1.34 header carries version 2");
const fixtureJson = attempt("generateJSONDecrypted of 26.1.34 data returns", () =>
  runner.generateJSONDecrypted(
    fixtureSchema,
    { path: "/fixture/user.bin", data: new Uint8Array(Buffer.from(fixture.dataHex, "hex")) },
    { privateKey: new Uint8Array(Buffer.from(fixture.privateKeyHex, "hex")), header: fixture.header }
  )
);
const fixturePlainJson = runner.generateJSON(fixtureSchema, {
  path: "/fixture/plain.bin",
  data: runner.generateBinary(fixtureSchema, fixture.json, { sizePrefix: false }),
});
check(fixtureJson === fixturePlainJson, "26.1.34 data decrypts to the original JSON");

// With the encryption module loaded separately, the documented JS API
// decrypts each field with the header.
await loadEncryptionWasm();
const recipient = x25519Recipient();
const trip = roundTrip(runner, "x25519 with loadEncryptionWasm()", "x25519", recipient, "");
if (trip) {
  console.log("\nEncryptionContext#decryptFieldAt:");
  const ctx = EncryptionContext.forDecryption(
    recipient.privateKey,
    encryptionHeaderFromJSON(new TextDecoder().decode(trip.header))
  );
  check(ctx.getVersion() === 3, "forDecryption reads format 3 from the header");
  const fields = new Uint8Array(trip.data);
  for (const { start, end } of encryptedRegions(fields)) {
    ctx.decryptFieldAt(fields, start, end - start, 0);
  }
  ctx.destroy();
  check(sameBytes(fields, trip.plain), "decryptFieldAt per field gives the generateBinary bytes");
}

console.log(failures === 0 ? "\nAll encryption round-trip checks passed." : `\n${failures} check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
