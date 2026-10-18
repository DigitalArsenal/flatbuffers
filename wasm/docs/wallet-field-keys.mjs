/**
 * Per-field encryption keyed from the signed-in wallet.
 *
 * The recipient key is the wallet's own contact-encryption key: X25519 at
 * SLIP-10 m/44'/0'/0'/1'/0', read from the public identity the wallet client
 * reports. The page never holds a wallet secret.
 *
 * Each field is sealed with the SDN Unified ECIES pipeline (sdn-server
 * internal/ecies SealField, flatbuffers EncryptionContext):
 *
 *   Z        = X25519(ephemeral, recipient)
 *   K        = HKDF-SHA256(Z, salt = none, info = CONTEXT)
 *   CONTEXT  = "sdn-field-encryption/v1|" site "|" schema "|" field "|k" version
 *   fieldKey = HKDF-SHA256(K, "flatbuffers-field" || BE16(fieldId) || BE32(0))
 *   fieldIV  = HKDF-SHA256(K, "flatbuffers-iv"    || BE16(fieldId) || BE32(0))
 *   value    = AES-256-CTR(fieldKey, fieldIV) XOR plaintext
 *
 * and its header is an SDS `$ENC` record. One wallet key, then a key per site,
 * schema, field and key version through HKDF's info.
 */

import { Builder } from 'flatbuffers';

const WALLET_RECORD = Symbol.for('sdn.wallet.public-client.v1');
const LABEL = /^[A-Za-z0-9_.-]{1,64}$/u;
const HEX32 = /^[0-9a-f]{64}$/u;

export const FIELD_KEY_VERSION = 1;
export const CONTEXT_PREFIX = 'sdn-field-encryption/v1';

export function fieldContext(site, schema, field, version = FIELD_KEY_VERSION) {
  for (const [name, value] of [['site', site], ['schema', schema], ['field', field]]) {
    if (typeof value !== 'string' || !LABEL.test(value)) throw new Error(`invalid ${name} label`);
  }
  if (!Number.isInteger(version) || version < 1) throw new Error('invalid key version');
  return `${CONTEXT_PREFIX}|${site}|${schema}|${field}|k${version}`;
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** The signed-in wallet's encryption key, or null when signed out. */
export function walletEncryptionKey(snapshot) {
  if (snapshot?.status !== 'connected' || !snapshot.identity) return null;
  const key = snapshot.identity.keys?.find((k) => k.purpose === 'contact-encryption' && k.curve === 'x25519');
  if (!key || !HEX32.test(key.publicKeyHex)) return null;
  return Object.freeze({
    publicKey: hexToBytes(key.publicKeyHex),
    publicKeyHex: key.publicKeyHex,
    path: key.path,
    accountPeerId: snapshot.identity.accountPeerId,
  });
}

function walletRecord() {
  return globalThis.document?.[WALLET_RECORD] ?? null;
}

/**
 * Call listener(key | null) now and whenever the wallet signs in or out.
 * The SDN stack nav owns the wallet client; it may start after this module.
 */
export function watchWallet(listener) {
  let attached = false;
  const attach = () => {
    const record = walletRecord();
    if (!record || attached) return Boolean(record);
    attached = true;
    record.addPresenter({ render: () => listener(walletEncryptionKey(record.getSnapshot())) });
    listener(walletEncryptionKey(record.getSnapshot()));
    return true;
  };
  listener(null);
  if (!attach()) {
    globalThis.addEventListener?.('DOMContentLoaded', attach, { once: true });
    globalThis.addEventListener?.('load', attach, { once: true });
  }
}

/** Open the wallet's sign-in. Resolves false when the page has no wallet client. */
export async function signIn() {
  const record = walletRecord();
  if (!record) return false;
  await record.client.connect();
  return true;
}

/** A recipient's contact-encryption public key: 64 hex characters. */
export function parseRecipientKey(text) {
  const hex = String(text ?? '').trim().toLowerCase();
  if (!HEX32.test(hex)) throw new Error('A recipient key is 64 hex characters (their wallet encryption key)');
  return hexToBytes(hex);
}

/** The canonical SDS `$ENC` header of one sealed field. */
function byteVector(b, bytes) {
  b.startVector(1, bytes.length, 1);
  for (let i = bytes.length - 1; i >= 0; i -= 1) b.addInt8(bytes[i]);
  return b.endVector();
}

export function encodeENC({ ephemeralPublicKey, nonceStart, recipientKeyId, context, rootType }) {
  const b = new Builder(256);
  const eph = byteVector(b, ephemeralPublicKey);
  const nonce = byteVector(b, nonceStart);
  const rid = byteVector(b, recipientKeyId);
  const ctx = b.createString(context);
  const root = b.createString(rootType);
  b.startObject(11);
  b.addFieldInt8(0, 1, 0); // VERSION
  b.addFieldInt8(1, 0, -1); // KEY_EXCHANGE = X25519
  b.addFieldInt8(2, 0, -1); // SYMMETRIC = AES_256_CTR
  b.addFieldInt8(3, 0, -1); // KEY_DERIVATION = HKDF_SHA256
  b.addFieldOffset(4, eph, 0);
  b.addFieldOffset(5, nonce, 0);
  b.addFieldOffset(6, rid, 0);
  b.addFieldOffset(7, ctx, 0);
  b.addFieldOffset(9, root, 0);
  const enc = b.endObject();
  b.finish(enc, '$ENC');
  return b.asUint8Array().slice();
}

/**
 * Seal one field's bytes for a recipient X25519 key.
 * EncryptionContext is flatc-wasm's (../src/encryption.mjs), already loaded.
 */
export function sealField(EncryptionContext, recipientPublicKey, bytes, { site, schema, field, fieldId }) {
  const context = fieldContext(site, schema, field);
  const ctx = EncryptionContext.forEncryption(recipientPublicKey, { algorithm: 'x25519', context, version: 2 });
  try {
    const ciphertext = new Uint8Array(bytes);
    ctx.encryptScalar(ciphertext, 0, ciphertext.length, fieldId, 0);
    const header = ctx.getHeader();
    const enc = encodeENC({
      ephemeralPublicKey: header.senderPublicKey,
      nonceStart: header.nonceStart,
      recipientKeyId: header.recipientKeyId,
      context,
      rootType: schema,
    });
    return { ciphertext, enc, context, fieldId };
  } finally {
    ctx.destroy();
  }
}
