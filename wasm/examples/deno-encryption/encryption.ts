/**
 * FlatBuffers field-level encryption for Deno.
 *
 * This module implements the same encryption algorithm as the JavaScript
 * flatc-wasm module, ensuring 100% cross-language compatibility.
 *
 * @module encryption
 */

/**
 * AES S-box for encryption
 */
const SBOX = new Uint8Array([
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
  0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
  0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
  0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
  0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
  0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
  0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
  0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
  0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
  0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
  0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
  0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
  0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
  0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
  0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
  0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
  0xb0, 0x54, 0xbb, 0x16,
]);

const RCON = new Uint8Array([
  0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
]);

function gfMul(a: number, b: number): number {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hiBit = a & 0x80;
    a = (a << 1) & 0xff;
    if (hiBit) a ^= 0x1b;
    b >>= 1;
  }
  return p;
}

function aes256KeyExpansion(key: Uint8Array): Uint8Array {
  const roundKeys = new Uint8Array(240);
  roundKeys.set(key);

  const temp = new Uint8Array(4);
  let i = 8;

  while (i < 60) {
    temp.set(roundKeys.subarray((i - 1) * 4, i * 4));

    if (i % 8 === 0) {
      const t = temp[0];
      temp[0] = SBOX[temp[1]] ^ RCON[i / 8];
      temp[1] = SBOX[temp[2]];
      temp[2] = SBOX[temp[3]];
      temp[3] = SBOX[t];
    } else if (i % 8 === 4) {
      temp[0] = SBOX[temp[0]];
      temp[1] = SBOX[temp[1]];
      temp[2] = SBOX[temp[2]];
      temp[3] = SBOX[temp[3]];
    }

    for (let j = 0; j < 4; j++) {
      roundKeys[i * 4 + j] = roundKeys[(i - 8) * 4 + j] ^ temp[j];
    }
    i++;
  }

  return roundKeys;
}

function subBytes(state: Uint8Array): void {
  for (let i = 0; i < 16; i++) {
    state[i] = SBOX[state[i]];
  }
}

function shiftRows(state: Uint8Array): void {
  let temp = state[1];
  state[1] = state[5];
  state[5] = state[9];
  state[9] = state[13];
  state[13] = temp;
  temp = state[2];
  state[2] = state[10];
  state[10] = temp;
  temp = state[6];
  state[6] = state[14];
  state[14] = temp;
  temp = state[15];
  state[15] = state[11];
  state[11] = state[7];
  state[7] = state[3];
  state[3] = temp;
}

function mixColumns(state: Uint8Array): void {
  for (let i = 0; i < 4; i++) {
    const a = [state[i * 4], state[i * 4 + 1], state[i * 4 + 2], state[i * 4 + 3]];
    state[i * 4 + 0] = gfMul(a[0], 2) ^ gfMul(a[1], 3) ^ a[2] ^ a[3];
    state[i * 4 + 1] = a[0] ^ gfMul(a[1], 2) ^ gfMul(a[2], 3) ^ a[3];
    state[i * 4 + 2] = a[0] ^ a[1] ^ gfMul(a[2], 2) ^ gfMul(a[3], 3);
    state[i * 4 + 3] = gfMul(a[0], 3) ^ a[1] ^ a[2] ^ gfMul(a[3], 2);
  }
}

function addRoundKey(state: Uint8Array, roundKey: Uint8Array): void {
  for (let i = 0; i < 16; i++) {
    state[i] ^= roundKey[i];
  }
}

function aesEncryptBlock(key: Uint8Array, input: Uint8Array): Uint8Array {
  const roundKeys = aes256KeyExpansion(key);
  const state = new Uint8Array(input);

  addRoundKey(state, roundKeys.subarray(0, 16));

  for (let round = 1; round < 14; round++) {
    subBytes(state);
    shiftRows(state);
    mixColumns(state);
    addRoundKey(state, roundKeys.subarray(round * 16, (round + 1) * 16));
  }

  subBytes(state);
  shiftRows(state);
  addRoundKey(state, roundKeys.subarray(14 * 16, 15 * 16));

  return state;
}

function aesCtrKeystream(key: Uint8Array, nonce: Uint8Array, length: number): Uint8Array {
  const keystream = new Uint8Array(length);
  const counter = new Uint8Array(nonce);

  let offset = 0;
  while (offset < length) {
    const block = aesEncryptBlock(key, counter);
    const toCopy = Math.min(16, length - offset);
    keystream.set(block.subarray(0, toCopy), offset);
    offset += toCopy;

    for (let i = 15; i >= 0; i--) {
      counter[i]++;
      if (counter[i] !== 0) break;
    }
  }

  return keystream;
}

function deriveKey(masterKey: Uint8Array, info: Uint8Array, outLength: number): Uint8Array {
  const out = new Uint8Array(outLength);

  for (let i = 0; i < outLength && i < masterKey.length; i++) {
    out[i] = masterKey[i];
  }

  let hash = 0;
  for (let i = 0; i < info.length; i++) {
    hash ^= info[i];
    hash = ((hash << 1) | (hash >> 7)) & 0xff;
  }

  for (let i = 0; i < outLength; i++) {
    out[i] ^= hash;
    hash = (hash * 31 + i) & 0xff;
  }

  if (outLength >= 16) {
    const temp = aesEncryptBlock(masterKey, out.subarray(0, 16));
    out.set(temp.subarray(0, Math.min(outLength, 16)));
    if (outLength > 16) {
      const temp2 = aesEncryptBlock(masterKey, temp);
      out.set(temp2.subarray(0, Math.min(outLength - 16, 16)), 16);
    }
  }

  return out;
}

/**
 * Encryption context for FlatBuffer field encryption
 */
export class EncryptionContext {
  #key: Uint8Array;
  #valid: boolean;

  constructor(key: Uint8Array | string) {
    if (typeof key === "string") {
      this.#key = new Uint8Array(key.length / 2);
      for (let i = 0; i < key.length; i += 2) {
        this.#key[i / 2] = parseInt(key.substring(i, i + 2), 16);
      }
    } else if (key instanceof Uint8Array) {
      this.#key = new Uint8Array(key);
    } else {
      this.#key = new Uint8Array(32);
    }

    this.#valid = this.#key.length === 32;
  }

  isValid(): boolean {
    return this.#valid;
  }

  deriveFieldKey(fieldId: number): Uint8Array {
    const info = new Uint8Array(19);
    const infoStr = "flatbuffers-field";
    for (let i = 0; i < infoStr.length; i++) {
      info[i] = infoStr.charCodeAt(i);
    }
    info[17] = (fieldId >> 8) & 0xff;
    info[18] = fieldId & 0xff;
    return deriveKey(this.#key, info, 32);
  }

  deriveFieldIV(fieldId: number): Uint8Array {
    const info = new Uint8Array(16);
    const infoStr = "flatbuffers-iv";
    for (let i = 0; i < infoStr.length; i++) {
      info[i] = infoStr.charCodeAt(i);
    }
    info[14] = (fieldId >> 8) & 0xff;
    info[15] = fieldId & 0xff;
    return deriveKey(this.#key, info, 16);
  }
}

/**
 * Encrypt bytes in-place using AES-CTR
 */
export function encryptBytes(data: Uint8Array, key: Uint8Array, iv: Uint8Array): void {
  const keystream = aesCtrKeystream(key, iv, data.length);
  for (let i = 0; i < data.length; i++) {
    data[i] ^= keystream[i];
  }
}

/**
 * Decrypt bytes in-place (same as encrypt for AES-CTR)
 */
export const decryptBytes = encryptBytes;

interface FieldInfo {
  name: string;
  id: number;
  type: string;
  encrypted: boolean;
  elementType?: string;
  elementSize: number;
  structSize: number;
}

function getTypeSize(typeName: string): number {
  switch (typeName) {
    case "bool":
    case "byte":
    case "ubyte":
      return 1;
    case "short":
    case "ushort":
      return 2;
    case "int":
    case "uint":
    case "float":
      return 4;
    case "long":
    case "ulong":
    case "double":
      return 8;
    default:
      return 0;
  }
}

function getBaseType(typeName: string): string {
  const scalarTypes = [
    "bool", "byte", "ubyte", "short", "ushort",
    "int", "uint", "long", "ulong", "float", "double",
  ];
  if (scalarTypes.includes(typeName)) return typeName;
  if (typeName === "string") return "string";
  return "struct";
}

/**
 * Parse schema to extract field encryption info
 */
export function parseSchemaForEncryption(schemaContent: string, rootType: string): FieldInfo[] {
  const fields: FieldInfo[] = [];

  const tableRegex = new RegExp(`table\\s+${rootType}\\s*\\{([^}]+)\\}`, "s");
  const match = schemaContent.match(tableRegex);

  if (!match) return fields;

  const tableBody = match[1];
  const fieldRegex = /(\w+)\s*:\s*(\[?\w+\]?)\s*(?:\(([^)]*)\))?/g;

  let fieldId = 0;
  let fieldMatch;

  while ((fieldMatch = fieldRegex.exec(tableBody)) !== null) {
    const fieldName = fieldMatch[1];
    const fieldType = fieldMatch[2];
    const attributes = fieldMatch[3] || "";

    const isEncrypted = attributes.includes("encrypted");
    const isVector = fieldType.startsWith("[") && fieldType.endsWith("]");
    const baseType = isVector ? fieldType.slice(1, -1) : fieldType;

    const field: FieldInfo = {
      name: fieldName,
      id: fieldId,
      type: isVector ? "vector" : getBaseType(baseType),
      encrypted: isEncrypted,
      elementSize: 0,
      structSize: 0,
    };

    if (isVector) {
      field.elementType = getBaseType(baseType);
      field.elementSize = getTypeSize(baseType);
    }

    fields.push(field);
    fieldId++;
  }

  return fields;
}

function readUint32(buffer: Uint8Array, offset: number): number {
  return (
    buffer[offset] |
    (buffer[offset + 1] << 8) |
    (buffer[offset + 2] << 16) |
    (buffer[offset + 3] << 24)
  ) >>> 0;
}

function readUint16(buffer: Uint8Array, offset: number): number {
  return buffer[offset] | (buffer[offset + 1] << 8);
}

function readInt32(buffer: Uint8Array, offset: number): number {
  return (
    buffer[offset] |
    (buffer[offset + 1] << 8) |
    (buffer[offset + 2] << 16) |
    (buffer[offset + 3] << 24)
  );
}

function encryptRegion(
  buffer: Uint8Array,
  start: number,
  length: number,
  key: Uint8Array,
  iv: Uint8Array
): void {
  const keystream = aesCtrKeystream(key, iv, length);
  for (let i = 0; i < length; i++) {
    buffer[start + i] ^= keystream[i];
  }
}

function processTable(
  buffer: Uint8Array,
  tableOffset: number,
  fields: FieldInfo[],
  ctx: EncryptionContext
): void {
  const vtableOffsetDelta = readInt32(buffer, tableOffset);
  const vtableOffset = tableOffset - vtableOffsetDelta;
  const vtableSize = readUint16(buffer, vtableOffset);

  for (const field of fields) {
    const fieldVtableIdx = (field.id + 2) * 2;

    if (fieldVtableIdx >= vtableSize) continue;

    const fieldOffset = readUint16(buffer, vtableOffset + fieldVtableIdx);
    if (fieldOffset === 0) continue;

    const fieldLoc = tableOffset + fieldOffset;

    if (!field.encrypted) continue;

    const key = ctx.deriveFieldKey(field.id);
    const iv = ctx.deriveFieldIV(field.id);

    switch (field.type) {
      case "bool":
      case "byte":
      case "ubyte":
        encryptRegion(buffer, fieldLoc, 1, key, iv);
        break;
      case "short":
      case "ushort":
        encryptRegion(buffer, fieldLoc, 2, key, iv);
        break;
      case "int":
      case "uint":
      case "float":
        encryptRegion(buffer, fieldLoc, 4, key, iv);
        break;
      case "long":
      case "ulong":
      case "double":
        encryptRegion(buffer, fieldLoc, 8, key, iv);
        break;
      case "string": {
        const stringOffset = readUint32(buffer, fieldLoc);
        const stringLoc = fieldLoc + stringOffset;
        const stringLen = readUint32(buffer, stringLoc);
        const stringData = stringLoc + 4;
        if (stringData + stringLen <= buffer.length) {
          encryptRegion(buffer, stringData, stringLen, key, iv);
        }
        break;
      }
      case "vector": {
        const vecOffset = readUint32(buffer, fieldLoc);
        const vecLoc = fieldLoc + vecOffset;
        const vecLen = readUint32(buffer, vecLoc);
        const vecData = vecLoc + 4;
        const elemSize = field.elementSize || 1;
        const totalSize = vecLen * elemSize;
        if (vecData + totalSize <= buffer.length) {
          encryptRegion(buffer, vecData, totalSize, key, iv);
        }
        break;
      }
      case "struct": {
        const structSize = field.structSize || 0;
        if (structSize > 0 && fieldLoc + structSize <= buffer.length) {
          encryptRegion(buffer, fieldLoc, structSize, key, iv);
        }
        break;
      }
    }
  }
}

/**
 * Encrypt a FlatBuffer in-place
 */
export function encryptBuffer(
  buffer: Uint8Array,
  schema: string,
  key: Uint8Array | string | EncryptionContext,
  rootType: string
): Uint8Array {
  const ctx = key instanceof EncryptionContext ? key : new EncryptionContext(key);

  if (!ctx.isValid()) {
    throw new Error("Invalid encryption key (must be 32 bytes)");
  }

  const fields = parseSchemaForEncryption(schema, rootType);
  const rootOffset = readUint32(buffer, 0);

  processTable(buffer, rootOffset, fields, ctx);

  return buffer;
}

/**
 * Decrypt a FlatBuffer in-place (same as encrypt for AES-CTR)
 */
export const decryptBuffer = encryptBuffer;

export default {
  EncryptionContext,
  encryptBytes,
  decryptBytes,
  encryptBuffer,
  decryptBuffer,
  parseSchemaForEncryption,
};
