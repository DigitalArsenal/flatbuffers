/**
 * Type definitions for FlatBuffers field-level encryption
 */

/**
 * Encryption context for FlatBuffer field encryption
 */
export declare class EncryptionContext {
  /**
   * Create an encryption context
   * @param key - 32-byte key as Uint8Array or 64-character hex string
   */
  constructor(key: Uint8Array | string);

  /**
   * Check if context is valid
   */
  isValid(): boolean;

  /**
   * Derive a field-specific key
   * @param fieldId - field ID
   * @returns 32-byte derived key
   */
  deriveFieldKey(fieldId: number): Uint8Array;

  /**
   * Derive a field-specific IV
   * @param fieldId - field ID
   * @returns 16-byte derived IV
   */
  deriveFieldIV(fieldId: number): Uint8Array;
}

/**
 * Parsed field information for encryption
 */
export interface EncryptionFieldInfo {
  /** Field name */
  name: string;
  /** Field ID (position in table) */
  id: number;
  /** Field type (bool, int, string, vector, struct, etc.) */
  type: string;
  /** Whether field is marked encrypted */
  encrypted: boolean;
  /** Element type for vectors */
  elementType?: string;
  /** Element size for vectors */
  elementSize?: number;
  /** Size for structs */
  structSize?: number;
  /** Nested schema for table fields */
  nestedSchema?: EncryptionSchema;
}

/**
 * Parsed schema for encryption operations
 */
export interface EncryptionSchema {
  /** Fields in the table */
  fields: EncryptionFieldInfo[];
}

/**
 * Encrypt bytes using AES-CTR (XOR with keystream)
 * @param data - data to encrypt (modified in-place)
 * @param key - 32-byte key
 * @param iv - 16-byte IV
 */
export declare function encryptBytes(
  data: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array
): void;

/**
 * Decrypt bytes using AES-CTR (same as encrypt)
 * @param data - data to decrypt (modified in-place)
 * @param key - 32-byte key
 * @param iv - 16-byte IV
 */
export declare function decryptBytes(
  data: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array
): void;

/**
 * Encrypt a scalar value in a buffer
 * @param buffer - buffer containing the scalar
 * @param offset - offset of the scalar
 * @param size - size of the scalar (1, 2, 4, or 8)
 * @param ctx - encryption context
 * @param fieldId - field ID for key derivation
 */
export declare function encryptScalar(
  buffer: Uint8Array,
  offset: number,
  size: number,
  ctx: EncryptionContext,
  fieldId: number
): void;

/**
 * Parse a FlatBuffers schema to extract field encryption info
 * @param schemaContent - FlatBuffers schema content (.fbs)
 * @param rootType - name of the root type
 * @returns Parsed schema with encryption metadata
 */
export declare function parseSchemaForEncryption(
  schemaContent: string,
  rootType: string
): EncryptionSchema;

/**
 * Encrypt a FlatBuffer in-place
 *
 * Fields marked with the (encrypted) attribute will be encrypted.
 * The buffer structure remains valid - only field values change.
 *
 * @param buffer - FlatBuffer to encrypt (modified in-place)
 * @param schema - Parsed schema or schema content string
 * @param key - 32-byte encryption key, hex string, or EncryptionContext
 * @param rootType - Root type name (required if schema is string)
 * @returns The encrypted buffer (same reference)
 *
 * @example
 * ```javascript
 * import { encryptBuffer, EncryptionContext } from 'flatc-wasm/encryption';
 *
 * const key = crypto.getRandomValues(new Uint8Array(32));
 * const encrypted = encryptBuffer(buffer, schemaContent, key, 'MyTable');
 * ```
 */
export declare function encryptBuffer(
  buffer: Uint8Array,
  schema: EncryptionSchema | string,
  key: Uint8Array | string | EncryptionContext,
  rootType?: string
): Uint8Array;

/**
 * Decrypt a FlatBuffer in-place
 *
 * Same as encryptBuffer since AES-CTR is symmetric.
 *
 * @param buffer - FlatBuffer to decrypt (modified in-place)
 * @param schema - Parsed schema or schema content string
 * @param key - 32-byte encryption key, hex string, or EncryptionContext
 * @param rootType - Root type name (required if schema is string)
 * @returns The decrypted buffer (same reference)
 *
 * @example
 * ```javascript
 * import { decryptBuffer } from 'flatc-wasm/encryption';
 *
 * const decrypted = decryptBuffer(encrypted, schemaContent, key, 'MyTable');
 * ```
 */
export declare function decryptBuffer(
  buffer: Uint8Array,
  schema: EncryptionSchema | string,
  key: Uint8Array | string | EncryptionContext,
  rootType?: string
): Uint8Array;

declare const encryption: {
  EncryptionContext: typeof EncryptionContext;
  encryptBytes: typeof encryptBytes;
  decryptBytes: typeof decryptBytes;
  encryptScalar: typeof encryptScalar;
  encryptBuffer: typeof encryptBuffer;
  decryptBuffer: typeof decryptBuffer;
  parseSchemaForEncryption: typeof parseSchemaForEncryption;
};

export default encryption;
