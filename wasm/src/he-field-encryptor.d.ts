/**
 * HE Field Encryptor with Companion Schema Generation
 */

import { HEContext } from './he-context.js';
import { FlatcRunner } from './runner.js';

/** Identified field eligible for HE encryption */
export interface HEFieldInfo {
  /** Table name containing the field */
  table: string;
  /** Field name */
  field: string;
  /** Original FlatBuffer type (lowercase) */
  type: string;
  /** HE method to use ('Int64' or 'Double') */
  heMethod: string;
}

/**
 * Identify fields eligible for HE encryption in a schema.
 * @param schemaSource FlatBuffer schema (.fbs) content
 * @param fieldNames Optional specific field names to encrypt
 */
export function identifyHEFields(
  schemaSource: string,
  fieldNames?: string[]
): HEFieldInfo[];

/**
 * Generate a companion schema where HE-targeted scalar fields become [ubyte] vectors.
 * @param schemaSource Original FlatBuffer schema (.fbs) content
 * @param fields Fields to convert to ciphertext vectors
 */
export function generateCompanionSchema(
  schemaSource: string,
  fields: Pick<HEFieldInfo, 'table' | 'field'>[]
): string;

/**
 * Encrypt specified fields in JSON data using HE.
 * @param jsonData Parsed JSON data conforming to original schema
 * @param heContext HEContext with encryption capability
 * @param fields Fields to encrypt
 */
export function encryptFields(
  jsonData: Record<string, unknown>,
  heContext: HEContext,
  fields: HEFieldInfo[]
): Record<string, unknown>;

/**
 * Decrypt ciphertext vector fields back to plaintext values.
 * @param jsonData JSON data with encrypted fields
 * @param heContext Client HEContext with decryption capability
 * @param fields Fields to decrypt
 */
export function decryptFields(
  jsonData: Record<string, unknown>,
  heContext: HEContext,
  fields: HEFieldInfo[]
): Record<string, unknown>;

/**
 * Full pipeline: encrypt fields, generate binary via companion schema.
 * @param runner FlatcRunner instance
 * @param originalSchema Original schema source
 * @param companionSchema Companion schema with [ubyte] vectors
 * @param jsonData Input JSON data
 * @param heContext HEContext for encryption
 * @param fields Fields to encrypt
 * @param options Additional generateBinary options
 */
export function buildEncryptedBinary(
  runner: FlatcRunner,
  originalSchema: string,
  companionSchema: string,
  jsonData: Record<string, unknown> | string,
  heContext: HEContext,
  fields: HEFieldInfo[],
  options?: Record<string, unknown>
): Uint8Array;
