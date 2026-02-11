/**
 * HE Field Encryptor with Companion Schema Generation
 *
 * HE ciphertexts (~32KB+ per field at polyDegree=4096) cannot replace fixed-size
 * FlatBuffer scalar fields in-place. This module auto-generates a **companion
 * FlatBuffer schema** where HE-encrypted fields become `[ubyte]` vectors.
 *
 * The companion schema preserves all non-encrypted fields unchanged, so the
 * encrypted FlatBuffer is structurally valid and can flow through StreamingDispatcher.
 */

// FlatBuffer scalar types that can be HE-encrypted
const HE_ELIGIBLE_TYPES = new Set([
  'int8', 'int16', 'int32', 'int64',
  'uint8', 'uint16', 'uint32', 'uint64',
  'float', 'float32', 'float64', 'double',
  'byte', 'ubyte', 'short', 'ushort',
  'int', 'uint', 'long', 'ulong',
]);

// Map FlatBuffer type names to canonical forms for encrypt/decrypt
const TYPE_TO_HE_METHOD = {
  int8: 'Int64', byte: 'Int64',
  int16: 'Int64', short: 'Int64',
  int32: 'Int64', int: 'Int64',
  int64: 'Int64', long: 'Int64',
  uint8: 'Int64', ubyte: 'Int64',
  uint16: 'Int64', ushort: 'Int64',
  uint32: 'Int64', uint: 'Int64',
  uint64: 'Int64', ulong: 'Int64',
  float: 'Double', float32: 'Double',
  double: 'Double', float64: 'Double',
};

/**
 * Parse field definitions from a FlatBuffer schema table.
 * Returns an array of { name, type, metadata } for each field.
 *
 * @param {string} tableBody - The body of a table definition (between braces)
 * @returns {Array<{name: string, type: string, metadata: string|null}>}
 */
function parseTableFields(tableBody) {
  const fields = [];
  const lines = tableBody.split('\n');

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('//')) continue;

    // Match field: "name:type" with optional default, metadata, etc.
    const match = trimmed.match(/^(\w+)\s*:\s*(\[?\w+\]?)\s*(=\s*[^;(]*)?\s*(\([^)]*\))?\s*;/);
    if (match) {
      fields.push({
        name: match[1],
        type: match[2],
        metadata: match[4] || null,
      });
    }
  }

  return fields;
}

/**
 * Parse all table definitions from a schema source.
 *
 * @param {string} schemaSource - FlatBuffer schema (.fbs) content
 * @returns {Array<{name: string, fields: Array}>}
 */
function parseTables(schemaSource) {
  const tables = [];
  const tableRegex = /table\s+(\w+)\s*\{([^}]*)\}/g;
  let match;

  while ((match = tableRegex.exec(schemaSource)) !== null) {
    tables.push({
      name: match[1],
      fields: parseTableFields(match[2]),
      raw: match[0],
      bodyStart: match.index + match[0].indexOf('{') + 1,
      bodyEnd: match.index + match[0].lastIndexOf('}'),
    });
  }

  return tables;
}

/**
 * Identify fields eligible for HE encryption in a schema.
 *
 * Fields are eligible if they are scalar numeric types (int8..uint64, float, double).
 * Optionally filter by field name list or by `he_encrypted` metadata attribute.
 *
 * @param {string} schemaSource - FlatBuffer schema (.fbs) content
 * @param {string[]} [fieldNames] - Specific field names to encrypt (if omitted, uses metadata)
 * @returns {Array<{table: string, field: string, type: string, heMethod: string}>}
 */
export function identifyHEFields(schemaSource, fieldNames) {
  const tables = parseTables(schemaSource);
  const result = [];

  for (const table of tables) {
    for (const field of table.fields) {
      const baseType = field.type.replace(/[\[\]]/g, '');
      const isEligible = HE_ELIGIBLE_TYPES.has(baseType.toLowerCase());

      if (!isEligible) continue;

      // Check if field should be encrypted
      let shouldEncrypt = false;

      if (fieldNames && fieldNames.length > 0) {
        // Explicit field name list
        shouldEncrypt = fieldNames.includes(field.name) ||
                        fieldNames.includes(`${table.name}.${field.name}`);
      } else if (field.metadata) {
        // Check for he_encrypted metadata attribute
        shouldEncrypt = field.metadata.includes('he_encrypted');
      }

      if (shouldEncrypt) {
        result.push({
          table: table.name,
          field: field.name,
          type: baseType.toLowerCase(),
          heMethod: TYPE_TO_HE_METHOD[baseType.toLowerCase()] || 'Int64',
        });
      }
    }
  }

  return result;
}

/**
 * Generate a companion schema where HE-targeted scalar fields become `[ubyte]` vectors.
 * Non-encrypted fields remain unchanged, producing a valid .fbs schema.
 *
 * @param {string} schemaSource - Original FlatBuffer schema (.fbs) content
 * @param {Array<{table: string, field: string}>} fields - Fields to convert
 * @returns {string} Companion schema with ciphertext vector fields
 */
export function generateCompanionSchema(schemaSource, fields) {
  // Build a lookup set of "TableName.fieldName" for quick matching
  const fieldSet = new Set(fields.map(f => `${f.table}.${f.field}`));

  let result = schemaSource;
  const tables = parseTables(schemaSource);

  // Process tables in reverse order to preserve string offsets
  for (let t = tables.length - 1; t >= 0; t--) {
    const table = tables[t];
    let modified = false;
    let newBody = '';
    const bodyContent = schemaSource.substring(table.bodyStart, table.bodyEnd);
    const lines = bodyContent.split('\n');

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('//')) {
        newBody += line + '\n';
        continue;
      }

      // Check if this line's field should be converted
      const fieldMatch = trimmed.match(/^(\w+)\s*:\s*(\[?\w+\]?)/);
      if (fieldMatch) {
        const fieldName = fieldMatch[1];
        const key = `${table.name}.${fieldName}`;
        if (fieldSet.has(key)) {
          // Replace the scalar type with [ubyte] vector
          const newLine = line.replace(
            /:\s*\[?\w+\]?/,
            ':[ubyte]'
          );
          newBody += newLine + '\n';
          modified = true;
          continue;
        }
      }

      newBody += line + '\n';
    }

    if (modified) {
      // Replace the table body in the result
      const tableStart = result.indexOf(table.raw);
      if (tableStart >= 0) {
        const beforeBrace = table.raw.indexOf('{');
        const prefix = table.raw.substring(0, beforeBrace + 1);
        const newTable = prefix + '\n' + newBody.trimEnd() + '\n}';
        result = result.substring(0, tableStart) + newTable +
                 result.substring(tableStart + table.raw.length);
      }
    }
  }

  return result;
}

/**
 * Encrypt specified fields in JSON data using HE.
 * Numeric values are replaced with Uint8Array ciphertexts (as regular arrays
 * for JSON compatibility with companion schema's [ubyte] vectors).
 *
 * @param {object} jsonData - Parsed JSON data conforming to original schema
 * @param {object} heContext - HEContext with encryption capability
 * @param {Array<{field: string, type: string, heMethod: string}>} fields - Fields to encrypt
 * @returns {object} JSON data with encrypted fields (ciphertexts as number arrays)
 */
export function encryptFields(jsonData, heContext, fields) {
  if (!jsonData || typeof jsonData !== 'object') {
    throw new Error('jsonData must be a non-null object');
  }
  if (!heContext) {
    throw new Error('heContext is required');
  }

  const result = { ...jsonData };

  for (const fieldInfo of fields) {
    const fieldName = fieldInfo.field;
    if (!(fieldName in result)) continue;

    const value = result[fieldName];
    if (value === null || value === undefined) continue;

    let ciphertext;
    if (fieldInfo.heMethod === 'Double') {
      ciphertext = heContext.encryptDouble(Number(value));
    } else {
      ciphertext = heContext.encryptInt64(BigInt(value));
    }

    // Convert to regular array for JSON serialization (companion schema [ubyte])
    result[fieldName] = Array.from(ciphertext);
  }

  return result;
}

/**
 * Decrypt ciphertext vector fields back to plaintext values.
 *
 * @param {object} jsonData - JSON data with encrypted fields (ciphertext as number arrays)
 * @param {object} heContext - HEContext with decryption capability (client context)
 * @param {Array<{field: string, type: string, heMethod: string}>} fields - Fields to decrypt
 * @returns {object} JSON data with decrypted plaintext values
 */
export function decryptFields(jsonData, heContext, fields) {
  if (!jsonData || typeof jsonData !== 'object') {
    throw new Error('jsonData must be a non-null object');
  }
  if (!heContext || !heContext.canDecrypt()) {
    throw new Error('heContext must be a client context with decryption capability');
  }

  const result = { ...jsonData };

  for (const fieldInfo of fields) {
    const fieldName = fieldInfo.field;
    if (!(fieldName in result)) continue;

    const value = result[fieldName];
    if (value === null || value === undefined) continue;

    // Convert array back to Uint8Array ciphertext
    const ciphertext = value instanceof Uint8Array ? value : new Uint8Array(value);

    if (fieldInfo.heMethod === 'Double') {
      result[fieldName] = heContext.decryptDouble(ciphertext);
    } else {
      const bigVal = heContext.decryptInt64(ciphertext);
      // Convert bigint back to number for JSON compatibility if it fits
      result[fieldName] = Number(bigVal);
    }
  }

  return result;
}

/**
 * Full pipeline: encrypt fields → generate binary via companion schema → valid FlatBuffer.
 *
 * @param {object} runner - FlatcRunner instance
 * @param {string} originalSchema - Original FlatBuffer schema source
 * @param {string} companionSchema - Companion schema with [ubyte] vector fields
 * @param {object|string} jsonData - Input JSON data (object or string)
 * @param {object} heContext - HEContext for encryption
 * @param {Array<{field: string, type: string, heMethod: string}>} fields - Fields to encrypt
 * @param {object} [options] - Additional options for generateBinary
 * @returns {Uint8Array} FlatBuffer binary with encrypted ciphertext vectors
 */
export function buildEncryptedBinary(runner, originalSchema, companionSchema, jsonData, heContext, fields, options = {}) {
  // Parse JSON if string
  const data = typeof jsonData === 'string' ? JSON.parse(jsonData) : jsonData;

  // Encrypt the specified fields
  const encryptedData = encryptFields(data, heContext, fields);

  // Convert to JSON string for FlatcRunner
  const encryptedJson = JSON.stringify(encryptedData);

  // Normalize companion schema for FlatcRunner { entry, files } format
  const schemaInput = {
    entry: '/companion_schema.fbs',
    files: { '/companion_schema.fbs': companionSchema },
  };

  // Generate binary using companion schema
  const result = runner.generateBinary(schemaInput, encryptedJson, options);

  return result;
}
