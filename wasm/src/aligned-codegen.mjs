/**
 * @module aligned-codegen
 *
 * Generates aligned, fixed-size structs from FlatBuffers schemas for zero-copy
 * WASM interop. Outputs C++ headers and TypeScript view classes that share the
 * same memory layout.
 *
 * This is an alternative to standard FlatBuffers for cases where:
 * - You need zero-copy TypedArray views into WASM linear memory
 * - You don't need schema evolution (vtables add overhead)
 * - Your data is fixed-size (no variable-length strings/vectors)
 *
 * String Support:
 * By default, strings are variable-length and not supported. However, you can
 * enable fixed-length string support by setting the `defaultStringLength` option.
 * Strings will be stored as null-terminated char arrays with the specified max length.
 * Example: defaultStringLength: 255 means strings use 256 bytes (255 chars + null).
 */

// =============================================================================
// Type Definitions and Constants
// =============================================================================

/**
 * Scalar type information for layout calculation
 */
const SCALAR_TYPES = {
  bool:    { size: 1, align: 1, cppType: 'bool',     tsGetter: 'getUint8',    tsSetter: 'setUint8',    tsType: 'boolean' },
  byte:    { size: 1, align: 1, cppType: 'int8_t',   tsGetter: 'getInt8',     tsSetter: 'setInt8',     tsType: 'number' },
  ubyte:   { size: 1, align: 1, cppType: 'uint8_t',  tsGetter: 'getUint8',    tsSetter: 'setUint8',    tsType: 'number' },
  int8:    { size: 1, align: 1, cppType: 'int8_t',   tsGetter: 'getInt8',     tsSetter: 'setInt8',     tsType: 'number' },
  uint8:   { size: 1, align: 1, cppType: 'uint8_t',  tsGetter: 'getUint8',    tsSetter: 'setUint8',    tsType: 'number' },
  short:   { size: 2, align: 2, cppType: 'int16_t',  tsGetter: 'getInt16',    tsSetter: 'setInt16',    tsType: 'number' },
  ushort:  { size: 2, align: 2, cppType: 'uint16_t', tsGetter: 'getUint16',   tsSetter: 'setUint16',   tsType: 'number' },
  int16:   { size: 2, align: 2, cppType: 'int16_t',  tsGetter: 'getInt16',    tsSetter: 'setInt16',    tsType: 'number' },
  uint16:  { size: 2, align: 2, cppType: 'uint16_t', tsGetter: 'getUint16',   tsSetter: 'setUint16',   tsType: 'number' },
  int:     { size: 4, align: 4, cppType: 'int32_t',  tsGetter: 'getInt32',    tsSetter: 'setInt32',    tsType: 'number' },
  uint:    { size: 4, align: 4, cppType: 'uint32_t', tsGetter: 'getUint32',   tsSetter: 'setUint32',   tsType: 'number' },
  int32:   { size: 4, align: 4, cppType: 'int32_t',  tsGetter: 'getInt32',    tsSetter: 'setInt32',    tsType: 'number' },
  uint32:  { size: 4, align: 4, cppType: 'uint32_t', tsGetter: 'getUint32',   tsSetter: 'setUint32',   tsType: 'number' },
  float:   { size: 4, align: 4, cppType: 'float',    tsGetter: 'getFloat32',  tsSetter: 'setFloat32',  tsType: 'number' },
  float32: { size: 4, align: 4, cppType: 'float',    tsGetter: 'getFloat32',  tsSetter: 'setFloat32',  tsType: 'number' },
  long:    { size: 8, align: 8, cppType: 'int64_t',  tsGetter: 'getBigInt64', tsSetter: 'setBigInt64', tsType: 'bigint' },
  ulong:   { size: 8, align: 8, cppType: 'uint64_t', tsGetter: 'getBigUint64',tsSetter: 'setBigUint64',tsType: 'bigint' },
  int64:   { size: 8, align: 8, cppType: 'int64_t',  tsGetter: 'getBigInt64', tsSetter: 'setBigInt64', tsType: 'bigint' },
  uint64:  { size: 8, align: 8, cppType: 'uint64_t', tsGetter: 'getBigUint64',tsSetter: 'setBigUint64',tsType: 'bigint' },
  double:  { size: 8, align: 8, cppType: 'double',   tsGetter: 'getFloat64',  tsSetter: 'setFloat64',  tsType: 'number' },
  float64: { size: 8, align: 8, cppType: 'double',   tsGetter: 'getFloat64',  tsSetter: 'setFloat64',  tsType: 'number' },
};

// =============================================================================
// Schema Parsing
// =============================================================================

/**
 * Parse a FlatBuffers schema and extract struct/table definitions
 * @param {string} schemaContent - The .fbs schema content
 * @param {Object} options - Parsing options
 * @param {number} options.defaultStringLength - Max length for string fields (default: 0 = disabled)
 * @returns {ParsedSchema} Parsed schema with structs and tables
 */
export function parseSchema(schemaContent, options = {}) {
  const { defaultStringLength = 0 } = options;

  const result = {
    namespace: null,
    structs: [],
    tables: [],
    enums: [],
    options: { defaultStringLength },
  };

  // Remove comments
  let content = schemaContent
    .replace(/\/\/.*$/gm, '')
    .replace(/\/\*[\s\S]*?\*\//g, '');

  // Extract namespace
  const nsMatch = content.match(/namespace\s+([\w.]+)\s*;/);
  if (nsMatch) {
    result.namespace = nsMatch[1];
  }

  // Extract enums (for size calculation)
  const enumRegex = /enum\s+(\w+)\s*:\s*(\w+)\s*\{([^}]*)\}/g;
  let enumMatch;
  while ((enumMatch = enumRegex.exec(content)) !== null) {
    const [, name, baseType, body] = enumMatch;
    const values = body.split(',')
      .map(v => v.trim())
      .filter(v => v.length > 0)
      .map(v => {
        const parts = v.split('=').map(p => p.trim());
        return { name: parts[0], value: parts[1] ? parseInt(parts[1], 10) : null };
      });
    result.enums.push({ name, baseType, values });
  }

  // Extract structs
  const structRegex = /struct\s+(\w+)\s*\{([^}]*)\}/g;
  let structMatch;
  while ((structMatch = structRegex.exec(content)) !== null) {
    const [, name, body] = structMatch;
    const fields = parseFields(body, result.enums, { defaultStringLength });
    result.structs.push({ name, fields, isStruct: true });
  }

  // Extract tables (we'll convert compatible ones to aligned structs)
  const tableRegex = /table\s+(\w+)\s*\{([^}]*)\}/g;
  let tableMatch;
  while ((tableMatch = tableRegex.exec(content)) !== null) {
    const [, name, body] = tableMatch;
    const fields = parseFields(body, result.enums, { defaultStringLength });
    result.tables.push({ name, fields, isStruct: false });
  }

  return result;
}

/**
 * Parse field definitions from a struct/table body
 * @param {string} body - The body content between braces
 * @param {Array} enums - Known enum definitions for type resolution
 * @param {Object} options - Parsing options (defaultStringLength, etc.)
 * @returns {Array} Parsed field definitions
 */
function parseFields(body, enums, options = {}) {
  const fields = [];
  const lines = body.split(';').map(l => l.trim()).filter(l => l.length > 0);

  for (const line of lines) {
    // Match: name:type or name:[type] or name:[type:N] or name:[type:0xN]
    // The type portion can be: scalar, [type], [type:decimal], or [type:0xhex]
    const match = line.match(/^(\w+)\s*:\s*(\[?\w+(?::(?:0x[0-9a-fA-F]+|\d+))?\]?)(?:\s*=\s*[^;]*)?$/);
    if (!match) continue;

    const [, name, typeStr] = match;
    const field = parseFieldType(name, typeStr, enums, options);
    if (field) {
      fields.push(field);
    }
  }

  return fields;
}

/**
 * Parse a single field type
 * @param {string} name - Field name
 * @param {string} typeStr - Type string (e.g., "int", "[float:3]", "Vec3", "string")
 * @param {Array} enums - Known enum definitions
 * @param {Object} options - Parsing options (defaultStringLength, etc.)
 * @returns {Object|null} Parsed field or null if unsupported
 */
function parseFieldType(name, typeStr, enums, options = {}) {
  const { defaultStringLength = 0 } = options;

  // Check for string type - convert to fixed-size char array if defaultStringLength is set
  if (typeStr === 'string') {
    if (defaultStringLength > 0) {
      // String is stored as fixed-size char array with null terminator
      // e.g., defaultStringLength=255 means 256 bytes (255 chars + null)
      const totalSize = defaultStringLength + 1; // +1 for null terminator
      return {
        name,
        type: 'string',
        isArray: true,
        arraySize: totalSize,
        isString: true, // Mark as string for special handling in code generation
        maxStringLength: defaultStringLength,
        size: totalSize,
        align: 1,
        cppType: 'char',
        tsGetter: 'getUint8',
        tsSetter: 'setUint8',
        tsType: 'string', // Generated accessors will return/accept string
      };
    }
    return null; // Variable-length strings not supported without defaultStringLength
  }

  // Check for fixed-size array: [type:N] or [type:0xN] (hex)
  const arrayMatch = typeStr.match(/^\[(\w+):(0x[0-9a-fA-F]+|\d+)\]$/);
  if (arrayMatch) {
    const [, elemType, countStr] = arrayMatch;
    // parseInt with radix 0 or 16 handles both decimal and hex (0x prefix)
    const count = countStr.startsWith('0x') ? parseInt(countStr, 16) : parseInt(countStr, 10);

    // Check if element type is a scalar
    const baseInfo = SCALAR_TYPES[elemType];
    if (baseInfo) {
      return {
        name,
        type: elemType,
        isArray: true,
        arraySize: count,
        // Spread baseInfo first, then override size with computed value
        ...baseInfo,
        size: baseInfo.size * count,
        align: baseInfo.align,
      };
    }

    // Check if element type is an enum
    const enumDef = enums.find(e => e.name === elemType);
    if (enumDef) {
      const enumBaseInfo = SCALAR_TYPES[enumDef.baseType];
      if (enumBaseInfo) {
        return {
          name,
          type: elemType,
          isArray: true,
          arraySize: count,
          isEnum: true,
          enumDef,
          ...enumBaseInfo,
          size: enumBaseInfo.size * count,
          align: enumBaseInfo.align,
        };
      }
    }

    // Array of nested structs - size will be resolved later
    return {
      name,
      type: elemType,
      isArray: true,
      arraySize: count,
      isNestedStruct: true,
      size: 0, // Will be computed during layout
      align: 0,
    };
  }

  // Check for variable-length vector: [type] - not supported for aligned
  if (typeStr.startsWith('[') && typeStr.endsWith(']')) {
    return null; // Variable-length vectors not supported
  }

  // Check for scalar type
  const scalarInfo = SCALAR_TYPES[typeStr];
  if (scalarInfo) {
    return {
      name,
      type: typeStr,
      isArray: false,
      arraySize: 1,
      ...scalarInfo,
    };
  }

  // Check for enum type
  const enumDef = enums.find(e => e.name === typeStr);
  if (enumDef) {
    const baseInfo = SCALAR_TYPES[enumDef.baseType];
    if (baseInfo) {
      return {
        name,
        type: typeStr,
        isArray: false,
        arraySize: 1,
        isEnum: true,
        enumDef,
        ...baseInfo,
      };
    }
  }

  // Nested struct reference - will be resolved later
  return {
    name,
    type: typeStr,
    isArray: false,
    arraySize: 1,
    isNestedStruct: true,
    size: 0, // Will be computed during layout
    align: 0,
  };
}

// =============================================================================
// Layout Calculation
// =============================================================================

/**
 * Compute aligned layout for a struct
 * @param {Object} structDef - Struct definition with fields
 * @param {Object} allStructs - Map of all structs for nested resolution
 * @returns {Object} Layout with computed offsets, size, and alignment
 */
export function computeLayout(structDef, allStructs = {}) {
  const layout = {
    name: structDef.name,
    fields: [],
    size: 0,
    align: 1,
  };

  let offset = 0;
  let maxAlign = 1;

  for (const field of structDef.fields) {
    let fieldInfo = { ...field };

    // Resolve nested struct references
    if (field.isNestedStruct) {
      const nestedStruct = allStructs[field.type];
      if (!nestedStruct) {
        throw new Error(`Unknown struct type: ${field.type}`);
      }
      const nestedLayout = computeLayout(nestedStruct, allStructs);
      // For arrays of nested structs, multiply size by array count
      if (field.isArray && field.arraySize > 1) {
        fieldInfo.size = nestedLayout.size * field.arraySize;
      } else {
        fieldInfo.size = nestedLayout.size;
      }
      fieldInfo.align = nestedLayout.align;
      fieldInfo.nestedLayout = nestedLayout;
    }

    // Compute alignment padding
    const alignMask = fieldInfo.align - 1;
    const padding = (fieldInfo.align - (offset & alignMask)) & alignMask;
    offset += padding;

    fieldInfo.offset = offset;
    fieldInfo.padding = padding;

    layout.fields.push(fieldInfo);

    offset += fieldInfo.size;
    maxAlign = Math.max(maxAlign, fieldInfo.align);
  }

  // Add final padding to align struct size
  const finalPadding = (maxAlign - (offset & (maxAlign - 1))) & (maxAlign - 1);
  layout.size = offset + finalPadding;
  layout.align = maxAlign;
  layout.finalPadding = finalPadding;

  return layout;
}

// =============================================================================
// C++ Header Generation
// =============================================================================

/**
 * Generate C++ header for aligned structs
 * @param {Object} schema - Parsed schema
 * @param {Object} options - Generation options
 * @returns {string} C++ header content
 */
export function generateCppHeader(schema, options = {}) {
  const { includeGuard = true, pragmaOnce = true } = options;

  let code = '';

  // Header guard
  if (pragmaOnce) {
    code += '#pragma once\n\n';
  } else if (includeGuard) {
    const guard = schema.namespace
      ? `${schema.namespace.replace(/\./g, '_').toUpperCase()}_ALIGNED_H`
      : 'ALIGNED_STRUCTS_H';
    code += `#ifndef ${guard}\n#define ${guard}\n\n`;
  }

  code += '#include <cstdint>\n';
  code += '#include <cstddef>\n';
  code += '#include <cstring>\n\n';

  // Open namespace
  if (schema.namespace) {
    const parts = schema.namespace.split('.');
    for (const part of parts) {
      code += `namespace ${part} {\n`;
    }
    code += 'namespace Aligned {\n\n';
  }

  // Build struct lookup for nested resolution
  const allStructs = {};
  for (const s of schema.structs) {
    allStructs[s.name] = s;
  }
  for (const t of schema.tables) {
    allStructs[t.name] = t;
  }

  // Generate enums
  for (const enumDef of schema.enums) {
    code += generateCppEnum(enumDef);
  }

  // Generate structs
  for (const structDef of schema.structs) {
    code += generateCppStruct(structDef, allStructs);
  }

  // Generate tables as aligned structs (only if all fields are fixed-size)
  for (const tableDef of schema.tables) {
    if (isFixedSizeTable(tableDef, allStructs)) {
      code += generateCppStruct(tableDef, allStructs);
    }
  }

  // Close namespace
  if (schema.namespace) {
    code += '} // namespace Aligned\n';
    const parts = schema.namespace.split('.');
    for (let i = parts.length - 1; i >= 0; i--) {
      code += `} // namespace ${parts[i]}\n`;
    }
  }

  // Close include guard
  if (!pragmaOnce && includeGuard) {
    const guard = schema.namespace
      ? `${schema.namespace.replace(/\./g, '_').toUpperCase()}_ALIGNED_H`
      : 'ALIGNED_STRUCTS_H';
    code += `\n#endif // ${guard}\n`;
  }

  return code;
}

/**
 * Generate C++ enum definition
 * Always outputs explicit values for each enum constant for clarity
 */
function generateCppEnum(enumDef) {
  const baseInfo = SCALAR_TYPES[enumDef.baseType];
  let code = `enum class ${enumDef.name} : ${baseInfo.cppType} {\n`;

  let currentValue = 0;
  for (let i = 0; i < enumDef.values.length; i++) {
    const v = enumDef.values[i];
    // Use explicit value from schema if present, otherwise use auto-incremented value
    if (v.value !== null) {
      currentValue = v.value;
    }
    code += `  ${v.name} = ${currentValue}`;
    if (i < enumDef.values.length - 1) {
      code += ',';
    }
    code += '\n';
    currentValue++;
  }

  code += '};\n\n';
  return code;
}

/**
 * Recursively flatten nested struct fields for C++ code generation
 * @param {Object} field - The field to process
 * @param {number} baseOffset - Base offset for this field
 * @param {string} namePrefix - Name prefix for nested fields
 * @returns {Array<{name: string, field: Object, offset: number}>} Flattened field list
 */
function flattenNestedFieldsCpp(field, baseOffset, namePrefix) {
  const result = [];

  if (field.isNestedStruct && field.nestedLayout) {
    // Recursively flatten nested struct
    for (const nestedField of field.nestedLayout.fields) {
      const fullName = namePrefix ? `${namePrefix}_${nestedField.name}` : nestedField.name;
      const fieldOffset = baseOffset + nestedField.offset;

      if (nestedField.isNestedStruct && nestedField.nestedLayout) {
        // Recurse for deeply nested structs
        result.push(...flattenNestedFieldsCpp(nestedField, fieldOffset, fullName));
      } else {
        // Scalar or array field - add it directly
        result.push({ name: fullName, field: nestedField, offset: fieldOffset });
      }
    }
  } else {
    // Not a nested struct - add directly
    result.push({ name: namePrefix || field.name, field, offset: baseOffset });
  }

  return result;
}

/**
 * Generate C++ struct definition
 */
function generateCppStruct(structDef, allStructs) {
  const layout = computeLayout(structDef, allStructs);
  let code = '';

  // Collect all flattened fields (handles multi-level nesting)
  const flattenedFields = [];
  for (const field of layout.fields) {
    if (field.isNestedStruct && field.nestedLayout) {
      flattenedFields.push(...flattenNestedFieldsCpp(field, field.offset, field.name));
    } else {
      flattenedFields.push({ name: field.name, field, offset: field.offset });
    }
  }

  code += `// Total size: ${layout.size} bytes, aligned to ${layout.align} bytes\n`;
  code += `struct ${structDef.name} {\n`;

  let paddingCount = 0;
  let lastOffset = 0;

  for (const { name, field, offset } of flattenedFields) {
    // Add padding comment if there's a gap
    if (offset > lastOffset) {
      const gap = offset - lastOffset;
      if (gap > 0 && paddingCount === 0) {
        // Only add padding comment for first gap in struct
      }
    }

    if (field.isString) {
      // Fixed-length string: stored as char array with null terminator
      code += `  char ${name}[${field.arraySize}]; // offset ${offset}, max ${field.maxStringLength} chars + null\n`;
      lastOffset = offset + field.size;
    } else {
      const cppType = field.isEnum ? field.type : field.cppType;
      if (field.isArray) {
        code += `  ${cppType} ${name}[${field.arraySize}]; // offset ${offset}\n`;
        lastOffset = offset + field.size;
      } else {
        code += `  ${cppType} ${name}; // offset ${offset}\n`;
        lastOffset = offset + field.size;
      }
    }
  }

  // Final padding
  if (layout.finalPadding > 0) {
    code += `  uint8_t _pad${paddingCount}[${layout.finalPadding}]; // final padding\n`;
  }

  // Helper methods
  code += '\n';
  code += '  // Create from raw bytes (must be properly aligned)\n';
  code += `  static ${structDef.name}* fromBytes(void* data) {\n`;
  code += `    return reinterpret_cast<${structDef.name}*>(data);\n`;
  code += '  }\n';
  code += `  static const ${structDef.name}* fromBytes(const void* data) {\n`;
  code += `    return reinterpret_cast<const ${structDef.name}*>(data);\n`;
  code += '  }\n';
  code += '\n';
  code += '  // Copy to raw bytes\n';
  code += '  void copyTo(void* dest) const {\n';
  code += `    std::memcpy(dest, this, ${layout.size});\n`;
  code += '  }\n';
  code += '\n';
  code += '  // Copy from another instance\n';
  code += `  void copyFrom(const ${structDef.name}& src) {\n`;
  code += `    std::memcpy(this, &src, ${layout.size});\n`;
  code += '  }\n';

  // Generate string accessors for string fields
  const stringFields = flattenedFields.filter(({ field }) => field.isString);
  if (stringFields.length > 0) {
    code += '\n';
    code += '  // String accessors (null-terminated, fixed-size storage)\n';
    for (const { name, field } of stringFields) {
      // Getter returns const char*
      code += `  const char* get_${name}() const { return ${name}; }\n`;
      // Setter with safe copy (strncpy + ensure null terminator)
      code += `  void set_${name}(const char* value) {\n`;
      code += `    std::strncpy(${name}, value, ${field.maxStringLength});\n`;
      code += `    ${name}[${field.maxStringLength}] = '\\0'; // Ensure null termination\n`;
      code += '  }\n';
    }
  }

  code += '};\n';
  code += `static_assert(sizeof(${structDef.name}) == ${layout.size}, "${structDef.name} size mismatch");\n`;
  code += `static_assert(alignof(${structDef.name}) == ${layout.align}, "${structDef.name} alignment mismatch");\n\n`;

  // Constants
  code += `constexpr size_t ${structDef.name.toUpperCase()}_SIZE = ${layout.size};\n`;
  code += `constexpr size_t ${structDef.name.toUpperCase()}_ALIGN = ${layout.align};\n\n`;

  return code;
}

/**
 * Check if a table can be represented as a fixed-size struct
 */
function isFixedSizeTable(tableDef, allStructs) {
  for (const field of tableDef.fields) {
    // Fixed-length strings are supported (isString flag means it was converted)
    if (field.type === 'string' && !field.isString) return false;
    if (field.isArray && field.arraySize === undefined) return false;

    // Check nested structs
    if (field.isNestedStruct) {
      const nested = allStructs[field.type];
      if (!nested) return false;
      if (!nested.isStruct && !isFixedSizeTable(nested, allStructs)) return false;
    }
  }
  return true;
}

// =============================================================================
// TypeScript Generation
// =============================================================================

/**
 * Generate TypeScript view classes for aligned structs
 * @param {Object} schema - Parsed schema
 * @param {Object} options - Generation options
 * @param {string} options.format - 'ts' for TypeScript (default), 'js' for pure JavaScript
 * @returns {string} TypeScript/JavaScript content
 */
export function generateTypeScript(schema, options = {}) {
  const { moduleType = 'esm', format = 'ts' } = options;
  const useTypes = format !== 'js';

  let code = '';

  code += '/**\n';
  code += ' * Auto-generated aligned buffer accessors\n';
  code += ' * Use with WebAssembly.Memory for zero-copy access\n';
  code += ' */\n\n';

  // Build struct lookup for nested resolution
  const allStructs = {};
  for (const s of schema.structs) {
    allStructs[s.name] = s;
  }
  for (const t of schema.tables) {
    allStructs[t.name] = t;
  }

  // Generate enums as const objects
  for (const enumDef of schema.enums) {
    code += generateTsEnum(enumDef);
  }

  // Generate view classes for structs
  for (const structDef of schema.structs) {
    code += generateTsViewClass(structDef, allStructs);
  }

  // Generate view classes for fixed-size tables
  for (const tableDef of schema.tables) {
    if (isFixedSizeTable(tableDef, allStructs)) {
      code += generateTsViewClass(tableDef, allStructs);
    }
  }

  return code;
}

/**
 * Generate TypeScript enum as const object
 */
function generateTsEnum(enumDef) {
  let code = `export const ${enumDef.name} = {\n`;

  let currentValue = 0;
  for (const v of enumDef.values) {
    if (v.value !== null) {
      currentValue = v.value;
    }
    code += `  ${v.name}: ${currentValue},\n`;
    currentValue++;
  }

  code += '} as const;\n';
  code += `export type ${enumDef.name} = typeof ${enumDef.name}[keyof typeof ${enumDef.name}];\n\n`;

  return code;
}

/**
 * Recursively flatten nested struct fields into a list of scalar field entries
 * @param {Object} field - The field to process
 * @param {number} baseOffset - Base offset for this field
 * @param {string} namePrefix - Name prefix for nested fields
 * @returns {Array<{name: string, field: Object, offset: number}>} Flattened field list
 */
function flattenNestedFields(field, baseOffset, namePrefix) {
  const result = [];

  if (field.isNestedStruct && field.nestedLayout) {
    // Recursively flatten nested struct
    for (const nestedField of field.nestedLayout.fields) {
      const fullName = namePrefix ? `${namePrefix}_${nestedField.name}` : nestedField.name;
      const fieldOffset = baseOffset + nestedField.offset;

      if (nestedField.isNestedStruct && nestedField.nestedLayout) {
        // Recurse for deeply nested structs
        result.push(...flattenNestedFields(nestedField, fieldOffset, fullName));
      } else {
        // Scalar or array field - add it directly
        result.push({ name: fullName, field: nestedField, offset: fieldOffset });
      }
    }
  } else {
    // Not a nested struct - add directly
    result.push({ name: namePrefix || field.name, field, offset: baseOffset });
  }

  return result;
}

/**
 * Generate TypeScript view class for a struct
 */
function generateTsViewClass(structDef, allStructs) {
  const layout = computeLayout(structDef, allStructs);
  let code = '';

  // Collect all flattened fields (handles multi-level nesting)
  const flattenedFields = [];
  for (const field of layout.fields) {
    if (field.isNestedStruct && field.nestedLayout) {
      flattenedFields.push(...flattenNestedFields(field, field.offset, field.name));
    } else {
      flattenedFields.push({ name: field.name, field, offset: field.offset });
    }
  }

  // Size and alignment constants
  code += `export const ${structDef.name.toUpperCase()}_SIZE = ${layout.size};\n`;
  code += `export const ${structDef.name.toUpperCase()}_ALIGN = ${layout.align};\n\n`;

  // Offsets object
  code += `export const ${structDef.name}Offsets = {\n`;
  for (const { name, offset } of flattenedFields) {
    code += `  ${name}: ${offset},\n`;
  }
  code += '} as const;\n\n';

  // View class
  code += `export class ${structDef.name}View {\n`;
  code += '  private readonly view: DataView;\n\n';

  // Constructor
  code += '  constructor(buffer: ArrayBuffer, byteOffset = 0) {\n';
  code += `    this.view = new DataView(buffer, byteOffset, ${layout.size});\n`;
  code += '  }\n\n';

  // Factory for WASM memory
  code += `  static fromMemory(memory: WebAssembly.Memory, ptr: number): ${structDef.name}View {\n`;
  code += `    return new ${structDef.name}View(memory.buffer, ptr);\n`;
  code += '  }\n\n';

  // Factory for Uint8Array
  code += `  static fromBytes(bytes: Uint8Array, offset = 0): ${structDef.name}View {\n`;
  code += `    return new ${structDef.name}View(bytes.buffer, bytes.byteOffset + offset);\n`;
  code += '  }\n\n';

  // Getters and setters for each flattened field
  for (const { name, field, offset } of flattenedFields) {
    if (field.isString) {
      // Generate string accessor (getter returns string, setter accepts string)
      code += generateTsStringAccessor(name, field, offset);
    } else if (field.isArray) {
      // Generate array accessor with custom name
      code += generateTsArrayAccessorWithName(name, field, offset);
    } else {
      code += generateTsAccessor(name, field, offset);
    }
  }

  // toObject() method for debugging
  code += '  toObject(): Record<string, unknown> {\n';
  code += '    return {\n';
  for (const { name, field } of flattenedFields) {
    if (field.isString) {
      // String fields are already returned as string by getter
      code += `      ${name}: this.${name},\n`;
    } else if (field.isArray) {
      code += `      ${name}: Array.from(this.${name}),\n`;
    } else {
      code += `      ${name}: this.${name},\n`;
    }
  }
  code += '    };\n';
  code += '  }\n\n';

  // copyFrom() method for populating from a plain object
  code += '  copyFrom(obj: Partial<Record<string, unknown>>): void {\n';
  for (const { name, field } of flattenedFields) {
    if (field.isString) {
      // String fields: setter handles the conversion
      code += `    if (obj.${name} !== undefined) this.${name} = obj.${name} as string;\n`;
    } else if (field.isArray) {
      code += `    if (obj.${name} !== undefined) {\n`;
      code += `      const arr = this.${name};\n`;
      code += `      const src = obj.${name} as ArrayLike<${field.tsType}>;\n`;
      code += `      for (let i = 0; i < Math.min(arr.length, src.length); i++) arr[i] = src[i];\n`;
      code += '    }\n';
    } else {
      code += `    if (obj.${name} !== undefined) this.${name} = obj.${name} as ${field.tsType};\n`;
    }
  }
  code += '  }\n\n';

  // allocate() static method for creating new instances
  code += `  static allocate(): ${structDef.name}View {\n`;
  code += `    return new ${structDef.name}View(new ArrayBuffer(${layout.size}));\n`;
  code += '  }\n\n';

  // copyTo() method for copying to another buffer
  code += '  copyTo(dest: Uint8Array, offset = 0): void {\n';
  code += `    const src = new Uint8Array(this.view.buffer, this.view.byteOffset, ${layout.size});\n`;
  code += '    dest.set(src, offset);\n';
  code += '  }\n\n';

  // getBytes() method for getting a view of the raw bytes
  code += '  getBytes(): Uint8Array {\n';
  code += `    return new Uint8Array(this.view.buffer, this.view.byteOffset, ${layout.size});\n`;
  code += '  }\n';

  code += '}\n\n';

  // Array view class
  code += generateTsArrayViewClass(structDef.name, layout.size);

  return code;
}

/**
 * Generate getter/setter for a scalar field
 */
function generateTsAccessor(name, field, offset) {
  let code = '';

  const needsLittleEndian = field.size > 1 && !field.tsGetter.includes('Int8');
  const leArg = needsLittleEndian ? ', true' : '';

  // Handle bool specially
  if (field.type === 'bool') {
    code += `  get ${name}(): boolean {\n`;
    code += `    return this.view.${field.tsGetter}(${offset}) !== 0;\n`;
    code += '  }\n';
    code += `  set ${name}(v: boolean) {\n`;
    code += `    this.view.${field.tsSetter}(${offset}, v ? 1 : 0);\n`;
    code += '  }\n\n';
  } else {
    code += `  get ${name}(): ${field.tsType} {\n`;
    code += `    return this.view.${field.tsGetter}(${offset}${leArg});\n`;
    code += '  }\n';
    code += `  set ${name}(v: ${field.tsType}) {\n`;
    code += `    this.view.${field.tsSetter}(${offset}, v${leArg});\n`;
    code += '  }\n\n';
  }

  return code;
}

/**
 * Generate getter/setter for a fixed-length string field
 * Strings are stored as null-terminated char arrays
 */
function generateTsStringAccessor(name, field, offset) {
  let code = '';
  const maxLen = field.maxStringLength;
  const bufSize = field.arraySize;

  // Getter: read bytes until null terminator, decode as UTF-8
  code += `  get ${name}(): string {\n`;
  code += `    const bytes = new Uint8Array(this.view.buffer, this.view.byteOffset + ${offset}, ${bufSize});\n`;
  code += '    // Find null terminator\n';
  code += '    let len = 0;\n';
  code += `    while (len < ${maxLen} && bytes[len] !== 0) len++;\n`;
  code += '    return new TextDecoder().decode(bytes.subarray(0, len));\n';
  code += '  }\n';

  // Setter: encode as UTF-8, copy to buffer, null-terminate
  code += `  set ${name}(v: string) {\n`;
  code += `    const bytes = new Uint8Array(this.view.buffer, this.view.byteOffset + ${offset}, ${bufSize});\n`;
  code += '    const encoded = new TextEncoder().encode(v);\n';
  code += `    const copyLen = Math.min(encoded.length, ${maxLen});\n`;
  code += '    bytes.set(encoded.subarray(0, copyLen));\n';
  code += '    // Null-terminate\n';
  code += `    for (let i = copyLen; i < ${bufSize}; i++) bytes[i] = 0;\n`;
  code += '  }\n\n';

  // Also provide raw bytes accessor for advanced use
  code += `  get ${name}Bytes(): Uint8Array {\n`;
  code += `    return new Uint8Array(this.view.buffer, this.view.byteOffset + ${offset}, ${bufSize});\n`;
  code += '  }\n\n';

  return code;
}

/**
 * Get TypedArray type for a scalar type
 */
function getTypedArrayType(type) {
  const typedArrayMap = {
    byte: 'Int8Array', ubyte: 'Uint8Array', int8: 'Int8Array', uint8: 'Uint8Array',
    short: 'Int16Array', ushort: 'Uint16Array', int16: 'Int16Array', uint16: 'Uint16Array',
    int: 'Int32Array', uint: 'Uint32Array', int32: 'Int32Array', uint32: 'Uint32Array',
    float: 'Float32Array', float32: 'Float32Array',
    long: 'BigInt64Array', ulong: 'BigUint64Array', int64: 'BigInt64Array', uint64: 'BigUint64Array',
    double: 'Float64Array', float64: 'Float64Array',
  };
  return typedArrayMap[type] || 'Uint8Array';
}

/**
 * Generate accessor for a fixed-size array field
 */
function generateTsArrayAccessor(field) {
  return generateTsArrayAccessorWithName(field.name, field, field.offset);
}

/**
 * Generate accessor for a fixed-size array field with custom name and offset
 */
function generateTsArrayAccessorWithName(name, field, offset) {
  let code = '';
  const typedArrayType = getTypedArrayType(field.type);

  code += `  get ${name}(): ${typedArrayType} {\n`;
  code += `    return new ${typedArrayType}(this.view.buffer, this.view.byteOffset + ${offset}, ${field.arraySize});\n`;
  code += '  }\n\n';

  return code;
}

/**
 * Generate array view class for bulk access
 */
function generateTsArrayViewClass(structName, structSize) {
  let code = '';

  code += `export class ${structName}ArrayView {\n`;
  code += '  private readonly buffer: ArrayBuffer;\n';
  code += '  private readonly baseOffset: number;\n';
  code += '  readonly length: number;\n\n';

  code += '  constructor(buffer: ArrayBuffer, byteOffset: number, count: number) {\n';
  code += '    this.buffer = buffer;\n';
  code += '    this.baseOffset = byteOffset;\n';
  code += '    this.length = count;\n';
  code += '  }\n\n';

  code += `  static fromMemory(memory: WebAssembly.Memory, ptr: number, count: number): ${structName}ArrayView {\n`;
  code += `    return new ${structName}ArrayView(memory.buffer, ptr, count);\n`;
  code += '  }\n\n';

  code += `  at(index: number): ${structName}View {\n`;
  code += `    if (index < 0 || index >= this.length) {\n`;
  code += `      throw new RangeError(\`Index \${index} out of bounds [0, \${this.length})\`);\n`;
  code += '    }\n';
  code += `    return new ${structName}View(this.buffer, this.baseOffset + index * ${structSize});\n`;
  code += '  }\n\n';

  code += `  *[Symbol.iterator](): Iterator<${structName}View> {\n`;
  code += '    for (let i = 0; i < this.length; i++) {\n';
  code += '      yield this.at(i);\n';
  code += '    }\n';
  code += '  }\n';

  code += '}\n\n';

  return code;
}

// =============================================================================
// Plain JavaScript Generation (no TypeScript types)
// =============================================================================

/**
 * Generate plain JavaScript view classes for aligned structs (no TypeScript types)
 * @param {Object} schema - Parsed schema
 * @param {Object} options - Generation options
 * @returns {string} JavaScript content
 */
export function generateJavaScript(schema, options = {}) {
  // Build struct lookup for nested resolution
  const allStructs = {};
  for (const s of schema.structs) {
    allStructs[s.name] = s;
  }
  for (const t of schema.tables) {
    allStructs[t.name] = t;
  }

  let code = '';
  code += '/**\n';
  code += ' * Auto-generated aligned buffer accessors\n';
  code += ' * Use with WebAssembly.Memory for zero-copy access\n';
  code += ' */\n\n';

  // Generate enums as const objects (no TypeScript type alias)
  for (const enumDef of schema.enums) {
    code += `const ${enumDef.name} = {\n`;
    let currentValue = 0;
    for (const v of enumDef.values) {
      if (v.value !== null) {
        currentValue = v.value;
      }
      code += `  ${v.name}: ${currentValue},\n`;
      currentValue++;
    }
    code += '};\n\n';
  }

  // Generate view classes for structs
  for (const structDef of schema.structs) {
    code += generateJsViewClass(structDef, allStructs);
  }

  // Generate view classes for fixed-size tables
  for (const tableDef of schema.tables) {
    if (isFixedSizeTable(tableDef, allStructs)) {
      code += generateJsViewClass(tableDef, allStructs);
    }
  }

  return code;
}

/**
 * Generate plain JavaScript view class for a struct
 */
function generateJsViewClass(structDef, allStructs) {
  const layout = computeLayout(structDef, allStructs);
  let code = '';

  // Collect all flattened fields (handles multi-level nesting)
  const flattenedFields = [];
  for (const field of layout.fields) {
    if (field.isNestedStruct && field.nestedLayout) {
      flattenedFields.push(...flattenNestedFields(field, field.offset, field.name));
    } else {
      flattenedFields.push({ name: field.name, field, offset: field.offset });
    }
  }

  // Size and alignment constants
  code += `const ${structDef.name.toUpperCase()}_SIZE = ${layout.size};\n`;
  code += `const ${structDef.name.toUpperCase()}_ALIGN = ${layout.align};\n\n`;

  // Offsets object
  code += `const ${structDef.name}Offsets = {\n`;
  for (const { name, offset } of flattenedFields) {
    code += `  ${name}: ${offset},\n`;
  }
  code += '};\n\n';

  // View class
  code += `class ${structDef.name}View {\n`;

  // Constructor
  code += '  constructor(buffer, byteOffset = 0) {\n';
  code += `    this.view = new DataView(buffer, byteOffset, ${layout.size});\n`;
  code += '  }\n\n';

  // Factory for WASM memory
  code += `  static fromMemory(memory, ptr) {\n`;
  code += `    return new ${structDef.name}View(memory.buffer, ptr);\n`;
  code += '  }\n\n';

  // Factory for Uint8Array
  code += `  static fromBytes(bytes, offset = 0) {\n`;
  code += `    return new ${structDef.name}View(bytes.buffer, bytes.byteOffset + offset);\n`;
  code += '  }\n\n';

  // Getters and setters for each flattened field
  for (const { name, field, offset } of flattenedFields) {
    if (field.isString) {
      // Generate string accessor (getter returns string, setter accepts string)
      code += generateJsStringAccessor(name, field, offset);
    } else if (field.isArray) {
      code += generateJsArrayAccessor(name, field, offset);
    } else {
      code += generateJsAccessor(name, field, offset);
    }
  }

  // toObject() method for debugging
  code += '  toObject() {\n';
  code += '    return {\n';
  for (const { name, field } of flattenedFields) {
    if (field.isString) {
      // String fields are already returned as string by getter
      code += `      ${name}: this.${name},\n`;
    } else if (field.isArray) {
      code += `      ${name}: Array.from(this.${name}),\n`;
    } else {
      code += `      ${name}: this.${name},\n`;
    }
  }
  code += '    };\n';
  code += '  }\n\n';

  // copyFrom() method for populating from a plain object
  code += '  copyFrom(obj) {\n';
  for (const { name, field } of flattenedFields) {
    if (field.isString) {
      // String fields: setter handles the conversion
      code += `    if (obj.${name} !== undefined) this.${name} = obj.${name};\n`;
    } else if (field.isArray) {
      code += `    if (obj.${name} !== undefined) {\n`;
      code += `      const arr = this.${name};\n`;
      code += `      const src = obj.${name};\n`;
      code += `      for (let i = 0; i < Math.min(arr.length, src.length); i++) arr[i] = src[i];\n`;
      code += '    }\n';
    } else {
      code += `    if (obj.${name} !== undefined) this.${name} = obj.${name};\n`;
    }
  }
  code += '  }\n\n';

  // allocate() static method for creating new instances
  code += `  static allocate() {\n`;
  code += `    return new ${structDef.name}View(new ArrayBuffer(${layout.size}));\n`;
  code += '  }\n\n';

  // copyTo() method for copying to another buffer
  code += '  copyTo(dest, offset = 0) {\n';
  code += `    const src = new Uint8Array(this.view.buffer, this.view.byteOffset, ${layout.size});\n`;
  code += '    dest.set(src, offset);\n';
  code += '  }\n\n';

  // getBytes() method for getting a view of the raw bytes
  code += '  getBytes() {\n';
  code += `    return new Uint8Array(this.view.buffer, this.view.byteOffset, ${layout.size});\n`;
  code += '  }\n';

  code += '}\n\n';

  // Array view class
  code += generateJsArrayViewClass(structDef.name, layout.size);

  return code;
}

/**
 * Generate getter/setter for a scalar field (plain JS)
 */
function generateJsAccessor(name, field, offset) {
  let code = '';

  const needsLittleEndian = field.size > 1 && !field.tsGetter.includes('Int8');
  const leArg = needsLittleEndian ? ', true' : '';

  // Handle bool specially
  if (field.type === 'bool') {
    code += `  get ${name}() {\n`;
    code += `    return this.view.${field.tsGetter}(${offset}) !== 0;\n`;
    code += '  }\n';
    code += `  set ${name}(v) {\n`;
    code += `    this.view.${field.tsSetter}(${offset}, v ? 1 : 0);\n`;
    code += '  }\n\n';
  } else {
    code += `  get ${name}() {\n`;
    code += `    return this.view.${field.tsGetter}(${offset}${leArg});\n`;
    code += '  }\n';
    code += `  set ${name}(v) {\n`;
    code += `    this.view.${field.tsSetter}(${offset}, v${leArg});\n`;
    code += '  }\n\n';
  }

  return code;
}

/**
 * Generate accessor for a fixed-size array field (plain JS)
 */
function generateJsArrayAccessor(name, field, offset) {
  let code = '';
  const typedArrayType = getTypedArrayType(field.type);

  code += `  get ${name}() {\n`;
  code += `    return new ${typedArrayType}(this.view.buffer, this.view.byteOffset + ${offset}, ${field.arraySize});\n`;
  code += '  }\n\n';

  return code;
}

/**
 * Generate getter/setter for a fixed-length string field (plain JS)
 * Strings are stored as null-terminated char arrays
 */
function generateJsStringAccessor(name, field, offset) {
  let code = '';
  const maxLen = field.maxStringLength;
  const bufSize = field.arraySize;

  // Getter: read bytes until null terminator, decode as UTF-8
  code += `  get ${name}() {\n`;
  code += `    const bytes = new Uint8Array(this.view.buffer, this.view.byteOffset + ${offset}, ${bufSize});\n`;
  code += '    // Find null terminator\n';
  code += '    let len = 0;\n';
  code += `    while (len < ${maxLen} && bytes[len] !== 0) len++;\n`;
  code += '    return new TextDecoder().decode(bytes.subarray(0, len));\n';
  code += '  }\n';

  // Setter: encode as UTF-8, copy to buffer, null-terminate
  code += `  set ${name}(v) {\n`;
  code += `    const bytes = new Uint8Array(this.view.buffer, this.view.byteOffset + ${offset}, ${bufSize});\n`;
  code += '    const encoded = new TextEncoder().encode(v);\n';
  code += `    const copyLen = Math.min(encoded.length, ${maxLen});\n`;
  code += '    bytes.set(encoded.subarray(0, copyLen));\n';
  code += '    // Null-terminate\n';
  code += `    for (let i = copyLen; i < ${bufSize}; i++) bytes[i] = 0;\n`;
  code += '  }\n\n';

  // Also provide raw bytes accessor for advanced use
  code += `  get ${name}Bytes() {\n`;
  code += `    return new Uint8Array(this.view.buffer, this.view.byteOffset + ${offset}, ${bufSize});\n`;
  code += '  }\n\n';

  return code;
}

/**
 * Generate array view class for bulk access (plain JS)
 */
function generateJsArrayViewClass(structName, structSize) {
  let code = '';

  code += `class ${structName}ArrayView {\n`;

  code += '  constructor(buffer, byteOffset, count) {\n';
  code += '    this.buffer = buffer;\n';
  code += '    this.baseOffset = byteOffset;\n';
  code += '    this.length = count;\n';
  code += '  }\n\n';

  code += `  static fromMemory(memory, ptr, count) {\n`;
  code += `    return new ${structName}ArrayView(memory.buffer, ptr, count);\n`;
  code += '  }\n\n';

  code += `  at(index) {\n`;
  code += `    if (index < 0 || index >= this.length) {\n`;
  code += `      throw new RangeError(\`Index \${index} out of bounds [0, \${this.length})\`);\n`;
  code += '    }\n';
  code += `    return new ${structName}View(this.buffer, this.baseOffset + index * ${structSize});\n`;
  code += '  }\n\n';

  code += `  *[Symbol.iterator]() {\n`;
  code += '    for (let i = 0; i < this.length; i++) {\n';
  code += '      yield this.at(i);\n';
  code += '    }\n';
  code += '  }\n';

  code += '}\n\n';

  return code;
}

// =============================================================================
// Main API
// =============================================================================

/**
 * Generate aligned code from a FlatBuffers schema
 * @param {string} schemaContent - The .fbs schema content
 * @param {Object} options - Generation options
 * @param {number} options.defaultStringLength - Max length for string fields (default: 0 = disabled, 255 = recommended)
 * @returns {{ cpp: string, ts: string, js: string, schema: Object, layouts: Object }} Generated code and layout info
 */
export function generateAlignedCode(schemaContent, options = {}) {
  const { defaultStringLength = 0 } = options;
  const schema = parseSchema(schemaContent, { defaultStringLength });
  const cpp = generateCppHeader(schema, options);
  const ts = generateTypeScript(schema, options);
  const js = generateJavaScript(schema, options);

  // Compute layouts for all structs
  const allStructs = {};
  for (const s of schema.structs) {
    allStructs[s.name] = s;
  }
  for (const t of schema.tables) {
    allStructs[t.name] = t;
  }

  const layouts = {};
  for (const structDef of [...schema.structs, ...schema.tables]) {
    try {
      if (structDef.fields.length > 0) {
        layouts[structDef.name] = computeLayout(structDef, allStructs);
      }
    } catch (e) {
      // Skip structs with unresolved references
    }
  }

  return { cpp, ts, js, schema, layouts };
}

export default {
  parseSchema,
  computeLayout,
  generateCppHeader,
  generateTypeScript,
  generateJavaScript,
  generateAlignedCode,
};
