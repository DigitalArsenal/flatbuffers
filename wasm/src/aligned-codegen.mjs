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
 * @returns {ParsedSchema} Parsed schema with structs and tables
 */
export function parseSchema(schemaContent) {
  const result = {
    namespace: null,
    structs: [],
    tables: [],
    enums: [],
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
    const fields = parseFields(body, result.enums);
    result.structs.push({ name, fields, isStruct: true });
  }

  // Extract tables (we'll convert compatible ones to aligned structs)
  const tableRegex = /table\s+(\w+)\s*\{([^}]*)\}/g;
  let tableMatch;
  while ((tableMatch = tableRegex.exec(content)) !== null) {
    const [, name, body] = tableMatch;
    const fields = parseFields(body, result.enums);
    result.tables.push({ name, fields, isStruct: false });
  }

  return result;
}

/**
 * Parse field definitions from a struct/table body
 * @param {string} body - The body content between braces
 * @param {Array} enums - Known enum definitions for type resolution
 * @returns {Array} Parsed field definitions
 */
function parseFields(body, enums) {
  const fields = [];
  const lines = body.split(';').map(l => l.trim()).filter(l => l.length > 0);

  for (const line of lines) {
    // Match: name:type or name:[type] or name:[type:N]
    const match = line.match(/^(\w+)\s*:\s*(\[?\w+(?::\d+)?\]?)(?:\s*=\s*[^;]*)?$/);
    if (!match) continue;

    const [, name, typeStr] = match;
    const field = parseFieldType(name, typeStr, enums);
    if (field) {
      fields.push(field);
    }
  }

  return fields;
}

/**
 * Parse a single field type
 * @param {string} name - Field name
 * @param {string} typeStr - Type string (e.g., "int", "[float:3]", "Vec3")
 * @param {Array} enums - Known enum definitions
 * @returns {Object|null} Parsed field or null if unsupported
 */
function parseFieldType(name, typeStr, enums) {
  // Check for fixed-size array: [type:N]
  const arrayMatch = typeStr.match(/^\[(\w+):(\d+)\]$/);
  if (arrayMatch) {
    const [, elemType, countStr] = arrayMatch;
    const count = parseInt(countStr, 10);
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
      fieldInfo.size = nestedLayout.size;
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
  code += '#include <cstddef>\n\n';

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
 */
function generateCppEnum(enumDef) {
  const baseInfo = SCALAR_TYPES[enumDef.baseType];
  let code = `enum class ${enumDef.name} : ${baseInfo.cppType} {\n`;

  for (let i = 0; i < enumDef.values.length; i++) {
    const v = enumDef.values[i];
    code += `  ${v.name}`;
    if (v.value !== null) {
      code += ` = ${v.value}`;
    }
    if (i < enumDef.values.length - 1) {
      code += ',';
    }
    code += '\n';
  }

  code += '};\n\n';
  return code;
}

/**
 * Generate C++ struct definition
 */
function generateCppStruct(structDef, allStructs) {
  const layout = computeLayout(structDef, allStructs);
  let code = '';

  code += `// Total size: ${layout.size} bytes, aligned to ${layout.align} bytes\n`;
  code += `struct ${structDef.name} {\n`;

  let paddingCount = 0;
  for (const field of layout.fields) {
    // Add padding comment if needed
    if (field.padding > 0) {
      code += `  // ${field.padding} byte(s) padding\n`;
    }

    if (field.isNestedStruct) {
      // Flatten nested struct fields
      code += `  // Nested: ${field.type}\n`;
      for (const nestedField of field.nestedLayout.fields) {
        const cppType = nestedField.isEnum ? nestedField.type : nestedField.cppType;
        if (nestedField.isArray) {
          code += `  ${cppType} ${field.name}_${nestedField.name}[${nestedField.arraySize}]; // offset ${field.offset + nestedField.offset}\n`;
        } else {
          code += `  ${cppType} ${field.name}_${nestedField.name}; // offset ${field.offset + nestedField.offset}\n`;
        }
      }
    } else {
      const cppType = field.isEnum ? field.type : field.cppType;
      if (field.isArray) {
        code += `  ${cppType} ${field.name}[${field.arraySize}]; // offset ${field.offset}\n`;
      } else {
        code += `  ${cppType} ${field.name}; // offset ${field.offset}\n`;
      }
    }
  }

  // Final padding
  if (layout.finalPadding > 0) {
    code += `  uint8_t _pad${paddingCount}[${layout.finalPadding}]; // final padding\n`;
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
    // Variable-length types not supported
    if (field.type === 'string') return false;
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
 * @returns {string} TypeScript content
 */
export function generateTypeScript(schema, options = {}) {
  const { moduleType = 'esm' } = options;

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
 * Generate TypeScript view class for a struct
 */
function generateTsViewClass(structDef, allStructs) {
  const layout = computeLayout(structDef, allStructs);
  let code = '';

  // Size and alignment constants
  code += `export const ${structDef.name.toUpperCase()}_SIZE = ${layout.size};\n`;
  code += `export const ${structDef.name.toUpperCase()}_ALIGN = ${layout.align};\n\n`;

  // Offsets object
  code += `export const ${structDef.name}Offsets = {\n`;
  for (const field of layout.fields) {
    if (field.isNestedStruct) {
      for (const nestedField of field.nestedLayout.fields) {
        code += `  ${field.name}_${nestedField.name}: ${field.offset + nestedField.offset},\n`;
      }
    } else {
      code += `  ${field.name}: ${field.offset},\n`;
    }
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

  // Getters and setters for each field
  for (const field of layout.fields) {
    if (field.isNestedStruct) {
      // Generate accessors for flattened nested fields
      for (const nestedField of field.nestedLayout.fields) {
        const fullName = `${field.name}_${nestedField.name}`;
        const offset = field.offset + nestedField.offset;
        code += generateTsAccessor(fullName, nestedField, offset);
      }
    } else if (field.isArray) {
      // Generate array accessor
      code += generateTsArrayAccessor(field);
    } else {
      code += generateTsAccessor(field.name, field, field.offset);
    }
  }

  // toObject() method for debugging
  code += '  toObject(): Record<string, unknown> {\n';
  code += '    return {\n';
  for (const field of layout.fields) {
    if (field.isNestedStruct) {
      for (const nestedField of field.nestedLayout.fields) {
        const fullName = `${field.name}_${nestedField.name}`;
        code += `      ${fullName}: this.${fullName},\n`;
      }
    } else if (field.isArray) {
      code += `      ${field.name}: Array.from(this.${field.name}),\n`;
    } else {
      code += `      ${field.name}: this.${field.name},\n`;
    }
  }
  code += '    };\n';
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
 * Generate accessor for a fixed-size array field
 */
function generateTsArrayAccessor(field) {
  let code = '';

  // Determine the appropriate TypedArray type
  const typedArrayMap = {
    byte: 'Int8Array', ubyte: 'Uint8Array', int8: 'Int8Array', uint8: 'Uint8Array',
    short: 'Int16Array', ushort: 'Uint16Array', int16: 'Int16Array', uint16: 'Uint16Array',
    int: 'Int32Array', uint: 'Uint32Array', int32: 'Int32Array', uint32: 'Uint32Array',
    float: 'Float32Array', float32: 'Float32Array',
    long: 'BigInt64Array', ulong: 'BigUint64Array', int64: 'BigInt64Array', uint64: 'BigUint64Array',
    double: 'Float64Array', float64: 'Float64Array',
  };

  const typedArrayType = typedArrayMap[field.type] || 'Uint8Array';

  code += `  get ${field.name}(): ${typedArrayType} {\n`;
  code += `    return new ${typedArrayType}(this.view.buffer, this.view.byteOffset + ${field.offset}, ${field.arraySize});\n`;
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
// Main API
// =============================================================================

/**
 * Generate aligned code from a FlatBuffers schema
 * @param {string} schemaContent - The .fbs schema content
 * @param {Object} options - Generation options
 * @returns {{ cpp: string, ts: string, layout: Object }} Generated code and layout info
 */
export function generateAlignedCode(schemaContent, options = {}) {
  const schema = parseSchema(schemaContent);
  const cpp = generateCppHeader(schema, options);
  const ts = generateTypeScript(schema, options);

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

  return { cpp, ts, schema, layouts };
}

export default {
  parseSchema,
  computeLayout,
  generateCppHeader,
  generateTypeScript,
  generateAlignedCode,
};
