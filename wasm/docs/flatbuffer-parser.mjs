/**
 * FlatBuffer Binary Parser
 *
 * Parses FlatBuffer binary format without generated code to extract
 * field locations and values for visualization.
 */

/**
 * Convert bytes to hex string with spaces
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function toHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
}

/**
 * Convert bytes to hex string without spaces
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function toHexCompact(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * FlatBuffer field types and their sizes
 */
export const FieldTypes = {
  bool: { size: 1, read: (view, offset) => view.getUint8(offset) !== 0 },
  byte: { size: 1, read: (view, offset) => view.getInt8(offset) },
  ubyte: { size: 1, read: (view, offset) => view.getUint8(offset) },
  short: { size: 2, read: (view, offset) => view.getInt16(offset, true) },
  ushort: { size: 2, read: (view, offset) => view.getUint16(offset, true) },
  int: { size: 4, read: (view, offset) => view.getInt32(offset, true) },
  uint: { size: 4, read: (view, offset) => view.getUint32(offset, true) },
  long: { size: 8, read: (view, offset) => view.getBigInt64(offset, true) },
  ulong: { size: 8, read: (view, offset) => view.getBigUint64(offset, true) },
  float: { size: 4, read: (view, offset) => view.getFloat32(offset, true) },
  double: { size: 8, read: (view, offset) => view.getFloat64(offset, true) },
  // Offsets (for strings, vectors, tables)
  offset: { size: 4, read: (view, offset) => view.getUint32(offset, true) },
  // Structs - size varies, default to 12 (Vec3)
  struct: { size: 12, read: (view, offset) => view.getUint32(offset, true) },
};

/**
 * Parser for FlatBuffer binary format
 */
export class FlatBufferParser {
  /**
   * @param {Uint8Array} buffer - FlatBuffer binary data
   */
  constructor(buffer) {
    this.buffer = buffer;
    this.view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  }

  /**
   * Parse the FlatBuffer header
   * @returns {{ rootOffset: number, rootOffsetHex: string, fileId: string|null, fileIdHex: string, headerBytes: Uint8Array }}
   */
  parseHeader() {
    // Bounds check - need at least 4 bytes for root offset
    if (this.buffer.length < 4) {
      throw new Error(`Buffer too small for FlatBuffer header (length ${this.buffer.length})`);
    }

    const rootOffset = this.view.getUint32(0, true);

    // File identifier is at bytes 4-7 (after root offset)
    // Only present if the schema defines file_identifier
    let fileId = null;
    let fileIdHex = '--';

    if (this.buffer.length >= 8) {
      const idBytes = this.buffer.slice(4, 8);
      fileIdHex = toHex(idBytes);
      // Check if it looks like a valid identifier (printable ASCII)
      const chars = Array.from(idBytes).map(b => String.fromCharCode(b));
      if (chars.every(c => c.charCodeAt(0) >= 32 && c.charCodeAt(0) < 127)) {
        fileId = chars.join('').replace(/\0/g, '');
      }
    }

    return {
      rootOffset,
      rootOffsetHex: toHex(this.buffer.slice(0, 4)),
      fileId,
      fileIdHex,
      headerBytes: this.buffer.slice(0, 8),
    };
  }

  /**
   * Parse the vtable at a table position
   * @param {number} tablePos - Absolute position of the table
   * @returns {{ vtablePos: number, vtableSize: number, tableSize: number, fieldOffsets: number[], vtableBytes: Uint8Array }}
   */
  parseVTable(tablePos) {
    // Bounds check
    if (tablePos + 4 > this.buffer.length) {
      throw new Error(`Table position ${tablePos} is outside buffer (length ${this.buffer.length})`);
    }

    // Read the signed offset to the vtable (negative, pointing backward)
    const vtableOffset = this.view.getInt32(tablePos, true);
    const vtablePos = tablePos - vtableOffset;

    // Bounds check for vtable
    if (vtablePos < 0 || vtablePos + 4 > this.buffer.length) {
      throw new Error(`VTable position ${vtablePos} is outside buffer (length ${this.buffer.length})`);
    }

    // VTable structure:
    // [0-1]: vtable size (uint16)
    // [2-3]: table size (uint16)
    // [4+]:  field offsets (uint16 each)
    const vtableSize = this.view.getUint16(vtablePos, true);
    const tableSize = this.view.getUint16(vtablePos + 2, true);

    // Bounds check for full vtable
    if (vtablePos + vtableSize > this.buffer.length) {
      throw new Error(`VTable extends beyond buffer (vtable at ${vtablePos}, size ${vtableSize}, buffer length ${this.buffer.length})`);
    }

    // Calculate number of fields from vtable size
    const fieldCount = (vtableSize - 4) / 2;
    const fieldOffsets = [];

    for (let i = 0; i < fieldCount; i++) {
      const offset = this.view.getUint16(vtablePos + 4 + i * 2, true);
      fieldOffsets.push(offset);
    }

    return {
      vtablePos,
      vtableSize,
      tableSize,
      fieldOffsets,
      vtableBytes: this.buffer.slice(vtablePos, vtablePos + vtableSize),
    };
  }

  /**
   * Extract field bytes from the buffer
   * @param {number} tablePos - Table position
   * @param {number} fieldOffset - Field offset from vtable (0 = not present)
   * @param {number} fieldSize - Size of the field in bytes
   * @returns {Uint8Array|null}
   */
  extractFieldBytes(tablePos, fieldOffset, fieldSize) {
    if (fieldOffset === 0) return null;
    const start = tablePos + fieldOffset;
    // Bounds check
    if (start + fieldSize > this.buffer.length) return null;
    return this.buffer.slice(start, start + fieldSize);
  }

  /**
   * Read a string from the buffer
   * @param {number} tablePos - Table position
   * @param {number} fieldOffset - Field offset from vtable
   * @returns {{ value: string, bytes: Uint8Array, offset: number }|null}
   */
  readString(tablePos, fieldOffset) {
    if (fieldOffset === 0) return null;

    // Field contains offset to string
    const stringOffsetPos = tablePos + fieldOffset;
    // Bounds check
    if (stringOffsetPos + 4 > this.buffer.length) return null;

    const stringOffset = this.view.getUint32(stringOffsetPos, true);
    const stringStart = stringOffsetPos + stringOffset;

    // Bounds check for string length
    if (stringStart + 4 > this.buffer.length) return null;

    // String structure: [length:uint32][chars...][null]
    const length = this.view.getUint32(stringStart, true);

    // Bounds check for string data
    if (stringStart + 4 + length > this.buffer.length) return null;

    const stringBytes = this.buffer.slice(stringStart + 4, stringStart + 4 + length);
    const value = new TextDecoder().decode(stringBytes);

    return {
      value,
      bytes: stringBytes,
      lengthBytes: this.buffer.slice(stringStart, stringStart + 4),
      offset: stringStart,
    };
  }

  /**
   * Read a vector from the buffer
   * @param {number} tablePos - Table position
   * @param {number} fieldOffset - Field offset from vtable
   * @param {string} elementType - Type of vector elements
   * @param {number} [elementSize] - Optional element size override (for structs)
   * @returns {{ length: number, elements: any[], bytes: Uint8Array, offset: number }|null}
   */
  readVector(tablePos, fieldOffset, elementType, elementSize) {
    if (fieldOffset === 0) return null;

    const vectorOffsetPos = tablePos + fieldOffset;

    // Bounds check
    if (vectorOffsetPos + 4 > this.buffer.length) return null;

    const vectorOffset = this.view.getUint32(vectorOffsetPos, true);
    const vectorStart = vectorOffsetPos + vectorOffset;

    // Bounds check for vector length
    if (vectorStart + 4 > this.buffer.length) return null;

    // Vector structure: [length:uint32][elements...]
    const length = this.view.getUint32(vectorStart, true);
    // Use provided elementSize for structs, otherwise lookup in FieldTypes
    const baseTypeInfo = FieldTypes[elementType] || FieldTypes.ubyte;
    const typeInfo = elementSize
      ? { size: elementSize, read: baseTypeInfo.read }
      : baseTypeInfo;
    const elementsStart = vectorStart + 4;
    const totalSize = length * typeInfo.size;

    // Sanity check - if length seems unreasonable (> 10000 or extends past buffer), return empty
    if (length > 10000 || elementsStart + totalSize > this.buffer.length) {
      return {
        length: 0,
        elements: [],
        bytes: this.buffer.slice(vectorStart, Math.min(vectorStart + 4, this.buffer.length)),
        elementBytes: new Uint8Array(0),
        offset: vectorStart,
      };
    }

    // Bounds check for elements
    if (elementsStart + totalSize > this.buffer.length) {
      // Return only the valid portion
      const validSize = this.buffer.length - elementsStart;
      return {
        length,
        elements: [],
        bytes: this.buffer.slice(vectorStart, vectorStart + 4 + validSize),
        elementBytes: this.buffer.slice(elementsStart, elementsStart + validSize),
        offset: vectorStart,
      };
    }

    const elements = [];
    for (let i = 0; i < length; i++) {
      const elemOffset = elementsStart + i * typeInfo.size;
      if (elemOffset + typeInfo.size <= this.buffer.length) {
        elements.push(typeInfo.read(this.view, elemOffset));
      }
    }

    return {
      length,
      elements,
      bytes: this.buffer.slice(vectorStart, vectorStart + 4 + totalSize),
      elementBytes: this.buffer.slice(elementsStart, elementsStart + totalSize),
      offset: vectorStart,
    };
  }

  /**
   * Read a struct from the buffer (inline, not offset)
   * @param {number} tablePos - Table position
   * @param {number} fieldOffset - Field offset from vtable
   * @param {number} structSize - Size of the struct
   * @returns {{ bytes: Uint8Array, offset: number }|null}
   */
  readStruct(tablePos, fieldOffset, structSize) {
    if (fieldOffset === 0) return null;

    const structStart = tablePos + fieldOffset;
    // Bounds check
    if (structStart + structSize > this.buffer.length) return null;

    return {
      bytes: this.buffer.slice(structStart, structStart + structSize),
      offset: structStart,
    };
  }

  /**
   * Read a nested table from the buffer given an absolute position
   * @param {number} tablePos - Absolute position of the nested table
   * @param {Array} tableSchema - Schema fields for the nested table
   * @returns {Object|null} Parsed table with field values
   */
  readNestedTable(tablePos, tableSchema) {
    // Bounds check
    if (tablePos + 4 > this.buffer.length) return null;

    try {
      const vtable = this.parseVTable(tablePos);
      const result = {};

      for (let i = 0; i < tableSchema.length; i++) {
        const fieldDef = tableSchema[i];
        const fieldOffset = vtable.fieldOffsets[i] || 0;

        if (fieldOffset === 0) {
          result[fieldDef.name] = fieldDef.defaultValue ?? null;
          continue;
        }

        if (fieldDef.type === 'string') {
          const stringData = this.readString(tablePos, fieldOffset);
          result[fieldDef.name] = stringData ? stringData.value : null;
        } else {
          const typeInfo = FieldTypes[fieldDef.type];
          if (typeInfo) {
            const bytes = this.extractFieldBytes(tablePos, fieldOffset, typeInfo.size);
            if (bytes) {
              result[fieldDef.name] = this.interpretValue(bytes, fieldDef.type);
            }
          }
        }
      }

      return result;
    } catch {
      return null;
    }
  }

  /**
   * Interpret field value based on type
   * @param {Uint8Array} bytes - Field bytes
   * @param {string} type - Field type
   * @returns {any}
   */
  interpretValue(bytes, type) {
    if (!bytes || bytes.length === 0) return null;

    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const typeInfo = FieldTypes[type];

    if (typeInfo) {
      try {
        return typeInfo.read(view, 0);
      } catch {
        return `[${bytes.length} bytes]`;
      }
    }

    // Special handling for strings
    if (type === 'string') {
      try {
        return new TextDecoder().decode(bytes);
      } catch {
        return `[${bytes.length} bytes]`;
      }
    }

    return `[${bytes.length} bytes]`;
  }
}

/**
 * Schema field definition for parsing
 * @typedef {Object} SchemaField
 * @property {string} name - Field name
 * @property {string} type - Field type (short, int, string, etc.)
 * @property {number} [size] - Field size in bytes (for scalars)
 * @property {boolean} [isVector] - Whether this is a vector field
 * @property {boolean} [isStruct] - Whether this is an inline struct
 * @property {number} [structSize] - Size of struct if isStruct
 * @property {any} [defaultValue] - Default value if not present
 */

/**
 * Parse all fields from a FlatBuffer using a schema definition
 * @param {FlatBufferParser} parser - Parser instance
 * @param {SchemaField[]} schema - Array of field definitions
 * @returns {{ header: object, vtable: object, fields: object[] }}
 */
export function parseWithSchema(parser, schema) {
  const header = parser.parseHeader();
  const tablePos = header.rootOffset;
  const vtable = parser.parseVTable(tablePos);

  const fields = [];

  for (let i = 0; i < schema.length; i++) {
    const fieldDef = schema[i];
    const fieldOffset = vtable.fieldOffsets[i] || 0;

    let bytes = null;
    let value = null;
    let absoluteOffset = fieldOffset ? tablePos + fieldOffset : null;

    if (fieldOffset !== 0) {
      if (fieldDef.type === 'string') {
        const stringData = parser.readString(tablePos, fieldOffset);
        if (stringData) {
          bytes = stringData.bytes;
          value = stringData.value;
          absoluteOffset = stringData.offset;
        }
      } else if (fieldDef.isVector) {
        const vectorData = parser.readVector(tablePos, fieldOffset, fieldDef.elementType || 'ubyte', fieldDef.elementSize);
        if (vectorData) {
          bytes = vectorData.elementBytes;
          value = vectorData.elements;
          absoluteOffset = vectorData.offset;
          // For struct vectors, parse each struct
          if (fieldDef.elementType === 'struct' && fieldDef.structFields && vectorData.length > 0) {
            const parsedStructs = [];
            const elemSize = fieldDef.elementSize || 12;
            for (let j = 0; j < vectorData.length; j++) {
              const structBytes = bytes.slice(j * elemSize, (j + 1) * elemSize);
              if (structBytes.length === elemSize) {
                parsedStructs.push(parseStructBytes(structBytes, fieldDef.structFields));
              }
            }
            value = parsedStructs;
          }
          // For table vectors (offset elements), dereference and parse each nested table
          else if (fieldDef.elementType === 'offset' && fieldDef.tableSchema && vectorData.length > 0) {
            const parsedTables = [];
            const elementsStart = vectorData.offset + 4; // Skip length field
            for (let j = 0; j < vectorData.length; j++) {
              const offsetPos = elementsStart + j * 4;
              const relativeOffset = vectorData.elements[j];
              if (relativeOffset) {
                const tableAbsPos = offsetPos + relativeOffset;
                const parsed = parser.readNestedTable(tableAbsPos, fieldDef.tableSchema);
                if (parsed) {
                  parsedTables.push(parsed);
                }
              }
            }
            value = parsedTables;
          }
        }
      } else if (fieldDef.isStruct) {
        const structData = parser.readStruct(tablePos, fieldOffset, fieldDef.structSize);
        if (structData) {
          bytes = structData.bytes;
          absoluteOffset = structData.offset;
          // Parse struct fields
          value = parseStructBytes(bytes, fieldDef.structFields || []);
        }
      } else {
        const typeInfo = FieldTypes[fieldDef.type];
        if (typeInfo) {
          bytes = parser.extractFieldBytes(tablePos, fieldOffset, typeInfo.size);
          if (bytes) {
            value = parser.interpretValue(bytes, fieldDef.type);
          }
        }
      }
    }

    fields.push({
      name: fieldDef.name,
      type: fieldDef.type,
      vtableOffset: fieldOffset,
      absoluteOffset,
      bytes,
      value,
      present: fieldOffset !== 0,
      defaultValue: fieldDef.defaultValue,
    });
  }

  return { header, vtable, fields };
}

/**
 * Parse struct bytes into field values
 * @param {Uint8Array} bytes - Struct bytes
 * @param {Array<{name: string, type: string, offset: number}>} fields - Struct field definitions
 * @returns {Object}
 */
function parseStructBytes(bytes, fields) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const result = {};

  for (const field of fields) {
    const typeInfo = FieldTypes[field.type];
    if (typeInfo && field.offset + typeInfo.size <= bytes.length) {
      result[field.name] = typeInfo.read(view, field.offset);
    }
  }

  return result;
}

/**
 * Schema definitions for the demo schemas
 */
export const Schemas = {
  monster: {
    name: 'Monster',
    fileId: 'MONS',
    fields: [
      { name: 'pos', type: 'Vec3', isStruct: true, structSize: 12, structFields: [
        { name: 'x', type: 'float', offset: 0 },
        { name: 'y', type: 'float', offset: 4 },
        { name: 'z', type: 'float', offset: 8 },
      ]},
      { name: 'mana', type: 'short', defaultValue: 150 },
      { name: 'hp', type: 'short', defaultValue: 100 },
      { name: 'name', type: 'string' },
      { name: 'friendly', type: 'bool', defaultValue: false },
      { name: 'inventory', type: 'vector', isVector: true, elementType: 'ubyte' },
      { name: 'color', type: 'byte', defaultValue: 2 }, // Blue = 2
      { name: 'weapons', type: 'vector', isVector: true, elementType: 'offset', tableSchema: [
        { name: 'name', type: 'string' },
        { name: 'damage', type: 'short' },
      ]},
      { name: 'equipped', type: 'union' },
      { name: 'path', type: 'vector', isVector: true, elementType: 'struct', elementSize: 12, structFields: [
        { name: 'x', type: 'float', offset: 0 },
        { name: 'y', type: 'float', offset: 4 },
        { name: 'z', type: 'float', offset: 8 },
      ]},
    ],
  },

  weapon: {
    name: 'Weapon',
    fileId: 'WEAP',
    fields: [
      { name: 'name', type: 'string' },
      { name: 'damage', type: 'short' },
    ],
  },

  galaxy: {
    name: 'Galaxy',
    fileId: 'GALX',
    fields: [
      { name: 'num_stars', type: 'long' },
    ],
  },

  universe: {
    name: 'Universe',
    fileId: 'UNIV',
    fields: [
      { name: 'age', type: 'double' },
      { name: 'galaxies', type: 'vector', isVector: true, elementType: 'offset' },
    ],
  },
};

export default FlatBufferParser;
