/**
 * Format detection for FlatBuffer binary vs JSON input.
 *
 * Provides heuristic detection to auto-detect whether input data is:
 * - JSON (starts with '{' or '[' after whitespace)
 * - FlatBuffer binary (starts with valid u32 root offset)
 * - Unknown (neither pattern matches)
 *
 * Conservative: returns 'unknown' rather than guessing.
 */

// Minimum valid FlatBuffer size (4 bytes for root offset)
const MIN_FLATBUFFER_SIZE = 4;

// Maximum reasonable root offset for a FlatBuffer
// The root offset points to the root table, which must be within the buffer
const MAX_REASONABLE_SIZE = 100 * 1024 * 1024; // 100 MB

// JSON start characters (after whitespace)
const JSON_OBJECT_START = 0x7b; // '{'
const JSON_ARRAY_START = 0x5b;  // '['

// Whitespace characters
const SPACE = 0x20;
const TAB = 0x09;
const NEWLINE = 0x0a;
const CARRIAGE_RETURN = 0x0d;
const BOM_FIRST = 0xef; // UTF-8 BOM first byte

/**
 * Check if a byte is ASCII whitespace.
 * @param {number} byte
 * @returns {boolean}
 */
function isWhitespace(byte) {
  return byte === SPACE || byte === TAB || byte === NEWLINE || byte === CARRIAGE_RETURN;
}

/**
 * Find the first non-whitespace byte index, skipping optional UTF-8 BOM.
 * @param {Uint8Array} data
 * @returns {number} Index of first non-whitespace byte, or -1 if all whitespace
 */
function firstNonWhitespace(data) {
  let start = 0;

  // Skip UTF-8 BOM if present (0xEF 0xBB 0xBF)
  if (data.length >= 3 && data[0] === 0xef && data[1] === 0xbb && data[2] === 0xbf) {
    start = 3;
  }

  for (let i = start; i < data.length; i++) {
    if (!isWhitespace(data[i])) {
      return i;
    }
  }
  return -1;
}

/**
 * Detect the format of binary data.
 *
 * Heuristics:
 * - JSON: First non-whitespace byte is '{' or '['
 * - FlatBuffer: First 4 bytes form a little-endian u32 root offset that points
 *   within the buffer bounds (offset + 4 <= data.length)
 * - Unknown: Neither pattern matches
 *
 * @param {Uint8Array} data - Input data to detect
 * @returns {'json' | 'flatbuffer' | 'unknown'} Detected format
 */
export function detectFormat(data) {
  if (!data || data.length === 0) {
    return 'unknown';
  }

  // Check for JSON first (more distinctive signal)
  const idx = firstNonWhitespace(data);
  if (idx >= 0) {
    const firstByte = data[idx];
    if (firstByte === JSON_OBJECT_START || firstByte === JSON_ARRAY_START) {
      return 'json';
    }
  }

  // Check for FlatBuffer binary
  if (data.length >= MIN_FLATBUFFER_SIZE) {
    // Read little-endian u32 root offset
    const rootOffset = data[0] | (data[1] << 8) | (data[2] << 16) | ((data[3] << 24) >>> 0);

    // Root offset must point within the buffer
    // The root table starts at offset `rootOffset` from the beginning
    if (rootOffset >= MIN_FLATBUFFER_SIZE &&
        rootOffset < data.length &&
        rootOffset < MAX_REASONABLE_SIZE) {
      return 'flatbuffer';
    }
  }

  return 'unknown';
}

/**
 * Detect whether a string is JSON.
 *
 * @param {string} input - String to check
 * @returns {'json' | 'unknown'} Detected format
 */
export function detectStringFormat(input) {
  if (!input || typeof input !== 'string') {
    return 'unknown';
  }

  const trimmed = input.trimStart();
  if (trimmed.length === 0) {
    return 'unknown';
  }

  const firstChar = trimmed[0];
  if (firstChar === '{' || firstChar === '[') {
    return 'json';
  }

  return 'unknown';
}
