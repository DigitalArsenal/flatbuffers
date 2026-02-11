/**
 * Format detection for FlatBuffer binary vs JSON input.
 */

/** Detected data format */
export type DataFormat = 'json' | 'flatbuffer' | 'unknown';

/** Detected string format */
export type StringFormat = 'json' | 'unknown';

/**
 * Detect the format of binary data.
 *
 * Heuristics:
 * - JSON: First non-whitespace byte is '{' or '['
 * - FlatBuffer: First 4 bytes form a valid u32 root offset within bounds
 * - Unknown: Neither pattern matches
 *
 * @param data - Input data to detect
 * @returns Detected format
 */
export function detectFormat(data: Uint8Array): DataFormat;

/**
 * Detect whether a string is JSON.
 *
 * @param input - String to check
 * @returns Detected format ('json' or 'unknown')
 */
export function detectStringFormat(input: string): StringFormat;
