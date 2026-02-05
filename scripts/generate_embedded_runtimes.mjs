#!/usr/bin/env node
/**
 * generate_embedded_runtimes.mjs
 *
 * Build-time script that reads FlatBuffers language runtime source files,
 * creates a JSON map { "relative/path": "content" } per language,
 * brotli-compresses each, and emits a C header with static byte arrays
 * for embedding into the WASM binary.
 *
 * Usage:
 *   node scripts/generate_embedded_runtimes.mjs <flatbuffers-repo-path> <output-header-path>
 *
 * Example:
 *   node scripts/generate_embedded_runtimes.mjs ./flatbuffers-repo src/embedded_runtimes_data.h
 */

import fs from 'fs';
import path from 'path';
import { brotliCompressSync, constants as zlibConstants } from 'node:zlib';

const REPO_DIR = process.argv[2] || path.resolve(process.cwd(), 'flatbuffers-repo');
const OUTPUT_HEADER = process.argv[3] || path.resolve(process.cwd(), 'src', 'embedded_runtimes_data.h');

// Language runtime directory mappings
// Each entry: { lang, srcDir, include, exclude }
// srcDir is relative to REPO_DIR
// include: glob-like patterns (simplified: extensions or exact dirs)
// exclude: patterns to skip (test dirs, docs, etc.)
const LANGUAGE_RUNTIMES = [
  {
    lang: 'python',
    srcDir: 'python/flatbuffers',
    prefix: 'flatbuffers',
    extensions: ['.py'],
    exclude: ['__pycache__', '.pyc'],
  },
  {
    lang: 'ts',
    srcDir: 'ts',
    prefix: '',
    extensions: ['.ts'],
    exclude: ['node_modules', 'package.json', 'tsconfig.json', '.d.ts', 'test', 'tests'],
  },
  {
    lang: 'go',
    srcDir: 'go',
    prefix: '',
    extensions: ['.go'],
    exclude: ['test', 'tests', '_test.go'],
  },
  {
    lang: 'java',
    srcDir: 'java/src/main/java/com/google/flatbuffers',
    prefix: 'com/google/flatbuffers',
    extensions: ['.java'],
    exclude: ['test', 'tests'],
  },
  {
    lang: 'kotlin',
    srcDir: 'kotlin/flatbuffers-kotlin/src',
    prefix: '',
    extensions: ['.kt'],
    exclude: ['commonTest', 'jvmTest', 'jsTest', 'nativeTest', 'test', 'tests'],
  },
  {
    lang: 'swift',
    srcDir: 'swift/Sources',
    prefix: '',
    extensions: ['.swift'],
    exclude: ['Documentation.docc', 'test', 'tests'],
  },
  {
    lang: 'dart',
    srcDir: 'dart/lib',
    prefix: '',
    extensions: ['.dart'],
    exclude: ['test', 'tests'],
  },
  {
    lang: 'php',
    srcDir: 'php',
    prefix: '',
    extensions: ['.php'],
    exclude: ['test', 'tests', 'vendor'],
  },
  {
    lang: 'csharp',
    srcDir: 'net/FlatBuffers',
    prefix: 'FlatBuffers',
    extensions: ['.cs'],
    exclude: ['test', 'tests', 'obj', 'bin'],
  },
  {
    lang: 'cpp',
    srcDir: 'include/flatbuffers',
    prefix: 'flatbuffers',
    extensions: ['.h'],
    exclude: [
      'idl.h', 'flatc.h', 'code_generator.h', 'hash.h', 'flatc_main.h',
      'file_manager.h',
    ],
    excludePatterns: [/^idl_gen/, /^bfbs_gen/],
  },
  {
    lang: 'rust',
    srcDir: 'rust/flatbuffers/src',
    prefix: '',
    extensions: ['.rs'],
    exclude: ['test', 'tests'],
  },
];

/**
 * Recursively collect files from a directory.
 */
function collectFiles(dir, basePath, config) {
  const results = {};
  if (!fs.existsSync(dir)) {
    console.warn(`  Warning: directory not found: ${dir}`);
    return results;
  }

  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    const relPath = basePath ? `${basePath}/${entry.name}` : entry.name;

    // Check exclusions
    if (config.exclude && config.exclude.includes(entry.name)) continue;
    if (config.excludePatterns && config.excludePatterns.some(p => p.test(entry.name))) continue;

    if (entry.isDirectory()) {
      // Check if entire directory is excluded
      if (config.exclude && config.exclude.some(e => entry.name.toLowerCase().includes(e.toLowerCase()))) continue;
      Object.assign(results, collectFiles(fullPath, relPath, config));
    } else if (entry.isFile()) {
      // Check extension
      if (config.extensions && !config.extensions.some(ext => entry.name.endsWith(ext))) continue;
      // Check file-level exclusion suffixes (like _test.go)
      if (config.exclude && config.exclude.some(e => entry.name.endsWith(e))) continue;

      const content = fs.readFileSync(fullPath, 'utf8');
      // Use the prefix for the final path key
      const outputKey = config.prefix ? `${config.prefix}/${relPath}` : relPath;
      results[outputKey] = content;
    }
  }
  return results;
}

/**
 * Convert a byte array to a C array initializer string.
 */
function bytesToCArray(bytes, indent = '  ') {
  const lines = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const slice = bytes.subarray(i, Math.min(i + 16, bytes.length));
    const hex = Array.from(slice).map(b => `0x${b.toString(16).padStart(2, '0')}`).join(', ');
    lines.push(`${indent}${hex}`);
  }
  return lines.join(',\n');
}

// Main
console.log('=== Generating Embedded Runtime Data ===');
console.log(`  Repo: ${REPO_DIR}`);
console.log(`  Output: ${OUTPUT_HEADER}`);

const runtimeData = [];
let totalRaw = 0;
let totalCompressed = 0;

for (const config of LANGUAGE_RUNTIMES) {
  const srcDir = path.join(REPO_DIR, config.srcDir);
  console.log(`\n  Processing: ${config.lang} (${config.srcDir})`);

  const files = collectFiles(srcDir, '', config);
  const fileCount = Object.keys(files).length;

  if (fileCount === 0) {
    console.warn(`    Warning: No files found for ${config.lang}`);
    continue;
  }

  // Create JSON map
  const jsonStr = JSON.stringify(files);
  const jsonBytes = Buffer.from(jsonStr, 'utf8');

  // Brotli compress at quality 11 (max compression)
  const compressed = brotliCompressSync(jsonBytes, {
    params: {
      [zlibConstants.BROTLI_PARAM_QUALITY]: 11,
    },
  });

  totalRaw += jsonBytes.length;
  totalCompressed += compressed.length;

  console.log(`    Files: ${fileCount}`);
  console.log(`    Raw JSON: ${(jsonBytes.length / 1024).toFixed(1)} KB`);
  console.log(`    Compressed: ${(compressed.length / 1024).toFixed(1)} KB (${((1 - compressed.length / jsonBytes.length) * 100).toFixed(0)}% reduction)`);

  runtimeData.push({
    lang: config.lang,
    fileCount,
    rawSize: jsonBytes.length,
    compressedSize: compressed.length,
    compressed,
  });
}

// Generate C header
let header = `// AUTO-GENERATED by generate_embedded_runtimes.mjs — DO NOT EDIT
// Contains brotli-compressed FlatBuffers language runtime libraries.
// Total: ${runtimeData.length} languages, ${(totalRaw / 1024).toFixed(0)} KB raw → ${(totalCompressed / 1024).toFixed(0)} KB compressed

#ifndef EMBEDDED_RUNTIMES_DATA_H
#define EMBEDDED_RUNTIMES_DATA_H

#include <cstddef>
#include <cstdint>

`;

// Emit compressed data arrays
for (const rt of runtimeData) {
  header += `// ${rt.lang}: ${rt.fileCount} files, ${rt.rawSize} bytes raw → ${rt.compressedSize} bytes compressed\n`;
  header += `static const uint8_t kRuntime_${rt.lang}[] = {\n`;
  header += bytesToCArray(rt.compressed);
  header += `\n};\n\n`;
}

// Emit lookup table struct and array
header += `struct EmbeddedRuntime {
  const char* name;
  const uint8_t* data;
  size_t compressed_size;
  size_t raw_size;
  int file_count;
};

static const EmbeddedRuntime kEmbeddedRuntimes[] = {
`;

for (const rt of runtimeData) {
  header += `  { "${rt.lang}", kRuntime_${rt.lang}, ${rt.compressedSize}, ${rt.rawSize}, ${rt.fileCount} },\n`;
}

header += `};

static const int kEmbeddedRuntimeCount = ${runtimeData.length};

#endif // EMBEDDED_RUNTIMES_DATA_H
`;

// Write output
const outputDir = path.dirname(OUTPUT_HEADER);
if (!fs.existsSync(outputDir)) {
  fs.mkdirSync(outputDir, { recursive: true });
}
fs.writeFileSync(OUTPUT_HEADER, header);

console.log(`\n=== Summary ===`);
console.log(`  Languages: ${runtimeData.length}`);
console.log(`  Total raw: ${(totalRaw / 1024).toFixed(0)} KB`);
console.log(`  Total compressed: ${(totalCompressed / 1024).toFixed(0)} KB`);
console.log(`  Compression ratio: ${((1 - totalCompressed / totalRaw) * 100).toFixed(0)}%`);
console.log(`  Header written to: ${OUTPUT_HEADER}`);
