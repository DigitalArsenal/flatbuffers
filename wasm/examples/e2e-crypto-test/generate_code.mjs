#!/usr/bin/env node
/**
 * Code Generator for E2E Cross-Language Encryption Tests
 *
 * Uses WASM flatc to generate FlatBuffer code in all 7 languages:
 * - TypeScript (Node.js)
 * - Go
 * - Python
 * - Rust
 * - Java
 * - C#
 * - Swift
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, rmSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const schemasDir = join(__dirname, 'schemas');
const generatedDir = join(__dirname, 'generated');

// Language configurations
const LANGUAGES = [
  {
    name: 'typescript',
    flatcLang: 'ts',
    dir: 'ts',
    options: { tsNoImportExt: false },
    description: 'TypeScript for Node.js'
  },
  {
    name: 'go',
    flatcLang: 'go',
    dir: 'go',
    options: {},
    description: 'Go'
  },
  {
    name: 'python',
    flatcLang: 'python',
    dir: 'python',
    options: { pythonTyping: true },
    description: 'Python'
  },
  {
    name: 'rust',
    flatcLang: 'rust',
    dir: 'rust',
    options: {},
    description: 'Rust'
  },
  {
    name: 'java',
    flatcLang: 'java',
    dir: 'java',
    options: {},
    description: 'Java'
  },
  {
    name: 'csharp',
    flatcLang: 'csharp',
    dir: 'csharp',
    options: {},
    description: 'C#'
  },
  {
    name: 'swift',
    flatcLang: 'swift',
    dir: 'swift',
    options: {},
    description: 'Swift'
  }
];

async function main() {
  console.log('='.repeat(60));
  console.log('FlatBuffers E2E Code Generator');
  console.log('='.repeat(60));
  console.log();

  // Load flatc-wasm
  let flatc;
  try {
    const flatcWasm = await import('flatc-wasm');
    flatc = await flatcWasm.FlatcRunner.init();
    console.log(`FlatC version: ${flatc.version()}`);
    console.log();
  } catch (e) {
    console.error('Failed to load flatc-wasm. Make sure it is built and linked.');
    console.error('Run: cd ../../../.. && npm link');
    console.error(e.message);
    process.exit(1);
  }

  // Load schema
  const schemaPath = join(schemasDir, 'message.fbs');
  if (!existsSync(schemaPath)) {
    console.error(`Schema not found: ${schemaPath}`);
    process.exit(1);
  }

  const schemaContent = readFileSync(schemaPath, 'utf8');
  console.log('Schema: schemas/message.fbs');
  console.log();

  const schemaInput = {
    entry: '/message.fbs',
    files: {
      '/message.fbs': schemaContent
    }
  };

  // Create output directory
  if (existsSync(generatedDir)) {
    rmSync(generatedDir, { recursive: true });
  }
  mkdirSync(generatedDir, { recursive: true });

  // Generate code for each language
  const results = [];
  for (const lang of LANGUAGES) {
    console.log(`Generating ${lang.description}...`);
    const outDir = join(generatedDir, lang.dir);
    mkdirSync(outDir, { recursive: true });

    try {
      const files = flatc.generateCode(schemaInput, lang.flatcLang, lang.options);
      const fileCount = Object.keys(files).length;

      // Write files to disk
      for (const [filename, content] of Object.entries(files)) {
        const filePath = join(outDir, filename);
        const fileDir = dirname(filePath);
        if (!existsSync(fileDir)) {
          mkdirSync(fileDir, { recursive: true });
        }
        writeFileSync(filePath, content);
      }

      console.log(`  ✓ Generated ${fileCount} file(s) in generated/${lang.dir}/`);
      results.push({ lang: lang.name, success: true, files: Object.keys(files) });
    } catch (e) {
      console.log(`  ✗ Failed: ${e.message}`);
      results.push({ lang: lang.name, success: false, error: e.message });
    }
  }

  // Generate JSON Schema for reference
  console.log('\nGenerating JSON Schema...');
  try {
    const jsonSchema = flatc.generateJsonSchema(schemaInput);
    const jsonSchemaPath = join(generatedDir, 'message.schema.json');
    writeFileSync(jsonSchemaPath, jsonSchema);
    console.log('  ✓ Generated message.schema.json');
  } catch (e) {
    console.log(`  ✗ Failed: ${e.message}`);
  }

  // Summary
  console.log('\n' + '='.repeat(60));
  console.log('Summary');
  console.log('='.repeat(60));

  const succeeded = results.filter(r => r.success).length;
  const failed = results.filter(r => !r.success).length;

  console.log(`\nGenerated: ${succeeded}/${results.length} languages`);

  if (failed > 0) {
    console.log('\nFailed languages:');
    for (const r of results.filter(r => !r.success)) {
      console.log(`  - ${r.lang}: ${r.error}`);
    }
  }

  console.log('\nGenerated files:');
  for (const r of results.filter(r => r.success)) {
    console.log(`  ${r.lang}:`);
    for (const f of r.files) {
      console.log(`    - ${f}`);
    }
  }

  // Write manifest
  const manifest = {
    schema: 'schemas/message.fbs',
    generated: new Date().toISOString(),
    languages: results
  };
  writeFileSync(join(generatedDir, 'manifest.json'), JSON.stringify(manifest, null, 2));
  console.log('\nManifest: generated/manifest.json');

  process.exit(failed > 0 ? 1 : 0);
}

main().catch(e => {
  console.error('Fatal error:', e);
  process.exit(1);
});
