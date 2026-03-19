#!/usr/bin/env node

import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { FlatcRunner } from '../../wasm/src/runner.mjs';

const ROOT = process.cwd();
const FLATC = join(ROOT, 'build', 'flatc');

const SCHEMA = `
namespace Example;

table Child {
  value:uint;
}

union Payload { Child }

table Root {
  id:uint;
  name:string (aligned_max_length: 12);
  values:[ushort] (aligned_max_count: 4);
  children:[Child] (aligned_max_count: 2);
  names:[string] (aligned_max_count: 3);
  payload:Payload;
  payloads:[Payload] (aligned_max_count: 2);
}

root_type Root;
`;

const LANGUAGES = [
  'cpp',
  'ts',
  'go',
  'python',
  'rust',
  'java',
  'csharp',
  'kotlin',
  'dart',
  'swift',
  'php',
];

function normalizeCode(source) {
  return source.replace(/\r\n/g, '\n').trim();
}

function readOutputFiles(dir) {
  const files = {};
  for (const name of readdirSync(dir)) {
    files[name] = readFileSync(join(dir, name), 'utf8');
  }
  return files;
}

async function main() {
  const runner = await FlatcRunner.init();
  const tempRoot = mkdtempSync(join(tmpdir(), 'aligned-wasm-parity-'));

  try {
    const schemaPath = join(tempRoot, 'aligned_mode.fbs');
    writeFileSync(schemaPath, SCHEMA);

    const schemaInput = {
      entry: '/aligned_mode.fbs',
      files: { '/aligned_mode.fbs': SCHEMA },
    };

    for (const lang of LANGUAGES) {
      const nativeOutDir = join(tempRoot, `native-${lang}`);
      const native = spawnSync(
        FLATC,
        [`--${lang}`, '--aligned', '-o', nativeOutDir, schemaPath],
        { encoding: 'utf8' }
      );

      if (native.status !== 0 || native.stderr.includes('error:')) {
        throw new Error(
          `native aligned ${lang} generation failed:\n${native.stderr || native.stdout}`
        );
      }

      const nativeFiles = readOutputFiles(nativeOutDir);
      const wasmFiles = runner.generateCode(schemaInput, lang, { aligned: true });

      assert.deepStrictEqual(
        Object.keys(wasmFiles).sort(),
        Object.keys(nativeFiles).sort(),
        `${lang}: native and wasm produced the same file set`
      );

      for (const [name, nativeSource] of Object.entries(nativeFiles)) {
        assert.equal(
          normalizeCode(wasmFiles[name]),
          normalizeCode(nativeSource),
          `${lang}: ${name} matches native output`
        );
      }
    }

    console.log('aligned native/wasm codegen parity passed');
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
}

await main();
