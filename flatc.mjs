import { argv } from 'process';
import flatcModule from './wasm_build/flatc.mjs';
import fs from 'fs';

const Module = await flatcModule({
    noExitRuntime: true,
    noInitialRun: true,
});

console.log(Module.arguments)

const schema = fs.readFileSync('./tests/monster_extra.fbs');
Module.FS_createDataFile('/', 'schema.fbs', schema, true, true);
Module.callMain(['--cpp', '/schema.fbs']);

const entries = Module.FS.readdir('/');
const files = entries.filter(name => {
  const path = `/${name}`;
  const stat = Module.FS.stat(path);
  return Module.FS.isFile(stat.mode);
});

for (const name of files) {
  console.log(`\n--- ${name} ---`);
  try {
    console.log(Module.FS.readFile(`/${name}`, { encoding: 'utf8' }).slice(0,10));
  } catch (e) {
    console.error(`Error reading file ${name}:`, e);
  }
}
