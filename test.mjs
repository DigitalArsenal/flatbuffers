import './build/flatc.js'; // This defines a global `Module`

Module.onRuntimeInitialized = () => {
  // 1. Write the schema to the in-memory FS
  const schema = `
    table Monster {
      hp:int;
    }
    root_type Monster;
  `;

  Module.FS.writeFile('schema.fbs', schema);

  // 2. Prepare CLI args
  const args = ['flatc', '--json', '-o', 'out', 'schema.fbs'];

  const argvPtrs = args.map(arg => {
    const len = Module.lengthBytesUTF8(arg) + 1;
    const ptr = Module._malloc(len);
    Module.stringToUTF8(arg, ptr, len);
    return ptr;
  });

  const argvPtrArray = Module._malloc(argvPtrs.length * 4);
  argvPtrs.forEach((ptr, i) => {
    Module.setValue(argvPtrArray + i * 4, ptr, 'i32');
  });

  // 3. Call main
  const exitCode = Module._main(args.length, argvPtrArray);
  console.log(`flatc exited with code: ${exitCode}`);

  // 4. Read output file (if generated)
  try {
    const output = Module.FS.readFile('out/schema.json', { encoding: 'utf8' });
    console.log('Generated output:', output);
  } catch (e) {
    console.error('Output not found:', e);
  }

  // 5. Cleanup
  argvPtrs.forEach(ptr => Module._free(ptr));
  Module._free(argvPtrArray);
};