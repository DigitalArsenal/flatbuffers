import flatcModule from './flatc.mjs';

/**
 * FlatBuffers WASM flatc compiler wrapper, fully isomorphic for browser or Node.
 */
export class FlatcRunner {
  /**
   * Initialize the FlatcRunner with the WASM module.
   * @param {object} [moduleOptions] - Options for flatcModule
   * @returns {Promise<FlatcRunner>}
   */
  static async init(moduleOptions = {}) {
    let stdout = '';
    let stderr = '';
    const Module = await flatcModule({
      noExitRuntime: true,
      noInitialRun: true,
      print: (text) => { stdout += text + '\n'; },
      printErr: (text) => { stderr += text + '\n'; },
      ...moduleOptions,
    });
    return new FlatcRunner(Module, stdout, stderr);
  }

  /**
   * @param {any} Module - Emscripten module instance
   * @param {string} initialStdout
   * @param {string} initialStderr
   */
  constructor(Module, initialStdout = '', initialStderr = '') {
    this.Module = Module;
    this._stdout = initialStdout;
    this._stderr = initialStderr;
  }

  /**
   * Mount a single file into the virtual FS.
   * @param {string} filepath - POSIX path (e.g. '/schema.fbs')
   * @param {Uint8Array|string} data - File contents
   */
  mountFile(filepath, data) {
    const dir = filepath.substring(0, filepath.lastIndexOf('/')) || '/';
    const parts = dir.split('/').filter(p => p);
    let cur = '';
    for (const part of parts) {
      cur += '/' + part;
      try { this.Module.FS.mkdir(cur); } catch {}
    }
    const name = filepath.substring(filepath.lastIndexOf('/') + 1);
    const content = typeof data === 'string'
      ? this.Module.intArrayFromString(data, true)
      : data;
    try { this.Module.FS.unlink(filepath); } catch {}
    this.Module.FS_createDataFile(dir, name, content, true, true);
  }

  /**
   * Mount multiple files.
   * @param {{path:string,data:Uint8Array|string}[]} files
   */
  mountFiles(files) {
    for (const f of files) {
      this.mountFile(f.path, f.data);
    }
  }

  /**
   * Execute flatc with arguments.
   * @param {string[]} args
   * @returns {{code:number, stdout:string, stderr:string}}
   */
  runCommand(args) {
    this._stdout = '';
    this._stderr = '';
    let code = 0;
    try {
      this.Module.callMain(args);
    } catch (e) {
      if (typeof e === 'number') code = e;
      else throw e;
    }
    return { code, stdout: this._stdout.trim(), stderr: this._stderr.trim() };
  }

  /**
   * Generate FlatBuffers binary from schema and JSON.
   * @param {{path:string,data:string}} schemaInput
   * @param {{path:string,data:string}} jsonInput
   * @param {string[]} [includeDirs=[]]
   * @returns {Uint8Array}
   */
  generateBinary(schemaInput, jsonInput, includeDirs = []) {
    this.mountFiles([schemaInput, jsonInput]);
    const includeFlags = includeDirs.flatMap(d => ['-I', d]);
    const args = ['--binary', '--unknown-json', ...includeFlags, schemaInput.path, jsonInput.path];
    const result = this.runCommand(args);
    if (result.code !== 0) throw new Error(`flatc exited ${result.code}: ${result.stderr}`);
    const files = this.Module.FS.readdir('/').filter(f => f.endsWith('.mon'));
    if (files.length !== 1) throw new Error(`Expected one .mon, found: ${files}`);
    return this.Module.FS.readFile(`/${files[0]}`);
  }

  /**
   * Generate JSON text from FlatBuffers binary.
   * @param {{path:string,data:string}} schemaInput
   * @param {{path:string,data:Uint8Array}} binaryInput
   * @param {string[]} [includeDirs=[]]
   * @param {{rawBinary?:boolean,strictJson?:boolean,defaultsJson?:boolean}} [opts={rawBinary:true}]
   * @returns {string}
   */
  generateJSON(schemaInput, binaryInput, includeDirs = [], opts = {}) {
    this.mountFiles([schemaInput, { path: binaryInput.path, data: binaryInput.data }]);
    const flags = ['--json'];
    if (opts.rawBinary !== false) flags.push('--raw-binary');
    if (opts.strictJson) flags.push('--strict-json');
    if (opts.defaultsJson) flags.push('--defaults-json');
    const includeFlags = includeDirs.flatMap(d => ['-I', d]);
    const args = [...flags, ...includeFlags, schemaInput.path, binaryInput.path];
    const result = this.runCommand(args);
    if (result.code !== 0) throw new Error(`flatc exited ${result.code}: ${result.stderr}`);
    const outPath = schemaInput.path.replace(/\\.fbs$/, '.json');
    return this.Module.FS.readFile(outPath, { encoding: 'utf8' });
  }

  /**
   * Generate code for given language.
   * @param {{path:string,data:string}} schemaInput
   * @param {string[]} languages - e.g. ['--cpp','--java']
   * @param {string[]} [includeDirs=[]]
   * @param {string} [outputDir='/out']
   * @returns {{[filename:string]:string}} Map of generated files
   */
  generateCode(schemaInput, languages, includeDirs = [], outputDir = '/out') {
    try { this.Module.FS.mkdir(outputDir); } catch {}
    this.mountFile(schemaInput.path, schemaInput.data);
    const includeFlags = includeDirs.flatMap(d => ['-I', d]);
    const args = [...languages, '-o', outputDir, ...includeFlags, schemaInput.path];
    const result = this.runCommand(args);
    if (result.code !== 0) throw new Error(`flatc exited ${result.code}: ${result.stderr}`);
    const files = this.Module.FS.readdir(outputDir);
    const output = {};
    for (const f of files) {
      output[f] = this.Module.FS.readFile(`${outputDir}/${f}`, { encoding: 'utf8' });
    }
    return output;
  }

  /**
   * Get flatc usage help text.
   * @returns {string}
   */
  help() {
    return this.runCommand(['--help']).stdout;
  }

  /**
   * Get flatc version string.
   * @returns {string}
   */
  version() {
    return this.runCommand(['--version']).stdout;
  }
}