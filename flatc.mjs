import flatcModule from './flatc.mjs';
import JSZip from 'jszip';

/**
 * FlatBuffers WASM flatc compiler wrapper, fully isomorphic for browser or Node,
 * with support for mounting and exporting ZIP archives.
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
      print: text => { stdout += text + '\n'; },
      printErr: text => { stderr += text + '\n'; },
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
    const dir = filepath.slice(0, filepath.lastIndexOf('/')) || '/';
    dir.split('/').filter(Boolean).reduce((cur, part) => {
      cur += '/' + part;
      try { this.Module.FS.mkdir(cur); } catch {};
      return cur;
    }, '');
    const name = filepath.slice(filepath.lastIndexOf('/') + 1);
    const content = typeof data === 'string'
      ? this.Module.intArrayFromString(data, true)
      : data;
    try { this.Module.FS.unlink(filepath); } catch {};
    this.Module.FS_createDataFile(dir, name, content, true, true);
  }

  /**
   * Mount multiple files.
   * @param {{path:string,data:Uint8Array|string}[]} files
   */
  mountFiles(files) {
    files.forEach(f => this.mountFile(f.path, f.data));
  }

  /**
   * Mount a ZIP archive into the FS preserving folder structure.
   * @param {Uint8Array|ArrayBuffer} zipData - ZIP file data
   * @param {string} mountRoot - Root path in FS (e.g. '/')
   * @returns {Promise<void>}
   */
  async mountZip(zipData, mountRoot = '/') {
    const zip = await JSZip.loadAsync(zipData);
    await Promise.all(Object.keys(zip.files).map(async rel => {
      const file = zip.files[rel];
      const target = (mountRoot + rel).replace(/\/+/g, '/');
      if (file.dir) {
        try { this.Module.FS.mkdir(target); } catch {};
      } else {
        const data = await file.async('uint8array');
        this.mountFile(target, data);
      }
    }));
  }

  /**
   * Export a directory from FS as a ZIP archive.
   * @param {string} root - FS directory to zip (e.g. '/')
   * @returns {Promise<Uint8Array>} ZIP file as Uint8Array
   */
  async exportZip(root = '/') {
    const zip = new JSZip();
    const walk = path => {
      this.Module.FS.readdir(path).forEach(name => {
        if (name === '.' || name === '..') return;
        const full = (path + '/' + name).replace(/\/+/g, '/');
        const stat = this.Module.FS.stat(full);
        if (stat.isDirectory) {
          const folder = zip.folder(full.startsWith('/') ? full.slice(1) : full);
          walk(full);
        } else {
          const data = this.Module.FS.readFile(full, { encoding: 'binary' });
          zip.file(full.startsWith('/') ? full.slice(1) : full, data);
        }
      });
    };
    walk(root);
    const blob = await zip.generateAsync({ type: 'uint8array' });
    return blob;
  }

  /**
   * Read file from virtual FS.
   * @param {string} filepath
   * @param {{encoding:'utf8'|'binary'}} [opts]
   * @returns {string|Uint8Array}
   */
  readFile(filepath, opts = {}) {
    return this.Module.FS.readFile(filepath, opts);
  }

  /**
   * Write file to virtual FS.
   * @param {string} filepath
   * @param {Uint8Array|string} data
   */
  writeFile(filepath, data) {
    this.mountFile(filepath, data);
  }

  /**
   * List directory entries in virtual FS.
   * @param {string} dirpath - POSIX directory path
   * @returns {string[]}
   */
  listFiles(dirpath = '/') {
    return this.Module.FS.readdir(dirpath);
  }

  /**
   * Remove all files and directories under a path in FS.
   * @param {string} root - POSIX path to clear
   */
  clearFS(root = '/') {
    const walk = path => {
      this.Module.FS.readdir(path).forEach(name => {
        if (name === '.' || name === '..') return;
        const full = `${path}/${name}`;
        const stat = this.Module.FS.stat(full);
        if (stat.isDirectory) {
          walk(full);
          try { this.Module.FS.rmdir(full); } catch {};
        } else {
          try { this.Module.FS.unlink(full); } catch {};
        }
      });
    };
    walk(root);
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
    const outPath = schemaInput.path.replace(/\.fbs$/, '.json');
    return this.Module.FS.readFile(outPath, { encoding: 'utf8' });
  }

  /**
   * Generate code for given language.
   * @param {{path:string,data:string}} schemaInput
   * @param {string[]} languages
   * @param {string[]} [includeDirs=[]]
   * @param {string} [outputDir='/out']
   * @returns {{[filename:string]:string}}
   */
  generateCode(schemaInput, languages, includeDirs = [], outputDir = '/out') {
    try { this.Module.FS.mkdir(outputDir); } catch {};
    this.mountFile(schemaInput.path, schemaInput.data);
    const includeFlags = includeDirs.flatMap(d => ['-I', d]);
    const args = [...languages, '-o', outputDir, ...includeFlags, schemaInput.path];
    const result = this.runCommand(args);
    if (result.code !== 0) throw new Error(`flatc exited ${result.code}: ${result.stderr}`);
    const files = this.Module.FS.readdir(outputDir);
    const output = {};
    files.forEach(f => {
      output[f] = this.Module.FS.readFile(`${outputDir}/${f}`, { encoding: 'utf8' });
    });
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