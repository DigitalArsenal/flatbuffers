import flatcModule from "./flatc.mjs";
import { EventEmitter } from "events";

/**
 * @typedef {Object} ModuleOptions
 * @property {boolean} [noInitialRun]
 * @property {boolean} [noExitRuntime]
 * @property {(text: string) => void} [print]
 * @property {(text: string) => void} [printErr]
 * @property {WebAssembly.Memory} [wasmMemory]
 * @property {(path: string) => string} [locateFile]
 * @property {Array<string>} [arguments]
 * @property {number} [TOTAL_MEMORY]
 * @property {number} [TOTAL_STACK]
 * @property {() => void} [onRuntimeInitialized]
 * @property {() => void} [preRun]
 * @property {() => void} [postRun]
 * @property {import("stream").Writable} [stdoutStream]
 * @property {import("stream").Writable} [stderrStream]
 */

/**
 * FlatBuffers WASM flatc compiler wrapper with buffered and streaming output.
 */
export class FlatcRunner extends EventEmitter {
  /**
   * @type {any}
   */
  Module;

  /**
   * @type {string}
   */
  _stdout = "";

  /**
   * @type {string}
   */
  _stderr = "";

  /**
   * @type {import("stream").Writable|null}
   */
  stdoutStream = null;

  /**
   * @type {import("stream").Writable|null}
   */
  stderrStream = null;

  /**
   * @param {any} Module
   * @param {import("stream").Writable|null} stdoutStream
   * @param {import("stream").Writable|null} stderrStream
   */
  constructor(Module, stdoutStream = null, stderrStream = null) {
    super();
    this.Module = Module;
    this.stdoutStream = stdoutStream;
    this.stderrStream = stderrStream;
  }

  /**
   * Initialize the FlatcRunner with optional output streams.
   * @param {ModuleOptions} [moduleOptions={}]
   * @returns {Promise<FlatcRunner>}
   */
  static async init(moduleOptions = {}) {
    let runner;

    const Module = await flatcModule({
      noExitRuntime: true,
      noInitialRun: true,
      print: (text) => {
        if (moduleOptions.stdoutStream) {
          moduleOptions.stdoutStream.write(text + "\n");
        } else {
          runner._stdout += text + "\n";
          runner.emit("stdout", text);
        }
      },
      printErr: (text) => {
        if (moduleOptions.stderrStream) {
          moduleOptions.stderrStream.write(text + "\n");
        } else {
          runner._stderr += text + "\n";
          runner.emit("stderr", text);
        }
      },
      ...moduleOptions,
    });

    runner = new FlatcRunner(Module, moduleOptions.stdoutStream || null, moduleOptions.stderrStream || null);
    return runner;
  }

  /**
   * Run flatc with args and return buffered result.
   * @param {string[]} args
   * @returns {{code: number, stdout: string, stderr: string}}
   */
  runCommand(args) {
    this._stdout = "";
    this._stderr = "";

    let code = 0;
    try {
      this.Module.callMain(args);
    } catch (e) {
      if (typeof e === "number") code = e;
      else throw e;
    }

    return {
      code,
      stdout: this._stdout.trim(),
      stderr: this._stderr.trim(),
    };
  }

  /**
   * Mount file into the Emscripten virtual FS.
   * @param {string} filepath
   * @param {Uint8Array|string} data
   */
  mountFile(filepath, data) {
    const dir = filepath.substring(0, filepath.lastIndexOf("/")) || "/";
    const parts = dir.split("/").filter(Boolean);
    let cur = "";
    for (const part of parts) {
      cur += "/" + part;
      try {
        this.Module.FS.mkdir(cur);
      } catch (e) {}
    }
    const name = filepath.substring(filepath.lastIndexOf("/") + 1);
    const content =
      typeof data === "string" ? new TextEncoder().encode(data) : data;
    try {
      this.Module.FS.unlink(filepath);
    } catch (err) {}
    this.Module.FS_createDataFile(dir, name, content, true, true);
  }

  /**
   * Mount multiple files.
   * @param {{path: string, data: Uint8Array|string}[]} files
   */
  mountFiles(files) {
    for (const f of files) {
      this.mountFile(f.path, f.data);
    }
  }

  /**
   * Generate binary (.mon) from schema and JSON.
   * @param {{path: string, data: string}} schemaInput
   * @param {{path: string, data: string}} jsonInput
   * @param {string[]} [includeDirs=[]]
   * @returns {Uint8Array}
   */
  generateBinary(schemaInput, jsonInput, includeDirs = []) {
    this.mountFiles([schemaInput, jsonInput]);
    const includeFlags = includeDirs.flatMap((d) => ["-I", d]);
    const args = [
      "--binary",
      "--unknown-json",
      ...includeFlags,
      schemaInput.path,
      jsonInput.path,
    ];
    const result = this.runCommand(args);
    if (result.code !== 0)
      throw new Error(`flatc exited ${result.code}: ${result.stderr}`);
    const files = this.Module.FS.readdir("/").filter((f) => f.endsWith(".mon"));
    if (files.length !== 1)
      throw new Error(`Expected one .mon, found: ${files}`);
    return this.Module.FS.readFile(`/${files[0]}`);
  }

  /**
   * Generate JSON from schema and binary.
   * @param {{path: string, data: string}} schemaInput
   * @param {{path: string, data: Uint8Array}} binaryInput
   * @param {string[]} [includeDirs=[]]
   * @param {{rawBinary?: boolean, strictJson?: boolean, defaultsJson?: boolean}} [opts={}]
   * @returns {string}
   */
  generateJSON(schemaInput, binaryInput, includeDirs = [], opts = {}) {
    this.mountFiles([
      schemaInput,
      { path: binaryInput.path, data: binaryInput.data },
    ]);
    const flags = ["--json"];
    if (opts.rawBinary !== false) flags.push("--raw-binary");
    if (opts.strictJson) flags.push("--strict-json");
    if (opts.defaultsJson) flags.push("--defaults-json");
    const includeFlags = includeDirs.flatMap((d) => ["-I", d]);
    const args = [
      ...flags,
      ...includeFlags,
      schemaInput.path,
      binaryInput.path,
    ];
    const result = this.runCommand(args);
    if (result.code !== 0)
      throw new Error(`flatc exited ${result.code}: ${result.stderr}`);
    const outPath = schemaInput.path.replace(/\.fbs$/, ".json");
    return this.Module.FS.readFile(outPath, { encoding: "utf8" });
  }

  /**
   * Generate code from schema.
   * @param {{path: string, data: string}} schemaInput
   * @param {string[]} languages
   * @param {string[]} [includeDirs=[]]
   * @param {string} [outputDir="/out"]
   * @returns {{[filename: string]: string}}
   */
  generateCode(schemaInput, languages, includeDirs = [], outputDir = "/out") {
    try {
      this.Module.FS.mkdir(outputDir);
    } catch (e) {}
    this.mountFile(schemaInput.path, schemaInput.data);
    const includeFlags = includeDirs.flatMap((d) => ["-I", d]);
    const args = [
      ...languages,
      "-o",
      outputDir,
      ...includeFlags,
      schemaInput.path,
    ];
    const result = this.runCommand(args);
    if (result.code !== 0)
      throw new Error(`flatc exited ${result.code}: ${result.stderr}`);
    const files = this.Module.FS.readdir(outputDir);
    const output = {};
    for (const f of files) {
      output[f] = this.Module.FS.readFile(`${outputDir}/${f}`, {
        encoding: "utf8",
      });
    }
    return output;
  }

  /**
   * Get flatc --help text (buffered).
   * @returns {string}
   */
  help() {
    return this.runCommand(["--help"]).stdout;
  }

  /**
   * Get flatc --version text (buffered).
   * @returns {string}
   */
  version() {
    return this.runCommand(["--version"]).stdout;
  }
}
