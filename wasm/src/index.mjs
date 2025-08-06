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
  /** @type {any} */
  Module;

  /** @type {string} */
  _stdout = "";

  /** @type {string} */
  _stderr = "";

  /** @type {import("stream").Writable|null} */
  stdoutStream = null;

  /** @type {import("stream").Writable|null} */
  stderrStream = null;

  /** @type {Array<{timestamp: string, method: string, message: string, stack: string}>} */
  errors = [];

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
    const runner = new FlatcRunner(
      null,
      moduleOptions.stdoutStream || null,
      moduleOptions.stderrStream || null
    );

    const Module = await flatcModule({
      noExitRuntime: true,
      noInitialRun: true,
      print: (text) => {
        if (runner.stdoutStream) {
          runner.stdoutStream.write(text + "\n");
        } else {
          runner._stdout += text + "\n";
          runner.emit("stdout", text);
        }
      },
      printErr: (text) => {
        if (runner.stderrStream) {
          runner.stderrStream.write(text + "\n");
        } else {
          runner._stderr += text + "\n";
          runner.emit("stderr", text);
        }
      },
      ...moduleOptions,
    });

    runner.Module = Module;
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
  // Recursively list all files and directories starting from root
  listAllFiles(path) {
    const FS = this.Module.FS;
    const entries = [];

    const recurse = (current) => {
      let stats;
      try {
        stats = FS.stat(current);
      } catch (e) {
        this._logError("listAllFiles.stat", e);
        return;
      }

      if (FS.isDir(stats.mode)) {
        let children;
        try {
          children = FS.readdir(current).filter(
            (name) => name !== "." && name !== ".."
          );
        } catch (e) {
          this._logError("listAllFiles.readdir", e);
          return;
        }

        for (const child of children) {
          recurse(current === "/" ? `/${child}` : `${current}/${child}`);
        }
      } else {
        entries.push(current);
      }
    };

    recurse(path);
    return entries;
  }

  /**
   * Mount file into the Emscripten virtual filesystem.
   * @param {string} filepath
   * @param {Uint8Array|string} data
   */
  mountFile(filepath, data) {
    const { FS } = this.Module;
    const dir = filepath.substring(0, filepath.lastIndexOf("/")) || "/";
    const parts = dir.split("/").filter(Boolean);
    let cur = "";
    for (const part of parts) {
      cur += "/" + part;
      try {
        FS.mkdir(cur);
      } catch (e) {
        if (e.code !== "EEXIST") this._logError("mountFile.mkdir", e);
      }
    }

    const content =
      typeof data === "string" ? new TextEncoder().encode(data) : data;

    try {
      FS.unlink(filepath);
    } catch (err) {
      if (err.code !== "ENOENT") this._logError("mountFile.unlink", err);
    }

    try {
      FS.writeFile(filepath, content, { encoding: "binary" });
    } catch (err) {
      this._logError("mountFile.writeFile", err);
    }
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
    const outDir = `/${crypto.randomUUID()}`;
    const jsonInputPath = `/input-${crypto.randomUUID()}.json`;

    this.mountFiles([
      schemaInput,
      { path: jsonInputPath, data: jsonInput.data },
    ]);

    // Create output dir if it doesn’t exist
    try {
      this.Module.FS.mkdir(outDir);
    } catch (e) {
      if (e.code !== "EEXIST") throw e;
    }

    const includeFlags = includeDirs.flatMap((d) => ["-I", d]);
    const _args = [
      "--binary",
      "--unknown-json",
      "-o",
      outDir,
      ...includeFlags,
      schemaInput.path,
      jsonInputPath,
    ];

    const result = this.runCommand(_args);

    if (result.code !== 0)
      throw new Error(`flatc exited ${result.code}: ${result.stderr}`);

    const files = this.Module.FS.readdir(outDir).filter((f) =>
      f.endsWith(".mon")
    );

    if (files.length !== 1)
      throw new Error(`Expected one .mon, found: ${files.join(",")}`);

    const outPath = `${outDir}/${files[0]}`;
    return this.Module.FS.readFile(outPath);
  }

  /**
   * Generate JSON text from a FlatBuffers binary using a schema.
   *
   * @param {{ path: string, data: string }} schemaInput - The schema .fbs file path and contents.
   * @param {{ path: string, data: Uint8Array }} binaryInput - The binary .mon file path and buffer.
   * @param {string[]} [includeDirs=[]] - Optional list of include directories (-I flags) for the schema.
   * @param {{
   *   rawBinary?: boolean,
   *   strictJson?: boolean,
   *   defaultsJson?: boolean
   * }} [opts={}] - Optional flags to customize JSON output.
   *
   * @returns {string} The generated JSON string.
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

    const inPath = binaryInput.path;
    const outPath = inPath.replace(/\.mon$/, ".json") || `${inPath}.json`;

    const outputDir = outPath.substring(0, outPath.lastIndexOf("/")) || "/";

    flags.push("-o", outputDir);

    const _args = [...flags, ...includeFlags, schemaInput.path, "--", inPath];

    const result = this.runCommand(_args);
    if (result.code !== 0) {
      throw new Error(`flatc exited ${result.code}: ${result.stderr}`);
    }

    const stats = this.Module.FS.stat(outPath);
    if (this.Module.FS.isDir(stats.mode)) {
      throw new Error(
        `Expected JSON file at ${outPath}, but it's a directory.`
      );
    }

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
    } catch (e) {
      this._logError("generateCode.mkdir", e);
    }
    this.mountFile(schemaInput.path, schemaInput.data);
    const includeFlags = includeDirs.flatMap((d) => ["-I", d]);
    const _args = [
      ...languages,
      "-o",
      outputDir,
      ...includeFlags,
      schemaInput.path,
    ];
    const result = this.runCommand(_args);
    if (result.code !== 0)
      throw new Error(`flatc exited ${result.code}: ${result.stderr}`);
    const files = this.Module.FS.readdir(outputDir);
    const output = {};
    for (const f of files) {
      try {
        output[f] = this.Module.FS.readFile(`${outputDir}/${f}`, {
          encoding: "utf8",
        });
      } catch (e) {
        this._logError("generateCode.readFile", e);
        throw e;
      }
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

  /**
   * Get collected internal errors.
   * @returns {Array<{timestamp: string, method: string, message: string, stack: string}>}
   */
  getErrors() {
    return this.errors;
  }

  /**
   * Internal error logger.
   * @param {string} method - Method name where the error occurred.
   * @param {Error} error - The error object.
   */
  _logError(method, error) {
    const timestamp = new Date().toISOString();
    this.errors.push({
      timestamp,
      method,
      message: error?.message,
      stack: error?.stack,
    });
  }
}
