/**
 * @module FlatcRunner
 *
 * Provides an interface to run the FlatBuffers compiler (flatc) through a WebAssembly module.
 * Offers functionality for mounting files, generating binaries, JSON, and code from schemas.
 */

import Emittery from "emittery";
import flatcModule from "../flatc.mjs";
import { runCommand } from "../utils/run-command.mjs";
import { logError } from "../utils/errors.mjs";
import { listAllFiles } from "../fs/list.mjs";
import { generateBinary } from "../generators/binary.mjs";
import { generateJSON } from "../generators/json.mjs";
import { generateCode } from "../generators/code.mjs";
import console from "node:console";

/**
 * Class representing the FlatBuffers compiler runner.
 * Extends EventEmitter to allow event-based interactions.
 */
export class FlatcRunner extends Emittery {
  /**
   * Create a FlatcRunner instance.
   * @param {Object|null} Module - The instantiated WebAssembly module.
   * @param {WritableStream|null} [stdoutStream=null] - Optional stream for standard output.
   * @param {WritableStream|null} [stderrStream=null] - Optional stream for standard error.
   */
  constructor(Module, stdoutStream = null, stderrStream = null) {
    super();
    this.Module = Module;
    this.stdoutStream = stdoutStream;
    this.stderrStream = stderrStream;
    this._stdout = "";
    this._stderr = "";
    this.errors = [];
  }

  /**
   * Asynchronously initializes the WebAssembly module and returns a FlatcRunner instance.
   * @param {Object} [moduleOptions={}] - Options passed to the WebAssembly module.
   * @returns {Promise<FlatcRunner>} The initialized FlatcRunner instance.
   */
  static async init(moduleOptions = {}) {
    const runner = new FlatcRunner(
      null,
      moduleOptions.stdoutStream,
      moduleOptions.stderrStream
    );
    const Module = await flatcModule({
      noExitRuntime: true,
      noInitialRun: true,
      print: (text) => (runner._stdout += text + "\n"),
      printErr: (text) => (runner._stderr += text + "\n"),
      ...moduleOptions,
    });
    runner.Module = Module;
    return runner;
  }

  /**
   * Run a command using the flatc compiler.
   * @param {string[]} args - Command-line arguments for flatc.
   * @returns {{ stdout: string, stderr: string }} The output from stdout and stderr.
   */
  runCommand(args) {
    return runCommand.call(this, args);
  }

  /**
   * Mount a single file into the WebAssembly file system.
   * @param {string} path - The target path in the virtual FS.
   * @param {string|Uint8Array} data - The file contents.
   */
  mountFile(path, data) {
    const { FS } = this.Module;
    const dir = path.substring(0, path.lastIndexOf("/")) || "/";
    const parts = dir.split("/").filter(Boolean);
    let cur = "";
    for (const part of parts) {
      cur += "/" + part;
      try {
        FS.mkdir(cur);
      } catch {
        //not required
      }
    }
    FS.writeFile(
      path,
      typeof data === "string" ? new TextEncoder().encode(data) : data
    );
  }

  /**
   * Mount multiple files into the WebAssembly file system.
   * @param {{ path: string, data: string|Uint8Array }[]} files - Array of files to mount.
   */
  mountFiles(files) {
    for (const f of files) this.mountFile(f.path, f.data);
  }

  /**
   * Recursively list all files from a given directory in the WebAssembly FS.
   * @param {string} path - The directory path to list files from.
   * @returns {string[]} Array of file paths.
   */
  listAllFiles(path) {
    return listAllFiles.call(this, path);
  }

  /**
   * Generate FlatBuffer binary output from schema and data.
   * @param {...any} args - Arguments passed to the binary generator.
   * @returns {Uint8Array} The generated FlatBuffer binary.
   */
  generateBinary(...args) {
    return generateBinary.call(this, ...args);
  }

  /**
   * Generate JSON output from schema and binary data.
   * @param {...any} args - Arguments passed to the JSON generator.
   * @returns {string} The generated JSON string.
   */
  generateJSON(...args) {
    return generateJSON.call(this, ...args);
  }

  /**
   * Generate source code (e.g., C++, Java, etc.) from schema.
   * @param {...any} args - Arguments passed to the code generator.
   * @returns {Object} Map of generated file paths to their contents.
   */
  generateCode(...args) {
    return generateCode.call(this, ...args);
  }

  /**
   * Show the help text from flatc.
   * @returns {string} Help text output.
   */
  help() {
    return this.runCommand(["--help"]).stdout;
  }

  /**
   * Show the flatc version string.
   * @returns {string} Version output.
   */
  version() {
    return this.runCommand(["--version"]).stdout;
  }

  /**
   * Log an error associated with a specific method.
   * @param {string} method - The method name.
   * @param {Error} err - The error object.
   */
  _logError(method, err) {
    logError.call(this, method, err);
  }

  /**
   * Get all collected errors from command execution.
   * @returns {Error[]} Array of error objects.
   */
  getErrors() {
    return this.errors;
  }
}
