import { FlatcRunner } from "./runner.mjs";
import flatcModule from "../flatc.mjs";

/**
 * Class for performing high-performance FlatBuffer transformations in a streaming context.
 * Extends FlatcRunner and supports persistent schema preloading.
 */
export class StreamingTransformer extends FlatcRunner {
  #entryPath = null;

  /**
   * Initialize a StreamingTransformer with preloaded FlatBuffer schema files.
   *
   * @param {{ entry: string, files: Record<string, string | Uint8Array> }} schemaInput
   * @param {Object} [moduleOptions={}]
   * @returns {Promise<StreamingTransformer>}
   */
  static async create(schemaInput, moduleOptions = {}) {
    const instance = new StreamingTransformer(
      null,
      moduleOptions.stdoutStream,
      moduleOptions.stderrStream
    );

    const Module = await flatcModule({
      noExitRuntime: true,
      noInitialRun: true,
      print: (text) => (instance._stdout += text + "\n"),
      printErr: (text) => (instance._stderr += text + "\n"),
      ...moduleOptions,
    });

    instance.Module = Module;

    const filesArray = Object.entries(schemaInput.files).map(
      ([path, data]) => ({ path, data })
    );
    instance.mountFiles(filesArray);
    instance.#entryPath = schemaInput.entry;

    return instance;
  }

  /**
   * Convert JSON to FlatBuffer binary using the preloaded schema.
   *
   * @param {string | Uint8Array} json
   * @returns {Uint8Array}
   */
  transformJsonToBinary(json) {
    if (!this.#entryPath) throw new Error("Schema entry path not loaded.");
    const schemaData = this.Module.FS.readFile(this.#entryPath);
    const encodedJson =
      typeof json === "string"
        ? json
        : new TextEncoder().encode(JSON.stringify(json));
    return this.generateBinary(
      { path: this.#entryPath, data: schemaData },
      encodedJson
    );
  }

  /**
   * Convert FlatBuffer binary to JSON (as UTF-8 buffer) using the preloaded schema.
   *
   * @param {Uint8Array} buffer
   * @returns {Uint8Array} JSON output as raw buffer
   */
  transformBinaryToJson(buffer) {
    if (!this.#entryPath) throw new Error("Schema entry path not loaded.");

    const schemaData = this.Module.FS.readFile(this.#entryPath);
    return this.generateJSON(
      { path: this.#entryPath, data: schemaData },
      buffer,
      [],
      { encoding: null }
    );
  }
}
