import { FlatcRunner } from "./runner.mjs";
import flatcModule from "../flatc.mjs";

/**
 * Stateless high-performance FlatBuffer transformer.
 * Internally manages WASM instances for each transform call to prevent memory leaks.
 */
export class StreamingTransformer {
  /** @type {{ entry: string, files: Record<string, string | Uint8Array> }} */
  #schemaInput;

  /**
   * @param {{ entry: string, files: Record<string, string | Uint8Array> }} schemaInput
   */
  constructor(schemaInput) {
    this.#schemaInput = schemaInput;
  }

  /**
   * @param {{ entry: string, files: Record<string, string | Uint8Array> }} schemaInput
   * @returns {Promise<StreamingTransformer>}
   */
  static async create(schemaInput) {
    return new StreamingTransformer(schemaInput);
  }

  /**
   * Convert JSON to FlatBuffer binary (fresh WASM instance per call).
   * @param {string | Uint8Array} json
   * @returns {Promise<Uint8Array>}
   */
  async transformJsonToBinary(json) {
    const runner = await this.#initRunner();
    try {
      return runner.generateBinary(this.#schemaInput, json);
    } finally {
      this.#destroyRunner(runner);
    }
  }

  /**
   * Convert FlatBuffer binary to JSON (fresh WASM instance per call).
   * @param {Uint8Array} buffer
   * @returns {Promise<Uint8Array>}
   */
  async transformBinaryToJson(buffer) {
    const runner = await this.#initRunner();
    try {
      return runner.generateJSON(
        this.#schemaInput,
        { path: "/input.mon", data: buffer },
        undefined,
        { encoding: null }
      );
    } finally {
      this.#destroyRunner(runner);
    }
  }

  /**
   * Internal: Create a fresh FlatcRunner with new WASM instance.
   * @returns {Promise<FlatcRunner>}
   */
  async #initRunner() {
    const runner = new FlatcRunner(null);
    const Module = await flatcModule({
      noExitRuntime: true,
      noInitialRun: true,
      print: (text) => (runner._stdout += text + "\n"),
      printErr: (text) => (runner._stderr += text + "\n"),
    });
    runner.Module = Module;
    return runner;
  }

  /**
   * Internal: Clean up the FS and memory (no-op if not needed).
   * @param {FlatcRunner} runner
   */
  #destroyRunner(runner) {
    if (runner?.Module?.FS) {
      try {
        const root = runner.Module.FS.readdir("/");
        for (const name of root) {
          if (name === "." || name === "..") continue;
          try {
            runner.Module.FS.unmount(`/${name}`);
          } catch {
            //not required
          }
          try {
            runner.Module.FS.rmdir(`/${name}`);
          } catch {
            //not required
          }
        }
        runner.Module.FS.streams.length = 0;
        runner.Module.FS.root.contents = {};
      } catch {
        //not required
      }
    }
  }
}
