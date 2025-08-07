import { getIncludeDirsFromSchemaInput } from "../fs/generate-include.mjs";

/**
 * Converts a FlatBuffer binary (.mon) to its JSON representation.
 * Cleans up binary input and output JSON file after execution.
 *
 * @param {{ entry: string, files: Record<string, string|Uint8Array> }} schemaInput - Full schema input tree.
 * @param {{ path: string, data: Uint8Array }} binaryInput - The binary buffer to deserialize.
 * @param {Object} [opts={}] - Output options.
 * @param {boolean} [opts.rawBinary=true]
 * @param {boolean} [opts.defaultsJson=false]
 * @param {"utf8" | null} [opts.encoding=null]
 * @returns {string|Uint8Array} The JSON output.
 *
 * @this {FlatcRunner}
 */
export function generateJSON(schemaInput, binaryInput, opts = {}) {
  const outPath = binaryInput.path.replace(/\.mon$/, ".json");
  const outDir = outPath.substring(0, outPath.lastIndexOf("/")) || "/";

  const schemaUnchanged =
    this._cachedSchema &&
    this._cachedSchema.entry === schemaInput.entry &&
    Object.keys(this._cachedSchema.files).length ===
      Object.keys(schemaInput.files).length &&
    Object.keys(this._cachedSchema.files).every(
      (key) =>
        schemaInput.files[key] &&
        this._cachedSchema.files[key] === schemaInput.files[key]
    );

  if (!schemaUnchanged) {
    this.mountFiles(
      Object.entries(schemaInput.files).map(([path, data]) => ({
        path,
        data: typeof data === "string" ? data : new Uint8Array(data),
      }))
    );
    this._cachedSchema = schemaInput;
    this._cachedIncludeDirs = getIncludeDirsFromSchemaInput(schemaInput);
  }

  this.mountFiles([
    {
      path: binaryInput.path,
      data: binaryInput.data,
    },
  ]);

  const args = [
    "--json",
    "--strict-json",
    ...(opts.rawBinary === false ? [] : ["--raw-binary"]),
    ...(opts.defaultsJson ? ["--defaults-json"] : []),
    "-o",
    outDir,
    ...this._cachedIncludeDirs.flatMap((d) => ["-I", d]),
    schemaInput.entry,
    "--",
    binaryInput.path,
  ];

  const result = this.runCommand(args);

  const cleanup = () => {
    try {
      this.Module.FS.unlink(binaryInput.path);
    } catch {}

    try {
      this.Module.FS.unlink(outPath);
    } catch {}

    try {
      const files = this.Module.FS.readdir(outDir);
      if (files.every((f) => f === "." || f === "..")) {
        this.Module.FS.rmdir(outDir);
      }
    } catch {
      // don't need it
    }
  };

  if (result.code !== 0) {
    cleanup();
    throw new Error(
      [
        `flatc failed with exit code ${result.code}`,
        `Arguments: ${args.join(" ")}`,
        `--- stdout ---`,
        result.stdout?.trim() || "(empty)",
        `--- stderr ---`,
        result.stderr?.trim() || "(empty)",
      ].join("\n")
    );
  }

  const output = this.Module.FS.readFile(outPath, {
    encoding: opts?.encoding ?? null,
  });

  cleanup();
  return output;
}