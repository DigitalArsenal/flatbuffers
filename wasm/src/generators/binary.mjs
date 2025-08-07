import { randomUUID } from "node:crypto";
import { getIncludeDirsFromSchemaInput } from "../fs/generate-include.mjs";

/**
 * Generates a FlatBuffer binary (.mon) file from the given schema and JSON input.
 * Caches the mounted schema and include paths to avoid reloading on repeated use.
 * Cleans up temporary files after execution.
 *
 * @param {{ entry: string, files: Record<string, string|Uint8Array> }} schemaInput - Schema tree to mount.
 * @param {string|Uint8Array} jsonInput - JSON input to serialize.
 * @returns {Uint8Array} The compiled binary output.
 *
 * @this {FlatcRunner}
 */
export function generateBinary(schemaInput, jsonInput) {
  const outDir = `/${randomUUID()}`;
  const jsonInputPath = `/input-${randomUUID()}.json`;

  this.Module.FS.mkdirTree(outDir);

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

  // Always mount fresh JSON input
  this.mountFiles([
    {
      path: jsonInputPath,
      data:
        typeof jsonInput === "string"
          ? new TextEncoder().encode(jsonInput)
          : jsonInput,
    },
  ]);

  const args = [
    "--binary",
    "--unknown-json",
    "-o",
    outDir,
    ...this._cachedIncludeDirs.flatMap((d) => ["-I", d]),
    schemaInput.entry,
    jsonInputPath,
  ];

  const result = this.runCommand(args);

  const cleanup = () => {
    try {
      this.Module.FS.unlink(jsonInputPath);
    } catch {}

    try {
      const outputFiles = this.Module.FS.readdir(outDir);
      for (const f of outputFiles) {
        if (f !== "." && f !== "..") {
          try {
            this.Module.FS.unlink(`${outDir}/${f}`);
          } catch {}
        }
      }
      this.Module.FS.rmdir(outDir);
    } catch {}
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

  const files = this.Module.FS.readdir(outDir);
  const file = files.find((f) => f.endsWith(".mon"));

  if (!file) {
    cleanup();
    throw new Error(
      [
        `flatc succeeded but no .mon output was found.`,
        `Expected output in directory: ${outDir}`,
        `Files present: ${files.join(", ")}`,
        `Arguments: ${args.join(" ")}`,
        `--- stdout ---`,
        result.stdout?.trim() || "(empty)",
        `--- stderr ---`,
        result.stderr?.trim() || "(empty)",
      ].join("\n")
    );
  }

  const output = this.Module.FS.readFile(`${outDir}/${file}`);
  cleanup();
  return output;
}