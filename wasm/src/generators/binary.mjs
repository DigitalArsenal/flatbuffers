import { randomUUID } from "node:crypto";
import { getIncludeDirsFromSchemaInput } from "../fs/generate-include.mjs";
/**
 * Generates a FlatBuffer binary (.mon) file from the given schema and JSON input.
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

  this.mountFiles([
    ...Object.entries(schemaInput.files).map(([path, data]) => ({
      path,
      data: typeof data === "string" ? data : new Uint8Array(data),
    })),
    {
      path: jsonInputPath,
      data:
        typeof jsonInput === "string"
          ? new TextEncoder().encode(jsonInput)
          : jsonInput,
    },
  ]);

  const includeDirs = getIncludeDirsFromSchemaInput(schemaInput);

  const args = [
    "--binary",
    "--unknown-json",
    "-o",
    outDir,
    ...includeDirs.flatMap((d) => ["-I", d]),
    schemaInput.entry,
    jsonInputPath,
  ];

  const result = this.runCommand(args);
  if (result.code !== 0) throw new Error(result.stderr);

  const file = this.Module.FS.readdir(outDir).find((f) => f.endsWith(".mon"));
  if (!file) throw new Error("No output file (.mon) was produced");

  return this.Module.FS.readFile(`${outDir}/${file}`);
}
