/**
 * Converts a FlatBuffer binary (.mon) file into its corresponding JSON representation.
 *
 * Mounts the schema and binary files into the WebAssembly file system, runs the
 * FlatBuffers compiler (`flatc`) with the `--json` flag, and returns the resulting JSON string.
 *
 * @param {{ path: string, data: string|Uint8Array }} schemaInput - The FlatBuffers schema file.
 * @param {{ path: string, data: Uint8Array }} binaryInput - The FlatBuffer binary input (.mon) to deserialize.
 * @param {string[]} [includeDirs=[]] - Optional array of include directories for schema resolution.
 * @param {Object} [opts={}] - Optional flags for JSON output behavior.
 * @param {boolean} [opts.rawBinary=true] - Include raw binary data (default: true).
 * @param {boolean} [opts.strictJson=false] - Enable strict JSON compliance.
 * @param {boolean} [opts.defaultsJson=false] - Output default values in JSON.
 * @returns {string} The resulting JSON string.
 *
 * @throws {Error} If the FlatBuffers compiler exits with a non-zero status code.
 *
 * @this {FlatcRunner} The FlatcRunner instance containing the initialized WebAssembly Module.
 */
export function generateJSON(
  schemaInput,
  binaryInput,
  includeDirs = [],
  opts = {}
) {
  this.mountFiles([
    schemaInput,
    { path: binaryInput.path, data: binaryInput.data },
  ]);
  const outPath = binaryInput.path.replace(/\.mon$/, ".json");
  const args = [
    "--json",
    ...(opts.rawBinary === false ? [] : ["--raw-binary"]),
    ...(opts.strictJson ? ["--strict-json"] : []),
    ...(opts.defaultsJson ? ["--defaults-json"] : []),
    "-o",
    outPath.substring(0, outPath.lastIndexOf("/")) || "/",
    ...includeDirs.flatMap((d) => ["-I", d]),
    schemaInput.path,
    "--",
    binaryInput.path,
  ];
  const result = this.runCommand(args);
  if (result.code !== 0) throw new Error(result.stderr);
  return this.Module.FS.readFile(outPath, { encoding: "utf8" });
}
