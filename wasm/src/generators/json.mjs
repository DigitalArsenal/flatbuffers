/**
 * Converts a FlatBuffer binary (.mon) to its JSON representation.
 *
 * @param {{ entry: string, files: Record<string, string|Uint8Array> }} schemaInput - Full schema input tree.
 * @param {{ path: string, data: Uint8Array }} binaryInput - The binary buffer to deserialize.
 * @param {string[]} [includeDirs=[]] - Optional include directories.
 * @param {Object} [opts={}] - Output options.
 * @param {boolean} [opts.rawBinary=true]
 * @param {boolean} [opts.strictJson=false]
 * @param {boolean} [opts.defaultsJson=false]
 * @param {"utf8" | null} [opts.encoding=null]
 * @returns {string|Uint8Array} The JSON output.
 *
 * @this {FlatcRunner}
 */
export function generateJSON(
  schemaInput,
  binaryInput,
  includeDirs = [],
  opts = {}
) {
  const outPath = binaryInput.path.replace(/\.mon$/, ".json");

  this.mountFiles([
    ...Object.entries(schemaInput.files).map(([path, data]) => ({
      path,
      data: typeof data === "string" ? data : new Uint8Array(data),
    })),
    { path: binaryInput.path, data: binaryInput.data },
  ]);

  const args = [
    "--json",
    ...(opts.rawBinary === false ? [] : ["--raw-binary"]),
    ...(opts.strictJson ? ["--strict-json"] : []),
    ...(opts.defaultsJson ? ["--defaults-json"] : []),
    "-o",
    outPath.substring(0, outPath.lastIndexOf("/")) || "/",
    ...includeDirs.flatMap((d) => ["-I", d]),
    schemaInput.entry,
    "--",
    binaryInput.path,
  ];

  const result = this.runCommand(args);
  if (result.code !== 0) throw new Error(result.stderr);

  return this.Module.FS.readFile(outPath, {
    encoding: opts?.encoding ?? null,
  });
}