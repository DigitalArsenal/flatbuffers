/**
 * Generates a FlatBuffer binary (.mon) file from the given schema and JSON input.
 *
 * Mounts the schema and JSON input into the WebAssembly file system, executes the
 * FlatBuffers compiler (`flatc`) in binary mode, and returns the resulting binary output.
 *
 * @param {{ path: string, data: string|Uint8Array }} schemaInput - The schema file to compile, including its virtual path and contents.
 * @param {{ data: string|Uint8Array }} jsonInput - The JSON input data to serialize using the schema.
 * @param {string[]} [includeDirs=[]] - Optional array of include directories for schema resolution.
 * @returns {Uint8Array} The compiled FlatBuffer binary data.
 *
 * @throws {Error} If the FlatBuffers compiler exits with a non-zero status or if output file is not found.
 *
 * @this {FlatcRunner} The FlatcRunner instance containing the initialized WebAssembly Module.
 */
export function generateBinary(schemaInput, jsonInput, includeDirs = []) {
  const outDir = `/${crypto.randomUUID()}`;
  const jsonInputPath = `/input-${crypto.randomUUID()}.json`;
  this.mountFiles([schemaInput, { path: jsonInputPath, data: jsonInput.data }]);
  try {
    this.Module.FS.mkdir(outDir);
  } catch {
    // not required
  }
  const args = [
    "--binary",
    "--unknown-json",
    "-o",
    outDir,
    ...includeDirs.flatMap((d) => ["-I", d]),
    schemaInput.path,
    jsonInputPath,
  ];
  const result = this.runCommand(args);
  if (result.code !== 0) throw new Error(result.stderr);
  const file = this.Module.FS.readdir(outDir).find((f) => f.endsWith(".mon"));
  return this.Module.FS.readFile(`${outDir}/${file}`);
}
