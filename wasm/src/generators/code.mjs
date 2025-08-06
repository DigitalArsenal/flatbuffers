/**
 * Generates source code in the specified target languages from a FlatBuffers schema file.
 *
 * Mounts the schema file into the WebAssembly file system, runs the FlatBuffers compiler
 * (`flatc`) with the given language flags, and returns the contents of the generated source files.
 *
 * @param {{ path: string, data: string|Uint8Array }} schemaInput - The schema file, including its virtual path and contents.
 * @param {string[]} languages - An array of `flatc` language flags (e.g., ["--js", "--cpp"]).
 * @param {string[]} [includeDirs=[]] - Optional array of include directories for schema resolution.
 * @param {string} [outputDir="/out"] - The directory to write generated code files to within the virtual file system.
 * @returns {Object.<string, string>} An object mapping filenames to their file contents.
 *
 * @throws {Error} If the FlatBuffers compiler exits with a non-zero status code.
 *
 * @this {FlatcRunner} The FlatcRunner instance containing the initialized WebAssembly Module.
 */
export function generateCode(
  schemaInput,
  languages,
  includeDirs = [],
  outputDir = "/out"
) {
  try {
    this.Module.FS.mkdir(outputDir);
  } catch {
    // not required
  }
  this.mountFile(schemaInput.path, schemaInput.data);
  const args = [
    ...languages,
    "-o",
    outputDir,
    ...includeDirs.flatMap((d) => ["-I", d]),
    schemaInput.path,
  ];
  const result = this.runCommand(args);
  if (result.code !== 0) throw new Error(result.stderr);
  const files = this.Module.FS.readdir(outputDir);
  const out = {};
  for (const file of files) {
    out[file] = this.Module.FS.readFile(`${outputDir}/${file}`, {
      encoding: "utf8",
    });
  }
  return out;
}
