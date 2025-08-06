import { randomUUID } from "node:crypto";

/**
 * @typedef {"cpp"|"csharp"|"dart"|"go"|"java"|"json"|"jsonschema"|"kotlin"|"kotlin-kmp"|"lobster"|"lua"|"nim"|"php"|"python"|"rust"|"swift"|"ts"} SupportedLanguage
 */

/**
 * @typedef {Object} GenerateCodeOptions
 * @property {boolean} [genObjectApi] - Enable the object-based API.
 * @property {boolean} [genOneFile] - Generate a single file for supported languages.
 * @property {boolean} [pythonTyping] - Enable Python type annotations.
 * @property {boolean} [pythonVersion] - Enable Python version-specific code.
 * @property {boolean} [noIncludes] - Disable generation of include statements.
 * @property {boolean} [genCompare] - Generate equality operators in object API.
 * @property {boolean} [genNameStrings] - Generate type name functions.
 * @property {boolean} [reflectNames] - Enable name reflection in generated code.
 * @property {boolean} [reflectTypes] - Enable type reflection in generated code.
 * @property {boolean} [genJsonEmit] - Generate JSON emit code.
 * @property {boolean} [keepPrefix] - Retain original include prefix.
 * @property {boolean} [preserveCase] - Preserve field name casing.
 */

/**
 * Generates source code in the specified target language from a FlatBuffers schema input tree.
 *
 * Mounts all schema files into the WebAssembly file system, runs the FlatBuffers compiler
 * (`flatc`) with the given language and options, and returns the contents of the generated files.
 *
 * @param {{ files: Record<string, string|Uint8Array|Buffer>, entry: string }} schemaInput - Virtual file tree for flatc. All keys are virtual paths.
 * @param {SupportedLanguage} language - Target language for code generation (e.g. "cpp", "rust", "python").
 * @param {string[]} [includeDirs=[]] - Include dirs passed to `-I`. Must correspond to prefixes in `schemaInput.files`.
 * @param {string} [outputDir] - Optional virtual output directory. Defaults to `/out/<uuid>`.
 * @param {GenerateCodeOptions} [options={}] - Additional flags to pass to `flatc`.
 * @returns {Record<string, string>} An object mapping generated filenames (relative paths) to contents.
 *
 * @throws {Error} If `flatc` exits with a non-zero status code.
 *
 * @this {FlatcRunner}
 */
export function generateCode(
  schemaInput,
  language,
  includeDirs = [],
  outputDir = `/out/${randomUUID()}`,
  options = {}
) {
  this.Module.FS.mkdirTree(outputDir);

  this.mountFiles(
    Object.entries(schemaInput.files).map(([path, data]) => ({
      path,
      data:
        typeof data === "string"
          ? data
          : data instanceof Uint8Array
          ? data
          : new Uint8Array(data),
    }))
  );

  /** @type {string[]} */
  const args = [`--${language}`, "-o", outputDir];

  for (const dir of includeDirs) {
    args.push("-I", dir);
  }

  if (options.genObjectApi) args.push("--gen-object-api");
  if (options.genOneFile) args.push("--gen-onefile");
  if (options.pythonTyping) args.push("--python-typing");
  if (options.pythonVersion) args.push("--python-version");
  if (options.noIncludes) args.push("--no-includes");
  if (options.genCompare) args.push("--gen-compare");
  if (options.genNameStrings) args.push("--gen-name-strings");
  if (options.reflectNames) args.push("--reflect-names");
  if (options.reflectTypes) args.push("--reflect-types");
  if (options.genJsonEmit) args.push("--gen-json-emit");
  if (options.keepPrefix) args.push("--keep-prefix");
  if (options.preserveCase) args.push("--preserve-case");

  args.push(schemaInput.entry);

  const result = this.runCommand(args);
  const success = result.code === 0;

  const walk = (path, base = "") => {
    const result = {};
    const entries = this.Module.FS.readdir(path).filter(
      (e) => e !== "." && e !== ".."
    );
    for (const entry of entries) {
      const fullPath = `${path}/${entry}`;
      const relPath = base ? `${base}/${entry}` : entry;
      const stat = this.Module.FS.stat(fullPath);
      if (this.Module.FS.isDir(stat.mode)) {
        Object.assign(result, walk(fullPath, relPath));
      } else {
        result[relPath] = this.Module.FS.readFile(fullPath, {
          encoding: "utf8",
        });
      }
    }
    return result;
  };

  const files = success ? walk(outputDir) : {};

  if (!success) throw new Error(result.stderr);
  return files;
}