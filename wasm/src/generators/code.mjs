import { randomUUID } from "node:crypto";
import { getIncludeDirsFromSchemaInput } from "../fs/generate-include.mjs";

/**
 * @typedef {"cpp"|"csharp"|"dart"|"go"|"java"|"json"|"jsonschema"|"kotlin"|"kotlin-kmp"|"lobster"|"lua"|"nim"|"php"|"python"|"rust"|"swift"|"ts"} SupportedLanguage
 */

/**
 * @typedef {Object} GenerateCodeOptions
 * @property {boolean} [genObjectApi]
 * @property {boolean} [genOneFile]
 * @property {boolean} [pythonTyping]
 * @property {boolean} [pythonVersion]
 * @property {boolean} [noIncludes]
 * @property {boolean} [genCompare]
 * @property {boolean} [genNameStrings]
 * @property {boolean} [reflectNames]
 * @property {boolean} [reflectTypes]
 * @property {boolean} [genJsonEmit]
 * @property {boolean} [keepPrefix]
 * @property {boolean} [preserveCase]
 */

/**
 * Generates source code in the specified target language from a FlatBuffers schema input tree.
 *
 * @param {{ files: Record<string, string|Uint8Array|Buffer>, entry: string }} schemaInput
 * @param {SupportedLanguage} language
 * @param {string} [outputDir]
 * @param {GenerateCodeOptions} [options={}]
 * @returns {Record<string, string>}
 *
 * @throws {Error}
 *
 * @this {FlatcRunner}
 */
export function generateCode(
  schemaInput,
  language,
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

  const includeDirs = getIncludeDirsFromSchemaInput(schemaInput);

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
  if (result.code !== 0) throw new Error(result.stderr);

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

  return walk(outputDir);
}