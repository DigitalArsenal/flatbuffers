import path from "node:path";
import fs from "node:fs/promises";

/**
 * Recursively walks a directory and yields all `.fbs` file paths.
 *
 * @param {string} dir - The root directory to start walking.
 * @returns {AsyncGenerator<string>} - An async generator yielding absolute `.fbs` file paths.
 */
export async function* walkFbsFiles(dir) {
  for (const entry of await fs.readdir(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      yield* walkFbsFiles(fullPath);
    } else if (entry.isFile() && entry.name.endsWith(".fbs")) {
      yield fullPath;
    }
  }
}

/**
 * Loads all `.fbs` files from a root directory and returns them
 * as virtual paths with content, suitable for FlatcRunner input.
 *
 * @param {string} rootDir - The root directory to search under.
 * @returns {Promise<Array<{ path: string, data: string }>>}
 */
export async function loadFbsFiles(rootDir) {
  const files = [];
  for await (const filePath of walkFbsFiles(rootDir)) {
    const data = await fs.readFile(filePath, "utf8");
    const relPath = path.relative(rootDir, filePath);
    files.push({ path: `/${relPath}`, data });
  }
  return files;
}


export function getLanguageEntries() {
  const objectApiCapable = new Set([
    "cpp",
    "csharp",
    "go",
    "java",
    "kotlin",
    "kotlin-kmp",
    "lua",
    "php",
    "python",
    "rust",
    "swift",
  ]);

  const hardcodedLanguages = [
    "cpp",
    "csharp",
    "dart",
    "go",
    "java",
    "jsonschema",
    "kotlin",
    "kotlin-kmp",
    "lobster",
    "lua",
    "nim",
    "php",
    "python",
    "rust",
    "swift",
    "ts",
  ];

  return hardcodedLanguages.map((language) => ({
    language,
    options: objectApiCapable.has(language) ? { objectAPI: true } : {},
  }));
}
