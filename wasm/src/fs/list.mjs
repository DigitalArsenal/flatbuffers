/**
 * Recursively lists all files under the specified directory path within the
 * WebAssembly virtual file system.
 *
 * @param {string} path - The root directory path to start traversal from.
 * @returns {string[]} An array of file paths found under the given directory.
 *
 * @this {FlatcRunner} The FlatcRunner instance containing the initialized WebAssembly Module.
 */
export function listAllFiles(path) {
  const FS = this.Module.FS;
  const result = [];
  const traverse = (p) => {
    const stat = FS.stat(p);
    if (FS.isDir(stat.mode)) {
      for (const name of FS.readdir(p).filter(n => n !== "." && n !== "..")) {
        traverse(p === "/" ? `/${name}` : `${p}/${name}`);
      }
    } else result.push(p);
  };
  traverse(path);
  return result;
}
