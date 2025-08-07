/**
 * Computes a deduplicated list of include directories from a FlatBuffers schema input tree.
 *
 * @param {{ files: Record<string, string|Uint8Array> }} schemaInput
 * @returns {string[]} Unique directory paths used as include paths (POSIX-style)
 */
export function getIncludeDirsFromSchemaInput(schemaInput) {
  const dirs = new Set();

  for (const filePath of Object.keys(schemaInput.files)) {
    const lastSlash = filePath.lastIndexOf("/");
    const dir = lastSlash > 0 ? filePath.slice(0, lastSlash) : "/";
    dirs.add(dir);
  }

  return Array.from(dirs);
}
