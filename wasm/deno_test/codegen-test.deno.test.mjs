import { assert } from "https://deno.land/std@0.214.0/assert/mod.ts";
import { FlatcRunner } from "../src/mod.mjs";
import { runCodegenSmokeTest } from "../shared_test/codegen-test.mjs";
import {
  loadFbsFiles,
  getLanguageEntries,
} from "../shared_test/util/load-fbs-files.mjs";

const TEST_ROOT = new URL("../../tests/", import.meta.url).pathname;

/**
 * Creates a buffered WritableStream to capture stdout output from the FlatcRunner.
 *
 * @returns {{
 *   writable: WritableStream;
 *   getOutput: () => string;
 * }}
 * Writable stream for capturing output and a function to retrieve it.
 */
function createBufferedStdout() {
  const buffer = [];
  const writable = new WritableStream({
    write(chunk) {
      buffer.push(
        typeof chunk === "string" ? chunk : new TextDecoder().decode(chunk)
      );
    },
  });
  return {
    writable,
    getOutput: () => buffer.join(""),
  };
}

Deno.test("FlatcRunner generateCode smoke test per language", async () => {
  const languageEntries = getLanguageEntries();

  const results = await runCodegenSmokeTest({
    FlatcRunner,
    loadSchemaFile: async () => {
      const files = await loadFbsFiles(TEST_ROOT);
      const main = files.find((f) => f.path.endsWith("/monster_test.fbs"));
      if (!main) throw new Error("monster_test.fbs not found");
      return {
        entry: main.path,
        files: Object.fromEntries(files.map((f) => [f.path, f.data])),
      };
    },
    languageEntries,
    createStdoutStream: () => createBufferedStdout().writable,
  });

  for (const { language, success, files, error } of results) {
    assert(success, `Code generation failed for ${language}: ${error}`);
    assert(
      Object.keys(files).length > 0,
      `No files generated for ${language}`
    );
  }
});
