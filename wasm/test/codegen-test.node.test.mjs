import { describe, it, expect } from "vitest";
import path from "node:path";
import { Writable } from "node:stream";
import { FlatcRunner } from "../src/index.mjs";
import { runCodegenSmokeTest } from "../shared_test/codegen-test.mjs";
import {
  loadFbsFiles,
  getLanguageEntries,
} from "../shared_test/util/load-fbs-files.mjs";

const TEST_ROOT = path.resolve(__dirname, "../../tests");

function createNoopStream() {
  return new Writable({
    write(_chunk, _, cb) {
      cb();
    },
  });
}

describe("FlatcRunner generateCode", () => {
  it("should generate files for all supported languages without error", async () => {
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
      createStdoutStream: () => createNoopStream(),
    });

    for (const { language, success, files, error } of results) {
      if (!success) {
        console.error(`${language} failed: ${error}`);
      } else {
        console.log(
          `${language} succeeded with ${Object.keys(files).length} file(s)`
        );
      }

      expect(success).toBe(true);
      expect(Object.keys(files).length).toBeGreaterThan(0);
    }
  });
});
