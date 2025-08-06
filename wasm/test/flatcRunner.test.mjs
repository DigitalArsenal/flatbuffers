import { describe, it, expect } from "vitest";
import { FlatcRunner } from "../src/index.mjs";
import fs from "node:fs/promises";
import path from "node:path";
import { Writable } from "node:stream";

const TEST_ROOT = path.resolve(__dirname, "../../tests");
const JSON_FILE = path.join(TEST_ROOT, "monsterdata_test.json");
const MON_FILE = path.join(TEST_ROOT, "monsterdata_test.mon");

async function* walkFbsFiles(dir) {
  for (const entry of await fs.readdir(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      yield* walkFbsFiles(fullPath);
    } else if (entry.isFile() && entry.name.endsWith(".fbs")) {
      yield fullPath;
    }
  }
}

async function loadFbsFiles(root) {
  const files = [];
  for await (const filePath of walkFbsFiles(root)) {
    const data = await fs.readFile(filePath, "utf8");
    const relPath = path.relative(root, filePath);
    files.push({
      path: `/${relPath}`,
      data,
    });
  }
  return files;
}

describe("FlatcRunner", () => {
  it("should round-trip flatbuffer JSON to binary and back to JSON", async () => {
    let stdoutBuffer = "";
    const stdoutStream = new Writable({
      write(chunk, _, callback) {
        stdoutBuffer += chunk.toString();
        callback();
      },
    });

    const runner = await FlatcRunner.init({ stdoutStream });

    const fbsFiles = await loadFbsFiles(TEST_ROOT);
    const jsonInput = {
      path: "/monsterdata_test.json",
      data: await fs.readFile(JSON_FILE, "utf8"),
    };

    const schemaInput = fbsFiles.find((f) =>
      f.path.endsWith("monster_test.fbs")
    );
    if (!schemaInput) throw new Error("monster_test.fbs not found");
    await runner.mountFiles(fbsFiles);

    // Generate .mon binary from JSON
    const binaryBuffer = runner.generateBinary(schemaInput, jsonInput, [
      "/",
      "include_test",
    ]);

    // Convert .mon binary back to JSON
    const roundTrippedJson = runner.generateJSON(
      schemaInput,
      { path: "/roundtrip.mon", data: binaryBuffer },
      ["/", "include_test"],
      { strictJson: true }
    );

    const parsedOutput = JSON.parse(roundTrippedJson);

    // Use expected transformed values from the original .mon file
    const expectedBuffer = await fs.readFile(MON_FILE);
    const expectedJson = runner.generateJSON(
      schemaInput,
      { path: "/expected.mon", data: expectedBuffer },
      ["/", "include_test"],
      { strictJson: true }
    );

    const parsedExpected = JSON.parse(expectedJson);

    expect(parsedOutput).toEqual(parsedExpected);
  });
});
