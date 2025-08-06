import { assertEquals } from "https://deno.land/std@0.214.0/assert/mod.ts";
import { FlatcRunner } from "../src/mod.mjs";
import { join, relative } from "https://deno.land/std@0.214.0/path/mod.ts";
import { runFlatcRoundTripTest } from "../shared_test/json-binary-test.mjs";

const TEST_ROOT = new URL("../../tests/", import.meta.url).pathname;
const JSON_FILE = join(TEST_ROOT, "monsterdata_test.json");
const MON_FILE = join(TEST_ROOT, "monsterdata_test.mon");

function createBufferedStdout() {
  const buffer = [];
  const writable = new WritableStream({
    write(chunk) {
      buffer.push(
        typeof chunk === "string" ? chunk : new TextDecoder().decode(chunk)
      );
    },
  });
  return { writable, getOutput: () => buffer.join("") };
}

async function* walkFbsFiles(dir) {
  for await (const entry of Deno.readDir(dir)) {
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory) {
      yield* walkFbsFiles(fullPath);
    } else if (entry.isFile && entry.name.endsWith(".fbs")) {
      yield fullPath;
    }
  }
}

async function loadFbsFiles() {
  const files = [];
  for await (const filePath of walkFbsFiles(TEST_ROOT)) {
    const data = await Deno.readTextFile(filePath);
    const relPath = relative(TEST_ROOT, filePath);
    files.push({ path: `/${relPath}`, data });
  }
  return files;
}

Deno.test("FlatcRunner round-trip: JSON → .mon → JSON", async () => {
  const { actual, expected } = await runFlatcRoundTripTest({
    FlatcRunner,
    loadFbsFiles,
    readJsonFile: () => Deno.readTextFile(JSON_FILE),
    readMonFile: () => Deno.readFile(MON_FILE),
    createStdoutStream: () => createBufferedStdout().writable,
  });

  assertEquals(actual, expected);
});
