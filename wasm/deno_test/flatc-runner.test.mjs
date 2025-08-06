import { assertEquals } from "https://deno.land/std@0.214.0/assert/mod.ts";
import { FlatcRunner } from "../src/mod.mjs";
import { join, relative } from "https://deno.land/std@0.214.0/path/mod.ts";

const TEST_ROOT = new URL("../../tests/", import.meta.url).pathname;
const JSON_FILE = join(TEST_ROOT, "monsterdata_test.json");
const MON_FILE = join(TEST_ROOT, "monsterdata_test.mon");

// Custom stdout stream that buffers written text
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

async function loadFbsFiles(root) {
  const files = [];
  for await (const filePath of walkFbsFiles(root)) {
    const data = await Deno.readTextFile(filePath);
    const relPath = relative(root, filePath);
    files.push({
      path: `/${relPath}`,
      data,
    });
  }
  return files;
}

Deno.test("FlatcRunner round-trip: JSON → .mon → JSON", async () => {
  const stdout = createBufferedStdout();
  const runner = await FlatcRunner.init({ stdoutStream: stdout.writable });

  const fbsFiles = await loadFbsFiles(TEST_ROOT);
  const jsonInput = {
    path: "/monsterdata_test.json",
    data: await Deno.readTextFile(JSON_FILE),
  };

  const schemaInput = fbsFiles.find((f) => f.path.endsWith("monster_test.fbs"));
  if (!schemaInput) throw new Error("monster_test.fbs not found");

  await runner.mountFiles(fbsFiles);

  const binaryBuffer = runner.generateBinary(schemaInput, jsonInput, [
    "/",
    "include_test",
  ]);

  const roundTrippedJson = runner.generateJSON(
    schemaInput,
    { path: "/roundtrip.mon", data: binaryBuffer },
    ["/", "include_test"],
    { strictJson: true }
  );

  const parsedOutput = JSON.parse(roundTrippedJson);

  const expectedBuffer = await Deno.readFile(MON_FILE);
  const expectedJson = runner.generateJSON(
    schemaInput,
    { path: "/expected.mon", data: expectedBuffer },
    ["/", "include_test"],
    { strictJson: true }
  );

  const parsedExpected = JSON.parse(expectedJson);

  assertEquals(parsedOutput, parsedExpected);
});
