// deno_test/streaming-transformer.deno.test.mjs

import { assertEquals } from "https://deno.land/std@0.214.0/assert/mod.ts";
import { StreamingTransformer } from "../src/mod.mjs";
import { runStreamingTransformerTest } from "../shared_test/streaming-transformer-test.mjs";
import { loadFbsFiles } from "../shared_test/util/load-fbs-files.mjs";

const TEST_ROOT = new URL("../../tests/", import.meta.url).pathname;

/**
 * Loads the schema input from test files.
 */
async function loadSchemaFile() {
  const files = await loadFbsFiles(TEST_ROOT);
  const main = files.find((f) => f.path.endsWith("/monster_test.fbs"));
  if (!main) throw new Error("monster_test.fbs not found");
  return {
    entry: main.path,
    files: Object.fromEntries(files.map((f) => [f.path, f.data])),
  };
}

/**
 * Provides a sample JSON object for the Monster schema.
 */
function sampleJson() {
  return Promise.resolve({
    pos: { x: 1, y: 2, z: 3 },
    name: "Orc",
    color: "Red",
  });
}

/**
 * Initializes a StreamingTransformer with the schema input.
 */
async function initTransformer(schemaInput) {
  return await StreamingTransformer.create(schemaInput);
}

Deno.test("StreamingTransformer (Deno) round-trip test", async () => {
  const { inputJson, outputJson } = await runStreamingTransformerTest({
    initTransformer,
    loadSchemaFile,
    sampleJson,
  });

  assertEquals(outputJson.name, inputJson.name);
  assertEquals(outputJson.pos.x, inputJson.pos.x);
  assertEquals(outputJson.pos.y, inputJson.pos.y);
  assertEquals(outputJson.pos.z, inputJson.pos.z);
});
