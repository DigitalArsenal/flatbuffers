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
  const main = files.find((f) => f.path.endsWith("monster_test.fbs"));
  if (!main) throw new Error("monster_test.fbs not found");
  return {
    entry: main.path,
    files: Object.fromEntries(files.map((f) => [f.path, f.data])),
  };
}

/**
 * Provides a sample JSON buffer for the Monster schema.
 * Must return raw Uint8Array.
 */
function sampleJson() {
  const obj = {
    pos: { x: 1, y: 2, z: 3 },
    name: "Orc",
    color: "Red",
  };
  return Promise.resolve(new TextEncoder().encode(JSON.stringify(obj)));
}

/**
 * Initializes a StreamingTransformer with the schema input.
 */
function initTransformer(schemaInput) {
  return StreamingTransformer.create(schemaInput);
}

Deno.test("StreamingTransformer (Deno) round-trip test", async () => {
  const { inputJson, outputJson } = await runStreamingTransformerTest({
    initTransformer,
    loadSchemaFile,
    sampleJson,
  });

  const input = JSON.parse(inputJson);
  const output = JSON.parse(outputJson);

  assertEquals(output.name, input.name);
  assertEquals(output.pos.x, input.pos.x);
  assertEquals(output.pos.y, input.pos.y);
  assertEquals(output.pos.z, input.pos.z);
});
