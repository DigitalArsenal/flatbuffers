import { assertEquals } from "https://deno.land/std@0.214.0/assert/mod.ts";
import { FlatcRunner, StreamingTransformer } from "../src/mod.mjs";
import { runStreamingTransformerTest } from "../shared_test/streaming-transformer-test.mjs";
import { loadFbsFiles } from "../shared_test/util/load-fbs-files.mjs";
import { join } from "https://deno.land/std@0.214.0/path/mod.ts";
import console from "node:console";

const TEST_ROOT = new URL("../../tests/", import.meta.url).pathname;
const BIN_FILE = join(TEST_ROOT, "monsterdata_test.mon");

async function loadSchemaFile() {
  const files = await loadFbsFiles(TEST_ROOT);
  const main = files.find((f) => f.path.endsWith("monster_test.fbs"));
  if (!main) throw new Error("monster_test.fbs not found");
  return {
    entry: main.path,
    files: Object.fromEntries(files.map((f) => [f.path, f.data])),
  };
}

async function loadJsonFromBinary(schemaInput) {
  const binary = await Deno.readFile(BIN_FILE);
  const runner = await FlatcRunner.init();
  const jsonBuffer = runner.generateJSON(
    schemaInput,
    { path: "/input.mon", data: binary },
    { encoding: "utf8" }
  );
  return jsonBuffer;
}

function initTransformer(schemaInput) {
  return StreamingTransformer.create(schemaInput);
}

Deno.test("StreamingTransformer (Deno) round-trip test", async () => {
  const schemaInput = await loadSchemaFile();
  const inputJson = await loadJsonFromBinary(schemaInput);

  const result = await runStreamingTransformerTest({
    initTransformer,
    loadSchemaFile: () => schemaInput,
    sampleJson: () => Promise.resolve(new TextEncoder().encode(inputJson)),
  });

  const input = JSON.parse(result.inputJson);
  const output = JSON.parse(result.outputJson);

  assertEquals(output.name, input.name);
  assertEquals(output.pos.x, input.pos.x);
  assertEquals(output.pos.y, input.pos.y);
  assertEquals(output.pos.z, input.pos.z);

  console.log(
    `[perf] rounds=${result.rounds}, total=${result.totalTimeMs.toFixed(
      2
    )}ms, per round=${result.timePerTransformMs.toFixed(2)}ms`
  );
});
