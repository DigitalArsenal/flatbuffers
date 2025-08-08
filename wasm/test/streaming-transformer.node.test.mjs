import { describe, it, expect } from "vitest";
import path from "node:path";
import fs from "node:fs/promises";
import { TextEncoder } from "node:util";
import { StreamingTransformer, FlatcRunner } from "../src/index.mjs";
import { runStreamingTransformerTest } from "../shared_test/streaming-transformer-test.mjs";
import { loadFbsFiles } from "../shared_test/util/load-fbs-files.mjs";

const TEST_ROOT = path.resolve(__dirname, "../../tests");
const MON_FILE = path.join(TEST_ROOT, "monsterdata_test.mon");

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
  const binary = await fs.readFile(MON_FILE);
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

describe("StreamingTransformer", () => {
  it("should round-trip binary to JSON and back and match original fields", async () => {
    const schemaInput = await loadSchemaFile();
    const inputJson = await loadJsonFromBinary(schemaInput);

    const result = await runStreamingTransformerTest({
      initTransformer,
      loadSchemaFile: () => schemaInput,
      sampleJson: () => Promise.resolve(new TextEncoder().encode(inputJson)),
    });

    const input = JSON.parse(result.inputJson);
    const output = JSON.parse(result.outputJson);

    expect(output.name).toEqual(input.name);
    expect(output.pos.x).toEqual(input.pos.x);
    expect(output.pos.y).toEqual(input.pos.y);
    expect(output.pos.z).toEqual(input.pos.z);

    console.log(
      `[perf] rounds=${result.rounds}, total=${result.totalTimeMs.toFixed(
        2
      )}ms, per round=${result.timePerTransformMs.toFixed(2)}ms`
    );
  }, 15000);
});
