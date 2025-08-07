import { performance } from "node:perf_hooks";

/**
 * Shared performance and correctness test for StreamingTransformer.
 *
 * @param {object} options
 * @param {() => Promise<StreamingTransformer>} options.initTransformer - Factory that returns a StreamingTransformer instance.
 * @param {() => Promise<{ entry: string, files: Record<string, string | Uint8Array> }>} options.loadSchemaFile
 * @param {() => Promise<Uint8Array>} options.sampleJson - Function that returns a raw JSON buffer
 * @returns {Promise<{
 *   inputJson: string,
 *   outputJson: string,
 *   timePerTransformMs: number,
 *   totalTimeMs: number,
 *   rounds: number
 * }>}
 */
export async function runStreamingTransformerTest({
  initTransformer,
  loadSchemaFile,
  sampleJson,
}) {
  const schemaInput = await loadSchemaFile();
  const transformer = await initTransformer(schemaInput);
  const baseJsonBuffer = await sampleJson();
  const baseJson = JSON.parse(new TextDecoder().decode(baseJsonBuffer));

  const rounds = 50;
  const mutatedJsons = [];

  for (let i = 0; i < rounds; i++) {
    const clone = JSON.parse(JSON.stringify(baseJson));
    mutatedJsons.push(new TextEncoder().encode(JSON.stringify(clone)));
  }

  const outputs = [];
  const start = performance.now();

  for (let i = 0; i < rounds; i++) {
    const binary = await transformer.transformJsonToBinary(mutatedJsons[i]);
    const outputBuffer = await transformer.transformBinaryToJson(binary);
    outputs.push(outputBuffer);
  }

  const end = performance.now();
  const totalTimeMs = end - start;
  const timePerTransformMs = totalTimeMs / rounds;

  return {
    inputJson: new TextDecoder().decode(mutatedJsons[0]),
    outputJson: new TextDecoder().decode(outputs[0]),
    timePerTransformMs,
    totalTimeMs,
    rounds,
  };
}