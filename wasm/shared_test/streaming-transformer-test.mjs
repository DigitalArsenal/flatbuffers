/**
 * Shared test function for StreamingTransformer.
 *
 * @param {object} options
 * @param {() => Promise<StreamingTransformer>} options.initTransformer - Factory that returns a StreamingTransformer instance.
 * @param {() => Promise<{ entry: string, files: Record<string, string|Uint8Array> }>} options.loadSchemaFile
 * @param {() => Promise<Uint8Array>} options.sampleJson - Function that returns a raw JSON buffer
 */
export async function runStreamingTransformerTest({
  initTransformer,
  loadSchemaFile,
  sampleJson,
}) {
  const schemaInput = await loadSchemaFile();
  const transformer = await initTransformer(schemaInput);
  const jsonBuffer = await sampleJson();

  const binary = transformer.transformJsonToBinary(jsonBuffer);
  const outputBuffer = transformer.transformBinaryToJson(binary);

  const inputJson = new TextDecoder().decode(jsonBuffer);
  const outputJson = new TextDecoder().decode(outputBuffer);

  return { inputJson, outputJson };
}
