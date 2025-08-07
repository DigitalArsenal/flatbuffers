import console from "node:console";

/**
 * Runs a FlatBuffers round-trip test:
 * JSON → Binary (.mon) → JSON
 *
 * @param {object} options
 * @param {typeof import("../src/core/runner.mjs").FlatcRunner} options.FlatcRunner
 * @param {() => Promise<Array<{ path: string, data: string | Uint8Array }>>} options.loadFbsFiles
 * @param {() => Promise<string | Uint8Array>} options.readJsonFile
 * @param {() => Promise<Uint8Array>} options.readMonFile
 * @param {() => any} options.createStdoutStream
 */
export async function runFlatcRoundTripTest({
  FlatcRunner,
  loadFbsFiles,
  readJsonFile,
  readMonFile,
  createStdoutStream,
}) {
  const fbsFiles = await loadFbsFiles();
  const jsonInput = await readJsonFile();

  const entryFile = fbsFiles.find((f) => f.path.endsWith("monster_test.fbs"));
  if (!entryFile) throw new Error("monster_test.fbs not found");

  const schemaInput = {
    entry: entryFile.path,
    files: Object.fromEntries(fbsFiles.map((f) => [f.path, f.data])),
  };

  const runner = await FlatcRunner.init({ stdoutStream: createStdoutStream() });

  const binaryBuffer = runner.generateBinary(schemaInput, jsonInput);

  const roundTrippedJson = runner.generateJSON(
    schemaInput,
    { path: "/roundtrip.mon", data: binaryBuffer },
    { encoding: "utf8" }
  );

  const expectedBuffer = await readMonFile();
  const expectedJson = runner.generateJSON(
    schemaInput,
    { path: "/expected.mon", data: expectedBuffer },
    { encoding: "utf8" }
  );

  return {
    actual: JSON.parse(roundTrippedJson),
    expected: JSON.parse(expectedJson),
  };
}
