export async function runFlatcRoundTripTest({ FlatcRunner, loadFbsFiles, readJsonFile, readMonFile, createStdoutStream }) {
  const fbsFiles = await loadFbsFiles();
  const jsonInput = {
    path: "/monsterdata_test.json",
    data: await readJsonFile(),
  };

  const schemaInput = fbsFiles.find((f) => f.path.endsWith("monster_test.fbs"));
  if (!schemaInput) throw new Error("monster_test.fbs not found");

  const runner = await FlatcRunner.init({ stdoutStream: createStdoutStream() });
  await runner.mountFiles(fbsFiles);

  const binaryBuffer = runner.generateBinary(schemaInput, jsonInput, ["/", "include_test"]);

  const roundTrippedJson = runner.generateJSON(
    schemaInput,
    { path: "/roundtrip.mon", data: binaryBuffer },
    ["/", "include_test"],
    { strictJson: true }
  );

  const expectedBuffer = await readMonFile();
  const expectedJson = runner.generateJSON(
    schemaInput,
    { path: "/expected.mon", data: expectedBuffer },
    ["/", "include_test"],
    { strictJson: true }
  );

  return {
    actual: JSON.parse(roundTrippedJson),
    expected: JSON.parse(expectedJson),
  };
}
