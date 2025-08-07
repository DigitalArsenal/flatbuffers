export async function runCodegenSmokeTest({
  FlatcRunner,
  loadSchemaFile,
  languageEntries,
  createStdoutStream,
  outputDir = "/out",
}) {
  const schemaInput = await loadSchemaFile();
  const results = [];

  for (const { language, options } of languageEntries) {
    const runner = await FlatcRunner.init({
      stdoutStream: createStdoutStream(),
    });

    try {
      const files = runner.generateCode(
        schemaInput,
        language,
        outputDir,
        options
      );
      results.push({ language, success: true, files });
    } catch (err) {
      const serializedError =
        err && typeof err === "object"
          ? JSON.stringify(err, Object.getOwnPropertyNames(err), 2)
          : String(err);

      results.push({
        language,
        success: false,
        error: serializedError,
        files: {},
      });
    }
  }

  return results;
}
