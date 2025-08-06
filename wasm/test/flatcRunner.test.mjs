import { FlatcRunner } from "../src/index.mjs";
import { Writable } from "stream";

let versionOutput = "";
let helpOutput = "";

const stdoutCollector = new Writable({
  write(chunk, encoding, callback) {
    const str = chunk.toString();
    if (str.includes("version")) versionOutput += str;
    else helpOutput += str;
    callback();
  },
});

const runner = await FlatcRunner.init({
  stdoutStream: stdoutCollector,
});

runner.version();
runner.help();

setTimeout(() => {
  console.log("Version:", versionOutput.trim());
  console.log("Help:", helpOutput.trim());
}, 200);
