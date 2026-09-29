/**
 * FlatcRunner stack test: one long-lived runner converts 10,000 times, and
 * flatc's stack pointer is where it started after every command, on success
 * and on failure.
 *
 * Emscripten's callMain pushes argv and every argument string onto flatc's
 * stack and never pops them, and exit() inside main unwinds past main's
 * frames. The runtime stays alive between commands, so a runner that does
 * not restore the stack pointer loses about a kilobyte per conversion with
 * this schema (one `-I` per include directory) and traps with "memory access
 * out of bounds" long before 10,000 conversions.
 */

import { FlatcRunner } from "../src/runner.mjs";

const CONVERSIONS = 10000;
const PARTS = 20;

const pad = (n) => String(n).padStart(2, "0");
const files = {};
const rootFields = [];
const includes = [];
const json = { name: "stack" };
for (let i = 0; i < PARTS; i++) {
  files[`/schemas/part${pad(i)}/part${pad(i)}.fbs`] =
    `namespace Stack;\ntable Part${pad(i)} { value:int; label:string; }\n`;
  includes.push(`include "part${pad(i)}.fbs";`);
  rootFields.push(`  part${pad(i)}:Part${pad(i)};`);
  json[`part${pad(i)}`] = { value: i * 7, label: `part ${i}` };
}
files["/schemas/root/root.fbs"] = `${includes.join("\n")}
namespace Stack;
table Root {
${rootFields.join("\n")}
  name:string;
}
root_type Root;
`;
const schema = { entry: "/schemas/root/root.fbs", files };
const jsonText = JSON.stringify(json);

let failures = 0;
function check(condition, message) {
  if (condition) {
    console.log(`  ✓ ${message}`);
  } else {
    console.log(`  ✗ ${message}`);
    failures++;
  }
}
const sameBytes = (a, b) =>
  a.length === b.length && a.every((value, index) => value === b[index]);

console.log("\n=== FlatcRunner stack tests ===\n");

const runner = await FlatcRunner.init();
check(
  typeof runner.Module.stackSave === "function" &&
    typeof runner.Module.stackRestore === "function",
  "flatc module exports stackSave and stackRestore"
);
const stackTop = runner.Module.stackSave();

console.log("\n1. Every method that runs flatc's main:");
const binary = runner.generateBinary(schema, jsonText, { sizePrefix: false });
const expectedJson = runner.generateJSON(schema, { path: "/in/root.bin", data: binary });
const methods = {
  "runCommand --version": () => runner.runCommand(["--version"]),
  "version()": () => runner.version(),
  "help()": () => runner.help(),
  "generateBinary": () => runner.generateBinary(schema, jsonText),
  "generateJSON": () => runner.generateJSON(schema, { path: "/in/root.bin", data: binary }),
  "generateCode (ts)": () => runner.generateCode(schema, "ts"),
  "generateJsonSchema": () => runner.generateJsonSchema(schema),
  "runCommand with an unknown flag (exit 1)": () => {
    const result = runner.runCommand(["--no-such-flag"]);
    if (result.code !== 1) throw new Error(`exit ${result.code}`);
  },
  "generateBinary with invalid JSON (throws)": () => {
    try {
      runner.generateBinary(schema, "{ not json");
    } catch (e) {
      if (/exit 1/.test(e.message)) return;
      throw e;
    }
    throw new Error("did not throw");
  },
  "runCommand with a missing schema (exit 1)": () => {
    const result = runner.runCommand(["--binary", "-o", "/tmp", "/no/such.fbs", "/no/such.json"]);
    if (result.code !== 1) throw new Error(`exit ${result.code}`);
  },
};
for (const [name, run] of Object.entries(methods)) {
  let error = null;
  try {
    run();
  } catch (e) {
    error = e;
  }
  const drift = runner.Module.stackSave() - stackTop;
  check(
    error === null && drift === 0,
    `${name}: ${error ? `failed: ${error.message}` : `stack moved ${drift} bytes`}`
  );
}

console.log(`\n2. ${CONVERSIONS.toLocaleString("en-US")} conversions in one runner:`);
let encodes = 0;
let decodes = 0;
let failed = 0;
let firstDrift = null;
let trap = null;
const started = Date.now();
for (let i = 0; i < CONVERSIONS; i++) {
  try {
    if (i % 10 === 9) {
      // A failing conversion: flatc exits from inside main.
      let threw = false;
      try {
        runner.generateBinary(schema, `{ "name": "stack", "part00": ${i} }`);
      } catch (e) {
        if (!/exit 1/.test(e.message)) throw e;
        threw = true;
      }
      if (!threw) throw new Error(`conversion ${i} accepted invalid JSON`);
      failed++;
    } else if (i % 2 === 0) {
      const out = runner.generateBinary(schema, jsonText, { sizePrefix: false });
      if (!sameBytes(out, binary)) throw new Error(`encode ${i} differs from the first`);
      encodes++;
    } else {
      const out = runner.generateJSON(schema, { path: "/in/root.bin", data: binary });
      if (out !== expectedJson) throw new Error(`decode ${i} differs from the first`);
      decodes++;
    }
  } catch (e) {
    trap = `conversion ${i}: ${e.message.split("\n")[0]}`;
    break;
  }
  const drift = runner.Module.stackSave() - stackTop;
  if (drift !== 0 && firstDrift === null) firstDrift = { conversion: i, drift };
}
const seconds = ((Date.now() - started) / 1000).toFixed(1);
console.log(
  `    ${encodes} encodes, ${decodes} decodes, ${failed} failing conversions in ${seconds} s`
);
check(trap === null, `no trap${trap ? `: ${trap}` : ""}`);
check(
  firstDrift === null,
  firstDrift
    ? `stack moved ${firstDrift.drift} bytes after conversion ${firstDrift.conversion}`
    : "stack pointer after every conversion equals the stack pointer before"
);
check(
  encodes + decodes + failed === CONVERSIONS,
  `${encodes + decodes + failed} of ${CONVERSIONS} conversions ran`
);
check(
  runner.Module.stackSave() === stackTop,
  `stack pointer after: ${runner.Module.stackSave()}, before: ${stackTop}`
);

console.log(`\n${failures === 0 ? "All stack tests passed" : `${failures} stack test(s) failed`}`);
process.exit(failures === 0 ? 0 : 1);
