# flatc-wasm

> An isomorphic WebAssembly wrapper for the [FlatBuffers](https://github.com/google/flatbuffers) `flatc` compiler — usable in **Node.js**, **Deno**, and the **Browser**.

This package provides a unified interface to run `flatc` entirely in JavaScript environments using WebAssembly. It supports schema compilation, JSON ⇄ binary roundtrips, code generation, and more.

---

## 📦 Installation

### Node.js

```bash
npm install flatc-wasm
```

### Deno

```ts
import { FlatcRunner } from "npm:flatc-wasm";
```

---

## Quick Start

### Node/Deno/Browser (FlatcRunner API)

```ts
import { FlatcRunner } from "flatc-wasm";

const runner = await FlatcRunner.init();

runner.mountFiles([
  {
    path: "/monster.fbs",
    data: `
      namespace MyGame.Sample;

      table Monster {
        id: int;
        name: string;
      }

      root_type Monster;
    `,
  },
  {
    path: "/monster.json",
    data: JSON.stringify({ id: 42, name: "Goblin" }),
  },
]);

const binary = runner.generateBinary(
  { path: "/monster.fbs" },
  { path: "/monster.json" }
);

const restoredJSON = runner.generateJSON(
  { path: "/monster.fbs" },
  { path: "/monster.mon", data: binary }
);

console.log("Restored JSON:", restoredJSON);
```

---

## StreamingTransformer Example

```ts
import { StreamingTransformer } from "flatc-wasm";

const transformer = await StreamingTransformer.create({
  entry: "/monster.fbs",
  files: {
    "/monster.fbs": `
      namespace MyGame.Sample;

      table Monster {
        id: int;
        name: string;
      }

      root_type Monster;
    `,
  },
});

const binary = await transformer.transformJsonToBinary(
  JSON.stringify({
    id: 1,
    name: "Zombie",
  })
);

const json = await transformer.transformBinaryToJson(binary);

console.log("Round-tripped JSON:", new TextDecoder().decode(json));
```

---

## API Overview

### `FlatcRunner.init([options])`

Initializes the WASM runtime.

| Option         | Description                        |
| -------------- | ---------------------------------- |
| `stdoutStream` | Writable stream for stdout capture |
| `stderrStream` | Writable stream for stderr capture |

### Methods

- **`mountFile(path, data)`**  
  Mounts a single file (e.g., a `.fbs` schema or `.json` input) into the in-memory file system used by the WASM module.

- **`mountFiles([{ path, data }])`**  
  Mounts multiple files at once into the virtual file system. Useful for schemas with imports/includes or multi-file projects.

- **`generateBinary(schema, json)`**  
  Compiles a JSON input into FlatBuffer binary format (`.mon`) using the provided schema.

  - `schema`: `{ path: string }`
  - `json`: `{ path: string, data: string | Uint8Array }`

- **`generateJSON(schema, buffer)`**  
  Converts FlatBuffer binary data back into a human-readable JSON object using the schema.

  - `schema`: `{ path: string }`
  - `buffer`: `{ path: string, data: Uint8Array }`

- **`generateCode(schema)`**  
  Generates target source code (e.g., TypeScript, C++, Rust) from the provided schema.  
  Returns a mapping of file paths to their contents.

- **`listAllFiles(path)`**  
  Recursively lists all mounted files and directories under the given virtual path.

- **`help()`**  
  Returns the help text for the `flatc` command-line tool, showing available flags and options.

- **`version()`**  
  Returns the current version of the `flatc` compiler being used via WebAssembly.

- **`getErrors()`**  
  Retrieves any collected errors that occurred during file mounting or command execution.

---

## Testing

### Node

```bash
npm test
```

### Deno

```bash
deno task test --allow-read --allow-env
```

---

## 📖 License

[Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0)
